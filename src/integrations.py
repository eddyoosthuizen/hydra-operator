# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import logging
import subprocess
from dataclasses import asdict, dataclass, field
from typing import Any, KeysView, Optional, Type, TypeAlias, Union
from urllib.parse import quote, urlparse

import dacite
from charmlibs.interfaces.security_otlp import SecurityOtlpRequirer
from charms.certificate_transfer_interface.v1.certificate_transfer import (
    CertificateTransferRequires,
)
from charms.data_platform_libs.v0.data_interfaces import DatabaseRequires
from charms.hydra.v0.hydra_token_hook import AuthIn, HydraHookRequirer
from charms.identity_platform_login_ui_operator.v0.login_ui_endpoints import (
    LoginUIEndpointsRequirer,
)
from charms.tempo_coordinator_k8s.v0.tracing import TracingEndpointRequirer
from charms.traefik_k8s.v0.traefik_route import TraefikRouteRequirer
from jinja2 import Template
from ops.model import Container, Model
from ops.pebble import Layer
from yarl import URL

from configs import ServiceConfigs
from constants import (
    ADMIN_PORT,
    CA_BUNDLE_PATH,
    INTEGRATION_CA_BUNDLE_PATH,
    INTERNAL_ROUTE_INTEGRATION_NAME,
    MIGRATION_VERSION_KEY_PREFIX,
    PEER_INTEGRATION_NAME,
    POSTGRESQL_DSN_TEMPLATE,
    PUBLIC_PORT,
    PUBLIC_ROUTE_INTEGRATION_NAME,
    SECURITY_OTLP_FILTER_BINARY_PATH,
    SECURITY_OTLP_FILTER_POLICY,
    SECURITY_OTLP_FILTER_SERVICE,
    SECURITY_OTLP_FILTER_SOURCE_PATH,
)
from env_vars import EnvVars

logger = logging.getLogger(__name__)

JsonSerializable: TypeAlias = Union[dict[str, Any], list[Any], int, str, float, bool, Type[None]]


class PeerData:
    def __init__(self, model: Model) -> None:
        self._model = model
        self._app = model.app

    def __getitem__(self, key: str) -> JsonSerializable:
        if not (peers := self._model.get_relation(PEER_INTEGRATION_NAME)):
            return {}

        value = peers.data[self._app].get(key)
        return json.loads(value) if value else {}

    def __setitem__(self, key: str, value: Any) -> None:
        if not (peers := self._model.get_relation(PEER_INTEGRATION_NAME)):
            return

        peers.data[self._app][key] = json.dumps(value)

    def pop(self, key: str) -> JsonSerializable:
        if not (peers := self._model.get_relation(PEER_INTEGRATION_NAME)):
            return {}

        data = peers.data[self._app].pop(key, None)
        return json.loads(data) if data else {}

    def keys(self) -> KeysView[str]:
        if not (peers := self._model.get_relation(PEER_INTEGRATION_NAME)):
            return KeysView({})

        return peers.data[self._app].keys()

    def migration_versions(self) -> dict[int, JsonSerializable]:
        """Return the workload versions recorded for the database integrations, by id.

        The ids grow with time, so the highest one belongs to the most recent integration.
        """
        versions = {}
        for key in self.keys():
            integration_id = key.removeprefix(MIGRATION_VERSION_KEY_PREFIX)
            if key != integration_id and integration_id.isdigit() and (version := self[key]):
                versions[int(integration_id)] = version

        return versions


@dataclass(frozen=True, slots=True)
class DatabaseConfig:
    """The data source from the database integration."""

    endpoint: str = ""
    database: str = ""
    username: str = ""
    password: str = ""
    migration_version: str = ""

    @property
    def dsn(self) -> str:
        # Unescaped, a character such as "/" or "%" in the credentials breaks the URL
        return POSTGRESQL_DSN_TEMPLATE.substitute(
            username=quote(self.username, safe=""),
            password=quote(self.password, safe=""),
            endpoint=self.endpoint,
            database=self.database,
        )

    def to_service_configs(self) -> ServiceConfigs:
        return {
            "dsn": self.dsn,
        }

    @classmethod
    def load(cls, requirer: DatabaseRequires) -> "DatabaseConfig":
        if not (database_integrations := requirer.relations):
            return cls()

        integration_id = database_integrations[0].id
        integration_data: dict[str, str] = requirer.fetch_relation_data()[integration_id]

        return cls(
            endpoint=integration_data.get("endpoints", "").split(",")[0],
            database=requirer.database,
            username=integration_data.get("username", ""),
            password=integration_data.get("password", ""),
            migration_version=f"{MIGRATION_VERSION_KEY_PREFIX}{integration_id}",
        )


@dataclass(frozen=True, slots=True)
class TracingData:
    """The data source from the tracing integration."""

    is_ready: bool = False
    http_endpoint: str = ""

    def to_env_vars(self) -> EnvVars:
        if not self.is_ready:
            return {}

        return {
            "TRACING_ENABLED": True,
            "TRACING_PROVIDER": "otel",
            "TRACING_PROVIDERS_OTLP_SERVER_URL": self.http_endpoint,
            "TRACING_PROVIDERS_OTLP_INSECURE": "true",
            "TRACING_PROVIDERS_OTLP_SAMPLING_SAMPLING_RATIO": "1.0",
        }

    @classmethod
    def load(cls, requirer: TracingEndpointRequirer) -> "TracingData":
        if not (is_ready := requirer.is_ready()):
            return cls()

        # The provider can be ready without this receiver, e.g. a relay with no backend yet
        if not (endpoint := requirer.get_endpoint("otlp_http")):
            return cls()

        http_endpoint = urlparse(endpoint)

        return cls(
            is_ready=is_ready,
            http_endpoint=http_endpoint.geturl().replace(f"{http_endpoint.scheme}://", "", 1),
        )


@dataclass(frozen=True, slots=True)
class LoginUIEndpointData:
    """The data source from the login-ui integration."""

    consent_url: str = ""
    device_verification_url: str = ""
    oidc_error_url: str = ""
    login_url: str = ""
    post_device_done_url: str = ""

    def is_ready(self) -> bool:
        return all(v for _, v in self.to_service_configs().items())

    def to_service_configs(self) -> ServiceConfigs:
        return asdict(self)

    @classmethod
    def load(cls, requirer: LoginUIEndpointsRequirer) -> "LoginUIEndpointData":
        try:
            login_ui_endpoints = requirer.get_login_ui_endpoints()
        except Exception as exc:
            logger.error("Failed to fetch the login ui endpoints: %s", exc)
            return cls()

        return (
            dacite.from_dict(data_class=LoginUIEndpointData, data=login_ui_endpoints)
            if login_ui_endpoints
            else cls()
        )


@dataclass(slots=True)
class HydraHookData:
    """The data source from the hydra integration."""

    is_ready: bool = False
    auth_enabled: bool = False
    url: str = ""
    auth_type: Optional[str] = None
    auth_name: Optional[str] = None
    auth_value: Optional[str] = None
    auth_in: Optional[str] = None
    claims: list[str] = field(default_factory=list)

    def to_service_configs(self) -> ServiceConfigs:
        if not self.is_ready:
            return {}

        r: dict[str, object] = {
            "token_hook_url": self.url,
        }
        if self.auth_enabled:
            r.update({
                "token_hook_auth_type": "api_key",
                "token_hook_auth_name": self.auth_name,
                "token_hook_auth_value": self.auth_value,
                "token_hook_auth_in": self.auth_in,
            })
        if self.claims:
            r["token_hook_claims"] = self.claims
        return r

    @classmethod
    def load(cls, requirer: HydraHookRequirer) -> "HydraHookData":
        if not (is_ready := requirer.ready()):
            return cls()

        if not (data := requirer.consume_relation_data()):
            return cls()

        c = cls(
            is_ready=is_ready,
            url=data.url,
            auth_enabled=data.auth_enabled,
            claims=data.enabled_claims,
        )
        if c.auth_enabled:
            c.auth_type = "api_key"
            c.auth_name = data.auth_config_name
            c.auth_value = data.auth_config_value
            auth_in = data.auth_config_in
            c.auth_in = auth_in.value if isinstance(auth_in, AuthIn) else auth_in
        return c


def get_external_host_and_scheme(
    requirer: TraefikRouteRequirer, relation_name: str
) -> tuple[str, str]:
    """Extract external_host and scheme from a Traefik route relation.

    If the relation or the remote application data is not available,
    returns empty strings as default values.
    """
    if not (relation := requirer._charm.model.get_relation(relation_name)):
        return "", ""
    if not relation.app:
        return "", ""
    data = relation.data[relation.app]
    return data.get("external_host", ""), data.get("scheme", "")


@dataclass(frozen=True, slots=True)
class InternalIngressData:
    """The data source from the internal-ingress integration."""

    public_endpoint: URL
    admin_endpoint: URL
    config: dict = field(default_factory=dict)

    @classmethod
    def load(
        cls, requirer: TraefikRouteRequirer, use_ingress_for_relations: bool = False
    ) -> "InternalIngressData":
        model, app = requirer._charm.model.name, requirer._charm.app.name
        external_host, scheme = get_external_host_and_scheme(
            requirer, INTERNAL_ROUTE_INTEGRATION_NAME
        )

        external_endpoint = f"{scheme}://{external_host}"

        with open("templates/internal-route.json.j2", "r") as file:
            template = Template(file.read())

        ingress_config = json.loads(
            template.render(
                model=model,
                app=app,
                public_port=PUBLIC_PORT,
                admin_port=ADMIN_PORT,
                external_host=external_host,
            )
        )

        public_endpoint = URL(
            external_endpoint
            if external_host and use_ingress_for_relations
            else f"http://{app}.{model}.svc.cluster.local:{PUBLIC_PORT}"
        )
        admin_endpoint = URL(
            external_endpoint
            if external_host and use_ingress_for_relations
            else f"http://{app}.{model}.svc.cluster.local:{ADMIN_PORT}"
        )

        return cls(
            public_endpoint=public_endpoint,
            admin_endpoint=admin_endpoint,
            config=ingress_config,
        )


@dataclass(frozen=True, slots=True)
class PublicRouteData:
    """The data source from the public-route integration."""

    url: URL = URL()
    config: dict = field(default_factory=dict)

    def is_ready(self) -> bool:
        return bool(self.url)

    @classmethod
    def load(cls, requirer: TraefikRouteRequirer) -> "PublicRouteData":
        model, app = requirer._charm.model.name, requirer._charm.app.name
        external_host, scheme = get_external_host_and_scheme(
            requirer, PUBLIC_ROUTE_INTEGRATION_NAME
        )

        if not external_host:
            logger.error("External hostname is not set on the ingress provider")
            return cls()

        external_endpoint = f"{scheme}://{external_host}"

        # template could have use PathPrefixRegexp but going for a simple one right now
        with open("templates/public-route.json.j2", "r") as file:
            template = Template(file.read())

        ingress_config = json.loads(
            template.render(
                model=model,
                app=app,
                public_port=PUBLIC_PORT,
                external_host=external_host,
            )
        )

        return cls(
            url=URL(external_endpoint),
            config=ingress_config,
        )

    @property
    def secured(self) -> bool:
        return self.url.scheme == "https"

    def to_service_configs(self) -> ServiceConfigs:
        return {"public_url": str(self.url)}


@dataclass(frozen=True, slots=True)
class TLSCertificates:
    """TEST SCAFFOLDING, not production -- see STATUS.md "Path B".

    Mirrors kratos's receive-ca-cert handling verbatim, solely so send-security-otlp's
    delivery can be exercised against the e2e harness's self-signed CA. hydra is not
    expected to need this once the provider's ingress presents a publicly-trusted
    certificate (the decided design); remove this class and its call site then.
    """

    ca_bundle: str

    @classmethod
    def load(cls, requirer: CertificateTransferRequires) -> "TLSCertificates":
        """Fetch the CA certificates from all "receive-ca-cert" integrations.

        Compose the trusted CA certificates in /etc/ssl/certs/ca-certificates.crt.
        """
        ca_certs = requirer.get_all_certificates()
        ca_bundle = "\n".join(sorted(ca_certs))

        if ca_bundle:
            current_ca_cert = (
                INTEGRATION_CA_BUNDLE_PATH.read_text()
                if INTEGRATION_CA_BUNDLE_PATH.exists()
                else ""
            )
            if current_ca_cert != ca_bundle:
                INTEGRATION_CA_BUNDLE_PATH.parent.mkdir(parents=True, exist_ok=True)
                INTEGRATION_CA_BUNDLE_PATH.write_text(ca_bundle)
                subprocess.run(["update-ca-certificates", "--fresh"], check=True)
        else:
            if INTEGRATION_CA_BUNDLE_PATH.exists():
                INTEGRATION_CA_BUNDLE_PATH.unlink(missing_ok=True)
                subprocess.run(["update-ca-certificates", "--fresh"], check=True)

        return cls(ca_bundle=CA_BUNDLE_PATH.read_text())


SECURITY_OTLP_LOG_TARGET_PREFIX = "security-otlp"


def _security_otlp_log_target(relation_id: int, endpoint: str, enable: bool) -> dict:
    name = f"{SECURITY_OTLP_LOG_TARGET_PREFIX}-{relation_id}"
    return {
        name: {
            "override": "replace",
            # Points at the filter service (below), not "all": confirmed against
            # Pebble's own Service.LogsTo (research-and-context/pebble/internals/plan/plan.go)
            # that "all" means every service in the plan, so leaving this as "all" would
            # forward the real workload's raw, unfiltered output alongside the filtered
            # copy -- see STATUS.md Next-steps item 4 for the full finding.
            "services": (
                [SECURITY_OTLP_FILTER_SERVICE] if enable else [f"-{SECURITY_OTLP_FILTER_SERVICE}"]
            ),
            "type": "opentelemetry",
            "location": endpoint,
        }
    }


def _security_otlp_filter_service(real_service_name: str) -> dict:
    """TEST SCAFFOLDING, not production -- see STATUS.md Next-steps item 4.

    Pebble service definition for the filter binary: tails `real_service_name`'s own
    captured log stream via Pebble's client API (poc-log-filtering/main.go), applies
    `SECURITY_OTLP_FILTER_POLICY`, and re-emits only matching lines on its own stdout --
    which Pebble captures the same way it captures any service, so the log-target above
    can forward it with no further plumbing. `real_service_name`'s own command is never
    touched, so the `logging` relation's log-target (LogForwarder, a different vendored
    library -- see the same STATUS.md item for why its own `services: ["all"]` also
    needs attention) keeps seeing the full, unfiltered stream.
    """
    return {
        SECURITY_OTLP_FILTER_SERVICE: {
            "override": "replace",
            "command": (
                f"{SECURITY_OTLP_FILTER_BINARY_PATH} "
                f"-service {real_service_name} -policy {SECURITY_OTLP_FILTER_POLICY}"
            ),
            "startup": "enabled",
        }
    }


def _push_security_otlp_filter_binary(container: Container) -> None:
    """TEST SCAFFOLDING, not production -- see STATUS.md Next-steps item 4.

    Delivers the filter binary checked into this charm's own src/ into the workload
    container, unconditionally on every reconcile -- matching push_ca_certs's own
    established idempotency posture (a plain overwrite, not a skip-if-unchanged check).
    Stands in for the still-undecided production packaging mechanism (a charm resource
    or a charmcraft.yaml build part); this is a stopgap, not a design decision.
    """
    container.push(
        str(SECURITY_OTLP_FILTER_BINARY_PATH),
        SECURITY_OTLP_FILTER_SOURCE_PATH.read_bytes(),
        permissions=0o755,
        make_dirs=True,
    )


def configure_security_otlp_log_forwarding(
    container: Container, requirer: SecurityOtlpRequirer, real_service_name: str
) -> None:
    """Forward the workload's security-relevant logs to every related security-otlp endpoint.

    Logs go through a dedicated filter service rather than forwarding everything.
    Builds one Pebble log-target per related `send-security-otlp` relation -- there can be
    more than one, since the relation is intentionally unbounded (see the spec). Also
    disables any previously configured target whose relation is no longer active, so a
    broken relation stops forwarding rather than continuing to ship logs to a stale
    endpoint.
    """
    active_endpoints = requirer.endpoints

    targets: dict = {}
    for relation_id, endpoint in active_endpoints.items():
        targets.update(_security_otlp_log_target(relation_id, endpoint.endpoint, enable=True))

    existing_targets = container.get_plan().to_dict().get("log-targets", {})
    for name in existing_targets:
        if not name.startswith(f"{SECURITY_OTLP_LOG_TARGET_PREFIX}-"):
            continue
        relation_id = int(name.removeprefix(f"{SECURITY_OTLP_LOG_TARGET_PREFIX}-"))
        if relation_id not in active_endpoints:
            targets.update(_security_otlp_log_target(relation_id, "(removed)", enable=False))

    if not targets:
        return

    _push_security_otlp_filter_binary(container)

    layer = Layer(
        {
            "services": _security_otlp_filter_service(real_service_name),
            "log-targets": targets,
        }
    )
    container.add_layer("security-otlp-log-forwarding", layer, combine=True)
    # add_layer() alone only updates pebble's plan -- it does not start the new
    # "security-otlp-filter" service. replan() is what PebbleService.plan() (services.py)
    # already relies on for the primary service; needed here for the same reason, or the
    # filter service is defined but never actually runs.
    container.replan()
