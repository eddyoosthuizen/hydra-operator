# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from pathlib import Path
from string import Template

# Charm constants
POSTGRESQL_DSN_TEMPLATE = Template("postgres://$username:$password@$endpoint/$database")
WORKLOAD_CONTAINER = "hydra"
WORKLOAD_SERVICE = "hydra"
PEBBLE_READY_CHECK_NAME = "ready"
PEBBLE_ALIVE_CHECK_NAME = "alive"
COOKIE_SECRET_KEY = "cookie"
SYSTEM_SECRET_KEY = "system"
COOKIE_SECRET_LABEL = "cookiesecret"
SYSTEM_SECRET_LABEL = "systemsecret"
DEFAULT_OAUTH_SCOPES = ["openid", "profile", "email", "phone"]
DEFAULT_RESPONSE_TYPES = ["code"]
SYSTEM_SECRET = "system"
COOKIE_SECRET = "cookie"
ALLOWED_SECRET_TYPES = [SYSTEM_SECRET, COOKIE_SECRET]

# Peer relation keys
MIGRATION_VERSION_KEY_PREFIX = "migration_version_"
PEER_INTEGRATION_SYSTEM_SECRET_KEYS = "system_keys"
PEER_INTEGRATION_COOKIE_SECRET_KEYS = "cookie_keys"

# Application constants
HYDRA_SERVICE_COMMAND = "hydra serve all"
PUBLIC_PORT = 4444
ADMIN_PORT = 4445
CONFIG_FILE_NAME = "/etc/config/hydra.yaml"

# Integration constants
HYDRA_TOKEN_HOOK_INTEGRATION_NAME = "hydra-token-hook"
DATABASE_INTEGRATION_NAME = "pg-database"
PUBLIC_INGRESS_INTEGRATION_NAME = "public-ingress"
ADMIN_INGRESS_INTEGRATION_NAME = "admin-ingress"
INTERNAL_ROUTE_INTEGRATION_NAME = "internal-route"
PUBLIC_ROUTE_INTEGRATION_NAME = "public-route"
LOGIN_UI_INTEGRATION_NAME = "ui-endpoint-info"
PEER_INTEGRATION_NAME = "hydra"
PROMETHEUS_SCRAPE_INTEGRATION_NAME = "metrics-endpoint"
LOGGING_RELATION_NAME = "logging"
GRAFANA_DASHBOARD_INTEGRATION_NAME = "grafana-dashboard"
TEMPO_TRACING_INTEGRATION_NAME = "tracing"
OAUTH_INTEGRATION_NAME = "oauth"
SECURITY_OTLP_INTEGRATION_NAME = "send-security-otlp"

# TEST SCAFFOLDING, not production: CA trust plumbing to exercise send-security-otlp's
# delivery path against the e2e harness's self-signed CA. See STATUS.md "Path B".
CERTIFICATE_TRANSFER_INTEGRATION_NAME = "receive-ca-cert"
CA_BUNDLE_PATH = Path("/etc/ssl/certs/ca-certificates.crt")
INTEGRATION_CA_BUNDLE_PATH = Path("/usr/local/share/ca-certificates/ca-certificates.crt")

# TEST SCAFFOLDING, not production: how the security-otlp filter binary gets into the
# workload container. The binary is checked into this charm's own src/ (built by
# ../poc-log-filtering/, CGO_ENABLED=0 static) and pushed from there -- a stopgap for
# the still-open packaging decision (charm resource vs. a charmcraft.yaml build part),
# not the production delivery mechanism. See STATUS.md Next-steps item 4.
SECURITY_OTLP_FILTER_SERVICE = "security-otlp-filter"
SECURITY_OTLP_FILTER_SOURCE_PATH = Path(__file__).parent / "security-otlp-filter"
SECURITY_OTLP_FILTER_BINARY_PATH = Path("/tmp/security-otlp-filter")
# hybrid: the one of poc-log-filtering's policies whose live-confirmed behavior is
# closest to "forward everything except confirmed noise" -- the least surprising
# default while the actual filtering policy is still a SecOps decision (see
# ../poc-log-filtering/METHODOLOGIES.md).
SECURITY_OTLP_FILTER_POLICY = "hybrid"
