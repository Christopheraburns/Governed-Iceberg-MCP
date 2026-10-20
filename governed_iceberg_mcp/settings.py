"""Every knob comes from the environment; adapting to a cluster means changing the env file, not the code."""
import os
from dataclasses import dataclass, field


def flag(name, default):
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Settings:
    # ── Listening. Workbench sets CDSW_APP_PORT and reaches the application on 127.0.0.1. ──
    bind: str = field(default_factory=lambda: os.getenv("MCP_BIND", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.getenv("CDSW_APP_PORT") or os.getenv("MCP_PORT", "8772")))
    public_url: str = field(default_factory=lambda: os.getenv("MCP_PUBLIC_URL", "").rstrip("/"))

    # ── Who is calling. `knox` verifies a KNOXTOKEN offline against Knox's JWKS; `development` trusts DEV_USER. ──
    auth_mode: str = field(default_factory=lambda: os.getenv("AUTH_MODE", "knox").strip().lower())
    dev_user: str = field(default_factory=lambda: os.getenv("DEV_USER", "developer"))
    knox_jwks_url: str = field(default_factory=lambda: os.getenv("KNOX_JWKS_URL", ""))
    knox_jwks_file: str = field(default_factory=lambda: os.getenv("KNOX_JWKS_FILE", ""))
    knox_issuer: str = field(default_factory=lambda: os.getenv("KNOX_ISS", "KNOXSSO"))
    knox_audience: str = field(default_factory=lambda: os.getenv("KNOX_AUD", ""))  # empty skips the audience check
    knox_token_url: str = field(default_factory=lambda: os.getenv("KNOX_TOKEN_URL", ""))  # advertised to MCP clients (RFC 9728)
    jwks_timeout: int = field(default_factory=lambda: int(os.getenv("MCP_JWKS_TIMEOUT", "10")))

    # ── Impala. The MCP authenticates as ONE proxy principal and impersonates the caller with ?doAs=<user>. ──
    impala_host: str = field(default_factory=lambda: os.getenv("IMPALA_HOST", ""))
    impala_port: int = field(default_factory=lambda: int(os.getenv("IMPALA_PORT", "443")))
    impala_database: str = field(default_factory=lambda: os.getenv("IMPALA_DATABASE", "default"))
    impala_auth: str = field(default_factory=lambda: os.getenv("IMPALA_AUTH_MECHANISM", "GSSAPI").upper())
    impala_service_name: str = field(default_factory=lambda: os.getenv("IMPALA_SVC_NAME", "hive"))  # CDW VW SPN service name
    impala_krb_host: str = field(default_factory=lambda: os.getenv("KRB_FQDN", ""))  # VW SPN host; differs from the connect host on CDW
    impala_http_path: str = field(default_factory=lambda: os.getenv("IMPALA_HTTP_PATH", "cliservice"))
    impala_use_ssl: bool = field(default_factory=lambda: flag("IMPALA_USE_SSL", True))
    impala_ca_cert: str = field(default_factory=lambda: os.getenv("IMPALA_CA_CERT", ""))
    impala_timeout: int = field(default_factory=lambda: int(os.getenv("IMPALA_TIMEOUT", "60")))
    impala_user: str = field(default_factory=lambda: os.getenv("IMPALA_USER", ""))  # LDAP only
    impala_password: str = field(default_factory=lambda: os.getenv("IMPALA_PASSWORD", ""))  # LDAP only
    impersonate: bool = field(default_factory=lambda: flag("IMPALA_IMPERSONATE", True))

    # ── Kerberos proxy identity: the "I may impersonate" credential. Never the end user's. ──
    keytab: str = field(default_factory=lambda: os.getenv("MCP_KEYTAB", ""))
    principal: str = field(default_factory=lambda: os.getenv("MCP_PRINC", ""))
    kinit_interval: int = field(default_factory=lambda: int(os.getenv("KINIT_INTERVAL_SECONDS", str(6 * 3600))))
    ccache_dir: str = field(default_factory=lambda: os.getenv("KRB5_CCACHE_DIR", os.path.join(os.path.expanduser("~"), ".governed-mcp")))

    # ── Results. ──
    default_limit: int = field(default_factory=lambda: int(os.getenv("QUERY_DEFAULT_LIMIT", "500")))
    max_limit: int = field(default_factory=lambda: int(os.getenv("QUERY_MAX_LIMIT", "5000")))

    def check(self):
        problems = []
        if self.auth_mode not in ("knox", "development"):
            problems.append("AUTH_MODE must be knox or development")
        if self.auth_mode == "knox" and not (self.knox_jwks_url or self.knox_jwks_file):
            problems.append("AUTH_MODE=knox needs KNOX_JWKS_URL (or KNOX_JWKS_FILE) to verify tokens")
        if not self.impala_host:
            problems.append("IMPALA_HOST is required (the CDW Impala coordinator host)")
        if self.impala_auth == "GSSAPI":
            if not (self.keytab and self.principal):
                problems.append("GSSAPI needs MCP_KEYTAB and MCP_PRINC (the proxy principal that may impersonate callers)")
            if not self.impala_krb_host:
                problems.append("GSSAPI needs KRB_FQDN (the virtual warehouse's SPN host, from describe-vw kerberosImpalaShell)")
        elif self.impala_auth == "LDAP":
            if not (self.impala_user and self.impala_password):
                problems.append("LDAP needs IMPALA_USER and IMPALA_PASSWORD")
        else:
            problems.append("IMPALA_AUTH_MECHANISM must be GSSAPI or LDAP")
        return problems
