"""Per-user access to CDW Impala.

The MCP authenticates as one constant proxy principal (its keytab) and passes the caller in the HS2-HTTP path,
`cliservice?doAs=<user>`: exactly how Knox and the Impala JDBC driver delegate, so it is version-independent.
Impala checks the proxy's short name against --authorized_proxy_user_config and runs the session as the caller,
which is the identity Ranger authorizes. Who may impersonate is in the ticket; who is impersonated is per call.

Do not combine this with the `impala.doas.user` session option: Impala rejects requests that set both.
"""
import logging
import os
import subprocess
import threading
import time
from urllib.parse import quote

from impala.dbapi import connect

from .observability import query_fingerprint

log = logging.getLogger("governed-mcp.impala")


class Kerberos:
    """Keeps a ticket for the proxy principal in a private credential cache, renewed on an interval."""

    def __init__(self, settings):
        self.settings = settings
        self.lock = threading.Lock()
        self.obtained = 0.0
        os.makedirs(settings.ccache_dir, mode=0o700, exist_ok=True)
        os.environ["KRB5CCNAME"] = "FILE:" + os.path.join(settings.ccache_dir, f"krb5cc_mcp_{os.getpid()}")

    def ensure(self, force=False):
        with self.lock:
            if not force and time.monotonic() - self.obtained < self.settings.kinit_interval:
                return
            started = time.monotonic()
            result = subprocess.run(["kinit", "-kt", self.settings.keytab, self.settings.principal], capture_output=True, text=True, timeout=60)
            if result.returncode:
                raise RuntimeError(f"kinit failed for {self.settings.principal} with keytab {self.settings.keytab}: {(result.stderr or result.stdout).strip()}")
            self.obtained = time.monotonic()
            log.info("kinit %s ok in %.1fs (cache %s)", self.settings.principal, time.monotonic() - started, os.environ["KRB5CCNAME"])


class Impala:
    def __init__(self, settings, state=None):
        self.settings = settings
        self.state = state
        self.kerberos = Kerberos(settings) if settings.impala_auth == "GSSAPI" else None

    def http_path(self, user):
        path = self.settings.impala_http_path.lstrip("/")
        if not self.settings.impersonate:
            return path
        return f"{path}{'&' if '?' in path else '?'}doAs={quote(user, safe='')}"

    def connect_as(self, user):
        s = self.settings
        common = dict(host=s.impala_host, port=s.impala_port, database=s.impala_database, timeout=s.impala_timeout,
            use_ssl=s.impala_use_ssl, ca_cert=s.impala_ca_cert or None, use_http_transport=True, http_path=self.http_path(user))
        if s.impala_auth == "GSSAPI":
            self.kerberos.ensure()
            return connect(auth_mechanism="GSSAPI", kerberos_service_name=s.impala_service_name, krb_host=s.impala_krb_host, **common)
        return connect(auth_mechanism="LDAP", user=s.impala_user, password=s.impala_password, **common)

    def run(self, user, sql, limit):
        """Run one statement as `user`; return columns and up to `limit` rows (plus whether more were cut off)."""
        started = time.monotonic()
        try:
            connection = self.connect_as(user)
        except Exception as exc:
            ticket_problem = self.kerberos is not None and any(word in str(exc).upper() for word in ("GSS", "KERBEROS", "TICKET"))
            if not ticket_problem:
                raise
            self.kerberos.ensure(force=True)  # a stale ticket: renew once and retry
            connection = self.connect_as(user)
        try:
            cursor = connection.cursor()
            cursor.execute(sql)
            columns = [d[0] for d in cursor.description or []]
            rows = cursor.fetchmany(limit + 1) if cursor.description else []
            truncated = len(rows) > limit
            result = {"columns": columns, "rows": [list(r) for r in rows[:limit]], "row_count": min(len(rows), limit), "truncated": truncated,
                "duration_ms": int((time.monotonic() - started) * 1000)}
            cursor.close()
            if self.state:
                self.state.event("query_succeeded", user=user, fingerprint=query_fingerprint(sql), rows=result["row_count"],
                    truncated=result["truncated"], duration_ms=result["duration_ms"])
            return result
        except Exception as exc:
            if self.state:
                self.state.event("query_failed", user=user, fingerprint=query_fingerprint(sql),
                    duration_ms=int((time.monotonic() - started) * 1000), error=str(exc)[:300])
            raise
        finally:
            if "connection" in locals():
                connection.close()
