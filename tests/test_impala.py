import subprocess

import pytest

from governed_iceberg_mcp import impala as module
from governed_iceberg_mcp.impala import Impala


class FakeCursor:
    def __init__(self, rows):
        self.rows = rows; self.description = [("id",), ("region",)] if rows is not None else None; self.sql = None
    def execute(self, sql): self.sql = sql
    def fetchmany(self, n): return self.rows[:n]
    def close(self): pass


class FakeConnection:
    def __init__(self, rows): self.cursor_ = FakeCursor(rows); self.closed = False
    def cursor(self): return self.cursor_
    def close(self): self.closed = True


def test_the_caller_travels_in_the_http_path_as_doas(settings, monkeypatch):
    seen = {}
    monkeypatch.setattr(module, "connect", lambda **kw: seen.update(kw) or FakeConnection([[1, "west"], [2, "east"], [3, "north"]]))
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, "", ""))
    result = Impala(settings).run("ana lyst/1", "SELECT * FROM t", 2)
    assert seen["http_path"] == "cliservice?doAs=ana%20lyst%2F1" and seen["auth_mechanism"] == "GSSAPI"
    assert seen["krb_host"] == "vw-spn.example" and seen["kerberos_service_name"] == "hive" and seen["use_http_transport"] is True
    assert result["columns"] == ["id", "region"] and result["rows"] == [[1, "west"], [2, "east"]] and result["truncated"] is True


def test_impersonation_can_be_switched_off_and_ldap_uses_the_service_account(settings, monkeypatch):
    monkeypatch.setenv("IMPALA_IMPERSONATE", "false"); monkeypatch.setenv("IMPALA_AUTH_MECHANISM", "LDAP")
    monkeypatch.setenv("IMPALA_USER", "svc"); monkeypatch.setenv("IMPALA_PASSWORD", "pw")
    from governed_iceberg_mcp.settings import Settings
    seen = {}
    monkeypatch.setattr(module, "connect", lambda **kw: seen.update(kw) or FakeConnection([]))
    Impala(Settings()).run("analyst1", "SHOW TABLES", 5)
    assert seen["http_path"] == "cliservice" and seen["auth_mechanism"] == "LDAP" and seen["user"] == "svc"


def test_a_failed_kinit_is_reported_with_the_principal(settings, monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 1, "", "kinit: Keytab contains no suitable keys"))
    with pytest.raises(RuntimeError, match="mcpclient@EXAMPLE.REALM.*no suitable keys"):
        Impala(settings).run("analyst1", "SELECT 1", 1)


def test_a_stale_ticket_is_renewed_once_and_the_query_retried(settings, monkeypatch):
    kinits = []
    monkeypatch.setattr(subprocess, "run", lambda cmd, **k: kinits.append(cmd) or subprocess.CompletedProcess(cmd, 0, "", ""))
    attempts = []
    def connect(**kw):
        attempts.append(kw)
        if len(attempts) == 1:
            raise RuntimeError("GSSAPI Error: Ticket expired")
        return FakeConnection([[1, "x"]])
    monkeypatch.setattr(module, "connect", connect)
    assert Impala(settings).run("analyst1", "SELECT 1", 5)["row_count"] == 1
    assert len(attempts) == 2 and len(kinits) == 2  # one at first use, one forced renewal
