import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from governed_iceberg_mcp.auth import Verifier
from governed_iceberg_mcp.settings import Settings


def test_a_knox_token_verifies_to_its_subject(settings, keys):
    assert Verifier(settings).verify(keys["mint"]("analyst1")) == "analyst1"
    assert Verifier(settings).warm() == ["knox-1"]


def test_bad_tokens_are_rejected_before_any_tool_runs(settings, keys):
    verifier = Verifier(settings)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    for bad, why in ((keys["mint"]("analyst1", expires_in=-5), "expired"), (keys["mint"]("analyst1", issuer="someone-else"), "issuer"),
            (keys["mint"]("analyst1", audience="other-topology"), "audience"), (keys["mint"]("", ), "no sub"),
            (keys["mint"]("analyst1", key=other), "signed by another key"), (keys["mint"]("analyst1", kid="unknown"), "unknown kid"), ("not.a.token", "garbage")):
        with pytest.raises(Exception):
            verifier.verify(bad), why


def test_audience_check_is_optional(settings, keys, monkeypatch):
    monkeypatch.setenv("KNOX_AUD", "")
    assert Verifier(Settings()).verify(keys["mint"]("analyst2", audience=None)) == "analyst2"


def test_configuration_problems_are_named(monkeypatch):
    monkeypatch.setenv("AUTH_MODE", "knox")
    for name in ("KNOX_JWKS_URL", "KNOX_JWKS_FILE", "IMPALA_HOST", "MCP_KEYTAB", "MCP_PRINC", "KRB_FQDN"):
        monkeypatch.delenv(name, raising=False)
    problems = Settings().check()
    assert any("KNOX_JWKS_URL" in p for p in problems) and any("IMPALA_HOST" in p for p in problems) and any("MCP_KEYTAB" in p for p in problems)
    monkeypatch.setenv("IMPALA_AUTH_MECHANISM", "LDAP"); monkeypatch.setenv("IMPALA_HOST", "h"); monkeypatch.setenv("KNOX_JWKS_URL", "https://knox/jwks")
    assert Settings().check() == ["LDAP needs IMPALA_USER and IMPALA_PASSWORD"]
