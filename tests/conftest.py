import json
import sys
import time
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from governed_iceberg_mcp.settings import Settings  # noqa: E402


class FakeImpala:
    """Stands in for the warehouse: records who asked for what and answers with canned rows."""

    def __init__(self):
        self.calls = []
        self.answers = {"SHOW DATABASES": (["name", "comment"], [["default", ""], ["sales", "Sales data"]]),
            "SHOW TABLES IN sales": (["name"], [["orders"], ["customers"]]),
            "DESCRIBE sales.orders": (["name", "type", "comment"], [["id", "bigint", ""], ["region", "string", "Sales region"], ["amount", "decimal(10,2)", ""]])}
        self.rows_for_user = {"analyst1": [[1, "west", 10], [2, "east", 20], [3, "west", 30], [4, "north", 40]], "analyst2": [[1, "west", 10], [3, "west", 30]]}

    def run(self, user, sql, limit):
        self.calls.append((user, sql, limit))
        if sql in self.answers:
            columns, rows = self.answers[sql]
        else:
            columns, rows = ["id", "region", "amount"], self.rows_for_user.get(user, [])
        return {"columns": columns, "rows": rows[:limit], "row_count": min(len(rows), limit), "truncated": len(rows) > limit, "duration_ms": 1}


@pytest.fixture
def keys(tmp_path):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    jwk["kid"] = "knox-1"; jwk["use"] = "sig"; jwk["alg"] = "RS256"
    jwks = tmp_path / "jwks.json"
    jwks.write_text(json.dumps({"keys": [jwk]}))
    pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

    def mint(sub, issuer="KNOXSSO", audience="agent-proxy", expires_in=3600, kid="knox-1", key=pem):
        claims = {"sub": sub, "iss": issuer, "exp": int(time.time()) + expires_in}
        if audience:
            claims["aud"] = audience
        return jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})

    return {"jwks": jwks, "mint": mint}


@pytest.fixture
def settings(keys, monkeypatch):
    for name, value in {"AUTH_MODE": "knox", "KNOX_JWKS_FILE": str(keys["jwks"]), "KNOX_ISS": "KNOXSSO", "KNOX_AUD": "agent-proxy",
            "KNOX_TOKEN_URL": "https://knox.example/gateway/agent-token/knoxtoken/api/v2/token", "MCP_PUBLIC_URL": "https://mcp.example",
            "IMPALA_HOST": "coordinator.example", "IMPALA_AUTH_MECHANISM": "GSSAPI", "MCP_KEYTAB": "/tmp/mcp.keytab", "MCP_PRINC": "mcpclient@EXAMPLE.REALM",
            "KRB_FQDN": "vw-spn.example", "IMPALA_DATABASE": "default", "QUERY_DEFAULT_LIMIT": "3", "QUERY_MAX_LIMIT": "10"}.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("CDSW_APP_PORT", raising=False)
    return Settings()
