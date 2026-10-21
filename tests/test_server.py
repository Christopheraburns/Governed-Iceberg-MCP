import json

import pytest
from starlette.testclient import TestClient

from conftest import FakeImpala
from governed_iceberg_mcp.server import build_app
from governed_iceberg_mcp.settings import Settings
from governed_iceberg_mcp.tools import read_only

HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}


def rpc(client, method, params=None, token=None, id=1):
    headers = {**HEADERS, **({"Authorization": f"Bearer {token}"} if token else {})}
    response = client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "id": id, "method": method, "params": params or {}})
    if response.status_code != 200:
        return response.status_code, response.json()
    body = response.text
    if body.startswith("event:") or "\ndata:" in body or body.startswith("data:"):
        body = next(line[5:].strip() for line in body.splitlines() if line.startswith("data:"))
    return response.status_code, json.loads(body)


def call(client, token, name, arguments=None):
    status, message = rpc(client, "tools/call", {"name": name, "arguments": arguments or {}}, token)
    assert status == 200, message
    return message["result"]


@pytest.fixture
def stack(settings):
    impala = FakeImpala()
    with TestClient(build_app(settings, impala=impala)) as client:
        yield client, impala


def test_health_and_resource_metadata_need_no_token(stack):
    client, _ = stack
    health = client.get("/healthz").json()
    assert health["status"] == "ok" and health["auth_mode"] == "knox"
    metadata = client.get("/.well-known/oauth-protected-resource").json()
    assert metadata == {"resource": "https://mcp.example/mcp", "authorization_servers": ["https://knox.example/gateway/agent-token/knoxtoken/api/v2/token"],
        "bearer_methods_supported": ["header"]}


def test_mcp_without_a_valid_token_is_refused_fail_closed(stack, keys):
    client, impala = stack
    status, body = rpc(client, "tools/list")
    assert status == 401 and body == {"error": "missing Knox bearer token"}
    response = client.post("/mcp", headers={**HEADERS, "Authorization": "Bearer nonsense"}, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert response.status_code == 401 and response.headers["WWW-Authenticate"] == 'Bearer resource_metadata="https://mcp.example/.well-known/oauth-protected-resource"'
    status, _ = rpc(client, "tools/call", {"name": "execute_query", "arguments": {"query": "SELECT 1"}}, keys["mint"]("analyst1", expires_in=-1))
    assert status == 401 and impala.calls == []  # nothing reached the warehouse


def test_the_catalog_lists_the_five_tools(stack, keys):
    client, _ = stack
    status, init = rpc(client, "initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}, keys["mint"]("analyst1"))
    assert status == 200 and init["result"]["serverInfo"]["name"] == "Governed Iceberg MCP"
    status, listing = rpc(client, "tools/list", token=keys["mint"]("analyst1"))
    assert sorted(t["name"] for t in listing["result"]["tools"]) == ["describe_table", "execute_query", "get_schema", "list_databases", "whoami"]
    query = next(t for t in listing["result"]["tools"] if t["name"] == "execute_query")
    assert query["inputSchema"]["required"] == ["query"] and "Ranger" in query["description"]


def test_queries_run_as_the_token_subject_and_results_differ_per_user(stack, keys):
    client, impala = stack
    sql = "SELECT id, region, amount FROM sales.orders ORDER BY id"
    first = call(client, keys["mint"]("analyst1"), "execute_query", {"query": sql, "limit": 10})["structuredContent"]
    second = call(client, keys["mint"]("analyst2"), "execute_query", {"query": sql, "limit": 10})["structuredContent"]
    assert first["row_count"] == 4 and second["row_count"] == 2
    assert [c[0] for c in impala.calls] == ["analyst1", "analyst2"] and impala.calls[0][1] == sql
    who = call(client, keys["mint"]("analyst2"), "whoami")["structuredContent"]
    assert who["user"] == "analyst2" and who["impersonation"].startswith("doAs=analyst2 via GSSAPI proxy mcpclient@EXAMPLE.REALM")


def test_limits_are_clamped_and_truncation_reported(stack, keys):
    client, impala = stack
    result = call(client, keys["mint"]("analyst1"), "execute_query", {"query": "SELECT * FROM sales.orders"})["structuredContent"]
    assert result["row_count"] == 3 and result["truncated"] is True and impala.calls[-1][2] == 3  # QUERY_DEFAULT_LIMIT
    call(client, keys["mint"]("analyst1"), "execute_query", {"query": "SELECT * FROM sales.orders", "limit": 999})
    assert impala.calls[-1][2] == 10  # QUERY_MAX_LIMIT


def test_catalog_tools_use_the_default_database_and_validate_identifiers(stack, keys):
    client, impala = stack
    token = keys["mint"]("analyst1")
    assert call(client, token, "list_databases")["structuredContent"] == {"databases": ["default", "sales"]}
    assert call(client, token, "get_schema", {"database": "sales"})["structuredContent"] == {"database": "sales", "tables": ["orders", "customers"]}
    described = call(client, token, "describe_table", {"table": "orders", "database": "sales"})["structuredContent"]
    assert described["columns"][1] == {"name": "region", "type": "string", "comment": "Sales region"}
    call(client, token, "get_schema")
    assert impala.calls[-1][1] == "SHOW TABLES IN default"
    result = call(client, token, "describe_table", {"table": "orders; DROP TABLE x"})
    assert result["isError"] and "plain identifier" in result["content"][0]["text"]


def test_only_read_only_statements_pass_the_guard():
    assert read_only("  select 1;  ") == "select 1"
    for sql in ("DROP TABLE t", "insert into t values (1)", "select 1; select 2", "", "ALTER TABLE t ADD COLUMNS (x int)"):
        with pytest.raises(ValueError):
            read_only(sql)
    assert read_only("WITH x AS (SELECT 1) SELECT * FROM x").startswith("WITH")
    for sql in ("WITH x AS (SELECT 1) INSERT INTO t SELECT * FROM x", "WITH x AS (SELECT 1) UPDATE t SET a = 1",
                "WITH x AS (SELECT 1) DELETE FROM t"):
        with pytest.raises(ValueError):
            read_only(sql)


def test_development_mode_trusts_the_configured_user(settings, monkeypatch):
    monkeypatch.setenv("AUTH_MODE", "development"); monkeypatch.setenv("DEV_USER", "localdev")
    impala = FakeImpala()
    with TestClient(build_app(Settings(), impala=impala)) as client:
        status, body = rpc(client, "tools/call", {"name": "whoami", "arguments": {}})  # no token at all
        assert status == 200 and body["result"]["structuredContent"]["user"] == "localdev"
        assert client.get("/healthz").json()["auth_mode"] == "development"
