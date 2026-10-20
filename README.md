# Governed Iceberg MCP (standalone)

A self-contained MCP server for Cloudera AI Workbench that lets agents query Iceberg tables through Impala
**as the calling user**, so Ranger enforces that user's row and column policies. It is independent of Daedalus
and lives in this repository for reference only: nothing here imports from the rest of the repo.

It joins three proven pieces:

| Piece | Origin | What is reused |
|---|---|---|
| Tools | [cloudera/iceberg-mcp-server](https://github.com/cloudera/iceberg-mcp-server) | FastMCP + impyla; `execute_query` and `get_schema`, extended with `list_databases`, `describe_table` and `whoami` |
| Identity | knox-doas-cdw-mcp (Cloudera field work) | Offline verification of the Knox token against Knox's JWKS, `sub` = the account; one constant proxy principal impersonates the caller with `cliservice?doAs=<user>`; fail-closed 401; RFC 9728 resource metadata |
| Hosting | Daedalus `deploy/workbench/launch_server.py` | Workbench application entrypoint: listens on `CDSW_APP_PORT`, survives the IPython kernel launch, relays logs to project storage, shows the last 40 lines on failure |

## How a request flows

```
agent (n8n / Copilot / Claude)
  │ POST /mcp  Authorization: Bearer <KNOXTOKEN>
  ▼
AuthMiddleware ── verify RS256 offline against Knox JWKS (iss, aud, exp) ──► sub = analyst1   (else 401, nothing runs)
  ▼
tool (execute_query …) runs as analyst1
  ▼
impyla ── GSSAPI as the proxy principal (keytab) ── HTTP path cliservice?doAs=analyst1 ──► CDW Impala VW
                                                                                           └─► Ranger: analyst1's policies
```

The MCP never holds user credentials. The ticket proves the MCP *may* impersonate; `doAs` says *who* each call
runs as. The two must not be combined with the `impala.doas.user` session option (Impala rejects both at once).

## Tools

| Tool | Does | Runs |
|---|---|---|
| `whoami` | Reports the verified account and how it is impersonated | nothing on the warehouse |
| `list_databases` | Databases visible to the caller | `SHOW DATABASES` |
| `get_schema(database?)` | Tables in a database (default: `IMPALA_DATABASE`) | `SHOW TABLES IN db` |
| `describe_table(table, database?)` | Columns, types and comments | `DESCRIBE db.table` |
| `execute_query(query, limit?)` | Read-only SQL; returns `columns`, `rows`, `row_count`, `truncated` | the statement, capped at `QUERY_MAX_LIMIT` rows |

`execute_query` accepts one statement starting with SELECT, WITH, SHOW, DESCRIBE or EXPLAIN. That check guards
against accidents; Ranger is the security boundary.

## Deploy as a Workbench application

1. Put this directory in the project (for example `daedalus/Standalone`, or on its own).
2. In a Workbench session: `pip install -r requirements.txt`. The `kerberos` package builds against the
   krb5 client libraries, which the Cloudera runtimes ship.
3. Put the proxy keytab in project storage (for example `~/.keytabs/mcpclient.keytab`, mode 600). Its short
   name must be listed in the virtual warehouse's `--authorized_proxy_user_config`.
4. Set the environment variables from [env.example](env.example) on the project or the application. The
   required ones are `KNOX_JWKS_URL`, `IMPALA_HOST`, `KRB_FQDN`, `MCP_KEYTAB`, `MCP_PRINC`, and
   `MCP_PUBLIC_URL` (the application's URL, advertised to clients).
5. Create an application: script `Standalone/app.py` (path relative to the project root), the Python runtime,
   and **Bypass authentication** turned on, because clients present a Knox token, not a Workbench session.
6. Start it. The application log shows a start banner and either `Knox JWKS ready: kids [...]` and
   `kinit ... ok`, or the reason one of them failed. The full log is in `~/.governed-mcp/logs/server.log`.

Then connect a client to `https://<application-subdomain>.<workbench-domain>/mcp` with
`Authorization: Bearer <KNOXTOKEN>` (HTTP streamable transport, stateless).

### Getting a Knox token for a test

```bash
kinit analyst1
TOKEN=$(curl -s --negotiate -u : 'https://<knox-host>:8443/gateway/<token-topology>/knoxtoken/api/v2/token' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s "$MCP_PUBLIC_URL/mcp" -H "Authorization: Bearer $TOKEN" -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami","arguments":{}}}'
```

Repeat as a second user with a different Ranger policy to see the row counts differ on the same query.

## Run locally without a cluster

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
AUTH_MODE=development DEV_USER=analyst1 IMPALA_HOST=coordinator.example IMPALA_AUTH_MECHANISM=LDAP \
IMPALA_USER=x IMPALA_PASSWORD=x MCP_PORT=8772 .venv/bin/python -m governed_iceberg_mcp
```

`AUTH_MODE=development` trusts `DEV_USER` for every call and logs a warning; it is for local wiring tests only.
`whoami`, `tools/list` and the guard rails work without a warehouse; queries fail until `IMPALA_HOST` is real.

Tests: `.venv/bin/python -m pytest tests`. They mint tokens with a generated key and stand in a fake
warehouse, so they run anywhere.

## Settings

Every value comes from the environment; see [env.example](env.example) for the full list with comments.
The groups are: who is calling (`AUTH_MODE`, `KNOX_*`), the warehouse (`IMPALA_*`, `KRB_FQDN`), the proxy
identity (`MCP_KEYTAB`, `MCP_PRINC`, `KINIT_INTERVAL_SECONDS`), and serving (`MCP_BIND`, `MCP_PUBLIC_URL`,
`QUERY_*_LIMIT`). `IMPALA_AUTH_MECHANISM=LDAP` with a service account is supported for development; with
`IMPALA_IMPERSONATE=true` it still sends `doAs`, which works only if that account is an authorized proxy.

## Operational notes

- **Token lifetime.** Offline verification cannot revoke a still-valid token. Keep Knox token TTLs short, or
  enable Knox server-managed tokens so a token can be revoked; rotating the Knox signing key invalidates all.
- **Ticket renewal.** The server runs `kinit -kt` into a private credential cache at startup and every
  `KINIT_INTERVAL_SECONDS`, and once more on a GSSAPI failure before retrying the query.
- **Concurrency.** Each request opens its own Impala connection and closes it. The credential cache is shared
  within the process, which is fine because the principal never changes.
- **Health.** `GET /healthz` needs no token and reports version, auth mode, warehouse and start time.
- **Not included.** Token minting (Knox does it), writes, Keycloak introspection (a possible second auth
  mode), result pagination and query cancellation.
