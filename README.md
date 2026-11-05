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

## Authorization model

The MCP does not authorize anything itself. It establishes *who* is calling, propagates that identity to Impala,
and leaves every allow/deny decision to Ranger. The read-only check in `tools.py` guards against accidents; it is
not a security boundary. Two independent layers each have a switch:

| Layer | Setting | Options |
|---|---|---|
| Caller identity: who the agent acts for | `AUTH_MODE` | `knox` (production) or `development` |
| Warehouse connection: how the MCP reaches Impala | `IMPALA_AUTH_MECHANISM` + `IMPALA_IMPERSONATE` | `GSSAPI` or `LDAP`, impersonation on or off |

The management application uses a third, separate scheme (see below).

### Caller identity

**`AUTH_MODE=knox` — Knox JWT bearer token (production).** The client sends `Authorization: Bearer <KNOXTOKEN>`.
`AuthMiddleware` verifies it offline: RS256 signature against Knox's JWKS (cached, refetched on an unknown `kid`),
`iss`, `exp`, and `aud` when `KNOX_AUD` is set. `sub` becomes the user and travels to the tools in a context
variable, so tools never see the token. Any failure is a fail-closed 401 carrying
`WWW-Authenticate: Bearer resource_metadata=...`, and `/.well-known/oauth-protected-resource` (RFC 9728) tells
clients where tokens are minted. The MCP never mints tokens; Knox does, after a SPNEGO or LDAP login against the
token topology. Keys come from `KNOX_JWKS_URL`, or from `KNOX_JWKS_FILE` on air-gapped hosts that cannot reach
Knox at runtime.

Use it when:
- An analyst in n8n, Copilot or Claude asks questions of `sales.orders` and must only see her region's rows. She
  runs `kinit`, fetches a Knox token, and every query runs as her; Ranger's row filter does the rest, and the
  audit log shows her name rather than a service account.
- One "data copilot" is deployed for a whole department whose members have different column-masking policies.
  One deployment, per-user results, nothing per-user to configure on the MCP.

**`AUTH_MODE=development` — trust `DEV_USER`.** No token is checked; every request is treated as `DEV_USER`
and the server logs a warning at startup. Use it for local wiring tests without a cluster, or to reproduce a
Ranger policy problem as a specific user (`DEV_USER=analyst1`) against a dev warehouse. Never expose it beyond
a private network.

### Warehouse connection

**`IMPALA_AUTH_MECHANISM=GSSAPI` with `IMPALA_IMPERSONATE=true` (the intended production pairing).** The server
keeps a ticket for `MCP_PRINC` in a private credential cache (`kinit -kt` at startup, every
`KINIT_INTERVAL_SECONDS`, and once more after a GSSAPI failure), opens one impyla connection per request, and
passes `cliservice?doAs=<user>`. The proxy's short name must be in the virtual warehouse's
`--authorized_proxy_user_config`. This is the delegation mechanism Knox and the Impala JDBC driver use, so it
is version-independent. Use it on any Kerberized CDW deployment where per-user Ranger enforcement is the goal,
which is the point of this project.

**`IMPALA_AUTH_MECHANISM=LDAP` — service account.** Connects with `IMPALA_USER` / `IMPALA_PASSWORD`.
Impersonation can stay on (it works only if that LDAP account is an authorized proxy) or be turned off. Use it:
- In development against a non-Kerberized or LDAP-only warehouse where no keytab is available.
- With `IMPALA_IMPERSONATE=false` for a deliberately ungoverned deployment where every caller should see exactly
  what one service account sees, such as a sanitized reference dataset. `whoami` reports
  `none: queries run as the service account ...` in that case, so nobody mistakes it for governed access.

### Management application

`management_app.py` runs with Workbench authentication *enabled*, so Workbench's own login applies and the app
reads the `REMOTE-USER` and permission headers. Operators must be listed in `MANAGEMENT_ADMIN_USERS` or hold
RW/ADMIN project permission. It controls the MCP process (JWKS refresh, Kerberos renewal, maintenance mode)
and does not administer Ranger, Knox or the warehouse.

### Known weakness

Offline verification cannot revoke a still-valid token: a stolen token works until it expires. Keep Knox token
TTLs short or enable server-managed tokens. A per-request introspection call, or a short-lived cache of a
revocation list, would close the gap.

### OAuth 1 and OAuth 2

Neither is supported. `AUTH_MODE` accepts only `knox` and `development`, and the verifier is Knox-specific
(RS256, `iss=KNOXSSO`, `sub` taken as the raw username).

**OAuth 1.0a** should not be added. It is a request-signing scheme (HMAC over request parameters with a consumer
secret) from before TLS was universal; it is effectively deprecated, no MCP client implements it, and the MCP
authorization specification is built on OAuth 2.1 bearer tokens. Supporting it would mean per-request signature
verification for a client population of zero.

**OAuth 2.0 / 2.1** is a natural extension, and the scaffolding is half there: bearer-in-header, RFC 9728
resource metadata and the `WWW-Authenticate` challenge are exactly what the MCP spec expects of a resource
server. Two levels of ambition:

1. *Accept OIDC/OAuth 2 access tokens from an enterprise IdP* (Keycloak, Okta, Entra ID). This is a second
   `Verifier` with its own JWKS URL, issuer and audience, plus a claim-mapping rule
   (`preferred_username` / `email` / `upn` → the Ranger username). An `AUTH_MODE=oidc`, or a list of trusted
   issuers keyed by `iss`, lets one deployment accept both Knox and IdP tokens. Introspection (RFC 7662) against
   the IdP would also address the revocation weakness above. The hard requirement is that the IdP identity resolve
   to the principal Ranger knows, which usually holds in CDP because both sit on the same LDAP/AD.
2. *Full MCP-spec OAuth 2.1* so clients such as Claude Desktop or Cursor can run the interactive login
   themselves: PKCE, dynamic or pre-registered clients, and `authorization_servers` in the well-known document
   pointing at a real authorization server rather than Knox's mint URL. Downstream nothing changes: `doAs` needs
   only a username, so no token exchange is required unless the proxy keytab is to be replaced by per-user Knox
   delegation tokens.

Option 1 is a few dozen lines and should come first.

### When this server is the wrong choice

- **Autonomous or scheduled agents with no human principal.** The model assumes a person obtained a Knox token
  through their own Kerberos or LDAP login and the agent acts on their behalf. A nightly data-quality agent, a
  Slack bot answering a channel, or a multi-tenant SaaS front end has no calling user in the cluster's identity
  domain. The options are sharing one human's token (an audit and revocation problem) or
  `IMPALA_IMPERSONATE=false`, which runs everything as the proxy account and discards the governance that
  justifies the server. Those workloads need a dedicated service identity with its own Ranger policies, or a
  purpose-built server with narrower tools.
- **Write, ETL or heavy analytical workloads.** The server is read-only, caps results at `QUERY_MAX_LIMIT`
  (default 5,000) rows, has no pagination or query cancellation, and opens a fresh HS2 connection per call. An
  agent that needs to materialize a table, run a 30-minute scan or stream a large extract will hit every one of
  those limits. Spark, NiFi or direct Impala JDBC are the right tools; an agent in the loop should orchestrate
  them rather than query through this MCP.
- **Iceberg that is not behind Knox, Impala and Ranger.** The identity-propagation trick is HS2 `doAs`
  specific. Tables reached through a REST catalog and Trino, Snowflake or Athena have none of these pieces, so
  nothing here transfers.

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

## Management and monitoring application

The management_app.py file is a companion Cloudera AI Workbench application. Run it as a second application in the
same project, with Workbench authentication enabled and the same MCP_STATE_DIR as the MCP server. Do not enable
bypass authentication for the management application.

The MCP writes a redacted status.json and append-only events.jsonl to MCP_STATE_DIR. The management application renders
service health, query/auth activity, recent events, Kerberos status, and operational buttons for JWKS refresh, Kerberos
renewal, and maintenance mode. Commands are written to actions.jsonl and consumed by the MCP process.

Set MANAGEMENT_ADMIN_USERS for explicit operators, or allow Workbench users with REMOTE-USER-PERM=RW or ADMIN. The
application can be visualized with an embedded dashboard now; the event files are also a straightforward source for a
later Prometheus/OpenTelemetry exporter. The management application does not administer Ranger, Knox, CDW virtual
warehouses, or Workbench itself.

Create the second Workbench application with:

    Script: management_app.py
    Port: CDSW_APP_PORT
    Authentication: enabled
    Environment: MCP_STATE_DIR=<the same shared project-storage directory>
