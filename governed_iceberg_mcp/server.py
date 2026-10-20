"""The MCP server: FastMCP over stateless streamable HTTP, wrapped in Knox token verification.

Routes:
  POST /mcp                                   JSON-RPC (initialize, tools/list, tools/call); bearer token required
  GET  /.well-known/oauth-protected-resource  RFC 9728: where tokens come from
  GET  /healthz                               liveness, no token needed
"""
import logging
import socket
import sys
import time
from datetime import datetime, timezone

import uvicorn
from fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from . import __version__, tools
from .auth import AuthMiddleware, Verifier, resource_metadata
from .impala import Impala
from .settings import Settings

log = logging.getLogger("governed-mcp")
STARTED = datetime.now(timezone.utc).isoformat()


def build_app(settings, impala=None, verifier=None):
    problems = settings.check()
    if problems:
        raise SystemExit("Configuration problems:\n  - " + "\n  - ".join(problems))
    impala = impala or Impala(settings)
    verifier = verifier or (Verifier(settings) if settings.auth_mode == "knox" else None)
    mcp = FastMCP(name="Governed Iceberg MCP", version=__version__, instructions=(
        "Read-only access to Iceberg tables through Impala. Every call runs as the signed-in user, so results reflect "
        "that user's Ranger policies. Start with list_databases and get_schema to find tables, describe_table for "
        "columns, then execute_query."))
    tools.register(mcp, impala, settings)
    mcp_app = mcp.http_app(path="/mcp", stateless_http=True, transport="streamable-http",
        middleware=[Middleware(AuthMiddleware, settings=settings, verifier=verifier, log=log)])

    async def healthz(request):
        return JSONResponse({"status": "ok", "service": "governed-iceberg-mcp", "version": __version__, "auth_mode": settings.auth_mode,
            "warehouse": f"{settings.impala_host}:{settings.impala_port}", "host": socket.gethostname(), "started_at": STARTED})

    async def well_known(request):
        return JSONResponse(resource_metadata(settings))

    return Starlette(routes=[Route("/healthz", healthz), Route("/.well-known/oauth-protected-resource", well_known), Mount("/", app=mcp_app)],
        lifespan=mcp_app.lifespan)


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s", stream=sys.stdout)
    settings = Settings()
    app = build_app(settings)
    log.info("governed-iceberg-mcp %s on %s:%d (auth %s, impala %s via %s, impersonation %s)", __version__, settings.bind, settings.port,
        settings.auth_mode, f"{settings.impala_host}:{settings.impala_port}", settings.impala_auth, "doAs" if settings.impersonate else "off")
    if settings.auth_mode == "development":
        log.warning("AUTH_MODE=development: every caller is treated as %r. Never expose this mode beyond a private network.", settings.dev_user)
    else:
        try:
            log.info("Knox JWKS ready: kids %s", Verifier(settings).warm())
        except Exception as exc:
            log.warning("Knox JWKS not fetched yet (%s); it will be retried on the first request", exc)
    if settings.impala_auth == "GSSAPI":
        try:
            Impala(settings).kerberos.ensure()
        except Exception as exc:
            log.warning("Kerberos ticket not obtained at startup (%s); the first query will retry", exc)
    uvicorn.run(app, host=settings.bind, port=settings.port, log_level="warning", access_log=False)


if __name__ == "__main__":
    main()
