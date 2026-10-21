"""Caller identity.

Knox mints the token (SPNEGO or LDAP login against the token topology); this module verifies it offline
against Knox's JWKS and takes `sub` as the account. Verification is fail-closed: anything wrong with the token
answers 401 before any tool runs. The verified user travels to the tools in a context variable, so the tools
never see the token itself.
"""
import contextvars
import json
import time
from pathlib import Path

import jwt
from starlette.responses import JSONResponse

current_user: contextvars.ContextVar[str] = contextvars.ContextVar("current_user")


class Verifier:
    """Offline KNOXTOKEN verification. Keys come from the Knox JWKS URL (cached, refetched on an unknown kid)
    or from a JWKS file for air-gapped deployments."""

    def __init__(self, settings):
        self.settings = settings
        self.jwks_file = Path(settings.knox_jwks_file) if settings.knox_jwks_file else None
        self.client = jwt.PyJWKClient(settings.knox_jwks_url, timeout=settings.jwks_timeout) if settings.knox_jwks_url else None

    def signing_key(self, token):
        if self.jwks_file:
            kid = jwt.get_unverified_header(token).get("kid")
            keys = jwt.PyJWKSet.from_dict(json.loads(self.jwks_file.read_text())).keys
            match = next((k for k in keys if kid is None or k.key_id == kid), None)
            if match is None:
                raise jwt.PyJWKClientError(f"no key with kid {kid!r} in {self.jwks_file}")
            return match.key
        return self.client.get_signing_key_from_jwt(token).key

    def verify(self, token):
        """Return the account (`sub`) the token was issued to, or raise."""
        audience = self.settings.knox_audience or None
        claims = jwt.decode(token, self.signing_key(token), algorithms=["RS256"], issuer=self.settings.knox_issuer or None,
            audience=audience, options={"verify_aud": bool(audience), "verify_iss": bool(self.settings.knox_issuer)})
        if not claims.get("sub"):
            raise jwt.InvalidTokenError("token has no sub")
        return claims["sub"]

    def warm(self):
        """Fetch the JWKS once at startup so the first request does not pay for it; failures are reported, not fatal."""
        if self.client is None:
            return [k.key_id for k in jwt.PyJWKSet.from_dict(json.loads(self.jwks_file.read_text())).keys]
        return [k.key_id for k in self.client.get_jwk_set().keys]


def resource_metadata(settings):
    """RFC 9728: tells an MCP client where tokens come from. Knox is not a full OAuth server; this advertises its mint URL."""
    resource = (settings.public_url or f"http://{settings.bind}:{settings.port}") + "/mcp"
    return {"resource": resource, "authorization_servers": [settings.knox_token_url] if settings.knox_token_url else [],
        "bearer_methods_supported": ["header"]}


class AuthMiddleware:
    """Pure ASGI middleware around the MCP endpoint: no valid bearer token, no MCP."""

    def __init__(self, app, settings, verifier, log, state=None):
        self.app, self.settings, self.verifier, self.log, self.state = app, settings, verifier, log, state
        self.well_known = (settings.public_url or "") + "/.well-known/oauth-protected-resource"

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        if self.settings.auth_mode == "development":
            user = self.settings.dev_user
        else:
            header = next((v.decode() for k, v in scope["headers"] if k == b"authorization"), "")
            if not header.lower().startswith("bearer "):
                if self.state:
                    self.state.event("auth_rejected", reason="missing_bearer")
                return await self.reject(scope, receive, send, "missing Knox bearer token")
            started = time.monotonic()
            try:
                user = self.verifier.verify(header.split(None, 1)[1].strip())
            except Exception as exc:  # any verification failure is a 401; the reason goes to the log, not the client
                self.log.warning("token rejected after %.2fs: %s", time.monotonic() - started, exc)
                if self.state:
                    self.state.event("auth_rejected", reason="invalid_bearer")
                return await self.reject(scope, receive, send, "invalid Knox token")
            if self.state:
                self.state.event("auth_succeeded", user=user)
                if self.state.snapshot().get("maintenance"):
                    return await self.unavailable(scope, receive, send)
        token = current_user.set(user)
        try:
            await self.app(scope, receive, send)
        finally:
            current_user.reset(token)

    async def reject(self, scope, receive, send, reason):
        response = JSONResponse({"error": reason}, status_code=401,
            headers={"WWW-Authenticate": f'Bearer resource_metadata="{self.well_known}"'})
        await response(scope, receive, send)

    async def unavailable(self, scope, receive, send):
        response = JSONResponse({"error": "MCP is in maintenance mode"}, status_code=503,
            headers={"Retry-After": "30"})
        await response(scope, receive, send)
