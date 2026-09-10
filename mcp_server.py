"""MCP Server implementation for YNAB Connector.

This module provides the FastAPI-based MCP server that exposes
YNAB functionality to the Model Context Protocol using JSON-RPC 2.0.

All endpoints use the official YNAB API v1.85.0 terminology (/plans/ not /budgets/).
"""

from __future__ import annotations

import base64
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
import hashlib
import hmac
import html
import json
import logging
import re
import secrets
import time
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

logger = logging.getLogger(__name__)

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from config import settings
from ynab_client import YNABClient


# ============================================================================
# Request Helpers
# ============================================================================

def _external_base_url(request: Request) -> str:
    """Resolve the externally visible base URL (scheme + host), no trailing slash.

    `request.base_url` reflects the scheme/host of the connection uvicorn
    actually received. Behind a reverse proxy (e.g. Nginx Proxy Manager)
    that terminates TLS and forwards plain HTTP, that means "http", even
    though the client reached us over "https" — unless uvicorn's
    ProxyHeadersMiddleware is configured to trust the proxy's IP, which
    varies per deployment. Read the standard forwarded headers directly
    instead, falling back to the raw connection info when absent (e.g.
    local development without a proxy).
    """
    proto = request.headers.get("x-forwarded-proto", request.url.scheme).split(",")[0].strip()
    default_host = request.headers.get("host", request.url.netloc)
    host = request.headers.get("x-forwarded-host", default_host).split(",")[0].strip()
    return f"{proto}://{host}"


# ============================================================================
# Validation Helpers
# ============================================================================

def _validate_date_format(date_str: str | None, param_name: str) -> str | None:
    """Validate that a date string is in YYYY-MM-DD format.
    
    Args:
        date_str: The date string to validate
        param_name: Name of the parameter for error messages
        
    Returns:
        The validated date string, or None if not provided
        
    Raises:
        ValueError: If the date format is invalid
    """
    if date_str is None:
        return None
    
    if not isinstance(date_str, str):
        raise ValueError(f"{param_name} must be a string in YYYY-MM-DD format, got {type(date_str).__name__}")
    
    # YNAB expects YYYY-MM-DD format
    if not re.match(r'^\d{4}-\d{2}-\d{2}$', date_str):
        raise ValueError(f"{param_name} must be in YYYY-MM-DD format, got: {date_str}")
    
    # Optional: Validate it's a real date
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        raise ValueError(f"{param_name} is not a valid date: {date_str}")
    
    return date_str


def _validate_required_param(param: Any, param_name: str, expected_type: type | tuple = str) -> Any:
    """Validate that a required parameter is provided and of the correct type.
    
    Args:
        param: The parameter value
        param_name: Name of the parameter for error messages
        expected_type: Expected type(s) of the parameter
        
    Returns:
        The validated parameter value
        
    Raises:
        ValueError: If the parameter is missing or of wrong type
    """
    if param is None:
        raise ValueError(f"{param_name} is required")
    
    if not isinstance(param, expected_type):
        raise ValueError(f"{param_name} must be of type {expected_type.__name__ if isinstance(expected_type, type) else expected_type}, got {type(param).__name__}")
    
    return param


_OAUTH_TOKEN_EXPIRY_SECONDS = 3600
_OAUTH_REFRESH_TOKEN_EXPIRY_SECONDS = 30 * 24 * 3600  # 30 days
_AUTH_CODE_EXPIRY_SECONDS = 300  # 5 minutes
_CLIENT_REGISTRATION_EXPIRY_SECONDS = 10 * 365 * 24 * 3600  # effectively non-expiring


def _check_client_secret(provided: str, stored: str) -> bool:
    if not provided or not stored:
        return False
    return secrets.compare_digest(provided, stored)


def _verify_pkce_s256(code_verifier: str, code_challenge: str) -> bool:
    """Verify a PKCE S256 code_verifier against a stored code_challenge."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return secrets.compare_digest(expected, code_challenge)


def _hmac_sign(payload_b64: str) -> str:
    """Return base64url HMAC-SHA256 signature of payload_b64."""
    sig = hmac.new(settings.oauth_client_secret.encode(), payload_b64.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).decode().rstrip("=")


def _make_signed_token(payload: dict[str, Any]) -> str:
    """Encode payload as base64url JSON and append HMAC signature."""
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    return f"{payload_b64}.{_hmac_sign(payload_b64)}"


def _decode_signed_token(token: str) -> dict[str, Any] | None:
    """Verify signature and return decoded payload, or None if invalid/expired."""
    if not settings.oauth_client_secret:
        return None
    try:
        payload_b64, sig_b64 = token.rsplit(".", 1)
        if not secrets.compare_digest(_hmac_sign(payload_b64), sig_b64):
            return None
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "==").decode())
        if time.time() >= payload.get("exp", 0):
            return None
        return payload
    except Exception:
        return None


def _create_auth_code(client_id: str, redirect_uri: str, code_challenge: str, scope: str, is_public: bool) -> str:
    """Create a self-verifying auth code (survives server restarts)."""
    return _make_signed_token({
        "typ": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "scope": scope,
        "pub": is_public,
        "exp": int(time.time()) + _AUTH_CODE_EXPIRY_SECONDS,
        "nti": secrets.token_urlsafe(8),
    })


def _create_access_token() -> str:
    """Create a self-verifying access token (survives server restarts)."""
    return _make_signed_token({
        "typ": "access",
        "exp": int(time.time()) + _OAUTH_TOKEN_EXPIRY_SECONDS,
        "jti": secrets.token_urlsafe(16),
    })


def _create_refresh_token() -> str:
    """Create a self-verifying refresh token valid for 30 days."""
    return _make_signed_token({
        "typ": "refresh",
        "exp": int(time.time()) + _OAUTH_REFRESH_TOKEN_EXPIRY_SECONDS,
        "jti": secrets.token_urlsafe(16),
    })

def _verify_access_token(token: str) -> bool:
    """Return True if the token is a valid, unexpired access token."""
    payload = _decode_signed_token(token)
    return payload is not None and payload.get("typ") == "access"


def _oauth_enabled() -> bool:
    """True when the connector runs in OAuth mode rather than direct-bearer mode."""
    return bool(settings.oauth_client_id and settings.oauth_client_secret)


def _create_client_id(redirect_uris: list[str]) -> str:
    """Create a self-describing client_id for a dynamically registered client.

    The registration is encoded into the client_id itself and signed, so no
    server-side client store is needed and registrations survive restarts.
    """
    return _make_signed_token({
        "typ": "client",
        "redirect_uris": redirect_uris,
        "exp": int(time.time()) + _CLIENT_REGISTRATION_EXPIRY_SECONDS,
        "jti": secrets.token_urlsafe(8),
    })


def _resolve_client_redirect_uris(client_id: str) -> list[str] | None:
    """Return allowed redirect URIs for a client_id, or None if the client is unknown."""
    if not client_id:
        return None
    if settings.oauth_client_id and secrets.compare_digest(client_id, settings.oauth_client_id):
        return settings.oauth_redirect_uri_list
    payload = _decode_signed_token(client_id)
    if payload and payload.get("typ") == "client":
        uris = payload.get("redirect_uris")
        if isinstance(uris, list):
            return [str(uri) for uri in uris]
    return None


def _is_preconfigured_client(client_id: str) -> bool:
    """True for the statically configured (confidential) client."""
    return bool(settings.oauth_client_id) and secrets.compare_digest(client_id, settings.oauth_client_id)


def _consent_secret() -> str:
    """Shared secret the owner types to approve a dynamically registered client."""
    return settings.oauth_consent_secret or settings.oauth_client_secret


def _is_valid_redirect_uri(uri: str) -> bool:
    """Allow only https redirect URIs, plus loopback for local development."""
    try:
        parsed = urlparse(uri)
    except ValueError:
        return False
    if parsed.fragment or not parsed.netloc:
        return False
    if parsed.scheme == "https":
        return True
    return parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}


def get_ynab_api_key(
    authorization: str | None = None,
) -> str:
    """Backward-compatible auth helper using bearer-header-only behavior.

    Kept for tests/import compatibility. MCP runtime auth is enforced through
    get_ynab_api_key_from_bearer_header.
    """
    return get_ynab_api_key_from_bearer_header(authorization)


def get_ynab_client(api_key: str | None = None) -> YNABClient:
    """Backward-compatible client helper kept for test/import compatibility."""
    if api_key:
        return YNABClient(api_key=api_key)
    return YNABClient()


def get_ynab_api_key_from_bearer_header(authorization: str | None) -> str:
    """Resolve the YNAB API key from the Authorization header.

    If OAuth is configured: validates the signed access token, then returns YNAB key from env.
    If OAuth is not configured: treats the bearer token as a direct YNAB API key.
    """
    if authorization is not None:
        auth_value = authorization.strip()
        if auth_value.lower().startswith("bearer "):
            token = auth_value[7:].strip()
            if token:
                if settings.oauth_client_secret:
                    if _verify_access_token(token):
                        if not settings.ynab_api_key:
                            raise HTTPException(
                                status_code=500,
                                detail="YNAB_API_KEY is not configured on the server.",
                            )
                        return settings.ynab_api_key
                else:
                    return token

    raise HTTPException(
        status_code=401,
        detail="Authentication required. Provide a valid OAuth Bearer token.",
    )


def _startup_banner() -> str:
    """Render an ASCII banner with the running version, for quick identification
    in logs (e.g. Portainer) without having to query /mcp/health.
    """
    letters = {
        "Y": ["#   #", " # # ", "  #  ", "  #  ", "  #  "],
        "N": ["#   #", "##  #", "# # #", "#  ##", "#   #"],
        "A": [" ### ", "#   #", "#####", "#   #", "#   #"],
        "B": ["#### ", "#   #", "#### ", "#   #", "#### "],
    }
    art_rows = ["  ".join(letters[ch][row] for ch in "YNAB") for row in range(5)]
    oauth_enabled = bool(settings.oauth_client_id and settings.oauth_client_secret)
    oauth_label = (
        "OAuth: enabled" if oauth_enabled else "OAuth: disabled (direct bearer token mode)"
    )
    content = [*art_rows, "", "MCP CONNECTOR", f"v{settings.mcp_version}", oauth_label]
    width = max(len(line) for line in content) + 4
    top, bottom = "╔" + "═" * width + "╗", "╚" + "═" * width + "╝"
    body = "\n".join(f"║{line.center(width)}║" for line in content)
    return "\n".join([top, body, bottom])


@asynccontextmanager
async def _lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Print the version banner once the app is ready to serve."""
    print(_startup_banner(), flush=True)
    yield


# Create FastAPI application
app = FastAPI(
    title=settings.mcp_name,
    version=settings.mcp_version,
    description="YNAB MCP Connector - Interact with You Need A Budget API v1",
    lifespan=_lifespan,
)


# ============================================================================
# MCP Server Discovery Endpoint
# ============================================================================

@app.get("/.well-known/mcp/server-card")
async def server_card(request: Request) -> dict[str, Any]:
    """MCP Server Card for discovery.
    
    Allows MCP clients to discover the server.
    """
    base_url = _external_base_url(request)
    return {
        "name": settings.mcp_name,
        "description": "YNAB MCP Connector - Interact with You Need A Budget API",
        "version": settings.mcp_version,
        "url": "/mcp",
        "auth": {
            "type": "oauth2",
            "version": "2.1",
            "authorization_servers": [base_url],
            "resource_metadata": f"{base_url}/.well-known/oauth-protected-resource",
            "flows": {
                "authorizationCode": {
                    "authorizationUrl": f"{base_url}/oauth/authorize",
                    "tokenUrl": f"{base_url}/oauth/token",
                    "registrationUrl": f"{base_url}/register",
                    "pkceRequired": True,
                    "codeChallengeMethods": ["S256"],
                    "scopes": {
                        "ynab:read": "Read YNAB plans, accounts and transactions",
                        "ynab:write": "Create and modify YNAB transactions",
                    },
                }
            },
        },
        "capabilities": {
            "tools": {},
            "resources": {
                "list": {},
                "read": {},
                "write": {},
            },
        },
        "hints": {
            "resourceTemplates": [
                {
                    "uriTemplate": "ynab://user",
                    "name": "YNAB User",
                    "description": "Authenticated user information",
                },
                {
                    "uriTemplate": "ynab://plans",
                    "name": "All Plans",
                    "description": "List all YNAB plans",
                },
                {
                    "uriTemplate": "ynab://plan/{plan_id}",
                    "name": "Plan",
                    "description": "A specific YNAB plan",
                },
                {
                    "uriTemplate": "ynab://plan/{plan_id}/settings",
                    "name": "Plan Settings",
                    "description": "Settings for a specific plan",
                },
                {
                    "uriTemplate": "ynab://plan/{plan_id}/accounts",
                    "name": "Plan Accounts",
                    "description": "All accounts for a plan",
                },
                {
                    "uriTemplate": "ynab://plan/{plan_id}/accounts/{account_id}",
                    "name": "Account",
                    "description": "A specific account",
                },
                {
                    "uriTemplate": "ynab://plan/{plan_id}/categories",
                    "name": "Plan Categories",
                    "description": "All categories for a plan",
                },
                {
                    "uriTemplate": "ynab://plan/{plan_id}/categories/{category_id}",
                    "name": "Category",
                    "description": "A specific category",
                },
                {
                    "uriTemplate": "ynab://plan/{plan_id}/payees",
                    "name": "Plan Payees",
                    "description": "All payees for a plan",
                },
                {
                    "uriTemplate": "ynab://plan/{plan_id}/payees/{payee_id}",
                    "name": "Payee",
                    "description": "A specific payee",
                },
                {
                    "uriTemplate": "ynab://plan/{plan_id}/months",
                    "name": "Plan Months",
                    "description": "All months for a plan",
                },
                {
                    "uriTemplate": "ynab://plan/{plan_id}/months/{month}",
                    "name": "Plan Month",
                    "description": "A specific month for a plan",
                },
                {
                    "uriTemplate": "ynab://plan/{plan_id}/transactions",
                    "name": "Plan Transactions",
                    "description": "All transactions for a plan",
                },
                {
                    "uriTemplate": "ynab://plan/{plan_id}/transactions/{transaction_id}",
                    "name": "Transaction",
                    "description": "A specific transaction",
                },
                {
                    "uriTemplate": "ynab://plan/{plan_id}/scheduled_transactions",
                    "name": "Scheduled Transactions",
                    "description": "All scheduled transactions for a plan",
                },
            ]
        },
    }


# ============================================================================
# OAuth 2.0 Endpoints (Authorization Code + PKCE S256, as required by Claude.ai)
# ============================================================================

@app.get("/.well-known/oauth-protected-resource")
@app.get("/.well-known/oauth-protected-resource/mcp")
async def oauth_protected_resource_metadata(request: Request) -> dict[str, Any]:
    """OAuth Protected Resource Metadata (RFC 9728).

    Tells clients which authorization server issues tokens for this resource.
    Clients discover the OAuth flow here after receiving a 401. The
    `/mcp`-suffixed path is the RFC 9728 path-insertion form some clients
    (e.g. Mistral) probe for a resource served at `/mcp`.
    """
    base_url = _external_base_url(request)
    return {
        "resource": f"{base_url}/mcp",
        "authorization_servers": [base_url],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["ynab:read", "ynab:write"],
    }


@app.get("/.well-known/oauth-authorization-server")
@app.get("/.well-known/oauth-authorization-server/mcp")
async def oauth_server_metadata(request: Request) -> dict[str, Any]:
    """OAuth 2.1 Authorization Server Metadata (RFC 8414)."""
    base_url = _external_base_url(request)
    metadata: dict[str, Any] = {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/oauth/authorize",
        "token_endpoint": f"{base_url}/oauth/token",
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "scopes_supported": ["ynab:read", "ynab:write"],
    }
    if settings.oauth_dynamic_registration_enabled:
        metadata["registration_endpoint"] = f"{base_url}/register"
    return metadata


@app.post("/register")
async def oauth_register(request: Request) -> JSONResponse:
    """OAuth 2.0 Dynamic Client Registration (RFC 7591).

    Required by clients that only support OAuth 2.1 with dynamic registration
    (e.g. Mistral). Registration is unauthenticated per the RFC, so issued
    clients are public clients: they must use PKCE *and* the resource owner
    must approve them on the consent screen before any code is issued.
    """
    if not _oauth_enabled():
        return JSONResponse(status_code=501, content={"error": "oauth_not_configured"})
    if not settings.oauth_dynamic_registration_enabled:
        return JSONResponse(
            status_code=403,
            content={"error": "access_denied", "error_description": "Dynamic client registration is disabled."},
        )

    try:
        body = await request.json()
    except Exception:
        body = None
    if not isinstance(body, dict):
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_client_metadata", "error_description": "Request body must be a JSON object."},
        )

    redirect_uris = body.get("redirect_uris")
    if not isinstance(redirect_uris, list) or not redirect_uris or not all(isinstance(u, str) for u in redirect_uris):
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_redirect_uri", "error_description": "redirect_uris must be a non-empty array of strings."},
        )
    if len(redirect_uris) > 5:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_redirect_uri", "error_description": "At most 5 redirect_uris may be registered."},
        )
    for uri in redirect_uris:
        if not _is_valid_redirect_uri(uri):
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_redirect_uri", "error_description": f"redirect_uri must be https (or loopback http): {uri}"},
            )

    requested_auth_method = body.get("token_endpoint_auth_method", "none")
    if requested_auth_method not in ("none", None):
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_client_metadata", "error_description": "Only token_endpoint_auth_method 'none' (public client + PKCE) is supported."},
        )

    client_id = _create_client_id(redirect_uris)
    logger.info("OAuth dynamic client registered for redirect_uris=%r", redirect_uris)
    return JSONResponse(status_code=201, content={
        "client_id": client_id,
        "client_id_issued_at": int(time.time()),
        "client_name": body.get("client_name") or "Dynamically registered MCP client",
        "redirect_uris": redirect_uris,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": "ynab:read ynab:write",
    })


def _consent_page(params: dict[str, str], error: str = "") -> HTMLResponse:
    """Render the approval form shown for dynamically registered clients."""
    hidden = "".join(
        f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v)}">'
        for k, v in params.items()
    )
    error_html = f'<p class="err">{html.escape(error)}</p>' if error else ""
    redirect_uri = html.escape(params.get("redirect_uri", ""))
    body = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Authorize access</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem}}
.err{{color:#b00020}} code{{word-break:break-all}}
input[type=password]{{width:100%;padding:.5rem;font-size:1rem}}
button{{margin-top:1rem;padding:.6rem 1.2rem;font-size:1rem}}
</style></head><body>
<h1>Authorize access to your YNAB data</h1>
<p>An application is requesting access to this YNAB connector and will be sent back to:</p>
<p><code>{redirect_uri}</code></p>
<p>Only continue if you started this. Enter the connector approval secret to allow it.</p>
{error_html}
<form method="post" action="/oauth/authorize">
{hidden}
<label for="s">Approval secret</label>
<input id="s" type="password" name="consent_secret" autocomplete="current-password" autofocus>
<button type="submit">Allow access</button>
</form></body></html>"""
    status = 401 if error else 200
    return HTMLResponse(content=body, status_code=status)


def _authorize_request_params(q: Any) -> dict[str, str]:
    return {
        "response_type": q.get("response_type", ""),
        "client_id": q.get("client_id", ""),
        "redirect_uri": q.get("redirect_uri", ""),
        "code_challenge": q.get("code_challenge", ""),
        "code_challenge_method": q.get("code_challenge_method", ""),
        "state": q.get("state", ""),
        "scope": q.get("scope", ""),
    }


def _process_authorize(params: dict[str, str], consent_secret: str | None) -> Response:
    """Validate an authorization request and either redirect with a code,
    show the consent form, or return an error.
    """
    if not settings.oauth_client_id:
        return JSONResponse(status_code=501, content={"error": "oauth_not_configured"})

    client_id = params["client_id"]
    redirect_uri = params["redirect_uri"]
    state = params["state"]

    # Validate client_id before trusting redirect_uri (prevents open redirect)
    allowed_redirect_uris = _resolve_client_redirect_uris(client_id)
    if allowed_redirect_uris is None:
        logger.warning("OAuth authorize rejected: unknown client_id %r", client_id)
        return JSONResponse(status_code=400, content={"error": "invalid_client", "error_description": "Unknown client_id"})

    if redirect_uri not in allowed_redirect_uris:
        logger.warning("OAuth authorize rejected: redirect_uri mismatch (got %r, allowed %r)", redirect_uri, allowed_redirect_uris)
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_redirect_uri", "error_description": f"Registered redirect URIs: {', '.join(allowed_redirect_uris)}"},
        )

    if params["response_type"] != "code":
        qs = urlencode({"error": "unsupported_response_type", "state": state})
        return RedirectResponse(url=f"{redirect_uri}?{qs}", status_code=302)

    if params["code_challenge_method"] != "S256" or not params["code_challenge"]:
        qs = urlencode({"error": "invalid_request", "error_description": "PKCE S256 required", "state": state})
        return RedirectResponse(url=f"{redirect_uri}?{qs}", status_code=302)

    # Dynamically registered clients are unauthenticated by definition, so the
    # resource owner must explicitly approve them before a code is issued.
    is_public = not _is_preconfigured_client(client_id)
    if is_public:
        expected = _consent_secret()
        if not expected:
            return JSONResponse(
                status_code=500,
                content={"error": "server_error", "error_description": "No approval secret configured."},
            )
        if consent_secret is None:
            return _consent_page(params)
        if not secrets.compare_digest(consent_secret, expected):
            logger.warning("OAuth consent rejected: bad approval secret for redirect_uri %r", redirect_uri)
            return _consent_page(params, error="Incorrect approval secret.")

    code = _create_auth_code(client_id, redirect_uri, params["code_challenge"], params["scope"], is_public)

    redirect_params: dict[str, str] = {"code": code}
    if state:
        redirect_params["state"] = state
    return RedirectResponse(url=f"{redirect_uri}?{urlencode(redirect_params)}", status_code=302)


@app.get("/oauth/authorize")
async def oauth_authorize(request: Request) -> Response:
    """OAuth 2.1 authorization endpoint.

    The pre-configured client is auto-approved (single-owner connector).
    Dynamically registered clients must pass the consent screen first.
    """
    return _process_authorize(_authorize_request_params(request.query_params), consent_secret=None)


@app.post("/oauth/authorize")
async def oauth_authorize_consent(request: Request) -> Response:
    """Handle submission of the consent form for a dynamically registered client."""
    raw = (await request.body()).decode()
    form = {k: (v[0] if v else "") for k, v in parse_qs(raw, keep_blank_values=True).items()}
    return _process_authorize(_authorize_request_params(form), consent_secret=form.get("consent_secret", ""))


@app.post("/oauth/token")
async def oauth_token(request: Request) -> JSONResponse:
    """OAuth 2.1 token endpoint — authorization_code (PKCE S256) and refresh_token grants."""
    if not _oauth_enabled():
        return JSONResponse(
            status_code=501,
            content={"error": "oauth_not_configured", "error_description": "OAuth is not configured on this server."},
        )

    body = await request.body()
    params = parse_qs(body.decode())

    def _first(key: str) -> str:
        return (params.get(key) or [""])[0]

    grant_type = _first("grant_type")
    client_id = _first("client_id")
    client_secret = _first("client_secret")

    if _resolve_client_redirect_uris(client_id) is None:
        return JSONResponse(status_code=401, content={"error": "invalid_client"})

    # Confidential (pre-configured) clients must present their secret; public
    # clients issued via dynamic registration authenticate with PKCE instead.
    is_public = not _is_preconfigured_client(client_id)
    if not is_public and not _check_client_secret(client_secret, settings.oauth_client_secret):
        return JSONResponse(status_code=401, content={"error": "invalid_client"})

    if grant_type == "authorization_code":
        code = _first("code")
        code_verifier = _first("code_verifier")
        redirect_uri = _first("redirect_uri")

        pending = _decode_signed_token(code)
        if not pending or pending.get("typ") != "code":
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_grant", "error_description": "Invalid or expired authorization code"},
            )

        if pending["client_id"] != client_id or pending["redirect_uri"] != redirect_uri:
            return JSONResponse(status_code=400, content={"error": "invalid_grant"})

        if not _verify_pkce_s256(code_verifier, pending["code_challenge"]):
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_grant", "error_description": "PKCE verification failed"},
            )

    elif grant_type == "refresh_token":
        refresh_token = _first("refresh_token")
        payload = _decode_signed_token(refresh_token)
        if not payload or payload.get("typ") != "refresh":
            return JSONResponse(status_code=400, content={"error": "invalid_grant"})

    else:
        return JSONResponse(status_code=400, content={"error": "unsupported_grant_type"})

    return JSONResponse(content={
        "access_token": _create_access_token(),
        "refresh_token": _create_refresh_token(),
        "token_type": "Bearer",
        "expires_in": _OAUTH_TOKEN_EXPIRY_SECONDS,
    })

    if grant_type == "authorization_code":
        code = _first("code")
        code_verifier = _first("code_verifier")
        redirect_uri = _first("redirect_uri")

        pending = _decode_signed_token(code)
        if not pending or pending.get("typ") != "code":
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_grant", "error_description": "Invalid or expired authorization code"},
            )

        if pending["client_id"] != client_id or pending["redirect_uri"] != redirect_uri:
            return JSONResponse(status_code=400, content={"error": "invalid_grant"})

        if not _verify_pkce_s256(code_verifier, pending["code_challenge"]):
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_grant", "error_description": "PKCE verification failed"},
            )

    elif grant_type == "refresh_token":
        refresh_token = _first("refresh_token")
        payload = _decode_signed_token(refresh_token)
        if not payload or payload.get("typ") != "refresh":
            return JSONResponse(status_code=400, content={"error": "invalid_grant"})

    else:
        return JSONResponse(status_code=400, content={"error": "unsupported_grant_type"})

    return JSONResponse(content={
        "access_token": _create_access_token(),
        "refresh_token": _create_refresh_token(),
        "token_type": "Bearer",
        "expires_in": _OAUTH_TOKEN_EXPIRY_SECONDS,
    })


# ============================================================================
# MCP JSON-RPC 2.0 Protocol Endpoint
# ============================================================================

MCP_PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_MCP_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")


def _www_authenticate_header(request: Request) -> str:
    """Build the WWW-Authenticate challenge advertising the OAuth 2.1 flow."""
    realm = settings.mcp_name.replace('"', "")
    if not _oauth_enabled():
        return f'Bearer realm="{realm}"'
    base_url = _external_base_url(request)
    return (
        f'Bearer realm="{realm}", '
        f'resource_metadata="{base_url}/.well-known/oauth-protected-resource"'
    )


@app.get("/mcp")
@app.head("/mcp")
async def mcp_auth_challenge(request: Request) -> Response:
    """Advertise the authentication scheme to clients probing the MCP endpoint.

    Clients such as Mistral auto-detect the auth method by sending an
    unauthenticated request and reading the `WWW-Authenticate` header of the
    401 response, which points at the RFC 9728 resource metadata describing
    the OAuth 2.1 authorization server.
    """
    return JSONResponse(
        status_code=401,
        content={
            "error": "invalid_token",
            "error_description": "Authorization required. Obtain an OAuth 2.1 bearer token.",
        },
        headers={"WWW-Authenticate": _www_authenticate_header(request)},
    )


@app.post("/mcp")
async def mcp_handler(request: Request) -> JSONResponse:
    """Handle MCP JSON-RPC 2.0 requests.
    
    Implements the Model Context Protocol specification.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content={
                "jsonrpc": "2.0",
                "error": {
                    "code": -32600,
                    "message": "Invalid JSON",
                },
                "id": None,
            },
        )
    
    authorization = request.headers.get("authorization")
    www_auth = _www_authenticate_header(request)

    def _auth_401(detail: str, req_id: Any) -> JSONResponse:
        return JSONResponse(
            status_code=401,
            content={"jsonrpc": "2.0", "error": {"code": -32000, "message": detail}, "id": req_id},
            headers={"WWW-Authenticate": www_auth},
        )

    # Handle batch requests
    if isinstance(body, list):
        results = []
        for req in body:
            try:
                result = await _handle_rpc_request(req, authorization=authorization)
            except HTTPException as e:
                if e.status_code == 401:
                    return _auth_401(e.detail, req.get("id") if isinstance(req, dict) else None)
                raise
            results.append(result)
        return JSONResponse(content=results)

    # Handle single request
    try:
        result = await _handle_rpc_request(body, authorization=authorization)
    except HTTPException as e:
        if e.status_code == 401:
            return _auth_401(e.detail, body.get("id") if isinstance(body, dict) else None)
        raise
    return JSONResponse(content=result)


async def _handle_rpc_request(
    request: dict[str, Any], authorization: str | None = None
) -> dict[str, Any]:
    """Handle a single JSON-RPC 2.0 request."""
    request_id = request.get("id")
    method = request.get("method")
    params = request.get("params", {})

    # Every MCP method requires a bearer token, per the MCP authorization spec.
    # Returning 401 on `initialize` is what lets OAuth-aware clients discover
    # the flow instead of assuming the server is unauthenticated.
    methods_requiring_auth = {
        "initialize",
        "tools/list",
        "tools/call",
        "resources/list",
        "resources/read",
        "resources/write",
    }

    try:
        request_api_key: str | None = None
        if method in methods_requiring_auth:
            request_api_key = get_ynab_api_key_from_bearer_header(authorization)
        if method == "initialize":
            result = await _handle_initialize(params, request_id)
        elif method == "tools/list":
            result = await _handle_tools_list(params, request_id)
        elif method == "tools/call":
            result = await _handle_tools_call(params, request_id, api_key=request_api_key)
        elif method == "resources/list":
            result = await _handle_resources_list(params, request_id, api_key=request_api_key)
        elif method == "resources/read":
            result = await _handle_resources_read(params, request_id, api_key=request_api_key)
        elif method == "resources/write":
            result = await _handle_resources_write(params, request_id, api_key=request_api_key)
        else:
            result = {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}",
                },
                "id": request_id,
            }
        
        return result
    
    except HTTPException as e:
        if e.status_code == 401:
            raise  # propagate so mcp_handler can return a real HTTP 401
        return {
            "jsonrpc": "2.0",
            "error": {
                "code": -32000,
                "message": e.detail,
            },
            "id": request_id,
        }
    except Exception as e:
        return {
            "jsonrpc": "2.0",
            "error": {
                "code": -32603,
                "message": str(e),
            },
            "id": request_id,
        }


async def _handle_initialize(
    params: dict[str, Any], request_id: Any
) -> dict[str, Any]:
    """Handle MCP initialize request."""
    requested = params.get("protocolVersion")
    negotiated = requested if requested in SUPPORTED_MCP_PROTOCOL_VERSIONS else MCP_PROTOCOL_VERSION
    return {
        "jsonrpc": "2.0",
        "result": {
            "protocolVersion": negotiated,
            "capabilities": {
                "tools": {},
                "resources": {
                    "list": {},
                    "read": {
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "uri": {"type": "string"},
                            },
                            "required": ["uri"],
                        }
                    },
                    "write": {
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "uri": {"type": "string"},
                                "content": {"type": "string"},
                            },
                            "required": ["uri", "content"],
                        }
                    },
                },
            },
            "serverInfo": {
                "name": settings.mcp_name,
                "version": settings.mcp_version,
            },
        },
        "id": request_id,
    }


async def _handle_tools_list(
    params: dict[str, Any], request_id: Any
) -> dict[str, Any]:
    """Handle MCP tools/list request."""
    
    # ==========================================================================
    # Schema Definitions for Tool Input/Output Types
    # ==========================================================================
    
    # Account Schema
    account_schema = {
        "type": "object",
        "properties": {
            "id": {"type": "string", "description": "Unique identifier for the account"},
            "name": {"type": "string", "description": "Name of the account"},
            "type": {
                "type": "string",
                "enum": ["CHECKING", "SAVINGS", "CASH", "CREDIT_CARD", "LINE_OF_CREDIT", "OTHER_ASSET", "OTHER_LIABILITY"],
                "description": "Type of account"
            },
            "balance": {
                "type": "integer",
                "description": "Current balance in milliunits (1/1000 of currency unit)",
                "examples": [100000]
            },
            "cleared_balance": {
                "type": "integer",
                "description": "Cleared balance in milliunits"
            },
            "uncleared_balance": {
                "type": "integer",
                "description": "Uncleared balance in milliunits"
            },
            "closed": {"type": "boolean", "description": "Whether the account is closed"},
            "note": {"type": "string", "description": "Optional note for the account"},
            "on_budget": {"type": "boolean", "description": "Whether the account is on budget"},
        },
        "required": ["name", "type", "balance"],
    }
    
    # Category Schema
    category_schema = {
        "type": "object",
        "properties": {
            "id": {"type": "string", "description": "Unique identifier for the category"},
            "name": {"type": "string", "description": "Name of the category"},
            "hidden": {"type": "boolean", "description": "Whether the category is hidden"},
            "original_category_group_id": {
                "type": "string",
                "description": "ID of the original category group"
            },
            "note": {"type": "string", "description": "Optional note for the category"},
        },
        "required": ["name"],
    }
    
    # Category Group Schema
    category_group_schema = {
        "type": "object",
        "properties": {
            "id": {"type": "string", "description": "Unique identifier for the category group"},
            "name": {"type": "string", "description": "Name of the category group"},
            "hidden": {"type": "boolean", "description": "Whether the category group is hidden"},
            "categories": {
                "type": "array",
                "items": category_schema,
                "description": "List of categories in this group"
            },
        },
        "required": ["name"],
    }
    
    # Transaction Schema
    transaction_schema = {
        "type": "object",
        "properties": {
            "id": {"type": "string", "description": "Unique identifier for the transaction"},
            "date": {
                "type": "string",
                "format": "date",
                "description": "Transaction date in YYYY-MM-DD format",
                "examples": ["2024-01-15"]
            },
            "amount": {
                "type": "integer",
                "description": "Transaction amount in milliunits (positive for inflow, negative for outflow)",
                "examples": [100000, -50000]
            },
            "memo": {"type": "string", "description": "Memo or description for the transaction"},
            "cleared": {
                "type": "string",
                "enum": ["cleared", "uncleared", "reconciled"],
                "description": "Cleared status of the transaction"
            },
            "approved": {"type": "boolean", "description": "Whether the transaction is approved"},
            "flag_color": {
                "type": "string",
                "enum": ["red", "orange", "yellow", "green", "blue", "purple", "pink", "brown", "grey", "black"],
                "description": "Color flag for the transaction"
            },
            "account_id": {"type": "string", "description": "ID of the account the transaction belongs to"},
            "payee_id": {"type": "string", "description": "ID of the payee (if linked)"},
            "payee_name": {"type": "string", "description": "Name of the payee"},
            "category_id": {"type": "string", "description": "ID of the category"},
            "category_name": {"type": "string", "description": "Name of the category"},
            "subtransactions": {
                "type": "array",
                "items": {"type": "object"},
                "description": "List of subtransactions (for split transactions)"
            },
            "transaction_type": {
                "type": "string",
                "description": "Type of transaction"
            },
            "import_id": {"type": "string", "description": "Import ID for imported transactions"},
        },
        "required": ["date", "amount"],
    }
    
    # Scheduled Transaction Schema
    scheduled_transaction_schema = {
        "type": "object",
        "properties": {
            "id": {"type": "string", "description": "Unique identifier for the scheduled transaction"},
            "date_first": {
                "type": "string",
                "format": "date",
                "description": "First date of the scheduled transaction in YYYY-MM-DD format",
                "examples": ["2024-01-15"]
            },
            "date_next": {
                "type": "string",
                "format": "date",
                "description": "Next occurrence date in YYYY-MM-DD format"
            },
            "frequency": {
                "type": "string",
                "enum": ["daily", "weekly", "everyOtherWeek", "twiceAMonth", "every4Weeks", "monthly", "everyOtherMonth", "every3Months", "every6Months", "yearly", "everyOtherYear", "never"],
                "description": "How often the transaction occurs"
            },
            "amount": {
                "type": "integer",
                "description": "Amount in milliunits",
                "examples": [100000]
            },
            "memo": {"type": "string", "description": "Memo or description"},
            "flag_color": {
                "type": "string",
                "enum": ["red", "orange", "yellow", "green", "blue", "purple", "pink", "brown", "grey", "black"],
                "description": "Color flag"
            },
            "account_id": {"type": "string", "description": "ID of the account"},
            "payee_id": {"type": "string", "description": "ID of the payee"},
            "category_id": {"type": "string", "description": "ID of the category"},
            "category_name": {"type": "string", "description": "Name of the category"},
            "subtransactions": {
                "type": "array",
                "items": {"type": "object"},
                "description": "List of subtransactions"
            },
            "weeks_offset": {"type": "integer", "description": "Week offset for frequency"},
            "days_offset": {"type": "integer", "description": "Day offset for frequency"},
        },
        "required": ["date_first", "frequency", "amount"],
    }
    
    # Payee Schema
    payee_schema = {
        "type": "object",
        "properties": {
            "id": {"type": "string", "description": "Unique identifier for the payee"},
            "name": {"type": "string", "description": "Name of the payee"},
            "transfer_account_id": {
                "type": "string",
                "description": "Account ID if this is a transfer payee"
            },
            "deleted": {"type": "boolean", "description": "Whether the payee is deleted"},
        },
        "required": ["name"],
    }
    
    # Plan Schema (simplified for input)
    plan_schema = {
        "type": "object",
        "properties": {
            "id": {"type": "string", "description": "Unique identifier for the plan"},
            "name": {"type": "string", "description": "Name of the plan"},
        },
    }
    
    # Month Schema
    month_schema = {
        "type": "object",
        "properties": {
            "month": {
                "type": "string",
                "format": "date",
                "description": "Month identifier in YYYY-MM-DD format",
                "examples": ["2024-01-01"]
            },
            "note": {"type": "string", "description": "Optional note for the month"},
            "to_be_budgeted": {
                "type": "integer",
                "description": "Amount to be budgeted in milliunits"
            },
            "age_of_money": {
                "type": "integer",
                "description": "Age of money in days"
            },
            "categories": {
                "type": "array",
                "items": {"type": "object"},
                "description": "List of category budget information for the month"
            },
        },
        "required": ["month"],
    }
    
    # Common parameter descriptions
    common_params = {
        "plan_id": {
            "type": "string",
            "description": "The plan ID (can be a UUID, 'last-used', or 'default')",
            "examples": ["d95502e5-1217-4a6c-935b-c053888b3497", "last-used"]
        },
        "last_knowledge_of_server": {
            "type": "integer",
            "description": "Starting server knowledge timestamp for delta/incremental updates. Used to fetch only changes since this timestamp.",
            "minimum": 0,
            "examples": [0]
        },
        "since_date": {
            "type": "string",
            "format": "date",
            "description": "Filter transactions on or after this date (YYYY-MM-DD format)",
            "examples": ["2024-01-01"]
        },
        "until_date": {
            "type": "string",
            "format": "date",
            "description": "Filter transactions on or before this date (YYYY-MM-DD format)",
            "examples": ["2024-12-31"]
        },
    }
    
    tools = [
        # User tools
        {
            "name": "get_user",
            "description": "Get authenticated YNAB user information",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "description": "No parameters required",
            }
        },
        # Plans tools
        {
            "name": "get_plans",
            "description": "Get all plans accessible with the API key",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "include_accounts": {
                        "type": "boolean",
                        "description": "Whether to include the list of plan accounts in the response",
                        "default": False,
                    },
                },
            }
        },
        {
            "name": "get_plan",
            "description": "Get a specific plan by ID with all related entities",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan_id": common_params["plan_id"],
                    "last_knowledge_of_server": common_params["last_knowledge_of_server"],
                },
                "required": ["plan_id"],
            }
        },
        {
            "name": "get_plan_settings",
            "description": "Get settings for a specific plan",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan_id": common_params["plan_id"],
                },
                "required": ["plan_id"],
            }
        },
        # Accounts tools
        {
            "name": "get_accounts",
            "description": "Get all accounts for a plan",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan_id": common_params["plan_id"],
                    "last_knowledge_of_server": common_params["last_knowledge_of_server"],
                },
                "required": ["plan_id"],
            }
        },
        {
            "name": "get_account",
            "description": "Get a specific account by ID",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan_id": common_params["plan_id"],
                    "account_id": {
                        "type": "string",
                        "description": "The account ID (UUID)",
                        "examples": ["a1b2c3d4-e5f6-7890-abcd-ef1234567890"]
                    },
                },
                "required": ["plan_id", "account_id"],
            }
        },
        {
            "name": "create_account",
            "description": "Create a new account",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan_id": common_params["plan_id"],
                    "account": {
                        "allOf": [account_schema],
                        "description": "Account data with name, type, and balance (in milliunits). Required: name, type, balance.",
                    },
                },
                "required": ["plan_id", "account"],
            }
        },
        # Categories tools
        {
            "name": "get_categories",
            "description": "Get all categories for a plan",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan_id": common_params["plan_id"],
                    "last_knowledge_of_server": common_params["last_knowledge_of_server"],
                },
                "required": ["plan_id"],
            }
        },
        {
            "name": "get_category",
            "description": "Get a specific category by ID",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan_id": common_params["plan_id"],
                    "category_id": {
                        "type": "string",
                        "description": "The category ID (UUID)",
                        "examples": ["a1b2c3d4-e5f6-7890-abcd-ef1234567890"]
                    },
                },
                "required": ["plan_id", "category_id"],
            }
        },
        {
            "name": "create_category",
            "description": "Create a new category",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan_id": common_params["plan_id"],
                    "category": {
                        "allOf": [category_schema],
                        "description": "Category data including name and category_group_id. Required: name, category_group_id.",
                        "required": ["name", "category_group_id"],
                    },
                },
                "required": ["plan_id", "category"],
            }
        },
        {
            "name": "update_category",
            "description": "Update an existing category",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan_id": common_params["plan_id"],
                    "category_id": {
                        "type": "string",
                        "description": "The category ID (UUID)",
                        "examples": ["a1b2c3d4-e5f6-7890-abcd-ef1234567890"]
                    },
                    "category": {
                        "allOf": [category_schema],
                        "description": "Category data to update. Required: name.",
                        "required": ["name"],
                    },
                },
                "required": ["plan_id", "category_id", "category"],
            }
        },
        # Payees tools
        {
            "name": "get_payees",
            "description": "Get all payees for a plan",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan_id": common_params["plan_id"],
                    "last_knowledge_of_server": common_params["last_knowledge_of_server"],
                },
                "required": ["plan_id"],
            }
        },
        {
            "name": "get_payee",
            "description": "Get a specific payee by ID",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan_id": common_params["plan_id"],
                    "payee_id": {
                        "type": "string",
                        "description": "The payee ID (UUID)",
                        "examples": ["a1b2c3d4-e5f6-7890-abcd-ef1234567890"]
                    },
                },
                "required": ["plan_id", "payee_id"],
            }
        },
        {
            "name": "create_payee",
            "description": "Create a new payee",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan_id": common_params["plan_id"],
                    "payee": {
                        "allOf": [payee_schema],
                        "description": "Payee data with name. Required: name.",
                        "required": ["name"],
                    },
                },
                "required": ["plan_id", "payee"],
            }
        },
        # Months tools
        {
            "name": "get_months",
            "description": "Get all months for a plan",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan_id": common_params["plan_id"],
                    "last_knowledge_of_server": common_params["last_knowledge_of_server"],
                },
                "required": ["plan_id"],
            }
        },
        {
            "name": "get_month",
            "description": "Get a specific month for a plan",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan_id": common_params["plan_id"],
                    "month": {
                        "type": "string",
                        "format": "date",
                        "description": "Month in YYYY-MM-DD format or 'current'",
                        "examples": ["2024-01-01", "current"]
                    },
                },
                "required": ["plan_id", "month"],
            }
        },
        # Transactions tools
        {
            "name": "get_transactions",
            "description": "Get transactions for a plan. All amounts are in milliunits (1/1000 of currency unit).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan_id": common_params["plan_id"],
                    "since_date": common_params["since_date"],
                    "until_date": common_params["until_date"],
                    "type": {
                        "type": "string",
                        "enum": ["uncategorized", "unapproved"],
                        "description": "Filter by transaction type: 'uncategorized' for transactions without a category, 'unapproved' for transactions not yet approved",
                    },
                    "last_knowledge_of_server": common_params["last_knowledge_of_server"],
                    "limit": {"type": "integer", "description": "Maximum number of transactions to return (client-side pagination)", "minimum": 1},
                    "offset": {"type": "integer", "description": "Number of transactions to skip (client-side pagination)", "minimum": 0, "default": 0},
                },
                "required": ["plan_id"],
            }
        },
        {
            "name": "get_transaction",
            "description": "Get a specific transaction by ID",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan_id": common_params["plan_id"],
                    "transaction_id": {
                        "type": "string",
                        "description": "The transaction ID (UUID)",
                        "examples": ["a1b2c3d4-e5f6-7890-abcd-ef1234567890"]
                    },
                },
                "required": ["plan_id", "transaction_id"],
            }
        },
        {
            "name": "create_transaction",
            "description": "Create a new transaction. Amount must be in milliunits (1/1000 of currency unit).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan_id": common_params["plan_id"],
                    "transaction": {
                        "allOf": [transaction_schema],
                        "description": "Single transaction data. Required: date, amount, account_id. Amount in milliunits.",
                        "required": ["date", "amount", "account_id"],
                    },
                },
                "required": ["plan_id", "transaction"],
            }
        },
        {
            "name": "update_transaction",
            "description": "Update a single transaction. Amount must be in milliunits.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan_id": common_params["plan_id"],
                    "transaction_id": {
                        "type": "string",
                        "description": "The transaction ID (UUID)",
                        "examples": ["a1b2c3d4-e5f6-7890-abcd-ef1234567890"]
                    },
                    "transaction": {
                        "allOf": [transaction_schema],
                        "description": "Transaction data to update. Amount in milliunits.",
                    },
                },
                "required": ["plan_id", "transaction_id", "transaction"],
            }
        },
        {
            "name": "update_transactions",
            "description": "Update multiple transactions at once. Each transaction must have an id or import_id.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan_id": common_params["plan_id"],
                    "transactions": {
                        "type": "array",
                        "description": "List of transactions to update. Each must have id or import_id.",
                        "items": transaction_schema,
                        "minItems": 1,
                    },
                },
                "required": ["plan_id", "transactions"],
            }
        },
        {
            "name": "delete_transaction",
            "description": "Delete a transaction by ID",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan_id": common_params["plan_id"],
                    "transaction_id": {
                        "type": "string",
                        "description": "The transaction ID (UUID)",
                        "examples": ["a1b2c3d4-e5f6-7890-abcd-ef1234567890"]
                    },
                },
                "required": ["plan_id", "transaction_id"],
            },
        },
        {
            "name": "import_transactions",
            "description": "Import transactions from linked accounts. Returns transactions in milliunits.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan_id": common_params["plan_id"],
                },
                "required": ["plan_id"],
            }
        },
        # Scheduled Transactions tools
        {
            "name": "get_scheduled_transactions",
            "description": "Get all scheduled transactions for a plan. Amounts are in milliunits.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan_id": common_params["plan_id"],
                    "last_knowledge_of_server": common_params["last_knowledge_of_server"],
                },
                "required": ["plan_id"],
            }
        },
        {
            "name": "get_scheduled_transaction",
            "description": "Get a specific scheduled transaction by ID",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan_id": common_params["plan_id"],
                    "scheduled_transaction_id": {
                        "type": "string",
                        "description": "The scheduled transaction ID (UUID)",
                        "examples": ["a1b2c3d4-e5f6-7890-abcd-ef1234567890"]
                    },
                },
                "required": ["plan_id", "scheduled_transaction_id"],
            }
        },
        {
            "name": "create_scheduled_transaction",
            "description": "Create a new scheduled transaction. Amount must be in milliunits.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan_id": common_params["plan_id"],
                    "scheduled_transaction": {
                        "allOf": [scheduled_transaction_schema],
                        "description": "Scheduled transaction data. Required: date_first, frequency, amount (in milliunits).",
                        "required": ["date_first", "frequency", "amount"],
                    },
                },
                "required": ["plan_id", "scheduled_transaction"],
            }
        },
        {
            "name": "update_scheduled_transaction",
            "description": "Update a scheduled transaction. Amount must be in milliunits.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan_id": common_params["plan_id"],
                    "scheduled_transaction_id": {
                        "type": "string",
                        "description": "The scheduled transaction ID (UUID)",
                        "examples": ["a1b2c3d4-e5f6-7890-abcd-ef1234567890"]
                    },
                    "scheduled_transaction": {
                        "allOf": [scheduled_transaction_schema],
                        "description": "Scheduled transaction data to update. Amount in milliunits.",
                    },
                },
                "required": ["plan_id", "scheduled_transaction_id", "scheduled_transaction"],
            }
        },
        {
            "name": "delete_scheduled_transaction",
            "description": "Delete a scheduled transaction by ID",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "plan_id": common_params["plan_id"],
                    "scheduled_transaction_id": {
                        "type": "string",
                        "description": "The scheduled transaction ID (UUID)",
                        "examples": ["a1b2c3d4-e5f6-7890-abcd-ef1234567890"]
                    },
                },
                "required": ["plan_id", "scheduled_transaction_id"],
            },
        },
    ]
    
    return {
        "jsonrpc": "2.0",
        "result": {
            "tools": tools,
        },
        "id": request_id,
    }


async def _handle_tools_call(
    params: dict[str, Any], request_id: Any, api_key: str | None = None
) -> dict[str, Any]:
    """Handle MCP tools/call request."""
    name = params.get("name")
    arguments = params.get("arguments", {})
    
    if not api_key:
        raise HTTPException(status_code=401, detail="Authentication required")

    client = YNABClient(api_key=api_key)
    
    try:
        # User tools
        if name == "get_user":
            data = await client.get_user()
            content = [{"type": "text", "text": json.dumps(data)}]
        
        # Plans tools
        elif name == "get_plans":
            include_accounts = arguments.get("include_accounts", False)
            data = await client.get_plans(include_accounts=include_accounts)
            content = [{"type": "text", "text": json.dumps(data)}]
        
        elif name == "get_plan":
            plan_id = arguments.get("plan_id")
            last_knowledge = arguments.get("last_knowledge_of_server")
            if not plan_id:
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "plan_id is required"}, "id": request_id}
            data = await client.get_plan(plan_id, last_knowledge_of_server=last_knowledge)
            content = [{"type": "text", "text": json.dumps(data)}]
        
        elif name == "get_plan_settings":
            plan_id = arguments.get("plan_id")
            if not plan_id:
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "plan_id is required"}, "id": request_id}
            data = await client.get_plan_settings(plan_id)
            content = [{"type": "text", "text": json.dumps(data)}]
        
        # Accounts tools
        elif name == "get_accounts":
            plan_id = arguments.get("plan_id")
            last_knowledge = arguments.get("last_knowledge_of_server")
            if not plan_id:
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "plan_id is required"}, "id": request_id}
            data = await client.get_accounts(plan_id, last_knowledge_of_server=last_knowledge)
            content = [{"type": "text", "text": json.dumps(data)}]
        
        elif name == "get_account":
            plan_id = arguments.get("plan_id")
            account_id = arguments.get("account_id")
            if not plan_id or not account_id:
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "plan_id and account_id are required"}, "id": request_id}
            data = await client.get_account(plan_id, account_id)
            content = [{"type": "text", "text": json.dumps(data)}]
        
        elif name == "create_account":
            plan_id = arguments.get("plan_id")
            account_data = arguments.get("account")
            if not plan_id or not account_data:
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "plan_id and account are required"}, "id": request_id}
            data = await client.create_account(plan_id, account_data)
            content = [{"type": "text", "text": json.dumps(data)}]
        
        # Categories tools
        elif name == "get_categories":
            plan_id = arguments.get("plan_id")
            last_knowledge = arguments.get("last_knowledge_of_server")
            if not plan_id:
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "plan_id is required"}, "id": request_id}
            data = await client.get_categories(plan_id, last_knowledge_of_server=last_knowledge)
            content = [{"type": "text", "text": json.dumps(data)}]
        
        elif name == "get_category":
            plan_id = arguments.get("plan_id")
            category_id = arguments.get("category_id")
            if not plan_id or not category_id:
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "plan_id and category_id are required"}, "id": request_id}
            data = await client.get_category(plan_id, category_id)
            content = [{"type": "text", "text": json.dumps(data)}]
        
        elif name == "create_category":
            plan_id = arguments.get("plan_id")
            category_data = arguments.get("category")
            if not plan_id or not category_data:
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "plan_id and category are required"}, "id": request_id}
            data = await client.create_category(plan_id, category_data)
            content = [{"type": "text", "text": json.dumps(data)}]
        
        elif name == "update_category":
            plan_id = arguments.get("plan_id")
            category_id = arguments.get("category_id")
            category_data = arguments.get("category")
            if not plan_id or not category_id or not category_data:
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "plan_id, category_id, and category are required"}, "id": request_id}
            data = await client.update_category(plan_id, category_id, category_data)
            content = [{"type": "text", "text": json.dumps(data)}]
        
        # Payees tools
        elif name == "get_payees":
            plan_id = arguments.get("plan_id")
            last_knowledge = arguments.get("last_knowledge_of_server")
            if not plan_id:
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "plan_id is required"}, "id": request_id}
            data = await client.get_payees(plan_id, last_knowledge_of_server=last_knowledge)
            content = [{"type": "text", "text": json.dumps(data)}]
        
        elif name == "get_payee":
            plan_id = arguments.get("plan_id")
            payee_id = arguments.get("payee_id")
            if not plan_id or not payee_id:
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "plan_id and payee_id are required"}, "id": request_id}
            data = await client.get_payee(plan_id, payee_id)
            content = [{"type": "text", "text": json.dumps(data)}]
        
        elif name == "create_payee":
            plan_id = arguments.get("plan_id")
            payee_data = arguments.get("payee")
            if not plan_id or not payee_data:
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "plan_id and payee are required"}, "id": request_id}
            data = await client.create_payee(plan_id, payee_data)
            content = [{"type": "text", "text": json.dumps(data)}]
        
        # Months tools
        elif name == "get_months":
            plan_id = arguments.get("plan_id")
            last_knowledge = arguments.get("last_knowledge_of_server")
            if not plan_id:
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "plan_id is required"}, "id": request_id}
            data = await client.get_months(plan_id, last_knowledge_of_server=last_knowledge)
            content = [{"type": "text", "text": json.dumps(data)}]
        
        elif name == "get_month":
            plan_id = arguments.get("plan_id")
            month = arguments.get("month")
            if not plan_id or not month:
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "plan_id and month are required"}, "id": request_id}
            data = await client.get_month(plan_id, month)
            content = [{"type": "text", "text": json.dumps(data)}]
        
        # Transactions tools
        elif name == "get_transactions":
            plan_id = arguments.get("plan_id")
            if not plan_id:
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "plan_id is required"}, "id": request_id}
            
            try:
                # Validate required parameters
                _validate_required_param(plan_id, "plan_id", str)
                
                # Validate date formats
                since_date = _validate_date_format(arguments.get("since_date"), "since_date")
                until_date = _validate_date_format(arguments.get("until_date"), "until_date")
                
                type_filter = arguments.get("type")
                last_knowledge = arguments.get("last_knowledge_of_server")
                
                # Pagination parameters (client-side, default to no limit)
                limit = arguments.get("limit")
                offset = arguments.get("offset", 0)
                
                if limit is not None:
                    try:
                        limit = int(limit)
                        if limit <= 0:
                            raise ValueError("limit must be a positive integer")
                    except (ValueError, TypeError):
                        raise ValueError("limit must be a positive integer")
                
                if offset is not None:
                    try:
                        offset = int(offset)
                        if offset < 0:
                            raise ValueError("offset must be a non-negative integer")
                    except (ValueError, TypeError):
                        raise ValueError("offset must be a non-negative integer")
                
                data = await client.get_transactions(
                    plan_id,
                    since_date=since_date,
                    until_date=until_date,
                    type_filter=type_filter,
                    last_knowledge_of_server=last_knowledge,
                )
                
                # Apply client-side pagination if limit is specified
                if limit is not None and "data" in data and "transactions" in data["data"]:
                    transactions = data["data"]["transactions"]
                    paginated = transactions[offset:offset + limit]
                    data["data"]["transactions"] = paginated
                    # Add pagination metadata
                    data["data"]["pagination"] = {
                        "limit": limit,
                        "offset": offset,
                        "total": len(transactions)
                    }
                
                content = [{"type": "text", "text": json.dumps(data)}]
            except ValueError as e:
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": str(e)}, "id": request_id}
        
        elif name == "get_transaction":
            plan_id = arguments.get("plan_id")
            transaction_id = arguments.get("transaction_id")
            if not plan_id or not transaction_id:
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "plan_id and transaction_id are required"}, "id": request_id}
            data = await client.get_transaction(plan_id, transaction_id)
            content = [{"type": "text", "text": json.dumps(data)}]
        
        elif name == "create_transaction":
            plan_id = arguments.get("plan_id")
            if not plan_id:
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "plan_id is required"}, "id": request_id}
            transaction_data = arguments.get("transaction") or arguments.get("transactions", {})
            data = await client.create_transaction(plan_id, transaction_data)
            content = [{"type": "text", "text": json.dumps(data)}]
        
        elif name == "update_transaction":
            plan_id = arguments.get("plan_id")
            transaction_id = arguments.get("transaction_id")
            transaction_data = arguments.get("transaction")
            if not plan_id or not transaction_id or not transaction_data:
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "plan_id, transaction_id, and transaction are required"}, "id": request_id}
            data = await client.update_transaction(plan_id, transaction_id, transaction_data)
            content = [{"type": "text", "text": json.dumps(data)}]
        
        elif name == "update_transactions":
            plan_id = arguments.get("plan_id")
            transactions = arguments.get("transactions")
            if not plan_id or not transactions:
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "plan_id and transactions are required"}, "id": request_id}
            data = await client.update_transactions(plan_id, transactions)
            content = [{"type": "text", "text": json.dumps(data)}]
        
        elif name == "delete_transaction":
            plan_id = arguments.get("plan_id")
            transaction_id = arguments.get("transaction_id")
            if not plan_id or not transaction_id:
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "plan_id and transaction_id are required"}, "id": request_id}
            data = await client.delete_transaction(plan_id, transaction_id)
            content = [{"type": "text", "text": json.dumps(data)}]
        
        elif name == "import_transactions":
            plan_id = arguments.get("plan_id")
            if not plan_id:
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "plan_id is required"}, "id": request_id}
            data = await client.import_transactions(plan_id)
            content = [{"type": "text", "text": f"Imported transactions: {data}"}]
        
        # Scheduled Transactions tools
        elif name == "get_scheduled_transactions":
            plan_id = arguments.get("plan_id")
            last_knowledge = arguments.get("last_knowledge_of_server")
            if not plan_id:
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "plan_id is required"}, "id": request_id}
            data = await client.get_scheduled_transactions(plan_id, last_knowledge_of_server=last_knowledge)
            content = [{"type": "text", "text": json.dumps(data)}]
        
        elif name == "get_scheduled_transaction":
            plan_id = arguments.get("plan_id")
            scheduled_transaction_id = arguments.get("scheduled_transaction_id")
            if not plan_id or not scheduled_transaction_id:
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "plan_id and scheduled_transaction_id are required"}, "id": request_id}
            data = await client.get_scheduled_transaction(plan_id, scheduled_transaction_id)
            content = [{"type": "text", "text": json.dumps(data)}]
        
        elif name == "create_scheduled_transaction":
            plan_id = arguments.get("plan_id")
            transaction_data = arguments.get("scheduled_transaction")
            if not plan_id or not transaction_data:
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "plan_id and scheduled_transaction are required"}, "id": request_id}
            data = await client.create_scheduled_transaction(plan_id, transaction_data)
            content = [{"type": "text", "text": json.dumps(data)}]
        
        elif name == "update_scheduled_transaction":
            plan_id = arguments.get("plan_id")
            scheduled_transaction_id = arguments.get("scheduled_transaction_id")
            transaction_data = arguments.get("scheduled_transaction")
            if not plan_id or not scheduled_transaction_id or not transaction_data:
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "plan_id, scheduled_transaction_id, and scheduled_transaction are required"}, "id": request_id}
            data = await client.update_scheduled_transaction(plan_id, scheduled_transaction_id, transaction_data)
            content = [{"type": "text", "text": json.dumps(data)}]
        
        elif name == "delete_scheduled_transaction":
            plan_id = arguments.get("plan_id")
            scheduled_transaction_id = arguments.get("scheduled_transaction_id")
            if not plan_id or not scheduled_transaction_id:
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "plan_id and scheduled_transaction_id are required"}, "id": request_id}
            data = await client.delete_scheduled_transaction(plan_id, scheduled_transaction_id)
            content = [{"type": "text", "text": json.dumps(data)}]
        
        else:
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32601, "message": f"Tool not found: {name}"},
                "id": request_id,
            }
        
        return {
            "jsonrpc": "2.0",
            "result": {
                "content": content,
                "isError": False,
            },
            "id": request_id,
        }
    
    finally:
        client.close()


async def _handle_resources_list(
    params: dict[str, Any], request_id: Any, api_key: str | None = None
) -> dict[str, Any]:
    """Handle MCP resources/list request.
    
    Lists available YNAB resources that can be read.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="Authentication required")

    client = YNABClient(api_key=api_key)
    
    try:
        resources = []
        
        # Add user resource
        resources.append({
            "uri": "ynab://user",
            "name": "YNAB User",
            "description": "Authenticated user information",
            "mimeType": "application/json",
        })
        
        # Get all plans and add resources for each
        plans_response = await client.get_plans()
        plans = plans_response.get("data", {}).get("plans", [])
        
        for plan in plans:
            plan_id = plan.get("id", "")
            plan_name = plan.get("name", "Unknown Plan")
            
            # Plan resource
            resources.append({
                "uri": f"ynab://plan/{plan_id}",
                "name": f"Plan: {plan_name}",
                "description": f"YNAB Plan - {plan_name}",
                "mimeType": "application/json",
            })
            
            # Plan settings
            resources.append({
                "uri": f"ynab://plan/{plan_id}/settings",
                "name": f"Settings: {plan_name}",
                "description": f"Settings for plan: {plan_name}",
                "mimeType": "application/json",
            })
            
            # Accounts
            resources.append({
                "uri": f"ynab://plan/{plan_id}/accounts",
                "name": f"Accounts: {plan_name}",
                "description": f"Accounts for plan: {plan_name}",
                "mimeType": "application/json",
            })
            
            # Categories
            resources.append({
                "uri": f"ynab://plan/{plan_id}/categories",
                "name": f"Categories: {plan_name}",
                "description": f"Categories for plan: {plan_name}",
                "mimeType": "application/json",
            })
            
            # Payees
            resources.append({
                "uri": f"ynab://plan/{plan_id}/payees",
                "name": f"Payees: {plan_name}",
                "description": f"Payees for plan: {plan_name}",
                "mimeType": "application/json",
            })
            
            # Months
            resources.append({
                "uri": f"ynab://plan/{plan_id}/months",
                "name": f"Months: {plan_name}",
                "description": f"Months for plan: {plan_name}",
                "mimeType": "application/json",
            })
            
            # Transactions
            resources.append({
                "uri": f"ynab://plan/{plan_id}/transactions",
                "name": f"Transactions: {plan_name}",
                "description": f"Transactions for plan: {plan_name}",
                "mimeType": "application/json",
            })
            
            # Scheduled Transactions
            resources.append({
                "uri": f"ynab://plan/{plan_id}/scheduled_transactions",
                "name": f"Scheduled Transactions: {plan_name}",
                "description": f"Scheduled transactions for plan: {plan_name}",
                "mimeType": "application/json",
            })
        
        return {
            "jsonrpc": "2.0",
            "result": {
                "resources": resources,
            },
            "id": request_id,
        }
    
    finally:
        client.close()


async def _handle_resources_read(
    params: dict[str, Any], request_id: Any, api_key: str | None = None
) -> dict[str, Any]:
    """Handle MCP resources/read request.
    
    Read data from a YNAB resource URI.
    """
    uri = params.get("uri")
    
    if not uri:
        return {
            "jsonrpc": "2.0",
            "error": {"code": -32602, "message": "uri is required"},
            "id": request_id,
        }
    
    if not api_key:
        raise HTTPException(status_code=401, detail="Authentication required")

    client = YNABClient(api_key=api_key)
    
    try:
        # Parse the URI and fetch data
        if uri == "ynab://user":
            data = await client.get_user()
        
        elif uri.startswith("ynab://plan/"):
            parts = uri.replace("ynab://plan/", "").split("/")
            plan_id = parts[0]
            
            if len(parts) == 1:
                # Get full plan
                data = await client.get_plan(plan_id)
            elif parts[1] == "settings":
                data = await client.get_plan_settings(plan_id)
            elif parts[1] == "accounts":
                data = await client.get_accounts(plan_id)
            elif parts[1] == "categories":
                data = await client.get_categories(plan_id)
            elif parts[1] == "payees":
                data = await client.get_payees(plan_id)
            elif parts[1] == "months":
                if len(parts) == 2:
                    data = await client.get_months(plan_id)
                else:
                    month = parts[2]
                    data = await client.get_month(plan_id, month)
            elif parts[1] == "transactions":
                if len(parts) == 2:
                    data = await client.get_transactions(plan_id)
                else:
                    transaction_id = parts[2]
                    data = await client.get_transaction(plan_id, transaction_id)
            elif parts[1] == "scheduled_transactions":
                if len(parts) == 2:
                    data = await client.get_scheduled_transactions(plan_id)
                else:
                    scheduled_transaction_id = parts[2]
                    data = await client.get_scheduled_transaction(plan_id, scheduled_transaction_id)
            else:
                return {
                    "jsonrpc": "2.0",
                    "error": {"code": -32602, "message": f"Unsupported URI: {uri}"},
                    "id": request_id,
                }
        
        else:
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32602, "message": f"Unsupported URI: {uri}"},
                "id": request_id,
            }
        
        return {
            "jsonrpc": "2.0",
            "result": [
                {
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": json.dumps(data),
                }
            ],
            "id": request_id,
        }
    
    finally:
        client.close()


async def _handle_resources_write(
    params: dict[str, Any], request_id: Any, api_key: str | None = None
) -> dict[str, Any]:
    """Handle MCP resources/write request.
    
    Write data to a YNAB resource URI (for create/update operations).
    """
    uri = params.get("uri")
    content = params.get("content")
    
    if not uri:
        return {
            "jsonrpc": "2.0",
            "error": {"code": -32602, "message": "uri is required"},
            "id": request_id,
        }
    
    if not content:
        return {
            "jsonrpc": "2.0",
            "error": {"code": -32602, "message": "content is required"},
            "id": request_id,
        }
    
    if not api_key:
        raise HTTPException(status_code=401, detail="Authentication required")

    client = YNABClient(api_key=api_key)
    
    try:
        data = json.loads(content)
        
        # Parse the URI and perform write operation
        if uri.startswith("ynab://plan/"):
            parts = uri.replace("ynab://plan/", "").split("/")
            plan_id = parts[0]
            
            if len(parts) >= 2:
                resource_type = parts[1]
                
                if resource_type == "accounts" and len(parts) == 2:
                    # Create account
                    result = await client.create_account(plan_id, data)
                elif resource_type == "categories" and len(parts) == 2:
                    # Create category
                    result = await client.create_category(plan_id, data.get("category", data))
                elif resource_type == "payees" and len(parts) == 2:
                    # Create payee
                    result = await client.create_payee(plan_id, data.get("payee", data))
                elif resource_type == "transactions" and len(parts) == 2:
                    # Create transaction(s)
                    result = await client.create_transaction(plan_id, data)
                elif resource_type == "scheduled_transactions" and len(parts) == 2:
                    # Create scheduled transaction
                    result = await client.create_scheduled_transaction(plan_id, data.get("scheduled_transaction", data))
                elif resource_type == "categories" and len(parts) == 3:
                    # Update category
                    category_id = parts[2]
                    result = await client.update_category(plan_id, category_id, data.get("category", data))
                elif resource_type == "transactions" and len(parts) == 3:
                    # Update transaction
                    transaction_id = parts[2]
                    result = await client.update_transaction(plan_id, transaction_id, data.get("transaction", data))
                elif resource_type == "scheduled_transactions" and len(parts) == 3:
                    # Update scheduled transaction
                    scheduled_transaction_id = parts[2]
                    result = await client.update_scheduled_transaction(plan_id, scheduled_transaction_id, data.get("scheduled_transaction", data))
                else:
                    return {
                        "jsonrpc": "2.0",
                        "error": {"code": -32602, "message": f"Write not supported for URI: {uri}"},
                        "id": request_id,
                    }
            else:
                return {
                    "jsonrpc": "2.0",
                    "error": {"code": -32602, "message": f"Write not supported for URI: {uri}"},
                    "id": request_id,
                }
        else:
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32602, "message": f"Write not supported for URI: {uri}"},
                "id": request_id,
            }
        
        return {
            "jsonrpc": "2.0",
            "result": {
                "uri": uri,
                "text": json.dumps(result),
            },
            "id": request_id,
        }
    
    except json.JSONDecodeError:
        return {
            "jsonrpc": "2.0",
            "error": {"code": -32602, "message": "Invalid JSON in content"},
            "id": request_id,
        }
    
    finally:
        client.close()


# ============================================================================
# REST API Endpoints (for direct HTTP access)
# ============================================================================

@app.get("/mcp/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "version": settings.mcp_version}


@app.get("/mcp/info")
async def mcp_info() -> dict[str, Any]:
    """Get MCP server information."""
    return {
        "name": settings.mcp_name,
        "version": settings.mcp_version,
        "description": "YNAB API Connector aligned with official OpenAPI spec",
        "api_version": "1.85.0",
        "base_url": settings.ynab_api_url,
        "capabilities": {
            "user": {"read": True},
            "plans": {"read": True},
            "accounts": {"read": True, "write": True},
            "categories": {"read": True, "write": True},
            "payees": {"read": True, "write": True},
            "months": {"read": True},
            "transactions": {"read": True, "write": True, "delete": True},
            "scheduled_transactions": {"read": True, "write": True, "delete": True},
            "money_movements": {"read": True},
        },
    }
