"""Tests for OAuth 2.1 discovery, dynamic client registration and consent."""

import base64
import hashlib

import pytest
from fastapi.testclient import TestClient

from config import Settings
from mcp_server import app

REDIRECT_URI = "https://example.com/callback"
CONSENT_SECRET = "test_consent_secret"
CODE_VERIFIER = "a" * 64


def _code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


@pytest.fixture
def oauth_settings(monkeypatch):
    """Settings with OAuth enabled."""
    test_settings = Settings(
        ynab_api_key="test_api_key_12345",
        oauth_client_id="static-client-id",
        oauth_client_secret="static-client-secret",
        oauth_redirect_uris=REDIRECT_URI,
        oauth_consent_secret=CONSENT_SECRET,
        mcp_name="YNAB Connector Test",
        mcp_version="0.1.0",
    )
    monkeypatch.setattr("config.settings", test_settings)
    monkeypatch.setattr("mcp_server.settings", test_settings)
    monkeypatch.setattr("ynab_client.settings", test_settings)
    return test_settings


@pytest.fixture
def oauth_client(oauth_settings):
    return TestClient(app, follow_redirects=False)


def _register(client: TestClient) -> str:
    response = client.post("/register", json={"redirect_uris": [REDIRECT_URI]})
    assert response.status_code == 201
    return response.json()["client_id"]


class TestAuthChallenge:
    """Unauthenticated requests must advertise OAuth via WWW-Authenticate."""

    def test_get_mcp_returns_401_with_challenge(self, oauth_client):
        response = oauth_client.get("/mcp")
        assert response.status_code == 401
        assert "resource_metadata=" in response.headers["WWW-Authenticate"]
        assert response.headers["WWW-Authenticate"].startswith("Bearer ")

    def test_initialize_without_token_returns_401(self, oauth_client):
        response = oauth_client.post(
            "/mcp", json={"jsonrpc": "2.0", "method": "initialize", "id": 1}
        )
        assert response.status_code == 401
        assert "WWW-Authenticate" in response.headers

    def test_initialize_with_invalid_token_returns_401(self, oauth_client):
        response = oauth_client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "method": "initialize", "id": 1},
            headers={"Authorization": "Bearer not-a-real-token"},
        )
        assert response.status_code == 401


class TestDiscoveryMetadata:
    """RFC 8414 / RFC 9728 metadata documents."""

    @pytest.mark.parametrize(
        "path",
        ["/.well-known/oauth-authorization-server", "/.well-known/oauth-authorization-server/mcp"],
    )
    def test_authorization_server_metadata(self, oauth_client, path):
        data = oauth_client.get(path).json()
        assert data["registration_endpoint"].endswith("/register")
        assert "S256" in data["code_challenge_methods_supported"]
        assert "none" in data["token_endpoint_auth_methods_supported"]
        assert "refresh_token" in data["grant_types_supported"]

    @pytest.mark.parametrize(
        "path",
        ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"],
    )
    def test_protected_resource_metadata(self, oauth_client, path):
        data = oauth_client.get(path).json()
        assert data["resource"].endswith("/mcp")
        assert data["authorization_servers"]

    def test_registration_endpoint_hidden_when_disabled(self, oauth_settings, monkeypatch):
        monkeypatch.setattr(oauth_settings, "oauth_dynamic_registration_enabled", False)
        client = TestClient(app)
        data = client.get("/.well-known/oauth-authorization-server").json()
        assert "registration_endpoint" not in data


class TestDynamicClientRegistration:
    """RFC 7591 registration endpoint."""

    def test_registers_public_client(self, oauth_client):
        response = oauth_client.post("/register", json={"redirect_uris": [REDIRECT_URI]})
        assert response.status_code == 201
        data = response.json()
        assert data["client_id"]
        assert data["token_endpoint_auth_method"] == "none"
        assert data["redirect_uris"] == [REDIRECT_URI]

    def test_rejects_missing_redirect_uris(self, oauth_client):
        assert oauth_client.post("/register", json={}).status_code == 400

    def test_rejects_non_https_redirect_uri(self, oauth_client):
        response = oauth_client.post(
            "/register", json={"redirect_uris": ["http://evil.example.com/cb"]}
        )
        assert response.status_code == 400

    def test_allows_loopback_redirect_uri(self, oauth_client):
        response = oauth_client.post(
            "/register", json={"redirect_uris": ["http://localhost:1234/cb"]}
        )
        assert response.status_code == 201

    def test_rejects_confidential_client_request(self, oauth_client):
        response = oauth_client.post(
            "/register",
            json={"redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "client_secret_post"},
        )
        assert response.status_code == 400

    def test_disabled_registration_returns_403(self, oauth_settings, monkeypatch):
        monkeypatch.setattr(oauth_settings, "oauth_dynamic_registration_enabled", False)
        client = TestClient(app)
        response = client.post("/register", json={"redirect_uris": [REDIRECT_URI]})
        assert response.status_code == 403


class TestAuthorizeConsent:
    """Dynamically registered clients require owner approval."""

    def _authorize_params(self, client_id: str) -> dict[str, str]:
        return {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": REDIRECT_URI,
            "code_challenge": _code_challenge(CODE_VERIFIER),
            "code_challenge_method": "S256",
            "state": "xyz",
        }

    def test_dynamic_client_gets_consent_page(self, oauth_client):
        client_id = _register(oauth_client)
        response = oauth_client.get("/oauth/authorize", params=self._authorize_params(client_id))
        assert response.status_code == 200
        assert "Approval secret" in response.text

    def test_wrong_consent_secret_is_rejected(self, oauth_client):
        client_id = _register(oauth_client)
        response = oauth_client.post(
            "/oauth/authorize",
            data={**self._authorize_params(client_id), "consent_secret": "wrong"},
        )
        assert response.status_code == 401
        assert "Incorrect approval secret" in response.text

    def test_static_client_is_auto_approved(self, oauth_client, oauth_settings):
        response = oauth_client.get(
            "/oauth/authorize", params=self._authorize_params(oauth_settings.oauth_client_id)
        )
        assert response.status_code == 302
        assert response.headers["location"].startswith(f"{REDIRECT_URI}?code=")

    def test_unknown_client_is_rejected(self, oauth_client):
        response = oauth_client.get("/oauth/authorize", params=self._authorize_params("bogus"))
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client"

    def test_unregistered_redirect_uri_is_rejected(self, oauth_client):
        client_id = _register(oauth_client)
        params = {**self._authorize_params(client_id), "redirect_uri": "https://evil.example.com/cb"}
        response = oauth_client.get("/oauth/authorize", params=params)
        assert response.status_code == 400


class TestTokenExchange:
    """Full authorization_code + PKCE flow for a dynamically registered client."""

    def _obtain_code(self, client: TestClient, client_id: str) -> str:
        response = client.post(
            "/oauth/authorize",
            data={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": REDIRECT_URI,
                "code_challenge": _code_challenge(CODE_VERIFIER),
                "code_challenge_method": "S256",
                "consent_secret": CONSENT_SECRET,
            },
        )
        assert response.status_code == 302
        location = response.headers["location"]
        return location.split("code=", 1)[1].split("&")[0]

    def test_public_client_exchanges_code_without_secret(self, oauth_client):
        client_id = _register(oauth_client)
        code = self._obtain_code(oauth_client, client_id)
        response = oauth_client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "code_verifier": CODE_VERIFIER,
                "redirect_uri": REDIRECT_URI,
            },
        )
        assert response.status_code == 200
        assert response.json()["token_type"] == "Bearer"

    def test_wrong_code_verifier_is_rejected(self, oauth_client):
        client_id = _register(oauth_client)
        code = self._obtain_code(oauth_client, client_id)
        response = oauth_client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "code_verifier": "b" * 64,
                "redirect_uri": REDIRECT_URI,
            },
        )
        assert response.status_code == 400

    def test_access_token_authenticates_mcp_request(self, oauth_client):
        client_id = _register(oauth_client)
        code = self._obtain_code(oauth_client, client_id)
        token = oauth_client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "code_verifier": CODE_VERIFIER,
                "redirect_uri": REDIRECT_URI,
            },
        ).json()["access_token"]

        response = oauth_client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "method": "initialize", "id": 1},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        assert response.json()["result"]["protocolVersion"]

    def test_unknown_client_cannot_get_token(self, oauth_client):
        response = oauth_client.post(
            "/oauth/token", data={"grant_type": "authorization_code", "client_id": "bogus"}
        )
        assert response.status_code == 401


class TestProtocolVersionNegotiation:
    def test_echoes_supported_client_version(self, oauth_client):
        client_id = _register(oauth_client)
        code = TestTokenExchange()._obtain_code(oauth_client, client_id)
        token = oauth_client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "code_verifier": CODE_VERIFIER,
                "redirect_uri": REDIRECT_URI,
            },
        ).json()["access_token"]

        response = oauth_client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "method": "initialize",
                "id": 1,
                "params": {"protocolVersion": "2024-11-05"},
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.json()["result"]["protocolVersion"] == "2024-11-05"
