"""Tests for FastAPI endpoints."""

import pytest


class TestHealthEndpoint:
    """Tests for the /mcp/health endpoint."""

    def test_health_check_returns_200(self, test_client, mock_settings):
        """Test that the health check endpoint returns 200 OK."""
        response = test_client.get("/mcp/health")

        assert response.status_code == 200
        assert response.json() == {
            "status": "healthy",
            "version": mock_settings.mcp_version
        }


class TestInfoEndpoint:
    """Tests for the /mcp/info endpoint."""

    def test_info_returns_200(self, test_client):
        """Test that the info endpoint returns 200 OK."""
        response = test_client.get("/mcp/info")
        
        assert response.status_code == 200
        
        data = response.json()
        assert "name" in data
        assert "version" in data
        assert "description" in data
        assert "api_version" in data
        assert "base_url" in data
        assert "capabilities" in data

    def test_info_returns_expected_structure(self, test_client, mock_settings):
        """Test that the info endpoint returns the expected structure."""
        response = test_client.get("/mcp/info")
        data = response.json()

        # Check top-level fields
        assert data["name"] == mock_settings.mcp_name
        assert data["version"] == mock_settings.mcp_version
        assert "YNAB API Connector aligned with official OpenAPI spec" in data["description"]
        assert data["api_version"] == "1.85.0"
        
        # Check capabilities structure
        assert "user" in data["capabilities"]
        assert "plans" in data["capabilities"]
        assert "accounts" in data["capabilities"]
        assert "transactions" in data["capabilities"]


class TestServerCardEndpoint:
    """Tests for the /.well-known/mcp/server-card endpoint."""

    def test_server_card_returns_200(self, test_client):
        """Test that the server card endpoint returns 200 OK."""
        response = test_client.get("/.well-known/mcp/server-card")
        
        assert response.status_code == 200
        
        data = response.json()
        assert "name" in data
        assert "description" in data
        assert "version" in data
        assert "url" in data

    def test_server_card_served_at_resource_suffixed_path(self, test_client):
        """Clients probe the path-insertion form for a resource served at /mcp."""
        response = test_client.get("/.well-known/mcp/server-card/mcp")

        assert response.status_code == 200
        assert response.json() == test_client.get("/.well-known/mcp/server-card").json()

    def test_server_card_returns_expected_structure(self, test_client, mock_settings):
        """Test that the server card returns expected MCP discovery format."""
        response = test_client.get("/.well-known/mcp/server-card")
        data = response.json()

        assert data["name"] == mock_settings.mcp_name
        assert data["version"] == mock_settings.mcp_version
        assert data["url"] == "/mcp"
        assert "auth" in data
        assert data["auth"]["type"] == "oauth2"
        assert data["auth"]["version"] == "2.1"
        auth_code_flow = data["auth"]["flows"]["authorizationCode"]
        assert "tokenUrl" in auth_code_flow
        assert "authorizationUrl" in auth_code_flow
        assert "registrationUrl" in auth_code_flow
        assert auth_code_flow["pkceRequired"] is True
        assert "capabilities" in data
