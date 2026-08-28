"""Configuration management for YNAB MCP Connector."""

from __future__ import annotations

from pathlib import Path
import tomllib

from pydantic_settings import BaseSettings, SettingsConfigDict

# Only load .env file if it actually exists — otherwise rely purely on OS
# environment variables (e.g. when running in Docker with env vars injected
# via docker-compose). Without this guard, pydantic-settings may silently
# prefer the absent file path over real environment variables on some versions.
_env_file = ".env" if Path(".env").exists() else None


def _default_connector_version() -> str:
    """Read connector version from pyproject.toml with a safe fallback."""
    fallback_version = "0.4.3"
    try:
        pyproject_path = Path(__file__).with_name("pyproject.toml")
        data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
        return str(data.get("project", {}).get("version", fallback_version))
    except Exception:
        return fallback_version


class Settings(BaseSettings):
    """Application settings with environment variable support."""

    model_config = SettingsConfigDict(
        env_file=_env_file,
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # YNAB API Configuration
    ynab_api_key: str = ""
    ynab_api_url: str = "https://api.ynab.com/v1"

    # OAuth Configuration (for Claude.ai MCP integration)
    oauth_client_id: str = ""
    oauth_client_secret: str = ""
    oauth_redirect_uris: str = "https://claude.ai/api/mcp/auth_callback"

    # Server Configuration
    server_host: str = "0.0.0.0"
    server_port: int = 8000

    # MCP Configuration
    mcp_name: str = "YNAB Connector"
    mcp_version: str = _default_connector_version()

    @property
    def oauth_redirect_uri_list(self) -> list[str]:
        """Registered redirect URIs, parsed from a comma-separated env var."""
        return [uri.strip() for uri in self.oauth_redirect_uris.split(",") if uri.strip()]

    @property
    def ynab_headers(self) -> dict[str, str]:
        """Generate headers for YNAB API requests."""
        return {
            "Authorization": f"Bearer {self.ynab_api_key}",
            "Content-Type": "application/json",
        }


# Global settings instance
settings = Settings()
