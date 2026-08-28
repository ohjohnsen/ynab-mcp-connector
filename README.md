# YNAB MCP Connector

A Model Context Protocol (MCP) connector for You Need A Budget (YNAB) that exposes the official YNAB API v1.85.0 functionality to AI assistants like Claude.ai and Mistral.

## Features

- **MCP Standard Endpoints**: Health checks, server info, and capabilities
- **OAuth 2.0 Authentication**: Authorization Code + PKCE S256 flow with refresh tokens, compatible with Claude.ai connectors
- **Plans Management**: List and retrieve YNAB plan details with all related entities
- **User Information**: Get authenticated user data
- **Accounts Management**: Full CRUD operations for accounts
- **Categories Management**: Full CRUD operations for categories and category groups
- **Payees Management**: Full CRUD operations for payees
- **Transactions Management**: Full CRUD operations, bulk updates, and import functionality
- **Scheduled Transactions**: Full CRUD operations for future-dated transactions
- **Months**: Access plan months and month-specific data
- **Money Movements**: Read access to money movement history
- **Resource Discovery**: MCP-compatible resource endpoints using URIs
- **Tool Integration**: 30+ MCP tool endpoints for AI assistant integration

## Prerequisites

- Python 3.13+
- [uv](https://github.com/astral-sh/uv) package manager
- A [YNAB Personal Access Token](https://api.ynab.com/#personal-access-tokens)

## Quick Start

### 1. Clone and Setup

```bash
git clone <repository-url>
cd ynab-mcp-connector
```

### 2. Install Dependencies

```bash
uv sync
```

This installs all required dependencies:
- FastAPI
- Uvicorn
- Pydantic
- HTTPX

### 3. Configure `.env`

Create a `.env` file in the project root:

```env
YNAB_API_KEY=your_ynab_personal_access_token
OAUTH_CLIENT_ID=choose_any_client_id
OAUTH_CLIENT_SECRET=choose_any_client_secret
```

See [Authentication](#authentication) below for what these do and when `OAUTH_CLIENT_ID`/`OAUTH_CLIENT_SECRET` are needed.

### 4. Run the Server

```bash
uv run python main.py
```

The server will start on `http://0.0.0.0:8000` with auto-reload enabled.

### 5. Verify It Works

```bash
curl http://localhost:8000/mcp/health
# {"status":"healthy","version":"0.4.5"}

curl http://localhost:8000/mcp/info
# {"name":"YNAB Connector","version":"0.4.5",...}
```

## Authentication

This connector supports two authentication modes, chosen automatically based on whether `OAUTH_CLIENT_SECRET` is set.

### Mode 1: OAuth 2.0 (for Claude.ai and other MCP clients that require OAuth)

Set `OAUTH_CLIENT_ID` and `OAUTH_CLIENT_SECRET` in `.env` (any values you choose) along with `YNAB_API_KEY`. The connector then:

- Implements the **Authorization Code + PKCE (S256)** flow required by Claude.ai
- Auto-approves and redirects immediately — there is no consent page, since this connector is single-owner
- Issues self-verifying, HMAC-signed access tokens (1 hour) and refresh tokens (30 days) — no server-side session state, so tokens survive server restarts
- Returns a real HTTP `401` with a `WWW-Authenticate` header on unauthenticated MCP requests, so OAuth-aware clients can discover the flow

Relevant endpoints:

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/.well-known/oauth-protected-resource` | RFC 9728 — tells clients which auth server issues tokens for this resource |
| GET | `/.well-known/oauth-authorization-server` | RFC 8414 — authorization server metadata |
| GET | `/oauth/authorize` | Authorization endpoint (redirects with a code) |
| POST | `/oauth/token` | Token endpoint — `authorization_code` and `refresh_token` grants |

The registered redirect URIs default to Claude.ai's callback (`https://claude.ai/api/mcp/auth_callback`), overridable via `OAUTH_REDIRECT_URIS` (comma-separated list, e.g. to also allow a local debug callback).

In this mode, the YNAB API key lives only in the server's `.env` — it is never passed by the client.

### Mode 2: Direct Bearer Token (no `.env` required)

If `OAUTH_CLIENT_SECRET` is left unset, the connector falls back to treating the `Authorization` header as a YNAB personal access token directly:

```http
Authorization: Bearer <your_ynab_personal_access_token>
```

`YNAB_API_KEY` is not used in this mode — each request supplies its own token.

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `YNAB_API_KEY` | Yes, if using OAuth mode | `""` | YNAB personal access token, used server-side once an OAuth token is verified |
| `YNAB_API_URL` | No | `https://api.ynab.com/v1` | YNAB API base URL (v1.85.0) |
| `OAUTH_CLIENT_ID` | No (enables OAuth mode when set with secret) | `""` | Client ID issued to MCP clients connecting via OAuth |
| `OAUTH_CLIENT_SECRET` | No (enables OAuth mode when set) | `""` | Shared secret; also used as the HMAC signing key for issued tokens |
| `OAUTH_REDIRECT_URIS` | No | `https://claude.ai/api/mcp/auth_callback` | Registered OAuth redirect URIs (comma-separated) |
| `SERVER_HOST` | No | `0.0.0.0` | Server host address |
| `SERVER_PORT` | No | `8000` | Server port |
| `MCP_NAME` | No | `YNAB Connector` | MCP server name |
| `MCP_VERSION` | No | version from `pyproject.toml` | MCP server version |

## API Overview

This connector implements the **official YNAB API v1.85.0** specification.

### Supported Resources

| Resource | Operations | Description |
|----------|------------|-------------|
| User | Read | Authenticated user information |
| Plans | Read | List all plans, get plan details and settings |
| Accounts | Read, Create | All accounts for a plan |
| Categories | Read, Create, Update | Categories and category groups |
| Payees | Read, Create, Update | Payees for a plan |
| Payee Locations | Read | GPS locations for payees |
| Months | Read | Plan months with summaries and details |
| Transactions | Read, Create, Update, Delete | Full transaction management |
| Scheduled Transactions | Read, Create, Update, Delete | Future-dated transactions |
| Money Movements | Read | Money movement history |

## Parameter Validation

The connector validates all input parameters and returns clear error messages:

- **Required parameters**: Returns `"{param_name} is required"` if missing
- **Date parameters**: Must be in `YYYY-MM-DD` format (e.g., `"2024-01-15"`)
- **Type validation**: Parameters must match their expected types
- **Pagination**: `limit` must be a positive integer, `offset` must be non-negative

Invalid requests return JSON-RPC error responses with code `-32602` (Invalid params).

Authentication failures on methods that require it (`tools/call`, `resources/list`, `resources/read`, `resources/write`) return a real HTTP `401` (with `WWW-Authenticate` in OAuth mode) rather than a JSON-RPC error body, so OAuth-aware clients can detect and trigger re-authentication. All other errors are returned as HTTP 200 with a JSON-RPC error body, per the MCP JSON-RPC convention.

## MCP Integration

This connector implements the **Model Context Protocol (MCP)** specification using **JSON-RPC 2.0**, allowing AI assistants to interact with YNAB data.

### MCP Discovery

- **Server Card**: `GET /.well-known/mcp/server-card`
- **MCP Endpoint**: `POST /mcp` (JSON-RPC 2.0)
- **OAuth Discovery**: `GET /.well-known/oauth-protected-resource`, `GET /.well-known/oauth-authorization-server` (see [Authentication](#authentication))

### Resource URIs

All resources use the official YNAB `/plans/` terminology:

```
ynab://user
ynab://plans
ynab://plan/{plan_id}
ynab://plan/{plan_id}/settings
ynab://plan/{plan_id}/accounts
ynab://plan/{plan_id}/accounts/{account_id}
ynab://plan/{plan_id}/categories
ynab://plan/{plan_id}/categories/{category_id}
ynab://plan/{plan_id}/category_groups
ynab://plan/{plan_id}/category_groups/{category_group_id}
ynab://plan/{plan_id}/payees
ynab://plan/{plan_id}/payees/{payee_id}
ynab://plan/{plan_id}/payee_locations
ynab://plan/{plan_id}/payee_locations/{payee_location_id}
ynab://plan/{plan_id}/payees/{payee_id}/payee_locations
ynab://plan/{plan_id}/months
ynab://plan/{plan_id}/months/{month}
ynab://plan/{plan_id}/transactions
ynab://plan/{plan_id}/transactions/{transaction_id}
ynab://plan/{plan_id}/scheduled_transactions
ynab://plan/{plan_id}/scheduled_transactions/{scheduled_transaction_id}
ynab://plan/{plan_id}/money_movements
ynab://plan/{plan_id}/money_movement_groups
```

**Special plan_id values**: `"last-used"` and `"default"` are supported where applicable.

### Available MCP Tools

30+ tools are available via `tools/list` and `tools/call`:

**User:**
- `get_user` - Get authenticated user information

**Plans:**
- `get_plans` - List all accessible plans
- `get_plan` - Get a specific plan with all related entities
- `get_plan_settings` - Get settings for a plan

**Accounts:**
- `get_accounts` - List all accounts for a plan
- `get_account` - Get a specific account
- `create_account` - Create a new account

**Categories:**
- `get_categories` - List all categories for a plan
- `get_category` - Get a specific category
- `create_category` - Create a new category
- `update_category` - Update an existing category

**Category Groups:**
- `create_category_group` - Create a new category group
- `update_category_group` - Update a category group

**Payees:**
- `get_payees` - List all payees for a plan
- `get_payee` - Get a specific payee
- `create_payee` - Create a new payee
- `update_payee` - Update a payee

**Months:**
- `get_months` - List all months for a plan
- `get_month` - Get a specific month

**Transactions:**
- `get_transactions` - Get transactions for a plan (with filters)
- `get_transaction` - Get a specific transaction
- `create_transaction` - Create a new transaction
- `update_transaction` - Update a transaction
- `update_transactions` - Update multiple transactions
- `delete_transaction` - Delete a transaction
- `import_transactions` - Import transactions from linked accounts

**Scheduled Transactions:**
- `get_scheduled_transactions` - List all scheduled transactions
- `get_scheduled_transaction` - Get a specific scheduled transaction
- `create_scheduled_transaction` - Create a new scheduled transaction
- `update_scheduled_transaction` - Update a scheduled transaction
- `delete_scheduled_transaction` - Delete a scheduled transaction

### Example MCP Tool Calls

**Get User:**
```json
{
  "name": "get_user",
  "arguments": {}
}
```

**Get Plans:**
```json
{
  "name": "get_plans",
  "arguments": {
    "include_accounts": true
  }
}
```

**Get Plan:**
```json
{
  "name": "get_plan",
  "arguments": {
    "plan_id": "your-plan-id"
  }
}
```

**Get Transactions:**
```json
{
  "name": "get_transactions",
  "arguments": {
    "plan_id": "your-plan-id",
    "since_date": "2024-01-01",
    "until_date": "2024-01-31",
    "type": "uncategorized",
    "limit": 50,
    "offset": 0
  }
}
```

**Date Filtering:**
- `since_date`: Transactions on or after this date (format: `YYYY-MM-DD`)
- `until_date`: Transactions on or before this date (format: `YYYY-MM-DD`)
- Both parameters are optional. If not provided, all transactions are returned.
- Invalid date formats return a clear error message.

**Pagination:**
- `limit`: Maximum number of transactions to return (client-side pagination)
- `offset`: Number of transactions to skip
- When `limit` is specified, the response includes pagination metadata:
  ```json
  {
    "data": {
      "transactions": [...],
      "pagination": {
        "limit": 50,
        "offset": 0,
        "total": 125
      }
    }
  }
  ```

**Create Transaction:**
```json
{
  "name": "create_transaction",
  "arguments": {
    "plan_id": "your-plan-id",
    "transaction": {
      "account_id": "your-account-id",
      "date": "2024-01-15",
      "amount": 100000,
      "payee_name": "Grocery Store",
      "category_id": "your-category-id",
      "memo": "Weekly groceries",
      "cleared": "cleared",
      "approved": true
    }
  }
}
```

**Update Month Category Budget:**
```json
{
  "name": "update_month_category",
  "arguments": {
    "plan_id": "your-plan-id",
    "month": "2024-01-01",
    "category_id": "your-category-id",
    "budgeted": 500000
  }
}
```

> **Note**: All currency amounts are in **milliunits** format (e.g., $100 = 100000, $1 = 1000).

### MCP Resources

List all available resources:
```json
{
  "method": "resources/list",
  "params": {}
}
```

Read a specific resource:
```json
{
  "method": "resources/read",
  "params": {
    "uri": "ynab://plan/your-plan-id"
  }
}
```

Write to a resource (create/update):
```json
{
  "method": "resources/write",
  "params": {
    "uri": "ynab://plan/your-plan-id/transactions",
    "content": "{\"transaction\": {\"account_id\": \"...\", \"amount\": 100000}}"
  }
}
```

## REST API Endpoints

For direct HTTP access (in addition to MCP JSON-RPC):

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/mcp/health` | Health check |
| GET | `/mcp/info` | Server info and capabilities |
| GET | `/.well-known/mcp/server-card` | MCP server discovery card |
| GET | `/.well-known/oauth-protected-resource` | OAuth protected resource metadata (RFC 9728) |
| GET | `/.well-known/oauth-authorization-server` | OAuth authorization server metadata (RFC 8414) |
| GET | `/oauth/authorize` | OAuth authorization endpoint |
| POST | `/oauth/token` | OAuth token endpoint (`authorization_code`, `refresh_token` grants) |

## Project Structure

```
ynab-mcp-connector/
├── main.py              # Server entry point
├── config.py            # Configuration management
├── mcp_server.py        # FastAPI application with MCP JSON-RPC + OAuth endpoints
├── ynab_client.py       # YNAB API v1.85.0 client (aligned with official spec)
├── api-1.json           # YNAB OpenAPI specification v1.85.0
├── pyproject.toml       # Project configuration
├── Dockerfile           # Container image definition
├── docker-compose.yml   # Container deployment config
├── tests/               # Unit and integration tests
├── .gitignore
└── README.md
```

## Data Format Notes

### Currency Amounts
- All monetary values use **milliunits** format (integer)
- Example: $1.23 = 1230, $100 = 100000
- The connector passes amounts through exactly as returned by the YNAB API — no formatted/currency convenience fields are added

### Dates
- ISO 8601 format: `YYYY-MM-DD`
- Special value: `"current"` for current month
- Date-time format: `YYYY-MM-DDTHH:MM:SSZ`

### IDs
- Plans: UUID string or special values (`"last-used"`, `"default"`)
- Accounts: UUID string
- Categories: UUID string
- Payees: UUID string
- Transactions: String ID
- Scheduled Transactions: String ID

## Development

### Install Dev Dependencies

```bash
uv sync --all-extras
```

### Run Tests

```bash
uv run pytest
```

### Run Linter

```bash
uv run ruff check .
```

## API Compliance

This connector is **fully aligned** with the official YNAB API v1.85.0 OpenAPI specification.

- ✅ Uses `/plans/` terminology (not `/budgets/`)
- ✅ Uses `plan_id` parameter (not `budget_id`)
- ✅ Supports special values: `"last-used"`, `"default"`
- ✅ Implements all major YNAB API endpoints
- ✅ Follows YNAB's milliunits currency format
- ✅ Uses `api.ynab.com` base URL

## YNAB API Documentation

For more information on the YNAB API v1.85.0, see:
- https://api.ynab.com
- [api-1.json](./api-1.json) (included in this repository)

## License

This project is provided as-is for use with Mistral, Claude.ai, and YNAB.
