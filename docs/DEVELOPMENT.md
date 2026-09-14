# MCP Gateway Development

This document owns the repeatable development and validation workflow. User-facing installation belongs in `README.md` once a production release exists.

## Baseline

The current bootstrap is intentionally a conventional PHP application:

- PHP 8.4.1 or newer within the PHP 8.4-compatible dependency range;
- Laravel 13;
- Composer 2;
- MySQL as the production database;
- Blade/server-rendered frontend;
- no required Node.js build, Redis, queue worker, Docker, broker, or separate MCP daemon.

CI uses MySQL 8.4 to exercise a clean migration path. Application tests may use SQLite in memory when the test does not depend on MySQL-specific behavior.

## Install a development checkout

From the repository root:

```bash
composer install
cp .env.example .env
php artisan key:generate
```

Edit only the database values in `.env` for the local MySQL database and account you created:

```dotenv
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=mcp_gateway
DB_USERNAME=mcp_gateway
DB_PASSWORD=your-local-password
```

Then initialize and validate the application:

```bash
php artisan migrate
php artisan gateway:check
composer check
```

Run the local web server when needed:

```bash
composer dev
```

The health endpoint is `/up`.

## Deterministic validation

The normal repository checks are:

```bash
composer validate --strict
composer audit --locked
composer lint
composer analyse
composer test
```

`composer check` runs style, static analysis, and tests together. CI additionally runs `migrate:fresh` against MySQL and executes `gateway:check` with MySQL selected.

## MCP bootstrap compatibility fixture

`/_internal/mcp-bootstrap` exists only to prove the Laravel/PSR/MCP SDK integration during bootstrap. It is disabled by default and returns `404` unless both of these test-only settings are supplied:

```dotenv
MCP_BOOTSTRAP_FIXTURE_ENABLED=true
MCP_BOOTSTRAP_FIXTURE_TOKEN=an-ephemeral-test-token
```

Do not enable this fixture in production. The integration test starts an isolated local Laravel process, sends an explicit bearer token through the official MCP PHP client, exercises Streamable HTTP, lists the controlled fixture tool, and then shuts the process down.

The production MCP endpoint is implemented by the ChatGPT-facing workstream, not by promoting this fixture.

Handshake-era Streamable HTTP clients use an MCP session ID across multiple HTTP requests. In a normal PHP request lifecycle, the SDK's in-memory session store is not durable across workers/requests. The bootstrap therefore uses the SDK `FileSessionStore` under `storage/framework/mcp-sessions` with a bounded TTL (`MCP_SESSION_TTL_SECONDS`, default `3600`). That directory is private application state and is ignored by Git. A future multi-host deployment would need a shared durable store before horizontal scaling, but V1 is a single-host deployment.

## Locked protocol dependencies

The bootstrap deliberately isolates protocol packages behind `app/Infrastructure` adapters.

- `mcp/sdk` `0.8.1` — official PHP MCP SDK; owns MCP server/client framing and Streamable HTTP behavior.
- `symfony/psr-http-message-bridge` `8.1.x` — converts Laravel/Symfony HTTP Foundation requests and responses at the SDK boundary.
- `league/oauth2-server` `9.4.1` — selected for authorization-code, PKCE, access/refresh-token issuance, rotation primitives, and token/code revocation state.

Composer's lockfile is authoritative for transitive versions. Dependency upgrades require release-note review plus the focused MCP/OAuth compatibility tests; do not widen these constraints casually while the MCP SDK remains pre-1.0.

## OAuth boundary selected by bootstrap

`league/oauth2-server` does not natively authenticate OAuth clients with `private_key_jwt`. Its confidential-client path expects a client secret, while the current ChatGPT/WP AI Bridge contract uses Client ID Metadata plus signed `private_key_jwt` client assertions.

Therefore the Gateway authorization server uses this split:

1. a Gateway-owned OAuth edge adapter validates the exact approved client identity, metadata/JWKS, `private_key_jwt`, audience, signature, expiry, and replay rules;
2. only a successfully authenticated request may reach the League authorization-server lifecycle;
3. League owns authorization-code/PKCE validation and access/refresh-token issuance/rotation primitives;
4. Gateway persistence adapters implement League repository interfaces and durable revocation state;
5. token issuance, authorization-code cryptography, and refresh-token generation are not reimplemented by application controllers.

The complete ChatGPT-facing OAuth implementation is a later workstream. This bootstrap decision prevents that workstream from incorrectly treating League as a native `private_key_jwt` implementation or weakening the client-authentication contract to a shared secret.

## OpenLiteSpeed note

The official MCP SDK emits Streamable HTTP/SSE responses and sets response headers intended to discourage buffering. The exact OpenLiteSpeed/LSAPI buffering and long-response behavior must still be verified on the deployment stack before production delivery. Do not infer nginx-specific directives as an OpenLiteSpeed configuration.
