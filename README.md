# MCP Gateway

MCP Gateway is a small self-hosted PHP application that exposes one stable MCP endpoint for multiple independently authorized backend sites.

V1 ships with the [WP AI Bridge](https://github.com/ach1992/wp-ai-bridge) connector. It lets one ChatGPT custom MCP App work with multiple WordPress sites without creating a separate ChatGPT App for every site.

The Gateway is a routing and connection layer. WordPress and WP AI Bridge remain authoritative for WordPress permissions. MCP Gateway does not grant capabilities that the connected WordPress account or WP AI Bridge access policy denies.

## V1 highlights

- one public MCP endpoint for many connected WordPress sites;
- current ChatGPT custom MCP App OAuth/MCP flow;
- explicit `site_id` routing for every site-specific operation;
- independent encrypted credentials and revocation per site;
- a server-rendered administration panel for sites, connection status, activity, and client connection information;
- stable Gateway tools for listing sites, reading site context, inspecting Ability contracts, and executing an exact Ability;
- bounded outbound HTTP behavior with HTTPS validation, DNS pinning, redirect restrictions, timeouts, and response-size limits;
- deployment/runtime diagnostics through `php artisan gateway:check`;
- validated PHP 8.4 + MySQL + OpenLiteSpeed deployment shape;
- documented backup and recovery requirements.

## Requirements

MCP Gateway V1 is intended for a conventional Linux PHP host such as aaPanel with OpenLiteSpeed.

Required runtime:

- PHP `>= 8.4.1` on the PHP 8.4 line;
- PHP extensions: `curl`, `mbstring`, `openssl`, `pdo_mysql`, and `sodium`;
- cURL with `CURLOPT_RESOLVE` support;
- MySQL;
- Composer 2;
- HTTPS on a stable domain or subdomain;
- OpenLiteSpeed or an equivalent PHP web server that serves only the Laravel `public/` directory.

Normal V1 operation does **not** require Redis, Docker, Node.js, a queue worker, a message broker, or a separate MCP daemon.

## Installation

MCP Gateway does not require a separate installer shell script. The supported installation path is the repository-owned Composer + Artisan workflow below.

The examples use:

```text
APP_ROOT=/www/wwwroot/mcp-gateway
GATEWAY_ORIGIN=https://gateway.example.com
```

Replace these values with your real path and hostname.

### 1. Prepare the host

Before installing the application:

1. Create the Gateway site/domain in aaPanel or your hosting control panel.
2. Point DNS to the server.
3. Enable a valid HTTPS certificate for the exact Gateway hostname.
4. Select PHP 8.4 for the website and for the CLI used by Composer/Artisan.
5. Create a dedicated MySQL database and database user for MCP Gateway.

Verify the required CLI runtime:

```bash
php -v
php -r 'foreach (["curl", "mbstring", "openssl", "pdo_mysql", "sodium"] as $extension) { if (! extension_loaded($extension)) { fwrite(STDERR, "Missing PHP extension: {$extension}\n"); exit(1); } } if (! defined("CURLOPT_RESOLVE")) { fwrite(STDERR, "Missing cURL CURLOPT_RESOLVE support\n"); exit(1); } echo "Required PHP extensions: OK\n";'
composer --version
```

### 2. Install the release

For a stable installation, use an immutable release tag instead of a moving branch:

```bash
cd /www/wwwroot
git clone --branch v1.0.1 --depth 1 https://github.com/ach1992/mcp-gateway.git mcp-gateway
cd mcp-gateway
composer install --no-dev --no-interaction --prefer-dist --optimize-autoloader
composer check-platform-reqs --no-dev
cp .env.example .env
php artisan key:generate
```

Do not run `composer update` on the server. The deployment must use the committed `composer.lock` through `composer install`.

### 3. Configure `.env`

Set the production values for your host. At minimum, review and configure:

```dotenv
APP_ENV=production
APP_DEBUG=false
APP_URL=https://gateway.example.com

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=mcp_gateway
DB_USERNAME=mcp_gateway
DB_PASSWORD=<server-secret>

SESSION_DRIVER=file
SESSION_ENCRYPT=true
SESSION_SECURE_COOKIE=true
SESSION_HTTP_ONLY=true
SESSION_SAME_SITE=lax

CACHE_STORE=file
QUEUE_CONNECTION=sync
FILESYSTEM_DISK=local

MCP_BOOTSTRAP_FIXTURE_ENABLED=false
MCP_BOOTSTRAP_FIXTURE_TOKEN=

OAUTH_PRIVATE_KEY_PATH=storage/app/private/oauth/private.key
OAUTH_PUBLIC_KEY_PATH=storage/app/private/oauth/public.key
BRIDGE_CLIENT_PRIVATE_KEY_PATH=storage/app/private/bridge-client/private.key
BRIDGE_CLIENT_PUBLIC_KEY_PATH=storage/app/private/bridge-client/public.key
```

Important rules:

- `APP_URL` must be the canonical HTTPS origin for the Gateway. Do not include a path, query, fragment, or user information.
- Keep `APP_DEBUG=false` in production.
- Never commit `.env`, `APP_KEY`, passwords, OAuth tokens, or private keys.
- Keep `SESSION_ENCRYPT=true` and HTTPS-only cookies in production.
- Keep `MCP_BOOTSTRAP_FIXTURE_ENABLED=false` in production.
- The Gateway OAuth signing pair and Gateway-to-Bridge signing pair must be different keypairs.

### 4. Configure the web root and ownership

The website document root / aaPanel running directory must be:

```text
/www/wwwroot/mcp-gateway/public
```

Do **not** expose the repository root as the web root. The repository root contains `.env`, application code, private storage, and Composer metadata.

OpenLiteSpeed should have rewrite processing enabled and should load the repository-owned `public/.htaccess` rules.

Run Composer and Artisan as the application/PHP owner whenever practical. The PHP process must be able to write:

```text
storage/
bootstrap/cache/
```

Do not solve ownership problems with `chmod -R 777`. Private signing keys must remain outside `public/` with restrictive permissions.

### 5. Generate both signing keypairs

Run these commands as the deployment/PHP owner:

```bash
php artisan gateway:oauth-keygen
php artisan gateway:bridge-client-keygen
```

Expected messages include:

```text
OAuth signing keypair generated.
Bridge OAuth client signing keypair generated.
```

Do not use `--force` during a normal installation or upgrade. Replacing either signing identity is a deliberate key-rotation event, not routine deployment work.

### 6. Initialize the database and administrator

Run the migrations:

```bash
php artisan migrate --force
```

Create the first administrator interactively:

```bash
php artisan gateway:admin:create
```

The administrator password is accepted through hidden interactive prompts. Do not place the password in a shell command, deployment script, environment variable, or process argument.

### 7. Run the deployment gate

Before using the installation, run:

```bash
php artisan gateway:check
```

Every reported item must be `[OK]`. The check validates the important runtime/security requirements, including PHP extensions, MySQL, `APP_KEY`, canonical HTTPS identity, both signing keypairs, private storage, encrypted administrator sessions, and secure production cookies.

A failed check is a deployment blocker. Fix the underlying configuration or ownership issue instead of weakening the check.

### 8. Verify public endpoints

Use only non-secret endpoints for the initial smoke test:

```bash
curl --fail --silent --show-error https://gateway.example.com/up
curl --fail --silent --show-error https://gateway.example.com/.well-known/oauth-protected-resource/mcp
curl --fail --silent --show-error https://gateway.example.com/.well-known/oauth-authorization-server
curl --fail --silent --show-error --output /dev/null https://gateway.example.com/oauth/client.json
curl --fail --silent --show-error --output /dev/null https://gateway.example.com/oauth/jwks.json
```

Then validate the current ChatGPT OAuth client metadata contract:

```bash
php artisan gateway:oauth-client-check --refresh
```

Do not place access tokens, refresh tokens, authorization codes, assertions, passwords, `.env` contents, `APP_KEY`, or private-key contents in screenshots or logs.

## Connect WordPress sites

Each WordPress site needs a compatible WP AI Bridge installation. V1 was validated against the WP AI Bridge contract at commit `37d1b39b8f53f4667d67c4effc00e01f7aa193a8`.

For each site:

1. Sign in to MCP Gateway at:

   ```text
   https://gateway.example.com/admin/login
   ```

2. Open **Sites** and choose **Add WordPress site**.
3. Enter a human-readable site name and the site's canonical HTTPS WordPress base URL.
4. Save the site. The Gateway validates/discovers the WP AI Bridge OAuth/MCP endpoints.
5. Choose **Connect**.
6. Complete the WordPress/WP AI Bridge OAuth consent flow as the WordPress user whose permissions should be delegated.
7. Return to the Gateway and confirm the site shows as connected.
8. Use **Test connection** to verify the current Bridge connection.
9. Repeat for additional WordPress sites.

Each site stores an independent encrypted authorization relationship. Disconnecting or revoking one site does not grant or revoke permissions on another site.

WP AI Bridge access groups and WordPress capabilities still control what the Gateway can do. If Bridge denies an operation, the Gateway preserves that denial instead of bypassing it.

## Connect ChatGPT

The canonical client connection information is also shown in the authenticated Gateway page:

```text
https://gateway.example.com/admin/connection
```

For one ChatGPT custom MCP App, use this MCP server URL:

```text
https://gateway.example.com/mcp
```

The Gateway exposes OAuth/protected-resource discovery metadata from the same canonical HTTPS origin. ChatGPT should use that discovery flow rather than a manually pasted bearer token.

Before the first ChatGPT authorization, sign in to the Gateway administrator panel in the same browser. When ChatGPT starts OAuth authorization:

1. the Gateway shows the authorization consent page;
2. verify the displayed client/redirect information;
3. approve the connection;
4. ChatGPT exchanges the authorization code through the Gateway OAuth endpoint;
5. authenticated MCP tool discovery becomes available to the App.

One ChatGPT App is enough for all sites registered in the Gateway. Adding another WordPress site does not require changing the ChatGPT MCP endpoint.

## Gateway MCP tools

V1 intentionally exposes a small stable tool surface:

- `sites-list` — list configured sites without exposing credentials;
- `site-context` — inspect bounded connection/context information for one explicit site;
- `site-abilities-read` — discover or inspect the selected site's WP AI Bridge Ability contracts;
- `site-ability-execute` — execute one exact Ability against one explicit `site_id`.

Typical client flow:

1. Call `sites-list` and identify the required `site_id`.
2. Inspect that site's context or Ability catalog if needed.
3. Select the exact Ability.
4. Execute it with the explicit `site_id` and schema-valid input.

Do not rely on an implicit conversational "current site" for writes. Site selection is intentionally explicit.

## Administration

Useful operator pages:

```text
/admin              Dashboard
/admin/sites        Site registry
/admin/activity     Bounded recent activity
/admin/connection   MCP/client connection information
```

The web panel supports adding/editing site metadata, connect/reconnect/disconnect, connection testing, site removal, and recent activity inspection.

## Upgrade

Before every migration-bearing upgrade, preserve one recovery set containing:

- a consistent MySQL database backup;
- the matching `.env` / `APP_KEY` through your approved secret-backup mechanism;
- the Gateway OAuth signing keypair;
- the Gateway-to-Bridge signing keypair;
- the currently deployed release tag/commit and `composer.lock` identity.

Then move to the intended release tag and run:

```bash
composer install --no-dev --no-interaction --prefer-dist --optimize-autoloader
composer check-platform-reqs --no-dev
php artisan optimize:clear
php artisan migrate --force
php artisan gateway:check
```

Repeat the public endpoint smoke tests after the upgrade.

Do not blindly run `migrate:rollback` after a partial or unknown deployment failure. Restore the known recovery set or use release-specific roll-forward/rollback instructions when schema compatibility is uncertain.

## Troubleshooting

Start with:

```bash
php artisan gateway:check
```

Common causes of deployment problems:

- the website points at the repository root instead of `public/`;
- PHP CLI and web PHP use different versions/extensions;
- `storage/` or `bootstrap/cache/` is not writable by the PHP runtime;
- signing keys were generated by a different filesystem owner;
- `APP_URL` does not exactly match the public HTTPS origin;
- secure cookies are enabled while testing through plain HTTP;
- MySQL credentials/permissions are incorrect;
- ambient proxy configuration interferes with assumptions for direct Gateway-to-Bridge HTTP traffic.

For deployment details and security boundaries, see [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

## Documentation

- [`docs/MASTER-SPEC.md`](docs/MASTER-SPEC.md) — canonical V1 product requirements and boundaries.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — architecture and protocol boundaries.
- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) — detailed deployment, validation, backup, upgrade, and rollback guidance.
- [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) — development and validation workflow.
- [`docs/PROJECT-MAP.md`](docs/PROJECT-MAP.md) — maintainer/agent recovery map.

## Release status

V1 is complete and released. Stable installations should use the published `v1.0.1` tag rather than `main`.

Publishing a GitHub release does not deploy MCP Gateway to any server automatically. Production deployment remains an operator-controlled action.

## License

MCP Gateway is open-source software released under the [MIT License](LICENSE).
