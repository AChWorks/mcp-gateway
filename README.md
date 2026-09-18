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
- a deployment-ready ZIP and one-page web installer for aaPanel/shared hosting;
- a one-time browser updater for deployment-ZIP installations, with no SSH, Git, or Composer required on the target host;
- documented backup and recovery requirements.

## Requirements

MCP Gateway is intended for a conventional Linux PHP host such as aaPanel/OpenLiteSpeed or ordinary shared hosting.

Required runtime:

- PHP `>= 8.4.1`;
- PHP extensions: `curl`, `mbstring`, `openssl`, `pdo_mysql`, and `sodium`;
- cURL with `CURLOPT_RESOLVE` support;
- MySQL;
- HTTPS on a stable domain or subdomain;
- a web server/hosting panel that can point the domain document root to the package `public/` directory.

Composer 2 and Git are **not required on the target host** when using the recommended deployment ZIP. They are only required for the advanced source/CLI installation path.

Normal operation does **not** require Redis, Docker, Node.js, a queue worker, a message broker, or a separate MCP daemon.

## Installation

### Recommended: deployment ZIP + web installer

This is the easiest installation method for aaPanel and compatible shared hosting.

1. Create a dedicated HTTPS domain/subdomain, for example `gateway.example.com`.
2. Create a dedicated **empty** MySQL database and database user.
3. Open the [latest stable GitHub Release](https://github.com/ach1992/mcp-gateway/releases/latest) and download its named deployment asset `mcp-gateway-vX.Y.Z.zip`.
4. Upload and extract the ZIP on the host. The archive contains only deployment/runtime files and already includes production Composer dependencies in `vendor/`.
5. Point the domain document root / aaPanel running directory to the extracted package's `public/` directory. Example:

   ```text
   /www/wwwroot/mcp-gateway/public
   ```

6. Make sure the PHP process can write to:

   ```text
   storage/
   bootstrap/cache/
   ```

7. Enable the final HTTPS certificate **before** entering credentials in the installer.
8. Open:

   ```text
   https://gateway.example.com/install
   ```

9. Enter:
   - the canonical Gateway HTTPS URL;
   - MySQL host/port/database/user/password;
   - the first administrator name/email/password.
10. Select **Install MCP Gateway**.

The named deployment ZIP is assembled in a clean staging tree from the committed dependency lockfile. Its bundled `vendor/` contains production dependencies and required runtime/license material only; repository metadata, development tools/dependencies, package docs/examples/tests, generated test keys, sessions, caches, logs, and other transient state are excluded. Writable runtime directories are shipped empty.

The installer automatically:

- checks PHP/extensions, HTTPS, bundled dependencies, and writable paths;
- requires a dedicated empty MySQL database;
- writes a production `.env` and unique `APP_KEY`;
- runs the database migrations without shell command execution;
- generates the Gateway OAuth keypair and the separate Gateway-to-WP-AI-Bridge keypair;
- runs the existing Gateway environment/security check;
- creates the first administrator;
- writes a private installed marker and permanently disables reinstall through the web installer.

After success, continue to:

```text
https://gateway.example.com/admin/login
```

The installer never displays the MySQL password, `APP_KEY`, private keys, access tokens, or other generated secret material.

> The regular GitHub **Source code (zip)** archive is not the deployment package because it does not include production `vendor/`. Use the named `mcp-gateway-vX.Y.Z.zip` asset from the intended GitHub Release.

### aaPanel quick setup

A typical aaPanel setup is:

```text
Domain:          gateway.example.com
PHP:             8.4
Database:        dedicated MySQL database/user
Application:     /www/wwwroot/mcp-gateway
Running directory/document root:
                 /www/wwwroot/mcp-gateway/public
SSL:             enabled before /install
```

OpenLiteSpeed should have rewrite processing and `.htaccess` loading enabled. The repository-owned `public/.htaccess` handles both `/install` and normal Laravel routing.

Do **not** expose the package/repository root as the web document root, and do not solve permission problems with `chmod -R 777`.

### Shared hosting

The deployment ZIP/web installer can be used on shared hosting when the host provides:

- PHP 8.4.1+ with the required extensions;
- MySQL;
- HTTPS;
- permission to set a subdomain/addon-domain document root to the package `public/` directory;
- writable `storage/` and `bootstrap/cache/` directories.

If the hosting provider forces the entire application root to be public and cannot point the domain at `public/`, that hosting layout is not supported because it would expose private application files.

### Advanced: Git + Composer + Artisan

Operators who prefer source-based deployment can continue to use the existing CLI path:

```bash
cd /www/wwwroot
RELEASE_TAG=vX.Y.Z
git clone --branch "$RELEASE_TAG" --depth 1 https://github.com/ach1992/mcp-gateway.git mcp-gateway
cd mcp-gateway
composer install --no-dev --no-interaction --prefer-dist --optimize-autoloader
composer check-platform-reqs --no-dev
cp .env.example .env
php artisan key:generate
```

Configure `.env` with production values, including:

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

Then run:

```bash
php artisan gateway:oauth-keygen
php artisan gateway:bridge-client-keygen
php artisan migrate --force
php artisan gateway:admin:create
php artisan gateway:check
```

Do not run `composer update` on the server. Production source installation must consume the committed lockfile through `composer install`.

## Verify the installation

CLI operators can run:

```bash
php artisan gateway:check
php artisan gateway:oauth-client-check --refresh
```

For either installation method, verify the public endpoints:

```bash
curl --fail --silent --show-error https://gateway.example.com/up
curl --fail --silent --show-error https://gateway.example.com/.well-known/oauth-protected-resource/mcp
curl --fail --silent --show-error https://gateway.example.com/.well-known/oauth-authorization-server
curl --fail --silent --show-error --output /dev/null https://gateway.example.com/oauth/client.json
curl --fail --silent --show-error --output /dev/null https://gateway.example.com/oauth/jwks.json
```

Do not place access tokens, refresh tokens, authorization codes, assertions, passwords, `.env` contents, `APP_KEY`, or private-key contents in screenshots or logs.

## Connect WordPress sites

Each WordPress site needs a compatible WP AI Bridge installation. The current Gateway contract is validated against WP AI Bridge v0.4.1 at commit `5c5bdadf1d5594c006913770ea7b2f540b32e22a`, including its canonical `wp-ai-bridge/*` Ability namespace.

Before the first **Connect** attempt for a WordPress site, approve the Gateway as an additional OAuth client in that site's WP AI Bridge:

1. Confirm the Gateway publishes its client metadata at the exact URL derived from its canonical origin:

   ```text
   <GATEWAY_ORIGIN>/oauth/client.json
   ```

   For example, `https://gateway.example.com/oauth/client.json`.
2. In WordPress, open **WP AI Bridge -> OAuth Clients**.
3. Add that exact client metadata URL under **Approved client metadata URLs** and save. Do not add a callback URL, JWKS URL, shared secret, or private key.
4. Leave the built-in ChatGPT client in place if direct ChatGPT -> WP AI Bridge access is also wanted. It is independent from the additional-client list and does not need to be added manually.

WP AI Bridge fetches the approved client metadata itself. The document supplies the Gateway's exact `/oauth/sites/callback` redirect URI and `/oauth/jwks.json` signing-key URL, so operators must not paste either value separately into WordPress. Approval grants connection eligibility only; WP AI Bridge access groups and the authorizing WordPress user's capabilities remain authoritative for every operation.

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

If WordPress rejects the Gateway with `invalid_client` or reports that the OAuth client is not approved, verify that the exact current `<GATEWAY_ORIGIN>/oauth/client.json` URL is still present under **WP AI Bridge -> OAuth Clients** and is publicly reachable. After moving/reinstalling the Gateway on a different canonical origin, approve the new metadata URL before reconnecting. After intentionally replacing the Gateway Bridge-client signing keypair while keeping the same origin, keep the same approved metadata URL; WP AI Bridge obtains signing keys from the metadata-declared JWKS endpoint and may need a bounded JWKS refresh when it first sees the new key. Do not work around stale approval/key state by pasting tokens, callbacks, JWKS URLs, or shared secrets.

## Connect ChatGPT

The canonical client connection information is shown in the authenticated Gateway page:

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

The web installer is only for a **fresh installation**. Do not use `/install` to upgrade an existing Gateway.

### Recommended: browser update ZIP

Deployment-ZIP installations can be updated without SSH, Git, or Composer on the production host.

1. For migration-bearing releases, first preserve the documented recovery set: a consistent database backup, the matching `.env`/`APP_KEY`, both signing-key pairs, and the currently deployed release identity.
2. Download the named `mcp-gateway-update-vX.Y.Z.zip` asset from the intended GitHub Release. You may also download its `.sha256` file for an independent checksum check.
3. Upload the update ZIP into the **existing MCP Gateway application root** — the directory that already contains `.env`, `artisan`, `public/`, and `storage/`.
4. Extract the ZIP **in that same application root**. Extraction only adds a private `update/` staging directory and a temporary `public/update/` entrypoint; it does not replace the running application yet.
5. Open:

   ```text
   https://gateway.example.com/update/
   ```

6. If prompted, sign in with the existing MCP Gateway administrator account. The updater reuses the normal administrator session and CSRF protection.
7. Review the installed version, target version, package-integrity checks, and writable-path preflight, then choose **Update MCP Gateway**.
8. Keep the browser page open until it reports success.

The updater validates the exact package and target before changing managed files. It refuses same-version/downgrade attempts and rejects unsafe paths, symlinks, incomplete/tampered packages, source checkouts, invalid targets, and conflicts on Gateway-owned paths. After confirmation it runs the current Gateway preflight, creates and validates a private code backup under `storage/app/private/update-backups/`, enters Laravel maintenance mode, replaces application-managed files deterministically, verifies the complete installed runtime against the package manifest, preserves the production `.env` and all persistent `storage/`, clears caches, applies migrations, runs `gateway:check`, and returns the application to service.

`public/` is a shared hosting boundary, not an application-owned directory. The updater changes only the exact Gateway-owned public files declared by the release ownership manifest. Unknown or host-managed public files, including control-panel files such as aaPanel `public/.user.ini` and unknown files inside shared subdirectories, are neither deleted nor copied into the updater backup. Operators should not alter host-managed ownership or filesystem attributes merely to run an MCP Gateway update.

After a successful update, the temporary root `update/` directory, `public/update/` endpoint, and private updater state are removed automatically, so `/update/` cannot be run again. If the canonical `mcp-gateway-update-vX.Y.Z.zip` and matching checksum file are still present in the application root, the updater removes those exact files too. Arbitrarily renamed files are never deleted.

Only the three newest updater-created code backups are retained. Recovery is deliberately state-dependent. If backup creation or its initial integrity check fails **before maintenance mode**, the update aborts before managed application files are changed and no restore is needed. After maintenance begins:

- **Credible backup + another pre-migration failure:** the updater revalidates the backup and attempts automatic restore. If restore completes, updater state is cleared and the previous managed runtime returns to service. If the guarded restore itself cannot complete, migration still does not start; maintenance mode, updater state, and recovery evidence are retained for manual recovery.
- **Recovery backup is rejected when recovery or the final pre-migration check needs it:** database migration does not start and the updater does **not** restore from that rejected backup. Maintenance mode, updater state, and recovery evidence are retained for manual reconciliation. Do not assume the previous runtime was restored; depending on the failure point, the managed tree may be the complete candidate or a partially replaced tree.
- **Database migration may have started:** the updater intentionally does **not** attempt a blind code/database rollback. Maintenance mode and recovery evidence are retained until schema/data state is reconciled and a release-specific rollback or roll-forward procedure is chosen.

Whenever maintenance mode is retained after a failed update, treat the managed runtime as recovery-required until its exact state is verified. See `docs/DEPLOYMENT.md` for the authoritative operator recovery state machine.

Release-specific upgrade notes take precedence when they add requirements.

### Advanced: source/Composer installation

For an existing source/CLI deployment, move to the intended release and run:

```bash
composer install --no-dev --no-interaction --prefer-dist --optimize-autoloader
composer check-platform-reqs --no-dev
php artisan optimize:clear
php artisan migrate --force
php artisan gateway:check
```

The browser update ZIP intentionally refuses source checkouts (`.git` / `composer.lock`) so that it cannot silently overwrite a developer-managed deployment.

Do not blindly run `migrate:rollback` after a partial or unknown deployment failure.

## Troubleshooting

For the ZIP installer, start with the server checks shown on `/install`. Common causes are:

- using GitHub's generic source ZIP instead of the deployment-ready ZIP (so `vendor/` is missing);
- HTTPS not enabled before installation;
- the domain points at the application root instead of `public/`;
- PHP is older than 8.4.1 or a required extension is missing;
- `storage/` or `bootstrap/cache/` is not writable by the PHP process;
- the selected MySQL database is not empty;
- MySQL credentials/permissions are incorrect.

If the installer stops after creating `.env`, use a fresh extracted package and an empty database for the next attempt. Do not remove the private installed marker from a completed installation to force a reinstall.

For browser updates:

- a redirect from `/update/` to `/admin/login` is expected when the administrator session is not active;
- if `/update/` reports a package-integrity or incomplete-staging error, use the named update ZIP from the intended Release and extract it again in the existing application root before any update has started;
- do not manually copy the payload over the live application — the temporary updater owns deterministic file replacement;
- do not alter or delete unknown/control-panel files under `public/` for the updater; those paths are outside the Gateway ownership boundary;
- after a successful update, `/update/` should no longer exist;
- if a failure page says database migration may have started, do not re-run the updater or delete the private backup/state manually; follow a release-specific recovery or roll-forward procedure.

For an existing/CLI installation, also run:

```bash
php artisan gateway:check
```

For deployment details and security boundaries, see [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

## Documentation

- [`docs/MASTER-SPEC.md`](docs/MASTER-SPEC.md) — canonical V1 product requirements and boundaries.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — architecture and protocol boundaries.
- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) — detailed deployment, validation, backup, upgrade, and rollback guidance.
- [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) — development and validation workflow.
- [`docs/PROJECT-MAP.md`](docs/PROJECT-MAP.md) — maintainer/agent recovery map.

## Release status

GitHub Releases are the public release source of truth. Use the [latest stable Release](https://github.com/ach1992/mcp-gateway/releases/latest) and its named deployment/update assets rather than relying on a hard-coded version in this README.

Recommended installations should use the named deployment ZIP attached to the GitHub Release rather than the generic source archive or moving `main` branch. Existing deployment-ZIP installations should use the named browser update ZIP attached to the same Release.

Publishing a GitHub release does not deploy MCP Gateway to any server automatically. Production deployment remains an operator-controlled action.

## License

MCP Gateway is open-source software released under the [MIT License](LICENSE).