
# MCP Gateway

MCP Gateway is a self-hosted PHP control plane exposing one authenticated MCP endpoint for multiple explicitly authorized **Targets**. The current released connector is **WP AI Bridge** for WordPress. Direct SSH and AI Server Agent runtimes are not shipped.

A Target has a stable `target_id`, explicit Gateway user/client/Target access checks and connector-owned credentials. For WordPress, the authenticated WordPress principal and WP AI Bridge access groups remain authoritative; Gateway does not widen their permissions.

## Current release highlights

- Generic Target inventory, Target Groups, per-user access and scoped Activity.
- Target Admin pages for WordPress registration, connection, status and management.
- Target-specific WordPress OAuth PKCE, encrypted credentials, guarded rotating refresh/revocation and idle credential renewal.
- Client-profile-based Gateway OAuth/MCP, currently with the reviewed ChatGPT application profile.
- Four Target-era MCP tools: `targets-list`, `target-context`, `wordpress-abilities-read`, `wordpress-ability-execute`.
- Explicit `target_id` routing, read/mutation effect authorization, bounded downstream I/O and fail-closed ambiguous outcomes.
- HTTPS/DNS/redirect protections, `php artisan gateway:check` diagnostics, and PHP 8.4 + MariaDB 10.11 primary deployment compatibility.
- Clean deployment ZIP/web installer and guarded browser-update ZIP for aaPanel and compatible hosting.

**Upgrade compatibility:** an installation already using the Target model on v2.0.0 can update to v2.0.1 without an intentional connection or authorization reset. Earlier **Site-era v1.x → Target v2.x** upgrades are breaking: retired Site registrations, Site groups, and incompatible WordPress/ChatGPT authorizations must be reset under exact package-bound consent and an independently restorable database backup. An updater code backup is not a database backup. See [Target transition and recovery](docs/TARGET-TRANSITION-RUNBOOK.md) and [release notes](RELEASE_NOTES.md).

## Requirements

MCP Gateway is intended for a conventional Linux PHP host such as aaPanel/OpenLiteSpeed or ordinary shared hosting.

Required runtime:

- PHP `>= 8.4.1`;
- PHP extensions: `curl`, `mbstring`, `openssl`, `pdo_mysql`, and `sodium`;
- cURL with `CURLOPT_RESOLVE` support;
- MariaDB 10.11 (recommended/primary) or MySQL;
- HTTPS on a stable domain or subdomain;
- a web server/hosting panel that can point the domain document root to the package `public/` directory.

Composer 2 and Git are **not required on the target host** when using the recommended deployment ZIP. They are only required for the advanced source/CLI installation path.

Normal operation does **not** require Redis, Docker, Node.js, a queue worker, a message broker, or a separate MCP daemon.

## Installation

### Recommended: deployment ZIP + web installer

This is the easiest installation method for aaPanel and compatible shared hosting.

1. Create a dedicated HTTPS domain/subdomain, for example `gateway.example.com`.
2. Create a dedicated **empty** MariaDB (recommended) or MySQL database and database user.
3. Open the [latest stable GitHub Release](https://github.com/AChWorks/mcp-gateway/releases/latest) and download its named deployment asset `mcp-gateway-vX.Y.Z.zip`.
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
   - database engine plus host/port/database/user/password;
   - the first administrator name/email/password.
10. Select **Install MCP Gateway**.

The named deployment ZIP is assembled in a clean staging tree from the committed dependency lockfile. Its bundled `vendor/` contains production dependencies and required runtime/license material only; repository metadata, development tools/dependencies, package docs/examples/tests, generated test keys, sessions, caches, logs, and other transient state are excluded. Writable runtime directories are shipped empty.

The installer automatically:

- checks PHP/extensions, HTTPS, bundled dependencies, and writable paths;
- requires a dedicated empty MariaDB or MySQL database;
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

The installer never displays the database password, `APP_KEY`, private keys, access tokens, or other generated secret material.

> The regular GitHub **Source code (zip)** archive is not the deployment package because it does not include production `vendor/`. Use the named `mcp-gateway-vX.Y.Z.zip` asset from the intended GitHub Release.

### aaPanel quick setup

A typical aaPanel setup is:

```text
Domain:          gateway.example.com
PHP:             8.4
Database:        dedicated MariaDB (primary) or MySQL database/user
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
- MariaDB 10.11 (recommended) or MySQL;
- HTTPS;
- permission to set a subdomain/addon-domain document root to the package `public/` directory;
- writable `storage/` and `bootstrap/cache/` directories.

If the hosting provider forces the entire application root to be public and cannot point the domain at `public/`, that hosting layout is not supported because it would expose private application files.

### Advanced: Git + Composer + Artisan

Operators who prefer source-based deployment can continue to use the existing CLI path:

```bash
cd /www/wwwroot
RELEASE_TAG=vX.Y.Z
git clone --branch "$RELEASE_TAG" --depth 1 https://github.com/AChWorks/mcp-gateway.git mcp-gateway
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

DB_CONNECTION=mariadb
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


## Connect WordPress Targets

Every WordPress Target needs a compatible WP AI Bridge installation. The Gateway-to-Bridge OAuth client must be approved in WordPress **before** starting Target Connect:

1. Open **Gateway → Connection** (`/admin/connection`) and copy the Gateway's exact client metadata URL, `<GATEWAY_ORIGIN>/oauth/client.json`.
2. In WordPress, open **WP AI Bridge → OAuth Clients** and add that exact URL to **Approved client metadata URLs**. Do not paste secrets, callback URLs or JWKS URLs. Built-in direct ChatGPT → WP AI Bridge approval is separate and may remain enabled.
3. The advertised WordPress OAuth callback in the current Target contract is `<GATEWAY_ORIGIN>/oauth/targets/callback`; the Gateway metadata publishes it automatically.

For each WordPress Target:

1. Sign in to `<GATEWAY_ORIGIN>/admin/login`, open **Targets**, choose **Add Target**, and select **WordPress (WP AI Bridge)** as the connector type (the only supported enrollment option in v2.0.1).
2. Enter a unique immutable `target_id` (lowercase letters, digits and hyphens, at most 64 characters), display name and canonical public HTTPS WordPress base URL.
3. Choose **Verify and add WordPress Target**. Registration validates public discovery and does not itself grant WordPress credentials.
4. Open the Target details, select **Authorize WordPress**, and complete WP AI Bridge OAuth consent as the exact WordPress principal to delegate.
5. Confirm **Connected** and use **Check WordPress metadata** on Target details when diagnostic verification is required. Assign intended Gateway users/Target Groups deliberately; selected-scope users do not receive automatic access.
6. Repeat for other WordPress Targets. Credentials, revocation and authorization remain Target-specific.

If WP AI Bridge reports `invalid_client`, verify the exact approved Gateway client metadata URL and its reachability. A new Gateway origin requires new approval. Do not replace OAuth keys, paste tokens, or bypass approval/permission checks to resolve an ordinary connection problem.

**Upgrade users:** the legacy Site records and prior ChatGPT authorizations are not migrated into live Target grants. Register WordPress Targets again and separately reauthorize ChatGPT after the intentional reset. For ambiguous rotating-refresh outcomes, follow the Owner-only manual reconciliation warnings in the [Target runbook](docs/TARGET-TRANSITION-RUNBOOK.md) instead of blindly retrying or deleting credentials.


## Connect ChatGPT

The authenticated Gateway **Connection** page (`/admin/connection`) shows the canonical MCP endpoint, normally `https://gateway.example.com/mcp` for that deployment. Configure one ChatGPT custom MCP App against that endpoint and complete the Gateway's OAuth discovery/consent flow using an authorized Gateway user. No manually pasted bearer token is needed.

The **AI clients** page (`/admin/oauth-clients`) lists approved application profiles and individual Gateway authorizations. It identifies authenticated *applications*, not individual AI accounts; a client label does not confer Target permissions. Disabling a profile and revoking an exact authorization are distinct operations with different consequences.

After a breaking Site → Target upgrade and fresh OAuth consent, start a **new ChatGPT conversation** if an older conversation still advertises Site-era `sites-list` tools. Refresh/reconnect the supported app integration if a new conversation also retains an obsolete catalog. Do not create legacy API aliases or weaken OAuth to mask a cached tool definition.


## Gateway MCP tools

The released public tool catalog contains **exactly four** tools:

| Tool | Purpose |
| --- | --- |
| `targets-list` | List authorized Targets without credentials. |
| `target-context` | Read non-secret context for one explicitly authorized `target_id`. |
| `wordpress-abilities-read` | Inspect WordPress Ability metadata on one authorized WordPress Target. |
| `wordpress-ability-execute` | Execute a schema-valid Ability for an explicit authorized WordPress Target, subject to effect-class and downstream permissions. |

Typical flow: call `targets-list`, select an exact `target_id`, read `target-context` and the selected Ability's schema, then execute only the required authorized operation. Never infer an implicit Target from conversation history. Read-only metadata does not authorize writes, and a client-profile display label never grants Target access.

SSH/Agent tool names and runtimes are **not available** in the current release.


## Administration

| Path | Page |
| --- | --- |
| `/admin` | Dashboard |
| `/admin/targets` | Target registry and WordPress connection management |
| `/admin/target-groups` | Target Group assignments |
| `/admin/users` | Gateway users and access |
| `/admin/oauth-clients` | AI client profiles, grants and password-confirmed revocation |
| `/admin/activity` | Bounded Activity |
| `/admin/connection` | MCP and OAuth connection metadata |

Permission checks remain server-authoritative. A Target connection does not bypass WordPress principal or Bridge access-group restrictions.

## Upgrade

**Already on v2.0.0?** The v2.0.1 package is a maintenance update without a new Site/Target schema transition. Existing Target registrations, WP AI Bridge connection credentials, user/group restrictions, and ChatGPT grants are intended to survive. Take a verified database and secret recovery backup, run the normal guarded browser updater, then confirm version 2.0.1, Target connection, AI clients grant and User/Target Group forms. No voluntary disconnect/re-enrollment is required. **Pre-v2 Site-era installations remain different:** those upgrades involve an intentional breaking database/data transition. Follow [the Target transition runbook](docs/TARGET-TRANSITION-RUNBOOK.md), verify an independently restorable database backup, understand retired connections/grants and complete package-bound confirmations. Never blindly retry a partial MariaDB migration or assume code rollback reverses DDL.

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
- the selected MariaDB/MySQL database is not empty;
- database credentials/permissions are incorrect.

If the installer stops after creating `.env`, use a fresh extracted package and an empty database for the next attempt. Do not remove the private installed marker from a completed installation to force a reinstall.

For browser updates:

- a redirect from `/update/` to `/admin/login` is expected when the administrator session is not active;
- if `/update/` reports a package-integrity or incomplete-staging error, use the named update ZIP from the intended Release and extract it again in the existing application root before any update has started;
- do not manually copy the payload over the live application — the temporary updater owns deterministic file replacement;
- do not alter or delete unknown/control-panel files under `public/` for the updater; those paths are outside the Gateway ownership boundary;
- after a successful update, `/update/` should no longer exist;
- if a failure page says database migration may have started, do not re-run the updater or delete the private backup/state manually; follow a release-specific recovery or roll-forward procedure.

For ChatGPT custom App connection problems:

- first verify the Gateway itself with `php artisan gateway:check` and the documented OAuth/discovery endpoints before changing credentials;
- an approved ChatGPT `mcp` authorization is refreshable: access tokens remain short-lived, while rotating refresh tokens preserve connectivity until expiry or revocation;
- inspect the secret-safe `OAuth authorization decision.` and `OAuth token exchange completed.` log records. They include correlation identity, approved/requested scopes, outcome, and whether a refresh token was issued, but never the token value;
- if ChatGPT shows the App as disconnected while Gateway health/discovery remain healthy, use ChatGPT's **Reconnect** control when available. A disconnected UI state alone does not prove that Gateway OAuth keys or downstream site authorization were lost;
- preserve the failure time/time zone plus safe correlation IDs and relevant Activity metadata for diagnosis. Never copy access/refresh tokens, authorization codes, client assertions, private keys, or raw credential payloads into logs or support notes;
- do not rotate Gateway signing keys or reauthorize downstream WordPress sites solely as a reconnect diagnostic shortcut;
- if the problem persists after the relevant authorization checks, avoid repeated reconnect loops; check OpenAI service status and contact OpenAI Support with the observed state and timestamps.

For an existing/CLI installation, also run:

```bash
php artisan gateway:check
```

For deployment details and security boundaries, see [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).


## Documentation

- [Release notes](RELEASE_NOTES.md) — shipped changes and version-specific breaking-upgrade warnings.
- [Target transition and recovery runbook](docs/TARGET-TRANSITION-RUNBOOK.md) — migration consent, data preservation and partial-DDL recovery.
- [Client profile runbook](docs/CLIENT-PROFILE-RUNBOOK.md) — app identity, authorization isolation, grant revocation and recovery.
- [Master spec](docs/MASTER-SPEC.md) and [architecture](docs/ARCHITECTURE.md) — target contracts, including clearly identified future/not-yet-shipped connectors.
- [Deployment](docs/DEPLOYMENT.md), [development](docs/DEVELOPMENT.md) and [project map](docs/PROJECT-MAP.md) — operations and maintainer navigation.

## Release status

GitHub Releases are the public release source of truth. Use the [latest stable Release](https://github.com/AChWorks/mcp-gateway/releases/latest) and its named deployment/update assets rather than relying on a hard-coded version in this README.

Recommended installations should use the named deployment ZIP attached to the GitHub Release rather than the generic source archive or moving `main` branch. Existing deployment-ZIP installations should use the named browser update ZIP attached to the same Release.

Publishing a GitHub release does not deploy MCP Gateway to any server automatically. Production deployment remains an operator-controlled action.

## License

MCP Gateway is open-source software released under the [MIT License](LICENSE).