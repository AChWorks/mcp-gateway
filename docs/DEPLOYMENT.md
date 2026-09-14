# MCP Gateway Deployment Baseline

This document defines the current **pre-release deployment-validation baseline** for MCP Gateway on aaPanel + OpenLiteSpeed + PHP 8.4 + MySQL.

It is not a production release announcement and does not authorize deployment. Until a production-ready release exists, deploy only to an explicitly authorized test/staging environment and pin the exact reviewed commit. `README.md` remains the user-facing source for release availability.

## What this baseline proves

The current repository supports a conventional single-host PHP deployment with:

- PHP `>= 8.4.1` within the repository's PHP 8.4 target;
- Composer 2;
- MySQL as the production database;
- Laravel served only from the repository `public/` directory;
- Blade/static assets with no required Node.js production build;
- file-backed cache and administrator sessions by default;
- no required Redis, queue worker, broker, Docker runtime, or separate MCP daemon.

Production/runtime checks require PDO MySQL, OpenSSL, Sodium, a valid Laravel encryption key, MySQL as the configured database, a valid OAuth signing keypair, private storage that is not web-served, encrypted administrator sessions, and HTTPS-only sessions in production. CI also provisions `curl` and `mbstring`; keep those extensions enabled for the deployed PHP 8.4 runtime. `pdo_sqlite` is used by tests and is not a production database requirement.

## 1. Prerequisites

Before placing application code on the server, prepare:

1. An aaPanel site for the intended Gateway hostname or subdomain.
2. OpenLiteSpeed as the site's web server.
3. PHP 8.4 for both the site and deployment CLI. Verify the CLI used for Artisan/Composer is the intended PHP 8.4 runtime:

   ```bash
   php -v
   php -m | grep -E 'curl|mbstring|openssl|PDO|pdo_mysql|sodium'
   composer --version
   ```

4. A dedicated MySQL database and user scoped to the Gateway database. The account used for deployment migrations must be able to create/alter/drop application tables and indexes as well as perform normal application reads/writes. Do not use a global MySQL administrator account for normal application runtime.
5. DNS already resolving the Gateway hostname to the intended server before final HTTPS/OAuth verification.
6. A valid HTTPS certificate for the exact hostname. Production OAuth identity is derived from `APP_URL`, so the hostname must be stable before live integration.

On aaPanel, `/www/wwwroot/` is the normal website base location, but the actual application path may differ. In the examples below:

```text
APP_ROOT=/www/wwwroot/mcp-gateway
GATEWAY_ORIGIN=https://gateway.example.com
```

Replace both with the real authorized values.

## 2. OpenLiteSpeed document root and rewrite boundary

The effective web document root / running directory **must be**:

```text
<APP_ROOT>/public
```

Never expose the repository root as the website document root. The repository root contains `.env`, application code, private storage, Composer metadata, and other files that must not be directly web-accessible.

For OpenLiteSpeed:

- keep scripts/PHP enabled for the virtual host;
- set the document root (or aaPanel running directory) to `<APP_ROOT>/public`;
- enable rewrite processing;
- enable loading rewrite rules from `.htaccess` for this document root.

The repository already owns `public/.htaccess`. It preserves the `Authorization` header, preserves the XSRF header, serves existing files/directories directly, and sends other requests to `index.php`. Prefer this single repository-owned rewrite source instead of duplicating the same rules into an OpenLiteSpeed virtual-host rule block.

Do not copy nginx configuration into OpenLiteSpeed. LSAPI/SSE buffering and long-response behavior are intentionally **not** prescribed here; final Issue #8 validation must prove any required OpenLiteSpeed-specific adjustment on the production-like stack first.

## 3. Deployment user and filesystem ownership

Run Composer and Artisan as the application deployment/PHP owner whenever practical, not as an unrelated privileged account.

This matters especially for OAuth signing keys: `gateway:oauth-keygen` creates the key directory with mode `0700` and both key files with mode `0600`. The PHP process must therefore run as the owning account or have ownership deliberately aligned without weakening those permissions.

Required filesystem behavior:

- application source and `.env`: readable by the PHP process, not generally writable by web requests;
- `storage/`: writable by the PHP process;
- `bootstrap/cache/`: writable by the PHP process;
- `storage/app/private/`: never served by the web server;
- OAuth private/public key files: outside `public/`, owned for the PHP runtime, mode `0600` on Unix-like systems.

Do **not** fix a key ownership mistake by making the private key world/group readable.

## 4. Install an exact reviewed revision

For pre-release staging, use an exact reviewed commit. Once releases exist, prefer the immutable release tag/artifact rather than a moving branch.

Example:

```bash
cd /www/wwwroot
git clone https://github.com/ach1992/mcp-gateway.git mcp-gateway
cd mcp-gateway
git checkout <reviewed-commit-or-release-tag>
composer install --no-dev --no-interaction --prefer-dist --optimize-autoloader
cp .env.example .env
```

Do not run `composer update` on the server. Production/staging installation must consume the committed lockfile through `composer install`.

This repository currently contains Closure-backed web routes, so this baseline does not assume route caching or prescribe `php artisan optimize` as a deployment requirement. Add framework caches only after they are proven compatible with the exact release.

## 5. Configure production-shaped `.env`

Generate the Laravel application key after `.env` exists:

```bash
php artisan key:generate
```

Then configure at least these values for production-shaped validation:

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
```

Important boundaries:

- `APP_URL` must be one canonical HTTP(S) origin with no userinfo, query, fragment, or application subpath. In production it must be HTTPS.
- Keep `APP_DEBUG=false`.
- Do not commit `.env` or copy a development/test `APP_KEY` into production.
- Keep `SESSION_ENCRYPT=true`; production cookies must remain HTTPS-only.
- Do not enable the MCP bootstrap fixture in production.
- Keep Laravel's `local` filesystem private/non-served.
- The default OAuth key paths are intentionally below `storage/app/private/`, outside the public web root.

The rest of `.env.example` provides the current bounded timeout/size defaults. Change them only from evidence, not as a workaround for an unverified proxy/web-server problem.

## 6. Generate OAuth signing keys

After application ownership and `.env` are correct, generate the Gateway signing pair as the deployment/PHP owner:

```bash
php artisan gateway:oauth-keygen
```

Expected result:

```text
OAuth signing keypair generated.
```

The command refuses to overwrite an existing pair unless `--force` is supplied. Do not use `--force` during a normal deploy or upgrade; replacing signing keys is an explicit key-rotation event and may invalidate continuity assumptions for issued tokens.

Never print, copy into Git, or place the private key below `public/`.

## 7. Initialize the database and administrator

Apply the exact release migrations:

```bash
php artisan migrate --force
```

Create the initial administrator interactively:

```bash
php artisan gateway:admin:create
```

The administrator password is intentionally accepted only through hidden interactive prompts. Do not add it to a shell command, deployment script, environment variable, or process argument.

## 8. Run the repository-owned environment gate

Before treating the instance as deployable, run:

```bash
php artisan gateway:check
```

Every reported item must be `[OK]`. In the current application this validates, among other things:

- PHP `>= 8.4.1`;
- PDO MySQL, OpenSSL and Sodium;
- a valid Laravel encryption key;
- MySQL as the configured database driver;
- canonical `APP_URL` and HTTPS in production;
- a valid/matched OAuth signing keypair;
- signing keys outside `public/` with restricted permissions;
- private application storage not exposed through Laravel file serving;
- encrypted administrator sessions;
- HTTPS-only production session cookies.

A failed check is a deployment blocker. Fix the underlying configuration or ownership issue; do not weaken the check to make it pass.

## 9. Safe HTTP verification

Use only non-secret public/health endpoints for basic verification.

```bash
curl --fail --silent --show-error https://gateway.example.com/up
curl --fail --silent --show-error https://gateway.example.com/.well-known/oauth-protected-resource/mcp
curl --fail --silent --show-error https://gateway.example.com/.well-known/oauth-authorization-server
```

Expected behavior:

- `/up` succeeds without contacting every downstream WordPress site;
- protected-resource metadata identifies the configured Gateway MCP resource;
- authorization-server metadata identifies the same canonical issuer and the current OAuth endpoints.

Then verify the configured ChatGPT client metadata contract without printing JWK values or assertions:

```bash
php artisan gateway:oauth-client-check --refresh
```

Finally, sign in at `/admin/login` and confirm the authenticated Gateway connection-information page shows the canonical public MCP/discovery information without token/private-key values.

Do not include access tokens, refresh tokens, authorization codes, client assertions, passwords, `APP_KEY`, `.env` contents, or OAuth private-key contents in deployment logs/screenshots used as evidence.

## 10. OpenLiteSpeed validation still required by Issue #8

The official MCP SDK emits Streamable HTTP/SSE-compatible responses and already sets transport headers intended to discourage buffering. The repository has not yet proven the exact aaPanel/OpenLiteSpeed/LSAPI behavior on the target production-like stack.

Before production delivery, Issue #8 must still verify from executable evidence:

1. modern MCP requests through HTTPS/OpenLiteSpeed;
2. any retained legacy streaming/session compatibility path;
3. proxy/LSAPI buffering and timeout behavior under representative responses;
4. whether any OpenLiteSpeed setting actually needs adjustment.

If no adjustment is required, document that evidence. If an adjustment is required, record the smallest OpenLiteSpeed-specific setting proven by the test. Do not pre-apply nginx directives or generic buffering tweaks.

## 11. Backup and recovery baseline

Before every migration-bearing upgrade, preserve a recoverable set containing:

- a consistent MySQL database backup;
- the deployment `.env` / Laravel `APP_KEY` through the site's approved secret-backup mechanism;
- `OAUTH_PRIVATE_KEY_PATH` and `OAUTH_PUBLIC_KEY_PATH` with permissions preserved;
- the exact deployed Git commit/tag and Composer lockfile identity.

Treat the database, `APP_KEY`, and signing keypair as related recovery material. Losing signing/encryption material can invalidate or make security-sensitive persisted state unrecoverable.

Issue #4 has not yet integrated the final site-credential persistence contract. Therefore this baseline intentionally does **not** claim that the list above is the complete future backup set for connected WordPress sites. Final Issue #8 recovery validation must add every key/material required by the integrated #4 design and prove recovery with controlled credentials.

## 12. Upgrade and rollback outline

For an authorized staging/release upgrade:

1. Capture the backup/recovery set above.
2. Record the current deployed commit/tag.
3. Fetch the intended reviewed release/revision.
4. Install the committed dependencies without updating them:

   ```bash
   composer install --no-dev --no-interaction --prefer-dist --optimize-autoloader
   ```

5. Apply migrations:

   ```bash
   php artisan migrate --force
   ```

6. Re-run:

   ```bash
   php artisan gateway:check
   ```

7. Repeat the safe HTTP verification from this document.

Do not promise zero-downtime schema changes unless the exact release has been designed and tested for them.

If rollback is required, restore the previous reviewed code **and** reconcile database state. Do not blindly run `migrate:rollback` after an unknown or partially completed failure. When schema/data compatibility is uncertain, restore the pre-upgrade database backup or follow release-specific roll-forward/rollback instructions.

## 13. Current external references

These external references were checked while establishing this baseline. Repository/runtime evidence remains authoritative for MCP Gateway-specific commands and security checks.

- Laravel 13 documentation: https://laravel.com/framework/docs
- OpenLiteSpeed virtual-host/document-root and rewrite configuration: https://docs.openlitespeed.org/config/
- OpenLiteSpeed rewrite rules: https://docs.openlitespeed.org/config/rewriterules/
- aaPanel PHP Project/site configuration: https://www.aapanel.com/docs/Function/php.html
- aaPanel site deployment notes: https://www.aapanel.com/docs/faq/Site_Related.html

Final production readiness still belongs to Issue #8 and requires production-like OpenLiteSpeed/PHP validation plus the completed #4/#5/#6/#7 application paths.