# MCP Gateway Deployment Baseline

This document defines the supported **V1 deployment and validation baseline** for MCP Gateway on aaPanel + OpenLiteSpeed + PHP 8.4 + MySQL.

GitHub releases own public release identity. Production deployment remains an operator-controlled action: publishing a release does not authorize or perform deployment to any server. For stable installations, prefer an immutable release tag over a moving branch. `README.md` remains the user-facing installation and usage guide.

## What this baseline proves

The current repository supports a conventional single-host PHP deployment with:

- PHP `>= 8.4.1` within the repository's PHP 8.4 target;
- Composer 2;
- MySQL as the production database;
- Laravel served only from the repository `public/` directory;
- Blade/static assets with no required Node.js production build;
- file-backed cache and administrator sessions by default;
- no required Redis, queue worker, broker, Docker runtime, or separate MCP daemon.

Production/runtime checks require PDO MySQL, cURL with `CURLOPT_RESOLVE` DNS pinning support, OpenSSL, Sodium, a valid Laravel encryption key, MySQL as the configured database, two valid and distinct RSA signing keypairs, private storage that is not web-served, encrypted administrator sessions, and HTTPS-only sessions in production. The first signing pair owns the ChatGPT-facing Gateway OAuth server; the second owns the Gateway's `private_key_jwt` client identity when connecting to WP AI Bridge. CI also provisions `mbstring`; keep it enabled for the deployed PHP 8.4 runtime. `pdo_sqlite` is used by tests and is not a production database requirement.

Policy-controlled Gateway-to-Bridge HTTP requests are intentionally direct: the application explicitly disables Guzzle proxy use for those requests before applying the validated `CURLOPT_RESOLVE` target pin. Ambient `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and equivalent process settings must not become part of the Bridge transport path. Future proxy support would require a separate proxy-aware validation/pinning design; it must not be enabled by removing the direct-request invariant.

Under the pinned WP AI Bridge compatibility contract, OAuth `invalid_client` is not sufficient proof that an existing site authorization is terminal: temporary non-200 responses while resolving an approved additional client's metadata or JWKS can surface as `invalid_client` before refresh or revocation is attempted. The Gateway therefore preserves the encrypted site credential on generic `invalid_client` refresh/revocation failures and fails closed for later retry. A refresh `invalid_grant` remains terminal. Site removal must not proceed until remote revocation is actually confirmed.

## 1. Prerequisites

Before placing application code on the server, prepare:

1. An aaPanel site for the intended Gateway hostname or subdomain.
2. OpenLiteSpeed as the site's web server.
3. PHP 8.4 for both the site and deployment CLI. Verify the CLI used for Artisan/Composer is the intended PHP 8.4 runtime and that the explicitly required application extensions are loaded:

   ```bash
   php -v
   php -r 'foreach (["curl", "mbstring", "openssl", "pdo_mysql", "sodium"] as $extension) { if (! extension_loaded($extension)) { fwrite(STDERR, "Missing PHP extension: {$extension}\n"); exit(1); } } if (! defined("CURLOPT_RESOLVE")) { fwrite(STDERR, "Missing cURL CURLOPT_RESOLVE support\n"); exit(1); } echo "Required PHP extensions: OK\n";'
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

This matters especially for signing keys: `gateway:oauth-keygen` and `gateway:bridge-client-keygen` create private key directories with mode `0700` and key files with mode `0600`. The PHP process must therefore run as the owning account or have ownership deliberately aligned without weakening those permissions.

Required filesystem behavior:

- application source and `.env`: readable by the PHP process, not generally writable by web requests;
- `storage/`: writable by the PHP process;
- `bootstrap/cache/`: writable by the PHP process;
- `storage/app/private/`: never served by the web server;
- both OAuth signing keypairs: outside `public/`, owned for the PHP runtime, mode `0600` on Unix-like systems;
- the Bridge client signing pair must be distinct from the ChatGPT-facing Gateway OAuth signing pair.

Do **not** fix a key ownership mistake by making a private key world/group readable.

## 4. Install an immutable release

For stable V1 installations, use the immutable release tag rather than a moving branch. For development or controlled validation, an exact reviewed commit is also acceptable.

Example:

```bash
cd /www/wwwroot
git clone https://github.com/ach1992/mcp-gateway.git mcp-gateway
cd mcp-gateway
git checkout v1.0.0
composer install --no-dev --no-interaction --prefer-dist --optimize-autoloader
composer check-platform-reqs --no-dev
cp .env.example .env
```

`composer check-platform-reqs --no-dev` must succeed for the exact PHP CLI that will run Artisan. Do not run `composer update` on the server. Production/staging installation must consume the committed lockfile through `composer install`.

This baseline has not validated route/config optimization caches against every current route and deployment condition, so it does not prescribe `php artisan optimize` as a deployment requirement. Add framework caches only after they are proven compatible with the exact release.

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
BRIDGE_CLIENT_PRIVATE_KEY_PATH=storage/app/private/bridge-client/private.key
BRIDGE_CLIENT_PUBLIC_KEY_PATH=storage/app/private/bridge-client/public.key
```

Important boundaries:

- `APP_URL` must be one canonical HTTP(S) origin with no userinfo, query, fragment, or application subpath. In production it must be HTTPS.
- Keep `APP_DEBUG=false`.
- Do not commit `.env` or copy a development/test `APP_KEY` into production.
- Keep `SESSION_ENCRYPT=true`; production cookies must remain HTTPS-only.
- Do not enable the MCP bootstrap fixture in production.
- Keep Laravel's `local` filesystem private/non-served.
- Both signing-key directories are intentionally below `storage/app/private/`, outside the public web root.
- The Bridge client keypair is a separate trust identity. Do not point its paths at the ChatGPT-facing OAuth keypair.

The rest of `.env.example` provides the current bounded timeout/size defaults. Change them only from evidence, not as a workaround for an unverified proxy/web-server problem.

## 6. Generate signing keys

After application ownership and `.env` are correct, generate both signing pairs as the deployment/PHP owner:

```bash
php artisan gateway:oauth-keygen
php artisan gateway:bridge-client-keygen
```

Expected results include:

```text
OAuth signing keypair generated.
Bridge OAuth client signing keypair generated.
```

Both commands refuse to overwrite an existing pair unless `--force` is supplied. Do not use `--force` during a normal deploy or upgrade. Replacing the Gateway OAuth pair is an explicit server-key rotation event. Replacing the Bridge client pair changes the public JWKS used by approved WP AI Bridge clients and can require deliberate approval/reconnection handling; it is not a routine deployment step.

Never print, copy into Git, or place either private key below `public/`.

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
- PDO MySQL, cURL with DNS pinning support, OpenSSL and Sodium;
- a valid Laravel encryption key;
- MySQL as the configured database driver;
- canonical `APP_URL` and HTTPS in production;
- a valid/matched ChatGPT-facing Gateway OAuth signing keypair;
- a valid/matched and distinct Bridge client signing keypair;
- both signing pairs outside `public/` with restricted permissions;
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
curl --fail --silent --show-error --output /dev/null https://gateway.example.com/oauth/client.json
curl --fail --silent --show-error --output /dev/null https://gateway.example.com/oauth/jwks.json
```

Expected behavior:

- `/up` succeeds without contacting every downstream WordPress site;
- protected-resource metadata identifies the configured Gateway MCP resource;
- authorization-server metadata identifies the same canonical issuer and the current OAuth endpoints;
- the Bridge client metadata and JWKS endpoints are publicly reachable over the same canonical HTTPS origin.

Then verify the configured ChatGPT client metadata contract without printing JWK values or assertions:

```bash
php artisan gateway:oauth-client-check --refresh
```

Finally, sign in at `/admin/login` and confirm the authenticated Gateway connection-information page shows the canonical public MCP/discovery information without token/private-key values.

Do not include access tokens, refresh tokens, authorization codes, client assertions, passwords, `APP_KEY`, `.env` contents, or private-key contents in deployment logs/screenshots used as evidence.

## 10. OpenLiteSpeed V1 validation result

V1 validation completed the production-like aaPanel/OpenLiteSpeed/LSAPI proof on OpenLiteSpeed 1.8.4 with PHP 8.4 and MySQL 8.4. Modern MCP requests and the retained legacy compatibility flow worked through HTTPS/OpenLiteSpeed without an evidence-based need for custom buffering or timeout overrides beyond the normal Laravel `public/` document-root/rewrite configuration.

Do not pre-apply nginx directives or generic buffering tweaks. If a future release introduces materially different long-lived server-to-client streaming/SSE behavior, revalidate OpenLiteSpeed/LSAPI buffering and timeout behavior for that release before prescribing a new setting.

## 11. Backup and recovery baseline

Before every migration-bearing upgrade, preserve a recoverable set containing:

- a consistent MySQL database backup, including site registry, encrypted site credentials and OAuth-flow state owned by the deployed revision;
- the deployment `.env` / Laravel `APP_KEY` through the site's approved secret-backup mechanism;
- `OAUTH_PRIVATE_KEY_PATH` and `OAUTH_PUBLIC_KEY_PATH` with permissions preserved;
- `BRIDGE_CLIENT_PRIVATE_KEY_PATH` and `BRIDGE_CLIENT_PUBLIC_KEY_PATH` with permissions preserved;
- the exact deployed Git commit/tag and Composer lockfile identity.

Treat the database, `APP_KEY`, and both signing keypairs as one recovery set. Site access/refresh tokens are encrypted with the application encryption boundary, so restoring the database without the matching `APP_KEY` makes those credentials unusable. Restoring a different Bridge client keypair changes the `private_key_jwt` identity material advertised through the Gateway JWKS endpoint and can break approved site connections even when the database is intact.

V1 recovery validation proved this set on a controlled two-site installation: the database, matching `APP_KEY`, both signing keypairs, and exact code/lock identity were restored together and the encrypted site credentials remained usable. Preserve the same recovery-set invariant for future releases; backup presence alone is not sufficient unless restore assumptions remain valid.

## 12. Upgrade and rollback outline

For an authorized staging/release upgrade:

1. Capture the backup/recovery set above.
2. Record the current deployed commit/tag.
3. Fetch the intended reviewed release/revision.
4. Install the committed dependencies without updating them:

   ```bash
   composer install --no-dev --no-interaction --prefer-dist --optimize-autoloader
   composer check-platform-reqs --no-dev
   php artisan optimize:clear
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

V1 production-like readiness evidence was completed under Issue #8 and is preserved in the repository/GitHub history. Future releases must revalidate only the deployment assumptions materially changed by that release.