# MCP Gateway Deployment Baseline

This document defines the supported **V1 deployment and validation baseline** for MCP Gateway on PHP 8.4 + MariaDB 10.11 (primary) or MySQL, with aaPanel/OpenLiteSpeed as the primary validated host shape and compatible shared PHP hosting supported when it can expose only the application `public/` directory.

GitHub releases own public release identity. Production deployment remains an operator-controlled action: publishing a release does not authorize or perform deployment to any server. `README.md` remains the user-facing installation and usage guide.

## What this baseline proves

The current repository supports a conventional single-host PHP deployment with:

- PHP `>= 8.4.1` within the repository's PHP 8.4 target;
- MariaDB 10.11 as the primary production database target, with MySQL retained as a supported compatibility target;
- Laravel served only from the repository/package `public/` directory;
- a deployment-ready Release ZIP with production Composer dependencies bundled, so Git/Composer are not required on the target host;
- a separate authenticated browser-update ZIP for existing deployment-ZIP installations, also without requiring SSH, Git, or Composer;
- Git + Composer + Artisan as a supported advanced deployment path;
- Blade/static assets with no required Node.js production build;
- file-backed cache and administrator sessions by default;
- no required Redis, queue worker, broker, Docker runtime, or separate MCP daemon.

Production/runtime checks require the `pdo_mysql` extension for MariaDB/MySQL, cURL with `CURLOPT_RESOLVE` DNS pinning support, OpenSSL, Sodium, a valid Laravel encryption key, MariaDB or MySQL as the configured database, two valid and distinct RSA signing keypairs, private storage that is not web-served, encrypted administrator sessions, and HTTPS-only sessions in production. The first signing pair owns the ChatGPT-facing Gateway OAuth server; the second owns the Gateway's `private_key_jwt` client identity when connecting to WP AI Bridge. CI also provisions `mbstring`; keep it enabled for the deployed PHP 8.4 runtime. `pdo_sqlite` is used by tests and is not a production database requirement.

Policy-controlled Gateway-to-Bridge HTTP requests are intentionally direct: the application explicitly disables Guzzle proxy use for those requests before applying the validated `CURLOPT_RESOLVE` target pin. Ambient `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and equivalent process settings must not become part of the Bridge transport path. Future proxy support would require a separate proxy-aware validation/pinning design; it must not be enabled by removing the direct-request invariant.

Under the pinned WP AI Bridge compatibility contract, OAuth `invalid_client` is not sufficient proof that an existing site authorization is terminal: temporary non-200 responses while resolving an approved additional client's metadata or JWKS can surface as `invalid_client` before refresh or revocation is attempted. The Gateway therefore preserves the encrypted site credential on generic `invalid_client` refresh/revocation failures and fails closed for later retry. A refresh `invalid_grant` remains terminal. Site removal must not proceed until remote revocation is actually confirmed.

## 1. Prerequisites

Before placing application code on the server, prepare:

1. An aaPanel/shared-hosting site for the intended Gateway hostname or subdomain.
2. PHP 8.4 for the website. The runtime must provide `curl`, `mbstring`, `openssl`, `pdo_mysql`, and `sodium`, and cURL must expose `CURLOPT_RESOLVE`.
3. A dedicated **empty** MariaDB (recommended) or MySQL database and user scoped to the Gateway database. The account must be able to create/alter/drop application tables and indexes as well as perform normal application reads/writes. Do not use a global database administrator account for normal application runtime.
4. DNS resolving the Gateway hostname to the intended server before final HTTPS/OAuth verification.
5. A valid HTTPS certificate for the exact hostname. Production OAuth identity is derived from `APP_URL`, so the hostname must be stable before installation.
6. A hosting layout that can make the application `public/` directory the effective document root.

Composer 2 and Git are required only for the advanced source installation path. The recommended deployment ZIP already contains `vendor/`.

On aaPanel, `/www/wwwroot/` is the normal website base location. Example:

```text
APP_ROOT=/www/wwwroot/mcp-gateway
GATEWAY_ORIGIN=https://gateway.example.com
```

Replace both with the real values.

## 2. OpenLiteSpeed document root and rewrite boundary

The effective web document root / running directory **must be**:

```text
<APP_ROOT>/public
```

Never expose the application root as the website document root. It contains `.env`, application code, private storage, Composer runtime metadata, and other files that must not be directly web-accessible.

For OpenLiteSpeed:

- keep scripts/PHP enabled for the virtual host;
- set the document root (or aaPanel running directory) to `<APP_ROOT>/public`;
- enable rewrite processing;
- enable loading rewrite rules from `.htaccess` for this document root.

The repository owns `public/.htaccess`. It preserves the `Authorization` header, preserves the XSRF header, maps `/install` to the standalone fresh-install entry point, serves existing files/directories directly, and sends other requests to `index.php`. The browser update package temporarily creates `public/update/`, so `/update/` is served as a real temporary directory only while an update package is staged; successful update cleanup removes that directory again.

Do not copy nginx configuration into OpenLiteSpeed. LSAPI/SSE buffering and long-response behavior are not prescribed unless a future release produces evidence that a custom adjustment is needed.

## 3. Deployment user and filesystem ownership

The PHP process must be able to read the application and write only the runtime paths that need it.

Required filesystem behavior:

- application source and `.env`: readable by the PHP process;
- application root: writable during the one-time web install and browser update so `.env` can be created initially and managed release files can later be replaced;
- `storage/`: writable by the PHP process;
- `bootstrap/cache/`: writable by the PHP process;
- `storage/app/private/`: never served by the web server;
- both OAuth signing keypairs: outside `public/`, owned for the PHP runtime, mode `0600` on Unix-like systems;
- the Bridge client signing pair must be distinct from the ChatGPT-facing Gateway OAuth signing pair.

Do **not** fix an ownership problem with `chmod -R 777` or by making private keys world/group readable.

For advanced Composer/Artisan deployment, run Composer and Artisan as the application/PHP owner whenever practical.

## 4. Install an immutable release

### Recommended: deployment ZIP + web installer

For normal aaPanel/shared-hosting installs, download the named deployment package attached to the GitHub Release:

```text
mcp-gateway-vX.Y.Z.zip
```

Do not use GitHub's generic **Source code (zip)** archive; that archive does not contain production `vendor/` dependencies. The named deployment ZIP contains only the application/runtime files required for installation and operation.

### Release package hygiene invariant

The named deployment ZIP is a production artifact, not a filtered repository archive. Every current and future release must be built and verified through the repository-owned `bin/build-release-package.sh` and `bin/verify-release-package.sh` path.

The invariant is:

- assemble the artifact in a new staging tree rather than reusing the development checkout;
- install Composer dependencies directly with `--no-dev` from the committed source `composer.lock`;
- keep only application/runtime files, required generated Laravel package manifests, the runtime Composer manifest, dependency runtime resources, license/notice material, and version identity;
- remove dependency repository metadata, docs/examples/benchmarks, declared dev/test trees, development configs/tools, Composer binary proxies, and source-distribution signing/build leftovers only where they are demonstrably non-runtime;
- preserve package resources that runtime code can consume even when they are large or have names such as `dist` or `Test`;
- ship `storage/` as empty runtime directory scaffolding, including the empty `storage/framework/mcp-sessions/` directory required by legacy MCP session compatibility; never inherit test keys, sessions, caches, logs, views, or other generated state from CI/development;
- ship migrations but not factories, seeders, repository placeholders, or development database artifacts;
- omit source-only `composer.lock` from the deployment artifact after production `vendor/` has been built; the release/tag still identifies the authoritative repository lockfile used to build it;
- fail the build if the extracted ZIP does not pass exact top-level allowlisting, recursive hygiene checks, Composer runtime identity checks, Laravel bootstrap/route discovery, installer preflight, package-manifest rebuild, and a migration smoke test.

This rule is intentionally enforced in normal CI as well as release publication so a future feature or dependency change cannot silently reintroduce repository/test/build state into the operator package.

Procedure:

1. Upload and extract the deployment ZIP.
2. Point the HTTPS domain document root to `<APP_ROOT>/public`.
3. Confirm `storage/` and `bootstrap/cache/` are writable by the PHP process.
4. Open:

   ```text
   https://gateway.example.com/install
   ```

5. Provide the canonical HTTPS Gateway URL, dedicated empty MariaDB/MySQL database credentials, and first administrator details.
6. Complete installation once.

The installer runs before Laravel is configured and does **not** invoke shell commands. It validates the runtime, writes a production `.env` with a unique `APP_KEY`, runs migrations through Laravel's console kernel, generates both signing keypairs, runs `gateway:check`, creates the first administrator, and writes a private installed marker. After successful installation, `/install` cannot be used to reinstall/reset the Gateway.

The installer accepts credentials only over HTTPS and never redisplays/logs the database password, `APP_KEY`, private keys, or generated authorization material.

### Advanced: Git + Composer + Artisan

For development or operators who explicitly prefer source deployment:

```bash
cd /www/wwwroot
RELEASE_TAG=vX.Y.Z
git clone --branch "$RELEASE_TAG" --depth 1 https://github.com/ach1992/mcp-gateway.git mcp-gateway
cd mcp-gateway
composer install --no-dev --no-interaction --prefer-dist --optimize-autoloader
composer check-platform-reqs --no-dev
cp .env.example .env
```

`composer check-platform-reqs --no-dev` must succeed for the exact PHP CLI that will run Artisan. Do not run `composer update` on the server. Production/staging source installation must consume the committed lockfile through `composer install`.

The baseline does not prescribe `php artisan optimize` as a deployment requirement. Add framework caches only after they are proven compatible with the exact release.

## 5. Configure production-shaped `.env` (advanced path)

The web installer performs this section automatically. For the advanced CLI path, generate the Laravel application key after `.env` exists:

```bash
php artisan key:generate
```

Then configure at least:

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

MCP_EDGE_RATE_LIMIT_BURST_PER_SECOND=120
MCP_EDGE_RATE_LIMIT_PER_MINUTE=1200
MCP_PRINCIPAL_RATE_LIMIT_BURST_PER_SECOND=60
MCP_PRINCIPAL_RATE_LIMIT_PER_MINUTE=600

OAUTH_PRIVATE_KEY_PATH=storage/app/private/oauth/private.key
OAUTH_PUBLIC_KEY_PATH=storage/app/private/oauth/public.key
BRIDGE_CLIENT_PRIVATE_KEY_PATH=storage/app/private/bridge-client/private.key
BRIDGE_CLIENT_PUBLIC_KEY_PATH=storage/app/private/bridge-client/public.key
```

Important boundaries:

- `APP_URL` must be one canonical origin with no userinfo, query, fragment, or application subpath; production must use HTTPS;
- keep `APP_DEBUG=false`;
- do not commit `.env` or copy a development/test `APP_KEY` into production;
- keep `SESSION_ENCRYPT=true` and HTTPS-only production cookies;
- do not enable the MCP bootstrap fixture in production;
- keep Laravel's `local` filesystem private/non-served;
- both signing-key directories stay below `storage/app/private/`, outside the public web root;
- the Bridge client keypair is a separate trust identity.

The ChatGPT-facing MCP limiter is burst-aware by default: the unauthenticated edge allows 120 requests/second and 1,200/minute per source IP, while the authenticated principal allows 60 requests/second and 600/minute per `oauth_client_id + oauth_user_id`. Both windows must pass. Existing installations do not need new `.env` entries after an update because these values are application defaults; the variables above exist for evidence-based tuning without another code release. Values are clamped to at least 1, so setting them to zero does not disable abuse protection. A limited request remains an HTTP 429 with `Retry-After`/rate-limit headers and the bounded MCP diagnostic already recorded by the Gateway.

The rest of `.env.example` provides bounded timeout/size defaults. Change them only from evidence.

### Activity retention scheduling

Activity recording stays off the retention hot path: a routed operation writes one bounded metadata event, while `activity:prune` applies the configured age and row-count policy separately. Defaults are 30 days and 5,000 rows through `ACTIVITY_RETENTION_DAYS` and `ACTIVITY_MAX_ROWS`. Because pruning is scheduled rather than synchronous with every write, the row count can temporarily exceed the configured target between prune runs.

Configure the host's cron/scheduled-task facility to run Laravel's scheduler once per minute from the application root:

```cron
* * * * * cd <APP_ROOT> && php artisan schedule:run >> /dev/null 2>&1
```

Use the PHP 8.4 CLI that belongs to the deployed site when `php` is not that binary. The application schedules `activity:prune` once per day with overlap protection. If the Laravel scheduler is unavailable, run the same command from an equivalent host scheduler at least daily; without scheduled or manual pruning, the configured age/row targets are not enforced.

Operators may also apply the configured policy on demand:

```bash
php artisan activity:prune
```

Pruning serializes only competing prune runs and deletes expired/overflow records in fixed-size batches; ordinary Activity writers do not acquire the retention lock. The command reports only expired/overflow deletion counts and the remaining row count. It does not dump Activity records or credentials.

## 6. Generate signing keys (advanced path)

The web installer performs this automatically. For CLI deployment:

```bash
php artisan gateway:oauth-keygen
php artisan gateway:bridge-client-keygen
```

Expected results include:

```text
OAuth signing keypair generated.
Bridge OAuth client signing keypair generated.
```

Both commands refuse to overwrite an existing pair unless `--force` is supplied. Do not use `--force` during a normal deploy or upgrade. Never print, copy into Git, or place either private key below `public/`.

## 7. Initialize the database and administrator (advanced path)

The web installer performs this automatically against a dedicated empty database. For CLI deployment:

```bash
php artisan migrate --force
php artisan gateway:admin:create
```

The administrator password is accepted only through hidden interactive prompts. Do not add it to a shell command, deployment script, environment variable, or process argument.

## 8. Run the repository-owned environment gate

The web installer runs this gate automatically before creating the administrator. CLI operators must run:

```bash
php artisan gateway:check
```

Every reported item must be `[OK]`. The current application validates, among other things:

- PHP `>= 8.4.1`;
- the `pdo_mysql` extension for MariaDB/MySQL, cURL with DNS pinning support, OpenSSL and Sodium;
- a valid Laravel encryption key;
- MariaDB or MySQL as the configured database driver;
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
- authorization-server metadata identifies the same canonical issuer and current OAuth endpoints;
- Bridge client metadata and JWKS endpoints are publicly reachable over the same canonical HTTPS origin.

CLI operators can additionally verify the configured ChatGPT client metadata contract:

```bash
php artisan gateway:oauth-client-check --refresh
```

Before using **Connect** for any WP AI Bridge site, the site's WordPress administrator must approve the Gateway's exact additional OAuth client identity under **WP AI Bridge -> OAuth Clients -> Approved client metadata URLs**:

```text
<GATEWAY_ORIGIN>/oauth/client.json
```

The Gateway metadata document is authoritative for its redirect and signing-key endpoints. WP AI Bridge discovers the exact `<GATEWAY_ORIGIN>/oauth/sites/callback` redirect URI and `<GATEWAY_ORIGIN>/oauth/jwks.json` JWKS URI from that document; do not configure those URLs separately and never copy a private key or shared secret into WordPress. Keep the built-in direct ChatGPT client available when direct ChatGPT -> WP AI Bridge access is desired. Additional-client approval only makes the Gateway eligible to connect: WP AI Bridge access groups and the WordPress user authorizing OAuth still bound the resulting authority.

If an existing site later reports `invalid_client`, first confirm the exact current client metadata URL is still approved and reachable. A Gateway reinstall or move that changes `GATEWAY_ORIGIN` creates a different client identity and requires approval of the new metadata URL before reconnecting. Intentional Bridge-client key rotation on the same origin keeps the client ID stable; the metadata-declared JWKS endpoint remains the source of truth and WP AI Bridge performs bounded key refresh behavior rather than requiring a manually pasted JWKS URL.

Finally, sign in at `/admin/login` and confirm the authenticated Gateway connection-information page shows the canonical public MCP/discovery information without token/private-key values.

Do not include access tokens, refresh tokens, authorization codes, client assertions, passwords, `APP_KEY`, `.env` contents, or private-key contents in deployment logs/screenshots used as evidence.

### Production diagnostics runbook

Start diagnosis with the exact failure time/time zone, affected site/operation, HTTP status when known, and the Gateway correlation ID. Preserve identifiers and bounded metadata; never preserve raw credentials or request bodies merely to make a failure easier to inspect.

Use the evidence in this order:

1. **Gateway health/configuration** — run `php artisan gateway:check`; for ChatGPT client-contract questions also run `php artisan gateway:oauth-client-check --refresh`, then verify the safe public endpoints above.
2. **Operator Activity** — use `/admin/activity` to correlate the timestamp/site/operation/outcome/error category. Activity intentionally contains metadata rather than access/refresh tokens, authorization codes, client assertions, passwords, private keys, or arbitrary MCP payloads.
3. **Application log** — the default `daily` channel writes date-rotated Laravel logs under `storage/logs/` (normally `laravel-YYYY-MM-DD.log`) and retains 14 files by default through `LOG_DAILY_DAYS`. Historical installer defaults are normalized to the same bounded daily behavior unless the operator supplied a custom logging configuration.
4. **Web/PHP/OpenLiteSpeed evidence** — inspect the aaPanel/site/PHP/OpenLiteSpeed error log that owns the failing request only when the Gateway evidence is insufficient. Those paths are hosting-configuration state rather than Gateway-owned paths, so this document does not invent one fixed filesystem location; use the per-site/PHP error-log location configured by the host/control panel.
5. **Updater evidence** — for update failures, preserve the exact updater page/state and the private code backup under `storage/app/private/update-backups/`. The updater retains only the three newest updater-created code backups. Do not discard retained recovery evidence while an update is in a recovery-required state.

Classify the failure before changing credentials or retry policy: distinguish local preflight/configuration failure, rate limiting, OAuth client/grant failure, downstream network/TLS failure, protocol incompatibility, downstream authorization/rejection, and an ambiguous mutation outcome. Unknown writes must not be retried merely to improve observability.

The application-level log policy bounds retained file count, not the byte size of an unusually busy single day. Do not add arbitrary request-body logging or speculative logging infrastructure to obtain a strict byte cap. If measured production traffic shows daily log size can create disk pressure, treat that measurement as the trigger for a separate targeted log-size/host-retention change.

When escalating a problem, share only the timestamp/time zone, correlation ID, safe Activity/error category, relevant HTTP status/Retry-After metadata, release identity, and redacted log excerpts. Never attach `.env`, `APP_KEY`, bearer/refresh tokens, authorization codes, client assertions, database passwords, or private keys.

## 10. OpenLiteSpeed V1 validation result

Historical V1 validation completed the production-like aaPanel/OpenLiteSpeed/LSAPI proof on OpenLiteSpeed 1.8.4 with PHP 8.4 and MySQL 8.4. MariaDB 10.11 is now the primary development/CI/deployment target while MySQL compatibility remains supported. Modern MCP requests and the retained legacy compatibility flow worked through HTTPS/OpenLiteSpeed without an evidence-based need for custom buffering or timeout overrides beyond the normal Laravel `public/` document-root/rewrite configuration.

Do not pre-apply nginx directives or generic buffering tweaks. If a future release introduces materially different long-lived server-to-client streaming/SSE behavior, revalidate OpenLiteSpeed/LSAPI buffering and timeout behavior for that release before prescribing a new setting.

## 11. Backup and recovery baseline

Before every migration-bearing upgrade, preserve a recoverable set containing:

- a consistent MariaDB/MySQL database backup, including site registry, encrypted site credentials and OAuth-flow state owned by the deployed revision;
- the deployment `.env` / Laravel `APP_KEY` through the site's approved secret-backup mechanism;
- `OAUTH_PRIVATE_KEY_PATH` and `OAUTH_PUBLIC_KEY_PATH` with permissions preserved;
- `BRIDGE_CLIENT_PRIVATE_KEY_PATH` and `BRIDGE_CLIENT_PUBLIC_KEY_PATH` with permissions preserved;
- the exact deployed release identity and the corresponding repository Composer lockfile identity.

Treat the database, `APP_KEY`, and both signing keypairs as one recovery set. Site access/refresh tokens are encrypted with the application encryption boundary, so restoring the database without the matching `APP_KEY` makes those credentials unusable. Restoring a different Bridge client keypair changes the `private_key_jwt` identity material advertised through the Gateway JWKS endpoint and can break approved site connections even when the database is intact.

V1 recovery validation proved this set on a controlled two-site installation. Preserve the same recovery-set invariant for future releases; backup presence alone is not sufficient unless restore assumptions remain valid.

## 12. Upgrade and rollback outline

The web installer is **fresh-install only**. Never use `/install` to upgrade an existing Gateway.

### Deployment-ZIP installations

Each release publishes a separate browser-update artifact named `mcp-gateway-update-vX.Y.Z.zip`. Git, Composer, and SSH are not required for the normal update path.

For an authorized upgrade:

1. Capture the recovery set above when the release contains or may contain migrations.
2. Download the exact named update ZIP for the intended release and, when practical, compare it with its published `.sha256` file.
3. Upload the ZIP into the **existing Gateway application root** containing `.env`, `artisan`, `public/`, and `storage/`.
4. Extract it in that same application root. Extraction may add only private `update/` staging and temporary `public/update/`; it must not replace normal application-managed files before explicit confirmation.
5. Open `https://gateway.example.com/update/` over HTTPS.
6. Authenticate with the existing Gateway administrator account if prompted. The temporary updater reuses the normal administrator session and CSRF boundary.
7. Confirm the installed/target versions and all preflight checks, then choose **Update MCP Gateway**.
8. Keep the browser request active until success is reported, then repeat the safe HTTP verification from this document.

Before mutation, the browser updater verifies its private manifest and temporary public-entry hash, rejects symbolic links/unsafe targets, validates semantic version direction, confirms the target is an installed deployment-ZIP layout, and runs the current Gateway environment check. It then:

- verifies that the exact Gateway-managed paths used by the mutation/recovery model are readable and replaceable;
- creates and validates a code-only recovery backup under `storage/app/private/update-backups/` before maintenance mode;
- puts Laravel into maintenance mode only after that recovery state is credible;
- preserves `.env` and the entire persistent `storage/` tree;
- replaces all application-managed release paths rather than overlaying them, preventing deleted old files from lingering;
- replaces only explicitly Gateway-owned public files and preserves unknown/host-managed files under `public/`;
- verifies the complete installed managed runtime against the package hashes before crossing the migration boundary;
- runs `php artisan optimize:clear` through Laravel;
- runs migrations with `--force`;
- runs `gateway:check`;
- resumes the application only after successful postflight validation;
- retains only the three newest updater-created code backups;
- removes private update state, root `update/` staging, and `public/update/` after success so the temporary update URL cannot be reused;
- removes only the exact canonical uploaded `mcp-gateway-update-vX.Y.Z.zip` and matching checksum when those files are present in the application root; arbitrarily renamed files are not deleted.

#### Browser updater recovery state machine

Backup creation and its first integrity check happen before maintenance mode. If that initial recovery proof fails, the updater aborts before managed application files are changed; no automatic restore is needed and the application remains on the original runtime.

Once maintenance mode and managed-file replacement begin, "pre-migration failure" alone is not sufficient to infer that rollback occurred. Distinguish these recovery outcomes:

| State | Automatic action | Operator-visible result |
| --- | --- | --- |
| Recovery backup is credible, a different failure occurs before migration starts, and guarded restore completes | Revalidate the backup immediately before restore, restore the previous Gateway-managed application files, clear updater state, and resume the application | Previous managed runtime is restored; migration state is unchanged |
| Recovery backup is credible but the guarded restore itself cannot complete | Stop automatic recovery; do not start migration | Keep maintenance mode active and retain updater state plus backup evidence. The managed runtime may be partially restored/replaced and requires manual recovery |
| Recovery backup is rejected when an automatic restore or the final pre-migration boundary needs it | **Do not restore from the rejected backup and do not start migration** | Keep maintenance mode active and retain updater state plus backup evidence for manual reconciliation. Do not infer that old code was restored: after a completed stage the candidate runtime remains installed, while an earlier replacement failure may leave a partially replaced managed tree |
| Database migration may have started | **Do not perform blind code/database rollback** | Keep maintenance mode active and retain recovery evidence until schema/data state is reconciled and a release-specific roll-forward or rollback procedure is selected |

For either retained-maintenance pre-migration failure, do not re-extract, start another update, delete updater state, or discard the retained backup merely because migration did not start. A failed backup-integrity check means automatic restore is intentionally unavailable; a failed guarded restore means automatic recovery did not complete. Treat the current managed runtime as recovery-required until its exact state is verified. The retained code backup is evidence/recovery material, not proof that a database rollback or code restore is safe.

#### Public ownership boundary

`public/` is shared with the hosting/control-panel layer. MCP Gateway owns public **file paths**, not the entire directory or shared subdirectories. The canonical repository list is `bin/update-managed-public-paths.txt`, and each update artifact carries the checksummed copy as `update/MANAGED_PUBLIC_PATHS`.

- Every public file shipped by the release payload must be declared in that list.
- Once a public file path becomes Gateway-owned, keep the path declared even if a later release removes the file from the payload; the retained entry is the tombstone for deterministic stale-file cleanup.
- A listed path identifies a file only. Listing a directory must never imply ownership of unknown descendants.
- `public/update/` is separate temporary updater staging and is removed after a successful update.
- Any unlisted path is host/operator-managed and must survive both update and pre-migration restore unchanged. This includes aaPanel `public/.user.ini` and unknown files inside otherwise shared directories.
- An update must not require weakening ownership or filesystem protections on host-managed public state.

The update ZIP is intentionally unsupported for Git/source checkouts; use the source procedure below for those installations.

### Source/Composer installations

For source deployments, move to the reviewed release and run:

```bash
composer install --no-dev --no-interaction --prefer-dist --optimize-autoloader
composer check-platform-reqs --no-dev
php artisan optimize:clear
php artisan migrate --force
php artisan gateway:check
```

Do not promise zero-downtime schema changes unless the exact release has been designed and tested for them. Do not blindly run `migrate:rollback` after an unknown or partially completed failure. When schema/data compatibility is uncertain, restore the pre-upgrade database backup or follow release-specific roll-forward/rollback instructions.

## 13. Current external references

These external references were checked while establishing this baseline. Repository/runtime evidence remains authoritative for MCP Gateway-specific commands and security checks.

- Laravel 13 documentation: https://laravel.com/framework/docs
- OpenLiteSpeed virtual-host/document-root and rewrite configuration: https://docs.openlitespeed.org/config/
- OpenLiteSpeed rewrite rules: https://docs.openlitespeed.org/config/rewriterules/
- aaPanel PHP Project/site configuration: https://www.aapanel.com/docs/Function/php.html
- aaPanel site deployment notes: https://www.aapanel.com/docs/faq/Site_Related.html

V1 production-like readiness evidence was completed under Issue #8 and is preserved in the repository/GitHub history. Future releases must revalidate only deployment assumptions materially changed by that release.