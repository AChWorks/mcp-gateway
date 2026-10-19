# MCP Gateway Deployment Baseline

This document defines the supported **current deployment and validation baseline** for MCP Gateway on PHP 8.4 + MariaDB 10.11 (primary) or MySQL, with aaPanel/OpenLiteSpeed as the primary validated host shape and compatible shared PHP hosting supported when it can expose only the application `public/` directory. The panel-free Nginx/PHP-FPM procedure below is an operator example whose exact distro, TLS and runtime configuration must still be validated on the chosen server.

GitHub releases own public release identity. Production deployment remains an operator-controlled action: publishing a release does not authorize or perform deployment to any server. `README.md` remains the user-facing installation and usage guide. The [operator configuration reference](CONFIGURATION.md) inventories `.env.example` and explains login-session, OAuth/MCP timing and safe live configuration reloads.

## Releases, supported host profile and migration safety

Install or update **only** from the named official [GitHub Release](https://github.com/AChWorks/mcp-gateway/releases) assets and matching verified checksums. A GitHub source branch/green CI is not a release; a published release is **not** the version installed on the operator's PHP host. Reconcile actual installed version, migration history, admin session/cron and enabled connector settings separately. Do not use a fresh-install ZIP as an updater or bypass rollback/downgrade/version gates.

**Runtime profile:** ordinary HTTPS PHP 8.4 hosting, MariaDB 10.11 primary/MySQL compatible; required PHP extensions include `curl` with `CURLOPT_RESOLVE`, `mbstring`, `openssl`, `pdo_mysql`, `sodium`. Keep `public/` the only served document root, encrypted keys/storage private, and distinct Gateway OAuth-server vs Bridge-client RSA keypairs. No production Node, Redis, separate queue daemon or Docker is required by the baseline. Actual provider connectivity enforces public DNS/address/pin, verified TLS/SSH host identity and **direct** safe outbound HTTP, not ambient untrusted proxy environment variables.

**Version-dependent schema/behavior:** The v1 **Site → v2 Target** transition is a separately authorized **destructive** migration; see [legacy upgrade/recovery runbook](TARGET-TRANSITION-RUNBOOK.md). Later v2 updates are version-specific; use source migration files and official release notes, not a copied historical checklist. In particular public v2.3.0 introduced additive SSH command/Job/lease and Target Pause schema:
- `2026_10_15_000000_add_ssh_command_operational_limits.php`
- `2026_10_15_010000_create_ssh_command_jobs.php`
- `2026_10_15_020000_add_ssh_job_lifecycle_policy.php`
- `2026_10_15_030000_snapshot_ssh_job_admission_policy.php`
- `2026_10_16_000000_add_target_operations_paused.php`

Stable v2.3.1 introduces two additive Target-era migrations:
- `2026_10_16_010000_add_ssh_job_script_input_limit.php` for the Owner-adjustable detached SSH Job script limit;
- `2026_10_17_000000_add_target_ai_guidance.php` for optional per-Target AI guidance (an ordinary nullable note, never enforced authorization).

The supported updater must apply them before the new fields are used. A rollback refuses to discard non-null operator notes silently. Publication alone is **not** evidence an installed v2.3.0 host has either migration.

**Stable v2.3.2 adds one additive Activity migration:**

- `2026_10_17_010000_add_activity_diagnostic_context.php` adds a nullable
  JSON `activity_events.diagnostic_context` field for bounded, selectively
  credential-redacted observed source errors. Existing rows and the existing
  correlation/Activity storage remain intact; there is no new datastore.
  Apply the migration through the supported updater before using the new
  diagnostics view/MCP lookup. Reversing this migration **drops retained
  diagnostic context**; a code rollback does not safely undo database DDL.

The supported Job journal enforces immutable original user/client/Target/host binding and **no-replay** of an uncertain launch. Journal-bearing Job rollback refuses unsafe destructive schema cleanup; reconciliation requires evidence on the **original** remote host and the guarded command in [Direct SSH](DIRECT-SSH-CONNECTOR.md). Owner-only Target Pause blocks new Gateway-mediated stages, **not** an in-flight remote effect. Historic Agent connector type/support was retired; no Agent data cleanup/replay of the old Target migration is implied. v2.3.1's **fresh-install-only** SSH binary transfer default does **not** change an existing private `.env` or guarantee effective enablement on an installed host. Existing missing-key installs retain OFF; a new installation enables the mode but still requires genuine host/proxy/private-staging capacity and grants.

**Upgrade safety:** Independently test-restore the consistent database backup, protect `.env`, `APP_KEY`, OAuth/Bridge signing keys, storage and host-managed public files. A browser updater's application-file backup **cannot** undo MariaDB/MySQL DDL or revocations. Never replay a possibly dispatched WordPress refresh/revoke, SSH command/Job or migration after unknown progress to guess its result. Preserve original recovery fences and follow the updater's authenticated recovery path.

**WordPress + aaPanel note:** WordPress authenticated authorization and “Stale” health differ. Approved-proxy/DNS policy may require *narrow* PHP LSAPI `open_basedir` access to the actual resolver files, not a global disabling of SSRF/TLS or `open_basedir`. Inspect Owner Operations DNS preflight and actual PHP host configuration before guessing that OAuth was revoked. [Connector guide](CONNECTOR-INTEGRATION-GUIDE.md) owns credential durability. Detailed version-specific assets, issue/review/acceptance evidence and migrations are recoverable from the immutable GitHub Releases, PRs, CI and source—not additional living deployment-status sections.

## 1. Prerequisites

Before placing application code on the server, prepare:

1. An aaPanel/shared-hosting site **or** a self-managed Nginx/PHP-FPM host for the intended Gateway hostname or subdomain.
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

## Panel-free Linux VPS (Nginx, PHP-FPM and MariaDB)

**A hosting control panel is not required.** On a Linux VPS, install the web server, PHP-FPM, database and HTTPS certificate yourself; then use the **same official release ZIP and browser installer** as a panel-managed site. No Git, Composer, Docker or separate MCP service is necessary for the packaged installation.

The example below is for a **fresh, single-application Debian/Ubuntu-style server** with `sudo` access. It is an operator configuration template, not a claim that every distribution or reverse proxy was field-tested. Substitute the real hostname, paths, PHP-FPM socket and service user. **Do not copy it over an existing Nginx site, PHP-FPM pool, database or firewall configuration without reconciling their current owners.** For a multi-site host, use a dedicated PHP-FPM pool/account rather than letting unrelated applications share the `www-data` runtime identity.

### 1. Prepare packages, DNS and a database

Point the Gateway hostname's DNS A/AAAA records to the server, ensure incoming TCP **80 and 443** can reach it, and use an operating-system repository that genuinely supplies **PHP >= 8.4.1**. Before installing, check package availability:

```bash
sudo apt-get update
apt-cache policy php8.4-fpm php8.4-cli
```

If there is no usable PHP 8.4 candidate (for example, an older distribution's default packages provide PHP 8.3), provision a supported PHP 8.4 repository for **that exact distribution** using its maintained vendor instructions; **do not silently install an older PHP or add an unreviewed PPA**. With those packages available:

```bash
sudo apt-get install -y nginx mariadb-server cron unzip curl ca-certificates \
  php8.4-fpm php8.4-cli php8.4-curl php8.4-mbstring php8.4-mysql \
  php8.4-xml php8.4-zip certbot python3-certbot-nginx
sudo systemctl enable --now nginx php8.4-fpm mariadb cron
php8.4 -r 'foreach (["curl","mbstring","openssl","pdo_mysql","sodium"] as $e) { if (!extension_loaded($e)) { fwrite(STDERR, "$e missing\n"); exit(1); } } if (!defined("CURLOPT_RESOLVE")) { exit(1); } echo "PHP requirements OK\n";'
ls -l /run/php/php8.4-fpm.sock
```

PHP's `sodium` and `openssl` extensions may be supplied by the distribution's PHP common packages rather than separate module packages; the check above must succeed. Verify PHP-FPM uses the expected PHP 8.4 configuration, not only the CLI.

Create a **new empty** database and a database-scoped user, for example with `sudo mariadb` and the following interactive SQL (substitute a unique, strong password and do not publish it):

```sql
CREATE DATABASE mcp_gateway CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'mcp_gateway'@'127.0.0.1' IDENTIFIED BY 'REPLACE_WITH_STRONG_PRIVATE_PASSWORD';
GRANT ALL PRIVILEGES ON mcp_gateway.* TO 'mcp_gateway'@'127.0.0.1';
```

For the web installer, use database host `127.0.0.1`, port `3306`, name `mcp_gateway` and the new database account. The database grant is limited to this application database but includes DDL needed by the installer and future migrations. Do not use MariaDB's global root account for the app.

### 2. Download and verify the official ZIP

Choose a **published stable tag** from [GitHub Releases](https://github.com/AChWorks/mcp-gateway/releases); the tag below is an **example**, not a permanently pinned latest version.

```bash
RELEASE_TAG=v2.3.6    # Replace with the chosen published release tag.
cd "$(mktemp -d)"
curl --fail --location --output "mcp-gateway-$RELEASE_TAG.zip" \
  "https://github.com/AChWorks/mcp-gateway/releases/download/$RELEASE_TAG/mcp-gateway-$RELEASE_TAG.zip"
curl --fail --location --output "mcp-gateway-$RELEASE_TAG.zip.sha256" \
  "https://github.com/AChWorks/mcp-gateway/releases/download/$RELEASE_TAG/mcp-gateway-$RELEASE_TAG.zip.sha256"
sha256sum --check --strict "mcp-gateway-$RELEASE_TAG.zip.sha256"
sudo install -d -o www-data -g www-data -m 0750 /srv/mcp-gateway
sudo unzip -q "mcp-gateway-$RELEASE_TAG.zip" -d /srv/mcp-gateway
sudo chown -R www-data:www-data /srv/mcp-gateway
sudo -u www-data test -w /srv/mcp-gateway
sudo -u www-data test -w /srv/mcp-gateway/storage
sudo -u www-data test -w /srv/mcp-gateway/bootstrap/cache
```

This ownership example is **only for a new, dedicated installation root** where the default PHP-FPM pool runs as `www-data`. Match the actual PHP-FPM pool's user if different. Do not run a recursive ownership reset on an existing populated Gateway during an upgrade. The PHP worker must be able to create `.env`, private signing keys and updater-managed application files; keep the final private keys mode `0600` and never make the app tree world-writable. Only `/srv/mcp-gateway/public` may be exposed as the site's document root; private source and storage remain outside it.

### 3. Configure Nginx and PHP-FPM

Create `/etc/nginx/sites-available/mcp-gateway` with the following **example** server block. Replace the hostname, app root and `fastcgi_pass` socket path if your distribution differs. The exact PHP script allowlist matters: this Gateway uses **`public/install.php` before Laravel is installed**, the regular **`public/index.php`** front controller, and the temporary **`public/update/index.php`** browser updater.

```nginx
server {
    listen 80;
    server_name gateway.example.com;
    root /srv/mcp-gateway/public;
    index index.php;
    client_max_body_size 10m;  # Example: 8 MiB file plus form overhead.

    # Preserve the standalone first-install entry, outside Laravel.
    location = /install  { rewrite ^ /install.php last; }
    location = /install/ { rewrite ^ /install.php last; }

    # The update package temporarily stages public/update/index.php.
    location = /update  { return 301 /update/; }
    location = /update/ { rewrite ^ /update/index.php last; }

    location = /index.php {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $realpath_root/index.php;
        fastcgi_param HTTPS $https if_not_empty;
        fastcgi_param HTTP_AUTHORIZATION $http_authorization;
        fastcgi_param HTTP_X_XSRF_TOKEN $http_x_xsrf_token;
        fastcgi_pass unix:/run/php/php8.4-fpm.sock;
    }

    location = /install.php {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $realpath_root/install.php;
        fastcgi_param HTTPS $https if_not_empty;
        fastcgi_param HTTP_AUTHORIZATION $http_authorization;
        fastcgi_param HTTP_X_XSRF_TOKEN $http_x_xsrf_token;
        fastcgi_pass unix:/run/php/php8.4-fpm.sock;
    }

    location = /update/index.php {
        try_files $uri =410;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $realpath_root/update/index.php;
        fastcgi_param HTTPS $https if_not_empty;
        fastcgi_param HTTP_AUTHORIZATION $http_authorization;
        fastcgi_param HTTP_X_XSRF_TOKEN $http_x_xsrf_token;
        fastcgi_read_timeout 300s;  # Bounded example; verify upgrade budgets.
        fastcgi_pass unix:/run/php/php8.4-fpm.sock;
    }

    # Never execute arbitrary PHP or expose hidden files. OAuth discovery
    # under /.well-known/ must still reach Laravel; Certbot also uses it.
    location ~ \.php(?:/|$) { return 404; }
    location ~ /\.(?!well-known/) { return 404; }

    # Route OAuth/MCP/Admin URLs through Laravel; serve existing assets.
    location / { try_files $uri /index.php?$query_string; }
}
```

**Important:** Nginx does **not** read the packaged `public/.htaccess`. A generic Laravel `try_files` rule without the specific `/install` and `/update/` handlers can break the standalone installer and updater. The update endpoint resolves to its staged PHP file during an approved update; without the file, the exact handler returns **410** for `/update/` (and `/update` redirects once to that status), not an infinite redirect or Laravel 404. These locations pass HTTPS and the OAuth Authorization header to PHP-FPM. Do not open up a generic executable `location ~ \.php` handler.

Enable the site and validate Nginx **before** modifying a live Nginx host:

```bash
sudo ln -s /etc/nginx/sites-available/mcp-gateway /etc/nginx/sites-enabled/mcp-gateway
sudo nginx -t
sudo systemctl reload nginx
```

Set up a publicly trusted HTTPS certificate and redirect HTTP to HTTPS. With DNS and port 80 ready, a common Certbot/Nginx path is:

```bash
sudo certbot --nginx -d gateway.example.com
sudo nginx -t
sudo certbot renew --dry-run
```

Select the HTTPS redirect when offered, and verify the installed vhost really terminates TLS on port **443**. Do not enter passwords in the installer until HTTPS works; do not rely on arbitrary forwarded-proto headers. Confirm `php8.4-fpm`, Nginx and MariaDB services are running. If SSH/browser whole-file transfer is enabled, reconcile `client_max_body_size`, PHP-FPM `upload_max_filesize`/`post_max_size`, disk space, worker/request timeouts and the configured Gateway transfer limits; the values above are **examples, not proof of end-to-end capacity**.

### 4. Finish installation, schedule maintenance and verify

1. Open `https://gateway.example.com/install`; the **standalone web installer** creates the private production `.env`, keys, schema, admin account and installed marker. Enter the database values above. Do **not** run `php artisan key:generate` or `migrate:fresh` as an extra step after completing the web installer.
2. Log in at `https://gateway.example.com/admin/login`.
3. From the application root, verify the **actual site worker** can run the built-in environment and scheduler checks:

   ```bash
   sudo -u www-data sh -c 'cd /srv/mcp-gateway && /usr/bin/php8.4 artisan gateway:check'
   sudo -u www-data sh -c 'cd /srv/mcp-gateway && /usr/bin/php8.4 artisan schedule:list'
   ```

4. Add **one** system cron entry with `sudo crontab -u www-data -e` (for the same PHP-FPM account):

   ```cron
   * * * * * cd /srv/mcp-gateway && /usr/bin/php8.4 artisan schedule:run --no-ansi >> /dev/null 2>&1
   ```

   Check the cron service and a **real dispatch**, not only `schedule:list`. It maintains idle WordPress OAuth credentials, Activity retention and applicable SSH Job cleanup. Do not run the application's scheduler as root.

5. Verify `https://gateway.example.com/up` and `/admin/login` return healthy responses, HTTP redirects to HTTPS, and OAuth discovery at `https://gateway.example.com/.well-known/oauth-protected-resource/mcp` reaches Laravel. Review redacted Nginx/PHP-FPM/Laravel error logs if a route fails, and keep credentials out of logs.

**No-panel updates:** Download the *matching* official `mcp-gateway-update-vX.Y.Z.zip` and checksum over SSH/SFTP, verify SHA-256, and **extract the update ZIP into the existing application root**. This stages temporary `update/` and `public/update/` files without replacing the running application's managed code yet. Ensure both staged paths are accessible to the site PHP worker; do not make them world-writable. Keep a separately tested database backup and private `.env`/keys/`storage/`; then use the authenticated **`https://gateway.example.com/update/`** browser flow. Do **not** unzip the *fresh-install* ZIP over a running installation, call migrations manually as a substitute, or blindly retry an uncertain browser update. The detailed updater/recovery contract below is the same with or without a hosting panel.

For Apache-based panel-free hosts, the supplied `public/.htaccess` covers the application's rewrite contract when `mod_rewrite` and the required per-directory override policy are correctly enabled; the same private app-root, PHP 8.4, TLS, DB, worker ownership, installer and cron requirements still apply.

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

For normal ZIP-based installs, with or without a hosting panel, download the named deployment package attached to the GitHub Release:

```text
mcp-gateway-vX.Y.Z.zip
```

Do not use GitHub's generic **Source code (zip)** archive; that archive does not contain production `vendor/` dependencies. The named deployment ZIP contains only the application/runtime files required for installation and operation.

### Stable GitHub Release tag immutability (Owner/admin gate)

Before attempting the manual stable Release workflow, the repository
Owner/admin must establish a **GitHub-enforced** tag policy in
`AChWorks/mcp-gateway` (GitHub **Settings → Rulesets → New tag ruleset**):

- **Enforcement status:** `Active`.
- **Target tags:** include pattern `v*` (REST `refs/tags/v*`), with
  **no exclusions**. This protects current and historical stable tags.
- **Restrict updates:** enabled (ordinary writers cannot move the tag).
- **Restrict deletions:** enabled (ordinary writers cannot delete it).
- **Restrict creations:** disabled, so the official workflow can reserve a
  previously nonexistent tag with the create-only Git Reference API.
- **Bypass list:** empty; do not give ordinary Write/Maintain actors,
  repository roles or the Release workflow token an update/delete bypass.

The release publication guard automatically verifies an ACTIVE,
repository-level tag ruleset covering `refs/tags/v*`, restricting updates
and deletions, and allowing creation. It checks the policy using the
least-privilege GitHub workflow token before packaging, immediately before
reserving the tag, and after publication. Missing, disabled, mistargeted,
incomplete or inaccessible policy fails closed. There is no need to copy
ruleset IDs, timestamps or extra confirmations into each release dispatch.

**One-time Owner/admin responsibility:** configure the ruleset with an
**empty bypass list** and independently verify its complete settings in
GitHub. GitHub may hide `bypass_actors` from the read-only workflow
token. If a nonempty bypass list is visible, the guard rejects it;
otherwise it relies on the Owner's one-time configuration. Only an
administrator can subsequently add bypasses or change the ruleset;
deliberate administrator policy changes are a separate governance risk
and should be reviewed through normal repository administration, not
per-release attestation. Do not give the release CI token administrator
permissions just to read a hidden field.

The workflow's two Owner approval inputs remain only the exact reviewed
`approved_sha` and `approved_version`. Ruleset settings are a prerequisite,
**not automatically provisioned by CI**. Do not run manual
`gh release create` as a workaround if the platform policy is absent.
Current hermetic tests exercise the fail-closed decisions; they do not
prove GitHub has activated or is enforcing the actual ruleset.

The reservation procedure retains its create-only 201/SHA check,
rejects concurrent 409/422 and ambiguous API outcomes without retry,
preserves a tag-only partial publication for manual reconciliation,
uses `gh release create --verify-tag`, and independently verifies the
published lightweight tag plus all four downloaded package/checksum
asset bytes. Any unexpected tag/Release state requires explicit Owner
reconciliation; never force-move, delete or recreate a reserved tag.

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
git clone --branch "$RELEASE_TAG" --depth 1 https://github.com/AChWorks/mcp-gateway.git mcp-gateway
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
SESSION_LIFETIME=120
SESSION_EXPIRE_ON_CLOSE=false
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

The default browser `web` guard shares one `SESSION_LIFETIME=120` **minute idle timeout** across Gateway administrators and ordinary users. `SESSION_EXPIRE_ON_CLOSE` is optional and `false` by default. Neither extends OAuth access/refresh tokens, the separate legacy MCP session, nor the browser updater's fixed continuation deadline. Config cache can hide edits to `.env`; see [Configuration](CONFIGURATION.md#make-configuration-changes-safely) before changing live settings and never regenerate encryption/signing keys to tune a session timeout.

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

### Optional SSH whole-file data plane: host pre-enablement

The raw-binary SSH file-transfer endpoint is controlled by installed-version support, the effective configuration and the authenticated Target/Client permission boundary. [Whole-file exchange](WHOLE-FILE-EXCHANGE.md) owns its technical wire protocol. **Do not infer production enablement from source CI, a published release or a disposable binary-client pass.**

**Before a future explicit production enablement**, an operator must
validate the exact installed release and nominated host/profile, then:

- Confirm the HTTPS origin, OAuth client/user/Target read/write permissions,
  remote verified SSH host identity, reachable SFTP port, and pre-provisioned
  owner-owned private `0700` remote staging directory on the destination
  filesystem; no anonymous/remote URL fetch or generic filesystem proxy.
- Test that the real reverse proxy/CDN/webserver/PHP handler passes separate
  authenticated `application/octet-stream` requests and complete binary
  responses without lossy encoding or truncation. Measure request body
  buffering, accurate `Content-Length`, worker/sockets, first-byte/idle
  and downstream send/receive deadlines, including interrupted clients.
- Distinguish the **Owner-configured synchronous SSH object maximum** from
  the effective proxy upload limit, PHP request size, per-worker memory,
  `php://temp` spill directory quota, free inode/disk headroom and the
  actual client-capacity limit. These are **separate resource ceilings**;
  a larger setting is not allocated up-front.
- Measure **aggregate concurrent ingress staging** before remote SFTP
  admission: each accepted request may consume temporary disk even if
  another operation holds the per-Target SFTP lease. Exercise one and
  multiple simultaneously active uploads/downloads at actual accepted
  object sizes and slow-client rates, with disk pressure, cleanup and
  meaningful margin for application/update/OAuth state. Add earlier
  bounded ingress admission **only** when host measurements demonstrate
  insufficient safety; reuse existing quota/auth systems.
- Check revoked bearer/client/Target permission, over-limit/partial bytes,
  source changes, create-only collisions, uncertain writes and post-request
  cleanup. A server-side `download success` Activity event means **remote
  read + verified staging**, not confirmed end-client receipt; the receiving
  client must reject incomplete length or SHA-256 mismatch.
- Keep the feature disabled until the operator has recorded a *specific*
  host/proxy capacity result and any separate production rollout approval.
  Do not set `SSH_FILE_TRANSFER_ENABLED=true` simply because source CI or
  an isolated fixture passed. Model-native ChatGPT attachments and Agent
  Gateway routing are **not** implied.

Record environment-specific capacity and receiving-client evidence with the relevant open work item, not in a duplicated dated deployment-status appendix. Keep transfer authorization, host/proxy measurements and rollout consent separate from ordinary WordPress response-size settings.

### Activity retention scheduling

Activity recording stays off the retention hot path: a routed operation writes one bounded metadata event, while `activity:prune` applies the configured age and row-count policy separately. Defaults are 30 days and 5,000 rows through `ACTIVITY_RETENTION_DAYS` and `ACTIVITY_MAX_ROWS`. Because pruning is scheduled rather than synchronous with every write, the row count can temporarily exceed the configured target between prune runs.

Configure the host's cron/scheduled-task facility to run Laravel's scheduler once per minute from the application root:

```cron
* * * * * cd <APP_ROOT> && php artisan schedule:run >> /dev/null 2>&1
```

Use the PHP 8.4 CLI that belongs to the deployed site when `php` is not that binary. Run the scheduler **as the unprivileged site PHP worker**, not as root: executing Artisan as root can create unreadable Laravel cache files on aaPanel/OpenLiteSpeed. Configure **one** every-minute scheduler task rather than separate jobs for each Laravel scheduled command. For example, if the application root is `/www/acdomains/gateway.example.com` and the aaPanel task's **Execute user** is `www`:

```bash
cd /www/acdomains/gateway.example.com || exit 1
/www/server/php/84/bin/php artisan schedule:run --no-ansi
```

If the aaPanel task itself must run as `root`, the PHP process must still drop to `www`:

```bash
cd /www/acdomains/gateway.example.com || exit 1
runuser -u www -- /www/server/php/84/bin/php artisan schedule:run --no-ansi
```

Use the actual installed path, PHP version and PHP worker account. Check the **aaPanel Cron task log** after at least one real dispatch: `artisan schedule:list` only proves Laravel registered tasks, not that host cron executes them. The v2.2.1 application schedules `activity:prune` once per day and `gateway:wordpress-credentials-maintain` every minute, both with overlap protection. An installed v2.3.0 additionally schedules `gateway:ssh-jobs-prune` hourly, limited to safely reconciled terminal SSH Jobs with verified private remote spool directories; it does not start or stop Jobs. This command and its guarded new `ssh_command_jobs` migration are **not part of installed v2.2.1**. Migration rollback refuses to drop the table while *any* durable job record remains. Unknown or active remote work requires explicit reconciliation; do not manually erase the no-replay journal. Actual credential rotation occurs only when due; a successful cron run alone does not prove a token was renewed. Without scheduled pruning the configured age/row targets are not enforced, and without regular maintenance idle WordPress refresh grants may expire.

Operators may also apply the configured policy on demand:

```bash
php artisan activity:prune
```

Pruning serializes only competing prune runs and deletes expired/overflow records in fixed-size batches; ordinary Activity writers do not acquire the retention lock. The command reports only expired/overflow deletion counts and the remaining row count. It does not dump Activity records or credentials.

### WordPress Target credential idle maintenance (Target-era v2 releases)

The Laravel scheduler checks the bounded gateway:wordpress-credentials-maintain command once per minute with overlap protection; a running cron does not require a token exchange on each minute. For each connected WordPress Target with due encrypted credentials, Gateway schedules idle rotation well before the expiry of the **refresh token itself** (normally halfway through the latest provider-advertised refresh_token_expires_in), not halfway through its much shorter access token. Expired access tokens renew when an authenticated operation needs them. Without a provider refresh lifetime hint, use a conservative fallback based on access TTL rather than assuming an immortal grant. This avoids needless half-hourly rotation of a thirty-day offline credential. The encrypted token is never written to logs, queue payloads or scheduled-task arguments; each renewal is fenced by the existing database-backed Target refresh intent and does not perform remote I/O inside a transaction. WordPress may revoke a grant or expire a token sooner than the lifetime hint.

Without the host scheduler, active MCP traffic can still trigger on-demand renewal but **idle** WordPress Target authorizations may eventually expire and require reauthorization. Check that php artisan schedule:list includes gateway:wordpress-credentials-maintain; run a bounded non-production maintenance check with:

    php artisan gateway:wordpress-credentials-maintain --limit=20

The default batch size is 50 and the hard maximum is 200 due Targets per run. An ambiguous remote rotating exchange may make **one** exact, generation-fenced, provider-authorized recovery request within the short WordPress 60-second window, including an on-demand request. This rare bounded path may wait briefly for the first request to settle. It never replays a confirmed invalid/revoked grant, never issues an uncontrolled third request, and never assumes an unresolved intent is safely recovered. Continued unknown outcomes still require the WordPress authorization/reconciliation procedure. An expired refresh token is not sent to the remote provider. The scheduled command reports only aggregate counters and redacted bounded failure classifications, never bearer credentials. A Stale health timestamp does not revoke any credential. The Owner-only manual revocation-attestation form deliberately ends in Disconnected and is **not** a normal Refresh button. See the [connector integration guide](CONNECTOR-INTEGRATION-GUIDE.md).

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

The first account created by the installer or CLI bootstrap is the recoverable `owner` with all-Target authority. Later CLI-created accounts are `administrator` users. On an existing installation receiving the access-control migration, all already-present local users are preserved as enabled `administrator` / all-Target principals and the oldest existing account becomes `owner`; newly created users retain the least-privilege defaults unless an administrator explicitly assigns broader access. After bootstrap, use the authenticated `/admin/users` access-control UI to create least-privilege Operators/Viewers, choose All-Target vs Selected-Target scope, and apply direct per-Target and Target-group capability denials, with Target group membership and direct Target reachability. The system prevents disabling or demoting the last enabled Owner. Security-sensitive access changes require the acting Owner's current password and are transactionally audited. Disabling a user also invalidates their browser access on the next request and prevents existing MCP access tokens from being used.

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

The Gateway metadata document is authoritative for its redirect and signing-key endpoints. WP AI Bridge discovers the exact `<GATEWAY_ORIGIN>/oauth/targets/callback` redirect URI and `<GATEWAY_ORIGIN>/oauth/jwks.json` JWKS URI from that document; do not configure those URLs separately and never copy a private key or shared secret into WordPress. Keep the built-in direct ChatGPT client available when direct ChatGPT -> WP AI Bridge access is desired. Additional-client approval only makes the Gateway eligible to connect: WP AI Bridge access groups and the WordPress user authorizing OAuth still bound the resulting authority.

If an existing site later reports `invalid_client`, first confirm the exact current client metadata URL is still approved and reachable. A Gateway reinstall or move that changes `GATEWAY_ORIGIN` creates a different client identity and requires approval of the new metadata URL before reconnecting. Intentional Bridge-client key rotation on the same origin keeps the client ID stable; the metadata-declared JWKS endpoint remains the source of truth and WP AI Bridge performs bounded key refresh behavior rather than requiring a manually pasted JWKS URL.

Finally, sign in at `/admin/login` and confirm the authenticated Gateway connection-information page shows the canonical public MCP/discovery information without token/private-key values.

Do not include access tokens, refresh tokens, authorization codes, client assertions, passwords, `APP_KEY`, `.env` contents, or private-key contents in deployment logs/screenshots used as evidence.

### Production diagnostics runbook

### Structured diagnostics and safe support references

In public v2.1.2 and later, operational failures across the Admin panel,
WordPress and Direct SSH Target lifecycle, MCP tool results, optional SSH file
exchange, OAuth callbacks, and HTTP request handling use bounded machine error
codes and an actionable explanation rather than only a generic red alert.
Every Admin/HTTP response includes an `X-Correlation-ID` UUID. Authenticated
Admin operations show a failure category, the safe failure stage when known,
the recommended investigation, and the matching **Log reference**. The stored
Target page explains its last error without making another network request.
MCP tool errors preserve their existing `code` and `message` and add an
operator-oriented `next_step`; request IDs stay out of public MCP tool bodies.

Application failures log one structured `Gateway operation failure.` event
with correlation ID, bounded operation/error identity, authorized Target
identifier/type where known and only allowlisted safe diagnostics: e.g.
`failure_stage` = `dns_lookup`, `dns_timeout`, `tcp_connect`,
`tls_handshake`, `request_timeout`, `response_transfer`;
optional remote HTTP status and proven request-not-sent flag. This is not a
packet capture or complete root-cause diagnosis: when the network library
cannot prove the phase, treat it as unknown rather than guessing. The SAME
correlation identity joins Activity records to log records for routed MCP
operations. Routine malformed/unauthorized input remains visible in Activity,
not a high-volume detailed server error log. Nothing records OAuth tokens,
client assertions, passwords, SSH keys, shell text, SFTP paths, file contents,
raw untrusted HTTP response bodies or raw exception messages.

The fresh-install web installer and standalone authenticated browser updater
also display a short support reference on server-side failure. They run before
or during Laravel bootstrap, so **their references are written to the PHP
host/site error log**, not necessarily `storage/logs`. Preserve the updater
state, private backups, recovery evidence and original safety controls after
an unknown migration outcome; an error reference is not a retry authorization.

To investigate a real installed WordPress Target failure, first collect the
Target ID, action (e.g. metadata-check vs credential disconnect), last-error
code, UTC timestamp and displayed diagnostic reference from that exact
installed Gateway. On the **actual installed Gateway host** (not your laptop
or a different development/test server), run only anonymous non-secret checks
against the configured public WordPress origin:

```bash
getent ahosts wordpress.example.com
curl --noproxy '*' --silent --show-error --connect-timeout 5 --max-time 14 \
  --output /dev/null \
  --write-out 'HTTP=%{http_code} DNS=%{time_namelookup} TCP=%{time_connect} TLS=%{time_appconnect} TOTAL=%{time_total}\n' \
  https://wordpress.example.com/.well-known/oauth-protected-resource
grep -F '<diagnostic-uuid>' storage/logs/laravel-*.log
```

Use the Target's actual public hostname instead of `wordpress.example.com`.
Repeat the anonymous probe for `/.well-known/oauth-authorization-server` if
needed. A success from another host does not prove that the Gateway's source
IP or resolver is accepted by the WordPress firewall/WAF, DNS, TLS endpoint
or Iranian/international network path; nor does one failure prove intentional
geographic blocking. Compare finite `failure_stage` and response status
before changing networking. Do not send OAuth POSTs, refresh tokens, access
tokens, client assertions, credentials, or remote commands to obtain logs.
For `revocation_pending`, keep encrypted credentials and the pending intent
until upstream revocation is confirmed; do not force-clear a potentially
live remote grant. On an older public stable release these improved diagnostic
fields do **not** exist until an approved update is installed.

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

## 10. Backup and recovery baseline

Before every migration-bearing upgrade, preserve a recoverable set containing:

- a consistent MariaDB/MySQL database backup **of the actual installed revision**, including its migration ledger, registered `targets` and connector-specific configurations, encrypted `target_credentials` and credential metadata, WordPress OAuth flows and refresh/revocation intents, Gateway OAuth client authorizations and related grant/recovery state, Target Groups, user/Target grants and denials, Activity, and retained `ssh_command_jobs` journal records **where those tables exist**. When upgrading a genuine legacy Site-era installation, also preserve the actual legacy Site records and flows before the destructive transition (see [Target transition runbook](TARGET-TRANSITION-RUNBOOK.md));
- the deployment `.env` / Laravel `APP_KEY` through the installation's approved secret-backup mechanism;
- `OAUTH_PRIVATE_KEY_PATH` and `OAUTH_PUBLIC_KEY_PATH` with permissions preserved;
- `BRIDGE_CLIENT_PRIVATE_KEY_PATH` and `BRIDGE_CLIENT_PUBLIC_KEY_PATH` with permissions preserved;
- private application storage and any host-managed files required to restore this installation, with appropriate access protections;
- the exact deployed release identity and the corresponding repository Composer lockfile identity.

Treat the database, matching `APP_KEY`, both signing keypairs and required private runtime state as **one coherent recovery set**. Encrypted Target credentials and protected refresh/recovery state cannot be recovered correctly without the matching application encryption key. Replacing the Bridge client keypair changes the `private_key_jwt` signing identity advertised in its Gateway-hosted JWKS and may break existing downstream authorizations even if the database is intact. An application-code backup is **not** a database restore: independently test-restore the database and verify the associated key/file compatibility in an isolated environment before relying on this set for a stateful upgrade.

## 11. Upgrade and rollback outline

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
8. Keep the browser page open. The authenticated Stage uses a **303 See Other** transition to a fresh `GET /update/` after file replacement. This commits the renewed HttpOnly/Secure cookie before the newly installed runtime presents the browser-bound continuation form. JavaScript submits Finish once; with JavaScript disabled, choose **Continue update** once. Do not refresh a POST or start again. After success, repeat HTTP verification from this document.

The preflight GET must establish an update cookie that the browser actually returns on Start. **Start refuses a missing/invalid update cookie before maintenance or file changes.** The authenticated Start and completed Stage renew the cookie; the one-time continuation lifetime begins only after files are staged. The built update artifact normalizes only the temporary public updater directory/entry to modes `0755`/`0644`, so an OpenLiteSpeed front-end can serve `/update/` even when its Unix user differs from LSAPI; private updater state and backup modes must remain restrictive. Never fix this using broad permission changes on an installed site. A repeated old Stage POST is redirected to read-only status, not Laravel admin authentication; missing/invalid cookies never grant access to Finish. Cookie refusal is not proof of migration failure or success. Check the original browser profile and the operator recovery gate below.

Once database migration, Gateway health validation and maintenance exit have completed, any failure to prune older code backups or remove temporary updater files is **cleanup-only** and must appear as success-with-warning, not as database migration failure. If the private updater state cannot be removed, the authenticated browser is retained for read-only recovery; do not retry the update until the operator safely reconciles that state. If completion-state persistence also fails, an idle retained `migrate` record is classified as **postflight-unverified** rather than proof of migration failure: the record cannot distinguish an interrupted migration from a successful finish with failed housekeeping. Preserve the state and backups, verify installed version/health/maintenance and sanitized logs, and do not attempt blind migration recovery.

The updater records named phase durations in the PHP error log as phase and elapsed_ms, without authorization material. If an update is slow, correlate those timings with the hosting request timeouts and PHP worker logs (redacted) rather than estimating progress from browser time.

If the browser connection is interrupted, open the /update/ path **in the original browser session** to inspect browser-bound recovery state. An idle files-replaced step can be continued once using its valid time-bounded token; another running step must not be submitted in parallel. If the previous step stopped in migrate (or another uncertain state), **do not click Start/Continue again, run migration rollback, delete state, or re-extract**: preserve code and database recovery evidence for manual reconciliation. A missing temporary endpoint after cleanup does not itself prove success; verify the /admin and /up endpoints and installed version. After cleanup, the shipped public rewrite rules return a stable HTTP 410 for a missing temporary updater directory; OpenLiteSpeed may retain one cached 301 from the slashless URL before reaching 410. Do not modify production proxy/host rewrites without separate origin-vs-edge evidence. This behavior was reproduced with OpenLiteSpeed 1.8.4 and PHP 8.4 on an isolated disposable server using the shipped .htaccess: without the explicit guard, both URLs redirected to one another after staging cleanup; with the guard, /update/ returned 410, /update led once to 410, and the staged /update/ remained HTTP 200. These observations do not establish the root cause of the historical two-minute delay on the production host.

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
| Recovery backup is credible, a different failure occurs before migration starts, and guarded restore completes | Revalidate the backup immediately before restore, restore only Gateway-managed application files, retain a pre-migration recovery journal and attempt maintenance exit | Previous managed files restored; migration unchanged; public HTTP/Owner acceptance **still required** |
| Recovery backup is credible but the guarded restore itself cannot complete | Stop automatic recovery; do not start migration | Keep maintenance mode active and retain updater state plus backup evidence. The managed runtime may be partially restored/replaced and requires manual recovery |
| Recovery backup is rejected when an automatic restore or the final pre-migration boundary needs it | **Do not restore from the rejected backup and do not start migration** | Keep maintenance mode active and retain updater state plus backup evidence for manual reconciliation. Do not infer that old code was restored: after a completed stage the candidate runtime remains installed, while an earlier replacement failure may leave a partially replaced managed tree |
| Database migration may have started | **Do not perform blind code/database rollback** | Keep maintenance mode active and retain recovery evidence until schema/data state is reconciled and a release-specific roll-forward or rollback procedure is selected |

For either retained-maintenance pre-migration failure, do not re-extract, start another update, delete updater state, or discard the retained backup merely because migration did not start. A failed backup-integrity check means automatic restore is intentionally unavailable; a failed guarded restore means automatic recovery did not complete. Treat the current managed runtime as recovery-required until its exact state is verified. The retained code backup is evidence/recovery material, not proof that a database rollback or code restore is safe.

#### Owner-local recovery of an interrupted pre-migration update

**No public recovery endpoint is exposed.** A missing/expired browser continuation is **not** an authorization grant. The safely recoverable case is limited to an original code backup with exact cryptographic manifest, unchanged pre-upgrade migration ledger, `migration_started=false`, retained maintenance marker and no active execution lock. If the updater wrote `migrate`, `failed-after-migration-start` or `postflight-unverified`, **DO NOT run code-only recovery**: a DDL/postflight outcome is uncertain and must be reconciled using separate Owner-approved plans. Never restore a database using this code-only procedure.

The update ZIP contains a **private** `update/Recover.php` command for an Owner with an authenticated local shell. Execute as the actual **unprivileged LSAPI PHP worker** (the UID that owns `storage/app/private/update-state.json` and `storage/framework/down`), **never root**. Use the matching PHP 8.4 CLI. For example, from the installation root, after verifying the aaPanel VHost worker identity and using your panel's approved account switching mechanism:

```bash
php update/Recover.php --check
php update/Recover.php --recover
```

`--check` is a read-only updater preflight that deliberately **does not bootstrap the staged candidate Laravel runtime**. It validates the private package and authenticated previous-code snapshot, then uses the previous snapshot's library parser plus a bounded read-only PDO migration-ledger query with the preserved private database configuration. If database identity cannot be independently established, it fails closed; no candidate config cache is executed. It refuses busy locks, changed/missing or symlinked backups, mismatched archive identity/package hashes, unknown/possibly started migrations or a migration ledger not equal to the previous release. `--recover` repeats the same checks under the exclusive updater lock, creates and verifies a **separate protected copy of the replaced code**, writes and fsyncs a temporary private `recovery-restoring` journal file, atomically renames it and fsyncs its parent directory **before** changing managed files, restores only Gateway-managed paths from the authenticated pre-upgrade backup and verifies their hashes. Original state, backup, recovery archive, DB, `.env`, APP_KEY, private `storage/`, OAuth credentials/keys, Targets, aaPanel `.user.ini` and unknown public files are retained.

The command boots the **restored** Laravel runtime in new unprivileged PHP subprocesses for `optimize:clear`, `gateway:check` and `up`. It verifies `bootstrap/cache` and only the non-secret generated `packages.php` / `services.php` readability; generated `config.php` remains mode `0600` if present. It then makes five non-destructive HTTP GET readiness requests against the configured `APP_URL` (`/up`, `/admin/login` and the three OAuth metadata endpoints). Missing readiness is reported as `recovery-http-unverified`, **not success**; original evidence remains for reconciliation. A repeated command may retry the safe verification phase without re-running database migrations. `recovery-completed` proves restored public HTTP bootstrap only: independently test authenticated Admin and read-only Target/OAuth behavior before accepting installed-site recovery. Do **not** automatically delete private state or the archive after recovery; reconcile it under an explicit operator cleanup decision.

Never invoke root Artisan with restrictive `umask 077`, broadly change permissions/ownership or declare recovery from CLI-only `gateway:check`. If CLI cannot bootstrap, rollback was interrupted in an unknown place, migration data differs, the backup is corrupted or HTTP remains 500, stop and inspect a sanitized first Laravel/LSAPI error. Keep unrelated PRs, worktrees, release artifacts and installed WordPress authorizations untouched.

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

## Fresh-install SSH whole-file transfer configuration

New web-installer environments and installations copied from the repository's
current `.env.example` explicitly set `SSH_FILE_TRANSFER_ENABLED=true`.
The existing private `.env` is preserved on update; older installations with
no key retain the source fallback `false`. Set `false` for an explicit opt-out.
This SSH-only policy never enables WordPress Bridge private data exchange or
native ChatGPT attachment handling. The actual host still requires verified
HTTPS/OAuth, Target grants, safe remote `0700` staging, finite upload/download
budgets and PHP/proxy resource compatibility; see the
[whole-file guide](WHOLE-FILE-EXCHANGE.md).

## Owner operational settings and recovery-safe precedence

The integrated **Owner-only** `/admin/operations` page is the existing single typed, audited store for bounded WordPress HTTP request/response budgets and SSH command/transfer/Job limits. It requires a real authenticated Owner, password/CSRF, version-aware optimistic updates and applicable migration state. **Never** introduce a second settings registry per connector or treat a new release as proof the operator installed its columns. Exact implemented keys/defaults, permissible ranges and precedence are in [CONFIGURATION.md](CONFIGURATION.md) and the actual [settings service](../app/Application/Operations/OperationalSettings.php). The `ssh_job_max_script_kib` control (16 KiB default, Owner-adjustable 16–64 KiB) is independent of the synchronous command and per-call SFTP/output limits. Its additive nullable `2026_10_16_010000_add_ssh_job_script_input_limit.php` migration must be applied on the actual installation before this control is used; previously retained Job identities remain unchanged.

An empty Owner override restores its underlying source configuration; a maximum is a **ceiling**, not memory reserved for every request. A WordPress connect timeout and total HTTP deadline are different constraints, just as an SSH Job runtime is not a synchronous PHP request budget. Never weaken TLS/SSRF, verified SSH host pin, decoded-body hard bound, Target/user/Client grant, or provider-approved OAuth refresh-recovery fences to make a number larger.

**Rotating WordPress refresh safety:** A potentially sent refresh stores an immutable snapshot of its original request-timeout budget. Owner settings changed later do not retroactively shorten an in-flight request or reopen the provider's single-use recovery window. Older NULL timeout-intent snapshots keep conservative historical-source bounds. An ambiguous intent must be reconciled before any downgrade/rollback that would remove those fences; the relevant migration refuses destructive reversal with unresolved snapshots. Neither changing `.env` nor downgrading code is provider-token rollback. Retain encrypted credentials and avoid unsafe replay.

**SSH Job safety:** Finite per-user active admission, selected remote execution lifetime and terminal record retention are distinct. An expired lease does not prove a Job exited and must never permit silent request-ID replay. The same host/binding, safe remote cleanup and durable journal requirements apply during updates.

Public Installer/Updater behavior and non-production validation are owned above; [GitHub Issues](https://github.com/AChWorks/mcp-gateway/issues) retain unresolved operator acceptance and [Releases](https://github.com/AChWorks/mcp-gateway/releases) establish shipped version, while only an actual installed-host check establishes effective settings.
