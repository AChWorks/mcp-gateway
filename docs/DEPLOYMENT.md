# MCP Gateway Deployment Baseline

This document defines the supported **current deployment and validation baseline** for MCP Gateway on PHP 8.4 + MariaDB 10.11 (primary) or MySQL, with aaPanel/OpenLiteSpeed as the primary validated host shape and compatible shared PHP hosting supported when it can expose only the application `public/` directory.

GitHub releases own public release identity. Production deployment remains an operator-controlled action: publishing a release does not authorize or perform deployment to any server. `README.md` remains the user-facing installation and usage guide. The [operator configuration reference](CONFIGURATION.md) inventories `.env.example` and explains login-session, OAuth/MCP timing and safe live configuration reloads.

## v2.3.0 SSH upgrade requirements (#181 / #182)

**Prepared stable source; NOT yet a GitHub Release or installed operator version.** This version retains both current WordPress and Direct SSH connectors, removes the obsolete AI Server Agent-branded UI/permissions while preserving inert legacy records, adds Owner-tunable synchronous SSH limits, a disabled-by-default authenticated browser SSH file picker, and durable agentless SSH Jobs. GitHub Issue [#181](https://github.com/AChWorks/mcp-gateway/issues/181) and [#182](https://github.com/AChWorks/mcp-gateway/issues/182) track the acceptance and authorization gates; historical connector claims do not imply production availability.

The three additive migrations `2026_10_15_000000_add_ssh_command_operational_limits.php`, `2026_10_15_010000_create_ssh_command_jobs.php` and `2026_10_15_020000_add_ssh_job_lifecycle_policy.php` require a **separately verified database backup** before eventual rollout. The third migrates any earlier unpublished Job journals to typed Owner-configurable Job limits, finite admission leases, immutable non-secret original Target/User/host-key-digest snapshots and explicit operator attestations; it also widens runtime storage to support longer bounded Jobs. For prior prerelease Job rows, the original host identity is backfilled ONLY when the original saved binding matches the current config; otherwise it remains unknown and requires separate trusted operator evidence. The Job and lifecycle migrations deliberately refuse rollback while any durable no-replay record exists. Cleanup for orphaned/uncertain Jobs requires the separately gated local `php artisan gateway:ssh-jobs-reconcile inspect|retire` workflow, with verified cleanup on the ORIGINAL remote host and exact immutable binding; see [Direct SSH operator instructions](DIRECT-SSH-CONNECTOR.md#unpublished-v230-candidate-lightweight-agentless-ssh-jobs-181). The existing once-per-minute Laravel scheduler dispatches hourly `gateway:ssh-jobs-prune` only for safely reconciled terminal Jobs. A supported remote SSH Target additionally requires its own OS-native systemd service/user manager; enabling `linger` is a separate, privileged remote-host operator decision, **not a Gateway install step**.

A disposable loopback OpenSSH/systemd user fixture passed >15-second Job execution with real exit `7`, stdout/stderr, duplicate-start, verified cancellation, cleanup and refusal without linger in [CI #38774916531](https://github.com/AChWorks/mcp-gateway/actions/runs/38774916531) on the PRE-remediation RC (the new lifecycle candidate requires fresh CI); the binary browser POST/SFTP transport was independently exercised with 180,127 opaque bytes in its isolated feature test. The full combined release candidate, independent review, operator browser visual QA and production-host capability/capacity remain separately gated. Native ChatGPT file attachments are not supported by this evidence.

### Shipping gate

Only the exact versioned integrated SHA with successful source, real transport, MariaDB, dependency audit, browser-updater compatibility and **author-separated independent security review** may be promoted to a stable manual Release. Publication via the existing Owner-dispatched package workflow does not enable optional file mode or install on aaPanel automatically. The current stable installation and update instructions remain below until public Release assets are actually published.

## Current stable v2.2.1: packages and safe upgrade boundary

The current [stable v2.2.1 Release](https://github.com/AChWorks/mcp-gateway/releases/tag/v2.2.1) provides `mcp-gateway-v2.2.1.zip` for **fresh installation** and `mcp-gateway-update-v2.2.1.zip` for **existing deployment-ZIP installs**, with separate `.sha256` companions. Download and validate only assets belonging to the selected version; GitHub source archives are not replacement installer or update packages. Publishing does not establish the installed operator version or approve a production upgrade.

**Database changes depend on the starting release.** v2.2.1 adds no new schema migration beyond v2.2.0. The v2.2.0 line introduced `2026_10_13_000000_fence_wordpress_disconnect_recovery` in addition to the four earlier migrations documented in the historical v2.1.2 inventory below. Site-era v1→Target-era v2 is a separate breaking transition with data/reset requirements: see [Target transition](TARGET-TRANSITION-RUNBOOK.md) and the exact [release notes](../RELEASE_NOTES.md). Not every prerelease/skipped-version installation is covered by the published baseline matrix.

Before running a migration-bearing updater, independently **test-restore the consistent database backup** and preserve code, `.env`, `APP_KEY`, signing keys, private storage and host-managed public files. The updater's code-only backup cannot undo SQL/DDL. Never blindly restart a stalled updater or reverse migrations after unknown progress; use the private Owner-local `php update/Recover.php --check` only with the original verified backup and the actual unprivileged site PHP worker, then follow the guarded recovery procedure for the observed phase. After completion, verify HTTP readiness and authenticated Target/OAuth behavior on the actual host.

The next section retains the **historical v2.1.2 migration inventory** because those changes remain relevant to installations upgrading from older stable versions.

## v2.1.2 release and migration inventory

[Public v2.1.2](https://github.com/AChWorks/mcp-gateway/releases/tag/v2.1.2) is the reviewed WordPress + Direct SSH release built at immutable source SHA `75d0b2284d0ec7dc918795ae3f16198a86e1e656`. Its verified browser-update ZIP is `mcp-gateway-update-v2.1.2.zip`; its fresh-install ZIP is `mcp-gateway-v2.1.2.zip`. **Only the official assets and matching SHA256 companions on that Release page should be used.** Source publication is not server installation; installed Gateway/Bridge versions and actual host health require independent verification.

Upgrading from the **published v2.0.3** line to public v2.1.2 applies **four new additive database migrations** (the later v2.1.2 Stable promotion PR #169 itself changed only VERSION/documentation):

- `2026_10_10_000000_create_ssh_direct_target_configs.php` — direct SSH connector config storage;
- `2026_10_11_000000_create_operational_settings.php` — typed Owner settings;
- `2026_10_12_000000_snapshot_wordpress_refresh_http_timeout.php` — per-refresh intent timeout snapshots;
- `2026_10_12_010000_add_ssh_transfer_operational_limits.php` — bounded SSH transfer settings.

Run the authenticated browser updater only after taking and **test-restoring** a consistent database backup, plus separately protecting `.env`, `APP_KEY`, OAuth/Bridge signing keys, other private state and the old release artifacts. A code backup is **not** a database backup. The refresh timeout snapshot migration has a deliberate `down()` safeguard that rejects rollback while unresolved snapshotted intents remain. **Do not automatically reverse SQL or re-run an uncertain refresh, revoke or migration**. Use the updater's staged failure evidence and an operator-approved roll-forward/recovery plan. Published-baseline and RC8→Stable browser upgrades passed isolated tests, **not live aaPanel/OpenLiteSpeed/Cloudflare host acceptance**; see open [#135](https://github.com/AChWorks/mcp-gateway/issues/135) and [#97](https://github.com/AChWorks/mcp-gateway/issues/97).

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

Under the pinned WP AI Bridge compatibility contract, OAuth `invalid_client` is not sufficient proof that an existing site authorization is terminal: temporary non-200 responses while resolving an approved additional client's metadata or JWKS can surface as `invalid_client` before refresh or revocation is attempted. The Gateway therefore preserves the encrypted site credential on generic `invalid_client` refresh/revocation failures and fails closed for later retry. A first authenticated refresh returning the Bridge's exact HTTP 400 invalid_client now keeps the same encrypted offline grant and Target Connected, clears only the matching first attempt intent and schedules a bounded 60-second retry; it must NOT consume the provider's single-use lost-response allowance. While access renewal is deferred, a still-valid access bearer can be used, but an expired bearer cannot. An invalid_client on an already-uncertain second attempt does NOT prove the first did not rotate and remains fenced. HTTP 400 temporarily_unavailable can occur after a committed refresh successor; treat it as ambiguous under the provider's one-shot recovery deadline. Real invalid_grant or rejected immutable scope/resource binding remains terminal. Recovery responses keep original issue-time expiry bounds rather than granting a fresh lifetime. Site removal must not proceed until remote revocation is actually confirmed.

## WordPress recovery after v2.1.2 and effective PHP DNS file access

Source-integrated Issue #173 adds a guarded WordPress disconnect-recovery ledger, conditional Owner cancellation, and separately recorded public metadata evidence. See [WordPress Target disconnect recovery](TARGET-DISCONNECT-RECOVERY.md); **these functions are not part of published v2.1.2**. Old outstanding intents default to legacy_unknown, and migration rollback refuses to erase the ledger while pending intents exist.

Under aaPanel/OpenLiteSpeed PHP 8.4 LSAPI, the **effective VHost** php_admin_value open_basedir allowlist may prevent bounded React DNS from reading /etc/resolv.conf, /etc/hosts or symlink destinations, yielding a pre-dispatch dns_lookup network_failure. Use the Owner's **Operations → Outbound DNS compatibility preflight**, adjust only the required allowlisted files via approved aaPanel configuration, and rerun the checks under the actual LSAPI worker. Do not disable open_basedir globally, relax SSRF/TLS policy, add arbitrary DNS fallback or infer OAuth validity from successful public metadata. Verify previous public/.user.ini edits separately rather than assuming they were reverted.

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

### Optional SSH whole-file data plane: released but disabled; host acceptance pending

The authenticated SSH whole-file HTTP sidecar was introduced by
[PR #166](https://github.com/AChWorks/mcp-gateway/pull/166) and ships in
public **v2.1.2**, but the route is **OFF by default**. A published code feature
and successful disposable tests are not authorization to enable it on an operator host. Its exact wire
contract, per-mode bounded operation limits and source-integrated client
proof live in [WHOLE-FILE-EXCHANGE.md](WHOLE-FILE-EXCHANGE.md); keep that
document as the only detailed protocol definition.

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

[#154](https://github.com/AChWorks/mcp-gateway/issues/154) owns the
versioned effective host/client limits and measurement evidence;
[#112](https://github.com/AChWorks/mcp-gateway/issues/112) owns release
and installed-host go/no-go; [#147](https://github.com/AChWorks/mcp-gateway/issues/147)
owns supported transport/client delivery gaps. These are separate from
ordinary WordPress response size settings and from a future Owner-paused


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

Use the actual installed path, PHP version and PHP worker account. Check the **aaPanel Cron task log** after at least one real dispatch: `artisan schedule:list` only proves Laravel registered tasks, not that host cron executes them. The v2.2.1 application schedules `activity:prune` once per day and `gateway:wordpress-credentials-maintain` every minute, both with overlap protection. The unpublished v2.3.0 candidate additionally schedules `gateway:ssh-jobs-prune` hourly, limited to safely reconciled terminal SSH Jobs with verified private remote spool directories; it does not start or stop Jobs. This command and its guarded new `ssh_command_jobs` migration are **not part of installed v2.2.1**. Migration rollback refuses to drop the table while *any* durable job record remains. Unknown or active remote work requires explicit reconciliation; do not manually erase the no-replay journal. Actual credential rotation occurs only when due; a successful cron run alone does not prove a token was renewed. Without scheduled pruning the configured age/row targets are not enforced, and without regular maintenance idle WordPress refresh grants may expire.

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

## 13. Current external references

These external references were checked while establishing this baseline. Repository/runtime evidence remains authoritative for MCP Gateway-specific commands and security checks.

- Laravel 13 documentation: https://laravel.com/framework/docs
- OpenLiteSpeed virtual-host/document-root and rewrite configuration: https://docs.openlitespeed.org/config/
- OpenLiteSpeed rewrite rules: https://docs.openlitespeed.org/config/rewriterules/
- aaPanel PHP Project/site configuration: https://www.aapanel.com/docs/Function/php.html
- aaPanel site deployment notes: https://www.aapanel.com/docs/faq/Site_Related.html

V1 production-like readiness evidence was completed under Issue #8 and is preserved in the repository/GitHub history. Future releases must revalidate only deployment assumptions materially changed by that release.

## Owner operational settings — available since public v2.1.2 (#153)

Public v2.1.2 includes the Owner-only `/admin/operations` page, which can edit
**four finite WordPress downstream resource settings** without editing `.env`
or restarting PHP workers. On any particular host, the controls become available
only after an applicable release is actually installed and its required
migrations are applied; publication alone never updates an installation.

Current default values remain the original environment/source settings.
Leaving a value empty removes its override and restores the normalized source
setting in the next request/CLI maintenance invocation.

| Operational setting | Default source setting | Owner override range |
| --- | --- | --- |
| Ordinary, OAuth, metadata, mutating response | `BRIDGE_REMOTE_MAX_RESPONSE_BYTES` (64 KiB) | 16–1024 KiB |
| Confirmed read-only WP MCP response | `BRIDGE_REMOTE_READONLY_TOOL_MAX_RESPONSE_BYTES` (256 KiB) | 16–2048 KiB |
| WordPress HTTPS connection timeout | `BRIDGE_REMOTE_CONNECT_TIMEOUT_SECONDS` (2 s) | 1–15 seconds |
| WordPress HTTPS total request timeout | `BRIDGE_REMOTE_REQUEST_TIMEOUT_SECONDS` (5 s) | 2–30 seconds |

**v2.3.0 Owner command settings (#181):** the same Owner Settings page adds `ssh_command_timeout_seconds` (default maximum 15 seconds; selectable 15–30) and `ssh_command_max_kib` (default 8 KiB; selectable 8–64). A new additive nullable-column migration, `2026_10_15_000000_add_ssh_command_operational_limits.php`, is required before enabling the candidate. Older Owner forms must not erase these two overrides; the legacy WordPress JSON setting map is unchanged. SSH timeout refers to an individual synchronous exec phase, not a total PHP/proxy request SLA or a retained background job budget.

The connect timeout cannot exceed the total request timeout. The total request
deadline is shared by DNS A+AAAA validation and pinned HTTPS dispatch; it is
not a file/object size, overall logical job lifetime, or PHP/CDN/LSAPI worker
timeout. Both finite timeout overrides affect the same shared outbound HTTP
client used by WordPress metadata, OAuth and MCP Ability requests. The
independent 8 MiB decoded-response ceiling, fail-closed origin/IP policy,
no blind mutation replay, and provider-owned refresh/recovery timing remain
non-overridable. Ranges are provisional safety bounds, **not** measured
optimal settings for an actual host; #153 owns measurements and #154 owns
effective limits across client/proxy/WordPress/SSH layers.

A first *possibly sent* rotating WordPress refresh creates an immutable
request-timeout snapshot in `wp_ai_bridge_refresh_intents` before network
I/O. The single-use retry fence, CLI maintenance wait and manual revocation
settle period use that original timeout, **not a subsequent Owner setting**.
An older pre-migration intent with a NULL timeout snapshot preserves at
least **max(source connect timeout, source request timeout, current effective
request timeout)**. Before this migration, the transport's actual source
request deadline was max(connect, request), even when the environment's
connect value exceeded request. New Owner overrides must not hide that older
connect contribution. Keep the legacy source timeout environment stable while
unresolved pre-upgrade refreshes exist; if the historical environment is no
longer known, reconcile the unknown refresh with the provider rather than
assuming a new lower timeout is a safe replay fence. This prevents increasing
or decreasing Admin settings from reopening a spent provider recovery window
or overlapping a prior in-flight request. This implementation does not modify
the provider's 60-second one-shot window, Gateway's 45-second admission
boundary, or credential identity/expiry/revocation rules.

The existing persisted single-row `operational_settings` version prevents
stale Owner forms from overwriting a concurrent edit. The current password,
CSRF, Owner role and enabled-account checks remain mandatory; a transaction
audits changed numeric values, actor, version and timestamp. Legacy Owner
browser tabs that submit the original two response keys preserve the new
network overrides. **Downgrade compatibility:** timeout overrides live in
two nullable columns of the same `operational_settings` row, not inside the
legacy JSON response-budget map. Older application code ignores the new
columns and continues reading valid response budgets. This is one settings
subsystem, not an independent second registry.

Upgrading applies the small additive migration
`2026_10_12_000000_snapshot_wordpress_refresh_http_timeout.php`;
existing Target credentials, grants, refreshing intents, values and audit
history are preserved. Before deploying a different release, verify its
declared migrations and normal backup/recovery procedures. Rolling code back
does not roll an in-flight remote refresh back, nor does dropping a snapshot
column prove successful revocation. Finish/resolve pending uncertain refreshes
before a manual schema rollback; retain encrypted credentials and recovery
fences rather than forcing a replay. The migration's `down()` deliberately
**rejects rollback if any refresh intent still holds a timeout snapshot**.
This is a fail-closed schema gate, not a replacement for a safe code rollout:
**do not start a downgraded PHP binary while any such uncertain refresh may
still be in flight.** Keep Gateway in maintenance, check/reconcile or wait for
the provider window to expire (without blind replay), verify the intent state,
then roll back the schema/code in a controlled sequence. Old PHP cannot enforce
these newer per-intent fences on its own.

Do not represent v2.1.2's released code as **installed or host-verified**
without an approved deployment and actual PHP-FPM/CLI/cron/WordPress Bridge
checks establishing that. #147 remains the
owner of client-visible bidirectional file bytes;
