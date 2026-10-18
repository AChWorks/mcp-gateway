# MCP Gateway runtime configuration (.env)

This is the **operator-facing reference** for the environment keys shipped in `.env.example`. It describes their effective meaning in the current application configuration; it does not promise that arbitrary Laravel / PHP environment variables are supported Gateway features. The canonical values in an installed instance are its **private** `.env`, not this sample file. Never publish the real `.env` or secrets in a support ticket.

For fresh installs, the HTTPS web installer writes a production `.env` and generates the application and two separate signing keys. The source/Artisan installation path starts from `.env.example`. Already-installed gateways can adjust supported settings in their existing private `.env`; **never** rerun `/install`, rotate `APP_KEY`, regenerate signing keys, or re-enroll Targets just to change a session timeout.

## The most common question: how long does a login last?

`SESSION_LIFETIME=120` means **120 minutes of inactivity**, not two hours after login regardless of activity. The web `session` guard is shared by **Gateway administrator and ordinary Gateway user logins**; no separate administrator-only or per-user session TTL is implemented. An active user can remain signed in beyond that idle interval. Explicit logout and disabling a user can end a session earlier. The temporary browser updater reuses this authenticated administrator session but its **own continuation** has an additional fixed 30-minute deadline; `SESSION_LIFETIME` does not extend that deadline.

Example for an eight-hour idle timeout:

```dotenv
SESSION_DRIVER=file
SESSION_LIFETIME=480
SESSION_EXPIRE_ON_CLOSE=false
SESSION_ENCRYPT=true
```

`SESSION_EXPIRE_ON_CLOSE=true` creates a browser-session cookie rather than a persistent cookie; browser restore behavior can vary. It is *not* a separate role-specific expiration policy. If you need a strict maximum session age or separate admin/user limits, those are **not currently configurable** by an `.env` switch and require an intentionally designed application change.

Do not confuse the web-login session with:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `SESSION_LIFETIME` | `120` **minutes** | Inactivity limit of browser login for all Gateway web users |
| `MCP_SESSION_TTL_SECONDS` | `3600` **seconds** | Legacy cross-request MCP SDK session storage, not the website login |
| `OAUTH_AUTH_CODE_TTL_SECONDS` | `600` **seconds** | One-time OAuth authorization code |
| `OAUTH_ACCESS_TOKEN_TTL_SECONDS` | `3600` **seconds** | Gateway-issued OAuth bearer access token |
| `OAUTH_REFRESH_TOKEN_TTL_SECONDS` | `2592000` **seconds** (30 days) | Gateway-issued rotating refresh-token validity; this does **not** set WP AI Bridge's independently issued credential expiry |
| `BRIDGE_OAUTH_FLOW_TTL_SECONDS` | `600` **seconds** | Gateway-to-WordPress authorization-flow state |

Changing one timer does not implicitly extend any of the others. Do not assume existing issued tokens are retroactively extended by an `.env` edit.

## Make configuration changes safely

1. Verify the **installed release** and its release-specific runbook first. Do not edit during an active installer, browser upgrade or recovery; resolve the current operation first.
2. Create a restricted backup of the existing `.env` and preserve your separate database backup and both signing-key pairs when performing an upgrade. Do not send the backup to chat, logs or public storage. Avoid printing secrets in terminals captured by a support session.
3. Edit only the intended key in the **installed application's private** `.env`; keep production `APP_ENV=production`, `APP_DEBUG=false` and canonical HTTPS `APP_URL`. Preserve the file's ownership and restricted permissions.
4. If Laravel config is cached, the edit will **not** take effect until that cache is invalidated/rebuilt. From the application root use the matching PHP 8.4 CLI **as the same unprivileged account used for PHP/LSAPI**, not as root:

   ```bash
   php artisan config:clear
   php artisan gateway:check
   ```

   If your deployment intentionally uses configuration caching, rebuild the cache under the same account using its established deployment procedure and verify actual HTTP health. A panel-only operator must use the host's supported unprivileged configuration-reload path; do **not** make `bootstrap/cache` world-writable or restart production services without authorization.
5. Verify the behavior on the **actual installed host** (for `SESSION_LIFETIME`, sign in and check idle expiry; for outbound limits, use authorized non-destructive checks). No source CI proves a production setting was applied.

Changing `APP_URL` changes OAuth issuer/client metadata/callback identity and requires a planned client/Target reapproval procedure. Changing `APP_KEY` or deleting/replacing signing keys can invalidate encrypted credentials, authorizations or sessions. Changing a TTL does **not** justify either action.

## Complete `.env.example` key reference

Values below are the defaults in the sample template, **not necessarily** the production values written by the web installer. “Seconds,” “minutes,” “bytes,” “rows” and “days” are deliberately distinguished. The repository source is authoritative for validation and effective limits. For SSH whole-file transfer, distinguish older **disabled-by-default published releases** from the current source **fresh-install explicit ON** template and **legacy absent-key OFF** runtime fallback; never infer the installed host setting from either.

### Application, locale and deployment

| Key | Sample default | Effect / operator note |
| --- | --- | --- |
| `APP_NAME` | `MCP Gateway` | Displayed application name; quote values with spaces |
| `APP_ENV` | `local` | Runtime environment; **production installer writes `production`** |
| `APP_KEY` | empty | Laravel encryption identity; generated on installation, **never rotate casually** |
| `APP_DEBUG` | `false` | Must remain disabled in production to avoid exposing detailed failures |
| `APP_URL` | `http://127.0.0.1:8000` | Canonical OAuth issuer/origin; must be stable HTTPS in production |
| `APP_LOCALE` | `en` | Default Laravel locale |
| `APP_FALLBACK_LOCALE` | `en` | Fallback locale for missing translations |
| `APP_FAKER_LOCALE` | `en_US` | Fake-data locale for development/tests, not an operator-facing language selector |
| `APP_MAINTENANCE_DRIVER` | `file` | Storage for framework maintenance status; do not change during an updater transaction |

### Logging and database

| Key | Sample default | Effect / operator note |
| --- | --- | --- |
| `LOG_CHANNEL` | `daily` | Default application log channel |
| `LOG_STACK` | `daily` | Channels used when `LOG_CHANNEL=stack`; preserve bounded daily rotation |
| `LOG_DAILY_DAYS` | `14` days | Number of daily log files retained; plan disk capacity accordingly |
| `LOG_DEPRECATIONS_CHANNEL` | `null` | Deprecation warnings destination; `null` disables it |
| `LOG_LEVEL` | `info` | Minimum log severity; avoid verbose levels containing diagnostic metadata in production |
| `DB_CONNECTION` | `mariadb` | Supported primary DB driver, or MySQL per deployment docs |
| `DB_HOST` | `127.0.0.1` | Database host |
| `DB_PORT` | `3306` | Database TCP port |
| `DB_DATABASE` | `mcp_gateway` | Dedicated database name; changing it does not migrate existing data |
| `DB_USERNAME` | `mcp_gateway` | Dedicated database account, not root |
| `DB_PASSWORD` | empty | Database password, **secret**; installer asks for actual value |

### Web sign-in sessions and general runtime

| Key | Sample default | Effect / operator note |
| --- | --- | --- |
| `SESSION_DRIVER` | `file` | Storage for shared admin/user browser sessions; file-backed by default |
| `SESSION_LIFETIME` | `120` minutes | Browser-login **idle timeout**, shared by admin and ordinary users |
| `SESSION_EXPIRE_ON_CLOSE` | `false` | Browser-session cookie when `true`; not a role-specific or absolute TTL |
| `SESSION_ENCRYPT` | `true` | Encrypt session payloads; **keep true in production** |
| `SESSION_HTTP_ONLY` | `true` | HTTP-only session cookie, not readable by JavaScript; **keep true** |
| `SESSION_SAME_SITE` | `lax` | Browser cookie SameSite policy; not an OAuth token TTL |
| `SESSION_PATH` | `/` | Session-cookie path; default applies across Gateway URLs |
| `SESSION_DOMAIN` | `null` | Host-only domain default; changing domain can break session cookie delivery |
| `CACHE_STORE` | `file` | Default application cache backend; no Redis requirement |
| `QUEUE_CONNECTION` | `sync` | Jobs run synchronously by default; no queue worker required |
| `FILESYSTEM_DISK` | `local` | Default private Laravel filesystem disk; do not expose stored secrets publicly |
| `MAIL_MAILER` | `log` | Mail messages go to log rather than a real delivery provider by default |
| `MAIL_FROM_ADDRESS` | `gateway@example.invalid` | Sender address if email delivery is configured |
| `MAIL_FROM_NAME` | application name | Default email sender display name, derived from `APP_NAME` |

### Activity retention and MCP

| Key | Sample default | Effect / operator note |
| --- | --- | --- |
| `ACTIVITY_RETENTION_DAYS` | `30` days | Age-based activity-metadata retention; effective minimum 1 day |
| `ACTIVITY_MAX_ROWS` | `5000` rows | Target maximum after scheduled pruning; transient overage is possible |
| `ACTIVITY_PAGE_SIZE_MAX` | `100` rows | Maximum items per Activity page; clamped to 1–100 |
| `ACTIVITY_DIAGNOSTIC_CODE_MAX_BYTES` | `4096` bytes | Owner-configurable budget for retained original structured error codes; explicit truncation, minimum 128 bytes |
| `ACTIVITY_DIAGNOSTIC_MESSAGE_MAX_BYTES` | `65536` bytes | Owner-configurable budget for actual observed error messages; credential values selectively redacted, truncation marked, minimum 1024 bytes |
| `ACTIVITY_DIAGNOSTIC_DETAILS_MAX_BYTES` | `131072` bytes | Owner-configurable budget for original structured provider error details; keeps nonsecret paths/context, marks truncation, minimum 1024 bytes |
| `MCP_BOOTSTRAP_FIXTURE_ENABLED` | `false` | **Test fixture only**; never enable in production |
| `MCP_BOOTSTRAP_FIXTURE_TOKEN` | empty | Secret for test fixture; leave empty/disabled on production |
| `MCP_SESSION_TTL_SECONDS` | `3600` seconds | Legacy MCP session continuity; **not** login/OAuth lifetime |
| `MCP_CLIENT_CONNECT_TIMEOUT_SECONDS` | `2` seconds | Outbound MCP SDK connect timeout |
| `MCP_CLIENT_REQUEST_TIMEOUT_SECONDS` | `5` seconds | Outbound MCP SDK request timeout |
| `MCP_MAX_BODY_BYTES` | `1048576` bytes (1 MiB) | Gateway MCP request-body budget; not SSH whole-file transfer size |

### Gateway OAuth client discovery, signing, tokens and HTTP bounds

| Key | Sample default | Effect / operator note |
| --- | --- | --- |
| `OAUTH_PRIVATE_KEY_PATH` | `storage/app/private/oauth/private.key` | Private **Gateway OAuth signing key**; secret outside `public/` |
| `OAUTH_PUBLIC_KEY_PATH` | `storage/app/private/oauth/public.key` | Gateway OAuth public verification key |
| `OAUTH_CLIENT_METADATA_CACHE_SECONDS` | `300` seconds | Cache life for approved remote client metadata |
| `OAUTH_REMOTE_CONNECT_TIMEOUT_SECONDS` | `2` seconds | Outbound OAuth metadata connection timeout |
| `OAUTH_REMOTE_REQUEST_TIMEOUT_SECONDS` | `5` seconds | Outbound OAuth metadata request timeout |
| `OAUTH_REMOTE_MAX_RESPONSE_BYTES` | `65536` bytes (64 KiB) | Maximum permitted remote OAuth metadata response |
| `OAUTH_AUTH_CODE_TTL_SECONDS` | `600` seconds | Short-lived one-time authorization code |
| `OAUTH_ACCESS_TOKEN_TTL_SECONDS` | `3600` seconds | Gateway-issued bearer token validity |
| `OAUTH_REFRESH_TOKEN_TTL_SECONDS` | `2592000` seconds (30 days) | Gateway-issued rotating refresh token lifetime |
| `OAUTH_CLIENT_ASSERTION_MAX_SECONDS` | `300` seconds | Maximum supported client-assertion window |
| `OAUTH_REFRESH_RECOVERY_SECONDS` | `30` seconds | Narrow authenticated committed-refresh replay window; clamped to 5–60 |
| `OAUTH_REFRESH_RECOVERY_MAX_RECORDS` | `1000` records | Bound on replay records; clamped to 100–10000 |

### Gateway ingress rate limits

| Key | Sample default | Effect / operator note |
| --- | --- | --- |
| `MCP_EDGE_RATE_LIMIT_BURST_PER_SECOND` | `120` req/s | Unauthenticated ingress burst per source IP |
| `MCP_EDGE_RATE_LIMIT_PER_MINUTE` | `1200` req/min | Unauthenticated ingress sustained budget per source IP |
| `MCP_PRINCIPAL_RATE_LIMIT_BURST_PER_SECOND` | `60` req/s | Authenticated ingress burst per OAuth client/user |
| `MCP_PRINCIPAL_RATE_LIMIT_PER_MINUTE` | `600` req/min | Authenticated ingress sustained budget per OAuth client/user |

Both the edge and authenticated-principal limit apply when relevant. Their effective minimum is 1; setting a value to zero does **not** disable the limiter. Tune only against evidence of actual legitimate load. These limits do not grant additional Target permissions.

### Gateway-to-WP AI Bridge identity, OAuth and I/O

| Key | Sample default | Effect / operator note |
| --- | --- | --- |
| `BRIDGE_CLIENT_PRIVATE_KEY_PATH` | `storage/app/private/bridge-client/private.key` | Separate private Bridge OAuth-client key; do not reuse Gateway OAuth server key |
| `BRIDGE_CLIENT_PUBLIC_KEY_PATH` | `storage/app/private/bridge-client/public.key` | Public key for Gateway's Bridge client identity |
| `BRIDGE_CLIENT_ASSERTION_TTL_SECONDS` | `300` seconds | Gateway-to-Bridge client assertion validity |
| `BRIDGE_OAUTH_FLOW_TTL_SECONDS` | `600` seconds | WordPress Target authorization flow state lifetime |
| `BRIDGE_REMOTE_CONNECT_TIMEOUT_SECONDS` | `2` seconds | Outbound WP AI Bridge connection timeout |
| `BRIDGE_REMOTE_REQUEST_TIMEOUT_SECONDS` | `5` seconds | Outbound WP AI Bridge request timeout |
| `BRIDGE_REMOTE_MAX_RESPONSE_BYTES` | `65536` bytes (64 KiB) | Bounded regular Bridge metadata/OAuth response size |
| `BRIDGE_REMOTE_READONLY_TOOL_MAX_RESPONSE_BYTES` | `262144` bytes (256 KiB) | Larger read-only Bridge MCP tool budget, still subject to the transport hard ceiling |
| `CHATGPT_WP_FILE_MAX_BYTES` | `8388608` bytes (8 MiB) | Bounded WordPress-mode ChatGPT file-param private staging, source-clamped to 1–67108864 bytes (64 MiB); **not** the ordinary JSON-response or SSH whole-file limit. Effective Bridge/provider/host limits may be stricter. |
| `CHATGPT_WP_FILE_MAX_SECONDS` | `120` seconds | End-to-end source file download **plus** WordPress private lease append/verify deadline; source-clamped to 1–120 s. This is an operator private environment setting, not yet an Admin override. |
| `BRIDGE_TIMING_ENABLED` | `false` | Opt-in, request-local WordPress operation timings in the existing scoped Activity/AI diagnostics; no new service, logging store or HTTP endpoint |
| `BRIDGE_TIMING_MINIMUM_MS` | `1500` ms | Only successful requests at/above this total Gateway handler time are retained; when enabled, downstream connector failures retain timing. Pre-dispatch rejections (unknown Target, invalid input, missing permission or paused Target) do not retain timing, preserving access-probe isolation. Clamped to 0–1,800,000 ms. Use `0` only during bounded testing. |

Timing diagnostics are limited to fixed numeric phase durations and observed request counts. They are available only through the existing authorized Activity and exact-correlation diagnostics lookup; they contain no URL, bearer, request/response body or user input. `mcp_initialize_ms`, `mcp_classification_ms`, `mcp_execute_ms`, `mcp_close_ms`, credential and authorization phases are measured within the Gateway process. `dns_policy_ms` includes public-IP/DNS validation, `http_transport_ms` includes transport time, and cURL TCP/TLS/first-byte components appear only when their respective milestones are actually observed (missing does **not** mean zero). A reused connection may have a measured first-byte wait but no new TCP/TLS setup; `curl_observed_calls` counts callbacks with usable milestone observations only. `outbound_calls` counts attempted transport dispatches, not confirmed provider receipt; first-byte wait includes request upload and protocol processing, not only provider CPU time. For catalog reads, `target_lookup_ms` also includes permission-scoped lookup. Per-phase, transport and cURL components overlap; **do not sum them together**. `total_ms` excludes inbound OAuth/MCP client transport and the final Activity database insert, so it is **not** end-to-end ChatGPT latency. Environment-level configuration is read at request startup; keep disabled unless troubleshooting is requested. Existing Activity retention and Target/client authorization continue to apply.

Remote timeout/response settings are **budgets**, not guarantees of response speed or permission to bypass DNS pinning, SSRF checks, TLS verification, host-key verification or OAuth permissions.

### Direct SSH whole-file and verification bounds

| Key | Example / fresh-install behavior | Effect / operator note |
| --- | --- | --- |
| `SSH_FILE_TRANSFER_ENABLED` | `true` for **new installer/template**; `false` when absent | Authenticated SSH Direct whole-file browser/HTTPS exchange only. Existing private `.env` is preserved during updates. It enables the same SFTP backend that optional ChatGPT `target-file-input` SSH mode uses, but does not prove the ChatGPT host delivers a file. Real host, client, Target and resource admission remain required. |
| `SSH_FILE_TRANSFER_MAX_BYTES` | `8388608` bytes (8 MiB) | Default per-object whole-file size budget; independent of 16 KiB per-call SFTP limits and PHP/proxy caps |
| `SSH_FILE_TRANSFER_MAX_SECONDS` | `30` seconds | Synchronous whole-file deadline, independent of SSH Job lifetime |
| `SSH_VERIFY_MAX_ATTEMPTS_PER_MINUTE` | `6` attempts/minute | SSH credential verification admission by Target; not a transfer throughput rate |
| `SSH_VERIFY_DECAY_SECONDS` | `60` seconds | SSH credential verification admission decay period |
| `SSH_VERIFY_LEASE_SECONDS` | `30` seconds | SSH verification admission lease |

## Advanced settings (commented examples in the same complete template)

All keys below are present **commented** in `.env.example`; they are not active settings unless the operator deliberately selects and validates them. A comment's illustrative value is not evidence that a driver is ready on the installed host. Installed PHP extensions, storage tables, network permissions and user/client/Target access gates still apply. **No extra queue worker, Redis/Memcached daemon, external mail provider or non-MySQL database is required or promised by the supported basic Gateway profile.** The first-party source/configuration-consumer coverage guard prevents quietly losing a supported key, and records excluded unsupported adapter/template entries explicitly.

### Application identity, storage and database options

| Key | Source default / optional example | Effect / operator note |
| --- | --- | --- |
| `APP_PREVIOUS_KEYS` | empty | Prior application encryption keys during a *planned* rotation; values are **secrets**; never rotate `APP_KEY` as a routine configuration change |
| `APP_MAINTENANCE_STORE` | `database` | Laravel maintenance-store selection only when using a compatible maintenance driver; **do not change during an update/recovery** |
| `DB_URL` | unset | Optional connection URI; may override separate DB host/user/password values; a secret and recovery identity boundary |
| `DB_SOCKET` | empty | MySQL/MariaDB Unix socket, instead of default TCP when deliberately supported |
| `DB_CHARSET` | `utf8mb4` | MySQL/MariaDB connection character set; requires compatible database schema |
| `DB_COLLATION` | `utf8mb4_unicode_ci` | MySQL/MariaDB connection collation; avoid unplanned cross-DB differences |
| `MYSQL_ATTR_SSL_CA` | unset | CA file for PDO MySQL/MariaDB SSL; verify a protected local CA path and actual server TLS |
| `DB_FOREIGN_KEYS` | `true` | SQLite foreign-key enforcement only; SQLite is not the documented production MariaDB/MySQL deployment profile |

### Cache and optional database-backed queue configuration

| Key | Source default / optional example | Effect / operator note |
| --- | --- | --- |
| `CACHE_PREFIX` | derived from `APP_NAME` | Prefix for shared cache stores; do not collide with another installation |
| `CACHE_STORAGE_DISK` | unset | Disk for optional Laravel `storage` cache driver; keep private; baseline `CACHE_STORE=file` unchanged |
| `CACHE_STORAGE_PATH` | `framework/cache/data` | Relative path for optional storage cache driver, not a public upload directory |
| `DB_CACHE_CONNECTION` | unset | Database connection for optional cache table; schema must exist |
| `DB_CACHE_TABLE` | `cache` | Cache table for optional database cache driver |
| `DB_CACHE_LOCK_CONNECTION` | unset | DB connection for cache locks when database cache is selected |
| `DB_CACHE_LOCK_TABLE` | unset (example `cache_locks`) | Cache-lock table; ensure matching migration before enabling DB cache/locks |
| `DB_QUEUE_CONNECTION` | unset | Optional database-backed queue connection; **sync remains the supported zero-worker baseline** |
| `DB_QUEUE_TABLE` | `jobs` | Database queue table, requires schema/worker readiness when deliberately selected |
| `DB_QUEUE` | `default` | Queue name for optional DB queue, not a Gateway remote Target/Job ID |
| `DB_QUEUE_RETRY_AFTER` | `90` seconds | Reserved-job retry delay for optional DB queue; never an SSH Job no-replay override |
| `QUEUE_FAILED_DRIVER` | `database-uuids` | Laravel failed-queue-job store; not Gateway's retained SSH Job journal |

### Session and trusted-proxy controls

| Key | Source default / optional example | Effect / operator note |
| --- | --- | --- |
| `SESSION_SECURE_COOKIE` | derived from production environment | **HTTPS-only browser cookie on production.** Unset in the local HTTP template; HTTPS web installer explicitly writes `true`. Do not set `false` in production. |
| `SESSION_COOKIE` | derived from `APP_NAME` | Override shared session cookie name; changing it logs users out and may break SSO/browser continuity |
| `GATEWAY_TRUSTED_PROXIES` | unset (trust none) | Explicit trusted reverse-proxy IPv4/IPv6 addresses, max 64; never wildcard. Configure only for verified proxy topology. |
| `SESSION_CONNECTION` | unset | Optional DB session connection; only with matching session store/migrations |
| `SESSION_STORE` | unset | Optional cache-backed session store; test login, CSRF, logout and availability |
| `SESSION_TABLE` | `sessions` | Database session table when database storage is deliberately enabled |
| `SESSION_PARTITIONED_COOKIE` | `false` | Partitioned browser cookie policy; requires evaluated HTTPS/SameSite embedding context; not a generic OAuth fix |

### Logging and outbound mail adapters

| Key | Source default / optional example | Effect / operator note |
| --- | --- | --- |
| `LOG_DEPRECATIONS_TRACE` | `false` | Adds trace to Laravel deprecation logs; may reveal sensitive metadata; avoid on production |
| `LOG_PAPERTRAIL_HANDLER` | `SyslogUdpHandler` | Advanced Monolog handler class for optional Papertrail channel; never load untrusted class names |
| `LOG_SLACK_EMOJI` | `:boom:` | Slack logging channel emoji, not Gateway notifications or connector capability |
| `LOG_SLACK_USERNAME` | defaults to `APP_NAME` | Name for optional Slack error logging |
| `LOG_SLACK_WEBHOOK_URL` | unset | **Secret** optional Slack log webhook; outgoing log export needs deliberate data/security review |
| `LOG_STDERR_FORMATTER` | unset | Optional Monolog stderr formatter class; avoid arbitrary class loading |
| `LOG_SYSLOG_FACILITY` | `LOG_USER` (numeric `8`) | Syslog facility when its channel is selected; ensure system logging isolation |
| `PAPERTRAIL_URL` | unset | Papertrail log host; third-party data egress only after explicit approval |
| `PAPERTRAIL_PORT` | unset | Papertrail log port; confirm transport/TLS policy before external logging |
| `MAIL_EHLO_DOMAIN` | derived from `APP_URL` host | SMTP EHLO domain when `MAIL_MAILER=smtp`; not OAuth origin |
| `MAIL_HOST` | `127.0.0.1` | SMTP host, only when optional mailer deliberately configured |
| `MAIL_LOG_CHANNEL` | unset | Log-channel name when `MAIL_MAILER=log`; avoid sensitive mail bodies in logs |
| `MAIL_PASSWORD` | unset | **Secret** SMTP password, never commit actual credential |
| `MAIL_PORT` | `2525` | SMTP port when outbound mail is enabled |
| `MAIL_SCHEME` | unset | SMTP scheme (e.g. STARTTLS/TLS option) subject to actual mail transport support |
| `MAIL_SENDMAIL_PATH` | `/usr/sbin/sendmail -bs -i` | Local binary invocation for optional sendmail mailer; validate installed binary |
| `MAIL_URL` | unset | Optional SMTP connection URL; may include **secrets** and override separate mailer settings |
| `MAIL_USERNAME` | unset | SMTP login account; not Gateway user identity |

### Dependency-gated cache/Redis transports (not enabled by default)

The ordinary Gateway profile requires **no Redis, Memcached, external queue worker or cache daemon**. These first-party Laravel configuration inputs are real, but selecting a driver requires compatible installed extension/driver, privately provisioned service, resource bounds, deploy rollback and tests. Examples never enable them on their own.

| Key | Source default / optional example | Effect / operator note |
| --- | --- | --- |
| `MEMCACHED_HOST` | `127.0.0.1` | Optional Memcached server; requires supported extension/server and private network binding |
| `MEMCACHED_PORT` | `11211` | Optional Memcached port |
| `MEMCACHED_PERSISTENT_ID` | unset | Memcached persistent connection identity |
| `MEMCACHED_USERNAME` | unset | Optional Memcached SASL username |
| `MEMCACHED_PASSWORD` | unset | **Secret** Memcached SASL password |
| `REDIS_CLIENT` | `phpredis` | Redis client; requires appropriate installed extension/driver |
| `REDIS_URL` | unset | Redis connection URL, may carry **secrets** |
| `REDIS_HOST` | `127.0.0.1` | Redis endpoint; do not expose unauthenticated Redis over public networks |
| `REDIS_PORT` | `6379` | Redis connection port |
| `REDIS_USERNAME` | unset | Redis ACL username where configured |
| `REDIS_PASSWORD` | unset | **Secret** Redis authentication |
| `REDIS_DB` | `0` | Default Redis logical DB index |
| `REDIS_CACHE_DB` | `1` | Separate cache Redis DB index |
| `REDIS_PREFIX` | derived from `APP_NAME` | Key prefix to isolate installations |
| `REDIS_PERSISTENT` | `false` | Persistent Redis PHP connections; review worker behavior before enabling |
| `REDIS_CLUSTER` | `redis` | Redis clustering strategy when explicitly configured |
| `REDIS_MAX_RETRIES` | `3` | Client reconnect/command retry bound; do not use to retry effectful Gateway Target operations |
| `REDIS_BACKOFF_ALGORITHM` | `decorrelated_jitter` | Redis client connection retry backoff policy, not SSH Job replay |
| `REDIS_BACKOFF_BASE` | `100` milliseconds | Base Redis retry backoff duration |
| `REDIS_BACKOFF_CAP` | `1000` milliseconds | Maximum Redis retry backoff duration |
| `REDIS_CACHE_CONNECTION` | `cache` | Redis connection name for cache store |
| `REDIS_CACHE_LOCK_CONNECTION` | `default` | Redis connection name for cache locks |
| `REDIS_QUEUE_CONNECTION` | `default` | Redis connection for optional queue; no Gateway queue worker is mandatory |
| `REDIS_QUEUE` | `default` | Name of optional Redis queue |
| `REDIS_QUEUE_RETRY_AFTER` | `90` seconds | Queue reservation retry interval; not Gateway remote-action retry permission |

### One-time legacy maintenance and disposable-test switches

| Key | Source default / optional example | Effect / operator note |
| --- | --- | --- |
| `GATEWAY_TARGET_RESET_ACKNOWLEDGED` | unset | **Danger: historical destructive Site-to-Target transition only.** Use the exact Owner-approved migration attestation in [Target transition](TARGET-TRANSITION-RUNBOOK.md), never during a normal upgrade. |
| `GATEWAY_TARGET_RESET_DATABASE_BACKUP_VERIFIED` | unset | Separate operator attestation of an independently restorable DB backup for the same historical migration; flag does not create/verify a backup. Remove after use. |
| `MCP_GATEWAY_RECOVERY_TEST_LOOPBACK` | unset | **Disposable APP_ENV=testing only:** guarded local loopback HTTP override in recovery CLI tests; never set on any installed operator/production host. |

Unsupported framework scaffold entries (e.g. AWS/SQS/Beanstalkd/DynamoDB/Postmark/Resend/Slack-bot adapters and arbitrary auth-driver replacement) are **not** shipped Gateway capabilities; they are intentionally absent from the template, even where Laravel's example config references them. The first-party source inventory guard documents and checks these explicit exclusions. Do not install extra dependencies, enable arbitrary external services or change `AUTH_MODEL` to make the template appear complete.

For values managed in **Owner → Operational settings** use the existing audited
database-backed Owner control, **not** an invented `.env` key. In particular,
`ssh_job_max_script_kib` defaults to **16 KiB** and may be set to **16–64 KiB**
only after its additive `2026_10_16_010000_add_ssh_job_script_input_limit.php`
migration is applied on the installed host. It is separate from
`SSH_FILE_TRANSFER_MAX_BYTES`, synchronous command input, 16 KiB per-call SFTP
read/write and Job output windows. New settings do not retroactively change
the identity or authorization of retained Jobs.

## Operational cautions

- **Identity:** `APP_URL`, `APP_KEY`, OAuth/Bridge key paths, and browser cookie security are identity/access boundaries, not routine performance knobs. The configured key paths must remain separate, private and stable through upgrades.
- **Persistence:** activity pruning is scheduled, not synchronous; log retention is separate from Activity retention. File-backed sessions, cache and MCP state require private writable `storage/`.
- **Recovery:** the authenticated browser updater and Owner-local recovery have a separate private state machine. Do not modify updater continuation/journal state or mistake its fixed 30-minute continuation for an administrator login TTL; follow [Deployment](DEPLOYMENT.md). An updater **code backup is not a database backup**.
- **Versions:** `.env.example` is a development template, not evidence of the settings active on the actual server. Published GitHub Release, installed runtime, and a source prerelease candidate are different identities. A release does not auto-update your site.
- **Support:** provide installed version, sanitized symptoms, timestamps/timezone, and safe correlation IDs. Never provide raw `.env`, tokens, passwords, private keys, database backups, full authorization headers, or user/Target secrets.

Related: [README](../README.md), [Deployment and upgrade](DEPLOYMENT.md), [Client profile runbook](CLIENT-PROFILE-RUNBOOK.md), [Whole-file exchange](WHOLE-FILE-EXCHANGE.md), [Target transition runbook](TARGET-TRANSITION-RUNBOOK.md).
