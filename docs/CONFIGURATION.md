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

Values below are the defaults in the sample template, **not necessarily** the production values written by the web installer. “Seconds,” “minutes,” “bytes,” “rows” and “days” are deliberately distinguished. The repository source is authoritative for validation and effective limits. Operational features such as SSH whole-file transfer have their own **disabled-by-default** release contract.

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
| `SESSION_PATH` | `/` | Session-cookie path; default applies across Gateway URLs |
| `SESSION_DOMAIN` | `null` | Host-only domain default; changing domain can break session cookie delivery |
| `CACHE_STORE` | `file` | Default application cache backend; no Redis requirement |
| `QUEUE_CONNECTION` | `sync` | Jobs run synchronously by default; no queue worker required |
| `BROADCAST_CONNECTION` | `log` | Framework broadcasting backend; not an operator notification channel |
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

Remote timeout/response settings are **budgets**, not guarantees of response speed or permission to bypass DNS pinning, SSRF checks, TLS verification, host-key verification or OAuth permissions.

## Advanced supported settings — template alignment pending

**Canonical configuration discoverability rule:** every **actually supported and consumed first-party** environment variable must be listed exactly once in `.env.example` as a safe active default or an intelligible, explicitly commented operator-only/advanced example, and must have a matching accurate explanation here. A setting documented only in this section is **not** accepted as a permanent template omission. [PR #197](https://github.com/AChWorks/mcp-gateway/pull/197) owns the exhaustive static/dynamic/installer supported-key inventory, safety classification and both-direction CI guard. Current source and published `.env.example` are **not yet verified comprehensive**; do not conclude that keys absent from the template are unsupported, and do not enable high-risk/recovery/proxy settings by copying examples blindly. Preserve existing private `.env` and Owner Operational Settings precedence. This heading records an unresolved source/template reconciliation, not a second independent configuration authority.

These are **not extra user roles, guaranteed features or release approvals**. The production installer explicitly writes several security cookie flags even though the development `.env.example` does not list them.

| Key | Effective default / meaning |
| --- | --- |
| `SESSION_SECURE_COOKIE` | `true` when `APP_ENV=production`; require HTTPS-only browser cookies |
| `SESSION_HTTP_ONLY` | `true`; prevent JavaScript access to session cookie |
| `SESSION_SAME_SITE` | `lax`; baseline CSRF-aware cross-site cookie behavior |
| `SESSION_COOKIE` | Derived from `APP_NAME`; changing it logs out old browser sessions |
| `GATEWAY_TRUSTED_PROXIES` | Empty = trust **no** forwarded proxy headers; when necessary, comma-separated **exact IPv4/IPv6 addresses**, maximum 64, never a wildcard. Change only after identifying the actual trusted proxy path |
| `SSH_FILE_TRANSFER_ENABLED` | `false`; do not enable whole-file sidecar on a real host before separate Owner approval and installed-host acceptance; see [whole-file contract](WHOLE-FILE-EXCHANGE.md) |
| `SSH_FILE_TRANSFER_MAX_BYTES` | `8388608` bytes (8 MiB), bounded transfer budget when that feature is enabled |
| `SSH_FILE_TRANSFER_MAX_SECONDS` | `30` seconds, transfer wall-time budget |
| `SSH_VERIFY_MAX_ATTEMPTS_PER_MINUTE` | `6` attempts per Target; per-Target SSH credential verification admission |
| `SSH_VERIFY_DECAY_SECONDS` | `60` seconds; verification admission decay interval |
| `SSH_VERIFY_LEASE_SECONDS` | `30` seconds; verification admission lease window |

Advanced Laravel configuration keys beyond the list above are framework internals; avoid editing them unless the exact release and deployment procedure require it. For operational settings managed through the Gateway **Owner UI/database**, use that interface rather than presuming an equivalent `.env` key exists.

## Operational cautions

- **Identity:** `APP_URL`, `APP_KEY`, OAuth/Bridge key paths, and browser cookie security are identity/access boundaries, not routine performance knobs. The configured key paths must remain separate, private and stable through upgrades.
- **Persistence:** activity pruning is scheduled, not synchronous; log retention is separate from Activity retention. File-backed sessions, cache and MCP state require private writable `storage/`.
- **Recovery:** the authenticated browser updater and Owner-local recovery have a separate private state machine. Do not modify updater continuation/journal state or mistake its fixed 30-minute continuation for an administrator login TTL; follow [Deployment](DEPLOYMENT.md) and [Issue #135](https://github.com/AChWorks/mcp-gateway/issues/135). An updater **code backup is not a database backup**.
- **Versions:** `.env.example` is a development template, not evidence of the settings active on the actual server. Published GitHub Release, installed runtime, and an unmerged source RC are different identities. A release does not auto-update your site.
- **Support:** provide installed version, sanitized symptoms, timestamps/timezone, and safe correlation IDs. Never provide raw `.env`, tokens, passwords, private keys, database backups, full authorization headers, or user/Target secrets.

Related: [README](../README.md), [Deployment and upgrade](DEPLOYMENT.md), [Client profile runbook](CLIENT-PROFILE-RUNBOOK.md), [Whole-file exchange](WHOLE-FILE-EXCHANGE.md), [Target transition runbook](TARGET-TRANSITION-RUNBOOK.md).
