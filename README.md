# MCP Gateway

**MCP Gateway** is a self-hosted access and operations gateway. It connects authorized MCP clients (including ChatGPT) and human operators to registered **WordPress**, **SSH**, and **ArvanCloud API** Targets. One web Admin manages users, Target Groups, client authorization, permissions, operational settings and Activity.

Each Target uses its own downstream identity and permissions. A visible Tool or registered Target is **not** proof of authorization or remote connectivity.

> **v3 is the initial supported product line.** Install only an officially [published Release](https://github.com/AChWorks/mcp-gateway/releases), not a GitHub source archive. New installations use an empty database and the deployment ZIP; existing v3 installations use the separate, SHA-256-verified Update ZIP from a subsequent published Release. [VERSION](VERSION), GitHub Release, and the actually installed host can differ. See [acceptance Issue #330](https://github.com/AChWorks/mcp-gateway/issues/330) and [deployment/upgrade guidance](docs/DEPLOYMENT.md).

**Find what you need:** [Install](#install-a-published-release) · [Connect Targets](#connect-a-target) · [Connect ChatGPT](#connect-an-mcp-client) · [Tool inventory](#mcp-tools) · [Operations and recovery](#updates-and-recovery) · [Documentation map](docs/PROJECT-MAP.md).

## What it supports

| Target | Operations | Detailed guide |
| --- | --- | --- |
| **WordPress / WP AI Bridge** | Discover and execute WordPress Abilities; separately gated, single-site publish operation | [WordPress and client setup](#wordpress) · [Integration guide](docs/CONNECTOR-INTEGRATION-GUIDE.md) |
| **Direct / Reverse SSH** | Verified SSH commands, bounded SFTP, retained Jobs and optional binary transfer; includes diagnostics and durable Batch | [SSH](#ssh) · [SSH/Jobs](docs/DIRECT-SSH-CONNECTOR.md) |
| **ArvanCloud API** | Registered, fixed-origin REST calls with an encrypted Machine User key; optional OpenAPI catalog | [ArvanCloud](#arvancloud-api) · [Connector contract](docs/ARVANCLOUD-API-CONNECTOR.md) |

The ArvanCloud REST connector does not implement S3 signing or general large-object streaming. WordPress Abilities are discovered dynamically, not registered as a new public Gateway Tool for every Ability name.

## Requirements

- Linux hosting with an HTTPS domain, a web root pointing **only** to the app's `public/` directory, and PHP **8.4.1+** (8.5 recommended) with `curl`, `mbstring`, `openssl`, `pdo_mysql`, `sodium` and cURL `CURLOPT_RESOLVE`.
- A dedicated MariaDB/MySQL database. The primary CI profile uses PHP 8.5 and MariaDB 12.3; see the [supported host and compatibility baseline](docs/DEPLOYMENT.md#releases-supported-host-profile-and-migration-safety).
- Credentials and reachable endpoints **only** for connectors you choose to use.

Published deployment ZIPs include their PHP dependencies. The host does not need Git, Composer, Node, Redis, Docker or a dedicated MCP daemon for ordinary operation.

## Install a published Release

1. Download `mcp-gateway-vX.Y.Z.zip` and its matching `.sha256` from the [official GitHub Release](https://github.com/AChWorks/mcp-gateway/releases), then verify the checksum. **Do not use** GitHub's generic source archive.
2. Prepare a **new, empty** database. Extract the ZIP into a private application directory; configure the HTTPS site's document root to `<app-root>/public`, not `<app-root>`.
3. Make `storage/` and `bootstrap/cache/` writable by the site worker. Keep the rest of the app, `.env` and private keys outside public access; do not use blanket `777` permissions.
4. Open `https://gateway.example.com/install` and complete the **first-install-only** web installer.
5. Sign in at `/admin/login`; check `/up` and the Admin dashboard.
6. Configure a single cron entry running `php artisan schedule:run` **every minute as the site user**, and verify execution.

For aaPanel/OpenLiteSpeed or a plain Nginx/PHP-FPM VPS, use the [deployment instructions](docs/DEPLOYMENT.md), including rewrites, PHP worker ownership, cron, installation verification and recovery. Never assume a successful CI build means the package is installed.

## Connect a Target

### WordPress

1. Configure **WP AI Bridge** on the WordPress site and select the intended WordPress user/permissions.
2. Copy the **Gateway client metadata URL** from **Admin → Connection** (`/admin/connection`) and approve that exact URL in **WP AI Bridge → OAuth Clients**. Do **not** substitute the JWKS URL.
3. In **Targets → Add Target → WordPress**, enter a stable Target ID, name and canonical HTTPS WordPress URL; complete **Authorize WordPress** consent and assign the intended Gateway users/groups.
4. Discover permitted operations with `wordpress-abilities-read`, then use `wordpress-ability-execute`. The separate `wordpress-content-publish-create` Tool creates a **live published post**, only under its additional explicit grant—never use publication as a connectivity test.

A saved or previously Connected Target does not prove its stored remote credential is currently valid. For expiry, revoke and uncertain refresh follow [connection recovery](docs/TARGET-DISCONNECT-RECOVERY.md).

### SSH

1. Add an **SSH → Direct SSH** Target with the approved host, port, OS user and credential; independently verify and pin the remote **SSH server host key**.
2. Grant scoped user/Target access. Test with `ssh-file-stat` or a harmless, approved read-only `ssh-command-run`.
3. Use `ssh-file-read/write/list` for bounded SFTP, `ssh-job-start/status/output/cancel` for retained remote Jobs and `ssh-jobs-list` to recover the right Job after changing chats. Do not retry an uncertain remote effect with a new request ID.
4. Enable separate whole-file browser/HTTPS binary exchange only when the **installed** Gateway configuration and hosting resource limits allow it. Remote OS account privileges still apply.

For an inbound-blocked host, use the [Managed Reverse SSH guide](docs/REVERSE-SSH-MANAGED.md) or [manual route](docs/REVERSE-SSH-OPERATOR.md); privileged host installation requires explicit host approval. For intermediary routing, use [Connection Relays](docs/CONNECTION-RELAYS.md). Route registration or tunnel readiness is not proof of the final Target login.

### ArvanCloud API

1. Create a scoped ArvanCloud **Machine User key** and register the correct **product/region HTTPS API root** under **Targets → Add Target → ArvanCloud API**.
2. Assign the intended Gateway users, Target Groups and client grants. An unauthenticated **Check HTTPS endpoint** uses HEAD to check peer reachability only; **Verify API key** is a separate, optional, explicitly configured safe authenticated GET. Neither makes a mutating provider call.
3. Use `arvan-api-catalog` when an optional public OpenAPI description is configured, and `arvan-api-request` for authorized operations against the fixed API root. Downstream Machine User restrictions remain effective.

See [ArvanCloud API details](docs/ARVANCLOUD-API-CONNECTOR.md) for supported content types, connection diagnostics and recovery.

## Connect an MCP client

1. From **Admin → Connection**, copy `https://gateway.example.com/mcp`.
2. Register the endpoint in a compatible MCP client and complete **Gateway OAuth sign-in and consent** with a user whose **AI access** is enabled.
3. Call `targets-list` and `target-context` to choose an authorized Target; then use the supported Tools.

**ChatGPT client profiles:** fixed CIMD/`private_key_jwt` and separately opt-in DCR/`client_secret_post` connections are distinct identities. DCR registration is OFF by default; enabling it does not grant a Target or migrate existing consent. See [OAuth registration and reconnect](docs/OAUTH-CLIENT-REGISTRATION.md) and [client-profile diagnostics](docs/CLIENT-PROFILE-RUNBOOK.md).

**File attachments:** the optional `wordpress-file-input` and `target-file-input` FileParams tools remain **OFF by default**. A normal chat attachment is **not** automatically passed as a host-supported FileParams argument. This does not disable ordinary SFTP or supported file exchange. [Actual delivery evidence and open questions](https://github.com/AChWorks/mcp-gateway/issues/147).

## MCP tools

Gateway v3.0.0 registered **30 standard MCP Tools**, grouped below by purpose. Query the authenticated `tools/list` for the currently installed release; tool discovery is not authorization.

| Area | Tools | Purpose |
| --- | --- | --- |
| General (3) | `targets-list`, `target-context`, `operation-diagnostics-read` | Authorized discovery and diagnostics |
| WordPress (3) | `wordpress-abilities-read`, `wordpress-ability-execute`, `wordpress-content-publish-create` | Dynamic Abilities and separately gated publishing |
| WordPress Batch (2) | `wordpress-bridge-batch-preview`, `wordpress-bridge-batch-read` | Fixed read-only information Batch |
| ArvanCloud (2) | `arvan-api-catalog`, `arvan-api-request` | Optional OpenAPI catalog and authenticated fixed-origin REST |
| SSH commands (1) | `ssh-command-run` | Approved remote command |
| SFTP and file changes (6) | `ssh-file-stat`, `ssh-file-list`, `ssh-file-read`, `ssh-file-write`, `ssh-file-patch`, `ssh-change-verify` | Bounded, verifiable remote file operations |
| SSH Jobs (5) | `ssh-job-start`, `ssh-jobs-list`, `ssh-job-status`, `ssh-job-output`, `ssh-job-cancel` | Durable remote job lifecycle |
| SSH diagnostics (3) | `ssh-system-inspect`, `ssh-network-diagnose`, `ssh-logs-query` | Typed observations and diagnostics |
| SSH Batch (2) | `ssh-batch-preview`, `ssh-batch-run` | Preview and queue durable SSH command Batch |
| Shared Batch (3) | `target-batch-status`, `target-batches-list`, `target-batch-cancel` | Child outcomes, recovery and cancellation |

No general `execute-anything` Tool, automatic WordPress bulk publishing, or arbitrary ArvanCloud Batch provider is claimed.

## Updates and recovery

**Existing v3 installation:** Download the exact published Release's `mcp-gateway-update-vX.Y.Z.zip` and its checksum. Upload and extract the package at the installed application root, then open `/update/`, sign in as an **enabled Owner**, review preflight and perform the two-phase browser update. The first installation release, v3.0.0, had no Update ZIP; each subsequent update-capable v3 Release has a separate update artifact. Never extract a fresh-install deployment ZIP over a running installation. The supported direct-update window covers up to three previously published v3 stable releases, backed by independent package tests. [Upgrade and rollback runbook](docs/DEPLOYMENT.md#11-upgrade-and-rollback-outline).

Before changing a running host, preserve a **verified-restorable database backup, current code, private `.env`/`APP_KEY`, OAuth/Bridge signing keys and relevant remote Job state**. The browser updater retains a bounded private code backup; that is **not** a database backup. A code rollback cannot undo database schema changes or remote actions.

## Administration and safety

**Authorization:** roles set the maximum permission ceiling. Direct/Group/Global **Deny** and selected Target scope can further restrict it. OAuth Client approval, AI access, Target access and remote user credentials are separate requirements; Target Pause blocks **new** Gateway effects, not a remote operation already dispatched. Owner-sensitive forms require current-password confirmation. [User/Group workflows](docs/ADMIN-ACCESS-WORKFLOWS.md).

**Diagnostics:** use a response `diagnostic_reference` in **Admin → Activity** or `operation-diagnostics-read`. Preserve actual stage/cause and distinguish blocked, failed and uncertain remote effects; never blindly repeat an uncertain write.

## Troubleshooting and references

For install/login problems verify HTTPS, `public/` document root, PHP extensions, rewrite rules, DB and writable runtime paths. For WordPress `invalid_client`, verify exact Gateway metadata approval and real provider consent; do not rotate keys to guess. For ChatGPT OAuth 401/503, inspect correlation/Activity, upstream metadata/JWKS availability and approved client profile before revoking or reconnecting. For SSH, verify the **pinned host key**, OS user, SFTP path and current budget. [Deployment diagnostics](docs/DEPLOYMENT.md#production-diagnostics-runbook) · [Configuration](docs/CONFIGURATION.md).

The [documentation map](docs/PROJECT-MAP.md) identifies **one maintained reference per task**. For implementers: [Architecture](docs/ARCHITECTURE.md), [Master Specification](docs/MASTER-SPEC.md), [Development](docs/DEVELOPMENT.md). For what shipped: [GitHub Releases](https://github.com/AChWorks/mcp-gateway/releases) and [Release notes](RELEASE_NOTES.md). Unresolved work and acceptance are in [GitHub Issues](https://github.com/AChWorks/mcp-gateway/issues).

## License

See [LICENSE](LICENSE) and [NOTICE](NOTICE) for the current project terms and required source/attribution notices.
