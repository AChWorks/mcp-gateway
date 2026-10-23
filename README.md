# MCP Gateway

**MCP Gateway** is a self-hosted application that connects MCP clients (including ChatGPT) to **WordPress sites** and **SSH servers** you explicitly authorize. Each connection is a *Target*. The web Admin panel controls Targets, users, client authorizations, permissions and activity in one place.

Use it to discover and execute WordPress Abilities through **WP AI Bridge**, run authorized SSH commands, inspect or transfer files with SFTP, and manage longer-running SSH Jobs. The Gateway does not grant more access than the configured WordPress user or remote SSH account already has.

**Get started:** [Latest official Release](https://github.com/AChWorks/mcp-gateway/releases) · [Install](#install) · [Connect WordPress](#connect-wordpress) · [Connect SSH](#connect-direct-ssh) · [Connect ChatGPT](#connect-chatgpt-or-another-mcp-client)

## How it works

1. Install the Gateway on your own HTTPS domain.
2. Add a **WordPress** or **Direct SSH** Target in the Admin panel.
3. Authorize the Target and grant specific Gateway users or Target Groups access.
4. Connect your MCP client using Gateway OAuth, then choose a Target and use its permitted tools.

Targets can be **paused** without deleting their configuration or disconnecting WordPress. Pausing stops new Gateway operations for that Target; it does **not** stop a remote SSH Job already running. An MCP client's OAuth approval and a user's Target permissions are separate requirements. The Owner can also enable or disable a user's **AI connection access** independently of their human Admin login and Target operation grants; a disabled user's existing AI consent/tokens cannot be used. Optional per-Target AI guidance provides context to an AI client; it does not override permissions or approve operations.

## Requirements

- Linux web hosting with **PHP 8.4.1 or newer** and the `curl`, `mbstring`, `openssl`, `pdo_mysql` and `sodium` extensions; cURL must support `CURLOPT_RESOLVE`.
- **MariaDB** (10.11 recommended) or **MySQL**, with a dedicated database and user.
- A stable **HTTPS** domain and a web server that can serve the application's `public/` directory.
- A compatible **WP AI Bridge** installation for WordPress Targets, or an accessible SSH host and authorized credentials for Direct SSH Targets.

The official installation ZIP includes PHP dependencies: **Git and Composer are not needed on the hosting server**. Normal operation needs no Docker, Redis, Node.js, queue worker or separate MCP daemon.

## Install

1. Download **`mcp-gateway-vX.Y.Z.zip`** and its matching `.sha256` from a published [GitHub Release](https://github.com/AChWorks/mcp-gateway/releases). Verify the checksum. Do **not** use GitHub's generic “Source code (zip)” archive.
2. Prepare a **new, empty** MariaDB/MySQL database. Extract the ZIP into a private application directory and point the site's document root to **`<app-root>/public`**, never the application root.
3. Make `storage/` and `bootstrap/cache/` writable by the PHP site worker. Enable HTTPS and working URL rewrites; do not give the whole application `777` permissions.
4. Open **`https://gateway.example.com/install`** and complete the web installer with the site URL, database connection and first Admin user.
5. Sign in at **`/admin/login`**, then check **`/up`** and the Admin dashboard.
6. Configure **one cron job every minute** to execute Laravel `schedule:run` using the site's PHP 8.4 CLI **as the site worker, not root**. Confirm that the cron log shows it actually runs.

**No control panel?** A regular Linux VPS works too: install Nginx, PHP-FPM 8.4, MariaDB and HTTPS, then use the same ZIP/web installer. Follow the [step-by-step panel-free Linux installation guide](docs/DEPLOYMENT.md#panel-free-linux-vps-nginx-php-fpm-and-mariadb), including Nginx rules for the standalone installer, temporary updater and OAuth endpoints.

The web installer is for **first installation only**; use the [update instructions](#update-an-existing-installation) for existing deployments. aaPanel/OpenLiteSpeed and CLI/source installation details, cron examples and recovery procedures are in [Deployment](docs/DEPLOYMENT.md).

## Connect WordPress

1. Install and configure **WP AI Bridge** on WordPress, including the intended WordPress user's permissions.
2. In Gateway, open **Admin → Connection** (`/admin/connection`) and copy the Gateway's **`/oauth/client.json` metadata URL**.
3. In WordPress, open **WP AI Bridge → OAuth Clients** and approve that exact *client metadata URL* (not the JWKS URL).
4. In Gateway, open **Targets → Add Target → WordPress (WP AI Bridge)**. Enter a unique `target_id` (lowercase letters, digits and hyphens; maximum 64 characters), display name and the WordPress site's canonical HTTPS URL.
5. Verify the Target, select **Authorize WordPress**, complete consent using the intended WordPress account, and assign appropriate Gateway users or Target Groups.
6. In your MCP client, call `wordpress-abilities-read` to discover permitted Ability names and schemas, then `wordpress-ability-execute` for the selected Target. The distinct `wordpress-content-publish-create` tool creates a **publicly published post** only when the user/Target Group, AI client and WordPress account are independently authorized; use the general Ability path for an approved draft or existing-post operation. Never try a live publication merely to test connectivity.

A Gateway “Connected” status is not a guarantee that a remotely revoked or expired WordPress credential still works. For uncertain refresh, disconnect or consent, follow the [Target recovery guide](docs/TARGET-DISCONNECT-RECOVERY.md) rather than deleting credential state or repeatedly reconnecting.

## Connect Direct SSH

1. Open **Targets → Add Target → Direct SSH**. Enter a unique `target_id`, SSH host, port and remote account, then configure the supported password or private-key authentication.
2. **Independently verify the server's SSH host-key fingerprint** before trusting it; never bypass an unexpected host-key change.
3. Grant only the needed user/Target permissions. Start with `ssh-file-stat` or a harmless read-only `ssh-command-run` call.
4. Use `ssh-file-list` to inspect directories, `ssh-file-read` for bounded byte ranges, and `ssh-file-write` to create or conditionally overwrite a bounded file. Repeated writes do **not** append chunks.
5. For larger, complete binary files, use the separately authorized **SSH whole-file browser upload/download or HTTPS exchange** when enabled. The Admin Target page offers a local file picker and download action; uploads require an explicit remote destination and pre-existing private `0700` staging directory. Verify received size and SHA-256.
6. For scripts that outlive a synchronous command, use `ssh-job-start` with your own UUID `request_id`, then `ssh-job-status` and bounded `ssh-job-output`; cancel a specific Job with `ssh-job-cancel` only when appropriate.
7. In a later chat, use **ssh-jobs-list** for the same authorized Gateway user, OAuth client/profile and Target to find retained Job IDs; then deliberately call **ssh-job-status** on the chosen ID. Job listing never connects to the server or retries an old command.

**SSH transfer setting:** fresh-install templates enable `SSH_FILE_TRANSFER_ENABLED=true`; an existing installation retains its private `.env` and an **absent key means OFF**. Enable whole-file mode on an existing installation only after checking hosting limits and Target permissions. The Admin **Operational Settings** page provides bounded command and Job controls (including independent configurable SSH byte windows up to **512 KiB** and a selectable synchronous command timeout up to **600 seconds**, not guaranteed by every host/client); the remote account's actual OS privileges still apply. Detached Jobs require a compatible `systemd-run` environment, and an uncertain Job start must **not** be repeated with a new request UUID.

See [Direct SSH and Jobs](docs/DIRECT-SSH-CONNECTOR.md) and [whole-file exchange](docs/WHOLE-FILE-EXCHANGE.md) for prerequisites, limits, integrity checks and recovery.

## Connect ChatGPT or another MCP client

1. From **Admin → Connection**, copy the Gateway MCP endpoint, normally **`https://gateway.example.com/mcp`**.
2. Register it as a compatible MCP connection in your client and complete **Gateway OAuth** sign-in and consent with an authorized Gateway user/client profile.
3. Use `targets-list` and `target-context` to select an authorized `target_id`, then call the WordPress or SSH tools available to that user and client.

Manage client profiles and grants under **Admin → AI clients** (`/admin/oauth-clients`). After an upgrade, refresh/reconnect the MCP connection if your client still displays an outdated Tool catalog.


**ChatGPT OAuth choices:** the original fixed ChatGPT CIMD/`private_key_jwt` connection remains supported. This release also supports a separate opt-in DCR/`client_secret_post` connection: public registration starts **OFF**, and existing CIMD discovery stays ON. An administrator may deliberately enable DCR onboarding, create a **new** ChatGPT connection and approve its own consent; no grants, credentials or tokens transfer from the old connection. Closing public registration after onboarding does not revoke the new client. Read the [OAuth client registration and recovery guide](docs/OAUTH-CLIENT-REGISTRATION.md) before changing installed settings; publishing a release is not deployment or proof of actual ChatGPT interoperability.

**ChatGPT attachments:** native ChatGPT FileParams handoff is **paused and OFF by default**. The optional `target-file-input` and `wordpress-file-input` tools are not advertised while `CHATGPT_FILEPARAMS_ENABLED` is absent or `false`; a reliable host-provided file handoff has not been demonstrated for the current integration. Do not enable it just to retry attachments or weaken source-URL security. **This does not disable** ordinary SFTP, supported SSH browser/HTTPS binary transfer, or WordPress's native file-transfer Abilities. A file attached to a ChatGPT conversation is **not automatically available** to these tools.

## MCP tools at a glance

The normal Gateway tool set is **16 tools** (subject to authenticated client, user and Target grants):

| Tools | Use |
| --- | --- |
| `targets-list`, `target-context` | Find permitted Targets and inspect non-secret Target context. |
| `wordpress-abilities-read`, `wordpress-ability-execute` | Discover and invoke WordPress Abilities on a selected WordPress Target. |
| `wordpress-content-publish-create` | Create **one live published** WordPress `post` with a fixed, bounded Bridge operation and a separate scoped publish grant. This is **not** a draft creator or unrestricted editing tool. |
| `ssh-command-run` | Execute a bounded, non-interactive command as the authorized remote SSH account. |
| `ssh-file-stat`, `ssh-file-list`, `ssh-file-read`, `ssh-file-write` | Inspect SFTP paths, read bounded ranges, or create/conditionally overwrite bounded files. |
| `ssh-job-start`, `ssh-job-status`, `ssh-job-output`, `ssh-job-cancel` | Start, reconcile, inspect and cancel retained SSH Jobs without blindly replaying them. |
| `ssh-jobs-list` | List only retained Jobs for the currently authorized user, OAuth client/profile and selected Target; no remote execution. |
| `operation-diagnostics-read` | Look up permitted, credential-redacted failure evidence by `diagnostic_reference` or Target. |

WordPress plugin Abilities are discovered dynamically; a newly available Ability does **not** require a new Gateway MCP tool for its name.

## Administration and safety

From the Admin dashboard (`/admin`) you can manage **Targets**, **Target Groups**, **Users**, **AI clients**, **Operational Settings**, **Activity** and **Connection**. Only grant permissions appropriate to the actual WordPress user or SSH account; Gateway permissions do not turn root SSH into a sandbox.

When a tool fails, use its `diagnostic_reference` with **Admin → Activity** (`/admin/activity`) or `operation-diagnostics-read`. Diagnostics preserve the *observed* error and its stage with sensitive values removed; if a downstream system omitted the original cause, Gateway cannot reconstruct it. Never blindly retry a mutation with an unknown result.

Keep `.env`, application encryption and OAuth signing keys, database backups, credentials, tokens and private `storage/` outside the web root and out of public issue reports.

## Update an existing installation

1. Read the selected [Release notes](RELEASE_NOTES.md), preserve the existing `.env`, `APP_KEY`, OAuth/Bridge signing keys, application code and private `storage/`, and take a **consistent database backup whose restore can be verified**.
2. Download the matching **`mcp-gateway-update-vX.Y.Z.zip`** and its `.sha256` from the published Release; **do not** use the fresh-install ZIP or GitHub's generic source archive.
3. Extract the update ZIP into the **existing application root** (alongside `artisan`, `.env`, `public/` and `storage/`). Open **`https://gateway.example.com/update/`**, sign in as an existing administrator and follow the version/checksum/preflight checks.
4. Complete the browser updater **once**, then verify the installed version, `/up`, Admin sign-in, OAuth connection and authorized WordPress/SSH Targets. Successful cleanup removes the temporary updater endpoint.

Source commits and GitHub Releases do **not** update an installed Gateway automatically.

If an update stops during migration or recovery, **do not blindly retry** or treat a code-only backup as a database restore. Use the [Deployment and recovery guide](docs/DEPLOYMENT.md). Older v1 Site-era upgrades require the separate [Target transition runbook](docs/TARGET-TRANSITION-RUNBOOK.md); source/Composer installations use their own CLI procedure.

## Troubleshooting

- **Installer or HTTP error:** confirm PHP/extensions, HTTPS, URL rewrites, the `public/` web root, database access and writable runtime directories.
- **WordPress `invalid_client`:** verify the exact Gateway client metadata URL is approved in WP AI Bridge and inspect the Target's real consent/recovery status. Do not regenerate signing keys as a shortcut.
- **ChatGPT OAuth reconnect returns 503:** inspect the upstream ChatGPT CIMD/JWKS status and the Gateway correlation. If OpenAI documents are unavailable, use the separately reviewed DCR fallback described in [OAuth client registration](docs/OAUTH-CLIENT-REGISTRATION.md). Reconnecting the former CIMD client does not migrate it.
- **MCP tools missing:** verify OAuth client/user/Target grants, whether a Target is paused, and whether the client needs a Tool catalog refresh.
- **SSH command or file failure:** check the approved host-key fingerprint, remote OS account permissions, SFTP path and separately enabled whole-file transfer mode.
- **Unclear failure or interrupted update:** use authorized diagnostic evidence or [recovery instructions](docs/DEPLOYMENT.md); never repeat an operation that may already have changed a remote system.

## Further guides

- [Official Releases](https://github.com/AChWorks/mcp-gateway/releases) and [Release notes](RELEASE_NOTES.md) — versions and compatibility.
- [Deployment and recovery](docs/DEPLOYMENT.md) — hosting, cron, updates and backup procedures.
- [Configuration](docs/CONFIGURATION.md) and [`.env.example`](.env.example) — supported settings and safe changes.
- [Whole-file exchange](docs/WHOLE-FILE-EXCHANGE.md) and [Direct SSH](docs/DIRECT-SSH-CONNECTOR.md) — detailed remote file/Job operation.
- [Target connection recovery](docs/TARGET-DISCONNECT-RECOVERY.md) — safe WordPress OAuth recovery.
- [Project documentation map](docs/PROJECT-MAP.md) and [Master Specification](docs/MASTER-SPEC.md) — authoritative engineering references and durable product boundaries.
- [Development](docs/DEVELOPMENT.md) — source/CLI installation and contributor tests.

## License

Released under the [MIT License](LICENSE).
