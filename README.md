# MCP Gateway

MCP Gateway is a self-hosted PHP application that connects an authenticated MCP client to the specific servers and WordPress sites you authorize. Add each connection as a **Target**, control who can use it, and manage access from one web Admin panel.

**v2.3.0:** WordPress via WP AI Bridge, Direct SSH, Target Groups, user/Target permissions and OAuth for supported clients (including ChatGPT). This version adds Owner-adjustable SSH command and retained Job limits, authorized browser file selection, agentless systemd SSH Jobs on supported hosts and removes obsolete Agent-specific UI. **Install or update only from a matching official [GitHub Release](https://github.com/AChWorks/mcp-gateway/releases)**; source code and draft release branches are not installation packages.

## What you can do

- Register WordPress and SSH Targets and review their connection status.
- Discover and run WordPress Abilities through the existing WordPress principal and its WP AI Bridge permissions.
- Run authorized non-interactive SSH commands and bounded SFTP operations against verified SSH hosts. In v2.3.0, the Owner can adjust the bounded synchronous command limits and use lightweight retained systemd SSH Jobs on supported hosts.
- In v2.3.0, an authorized user can select a real local file in the Target Admin page and upload/download verified binary bytes when the optional SSH transfer mode is explicitly enabled by the operator.
- Assign users, Target Groups and permission scopes; review Activity and AI client authorizations.
- Install or update from the named GitHub Release ZIPs without requiring Git or Composer on the host.

**Limits to know:** SSH runs with the privileges of its configured remote OS account; Gateway permissions do not turn root into a sandbox. Optional whole-file SSH HTTP upload/download is **disabled by default** (`SSH_FILE_TRANSFER_ENABLED=false`) and is not a guarantee of ChatGPT attachment upload/download support. Other AI clients need a compatible, configured client profile; support for every MCP extension is not implied.

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

## Install (recommended: web installer)

1. Create an HTTPS domain or subdomain and a **dedicated empty** MariaDB/MySQL database and user.
2. Download `mcp-gateway-v2.2.1.zip` (the **deployment ZIP**, not GitHub's generic source archive) from the [v2.2.1 Release](https://github.com/AChWorks/mcp-gateway/releases/tag/v2.2.1). Verify the matching `.sha256`.
3. Extract it into a private application directory. Point the domain's **document root to its `public/` subdirectory**, for example `/www/wwwroot/mcp-gateway/public`. Never expose the application root.
4. Make `storage/` and `bootstrap/cache/` writable by the PHP worker. Enable HTTPS before entering credentials; do not use `chmod -R 777`.
5. Open `https://gateway.example.com/install`, supply the canonical URL, database settings and first administrator, then choose **Install MCP Gateway**.
6. After success, sign in at `/admin/login`. Do not remove the private installed marker to rerun installation.

A working aaPanel/OpenLiteSpeed setup needs PHP 8.4, rewrites/.htaccess and the correct `public/` running directory. Shared hosting must allow a separate private application root and `public/` web root. For Git + Composer + Artisan installations and hosting-specific procedures, use [Deployment](docs/DEPLOYMENT.md).

## Verify the installation

Open `/up` and `/admin/login` on your HTTPS domain. The following public discovery routes should be reachable:

```bash
curl --fail https://gateway.example.com/.well-known/oauth-protected-resource/mcp
curl --fail https://gateway.example.com/.well-known/oauth-authorization-server
curl --fail https://gateway.example.com/oauth/client.json
curl --fail https://gateway.example.com/oauth/jwks.json
```

For CLI-managed installs, run `php artisan gateway:check` as the application account. Configure **one host Cron task every minute** to invoke Laravel `schedule:run` with the PHP 8.4 CLI **as the site worker** (never root Artisan); this maintains idle WordPress credentials and Activity retention. Verify that the aaPanel task log shows a real dispatch, not only `schedule:list`. See [Deployment](docs/DEPLOYMENT.md#activity-retention-scheduling) for examples. Keep credentials and tokens out of screenshots and logs.

## Connect WordPress

1. Install a compatible **WP AI Bridge** on WordPress and configure its access permissions.
2. In Gateway, open **Connection** (`/admin/connection`) and copy its exact `/oauth/client.json` metadata URL. In WordPress, open **WP AI Bridge → OAuth Clients** and approve this **client metadata URL** (not its JWKS or callback URL).
3. In Gateway, choose **Targets → Add Target → WordPress (WP AI Bridge)**. Enter a unique `target_id` (lowercase letters, digits and hyphens, maximum 64), display name and canonical HTTPS WordPress URL. Verify and add it.
4. On Target details, choose **Authorize WordPress** and complete OAuth consent for the intended WordPress user. Confirm **Connected**, then assign permitted Gateway users or groups.
5. Use the `wordpress-abilities-read` tool to inspect live Ability names/schemas before calling `wordpress-ability-execute`. New WordPress Abilities do not require adding individual Gateway tool names.

A successful WordPress metadata check does **not** prove that an outstanding credential revocation finished. If Disconnect, refresh or consent is uncertain, follow the [Target recovery guide](docs/TARGET-TRANSITION-RUNBOOK.md); do not erase a pending revocation or repeatedly rotate credentials.

## Connect Direct SSH

1. Select **Targets → Add Target → Direct SSH**, enter a unique `target_id`, the SSH host, port and remote account, and choose supported password or private-key authentication.
2. Verify and trust the server's **SSH host-key fingerprint** using an independent trusted source before connecting; investigate unexpected key changes rather than bypassing host-key verification.
3. Assign the specific users and SSH permissions they need. Test with a read-only command or SFTP `stat` before allowing mutations.

SSH command execution is non-interactive and is constrained by Gateway access checks **and** the remote account's real OS privileges. SFTP is bounded; large binary file exchange requires the separately supported and explicitly enabled transfer path. In v2.3.0, the Owner can open **Admin → Operational Settings** to adjust the maximum command timeout (15–30 seconds; default ceiling 15) and command length (8–64 KiB; default 8 KiB), effective for new commands without restarting PHP. A longer-lived Job is not a longer synchronous HTTP request. The same Owner screen provides separate **Detached SSH Jobs** limits: concurrently admitted Jobs per user (default 2, adjustable 1–1024), maximum duration per Job (default 300 seconds, adjustable up to seven days), result retention (default 24 hours), and safe crash/reconciliation grace periods. There is no cumulative historical Job-count ceiling. Expiration of admission never reruns a script or proves a remote process stopped.

For actual file selection in v2.3.0, visit **Targets → [Direct SSH Target] → SSH file upload and download**, choose a file, enter its absolute remote destination and an already provisioned private `0700` staging directory, and submit. For a download, enter the remote absolute path and save the returned attachment; verify the supplied SHA-256 and byte length. The site operator must independently approve and enable `SSH_FILE_TRANSFER_ENABLED=true` only after validating PHP/proxy upload size, temporary storage and timeouts. The option is disabled by default. A ChatGPT chat attachment is **not automatically available** to these forms or MCP tools. See [whole-file exchange](docs/WHOLE-FILE-EXCHANGE.md).

For retained Jobs, use `ssh-job-start` with a caller-generated UUID `request_id` and a 16 KiB or smaller script. Save its returned `job_id`; poll `ssh-job-status`, read bounded stdout/stderr ranges with `ssh-job-output`, and use `ssh-job-cancel` only when appropriate. A remote host must support `systemd-run` with a persistent user manager (`linger` configured by its administrator), or a system manager for a deliberately configured root SSH account. Unsupported hosts fail closed. Reuse the same request UUID on an uncertain start; **never blindly send a different start request**. The command privileges remain those of the registered remote OS account. See [Direct SSH operator details](docs/DIRECT-SSH-CONNECTOR.md).

## Connect ChatGPT

1. Open Gateway **Connection** (`/admin/connection`) and copy the canonical MCP URL, usually `https://gateway.example.com/mcp`.
2. In ChatGPT, configure the supported custom MCP App/client profile with that URL and complete Gateway OAuth sign-in and consent for an authorized Gateway user.
3. Start with `targets-list`, select the exact `target_id` and inspect `target-context`. Only then call the authorized WordPress or SSH tools.

Use **AI clients** (`/admin/oauth-clients`) to manage application profiles and granted authorizations. Client approval is not the same as Target access. If an older ChatGPT conversation still exposes obsolete `sites-list` tools after an upgrade, refresh/reconnect the App and start a new conversation; do not weaken OAuth or add insecure aliases.

## Available MCP tools

The v2.2.1 MCP catalog provided nine tools. The **v2.3.0 catalog** registers 13, including four agentless SSH Job tools, shown below. These tools require an installed, migrated v2.3.0 release. Available operations remain constrained by the authenticated client, Gateway user and exact Target access permissions. SSH Jobs are available only after that version is installed and migrated on a supported host.

| Tool | Purpose |
| --- | --- |
| `targets-list` | List authorized Targets without credentials. |
| `target-context` | Read non-secret context for one explicitly authorized `target_id`. |
| `wordpress-abilities-read` | Inspect WordPress Ability metadata on one authorized WordPress Target. |
| `wordpress-ability-execute` | Execute a schema-valid Ability for an explicitly authorized WordPress Target, subject to effect-class and downstream permissions. |
| `ssh-command-run` | Run a bounded non-interactive command on an explicitly authorized, host-key-verified Direct SSH Target, within its OS privileges and Gateway permission policy. |
| `ssh-file-stat` | Inspect metadata for one authorized SSH Target SFTP path. |
| `ssh-file-list` | List a bounded directory on an authorized SSH Target using SFTP. |
| `ssh-file-read` | Read a bounded byte range from an authorized SSH Target SFTP file. |
| `ssh-file-write` | Create or conditionally overwrite a bounded SSH Target SFTP file, subject to explicit write authorization. |
| `ssh-job-start` | start a bounded persistent systemd SSH script with idempotent UUID request identity. |
| `ssh-job-status` | reconcile the exact retained Job state and real exit reason/code, when known. |
| `ssh-job-output` | read Base64 stdout/stderr windows without rerunning the remote script. |
| `ssh-job-cancel` | request a verified, best-effort stop of the exact Job. |

New WordPress plugin Abilities are discovered through the existing WordPress tools; the Gateway does not need a separate public tool per Ability. All operations are restricted by the authenticated user, client, Target and downstream WordPress/SSH permissions.

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

## Update safely

**For an existing deployment-ZIP installation**, use **`mcp-gateway-update-v2.2.1.zip`** from the [same v2.2.1 Release](https://github.com/AChWorks/mcp-gateway/releases/tag/v2.2.1), never the fresh-install ZIP, an old release's update ZIP or the generic GitHub source archive.

1. Confirm the installed version and review the [release notes](RELEASE_NOTES.md). Take and **test-restore a consistent database backup**; also preserve `.env`, `APP_KEY`, both OAuth/signing key pairs, current code and private state. An updater code snapshot is **not** a database backup.
2. Upload and extract the named update ZIP into the **existing application root** (where `artisan`, `.env`, `public/` and `storage/` reside). This stages a temporary `update/` and `public/update/`; it does not immediately replace the app.
3. Open `https://gateway.example.com/update/`, sign in as an existing administrator, verify the source/target versions and package checks, and select **Update MCP Gateway**. Keep the browser open through completion.
4. Verify the newly installed version, `/up`, Admin login, OAuth discovery, WordPress/SSH Targets and client authorizations. A successful update removes the temporary updater entry.

**Do not blindly retry failed updates.** If a migration may have started, code-only rollback is not a database rollback. Keep backup, private recovery state and logs, then follow the [deployment/recovery procedures](docs/DEPLOYMENT.md) before any further action. The private Owner-local recovery CLI is not an unauthenticated web recovery endpoint.

**Compatibility:** v1 Site-era → v2 Target-era upgrades are breaking and require the [Target transition runbook](docs/TARGET-TRANSITION-RUNBOOK.md). The v2.0.3 → v2.1.2 path added four database migrations; v2.2.0 added guarded WordPress disconnect-recovery migration handling. v2.2.1 does not introduce another migration on top of v2.2.0. The v2.3.0 line adds four migrations: SSH command operational-limit columns, the durable SSH Job journal, configurable Job lifecycle/recovery policy and original-host evidence, and immutable per-Job admission timing snapshots; back up and test restoration of the database before any eventual upgrade. The Job journal migration refuses unsafe rollback while any Job record remains. Historical prerelease installs or skipped versions require exact-release compatibility verification. Source/Composer-managed installations must use the [CLI deployment procedure](docs/DEPLOYMENT.md), not the browser ZIP updater.

## Troubleshooting

- **Cannot install:** check PHP/extensions, TLS, correct `public/` web root, writable runtime paths and an empty dedicated database. Never relax private file permissions globally.
- **WordPress `invalid_client`:** verify that WordPress approved Gateway's exact client metadata URL, then check the real Target status and pending OAuth operation before reconnecting. Do not regenerate Gateway keys to fix this error.
- **AI client disconnected:** verify Gateway health and OAuth discovery first; inspect and reconnect the correct client authorization when appropriate, without resetting healthy WordPress credentials.
- **Updater stalled/failed:** preserve backup and recovery evidence. Do not assume Laravel CLI readiness proves actual HTTP availability or that migrations can be reversed.

Use [Deployment](docs/DEPLOYMENT.md) and [Configuration](docs/CONFIGURATION.md) for detailed diagnostics, session lifetime (default `SESSION_LIFETIME=120` minutes of inactivity, `SESSION_EXPIRE_ON_CLOSE=false`), PHP-worker permissions and safe recovery. Do not publish passwords, tokens, `.env` or private keys in issue reports.

## Documentation

- [Releases](https://github.com/AChWorks/mcp-gateway/releases) and [release notes](RELEASE_NOTES.md) — shipped versions and compatibility.
- [Deployment, upgrade and recovery](docs/DEPLOYMENT.md) — detailed host setup, backups and troubleshooting.
- [Configuration](docs/CONFIGURATION.md) — settings, timeouts and safe live changes.
- [Target transition runbook](docs/TARGET-TRANSITION-RUNBOOK.md) — breaking v1→v2 upgrades and recovery boundaries.
- [Whole-file exchange](docs/WHOLE-FILE-EXCHANGE.md) — optional SSH binary transfer requirements and limits.
- [Direct SSH connector and Jobs](docs/DIRECT-SSH-CONNECTOR.md) — SSH Job prerequisites, bounded results and safe recovery.
- [Development](docs/DEVELOPMENT.md) — contributor setup and validation.

## License

MCP Gateway is available under the [MIT License](LICENSE).
