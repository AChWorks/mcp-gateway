# MCP Gateway v2.0.1

**Backward-compatible maintenance update from v2.0.0.** This release delivers the previously reviewed Target Admin / AI client UX and documentation improvements without adding a connector runtime, changing the public MCP tool contract, adding database migrations or intentionally resetting existing WordPress Targets, Target Groups, credentials, users, permissions, or ChatGPT OAuth grants. Publishing these packages does **not** install anything on an operator's server.

## Changes since v2.0.0

- **AI clients:** separate the client-profile and authorization panels; align the grant-revocation password field and action button in a responsive, page-scoped layout. Keep the existing password confirmation, CSRF, and revocation semantics.
- **Target Admin:** use **Add Target** in Dashboard and inventory; offer an explicit **Connector type** on creation. Only **WordPress (WP AI Bridge)** is available in this release. Keep WordPress URL, OAuth, and recovery language on the WordPress-specific steps; do not imply Direct SSH or AI Server Agent can be enrolled.
- **Access-management UX:** organize User, Target Group and per-Target denial controls by Gateway administration, shared Target actions, WordPress abilities, and clearly marked future SSH / paused Agent families. Preserve historical connector-specific denials when ordinary forms are edited, without turning denials into grants or changing the server authorization evaluator.
- **Documentation:** refresh the README, client-profile guidance, and Target-transition/connector UX contracts to reflect the shipped Target-era MCP tools and operator workflows. Retire obsolete Site-era flash messaging.

## Upgrade instructions and safety

For an **existing v2.0.0 installation**, use the **browser update asset**, `mcp-gateway-update-v2.0.1.zip`, **not** the fresh-install deployment ZIP. Verify its companion `.sha256`, preserve a consistent recoverable database backup and the matching `.env` / `APP_KEY` / private signing keys, then upload and extract the update ZIP into the existing application root (`.env`, `artisan`, `public/`, `storage/`). Open `https://<your-gateway>/update/`, sign in as an authorized administrator, confirm **Installed: 2.0.0 → Target: 2.0.1**, and run the guarded browser update.

The v2.0.0 → v2.0.1 path is **not** a new Site → Target migration: existing Target registration, WordPress/ChatGPT authorization and User/Target Group restrictions are expected to remain intact. Do **not** voluntarily revoke/reconnect healthy clients or clear credential/authorization tables just for this UI update. After updating, verify the installed `VERSION`, Gateway `/up`, OAuth discovery, Target connection state, AI clients grant state and permission forms. A published Release or a green CI job alone is not proof of production delivery.

**For pre-v2 Site-era installations**, the historical breaking Target migration and explicit data-reset/database-backup consent still apply. Follow the [Target transition runbook](docs/TARGET-TRANSITION-RUNBOOK.md); the updater's private code-only backup does not replace an independently restorable database backup. Stop rather than blindly retrying if staging/maintenance/upgrade state is uncertain.

## Acceptance evidence and boundaries

- [PR #132](https://github.com/AChWorks/mcp-gateway/pull/132) — AI client layout and Target-era documentation consistency, integrated after successful CI and MariaDB checks.
- [PR #133](https://github.com/AChWorks/mcp-gateway/pull/133) — Target-neutral/connector-aware permission presentation, independent author-separated **COMPLETE / APPROVE** with no BLOCKER/REQUIRED findings, exact-candidate CI and MariaDB Concurrency **SUCCESS**.
- The merged v2.0.0+ UX commits passed post-merge CI/MariaDB. The v2.0.1 release workflow must additionally verify the exact released v2.0.0 → v2.0.1 browser-update package, including its backup integrity and state-preservation checks, before publication.
- Real WordPress read and draft write/delete/readback were previously verified through ChatGPT → Gateway v2.0.0 → WP AI Bridge; no claim is made of live v2.0.1 deployment, all-connector parity, real SSH or Agent support. The owner performs production visual and continuity acceptance only after installation.

---

# MCP Gateway v2.0.0

**Breaking Target major release.** This version replaces the Site model and is not backward-compatible with existing Site-era API paths or saved connections. Publication provides verified downloadable packages; it does **not** deploy to a server, authorize a production migration or make a database backup for the operator. A controlled upgrade requires the operator's separately restorable database backup and fresh WordPress/ChatGPT authorization.

## Major release contents

- Generic immutable Target domain, ACL/Target Groups and scoped Activity, with real Target Admin inventory, registration, detail, display-name editing, checked metadata diagnostics and guarded removal.
- WordPress Target OAuth with target-bound encrypted PKCE credentials, signed client identity, confirmed remote revocation, bounded rotating refresh-token recovery and scheduled idle renewal.
- Owner-only, password-confirmed and audited **manual local recovery** from an unresolved WordPress rotating-refresh outcome after explicit WordPress-side client revocation attestation; no silent credential erasure or claim of automatically verified remote revocation.
- Authorized exact-Target MCP inventory/context plus WordPress Ability catalog and safety-class-gated execute; existing client-neutral ChatGPT OAuth remains supported.
- Intentional retirement of old Site-only routes and bulk-check pages; Agent and Direct SSH runtime remain **unimplemented** and are not advertised.

## Manual WordPress refresh recovery warning

If a rotating WordPress refresh becomes ambiguous, normal Target disconnect/reconnect is intentionally blocked. A WordPress administrator must first **remove and save** this Gateway's exact client metadata URL from WP AI Bridge's **Approved OAuth Clients**; this invalidates **all** non-ChatGPT additional OAuth clients on that WordPress site, not just the selected Gateway Target. Only after explicit approval and verification of this collateral effect may a Gateway Owner acknowledge that external revocation, confirm the exact Target ID and password, and clear the single local Target credential. Audit describes an **operator attestation**, never independent proof of remote revocation. See the runbook; the Gateway never automatically makes this remote approval-list change.

## Browser updater v2.0 reset consent
    
When upgrading a legacy installation containing old WordPress Site/credentials, Target membership/groups/activity or Gateway OAuth grants, the browser updater displays the affected-state summary **before staging managed files**. It requires two affirmative, **package/version-bound** confirmations: intentional connection reset and independently verified restorable database backup. Previously configured `.env` migration acknowledgments cannot bypass the browser confirmations. The one-time acknowledgment stays in protected updater state and is supplied only to the matching migration step; it is not saved into `.env`. Missing/stale confirmation stops before maintenance or managed-file replacement. The updater's private code backup is **not** a database backup; unexpected partial DDL still requires recovery from the operator's independently restorable database copy.
    
## Mandatory operator warning

The upgrade from published v1.2.1 replaces the legacy Site schema, invalidates incompatible Gateway OAuth grants and token generations, and requires fresh WordPress and ChatGPT authorization. It **preserves local administrators/users/roles, security keys, global authorization denials and unrelated Gateway data**, not the old connector registrations or Site groups. A consistent **independently restorable database backup** and explicit operator reset+backup acknowledgment are required *before destructive DDL*. The browser updater's code backup **is not** a database backup. A partial MariaDB DDL failure requires restoring the independent database backup; never assume rollback or automatically retry.

## Validation and outstanding live acceptance

The release candidate in [PR #131](https://github.com/AChWorks/mcp-gateway/pull/131) passed four GitHub Actions checks: source quality (Pint, PHPStan and PHPUnit), MariaDB 10.11 concurrency and access control, pinned WP AI Bridge OAuth/MCP contracts, and actual released-baseline browser-update tests (including a seeded v1.2.1 Site/OAuth state reset and preservation check). The executable code received independent **HIGH_ASSURANCE APPROVE**, with no remaining BLOCKER or REQUIRED finding. The owner separately authorized the merge and public v2.0.0 Release.

**The real external WordPress ↔ Gateway ↔ ChatGPT end-to-end flow remains unverified at publication** and is an explicit operator acceptance step after obtaining the package: fresh WordPress OAuth consent, ChatGPT reauthorization, Target inventory, Ability discovery/read/authorized execution, disconnect and revocation. CI contract tests do not establish real-provider acceptance. Publishing this Release does not install it, access operator credentials, or authorize destructive changes on any server.

For upgrades, follow [the Target transition and recovery runbook](docs/TARGET-TRANSITION-RUNBOOK.md) and [Issue #107](https://github.com/AChWorks/mcp-gateway/issues/107); verify a consistent, independently restorable database backup before consenting to reset. Never assume automatic rollback after partial MariaDB DDL.

---

# MCP Gateway v1.2.1

This is a backward-compatible feature release built on the v1.1.10 browser-update baseline. v1.2.0 was used only as a pre-release validation candidate and was not published as a stable release.

## Highlights

- MariaDB 10.11 is now the primary database target while MySQL compatibility remains supported.
- Multi-administrator access control adds owner/admin/operator/viewer roles with site-scoped authorization.
- Site Groups add reusable group-scoped access and site membership management.
- Site Health stores bounded connection evidence and exposes explicit single-site diagnostics.
- Selected-site bulk health checks add bounded multi-target operations with durable per-target status and partial-failure handling.
- Fleet inventory and Activity hot paths are better bounded for larger site counts.
- OAuth refresh/recovery diagnostics and continuity behavior are more robust while remaining secret-safe.
- Repository and WP AI Bridge namespace references are normalized under AChWorks.
- The Admin UI now uses a shared visual foundation for selects, checkboxes, filters, tables, access controls, responsive states, and dark mode.
- Permission controls now show human-readable titles, Gateway-wide vs site-scoped level, and concise behavioral help derived from the authoritative permission model.

## Upgrade compatibility

The official browser updater remains the supported path for deployment-ZIP installations. Release validation covers both the historical v1.1.2 baseline and the current v1.1.10 production baseline before publication.

A pre-release v1.2.0 candidate may also be upgraded normally to v1.2.1 because the final candidate advances the installed version instead of relying on a same-version replacement.
