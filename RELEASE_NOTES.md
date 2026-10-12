# MCP Gateway v2.1.2

**Planned stable release notes — not publicly published.** Candidate builds now carry distinct
SemVer prerelease identities (starting at **2.1.2-rc.1**). The current
**2.1.2-rc.3** candidate supersedes the previously distributed rc.1 and
rc.2 test artifacts; the eventual public stable release will use **2.1.2** only after
separate Owner authorization. Earlier
**2.1.0** and **2.1.1** test candidates were installed by operators, but neither
number was published as a stable Release. The updater must continue to reject
same-version and downgrade attempts. These notes describe candidate functionality; merging source or passing CI does not mean a public release, installed host or production has been changed.

## Changes since v2.0.3

- **Existing WordPress behavior retained:** dynamic native WordPress Abilities, fail-closed classifications, Target-bound OAuth permissions and long-idle offline-credential recovery. These include the v2.0.3 maintenance fixes plus unreleased HTTP deadline/DNS safety refinements.
- **Direct SSH Targets:** host-key pinning, bounded command execution, SFTP stat/list/range/write, and reusable bounded internal private streams. No implicit permission grants, private-network exception or unrestricted credential bypass.
- **Optional complete SSH binary upload/download:** authenticated per-Target file-transfer discovery, fixed-size/timeout/concurrency budgets, integrity-checked and guarded atomic publication, separate client-side whole-response digest verification. Feature remains **OFF by default** and must be deliberately enabled on an approved host. The 16 KiB inline call budget and 64 MiB/40-second optional SSH upper bound are not global client/WordPress/Agent file or job limits.
- **Owner operational controls:** one typed registry for bounded WordPress responses, HTTP connect/request deadlines and optional SSH transfer budgets; retains immutable authorization and network safety rules.
- **Owner Admin usability:** one connector-first Target enrollment form, independent password-only or private-key-only SSH login fields, explicit separately verified server public host-key/fingerprint guidance, consistent control styling, and grouped Operational Settings with per-field defaults and optional reset. The authorization, encrypted SSH credential format and settings audit semantics are unchanged. Admin CSS uses a content fingerprint to avoid stale styling after valid upgrades. The updater deliberately rejects a package whose VERSION is not newer than the installed VERSION.
- **Edit existing connector settings safely:** Owner password-gated, optimistic-revision-aware SSH host/port/user/trusted host-key and encrypted password/private-key replacement, preserving Target ID, user/Target Group membership and denial rules. Password/key may be left blank when retaining the same method. After any SSH configuration/secret change, clear old verification and require verified host key/login before SSH commands or SFTP are used. The private login key is never echoed or restored into the browser. WordPress HTTPS origin can change only after confirmed OAuth disconnect/revocation/recovery and renewed safe metadata discovery; tokens are never silently moved between sites and the Target must authorize again. No new schema migration.
- **Live connector permissions and readable UI:** Direct SSH is active (not a reserved/future permission). Add User defaults all remote command/SFTP controls to **DENY** but can apply an explicitly confirmed Owner grant for Selected Target scope during initial creation; older clients remain default-denied. Edit User preserves confirmed grants, requires confirmation for changes and revokes SSH when widening to All scope. User → Target permissions expose live SSH deny-only switches and confirmation for Target scope changes; Add/Edit Target Groups apply deny-only restrictions and never create grants. Clear checked=DENY help, role ceilings, preserved historical denials and paused Agent markers remain intact.
- **Operational readiness:** candidate acceptance covers the actual published v2.0.3 ZIP as an upgrade baseline, package verification, isolated installed WordPress + SSH acceptance, and a release workflow that requires explicit manual publication against an immutable reviewed main SHA.

## Safe upgrade and release gate

Use the **matching update ZIP**, not the fresh-install ZIP, over an existing v2.0.3 Target-era installation **or a previously installed 2.1.0/2.1.1 test candidate**.
Prereleases advance monotonically: `2.1.1 -> 2.1.2-rc.1 -> 2.1.2-rc.2 -> 2.1.2`.
Each `-rc.N` package is a separate test artifact and is never itself a public Release. The update must have a strictly newer VERSION; do not edit installed VERSION or suppress same-version/downgrade rejection. Verify its matching SHA-256 first, preserve a consistent independently restorable database backup plus protected .env/APP_KEY/OAuth and Bridge signing keys, then run the authenticated browser updater and verify Target/client/grant persistence. Never replay an ambiguous migration; preserve rollback or roll-forward evidence. Additional migrations require restoration rehearsals, not assumed DDL reversibility. Earlier v1.x Site-era baselines retain their explicit consent/reset requirements.

Publication is **manual only** after explicit Owner approval of the exact integrated commit and version; a PR merge or VERSION edit does not itself publish. Existing published v2.0.3 remains the default operator Release until that event. Real deployment, upstream production-host limits, native ChatGPT attachment receipt, WordPress full-object raw binary, durable SSH resume and Agent integration remain outside candidate claims.

---

# MCP Gateway v2.0.3

**Corrective maintenance release from v2.0.2, not the unreleased main feature line.** This patch addresses observed WordPress authorization reliability, fail-closed Ability execution and browser update diagnostics. It introduces **no Direct SSH/SFTP runtime, no new Owner operations-setting UI, no client file-transfer data plane, no public MCP tool name, no new database migration and no intentional credential, Target, client grant or role reset.** Publishing a GitHub Release never installs it on a server.

## Fixes since v2.0.2

- **WordPress remains logically authorized across long idle/Stale intervals.** Avoid unnecessary proactive refresh-token rotations every half-hour when the provider supplies a longer-lived offline grant. Renew expired short-lived access tokens on the next authorized operation, and perform scheduled offline refresh when truly due. Old Stale health observations are not proof of revocation. A running **Gateway host scheduler** is needed to maintain authorization beyond a finite offline-grant lifetime; the installer cannot create an indefinite token.
- **Lost or uncertain WordPress refresh outcome:** use provider-supported one-shot, bounded, exact-client/Target/resource/scope recovery; distinguish an initial pre-consumption `invalid_client` dependency outage from confirmed `invalid_grant` or a potentially committed successor. Do not blindly repeat unknown mutating operations or erase encrypted offline credentials because a transport failed. An already unrecoverable pre-upgrade refresh cannot necessarily be repaired by installing the patch; reconnect only when truly necessary.
- **Fail-closed WordPress Ability catalog retrieval:** transport, downstream authorization and protocol errors must propagate, never silently transform into an `Unclassified` execution permission. Successfully returned incomplete Ability annotations still follow existing explicit `Unclassified` grants.
- **Browser updater reliability guidance:** clarify PHP worker ownership when temporary staging cannot be written, and distinguish queued final checks from checks actually running. Display an explicit one-time manual Continue fallback when automatic stage→postflight continuation has not begun. Retain secure browser-bound expiry, migration-recovery and backup-integrity gates. The existing v2.0.2 post-cleanup `/update` and `/update/` no-staging **410** guard is preserved without modifying hosting/Cloudflare rules.
- **Release notes:** one correct GitHub release title, with only this version's change section and no previous-version duplicate headline.

## Updating an existing v2.0.2 Gateway

1. Obtain `mcp-gateway-update-v2.0.3.zip` and the matching `.sha256` from this release; verify the downloaded archive checksum. Do **not** unpack the fresh-install `mcp-gateway-v2.0.3.zip` over a running application.
2. Preserve a **consistent independently restorable database backup** and secure copies of `.env`, the Laravel encryption key and both Gateway signing keypairs. A code backup is **not** a database backup. Protect the live installation from concurrent admin changes during the update window.
3. Upload/extract the **update ZIP** in the existing Gateway application root so that the temporary `update/` and `public/update/` become available. Open the secured HTTPS `/update/` path, authenticate using the existing administrator session, and confirm **Installed: 2.0.2 → Target: 2.0.3** before starting.
4. Run Start **once**. Let the browser continue to the authenticated postflight automatically; if still showing a visible Continue button before a request starts, use it **once**. If the browser or request fails, inspect the scoped updater status/resume state; never restart a possibly-running migration or delete evidence blindly.
5. After explicit success, verify actual installed `2.0.3`, `/up`/OAuth discovery, a permitted WordPress read with an expired short-lived access token, installed host cron for idle credential maintenance, Target/client grants and updater cleanup. Preserve backups until the operator validates service. Do not declare a production issue resolved solely from source/CI.

Earlier Target-era v2.0.0/v2.0.1 installs must retain their registered Targets, credentials and client permissions across this patch. Upgrading directly from a historical Site-era v1.x baseline remains the **breaking Target transition**, requiring exact-version operator consent and a separately tested full database restore per the Target-transition runbook; this patch does not remove that requirement. Database DDL cannot be assumed reversible after an unknown interrupted migration.

## Validation boundary

This version is scoped to fixes already integrated/reviewed on the main development line and selectively backported for a maintenance release ([PR #159](https://github.com/AChWorks/mcp-gateway/pull/159)). Exact patch candidate CI, MariaDB historical upgrade tests, independent backport review and checksum-verified release assets are required before publication. WordPress long-idle installed-host acceptance [#97](https://github.com/AChWorks/mcp-gateway/issues/97), the nonreproduced historical browser updater host delay [#135](https://github.com/AChWorks/mcp-gateway/issues/135), and future mixed SSH release acceptance [#112](https://github.com/AChWorks/mcp-gateway/issues/112) remain separately tracked. No production deployment is authorized by publishing this release.

---

# MCP Gateway v2.0.2

**Backward-compatible updater reliability maintenance release.** This patch incorporates the independently reviewed browser-updater corrections from [PR #137](https://github.com/AChWorks/mcp-gateway/pull/137) for existing Target-era installations. It does not introduce a new connector runtime, an intentional connection reset, or a new application database migration. Publishing the Release does **not** install it on an operator's server.

## Changes since v2.0.1

- **Browser update continuity:** stage-to-postflight automatic continuation, authenticated bounded browser-session renewal, and safe single-operation behavior for concurrent, interrupted, or repeated requests. The operator should not need to repeatedly reload the page to trigger normal completion.
- **Actionable progress and recovery:** distinguish running, recoverable, expired, interrupted, and postflight-unverified states; retain usable instructions and a same-browser status action without JavaScript. Do not mislabel a maintenance window as an authorization failure or silently repeat migrations after an ambiguous result.
- **Postflight honesty:** persist successful migration/check/maintenance exit before noncritical cleanup. Report cleanup warnings without falsely reporting a migration failure, and handle combined completion-state persistence/deletion failures without unsafe retries.
- **OpenLiteSpeed URL cleanup:** a conditional, package-owned 410 guard prevents a /update ↔ /update/ trailing-slash redirect loop after temporary updater staging is removed. No production hosting/Cloudflare rewrite settings are changed by publishing this release.

## Updating an installed v2.0.1 Gateway

1. Download **`mcp-gateway-update-v2.0.2.zip`** and **`mcp-gateway-update-v2.0.2.zip.sha256`** from this version's GitHub Release, and verify the ZIP checksum. Do **not** use the fresh-install `mcp-gateway-v2.0.2.zip` on an existing installation.
2. Before changing live files, preserve a **consistent independently restorable database backup** and secure copies of the matching `.env`, `APP_KEY`, Gateway OAuth and Bridge signing keys. Confirm sufficient free space and a recoverable rollback/roll-forward plan. Updater code backups **do not** include the database.
3. Upload and extract the browser-update ZIP in the existing application root (containing `.env`, `artisan`, `public/`, and `storage/`). This prepares temporary updater files; it does not replace live managed files until the authorized browser Start action.
4. Open `https://<your-gateway>/update/` in the same browser, authenticate as an authorized administrator, verify **Installed 2.0.1 → Target 2.0.2**, and initiate the update once. Allow the automatic postflight transition; use the presented status/resume instructions if the browser loses the response. Do not repeatedly click Start, re-extract, delete state, or retry migration after an ambiguous postflight.
5. Confirm explicit success and version `2.0.2`, then validate `/up`, OAuth metadata, WordPress Targets and encrypted credentials, Users/Target Groups/denials, ChatGPT grants and capabilities, and the absence of redirect loops on removed temporary update URLs. Preserve the independent backup until acceptance is complete.

Earlier released baselines retain their original compatibility requirements. **v1.2.1 → v2.0.2 is a breaking Site → Target transition** requiring exact-version reset consent, independent database backup, and renewed affected connector/client authorization; consult [Target transition runbook](docs/TARGET-TRANSITION-RUNBOOK.md). v2.0.0/v2.0.1 Target-era patch upgrades must preserve existing connections, permissions, and authorizations without intentional resets.

## Verification and remaining limits

- [Issue #138](https://github.com/AChWorks/mcp-gateway/issues/138) owns the new-version release gate, including exact-candidate PHP 8.4 / MariaDB 10.11 released-baseline upgrade and backup integrity evidence. A Release/CI job alone does not prove installation on the operator's server.
- [Issue #135](https://github.com/AChWorks/mcp-gateway/issues/135) remains **open** for real origin-vs-Cloudflare/aaPanel timing evidence, the historical approximately two-minute handoff, and production operator acceptance. Repository fixes and a successful release do not establish its production root cause.
- Dashboard monitoring [#136](https://github.com/AChWorks/mcp-gateway/issues/136) is deferred; AI Server Agent Target [#111](https://github.com/AChWorks/mcp-gateway/issues/111) remains paused.

---

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
