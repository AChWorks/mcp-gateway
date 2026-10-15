# MCP Gateway v2.3.0

**Stable v2.3.0 source promotion; publication and installation are separately verified.**
This version collects Issues #181 and #182, including Owner-configurable
retained SSH Job resource/lifecycle limits and high-assurance reconciliation.
The preceding versioned integration RC is `2.3.0-rc.4`, candidate HEAD
`be66ed37247928991d404b76c198610912b5e3c8`.
Author-separated independent review, integration, an official verified
[GitHub Release](https://github.com/AChWorks/mcp-gateway/releases)
and actual host installation are distinct verifiable steps; neither
source promotion nor an unverified archive establishes deployment.

## Direct SSH command tuning and retained Jobs

- The existing Owner-only Operational Settings module now controls the maximum
  synchronous SSH exec timeout (15–30 seconds, default 15) and maximum command
  UTF-8 bytes (8–64 KiB, default 8 KiB). Actual runtime, MCP schema and
  Owner settings validation share the same finite limits; no uncertain
  command is automatically retried.
- Add `ssh-job-start`, `ssh-job-status`, `ssh-job-output` and
  `ssh-job-cancel` for **systemd-capable** SSH Targets. Durable Target/user/OAuth
  client plus UUID request identity prevents blind launch replay; script and
  output bytes are kept only in verified-private remote storage. A job
  may outlive the PHP request. It is not an Agent deployment or queue worker.
  Unsupported hosts fail closed. An hourly scheduler performs conservative
  cleanup of terminal jobs; unknown executions require reconciliation.
- Recovery hardening after independent review: stale pre-dispatch `preparing`
  intents are fenced against a late PHP launch and safely abandoned; expired
  uncertain admission leases no longer permanently consume a user's Job
  capacity. Journal/identity remain durable without automatic re-execution.
  An exact-binding, local deployment-operator attestation command handles
  orphaned/rotated/revoked SSH Job cleanup after **independent original-host
  verification**; operator retirement never claims a confirmed remote exit.
  New immutable non-secret original User/Target/SSH endpoint and pinned-key
  digest snapshots survive User/Target deletion so the operator can locate
  the ORIGINAL host without reusing a rotated Target. For earlier prerelease
  journals, binding-mismatched provenance is reported unknown, never guessed.
- The existing Owner-only, password-confirmed Operational Settings screen
  controls Job concurrency (default 2; 1–1024), maximum Job runtime
  (default 300 seconds; adjustable up to seven days), terminal-result retention
  (default 24 hours; 1–8760), pre-dispatch crash grace and post-runtime
  reconciliation grace. No cumulative historical Job-count cap is imposed.
- The SSH Job admission lease is renewed on the exact pre-dispatch CAS and
  immediately before systemd-run, covering bounded SSH/SFTP preparation,
  the actual possible dispatch delay, selected remote runtime and the
  **original** reconciliation grace. A timed-out staging request cannot
  start a Job after its admission slot may have been reassigned.
  Per-Job prelaunch/reconciliation snapshots survive later Owner changes;
  a fourth additive migration conservatively backfills older prerelease
  journal rows without discarding no-replay evidence.
- Real disposable OpenSSH/systemd validation and MariaDB same-user
  concurrency checks must be verified against the **current exact PR HEAD**
  at [PR #187 checks](https://github.com/AChWorks/mcp-gateway/pull/187/checks).
  Earlier green workflow runs (including #38791097112) are historical
  evidence, not approval of a changed candidate. Browser/operator-host
  acceptance, independent review and publication remain separate gates.

## SSH file exchange and connector presentation

- Authenticated Admin Target details gain a **browser file picker upload**
  and forced download form that reuse the existing SFTP/whole-file SHA-256
  transfer engine and registered Target permissions. They are disabled by
  default (`SSH_FILE_TRANSFER_ENABLED=false`); this is a browser fallback,
  **not native ChatGPT attachment handoff**. Exact binary SHA-256, create-only
  denial and explicit overwrite passed a real disposable OpenSSH fixture.
- Remove the never-implemented AI Server Agent product-specific permission
  selectors, paused UI and future-connector marketing. Preserve the reusable
  connector foundation, old dormant Target identity and persisted legacy
  denial rows; applied historical database migrations remain unmodified.

## Upgrade, security and rollback

- Four additive migrations: SSH command operational limits, the durable
  `ssh_command_jobs` journal, typed Owner Job policy/reconciliation evidence,
  and per-Job immutable admission timing snapshots for safe delayed launches.
  **A consistent, test-restored DB backup is required before any operator
  upgrade.** Journal rollback guards refuse dropping safety evidence while
  any Job record remains. Do not erase unknown Jobs to force rollback;
  browser-updater code backups do not reverse database changes.
- Refresh locked `symfony/http-foundation` from 8.1.6 to 8.1.9 to remediate
  advisory **CVE-2026-108082**, with Composer audit verified locally.
- No production Target, OS user, host setting, OAuth credential, or
  `SSH_FILE_TRANSFER_ENABLED` setting is modified by publishing source or a
  package. Changes to an actual installed host require a separate authorized
  deployment and compatibility/rollback checks.
- Exact-source CI of the final RC, fresh author-separated review,
  controlled integration, verified official Release assets and any
  installed-host upgrade are independent gates. Source promotion alone
  never proves public release or an installed operator version.

# MCP Gateway v2.2.1

**Stable v2.2.1 source promotion from independently approved `2.2.1-rc.10`.**
This promotion changes only VERSION and release documentation; no PHP
updater/recovery runtime, authorization, migration, or publication guard is
changed from the author-separated HIGH_ASSURANCE-approved RC.10 candidate.
The public release and four ZIP/checksum assets are published separately
by the explicit Owner-authorized GitHub workflow on the final integrated
main SHA. Publishing does not install or modify any operator host.

## Browser update and verified recovery (Issue #135)

The rc.4 source baseline remediated the four REQUIRED findings of the fresh
author-separated rc.3 review: malformed/absent continuation TTL now fails
closed in GET and Finish; the updater journals its migration/recovery boundary
using a same-directory atomic rename, file fsync and directory fsync before
crossing it; private Owner recovery validates the authenticated **previous**
runtime and original migration ledger without bootstrapping the staged
candidate; and the recovery page identifies automatic vs Owner-local origins,
with missing legacy provenance reported as unknown. Configuration reference,
administrator/user idle-session guidance and an automated .env documentation
coverage guard are included. All these changes require fresh exact-head
tests and a new independent review; no rc.3 approval carries forward.

- **Deterministic browser handoff:** authenticated Stage finishes with a
  `303 See Other` redirect to a fresh read-only `GET /update/`, allowing
  the browser to persist the renewed Secure/HttpOnly one-time cookie before
  Finish. JavaScript posts to the literal same-origin `/update/` path;
  it cannot use `form.action`, which is shadowed by the hidden input named
  `action`. Replayed old Stage POSTs redirect to state rather than
  misreporting broken administrator authentication.
- **Safe private Owner recovery:** the installation-bundled
  `php update/Recover.php --check|--recover` is CLI-only, never a public
  unauthenticated URL. It requires the real non-root site PHP worker, a
  verified original code snapshot, matching pre-upgrade migration ledger,
  completed file staging and an idle update lock. It keeps originals and
  an additional protected archive and refuses corrupted or missing backup,
  concurrent restore, partially replaced runtime and any possible
  database-migration/postflight uncertainty. Only Gateway-managed code
  may be restored; neither SQL nor Targets/OAuth/keypairs are reset.
- **Web-worker readiness and file permissions:** the temporary public
  Updater directory and entry are built with `0755`/`0644` permissions
  independent of packaging umask, without exposing private staging.
  Restored Laravel Artisan housekeeping executes as the unprivileged
  LSAPI PHP worker; non-secret generated manifests remain web-readable
  while private `config.php` and application secrets remain restricted.
  Restored HTTP health must pass real GET checks before completion is
  claimed. A failed readiness retains journal/backup evidence for
  operator reconciliation.

## Compatibility and delivery boundary

No *new* database schema migration is introduced by this correction over
`v2.2.0`. An installation still on `v2.1.2` will encounter the existing
`v2.2.0` migration when updated: retain a separately tested MariaDB
backup, original code backup, `.env`, APP_KEY and signing credentials.
No rollback of possibly started migrations is automated.

**Acceptance provenance — exact SHA and delivery environment:**
The rc.5 candidate at `9b9138792dc25ec0a91f1c051c5d5afce94ec985`
passed the official Quality, Update Package and Configuration Reference
workflows. The Update Package workflow downloaded and verified released
`v2.1.2` and `v2.2.0` ZIP checksums and exercised each upgrade and backup
integrity guard. A distinct disposable OpenLiteSpeed 1.8.4 + LSAPI PHP 8.4.15
+ MariaDB 12.3.3 + Chromium 149 installation ran **authenticated** Stage →
303 GET → Finish, Finish aborted before network send then resumed, concurrent
two-tab Finish, a rejected malformed continuation expiry, and a successful
server Finish whose HTTP response was lost to the browser. Actual code-only
Owner recovery from a failed candidate bootstrap was also proven under the
unprivileged PHP worker with HTTP readiness checks. See [Issue #135 browser
checkpoint](https://github.com/AChWorks/mcp-gateway/issues/135#issuecomment-6171029165).

The rc.5 browser test used a locally rebuilt, manifest-verified runtime
package with the **same source revision but different Composer-generated
vendor metadata** from the official GitHub artifact; it is not claimed to be
byte-identical to the official CI ZIP. No operator-host deployment, live
WordPress Target/OAuth action or production readiness is inferred.

The rc.6 candidate at `60635ebbad4bc7bb8efc6fe66f9d47b058fc0ff0`
aligned the manual stable Release workflow's nine historical baseline
upgrade/download/integrity loops with the Update Package CI, and introduced
a parity regression check. All rc.6 Quality, Update Package and Configuration
Reference workflows succeeded; a separate disposable OpenLiteSpeed/LSAPI/
Chromium test executed a real authenticated `v2.2.0 -> 2.2.1-rc.6`
browser upgrade, finishing with HTTP 200, retained secrets/host files and
normal ready endpoints. Earlier interruption/multi-tab/uncertain-response
and Owner-local recovery exercises used the **byte-identical rc.5 PHP
updater implementation**, not distinct rc.6 executions. See [rc.6 evidence](https://github.com/AChWorks/mcp-gateway/issues/135#issuecomment-6171573743).

The fresh independent rc.6 reviewer confirmed the application runtime and
these test boundaries but reported REQUIRED corrections to the stale
release-note candidate identity and unsafe success of pre-existing GitHub
Releases, plus missing pre-/post-publication immutable-state verification.

The **rc.7** candidate at `d9f57337a7f9490909d50ca2ba8069aa9259c393`
corrected the prerelease identity, rejected pre-existing Releases/Tags,
rechecked approved source before publication and verified published assets
and exact downloaded bytes after completion. Its three exact-head CI
workflows passed and 16 isolated publication-guard tests passed. A fresh
author-separated rc.7 review found its runtime and these controls sound
but identified one remaining REQUIRED publication TOCTOU defect: an
unrelated writer could create the requested tag between the final
absence check and `gh release create`, which ignores `--target` when a
matching tag already exists. Post-publication checks would detect but
not prevent an incorrectly targeted public Release.

The **rc.8** candidate closed the concurrent tag-*creation* boundary
by using GitHub's create-only Git Reference API to atomically reserve
the stable tag at the Owner-approved SHA after the final source
review/CI/baseline checks. A conflicting existing tag (HTTP 409/422) fails before publication,
including concurrent same-name tag creation; unknown request outcomes
fail closed without automatic retry. The resulting lightweight tag is
independently checked against the exact approved SHA before proceeding,
and `gh release create --verify-tag` refuses implicit tag creation. A
reserved tag with failed/partial Release publishing is intentionally
retained for manual reconciliation; it must not be moved/deleted or
silently replayed. All rc.7 post-publication checksum, tag-target and
downloaded-byte verification remains intact.

The rc.8 delta updated only the manual publication gate, hermetic
regressions, VERSION and documentation, without PHP runtime changes.
Its fresh author-separated HIGH_ASSURANCE review returned
**CHANGES_REQUIRED**: even after reserving a tag correctly, a repository
writer could force-move the unprotected tag before the public Release
consumed it. Checking again in the workflow would leave another
time-of-check/time-of-use gap.

The unique **rc.9** source candidate requires an **ACTIVE GitHub repository
tag Ruleset** applying to `refs/tags/v*`, with `Restrict updates` and
`Restrict deletions`, **no creation restriction**, and **no bypass actors**.
The publication guard reads the effective repository ruleset list and
full ruleset details, rejecting an absent/disabled/evaluate/mis-targeted
policy, missing restrictions, visible bypasses, uncertain API replies or
Owner-attestation identity drift before reservation or Release. GitHub
can hide bypass actors from the least-privilege workflow token, so the
Owner must first inspect the complete ruleset and attest its exact
GitHub-managed ID/updated_at (with the empty bypass list) at dispatch;
a subsequent ruleset revision invalidates that attestation. It rechecks
during the reservation and post-publication phases. The final tag
identity check now requires the exact lightweight commit ref written by
the create-only Git Reference API (not an annotated replacement that
peels to the same commit). Existing no-retry, partial-tag preservation,
and four-asset byte verification remain intact.

The **rc.10** source candidate simplifies the RC.9 policy check without
removing the GitHub-enforced tag immutability requirement: the Owner sets
and verifies an active `refs/tags/v*` no-bypass update/deletion restriction
**once**, and the workflow reads the current effective rule directly.
There are no per-release ruleset ID, timestamp or bypass-checkbox inputs;
the Owner only supplies the exact approved commit SHA and stable version.
Because GitHub withholds bypass details from read-only workflow tokens,
a deliberate administrator edit to the Ruleset is treated as a
repository-governance change instead of requiring an administrator
credential or repeated manual attestation on each release. Visible
nonempty bypasses, absent/inactive protection or GitHub API failure
remain fail-closed. No updater/recovery PHP runtime changed in rc.10.
The established atomic reservation, immutable lightweight tag identity,
partial-publication safety and four-asset downloaded-byte verification
are preserved.

**Live stable-tag prerequisite satisfied:** repository Ruleset
[#25136025](https://github.com/AChWorks/mcp-gateway/rules/25136025)
was independently verified ACTIVE on `refs/tags/v*`, disallowing
tag updates/deletions while allowing creation, with an empty bypass list.
The precise RC.10 implementation passed live read-only Ruleset verification.
An author-separated HIGH_ASSURANCE review returned COMPLETE / APPROVE for
RC.10 HEAD `d5aa86af6f0a8dbd03cfe242b14ed117953244a7`.
Quality, Update Package and Configuration Reference CI passed at that SHA;
the nine published-baseline upgrade and backup-integrity tests passed.
The stable VERSION/docs-only promotion must still use its own exact source
identity for integration/publication. These checks do not prove production
aaPanel installation; real host acceptance and backups remain separate.

The Owner authorized source integration and separately requested stable
publication, but neither the source Merge nor GitHub Release automatically
changes an installed site. See Issue #135, PR #178 and
`docs/DEPLOYMENT.md`.

---

# MCP Gateway v2.2.0

**Stable v2.2.0 promotion source.** This version promotes the independently
reviewed v2.2.0-rc.2 WordPress recovery and Admin reliability runtime.
The promotion changes VERSION and documentation only; application runtime,
authorization, migration and browser-update behavior are unchanged.
A GitHub source merge or CI run does not publish a release or install it
on an operator host. Public stable publication is a separately Owner-approved
manual action bound to the exact integrated main SHA and VERSION; deployment
and any live production OAuth/Target operation require separate authorization.

## Changes since public v2.1.2

- **Safe interrupted WordPress Disconnect recovery:** Target Details now
  separates public WordPress reachability, credential/authorization state,
  unfinished operation, last live probe and historical errors. An interrupted
  remote revocation cannot silently reactivate credentials or trigger an
  unproven retry. Proven never-dispatched token slots can be completed
  without replaying previously acknowledged revocations. A confirmed
  disconnect leads to guided fresh WordPress authorization.
- **Strict Owner-only conditional cancellation:** when *zero* revocations
  were dispatched or acknowledged, the exact credential identity/generation
  is unchanged, no incompatible OAuth/refresh is pending and the access
  bearer has more than 30 seconds left, the UI may offer Cancel pending
  disconnect. The server independently rechecks all safety, role, password
  and Target gates, then performs a real authenticated read-only WordPress
  catalog verification. Missing, expired, stale or unknown proof fails closed.
- **Honest remote-unknown recovery:** pre-upgrade revocation intents are
  classified as legacy_unknown rather than artificially safe. Unknown or
  partially applied remote revocation requires reviewed WordPress-side
  reconciliation and explicit Owner attestations; automatic forced reset,
  unknown-response replay or blind credential reuse are forbidden.
- **Owner-only local Target Forget (emergency last resort):** exact Target ID,
  current Owner password, two independent risk acknowledgments, required
  atomic Activity audit and transactional local deletion. The remote
  WordPress/SSH credential or OAuth grant is **NOT revoked or verified** by
  this action; previously running remote operations cannot be undone.
  Existing local per-Target ACLs, encrypted credentials, intents and
  memberships are removed, while independent audit snapshots survive.
- **Shared Admin resilience:** reusable panel spacing and consistent
  heading/table direction; long valid Target names no longer expand the
  document outside the intended horizontal table-scroll boundary. Responsive,
  light/dark, keyboard/focus and RTL/LTR layout evidence is recorded for
  the approved effective tree.
- **Actionable hosting diagnostics:** an Owner-facing outbound DNS
  compatibility preflight and explicit aaPanel/OpenLiteSpeed PHP LSAPI
  effective VHost open_basedir file-access guidance. A healthy metadata
  request remains distinct from authenticated OAuth catalog success.
  No SSRF, TLS, proxy or access-control safety rule is relaxed.

## Migration and safe upgrade from v2.1.2

The new additive migration
`2026_10_13_000000_fence_wordpress_disconnect_recovery.php`
adds WordPress metadata evidence and the durable disconnect revocation
ledger. Pre-existing pending intents become `legacy_unknown`, never
"safe to cancel" merely because a database update ran. Its `down()`
**refuses rollback while any revocation intent remains**; a partial or
uncertain migration must be reconciled rather than blindly repeated or
reversed. Do not delete or rewrite pending credentials to make rollback pass.

Before any authorized operator upgrade: take and **test-restore** a consistent
MariaDB/MySQL database backup, preserve the deployed `.env`, Laravel
`APP_KEY`, both OAuth/Bridge private signing keypairs, original release
artifacts and sensitive recovery state, verify available space and a
roll-forward plan. Use the exact version's checksum-verified
`mcp-gateway-update-vX.Y.Z.zip` in the existing application root and
the authenticated `/update/` flow; **never** use the fresh-install ZIP as
an updater, assume the browser updater's code backup contains the database,
or rerun a migration after an uncertain result. Confirm Target IDs,
permissions, audit, credentials and existing WordPress/SSH access afterward
without disconnecting a healthy live Target.

The published v2.1.2 installation remains unchanged by this source branch.
The candidate package validation must include **actual published v2.1.2
fresh-install ZIP as an explicit upgrade and backup-integrity baseline**
in addition to older releases. Isolated CI/browser evidence does not by
itself prove aaPanel installed-host compatibility, months-long OAuth
durability, or completion of Issue #173's production delivery checks.
See `docs/TARGET-DISCONNECT-RECOVERY.md`,
`docs/OFFLINE-TARGET-REMOVAL.md`, and `docs/DEPLOYMENT.md`.

---

# MCP Gateway v2.1.2

**Stable 2.1.2 promotion source.** This version promotes the previously
independently reviewed `2.1.2-rc.8` WordPress + Direct SSH runtime; the
promotion changes only VERSION and release documentation, not application
behavior, authorization contracts, migrations or updater code. The separate
`2.1.2-rc.1` through `2.1.2-rc.8` identities were test candidates, not public
stable Releases. Earlier `2.1.0` and `2.1.1` were also operator test versions.
Public publication is a **separately approved manual action against an exact
reviewed main commit**; a successful PR, VERSION change or CI does not publish,
install or enable the new version on any operator host. The updater continues
to reject same-version and downgrade attempts.

## Changes since v2.0.3

- **Existing WordPress behavior retained:** dynamic native WordPress Abilities, fail-closed classifications, Target-bound OAuth permissions and long-idle offline-credential recovery. These include the v2.0.3 maintenance fixes plus newly integrated HTTP deadline/DNS safety refinements.
- **Direct SSH Targets:** host-key pinning, bounded command execution, SFTP stat/list/range/write, and reusable bounded internal private streams. No implicit permission grants, private-network exception or unrestricted credential bypass.
- **Optional complete SSH binary upload/download:** authenticated per-Target file-transfer discovery, fixed-size/timeout/concurrency budgets, integrity-checked and guarded atomic publication, separate client-side whole-response digest verification. Feature remains **OFF by default** and must be deliberately enabled on an approved host. The 16 KiB inline call budget and 64 MiB/40-second optional SSH upper bound are not global client/WordPress/Agent file or job limits.
- **Owner operational controls:** one typed registry for bounded WordPress responses, HTTP connect/request deadlines and optional SSH transfer budgets; retains immutable authorization and network safety rules.
- **Owner Admin usability:** one connector-first Target enrollment form, independent password-only or private-key-only SSH login fields, explicit separately verified server public host-key/fingerprint guidance, consistent control styling, and grouped Operational Settings with per-field defaults and optional reset. The authorization, encrypted SSH credential format and settings audit semantics are unchanged. Admin CSS uses a content fingerprint to avoid stale styling after valid upgrades. The updater deliberately rejects a package whose VERSION is not newer than the installed VERSION.
- **Edit existing connector settings safely:** Owner password-gated, optimistic-revision-aware SSH host/port/user/trusted host-key and encrypted password/private-key replacement, preserving Target ID, user/Target Group membership and denial rules. Password/key may be left blank when retaining the same method. After any SSH configuration/secret change, clear old verification and require verified host key/login before SSH commands or SFTP are used. The private login key is never echoed or restored into the browser. WordPress HTTPS origin can change only after confirmed OAuth disconnect/revocation/recovery and renewed safe metadata discovery; tokens are never silently moved between sites and the Target must authorize again. No new schema migration.
- **No auto-assignment on enrollment:** creating a Target cannot create a positive User-to-Target access rule; Selected-scope administrators must be explicitly assigned by an Owner before opening or using it, including if they already hold a confirmed global SSH capability.
- **Explicit SSH Target Group lifecycle review:** Owner password AND a separate SSH group confirmation are required for changes to SSH group Target or User memberships and deletion of groups carrying SSH Targets or denials. A removal can lift a denial even when another group still supplies reachability; additions can enable previously Owner-approved SSH capabilities. Checks run under the group transaction lock (including stale edit forms); genuine no-op requests remain no-ops. Other connector memberships retain their previous behavior. No schema migration or unconditional SSH grants.
- **Live connector permissions and readable UI:** Direct SSH is active (not a reserved/future permission). Add User defaults all remote command/SFTP controls to **DENY** but can apply an explicitly confirmed Owner grant for Selected Target scope during initial creation; older clients remain default-denied. Edit User preserves confirmed grants, requires confirmation for changes and revokes SSH when widening to All scope. An unreviewed legacy Add/Edit User form cannot bypass deny-by-default merely by sending the standalone SSH confirmation flag; the explicit review marker is required for each new SSH grant. User → Target permissions expose live SSH deny-only switches and confirmation for Target scope changes; Add/Edit Target Groups apply deny-only restrictions and never create grants. Clear checked=DENY help, role ceilings, preserved historical denials and paused Agent markers remain intact.
- **Revision-safe Admin form recovery (RC7 review R4):** after any failed password, invalid name, or missing SSH acknowledgement, reuse submitted Target/Group denial checkboxes only when the flashed authorization revision exactly matches the same persisted ACL snapshot displayed with the new revision. On mismatch or missing revision, restore current persisted restrictions, clear previous SSH approval and display a readable re-review warning. An intentionally unchecked denial set may be restored only when the original revision is still current. Service-side User/Group transaction locks and Owner-only confirmation remain unchanged; no schema migration or public API changes.
- **Review RC6 remediation:** transaction-locked, revision-bound Owner confirmation of SSH Target-specific ACL changes, stale denial-revision rejection for Target Group edits (including old checked approvals), and secret-safe DNS/TCP/TLS/timeout propagation through WordPress MCP into the Activity-correlated operational log. Non-SSH access editing and published MCP error codes remain compatible; no new schema migration.
- **Actionable error diagnostics throughout Gateway:** consistent safe error categories and recommended checks in Admin Target details/operations and additive MCP tool hints; request/Activity/log correlation, DNS/TCP/TLS/deadline-stage diagnostics when provable, bounded secret-free logging across connector operations and file transfer. Fresh installer and standalone updater failures show PHP-server-log references. Remote OAuth revocation/unknown file-write outcomes remain fail-closed; diagnostics are not credential-reset buttons.
- **Operational readiness:** candidate acceptance covers the actual published v2.0.3 ZIP as an upgrade baseline, package verification, isolated installed WordPress + SSH acceptance, and a release workflow that requires explicit manual publication against an immutable reviewed main SHA.

## Safe upgrade and release gate

Use the **matching update ZIP**, not the fresh-install ZIP, over an existing v2.0.3 Target-era installation **or a previously installed 2.1.0/2.1.1 test candidate**.
Prereleases advance monotonically: `2.1.1 -> 2.1.2-rc.1 -> 2.1.2-rc.2 -> 2.1.2-rc.3 -> 2.1.2-rc.4 -> 2.1.2-rc.5 -> 2.1.2-rc.6 -> 2.1.2-rc.7 -> 2.1.2-rc.8 -> 2.1.2`.
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
