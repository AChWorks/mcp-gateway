# MCP Gateway v2.4.2

The temporary browser updater now requires an enabled Owner in role-aware installations before displaying update preflight or accepting Start. Access to the shared dashboard does not confer update authority. Supported older installations without roles retain their existing authenticated administrator upgrade path. Existing browser-bound continuation and operator recovery safeguards remain in place.

Owner sign-in can return directly to the exact local `/update/` entrypoint. Ordinary users and unsafe redirect destinations do not gain access through this return path. There is no new configuration, service or database migration.

The official release gates include all 25 configured published deployment baselines through v2.4.1, complete browser updates and backup-integrity fail-safe verification. This release does not deploy itself to installed hosts; stage only the matching official update ZIP and checksum for an approved update.

# MCP Gateway v2.4.1

**Stable v2.4.1 — coherent shared Admin widths and spacing, aligned permission badges, and ten recent Activity entries.**

This bounded follow-up to official v2.4.0 addresses the [Owner-reported Admin layout issues #136](https://github.com/AChWorks/mcp-gateway/issues/136):

- **Form and panel widths:** correct the shared composition of outer panels, inner forms and explanatory content so Users, Target Groups, enrollment, AI clients and related screens use their available space without stranding narrow content inside oversized panels.
- **Spacing and permission alignment:** separate the Dashboard Needs review panel from the following content grid and align permission-scope badges consistently at the trailing edge, including longer capability titles and narrow-screen wrapping.
- **Recent Activity:** show the ten newest authorized Dashboard Activity entries instead of five. Effective user/Target scope and newest-first order remain intact; Needs review stays bounded to five Targets.
- **Clear permission restrictions:** every restriction row visibly says “Deny”; user creation separates advanced restrictions and explains that a checked box blocks the capability. Role defaults, denied-permission fields and SSH safeguards retain their existing meaning.
- **Contextual SSH confirmation:** show group-membership/deletion acknowledgements only when that operation has SSH impact. WordPress-only Target membership no longer asks for unrelated SSH review; fresh server-side SSH checks, current-password confirmation and denial editors remain authoritative.
- **Authorized sign-in destination:** choose an available Admin section when Dashboard is denied, reject unsafe intended redirect origins, and provide an honest no-access screen or permission-aware 403 recovery with native sign-out. Existing section/resource Gates and OAuth authorization continuation remain intact.
- **Upgrade boundary:** no new database migration, environment key, mandatory service, credential rotation or permission-policy change is introduced. Existing native forms, CSRF and password-confirmation boundaries remain intact. Both package workflows include official v2.4.0 in the stable upgrade and backup-integrity matrices.

Publication and installation are separate from source preparation; installed-host acceptance requires its own verification.

# MCP Gateway v2.4.0

**Stable v2.4.0 — connector-neutral Dashboard and shared Admin experience, preserving existing access, native forms, OAuth and file-transfer boundaries.**

Compared with official v2.3.12, this release delivers the [Admin experience redesign #136](https://github.com/AChWorks/mcp-gateway/issues/136):

- **Shared Admin workspace:** permission-filtered desktop sidebar, keyboard-operable mobile navigation, practical content width, coherent light/dark surfaces and reusable form, table and feedback patterns. Eligible internal links use enhanced GET navigation while direct URLs, native form submissions and no-JavaScript access remain available. Authentication handoffs and file transfers retain native navigation; speculative prefetch and application snapshots are disabled.
- **Actionable Dashboard:** scoped needs-review rows, separate paused and lifecycle summaries, connector breakdown and recent Activity direct operators to the relevant Target or evidence. Stored connection state and recorded observations are not presented as proof of live remote health; opening the Dashboard does not probe the fleet.
- **Connector-owned presentation:** code-registered connector components own their enrollment, configuration and recovery presentation. Shared Target pages use registered presentation companions and a neutral unsupported fallback rather than assuming every Target is WordPress or SSH. Presentation never grants new operations or credentials.
- **Consistent decisions and recovery:** access forms associate field errors with their controls, permission choices say what is denied, operational settings provide local section links within one version-fenced native form, and Activity distinguishes failed from unknown outcomes while preserving readable recorded diagnostics.
- **Upgrade boundary:** no new database migration, environment key, credential rotation, OAuth client identity change or mandatory runtime service is introduced by this UI work. The package workflows include official v2.3.12 alongside the existing stable upgrade and backup-integrity baselines.
- **Verification and rollout:** author-separated review and source/browser checks cover scoped rendering, native/no-JavaScript paths, section-history and attachment draft preservation, and coherent asset changes. The richer Dashboard adds measured read/render work compared with the previous summary; fixed query counts do not imply constant runtime or a server speedup. Public publication does not install the release. Installed-host UX/performance, complete assistive-technology/localization acceptance and real downstream file operations remain separate.

# MCP Gateway v2.3.12

**Stable v2.3.12 — security remediation for Symfony Mime and actionable, read-only endpoint preflight across WordPress and Direct SSH Targets; preserve existing permission, MCP, OAuth and remote-authorization boundaries.**

Compared with official v2.3.11:

- **Security remediation ([Issue #246](https://github.com/AChWorks/mcp-gateway/issues/246), [PR #248](https://github.com/AChWorks/mcp-gateway/pull/248)):** replace the existing locked `symfony/mime v8.1.6` with upstream-fixed **v8.1.10** for `CVE-2026-45070` (MIME parameter-name validation). `composer audit --locked` remains enabled and passed on the reviewed patch and post-merge main; only the relevant locked dependency was changed, without new MCP/OAuth packages or application-source changes in the security patch.
- **Shared Target endpoint preflight ([PR #247](https://github.com/AChWorks/mcp-gateway/pull/247)):** **Targets → Add Target → Check endpoint from Gateway** now offers an optional read-only check for registered WordPress and Direct SSH connector types. The existing Admin session, CSRF, `TargetsCreate` permission and a separate rate limit protect this action. WordPress HTTPS checks retain public-address/DNS/SSRF policies; SSH checks use their separate public TCP-peer policy. Preflight does **not** contact or authenticate to the remote endpoint, register a Target, persist credentials or establish trust.
- **Actionable, safely redacted diagnostics:** common enrollment, WordPress origin reconfiguration, discovery and connection error handling, and SSH egress diagnostics preserve useful safe context, known block reasons, address provenance, operator next steps and correlation references where supported. Unsafe signed URLs/userinfo/query/fragments are not echoed back into Admin forms or diagnostic output.
- **Accurate checked subject and DNS provenance:** a successful observation identifies the checked HTTPS endpoint or SSH host:port and selected form parameters. Changing an endpoint, connector, SSH host or port marks that observation stale; returning to the old value still requires rechecking. Literal IPs are distinguished from resolver-produced addresses; no unverified DNS-resolution claim is made. Real operations still separately revalidate DNS, SSRF, TLS, SSH host keys, permissions and OAuth as applicable.
- **Additional metadata and docs:** the merged Koinon descriptor update ([PR #245](https://github.com/AChWorks/mcp-gateway/pull/245)) describes WordPress as an optional integration. README, Admin UI quality guidance, development and architecture documentation were updated for these shared Target features.
- **Upgrade and deployment limits:** no new migration, environment setting, existing Target credential rotation, OAuth client identity change or host-side requirement is introduced by the two new PRs. A successful preflight does **not** prove remote availability, TLS/SSH identity, OAuth consent, or future effect authorization. The official release workflow now checks updates and backup-integrity fail-safes from the published v2.3.11 baseline as well as older supported versions, and produces SHA-256 checksum files for its installation/update ZIPs. **Publishing this Release does not update a running Gateway**; installation and live acceptance on Production require separate authorization.

Operator references: [Target integration guide](docs/CONNECTOR-INTEGRATION-GUIDE.md), [development and tests](docs/DEVELOPMENT.md), [deployment and recovery](docs/DEPLOYMENT.md), and [architecture](docs/ARCHITECTURE.md).

# MCP Gateway v2.3.11

**Stable v2.3.11 — restore cross-origin connector authorization from the Admin under the existing restrictive Content Security Policy; preserve all v2.3.10 protections, existing Targets and OAuth client identities.**

Compared with official v2.3.10, this maintenance candidate fixes [external authorization regression #243](https://github.com/AChWorks/mcp-gateway/issues/243) without any WordPress-specific CSP exception:

- **Connector-neutral browser handoff:** an authorized Admin Target connection POST returns **303 to an opaque, short-lived same-origin GET**. The resulting protected Admin document navigates to the verified HTTPS provider with a meta refresh; it also offers an accessible manual link. This is a top-level browser navigation, not an external form POST or a relaxed CSP. All normal Admin forms keep `form-action 'self'`, `frame-ancestors 'none'`, no-referrer, no-store, and existing click/CSRF/Target permission boundaries.
- **Bounded, fail-closed destination handling:** only a connector-supplied authorization URL matching that trusted connector's separately verified HTTPS origin is eligible. The destination and OAuth state are **not** embedded in the same-origin continuation URL. The session-bound continuation is limited to a short **120-second window**, consumed once using an **atomic, expiring shared-cache claim** even across concurrent PHP workers or stale session writes, tied to the initiating Admin user and Target, and checks the relevant permission again before exposing the provider link. Refresh/back does not replay the initiating POST; expired/used or invalid handoffs return safely to Target recovery. Existing WP Bridge issuer/resource binding, PKCE and single-use callback logic are unchanged.
- **Regression coverage:** Laravel feature tests cover real WordPress begin/callback compatibility, the generic non-WordPress connector boundary, invalid destinations, expired/replayed/session-changed handoffs, permission revocation, and accessible fallback markup. A new path-scoped GitHub Actions browser check exercises a controlled, three-process HTTP race with shared encrypted file sessions/cache (exactly one successful handoff even after a stale session writer), followed by real Chromium POST→303→GET→external-provider navigation with production-equivalent Admin CSP, a no-JavaScript mobile path and rejection of an unrelated cross-origin Admin form. The external provider and HTTPS discovery are simulated in a strictly local fixture; these tests do **not** claim live WordPress account consent.
- **Upgrade compatibility and safety:** no database migration, new mandatory runtime dependency, credential re-enrollment, OAuth identity rotation or changed server configuration is required. The existing official updater, private storage, historical credentials, v2.3.10 security controls and installed-host operator approval boundaries remain intact. The supported released-package update matrix now explicitly includes the verified published **v2.3.10** baseline, in addition to earlier baselines.
- **Review and release boundary:** official stable publication requires fresh author-separated review of the exact candidate, relevant passing GitHub checks, Owner-approved protected-main integration and the manual guarded Release workflow. Publication alone does not install the updated Gateway. Following a separately authorized installation, verify CSP headers and the real browser journey to the WordPress consent screen before claiming the original Target incident resolved.

Technical contract: [Connector integration guide](docs/CONNECTOR-INTEGRATION-GUIDE.md), [development validation](docs/DEVELOPMENT.md), and [deployment/update guide](docs/DEPLOYMENT.md).

# MCP Gateway v2.3.10

**Stable v2.3.10 — bounded anonymous ChatGPT DCR registration, durable consent-safe capacity recovery, and layered Admin abuse protection, preserving all existing CIMD/DCR grants and client identities.**

Compared with official v2.3.9, this source release candidate contains the independently reviewed [security hardening #239](https://github.com/AChWorks/mcp-gateway/issues/239) through [PR #240](https://github.com/AChWorks/mcp-gateway/pull/240):

- **Standards-compatible, bounded public DCR registration:** the RFC 7591-style registration endpoint stays anonymous and **OFF unless deliberately enabled**. When ON, it retains **5 requests/minute/IP**, adds **15 successfully committed registrations/hour globally** (not consumed by invalid registration metadata), and enforces the existing **512 unretired clients** ceiling. A cheap quota precheck precedes the durable MariaDB admission lock; an authoritative quota check remains inside that lock. HTTP 429 with Retry-After and capacity 503 remain deliberately distinct; existing registered clients and refresh traffic are not blocked by new-registration quotas.
- **Conservative capacity recovery, not timed expiry:** only under full-capacity pressure can up to eight of the oldest DCR identities created *after* the new migration, at least **24 hours old** and *positively proven never authorized*, be permanently retired. Existing clients with unknown prior consent history are **not** automatically retired. Successful consent atomically sets a durable `ever_authorized_at` witness and disables automatic retirement under the existing profile/DCR/authorization locks. Revoked grants or deleted users cannot erase the witness. Tombstones/client identity and grant/token histories remain durable; already-authorized CIMD/DCR connections and signing/encryption material are not changed.
- **Admin brute-force and action limits:** known and unknown login emails use the same database-collation comparison-weight identity for a shared **10 failed attempts/15 minutes** across IPs, serialized with a shared lock; generic invalid-credential responses prevent the tested Unicode-alias account-enumeration oracle. The existing **20/minute/IP and 5/minute/(IP,email)** request limits remain. Current-password confirmations across sensitive Admin actions share **five failed guesses/15 minutes/user**; state-changing Admin operations have **60/minute/user and 120/minute/IP** limits, while reads/logout remain available. No permanent lockouts or new MFA/WAF mechanisms are introduced.
- **Admin browser response and history safety:** early CSRF 419, permission and rate-limit failures receive private/no-store, deny-frame, nosniff, no-referrer and narrow CSP response headers without altering unrelated OAuth/MCP routes or pretending inline JavaScript has a strict script CSP. DCR Admin history is paged at **50 profiles/page** with an additive index; historical CLI/readiness scans remain an explicitly measured-if-needed optional optimization.
- **Two additional additive migrations:** `2026_10_24_010000_index_dcr_admin_history` adds the DCR Admin listing index; `2026_10_24_020000_track_dcr_authorization_history` adds durable consent history/eligibility and the indexed reclamation path. Existing records with no positive history are conservatively unknown; surviving grants are backfilled. The latter migration **refuses rollback while any DCR identity exists**, to avoid destroying authorization evidence. Do not downgrade app code with live DCR clients or remove any DCR table/history; prefer a separately approved forward repair.
- **Supported deployment boundary:** all active PHP workers/hosts must share a lock-capable limiter cache and use consistent application code; an old/new-worker rolling overlap is **not** proven to enforce one cross-version login quota. On MariaDB/MySQL, verify that the actual `users.email` column collation matches the configured login parameter/connection collation before enabling the new security boundary. The tested primary profile is **MariaDB 10.11 / utf8mb4_unicode_ci**; no claim covers arbitrary misconfigured restored databases. Apply the official authenticated updater only after a restorable database backup and preservation of `.env`, `APP_KEY`, signing keys and persistent storage. Do not infer that public DCR quota starvation or deliberate 15-minute account lockout is eliminated.
- **Acceptance evidence:** fresh author-separated HIGH_ASSURANCE independent review of the exact R5 HEAD `e7947ffd9afc5195c24c9109ba5d07984d3e92bf` / TREE `0331403862e5f9c3037e83196c6a4174304fba7e` returned **COMPLETE / APPROVE**, no BLOCKER/REQUIRED findings. [PR #240](https://github.com/AChWorks/mcp-gateway/pull/240) merged to protected main as `8c2917df27a2bdacecb82c14aeab1d881295578b`, with six exact-R5 CI checks SUCCESS: quality **727 passed / 9393 assertions / 28 skipped**, real MariaDB **24 concurrency tests / 363 assertions**, real SSH/systemd, upgrade/backup integrity, CIMD compatibility, and commit attribution.
- **Publication and actual installation are separate:** this version's source preparation and passing CI do not publish a release or update Production. A separately Owner-authorized official Release must produce checksum-verified fresh-install and browser-update ZIPs; any installed host upgrade, configuration change or live OAuth/Target operation requires its own authorization. On the upgraded host, first verify security migration/collation/shared-cache readiness; then enable registration only for planned onboarding, establish a **new** ChatGPT DCR connection with human consent, confirm a read-only authorized MCP call and refresh, and optionally disable public registration afterward. Never infer real client recovery from CI. [Incident #235](https://github.com/AChWorks/mcp-gateway/issues/235) remains open pending live acceptance.

Operator references: [OAuth client registration/recovery](docs/OAUTH-CLIENT-REGISTRATION.md), [deployment and rollback](docs/DEPLOYMENT.md), and [configuration](docs/CONFIGURATION.md).

# MCP Gateway v2.3.9

**Stable v2.3.9 — resilient ChatGPT-facing OAuth with independent fixed CIMD/private_key_jwt and opt-in Dynamic Client Registration (DCR)/client_secret_post, while retaining existing access controls and client identity.**

Compared with the official v2.3.8 release:

- **Recoverable upstream OAuth dependency failures (#235, PR #237):** unavailable ChatGPT client metadata/JWKS now produces a bounded, diagnosable **503 temporarily_unavailable** instead of an uncaught browser/token HTTP 500, with fail-closed RS256/JWKS verification. No external client identity, existing consent, or signing key is silently replaced or bypassed. The observed external HTTP 404 outage later recovered; its exact relationship to every historical expired-client UI event remains unproven.
- **Two independent ChatGPT client strategies (#235):** keep the original stable CIMD client profile and `private_key_jwt` authentication. Add RFC 7591-style DCR with independent immutable client IDs, high-entropy hashed secret verifiers, exact HTTPS ChatGPT redirect matching, PKCE S256, explicit human login/consent and existing user/Target permissions. Both paths share code/refresh/revoke grants without cross-profile token or permission migration. DCR public registration is **OFF by default**; original CIMD discovery stays ON by default.
- **Durable bounded DCR lifecycle:** public registration is limited to 5/minute/source IP and 512 unretired identities. Explicit Owner-only disable → individual consent revocation → permanent retirement recovers an unused slot while retaining identity, secret-verifier, grant and token history; retired clients are never reused or re-enabled. Consent approval locks and revalidates the live durable client profile and DCR registration inside one MariaDB transaction, preventing stale approvals after retirement. Rare disable-during-consent maps to OAuth `invalid_client`, not HTTP 500.
- **Token continuity:** Access Tokens remain one hour by default. The new-install/default expiry of *newly issued rotating Refresh Tokens* is 180 days; existing private `.env` settings and previously issued token expiries are unchanged. Neither an update nor a DCR connection automatically migrates or revokes the existing CIMD connection. Normal rotation, authorization checks and bounded lost-response recovery remain enforced.
- **Additive schema and rollback precautions:** `2026_10_24_000000_create_oauth_dcr_clients` preserves historical authorizations and adds independent DCR records. The migration refuses table removal if DCR registrations exist; a code downgrade with live DCR clients is not a safe functional rollback. Before installing on a real Gateway, preserve a verified-restorable database backup, private `.env`, `APP_KEY`, separate signing keys and persistent storage, and use the official browser-update package; do not reinstall or rotate keys.
- **Review and test evidence:** PR #237 R3 fresh author-separated HIGH_ASSURANCE review of exact source HEAD `c38e13b15cbbed6f18bd4c114bb93982ff197b5b` returned **COMPLETE / APPROVE**, no BLOCKER/REQUIRED. All six exact-HEAD workflows passed, including full CI, MariaDB concurrency (16 tests / 189 assertions), released-baseline update preservation and upstream compatibility. This release additionally tests upgrades from official v2.3.8.
- **Installation and real-client acceptance are separate:** publication of this release **does not update the installed host**. Following a separately authorized operator deployment, enable DCR onboarding deliberately, create a **new** ChatGPT DCR connection with explicit consent, verify authorized MCP tool discovery/call and refresh/reconnect, then optionally close public registration. Verify the preexisting CIMD client independently. Incident [#235](https://github.com/AChWorks/mcp-gateway/issues/235) stays open until real installed-host recovery is proven.

Operator guide: [OAuth client registration and recovery](docs/OAUTH-CLIENT-REGISTRATION.md), [configuration](docs/CONFIGURATION.md), [deployment and rollback](docs/DEPLOYMENT.md).

# MCP Gateway v2.3.8

**Stable v2.3.8 — a shared, scope-fenced WordPress operation path for Admin and AI, a restricted published-post create capability, accurate SSH Target file windows and larger opt-in synchronous SSH deadlines.**

Compared with the official v2.3.7 release:

- **Shared WordPress Admin/AI use case (#200, PR #227):** existing MCP WordPress Ability discovery/execution and one authenticated Admin read-only `wp-ai-bridge/bridge-info` operation now reuse `WordpressTargetOperations`. The Admin request is POST+CSRF+throttle and remains limited to an explicitly authorized Target and readonly operation. Source controls check current User/Target/grants again at effect dispatch, retaining provider metadata/classification, Target Pause, Activity and no-blind-replay semantics. **This is not a generic Admin publishing or arbitrary WordPress Ability execution UI.**
- **Separate AI access and narrowly scoped WordPress publish-only operation (#200, PR #229):** the Owner can enable AI connection access per Gateway user independently of role, human Admin access and Target permissions; disabling AI invalidates existing bearer/consent access, and later enablement requires new consent. Current installation's Owner retains AI access after migration; new users default to AI off. The new `wordpress-content-publish-create` MCP Tool creates exactly **one live `post` with `status=publish`** using trusted `wp-ai-bridge/content-upsert`, bounded title/body, explicit User+Target Group semantic grants for non-Owner users and provider/native WordPress permissions. It cannot update existing content or create drafts; it does not grant generic mutation, site administration or AI client access. A stable caller operation ID is isolated by Gateway user, Target and authenticated client identity. Fresh exact OAuth, actor/grant, Target Pause and provider-side checks protect dispatch. The Tool is **effectful and publicly publishes**: test only on a disposable, explicitly approved site and never blindly retry an uncertain outcome.
- **SSH SFTP authenticated-session freshness (#200, PR #229):** after SSH authentication, inline and streamed file staging, effect-time writes and final hardlink/rename publication recheck both live scope/role/grants/Target Pause and the **original authenticated endpoint, host key, configuration and encrypted credential identity**. Reconfigured/rotated and reconnected Targets cannot silently authorize writes over an old SSH session. Keep the existing private staging, verified byte/digest, no-overwrite-by-default, cleanup and `outcome_unknown` guarantees.
- **Truthful SSH file discovery (#222, PR #228):** `target-context` now advertises the effective Owner-selected SFTP read/write windows instead of an obsolete fixed 16-KiB value. It does not bypass per-call encoded MCP payload limits or prove the connected client's capacity.
- **Extended *selectable* synchronous SSH limits (#230, PR #231):** Owner may set whole-file SSH transfer timeout up to **3,600 seconds (60 minutes)** and synchronous SSH command execution timeout up to **600 seconds (10 minutes)**; defaults stay at **30 seconds for whole-file transfer** and **15 seconds for command execution**. The bounded absolute deadline remains shared across ingress/staging/SFTP transfer; per-Target serialization leases and finite command/runtime gates scale coherently. ChatGPT signed-source HTTPS fetch stays independently bounded to at most **120 seconds**, and WordPress signed-file mode stays independently limited to **120 seconds**. Larger source policy does **not** override PHP workers, proxies, CDN, clients, SSH servers or the receiving URL's expiry. Retained SSH Jobs remain preferable for long commands; measurements of actual installed maxima and concurrent load remain open under [#154](https://github.com/AChWorks/mcp-gateway/issues/154).
- **Three additive migrations and upgrade protection:** `2026_10_20_000000_create_wordpress_publish_group_grants` adds explicit User/Target Group grants; `2026_10_20_020000_add_ai_access_enabled_to_users` defaults new accounts to AI OFF while preserving current Owner AI access; `2026_10_20_030000_expand_ssh_synchronous_transfer_timeout` widens the stored whole-file timeout from unsigned tinyint to unsigned smallint. Existing values, OAuth/Target credentials, persistent storage and Operator-managed `.env` are preserved through the supported browser updater. **Downgrade is refused** when a saved transfer limit is above 40 seconds or command timeout above 360 seconds; do not force an unsafe schema downgrade or manually reset security grants.
- **Assurance and independent review:** PRs #227, #228, #229 and #231 were independently reviewed and Owner-approved before their merges. Combined protected `main@6e3da3bf50df7cb99622fc147c788c66d99dc6c7` kept the R2-reviewed #231 source TREE `93aaf2ecfb953a1919da22b048da4c5a17b295b8`. All six post-merge official GitHub Actions workflows completed SUCCESS: quality **686 passed / 17 skipped / 8,770 assertions**, disposable real OpenSSH/systemd, MariaDB concurrency, WP Bridge contract, configuration, attribution and released-baseline updater/backup-integrity checks. Stable packaging also includes the **published v2.3.7** in all six synchronized historical baseline loops in Release/Update Package acceptance, without weakening prior baselines.
- **Operator deployment and actual limits:** official GitHub Release publishes two SHA-256-checkable ZIPs, **fresh install** and **browser update**; it does **not** deploy to any running Gateway. For an existing installation, preserve a *restorable* database backup, private `.env`, application/OAuth signing keys and persistent `storage/`; use the matching update ZIP and protected `/update/` workflow in [Deployment](docs/DEPLOYMENT.md). Verify installed version, three migrations, `gateway:check`, Admin, AI/OAuth and appropriately authorized Targets before claiming installed acceptance. Existing Owner settings are not automatically raised. An existing AI connection may need its Tool catalog refreshed to discover the new restricted Tool. Real single-site AI→Gateway→Bridge **draft** creation/readback has succeeded on the old general Ability Tool, **not** on the new restricted live-publish Tool. Multi-site content workflow Phase C remains deferred under [#200](https://github.com/AChWorks/mcp-gateway/issues/200); native ChatGPT FileParams remains OFF/parked under [#147](https://github.com/AChWorks/mcp-gateway/issues/147). Neither is claimed delivered by v2.3.8.

# MCP Gateway v2.3.7

**Stable v2.3.7 — discover retained SSH Jobs from a new conversation, tune bounded SSH resource budgets, and enforce a real command deadline while draining excess output.**

Compared with the official v2.3.6 release:

- **Recover SSH Jobs without replay (#221, PR #223):** A new read-only SSH MCP Tool, ssh-jobs-list, discovers retained Job IDs for the exact authenticated Gateway user, OAuth client/profile, original Target binding and current Target access. Small pages with optional status and tamper-evident HMAC keyset cursors preserve isolation, pause/revocation behavior, retention and uncertain Job discoverability. Listing is database-only; it never opens SSH, starts or repeats an effectful Job, exposes script/output/credential content, or recovers Jobs belonging to another client profile. Use ssh-job-status and ssh-job-output on the returned ID for deliberate follow-up.

- **Separate editable SSH ceilings (#222, PR #224):** Owner Operational Settings can independently select up to **512 KiB** for SSH command input, bounded stdout and stderr previews, detached Job script input, per-call retained Job output reads, SFTP inline file reads and writes, and aggregate SFTP directory-name bytes. Existing small defaults remain unchanged. The separately retained **1 MiB-per-stream SSH Job spool** and independently configured MiB-scale whole-file exchange remain intact. A 512 KiB decoded SFTP write expands to **699,052 Base64 characters** before JSON-RPC framing; encoded JSON, duplicate structured/text output, server request limits and receiving-client limits may still impose smaller effective windows.

- **Synchronous commands up to 360 seconds, with truthful outcomes (#222):** Owner may select a maximum SSH exec timeout up to **360 seconds** (default stays 15 seconds). The per-Target admission lease scales with the selected bound; a monotonic elapsed-time deadline is checked even while output packets are continuously ready. Captured stdout/stderr are capped independently while excess output is drained in bounded memory until a real exit is observed. Return an authentic exit code and per-stream truncation when completion is proven; on timeout, disconnect or missing exit evidence report outcome_unknown and **never automatically rerun** a potentially effectful command. Known insufficient PHP worker capacity fails before dispatch. PHP, proxy, CDN and MCP client timeouts must be qualified separately; configuring 360 seconds does not guarantee an installed client can wait that long.

- **Additive upgrade schema and safeguards:** The supported browser updater applies 2026_10_19_000000_index_ssh_job_client_discovery and 2026_10_19_010000_expand_ssh_resource_limits before exposing the new listing and widened settings. The former adds the scoped lookup index; the latter safely widens prior small integer setting columns and adds separate typed limits across SQLite and supported MariaDB/MySQL installs. Existing settings, Target/client grants, keys and retained Jobs must remain intact; rollback refuses a lossy narrowing when saved values exceed the old range. Do not manually run or reverse migrations as a substitute for the approved updater.

- **Release verification:** The independently reviewed #223 and #224 source changes, including their cumulative integration, had **COMPLETE / APPROVE** verdicts with no REQUIRED/BLOCKER findings. The exact merged main tree passed all six source CI workflows; its quality job had **627 passed, 7,678 assertions, 15 skipped**, including saturated-output OpenSSH monotonic-deadline enforcement, native command exits, a real 35-second SSH command, bounded multi-megabyte output draining, PHPStan, Pint and isolated systemd Job checks. This release also adds the **published v2.3.6** to all six synchronized historical released-baseline loops in Release and Update Package validation, including real browser-update and backup-integrity testing.

- **Operator installation and remaining limits:** For first installation, use only the named checksum-verified fresh-install ZIP. For an existing v2.3.6 or supported older release, preserve a separately restorable database backup, private .env, APP_KEY, OAuth signing keys and persistent storage; use the exact matching browser-update ZIP and authenticated /update/ flow described in [Deployment](docs/DEPLOYMENT.md), then verify installed VERSION, migrations, /up, Admin/OAuth and authorized Targets. GitHub Release publication **does not deploy** to any running Gateway or enable new Owner settings automatically. The optional 95-second and 350-second isolated fixtures and full installed PHP/proxy/CDN/ChatGPT 360-second or maximum 512 KiB end-to-end capacities have **not** been demonstrated; [capacity Issue #154](https://github.com/AChWorks/mcp-gateway/issues/154) remains open for qualified host/client measurements. Native ChatGPT FileParams remains OFF by default; its unrelated parked integration is not reenabled by this release.

# MCP Gateway v2.3.6

**Stable v2.3.6 — park unreliable native ChatGPT FileParams by default without disabling any supported file exchange.**

Compared with the official v2.3.5 release:

- **ChatGPT FileParams parked (#147, PR #217):** new `CHATGPT_FILEPARAMS_ENABLED=false` default (also OFF when the key is absent) hides both `target-file-input` and `wordpress-file-input` from MCP registration and prevents stale cached `tools/call` invocations. The 14 standard MCP tools, SSH SFTP read/write windows, OAuth HTTPS whole-file binary endpoints, Gateway Admin browser upload/download, SSH Jobs and WordPress native Abilities remain independent and authorized as before.
- **Preserve optional implementation and security boundaries:** no ChatGPT source-ingress code, WordPress private staging, SSH whole-file verification, database admission schema, TLS/DNS/public-IP SSRF guard, SHA-256 checks or source-origin restrictions are removed. PR #215 adds fixed-class nonsecret invalid-input diagnostics; PR #216 adds an Owner-only no-destination origin-host hint for rejected FileParams, without exposing signed query strings. Neither is proof the current ChatGPT host delivers FileParams. The observed platform-side safety blocks and earlier origin rejection are unresolved client/host integration limitations, **not a proven universal OpenAI defect**. No speculative origin allowlist expansion is permitted.
- **Existing `.env` needs no change for default OFF:** the official update retains operator-owned `.env`; an absent `CHATGPT_FILEPARAMS_ENABLED` key (confirmed on the existing production v2.3.5 host) is correct, as is explicit `false`. If an operator previously added `CHATGPT_FILEPARAMS_ENABLED=true`, set it to `false` before the update; re-enable only after independently reviewed actual host integration. Keep `SSH_FILE_TRANSFER_ENABLED` unchanged so the supported upload/download path stays available.
- **Published v2.3.5 added to release upgrade acceptance:** include v2.3.5 in the synchronized three historical baselines for each Release and Update Package workflow. This specifically exercises v2.3.5→v2.3.6 official browser-update and backup-integrity paths. No new runtime database migration, OAuth grant, Target credential format, service or dependency is added in this release.
- **Release and production verification:** issue #147 remains open only for distinct bidirectional and model-to-user file-output criteria; native FileParams is officially PARKED. For publication, require exact-main SHA independent review, all GitHub CI checks, the manually Owner-approved guarded Release workflow, and SHA-256-verified fresh-install/update ZIP assets. For a separately approved installed-host update, preserve and verify a restorable database backup, `.env`, signing keys and persistent storage; use the supported browser update, then confirm new VERSION/source identity, `/up`, `/admin/login`, OFF FileParams modes, and normal SSH/WordPress transfer capabilities. A new GitHub Release never automatically installs or refreshes ChatGPT's cached tool catalog.

**Existing hotpatch compatibility:** an Owner-authorized v2.3.5 host may already have the exact reviewed PR #217 one-file FileParams discovery change installed without changing `VERSION` or `config/bridge.php`. The verified v2.3.6 package must replace both managed files from the reviewed release source and preserve the private `.env`. Do not reinstall an older v2.3.5 package over the hotpatch or claim a complete v2.3.6 production update merely from release publication.

# MCP Gateway v2.3.5

**Stable v2.3.5 — source-ready, bounded ChatGPT file-parameter ingress for explicitly authorized WordPress and SSH Targets, to enable real host acceptance testing.**

Compared with the official v2.3.4 release:

- **ChatGPT FileParams source contract (#147, PR #212):** expose the new `target-file-input` MCP Tool with the host-declared `_meta["openai/fileParams"]=["file"]` and an exact, closed file object schema. Select a concrete authorized `target_id` and either `wordpress_media_stage` or `ssh_sftp_upload`. Preserve the previous `wordpress-file-input` Tool as a compatibility alias for WordPress staging. The new tool is an opt-in host integration path, **not evidence** that any ChatGPT plugin currently injects file bytes correctly.
- **Optional and permission-scoped discovery (prior independent review A2):** FileParams is listed only for the authenticated `chatgpt` OAuth profile with a locally eligible connected, unpaused and correctly scoped Target. WordPress requires matching destructive/readonly Gateway grants and provider credentials; SSH requires an authorized SFTP write Target and enabled whole-file mode. The generic Tool lists only currently eligible modes. Other OAuth clients never receive this vendor extension; `clientInfo` cannot impersonate the OAuth profile. Provider-side grants and remote staging constraints remain separately validated at execution time before signed GET. The ChatGPT connector may need to refresh its Tool catalogue after permissions or installations change.
- **Secure, bounded file intake:** accept only short-lived signed `files.oaiusercontent.com` HTTPS URLs with existing public-DNS, pinned-IP, TLS, no-redirect and nonlogging security rules. Capture and SHA-256-verify a bounded private, disk-spill byte stream rather than materializing large payloads in the MCP JSON response. The existing 8 MiB decoded JSON response guard stays unchanged. Reject interrupted, encoded, expired, oversize or unsafe file sources without publishing them.
- **WordPress private Media staging:** verify real selected-Target builder-write, readonly Site Read and native `upload_files` rights **before** source download. Reuse WP AI Bridge's existing `private-transfer` `limits/begin/append/verify` stages and exact transfer ID/byte/digest receipts. **No native Media publication** occurs from file-input; a separately authorized, original-ID `wp-ai-bridge/transfer-media-import` operation is required. No module install, theme install or package execution is introduced.
- **Direct SSH SFTP upload:** respect the existing optional `SSH_FILE_TRANSFER_ENABLED` flag, exact Target scope and `ssh.file.write` grants. Require caller-selected absolute destination and pre-provisioned 0700 private staging directory; never silently overwrite. Re-check Target grants after download, use the existing private SFTP stream engine and remote SHA-256 readback/atomic publication, and classify uncertain remote writes as non-retryable until the destination is reconciled. No shell-command upload, new background worker or file store.
- **Independent security remediation R1/R2 (prior reviewed SHA `2d8935f`):** the execution-time SSH FileParams pre-download gate now rejects a disconnected/reconnect-required selected Target, missing SSH configuration/required credential, or invalid local encrypted credential binding even if another Target remains eligible. The signed URL is not fetched, the remote host is not contacted, and effect-time checks remain independent. New database-serialized **shared admission capacity** limits both active transfers and pessimistically reserved local temporary spool bytes across Gateway workers/nodes: 1× per-file WordPress, 2× per-file SSH for the verified second copy. Operator private environment knobs `CHATGPT_FILE_MAX_ACTIVE=4`, `CHATGPT_FILE_WP_MAX_ACTIVE=2`, `CHATGPT_FILE_SSH_MAX_ACTIVE=2`, and `CHATGPT_FILE_MAX_RESERVED_BYTES=134217728` have finite documented clamps. Capacity denial happens before any signed GET; reservations release after success/failure and expired post-crash reservations self-reconcile without a daemon. The admission table contains no file/credential/Target metadata.
- **Separate finite limits:** the WordPress ChatGPT signed-file path defaults to 8 MiB / 120 seconds, adjustable through the private `CHATGPT_WP_FILE_MAX_BYTES` and `CHATGPT_WP_FILE_MAX_SECONDS` configuration (bounded by documented source safety caps). SSH file-input inherits the **existing** Owner-editable whole-file size/time profile with its independent limit. A streamed file's total budget spans download plus the selected Target operation, subject to stricter PHP worker, disk, proxy and provider constraints. The former WordPress-only fixed 256 KiB FileParams cap is removed; **no global unlimited file size** is implied.
- **Independent re-review R2-A temporary disk accounting correction:** remove the redundant signed HTTP response-body spool and whole-body copy. Guzzle now writes through the existing bounded stream filter **directly into the fresh, caller-owned private `php://temp` spool**. Non-success status, encoding, exact Content-Length and byte-limit checks still fail closed; caller SHA-256 and release/cleanup remain unchanged. WordPress now truly holds **1 disk-backed local copy** through receive/provider staging, consistent with its 1× capacity reservation; SSH holds at most **2 local copies** during verification, consistent with its 2× reserve. Focused Linux FD-level >64 KiB network-write tests measure the live open spool count and enforce exact Guzzle sink identity, and near-capacity WordPress/SSH tests verify real physical spool counts, signed-GET denial and private cleanup. Ordinary JSON response buffering is unaffected.
- **Verification and compatibility:** tests exercise modern/legacy authenticated MCP Tool discovery, real MCP tool dispatch, >256 KiB binary private WordPress staging, signed file URL/response protection, permission/paused-Target denial before fetch, and disposable OpenSSH SFTP transfer contracts. **One new capacity-admission database migration** (singleton lock plus short-lived non-content reservation rows), but no new OAuth scope, Target registration, vendor dependency or file store. The official browser updater must apply the migration before FileParams admission can succeed; it fails closed while absent. The update package source includes the published v2.3.4 historical baseline in all matching installation, browser-upgrade and backup-integrity checks.

**Remaining acceptance, not included in this release:** real signed-file injection by the **actual connected ChatGPT host** is still unverified, as is native model-to-user file-output attachment handoff. The source is intended to unlock that next acceptance stage on an operator-approved installed Gateway; source unit/CI, QA WordPress transfer and OpenSSH fixtures **must not** be claimed as live ChatGPT success. Do not close [Issue #147](https://github.com/AChWorks/mcp-gateway/issues/147) or the related WordPress host-validation issue merely because the release exists. Other connector-native/large-file modes remain scoped to their explicitly documented capabilities.

**Publication and update safety:** verify a restorable database backup before applying the new migration and do not roll it back while active signed-file leases exist. A code merge, GitHub Release or official ZIP alone does **not** update any production host or refresh its registered ChatGPT tools. Publication is Owner-gated by independent exact-HEAD review, required CI, a matching reviewed `main` SHA and the manual guarded release workflow. For existing installations, protect private `.env`, app/OAuth signing keys and persistent storage, verify a restorable database backup, and use the official matching checksum-verified browser-update ZIP. After operator update, refresh the existing ChatGPT MCP connection's Tool catalog; a second connector is not intrinsically required. Real transfer tests remain limited to explicitly authorized Targets.

# MCP Gateway v2.3.4

**Stable v2.3.4 — opt-in WordPress timing evidence and safe SSH Job output capture without limiting ordinary files.**

Compared with the official v2.3.3 release:

- **Measurable WordPress request stages (#154):** add a request-local, bounded timing waterfall for selected Gateway→WP AI Bridge operations, covering available lookup/authorization, MCP session/catalog/execute/close, public-IP/DNS validation, HTTP transport and observed cURL milestones. `BRIDGE_TIMING_ENABLED=false` by default; enabling it records sanitized, numeric timing evidence in the existing, authorized Target-scoped Activity diagnostics store, subject to the same retention and permissions. Unobserved cURL milestones remain unobserved rather than invented. Early pre-dispatch denials do not gain new timing evidence. This diagnostic feature does **not** alter timeouts, caching, permissions, SSRF/TLS validation or the underlying MCP session flow. Implemented via [PR #209](https://github.com/AChWorks/mcp-gateway/pull/209).
- **SSH Job large-file correctness (#210):** remove the systemd `LimitFSIZE=1048576` setting that mistakenly constrained ordinary regular-file writes by detached Job subprocesses. Keep **1 MiB per stdout/stderr stream** in private, bounded spool capture; drain overflow without killing or blocking the legitimate job. Preserve accurate `truncated` semantics, verified collector/exit evidence, original host/Target binding, no-replay protection, the SSH Job operator recovery model and existing permission gates. This permits legitimate commands to write files larger than the log capture cap, but does not increase the synchronous command or SFTP transfer budgets. Fixed by [PR #211](https://github.com/AChWorks/mcp-gateway/pull/211).
- **Compatibility:** no new database migration, OAuth grant, Target permission, public endpoint, client connector, extra PHP dependency or default-enabled diagnostic/transfer mode. Existing private `.env`, keys, storage and WordPress/SSH Target registrations stay operator-owned. A GitHub Release alone never installs the code on a server.
- **Upgrade verification:** package and browser-update/backup-integrity CI must now include the actual published `v2.3.3` install artifact in all matching historical-baseline lists, in addition to previous versions. Use only the official checked release ZIP and matching `.sha256`; back up and verify restore capability for the installed MariaDB/MySQL database before starting the browser updater.

**Not included or not yet proved:** the separately pending ChatGPT file-parameter ingress candidate in [PR #212](https://github.com/AChWorks/mcp-gateway/pull/212) is not part of this stable version. The native client file attachment handoff (#147), authenticated same-principal Direct-Bridge-vs-Gateway WordPress parity (#130), end-to-end host/client capacity (#154) and installed-client diagnostics (#199) still require explicit real operator/host/client acceptance; prior positive in-process WordPress and negative HTTP transport tests must not be presented as those results. This release does not grant permission to run real-site authorization or remote Job tests against a live host.

**Publication and update safety:** stable publication is separate from branch integration and requires an independently reviewed and Owner-approved exact merged `main` SHA via the guarded manual Release workflow. Preserve `.env`, `APP_KEY`, the distinct OAuth signing keys, and private `storage/`; keep a restorable database backup. If the supported browser updater detects an uncertain migration or backup/recovery state, follow its normal operator recovery procedure rather than force a retry.

# MCP Gateway v2.3.3

**Stable v2.3.3 — SSH/SFTP error fidelity and bounded, authorized diagnostics reliability.**

Compared with officially published v2.3.2:

- **SSH Job diagnostics and privacy:** actionable Job admission and connector failures use the existing, Target-scoped Activity store and the existing authorized Admin/AI diagnostics reader. Paused Targets do not reveal or generate error records for unrelated, malformed, expired or revoked Job handles. Known pre-dispatch contention remains visible in Activity without duplicating routine PHP warning logs.
- **Truthful SSH output and SFTP failures:** only an observed native SFTP missing-file/path status marks an unfinished Job spool as not yet available; permission, connection and other native failures retain their actual observed code and message in selectively redacted diagnostics instead of becoming successful envelopes.
- **Reliable file writes:** distinguish actual missing destinations from native permission/transport failures during overwrite preflight. Preserve safe source-error evidence for uncertain SFTP staging and SSH Job preparation, without exposing internal diagnostic context to public MCP responses or treating a possibly applied operation as safe to retry. If diagnostic redaction fails, best-effort temporary cleanup still runs and the result remains unknown and non-retryable.
- **Compatibility and maintenance:** no new migration, OAuth grant, Target permission, MCP tool, installation requirement, default file-transfer setting or new logging backend. The existing v2.3.2 `activity_events.diagnostic_context` migration must already be applied on an installed Gateway. This source change was independently HIGH_ASSURANCE reviewed (**R2 COMPLETE / APPROVE, 0 BLOCKER / 0 REQUIRED**) and integrated through [PR #207](https://github.com/AChWorks/mcp-gateway/pull/207). The previous release v2.3.2 is included in the published-baseline browser-update and backup-integrity CI checks.

**Known limitations:** [Issue #199](https://github.com/AChWorks/mcp-gateway/issues/199) remains open for additional ingress/OAuth/async provenance and real installed-host Admin/AI error, retention, load, memory, latency and log-volume acceptance. Upstream [WordPress MCP Adapter #298](https://github.com/WordPress/mcp-adapter/issues/298) can still remove a native provider error code before Gateway sees it; Gateway cannot reconstruct unobserved codes.

**Operator update:** Install only the official, checksum-verified v2.3.3 fresh-install ZIP or browser-update ZIP from its GitHub Release. If upgrading the existing v2.3.2 installation, preserve its private `.env`, encryption/signing keys, database and storage; take and test-restore a consistent database backup and use the supported browser-update procedure in [README](README.md) and [Deployment](docs/DEPLOYMENT.md). Publishing does **not** modify any running Gateway, run migrations on a host, grant new client permissions, or change a WordPress/SSH Target.

# MCP Gateway v2.3.2

**Stable v2.3.2 — source and published GitHub Release identities are distinct from any installed Gateway.**

Compared with publicly released v2.3.1:

- **Observed error fidelity:** preserve the original provider/MCP/transport error code,
  message and useful structured details as actually received, separate from the
  Gateway compatibility classification. Record the evidenced operation origin,
  stage, outcome certainty, correlation and retry safety; never fabricate a
  WordPress `WP_Error` code stripped upstream.
- **Authorized AI and Admin diagnostics:** a read-only
  `operation-diagnostics-read` MCP Tool and the existing Admin Activity view
  resolve the same canonical, bounded Activity evidence. Per-Target
  `activity.view`, actor/client/profile isolation and effective permissions
  remain enforced at retrieval, including negative/denied lookups; no raw log
  reader or new diagnostics datastore is introduced.
- **Selective confidentiality:** mask credentials, signed URLs and other secret
  values in plain, JSON-escaped and double-serialized URI representations
  before persistence or output, retaining useful nonsecret paths and native
  error context. Budget-limited text marks truncation explicitly. SSH
  pre-dispatch admission denials retain accurate provenance, and ambiguous
  remote effects are **not** reclassified as safe to retry.
- **Additive database migration:** the new
  `2026_10_17_010000_add_activity_diagnostic_context.php` adds one nullable
  JSON `activity_events.diagnostic_context` field to the existing Activity
  records. Existing records require no backfill. The supported updater applies
  the migration when installing this release; rolling it back drops stored
  diagnostic evidence and must not be treated as a harmless code rollback.
- **Upgrade evidence:** source PR #204 passed independent R4
  `COMPLETE / APPROVE` with no blocking or required findings. Its exact
  reviewed HEAD passed six GitHub workflows/seven checks, including MariaDB,
  WP AI Bridge contract and released-baseline update verification.
  The stable promotion also adds the publicly released v2.3.1 baseline
  to the reproducible package/update and backup-integrity acceptance suites.

**Limits:** [Issue #199](https://github.com/AChWorks/mcp-gateway/issues/199)
remains open for wider OAuth/ingress/async provenance, load/retention,
persistence-failure and installed-host Admin/AI verification.
[WordPress/mcp-adapter#298](https://github.com/WordPress/mcp-adapter/issues/298)
can strip original provider codes before Gateway receives them.

A source merge or published GitHub Release does **not** install or update any
operator host, run live migrations, enable features or authorize remote
operations. Use the official checksum-verified release assets and the
operator-controlled supported update path; protect private `.env`, keys,
persistent storage and a verified database backup before a future upgrade.

# MCP Gateway v2.3.1

**Stable v2.3.1 — official GitHub Release and installed-host status must be verified separately.**

Compared with the publicly released v2.3.0:

- **Fresh Direct SSH installs:** authenticated SSH whole-file browser/HTTPS
  transfer is explicitly enabled during new installation. Existing private
  `.env` files and explicit opt-outs remain unchanged; a missing setting
  retains the disabled runtime fallback. This does not add WordPress Bridge
  file exchange or native ChatGPT attachment handoff.
- **Detached SSH Jobs:** the Owner can tune script input to 16–64 KiB
  independently of synchronous commands and 16 KiB per-call SFTP windows.
  Larger scripts use the existing verified streaming transport. The additive
  `2026_10_16_010000_add_ssh_job_script_input_limit.php` migration is required
  on installed hosts before the new Owner setting can be used.
- **Configuration and upgrade safety:** the first-party environment template,
  configuration reference and source-consumer guard cover active and optional
  keys; destructive or sensitive optional settings remain inactive. Upgrade
  acceptance includes the latest published v2.3.0 baseline and checks that
  installed private `.env` data is preserved.
- **Per-Target AI guidance:** an optional short operator note on new and
  existing WordPress/SSH Targets is saved as shared Target metadata and
  exposed only through authorized MCP inventory/context. The note is
  advisory, never an approval token, grant or command execution policy.
  Existing Targets need no manual configuration.
- **Target Admin usability:** the merged Targets inventory distinguishes stored
  WordPress credentials from verified remote OAuth health and offers a clearer,
  responsive Target/Connector/connection/operations/action layout, including
  truthful labels for historic unsupported connector records.
- **Cross-hop WordPress diagnostics:** bounded evidence of the first observed
  failure layer (Gateway outbound, Gateway response limits, downstream HTTP or
  downstream MCP) can be found through an authenticated operation's diagnostic
  reference and existing correlation/Activity logs. A stripped WordPress
  provider error remains unknown, not an invented code. Mutating MCP isError
  never proves rollback or authorizes automatic retry.
- **Release-readiness:** align live fresh-vs-existing-install SSH guidance and
  cover the decoded 64/128/256 KiB WordPress envelope boundaries with
  deterministic connector fixtures. Real host limits and model file handoff
  still require separate post-install evidence.

Stable source promotion does not itself publish a GitHub Release, update an installed
Gateway, run migrations or enable host features. The Owner-approved manual Release
workflow verifies and publishes immutable artifacts from the exact promoted main SHA;
operator-controlled deployment and installed-host acceptance remain separate.

# MCP Gateway v2.3.0

**Stable v2.3.0 — public Release identity and installed-host status are verified separately.**
This promotes the Owner-approved, independently HIGH_ASSURANCE-reviewed
`2.3.0-rc.8` source, including Direct SSH command budgets, retained Jobs and
browser file selection (#181), Owner-only Target Pause/Resume (#189) and the
full retirement of the obsolete Agent connector identity and denial seeding
(#182). The prior security/pause changes were independently reviewed and
merged through [PR #190](https://github.com/AChWorks/mcp-gateway/pull/190);
the final Agent-only source/migration cleanup passed an independent
**COMPLETE / APPROVE** with no required findings, all five exact-head CI
workflows and published-baseline upgrade tests, and merged through
[PR #191](https://github.com/AChWorks/mcp-gateway/pull/191) as
`main@155ae9ff636c63d5b015b9fdbd8ab86ff28ac0e1`.
The [stable promotion PR #188](https://github.com/AChWorks/mcp-gateway/pull/188)
changes VERSION and release/operator documentation **only**, relative to
the independently reviewed and merged rc.8 source. Publication policy
requires exact-stable-HEAD CI, author-separated Owner-mediated review,
and an explicitly approved merged-main SHA; older PR checks cannot replace
those gates. The official GitHub Release is identified by its verified
tag and package assets, **not** by this source VERSION or changelog text.
Publishing a Release does not update an installed host, migrate its
database, or enable optional SSH file transfer.

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
- RC5 serializes Job launch-lease renewal and pre-dispatch lease extension
  against new same-user admissions under the same User-before-Job database
  locks. Every SSH/SFTP Job phase rejects a changed original Target endpoint
  or SSH trust binding before contacting the replacement host; ambiguous
  remote launch remains non-replayable.
- The rc.5 OpenSSH/systemd and MariaDB race evidence originated in
  [historical PR #187](https://github.com/AChWorks/mcp-gateway/pull/187/checks).
  The later rc.7 fixes were independently approved and integrated via
  [PR #190](https://github.com/AChWorks/mcp-gateway/pull/190), and the
  final Agent-only identity/migration cleanup (`rc.8`) was independently
  approved, tested and integrated via
  [PR #191](https://github.com/AChWorks/mcp-gateway/pull/191).
  The [stable promotion PR #188](https://github.com/AChWorks/mcp-gateway/pull/188)
  is the separate stable VERSION/documentation promotion, governed by its own
  exact-head checks and Owner-mediated independent review. Official publication
  binds to the explicitly approved, merged **main SHA** rather than any
  historical PR/check identity. Browser/operator-host acceptance and live
  deployment remain separate.

## Per-Target Pause / Resume (#189)

- The Owner can pause or resume new Gateway operations on any registered
  WordPress or SSH Target from the Target list or details. Pause is a durable,
  default-false **operations_paused** flag independent of Connected status.
  It preserves the saved endpoint, credentials, OAuth grants, Target groups,
  permission denials and SSH Job journal. Pausing is not remote revocation,
  cancellation, or evidence that an already-running remote Job stopped.
- MCP inventory and target-context identify an authorized paused Target,
  while operation-mode discovery is suppressed. Fresh server-side checks on
  WordPress Ability dispatch, SSH exec/SFTP, Job start/stages and browser/HTTP
  file transfer deny new work with target_paused, without disclosing
  unauthorized Targets. Safe local management and credential recovery remain.
- An additive migration enables old/new Targets by default; Owner POST action
  is idempotent, audited and protected by existing web/CSRF boundaries.
  Independent R2 delta review of rc.7 APPROVED; all five exact rc.7 checks PASSED.

## SSH file exchange and connector presentation

- Authenticated Admin Target details gain a **browser file picker upload**
  and forced download form that reuse the existing SFTP/whole-file SHA-256
  transfer engine and registered Target permissions. They are disabled by
  default (`SSH_FILE_TRANSFER_ENABLED=false`); this is a browser fallback,
  **not native ChatGPT attachment handoff**. Exact binary SHA-256, create-only
  denial and explicit overwrite passed a real disposable OpenSSH fixture.
- Fully retire the never-implemented AI Server Agent-specific UI/permissions,
  `ai_server_agent` supported stored connector identity and obsolete
  `agent.*` historical Target migration seeding/allowlist (#182), as
  explicitly authorized for the Owner's **single managed installation**.
  Keep the generic historical migration, all shared Target tables,
  WordPress/SSH registration and conservative non-Owner SSH default-deny.
  The Owner verified zero Agent records across six relevant database
  locations; no cleanup migration, installed DB DELETE or replay of an
  already-applied Target migration is required. These changes were validated
  by a clean MariaDB install, ten published-baseline update tests and
  independently verified candidate install/update artifacts.

## Upgrade, security and rollback

- Five additive migrations: SSH command operational-limit columns, durable
  `ssh_command_jobs` journal, typed Job lifecycle/attestation policy, immutable
  per-Job admission timing and per-Target operations-paused state (operations
  enabled by default). **A consistent, test-restored DB backup is required
  before an eventual operator upgrade.** The journal's rollback
  guard refuses dropping it while any job record remains; do not erase
  unknown jobs to force migration rollback. Browser-updater code backups do
  not reverse database changes.
- Refresh locked `symfony/http-foundation` from 8.1.6 to 8.1.9 to remediate
  advisory **CVE-2026-108082**, with Composer audit verified locally.
- No production Target, OS user, host setting, OAuth credential, or
  `SSH_FILE_TRANSFER_ENABLED` setting is modified by publishing source or a
  package. Changes to an actual installed host require a separate authorized
  deployment and compatibility/rollback checks.
- rc.5 source was integrated through [PR #187](https://github.com/AChWorks/mcp-gateway/pull/187),
  rc.7's independently approved Pause/Resume and authorization correction
  through [PR #190](https://github.com/AChWorks/mcp-gateway/pull/190), and
  independently approved rc.8 final Agent identity/migration retirement
  through [PR #191](https://github.com/AChWorks/mcp-gateway/pull/191).
  [PR #188](https://github.com/AChWorks/mcp-gateway/pull/188) is the distinct
  stable VERSION/docs-only promotion; its own exact-head checks and independent
  review are release-policy gates, not substitutes for the source reviews.
  The official Release and an operator-host upgrade remain separate;
  preserve a test-restorable database backup for installation.

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
