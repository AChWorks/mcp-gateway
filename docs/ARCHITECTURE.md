# MCP Gateway — Architecture

**Scope:** the source-level component boundaries and extension seams of the Gateway application. The [Master Specification](MASTER-SPEC.md) defines enduring product requirements; [Target/connector contract](TARGET-CONNECTOR-FOUNDATION.md), [remote I/O contract](REMOTE-IO-CONTRACT.md) and specialist guides define the corresponding detailed rules. Class and route references describe the application and should be checked against the selected code revision before changing implementation.

## 1. Runtime topology

```text
    Authenticated AI / MCP client             Authenticated browser operator
                    |                                      |
          HTTPS OAuth + /mcp                   HTTPS session + /admin
                    |                                      |
         MCP protocol / transport                     Admin controllers
                    \                                      /
                     \-- application Target/access -----/
                                      |
                         Registered connector adapters
                        /              |             \
           WP AI Bridge Target    Direct SSH Target   ArvanCloud API Target
           HTTPS OAuth/MCP       SSH/SFTP/Jobs        Fixed-origin HTTPS REST
                        \              |             /
                         \------ downstream systems-/

                MariaDB/MySQL + private keys, sessions and spool
```

Optional **connection routing** does not create another Target connector: SSH and WordPress Targets may explicitly use one shared [native OpenSSH/SOCKS5 Connection Relay](CONNECTION-RELAYS.md), while an inbound-blocked SSH Target may use a [managed](REVERSE-SSH-MANAGED.md) or [manual](REVERSE-SSH-OPERATOR.md) Reverse SSH route. The selected connector still verifies the actual remote identity and credentials, and normal Direct routing stays independent. The routing guides own setup, behavior and supported acceptance; this architecture does not duplicate their operating procedures.

The deployed application is PHP/Laravel with one authenticated public MCP endpoint and a server-rendered Blade Admin. Private keys, encrypted Target credentials and temporary data remain outside `public/`. The normal hosting profile needs no mandatory separate daemon, Redis, message broker or Node production build. Remote **SSH Jobs** may use the *Target host's own* supported systemd user or root manager; that is not a Gateway-host worker.

A separate, optional authenticated `/mcp/file-transfer/ssh/{targetId}/upload|download` HTTPS binary sidecar serves **supported SSH whole-file operations**. It is not an additional MCP server and is gated by effective configuration, authenticated identity, Target permissions, safe spool admission and SSH destination trust. The normal MCP JSON Tool payload is not a general binary-file transport.

### V3 shared durable Target Batch source (installed version separately verified)

In the **v3** source (see [VERSION](../VERSION)), `TargetBatchPlanner` and `TargetBatchCoordinator` implement exact selection, `AccessControl` policy, preview binding, durable idempotent journal, status, cancellation and encrypted results. `DeferredBatchAuthority` retains **verified** Web-session or OAuth Client/Consent provenance (never the bearer token) for later revalidation; a client disconnect or ordinary bearer expiry does not retroactively cancel authorized queued work. Current revocation, lost Target binding, pause and capability deny still stop **new** remote effects. Original Batch consent and profile generation remain persisted execution provenance; a different valid current authorization for the same User/Client can read or recover the historical `request_id` without re-admission, but cannot make queued effects under the old revoked authorization executable. `TargetBatchWorker` coordinates PHP CLI worker processes using MariaDB row locks, per-Batch and global active budgets, dispatch leases and non-replayable unknown outcomes. Each child is recorded in `target_batch_items` and its parent in `target_batches`. `gateway:batch-work` is available to the Laravel Scheduler or explicitly launched workers; the built-in single default scheduler process does not constitute a measured multi-host concurrency guarantee.

The shared core obtains current Target identity from an **optional connector-owned** `TargetBatchBindingContributor`, not SSH/WordPress `switch` branches; each adapter proves only its own native endpoint/credential/trust or durable consent binding. Absent capability/invalid state/Pause => no deferred dispatch. `TargetBatchOperationProvider` declares the operation's remote duration for the shared dispatch lease, which enables future registered providers without adding connector-specific timeout branches to the Worker. Active Batch scanning uses bounded keyset pages and durable **parent round-robin turns** rather than always restarting from the oldest created Batch. Under the existing globally locked admission row, every child claim atomically advances a monotonically increasing internal turn and records it on its parent; this preserves fairness after PHP worker restarts without relying on wall clocks, another queue service or a per-Target agent. An independent newer Batch gets a turn while an older Batch still has many runnable children. Parent ordering is rechecked against the locked current turn before any child claim; if another worker moved the pre-lock candidate, the worker restarts its bounded keyset scan rather than spending a second slot on stale priority. Contention rescans are bounded by the existing configured global active budget, and a later scheduled call can resume work; remote transport never runs under admission locks. **Concurrent** mode can select an independent eligible child while the first Target is busy in another Batch, but **rolling** mode waits for the original first queued Target to preserve declared order. Global/user/per-Target limits and no-replay `outcome_unknown` remain authoritative. This is explicitly not a generic connector operation runner or proof that every Target type supports Batch.

The first two audited `TargetBatchOperationProvider`s are `SshCommandBatchProvider` (delegates to existing verified SSH command runtime) and `WordpressBridgeInfoBatchProvider` (only the read-only `wp-ai-bridge/bridge-info` Ability, under existing WordPress authorization). Neither introduces a new SSH transport, external Agent, general-purpose executor, WordPress bulk publishing or a dynamic provider loader. `TargetBatchMcpToolRegistrar` exposes fixed typed MCP tools; `TargetBatchController` exposes session+CSRF browser JSON endpoints using the **same** shared Core. The original MCP Endpoint transport now composes focused registrars rather than owning all tool declarations. The future discovery strategy in Issue #327 remains **parked and unchanged**. These boundaries require future acceptance and additional features per [Issue #330](https://github.com/AChWorks/mcp-gateway/issues/330); they are not claims about the installed v2.7.3 release.

### Canonical permission boundary and Owner audit (#226 / v3)

The permission authority remains `GatewayRole` (role ceiling), `GatewayPermission` (capability names), and `AccessControl` (enabled account, global denies, Target scope, Group/direct denies, connector support). Owner recovery is explicit. AI admission additionally requires a verified OAuth User, Client/Profile, unrevoked consent and `ai_access_enabled`; it never inherits an Admin session, and a stale bearer token never substitutes for authority. The separate HTTP/Web Batch adapter uses the same application Batch Coordinator, but authenticated Session+CSRF as its origin. These are **code-owned decisions**, not new declarative permissions from this documentation.

### Issue #226 source authorization audit (completed; v3 installation acceptance separate)

[Issue #226](https://github.com/AChWorks/mcp-gateway/issues/226) verified **source and fixture** coverage of **28 permissions, four roles, 82 Admin routes and 30 standard MCP Tool registrations**. It is **closed for the source audit only**; real installed-v3 User/Client/Target/Group tests remain in [#330](https://github.com/AChWorks/mcp-gateway/issues/330). Detailed historical audit observations and the complete Role × Permission × Connector matrix belong to the [completed Issue](https://github.com/AChWorks/mcp-gateway/issues/226) and exact tests, **not** a copied second permissions registry in this document.

**Code authority:** [`GatewayRole::permissions()`](../app/Domain/Access/GatewayRole.php) determines the role ceiling; [`GatewayPermission::cases()` and exhaustive `targetApplicability()`](../app/Domain/Access/GatewayPermission.php) determine permission vocabulary and exact connector scope; [`AccessControl`](../app/Application/Access/AccessControl.php) determines effective role, User status, global Deny, Target scope, direct/group Deny and connector compatibility. Target selection grants reachability, **not** a missing capability. Multiple Group denials accumulate. Owner's recovery privilege does **not** make a WordPress-only permission valid for an SSH or ArvanCloud Target; an unknown future permission cannot implicitly default to all connectors. A checked Deny never grants access.

**Entry boundaries:** authenticated/CSRF-protected Human Admin routes use current User authority; OAuth-authenticated `/mcp` and file-transfer routes additionally enforce original User/Client/Profile/Consent, `ai_access_enabled`, Target and provider authority. A valid access token, a Tool listed in `tools/list`, a cached Target connection, an authorized Group or a prior verified SSH login cannot override a later revocation, changed Target binding, Pause or the remote account's real capabilities. Deferred Batch persists the verified original authority and rechecks it **before each not-yet-dispatched remote effect**; bearer expiry alone does not invalidate a durable grant, but revocation does. A successful or uncertain remote effect is never silently reexecuted to enforce a later policy change.

**Specialized effects:** `wordpress-content-publish-create` requires its separate positive User × Group publication grant; SSH command execution can exercise the remote OS account's privileges and is **not** sandboxed by SFTP Deny; `ssh-file-patch` preview and apply have distinct read/write rights; retained Jobs and Batch status/cancel remain bound to their original actors. FileParams registrations (`wordpress-file-input`, `target-file-input`) remain **OFF** unless the actual supported host supplies the required typed file argument and explicit Owner setting.

**Regression ownership:** [AccessControlTest](../tests/Feature/Security/AccessControlTest.php) exhaustively checks role/permission/connector decisions and real scoped queries; [AuthorizationRouteBoundaryTest](../tests/Feature/Security/AuthorizationRouteBoundaryTest.php) checks mounted Admin and MCP boundaries. Connector-specific tests cover Group overlap, OAuth consent/revocation, Job/file identity and Batch deferred authority. CI's MariaDB, Chromium and pinned OpenSSH fixtures prove their own tested paths, **not** a live v3 deployment.

## 2. Component ownership

| Concern | Source entry point | Boundary |
| --- | --- | --- |
| Target definition, connector registration | [`TargetConnectorRegistry`](../app/Application/Targets/TargetConnectorRegistry.php), [`TargetConnectorAdapter`](../app/Application/Targets/TargetConnectorAdapter.php) | Explicit, built-in connector types; no remote-supplied executable loader |
| User/role/Target/group grants | [`AccessControl`](../app/Application/Access/AccessControl.php), [`GatewayPermission`](../app/Domain/Access/GatewayPermission.php) | Actual authorization and anti-enumeration selection |
| AI/MCP entry | [`GatewayMcpEndpoint`](../app/Infrastructure/Mcp/GatewayMcpEndpoint.php), [`routes/mcp.php`](../routes/mcp.php) | Client-facing Tool schemas, authentication, request parsing and routing |
| AI dispatch revocation fence | [`McpDispatchAdmission`](../app/Application/Mcp/McpDispatchAdmission.php), [`AccessTokenRepository`](../app/Infrastructure/OAuth/League/Repositories/AccessTokenRepository.php) | Revalidates the exact middleware-authenticated token/consent plus original user/client/profile/resource/scope before external effects; separate from human operational permissions |
| Admin entry | [`routes/admin.php`](../routes/admin.php), `app/Http/Controllers/Admin` | Browser login/CSRF, Target lifecycle, groups, grants and operator settings |
| WordPress Ability execution | [`WordpressTargetOperations`](../app/Application/Targets/WordpressTargetOperations.php), [`WordpressTargetMcpToolHandlers`](../app/Application/Mcp/WordpressTargetMcpToolHandlers.php), [`WpAiBridgeMcpClient`](../app/Infrastructure/Connectors/WpAiBridge/WpAiBridgeMcpClient.php) | One shared authorization/Target/Pause/Activity/result path, presented by MCP and a bounded read-only Admin operation; downstream authentication, dynamic Ability catalog and effect classification |
| WordPress connection lifecycle | [`WpAiBridgeTargetConnectionService`](../app/Application/Targets/WpAiBridgeTargetConnectionService.php) | OAuth intent/recovery, exact credential/Target identity and remote lifecycle |
| SSH identity and execution | [`SshVerifiedTransport`](../app/Infrastructure/Connectors/SshDirect/SshVerifiedTransport.php), [`SshJobCoordinator`](../app/Application/Targets/SshJobCoordinator.php) | Approved numeric peer and pinned host key before credentials; separate sync/SFTP/retained Job semantics |
| Binary SSH exchange | [`TargetTransferCapabilities`](../app/Application/Files/TargetTransferCapabilities.php), [`SshWholeFileTransfer`](../app/Application/Files/SshWholeFileTransfer.php), [`SshWholeFileController`](../app/Http/Controllers/Mcp/SshWholeFileController.php) | Permission-filtered mode discovery, binary admission/staging, verified source/destination |
| ArvanCloud REST operations | [`ArvanApiOperations`](../app/Application/Targets/ArvanApiOperations.php), [`ArvanApiTargetAdapter`](../app/Infrastructure/Connectors/ArvanCloud/ArvanApiTargetAdapter.php) | Bound Machine User key, exact registered API root, Target-scoped HTTP method permissions, safe lifecycle/Test and uncertain remote mutation outcomes |
| Shared REST and OpenAPI primitives | [`ApiHttpTransport`](../app/Infrastructure/Http/Api/ApiHttpTransport.php), [`OpenApiOperationCatalog`](../app/Infrastructure/Http/Api/OpenApiOperationCatalog.php) | Safe fixed-origin HTTP execution and untrusted public OpenAPI catalog parsing; no arbitrary client-supplied origin or credential |
| Safe outbound HTTP | [`SafeHttpClient`](../app/Infrastructure/Http/SafeHttpClient.php) | HTTPS origin/DNS/peer/TLS policy and bounded decoded responses |
| Optional Target endpoint preflight | [`TargetEnrollmentPreflight`](../app/Application/Targets/TargetEnrollmentPreflight.php), [`TargetEndpointPreflight`](../app/Application/Targets/TargetEndpointPreflight.php) | One authenticated read-only Admin entry and typed HTTPS/SSH public-address policy checks; no provider contact, trust grant or credential use |
| Diagnostics and Activity | [`OperationDiagnostics`](../app/Support/OperationDiagnostics.php), [`ActivityRecorder`](../app/Infrastructure/Activity/ActivityRecorder.php) | Safe classifications, correlation and bounded audit rather than raw remote payloads |
| Bounded runtime settings | [`OperationalSettings`](../app/Application/Operations/OperationalSettings.php) | One typed persisted Owner settings subsystem with validated source fallbacks |

These layers are **not interchangeable**: `TargetConnectorAdapter` is a lifecycle/metadata interface and **does not** currently provide one generic invocation method for all WordPress/SSH business actions. Likewise, an existing MCP Tool handler is not a contract granting a matching Admin action automatically.

## 3. Real request paths

### Registered Target discovery

The authenticated client requests a bounded list or one explicit Target context. Gateway evaluates its real user/client scope and connector metadata through the local registry and database. Listing is indexed/paged and **does not contact every downstream Target** or synthesize a tool instance per Target. A registered hostname or cached IP alone never becomes a verified SSH peer identity.

### WordPress Ability invocation

The MCP entry validates the exact `target_id`, input and Gateway permission class. The connector uses the Target-bound authenticated WordPress MCP identity to discover the relevant actual Ability schema/effect and execute it. A compatible newly added WordPress Ability may be reached without adding a public Gateway Tool; the selected user/client/Target grants and downstream WordPress principal still govern access. A missing or unclassified annotation does not invent either a ban or a grant.

The transport and downstream result remain separate: a downstream text-only error cannot be retroactively assigned a specific original WordPress error code that was not received. A mutation after possible remote dispatch does not become safe to retry merely because its response failed.

### ArvanCloud REST/OpenAPI requests

An authenticated client selects an already registered `arvancloud` Target. The `arvan-api-catalog` tool reads optional public OpenAPI/Swagger metadata as untrusted **descriptions**, never as authorization; the `arvan-api-request` tool executes a compatible method and relative path against that Target's fixed HTTPS API root using its encrypted, bound Machine User key. The connector enforces exact role/user/client/Target scope, method-class permission, fresh Pause and credential revision checks, HTTPS DNS/TLS identity and redirect rejection. It does **not** grant arbitrary HTTP host selection, S3 SigV4 operations or resumable/binary streaming. A saved Target, source CI or published GitHub Release is not authenticated real-provider proof; [ArvanCloud operator guidance](ARVANCLOUD-API-CONNECTOR.md) and [Issue #310](https://github.com/AChWorks/mcp-gateway/issues/310) own that acceptance.

### Direct SSH actions and Jobs

An SSH request selects an **already enrolled** Target, checks the exact user/client capability and the current Target operations gate, then validates the approved resolved numeric TCP peer and independently pinned SSH **server host key before login**. The remote OS account determines command authority. Non-interactive synchronous exec, SFTP stat/list/ranged read/small write and detached systemd Jobs have **different budgets, confirmation and continuation semantics**.

The retained Job journal associates `request_id`, `job_id`, actor/client and original remote identity before effectful dispatch. Job polling/output/cancel reauthenticate and reauthorize new stages. A lost launch or uncertain cancellation cannot be blindly replayed. Connection metadata, exit marker and remote unit state are observed honestly rather than inventing confirmed completion.

### Whole-file SSH binary exchange

The public authenticated raw-HTTPS sidecar validates client/User/Target/operation permissions, finite object size/time and effective mode, then uses private local/remote staging and already verified SFTP operations. Upload publication and download receipt/integrity are distinct guarantees. The client must separately understand and receive that mode; `target-context` metadata or a server path does not guarantee the host supplied model-readable file bytes.

## 4. Security and operational state

**The identity chain** is Gateway principal + exact authenticated client profile/ID where applicable + immutable Target record/public key + connector family + downstream principal. A Target display name, URL, connected flag, OAuth profile label or Tool annotation cannot override it.

- `AccessControl` combines role ceilings, global grants/denials, selected Target reachability, group and direct restrictions; the Owner's recovery authority and non-Owner SSH default restrictions remain explicit. Gateway scope can only narrow downstream permissions.
- AI/MCP connectivity is a separate **account-level admission gate**, not another Role or a Target permission. `users.ai_access_enabled` defaults to false for new accounts. Only the installed Owner is enabled by the additive upgrade; first-run bootstrap creates an enabled Owner. `AuthorizationController`, token repositories/recovery and `RequireMcpAccessToken` all enforce the same per-user gate. Disabling it revokes OAuth authorizations immediately, including prior tokens; re-enabling never revives revoked consent. The human Admin session and authorized non-AI capabilities remain independent. The request middleware additionally binds the validated **exact access-token ID** and server-verified user/client/profile to the request. `McpDispatchAdmission` uses only that trusted request context to requery the original token **and its specific consent** at effectful WordPress classification/dispatch, SSH post-login command, SFTP staged writes/publication and retained Job stages; user-supplied Tool arguments cannot provide or override these identities. The check is channel-aware and does not alter human `AccessControl`. For both channels, inline and streamed SFTP writes also reload the current User and Target and reapply `ssh.file.write` role/scope/global/direct/group denies, connected identity and Target Pause before staging/payload batches and immediately before the exclusive hardlink or POSIX rename that makes a file visible. The same guard compares immutable scalar identity from the actually authenticated SSH session against current config/credential records: exact Target and config/credential record IDs, host/port/OS user/authentication method/pinned host key through `SshTargetBinding`, and a fingerprint of the original encrypted credential. Credential replacement/deletion or endpoint rebinding invalidates the old session even after independent verification returns the same Target to Connected; an unchanged binding or a new authenticated operation remains valid. This reuses the post-login trust check without decrypting secrets per block or holding database locks during network I/O. A valid OAuth channel or earlier SSH login cannot preserve revoked operational authority through a long transfer; failure after staging retains the conservative `outcome_unknown` and cleanup semantics.
- Target lifecycle and credential persistence use connector-specific encrypted, purpose-bound material. New/rotated endpoint or credential identities require appropriate revision fencing and fresh verification. WordPress pending refresh/disconnect and confirmed remote revocation are different states.
- Network requests are bounded and trust-checked according to their actual protocol. HTTPS/DNS/SSRF pinning applies to the approved HTTP path; the SSH transport separately verifies numeric TCP peer and pinned host key. Do not mechanically reuse one protocol's timeout or URL policy for the other.
- Stored `connected`, recent test, `stale` and Owner-paused operations are separate: inventory does not perform implicit health probes; Pause blocks newly admitted Gateway remote stages without undoing already-dispatched effects.
- Long HTTP/OAuth/SSH remote requests do not hold a database row lock for their whole network lifetime. Short prepare/fence/finalize stages prevent stale responses from reviving revoked credentials, changed Target configurations or forgotten Jobs.
- Errors and activity have bounded public classifications and safe private correlation. Internal topology, private paths, credential values and arbitrary command contents do not belong in ordinary client-facing messages.
- An Activity-store failure must not change the authoritative effect outcome. Its fallback warning preserves the operation/correlation/Target, storage failure stage, exception class, native code and selectively redacted driver cause; it must never log an exception-formatted SQL statement with bound input values.

## 5. Extension seams

```text
  Admin actions        MCP / AI tools          Supported external API
       \                     |                         /
        \-- authenticated adapter-specific input ---/
                              |
                application operation use cases
            authorize + bind Target(s) + admit budget
                              |
                   connector-owned executor
                              |
             outcome certainty + correlated Activity
```

**Implemented boundary (first #200 slice):** the shared Target/Access/Group/credential/Activity infrastructure and distinct MCP WordPress/SSH/ArvanCloud execution families. `WordpressTargetOperations` is now a shared application-owned use case for WordPress Ability catalog and execution, consumed unchanged by the MCP entry and one **strictly read-only** Admin `wp-ai-bridge/bridge-info` operation on an authorized selected Target. The browser route is POST+CSRF+throttle; it requires `targets.view` and `wordpress.abilities.execute.readonly` on the exact Target and refuses unclassified/mutating/destructive metadata regardless of other grants. No Admin-to-own-MCP HTTP call is used. The entry-time effective permission decisions are an **upper bound**, not a permanent grant: after trusted downstream classification, the shared service reloads the current User and exact Target-scoped permission immediately before dispatch (and the Admin read-only pilot rechecks `targets.view`), followed by the existing fresh Target Pause fence. Later grants never elevate an initially denied execution class. Admin is **not** yet a general-purpose Ability browser, semantic publisher or group publisher; these remain future #200 stages with separate approved acceptance.

**Restricted publication source slice (#200 Phase B, integrated in main):** `wordpress-content-publish-create` exposes a fixed `wp-ai-bridge/content-upsert` invocation with `action=create`, `post_type=post`, `status=publish`, a bounded title/body and stable caller `operation_id` deterministically namespaced by **Gateway User, stable Target, authenticated upstream AI client (or independent human channel), and caller operation ID** before the upstream Bridge reserves create identities (avoids cross-user, cross-client, cross-Target and human/AI duplicate-key interference while preserving safe retry identity). It checks the actual registered Bridge schema/classification, Owner-managed `User + Target Group` semantic grants for non-Owner roles, normal effective Target/role/global/group/direct denies, current User and AI connection flag/profile **plus the exact originating OAuth token and consent** near dispatch, Target Pause and a no-blind-retry/unknown outcome. Ordinary `Operator` or `Administrator` roles may receive this narrower permission **without** automatically receiving AI connectivity. Broad dynamic `wordpress-ability-execute` remains separately controlled by the four existing effect permissions; a restricted semantic grant cannot be used as generic mutation authority. The service can also be invoked by a properly authenticated human adapter without any AI client, but **no human Admin publishing form or live content pilot is delivered by this slice**. Historically, the additive v2 AI-access migration enabled the observed Owner only; it did not grant hypothetical legacy accounts AI access. The clean v3 installer initializes its own Owner and does not migrate v2 Users or grants. No real WordPress publish operation or upstream change is included in source tests.

**Intended extension:** move only the operation rules needed by a genuine additional consumer into small reusable application use cases. Do **not** route Admin through public `/mcp`, create a second authorization service, overload the lifecycle `TargetConnectorAdapter` with speculative methods or add an unproven workflow engine.

- **Another client profile:** adapt authentication/consent, retain exactly the same Target access and operation model.
- **Another compatible Target-side Ability/tool:** re-read the Target-owned catalog/schema under the existing reviewed connector and current permissions, not a public Tool per capability.
- **Another authenticated MCP-speaking Target:** introduce only a reviewed registration/authentication/transport adapter; standard `tools/list`/`tools/call` reuse is an interoperability design, **not** evidence arbitrary MCP servers can be enrolled now.
- **Human-executable or multi-Target operations:** resolve selected Targets, apply the same per-Target admission near dispatch, preserve partial/unknown outcomes, and add durable bulk state only where the concrete workflow requires it.
- **Additional data path:** use shared resource/integrity/authorization semantics with connector/native transport adapters and proven receiving-client support; never assume one generic Gateway storage/stream service makes every provider file-capable.

Runtime implementation and acceptance should be checked in the selected Git revision, tests and the owning work item. This architecture describes responsible components and safe extension seams, not a release chronology or an alternative backlog.

## Adjacent lifecycle and retention audit (Package A source review)

This is a **source-level** inventory, not a claim about installed-host backlog. Only confirmed forward-progress defects were changed; unknown remote effects are never cleaned on age alone.

| Resource | Creation / lifecycle owner | Expiry and cleanup path | Source assessment |
| --- | --- | --- | --- |
| SSH Jobs / original remote spool | `SshJobCoordinator`, retained original user/Target/systemd identity | Hourly persisted keyset prune + stale status reconciliation; stopped unit and private remote spool verified before delete, unresolved retained for operator | **Confirmed starvation fixed in candidate**; installed-host reconciliation still pending |
| WP AI Bridge idle refresh | `WpAiBridgeTargetConnectionService`, credential metadata and one-shot intent | Minute scheduler uses persisted due-date + Target keyset progress, preserving unresolved refresh/revocation intents | **Confirmed due-head starvation fixed in candidate**; no automatic replay of ambiguous rotation |
| OAuth DCR registrations | `DcrClientRegistration` | Serialized capacity pressure reclaims only positively never-authorized identities older than 24h | Healthy bounded admission; no unconditional deletion of revoked identity/history |
| OAuth refresh recovery / assertion anti-replay | `RefreshTokenRecoveryStore`, `ClientAssertionReplayStore` | Expired recoveries and assertion tokens deleted on their relevant authenticated operations; recovery rows capped | Bounded/on-demand cleanup, no repeating blocked head |
| OAuth authorization codes and bearer/refresh token history | OAuth repositories / grant revocation | Expiry is enforced on access; no universal scheduled historical-row deletion | **Retention-policy decision pending**: not safe to add arbitrary deletion of grant history without scope, consent and recovery audit |
| MCP SDK session files | Official `mcp/sdk` `FileSessionStore` | SDK probability-based session GC; lock-aware expired file removal | Existing SDK path, not a confirmed blocked-head defect; high-volume scans should be measured |
| ChatGPT temporary file admission | `ChatGptFileCapacity` with transactional lease | Expired leases cleared under admission lock; `php://temp` releases on PHP worker exit | No blocked-head dependency; actual host disk pressure remains environment-specific |
| Activity events | `ActivityRetention` with persistent lock | Daily age/row-count prune in bounded forward batches | Existing scheduled drain has progress guard |
| Browser installer/updater staging and code backups | Authenticated installer/updater state machine | Proven completed-phase cleanup; recovery-required state and private backups preserved | Must not erase unknown updater or diagnostic evidence based on age |

The source-level inventory does not authorize a Production cleanup or a new OAuth credential-retention period. Review each stored authorization/grant class before a separate retention policy is approved.
