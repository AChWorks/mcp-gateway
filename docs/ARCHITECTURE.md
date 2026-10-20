# MCP Gateway — Architecture

**Scope:** the source-level component boundaries and extension seams of the Gateway application. The [Master Specification](MASTER-SPEC.md) defines enduring product requirements; [Target/connector contract](TARGET-CONNECTOR-FOUNDATION.md), [remote I/O contract](REMOTE-IO-CONTRACT.md) and specialist guides define the corresponding detailed rules. Class and route references describe the application and should be checked against the selected code revision before changing implementation.

## 1. Runtime topology

```text
    Authenticated AI / MCP client              Authenticated browser operator
                     |                                     |
           HTTPS OAuth + /mcp                  HTTPS session + /admin
                     |                                     |
         MCP protocol / transport                      Admin controllers
                     \                                     /
                      \---- application Target/access ----/
                                      |
                     Connector registry + specific operations
                              /                    \
                WP AI Bridge Target           Direct SSH Target
              HTTPS OAuth + MCP call        SSH / SFTP / systemd Jobs
                              \                    /
                       Registered downstream systems

            MariaDB/MySQL + private keys, sessions and spool
```

The deployed application is PHP/Laravel with one authenticated public MCP endpoint and a server-rendered Blade Admin. Private keys, encrypted Target credentials and temporary data remain outside `public/`. The normal hosting profile needs no mandatory separate daemon, Redis, message broker or Node production build. Remote **SSH Jobs** may use the *Target host's own* supported systemd user or root manager; that is not a Gateway-host worker.

A separate, optional authenticated `/mcp/file-transfer/ssh/{targetId}/upload|download` HTTPS binary sidecar serves **supported SSH whole-file operations**. It is not an additional MCP server and is gated by effective configuration, authenticated identity, Target permissions, safe spool admission and SSH destination trust. The normal MCP JSON Tool payload is not a general binary-file transport.

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
| Safe outbound HTTP | [`SafeHttpClient`](../app/Infrastructure/Http/SafeHttpClient.php) | HTTPS origin/DNS/peer/TLS policy and bounded decoded responses |
| Diagnostics and Activity | [`OperationDiagnostics`](../app/Support/OperationDiagnostics.php), [`ActivityRecorder`](../app/Infrastructure/Activity/ActivityRecorder.php) | Safe classifications, correlation and bounded audit rather than raw remote payloads |
| Bounded runtime settings | [`OperationalSettings`](../app/Application/Operations/OperationalSettings.php) | One typed persisted Owner settings subsystem with validated source fallbacks |

These layers are **not interchangeable**: `TargetConnectorAdapter` is a lifecycle/metadata interface and **does not** currently provide one generic invocation method for all WordPress/SSH business actions. Likewise, an existing MCP Tool handler is not a contract granting a matching Admin action automatically.

## 3. Real request paths

### Registered Target discovery

The authenticated client requests a bounded list or one explicit Target context. Gateway evaluates its real user/client scope and connector metadata through the local registry and database. Listing is indexed/paged and **does not contact every downstream Target** or synthesize a tool instance per Target. A registered hostname or cached IP alone never becomes a verified SSH peer identity.

### WordPress Ability invocation

The MCP entry validates the exact `target_id`, input and Gateway permission class. The connector uses the Target-bound authenticated WordPress MCP identity to discover the relevant actual Ability schema/effect and execute it. A compatible newly added WordPress Ability may be reached without adding a public Gateway Tool; the selected user/client/Target grants and downstream WordPress principal still govern access. A missing or unclassified annotation does not invent either a ban or a grant.

The transport and downstream result remain separate: a downstream text-only error cannot be retroactively assigned a specific original WordPress error code that was not received. A mutation after possible remote dispatch does not become safe to retry merely because its response failed.

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

**Implemented boundary (first #200 slice):** the shared Target/Access/Group/credential/Activity infrastructure and specific MCP WordPress/SSH execution families. `WordpressTargetOperations` is now a shared application-owned use case for WordPress Ability catalog and execution, consumed unchanged by the MCP entry and one **strictly read-only** Admin `wp-ai-bridge/bridge-info` operation on an authorized selected Target. The browser route is POST+CSRF+throttle; it requires `targets.view` and `wordpress.abilities.execute.readonly` on the exact Target and refuses unclassified/mutating/destructive metadata regardless of other grants. No Admin-to-own-MCP HTTP call is used. The entry-time effective permission decisions are an **upper bound**, not a permanent grant: after trusted downstream classification, the shared service reloads the current User and exact Target-scoped permission immediately before dispatch (and the Admin read-only pilot rechecks `targets.view`), followed by the existing fresh Target Pause fence. Later grants never elevate an initially denied execution class. Admin is **not** yet a general-purpose Ability browser, semantic publisher or group publisher; these remain future #200 stages with separate approved acceptance.

**Restricted publication source slice (#200 Phase B, integrated in main):** `wordpress-content-publish-create` exposes a fixed `wp-ai-bridge/content-upsert` invocation with `action=create`, `post_type=post`, `status=publish`, a bounded title/body and stable caller `operation_id` deterministically namespaced by **Gateway User, stable Target, authenticated upstream AI client (or independent human channel), and caller operation ID** before the upstream Bridge reserves create identities (avoids cross-user, cross-client, cross-Target and human/AI duplicate-key interference while preserving safe retry identity). It checks the actual registered Bridge schema/classification, Owner-managed `User + Target Group` semantic grants for non-Owner roles, normal effective Target/role/global/group/direct denies, current User and AI connection flag/profile **plus the exact originating OAuth token and consent** near dispatch, Target Pause and a no-blind-retry/unknown outcome. Ordinary `Operator` or `Administrator` roles may receive this narrower permission **without** automatically receiving AI connectivity. Broad dynamic `wordpress-ability-execute` remains separately controlled by the four existing effect permissions; a restricted semantic grant cannot be used as generic mutation authority. The service can also be invoked by a properly authenticated human adapter without any AI client, but **no human Admin publishing form or live content pilot is delivered by this slice**. On the single existing install only Owner exists; the schema change grants AI to that Owner, not to hypothetical other legacy accounts. No real WordPress publish operation or upstream change is included in source tests.

**Intended extension:** move only the operation rules needed by a genuine additional consumer into small reusable application use cases. Do **not** route Admin through public `/mcp`, create a second authorization service, overload the lifecycle `TargetConnectorAdapter` with speculative methods or add an unproven workflow engine.

- **Another client profile:** adapt authentication/consent, retain exactly the same Target access and operation model.
- **Another compatible Target-side Ability/tool:** re-read the Target-owned catalog/schema under the existing reviewed connector and current permissions, not a public Tool per capability.
- **Another authenticated MCP-speaking Target:** introduce only a reviewed registration/authentication/transport adapter; standard `tools/list`/`tools/call` reuse is an interoperability design, **not** evidence arbitrary MCP servers can be enrolled now.
- **Human-executable or multi-Target operations:** resolve selected Targets, apply the same per-Target admission near dispatch, preserve partial/unknown outcomes, and add durable bulk state only where the concrete workflow requires it.
- **Additional data path:** use shared resource/integrity/authorization semantics with connector/native transport adapters and proven receiving-client support; never assume one generic Gateway storage/stream service makes every provider file-capable.

Runtime implementation and acceptance should be checked in the selected Git revision, tests and the owning work item. This architecture describes responsible components and safe extension seams, not a release chronology or an alternative backlog.
