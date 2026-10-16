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
| Admin entry | [`routes/admin.php`](../routes/admin.php), `app/Http/Controllers/Admin` | Browser login/CSRF, Target lifecycle, groups, grants and operator settings |
| WordPress Ability execution | [`WordpressTargetMcpToolHandlers`](../app/Application/Mcp/WordpressTargetMcpToolHandlers.php), [`WpAiBridgeMcpClient`](../app/Infrastructure/Connectors/WpAiBridge/WpAiBridgeMcpClient.php) | Target permission class, authenticated downstream MCP, dynamic Ability catalog |
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

**Implemented boundary:** the shared Target/Access/Group/credential/Activity infrastructure and specific MCP WordPress/SSH execution families. Admin handles lifecycle, permissions, operator settings and scoped SSH browser files; it does **not** share a general-purpose WordPress Ability dispatcher or group publisher.

**Intended extension:** move only the operation rules needed by a genuine additional consumer into small reusable application use cases. Do **not** route Admin through public `/mcp`, create a second authorization service, overload the lifecycle `TargetConnectorAdapter` with speculative methods or add an unproven workflow engine.

- **Another client profile:** adapt authentication/consent, retain exactly the same Target access and operation model.
- **Another compatible Target-side Ability/tool:** re-read the Target-owned catalog/schema under the existing reviewed connector and current permissions, not a public Tool per capability.
- **Another authenticated MCP-speaking Target:** introduce only a reviewed registration/authentication/transport adapter; standard `tools/list`/`tools/call` reuse is an interoperability design, **not** evidence arbitrary MCP servers can be enrolled now.
- **Human-executable or multi-Target operations:** resolve selected Targets, apply the same per-Target admission near dispatch, preserve partial/unknown outcomes, and add durable bulk state only where the concrete workflow requires it.
- **Additional data path:** use shared resource/integrity/authorization semantics with connector/native transport adapters and proven receiving-client support; never assume one generic Gateway storage/stream service makes every provider file-capable.

Runtime implementation and acceptance should be checked in the selected Git revision, tests and the owning work item. This architecture describes responsible components and safe extension seams, not a release chronology or an alternative backlog.
