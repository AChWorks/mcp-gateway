# MCP Gateway Architecture

This document describes the **Target-era architecture and engineering boundaries**. [MASTER-SPEC.md](./MASTER-SPEC.md) owns durable product intent and decisions. [TARGET-CONNECTOR-FOUNDATION.md](./TARGET-CONNECTOR-FOUNDATION.md) owns detailed Target/connector and security semantics; [REMOTE-IO-CONTRACT.md](./REMOTE-IO-CONTRACT.md) owns result/data behavior. GitHub Issues, exact Git/PRs, CI and Releases own **current implementation, pending work and delivery status**. Historical V1 Site-era designs remain available in Git history, not as competing active instructions.

## 1. Deployable topology

```text
  ChatGPT (supported reviewed client)
  additional reviewed client profiles when actually enabled
                     |
         authenticated HTTPS /mcp
                     v
       +---------------------------+
       | MCP Gateway (PHP/Laravel) |
       | OAuth + client identity   |
       | Target/Group inventory    |
       | shared scope/access rules |
       | MCP capability families   |
       | activity + safe errors    |
       +-------------+-------------+
                     |
            exact authorized target_id
                 /         \
                v           v
          WP AI Bridge    Direct SSH
          WP OAuth        pinned host key
          MCP/Abilities   SSH command/SFTP
                |           |
             WordPress   registered host

         MariaDB/MySQL + private local runtime state
```

WordPress and SSH use different **Target-side transports and permissions**, but share Gateway Target identity, inventory, client/user authorization, audit and bounded I/O principles. SSH command support is integrated in source; SFTP file PRs are independently gated and not implied shipped. AI Server Agent is **owner-paused** (#111): neither the diagram nor connector-neutral schema is permission to enable it or advertise its tools. Read current GitHub state before declaring a feature released or deployed.

One application, one public MCP endpoint and a server-rendered Blade Admin are intentional. The supported baseline is PHP 8.4, Laravel 13, MariaDB-primary/MySQL-compatible, OpenLiteSpeed/LSAPI or comparable PHP hosting; no mandatory Node, Redis, dedicated queue worker, message broker, object store, daemon or Kubernetes. Add infrastructure only after measured workload justifies it. The public web root is `public/`; encrypted Target credentials, session/cache state and keys are private and never served.

## 2. Ownership and dependencies

| Layer | Main source owner | Responsibility |
| --- | --- | --- |
| Domain | `app/Domain/Targets`, `app/Domain/Access` | Stable Target identity, access vocabulary and invariants |
| Application | `app/Application/Targets`, `app/Application/Access`, `app/Application/Mcp` | Target lifecycle, user/Target permissions, operation orchestration, bounded outcomes |
| Inbound MCP | `app/Infrastructure/Mcp/GatewayMcpEndpoint.php`, `routes/mcp.php` | Public MCP tool schema/annotations, supported protocol transport, authenticated user context |
| Client OAuth | `app/Infrastructure/OAuth`, `app/Http/Controllers/OAuth` | Profile-authenticated client identity, consent, PKCE, exact authorization, refresh/revocation |
| WordPress Target | `app/Infrastructure/Connectors/WpAiBridge` | Target metadata, WP OAuth, WordPress Ability catalog, compatible legacy downstream MCP calls |
| SSH Target | `app/Infrastructure/Connectors/SshDirect` | Registered endpoint/IP policy, host-key pin, SSH auth, command and gated SFTP mechanics |
| HTTP/transport policy | `app/Infrastructure/Http` and connector-specific transports | SSRF/dial protections, deadlines, size bounds, response processing |
| Admin | `app/Http/Controllers/Admin`, `resources/views/admin` | Scoped inventory, enrollment, grants, client profiles, connections and diagnostics |
| Persistence | `database/migrations`, `app/Domain/Targets/Target*.php` | Indexed Target-specific records, connector-owned configs and credentials |

Follow existing Laravel patterns. Keep application authorization and data semantics outside HTTP controllers, Blade and protocol adapters. Do **not** duplicate the Target auth or credential lifecycle for every connector. Do not create a dynamic third-party connector-code loader or universal network proxy.

## 3. Trust and identity model

The meaningful identities are **Gateway user**, **reviewed authenticated client profile**, **exact OAuth/protocol client ID**, **immutable registered Target identity** and **downstream principal/remote identity** where applicable. These are not interchangeable. Client/app/provider display names, IP address, target hostname and raw request arguments are not authority.

- Every Target operation selects an explicit, authorized `target_id`; never derive write/destructive routing from conversational state, a requested host or a similarly named Target.
- Shared AccessControl enforces role ceiling, global deny, Target reachability (direct/group), applicable group/direct capability denials and current user state **server-side**; view visibility and MCP annotations are non-authoritative hints.
- Credentials are purpose- and Target-bound, encrypted at rest, write-only in UI, excluded from MCP responses, Activity and logs. Downstream access still enforces WordPress principal/Ability/group policy or SSH OS-account permissions. Gateway grants can **narrow**, not expand, downstream authority.
- Independent sensitive effects (SSH shell, file read/write, root approval, destructive WP ability, package installation, public network exposure) keep explicit capability and approval boundaries. A grant to unrestricted SSH command authority is **not** a filesystem sandbox.
- Outbound registered endpoint and actual peer identity are verified under connector-specific strict policies: HTTPS, DNS/SSRF/TLS for WordPress; DNS/TCP peer, approved egress and independently pinned SSH host key **before credentials** for SSH. Unknown/private routing is not silently enabled.
- Unknown connector types and unsupported client auth strategies fail closed. New client authentication profiles remain reviewed, exact-client-bound and separately configurable; adding an ordinary downstream capability must not require inventing a new OAuth identity system.
- No remote HTTP/SSH call takes place with a long-held database row lock. Credential/health writes and refresh state use short, concurrency-safe prepare/finalize or fencing where appropriate; stale in-flight results must not override newer revocation/health state.

For security detail use the foundation, [CLIENT-PROFILE-RUNBOOK.md](./CLIENT-PROFILE-RUNBOOK.md) and [DIRECT-SSH-CONNECTOR.md](./DIRECT-SSH-CONNECTOR.md).

## 4. MCP protocol evolution and adaptive Target capabilities

The **public Gateway tool catalog** is bounded by reviewed capability families, not by number of Targets, installed plugins or downstream tool versions. Current family examples include `targets-list` and `target-context`; WordPress exposes `wordpress-abilities-read` and `wordpress-ability-execute`. SSH command/file families are exposed **only** when the actual implementation has landed, passed gates and is appropriate for the installed release. There are no `sites-*` aliases and no separate tool set per Target.

There are **three independently evolving capability layers**:

1. **MCP protocol capabilities:** The client and Gateway negotiate actual supported protocol methods, response semantics and optional extensions (Tasks, resources, subscriptions and other future capabilities). These are protocol concerns independent of a WordPress plugin or SSH operation. A compatible implemented extension may work without redeploying Target connectors; a wholly new wire behavior can require an SDK/adapter update. Unsupported is not the same as forbidden.
2. **Public Gateway discovery:** `tools/list` returns stable Gateway-owned tools and schemas. A genuinely new public tool family or breaking schema may need a code release and a client-catalog refresh, not every Target operation.
3. **Selected Target discovery:** WordPress Abilities or another supported Target's authenticated operation catalog can change independently. New operations within the existing invocation contract should normally work through the family discovery/execute interface without a hard-coded name allowlist or Gateway release. This pattern is implemented for WordPress; it is future acceptance work for other connectors.

**Discovery does not replace existing authorization.** An unfamiliar operation name or new tool annotation is **not** a rejection reason. Existing Gateway user/client/Target grants, configured operation-class permissions, valid request/identity and the downstream authority govern access. WordPress `unclassified` is a grantable existing execution permission, not an unconditional denial; preserve intentional non-owner denials. Distinguish an actual authorization rejection from an operation/extension unsupported by an adapter or an incompatible schema. The connector registry selects authenticated built-in Targets, not caller-supplied destinations or executable classes.

Keep protocol/version negotiation in a small reusable downstream MCP client adapter where a real second consumer justifies it. Present WordPress's legacy session behavior remains connector-owned; do not impose its initialize/session/close tax on stateless downstream versions. `server/discover`, `tools/list`, cache scope/TTL and optional extensions are used only when the negotiated version and peer support them. In MCP 2026-07-28, change notifications use negotiated `subscriptions/listen`; older notification delivery differs. See [MCP specification](https://modelcontextprotocol.io/specification/2026-07-28) and [PHP SDK extensions](https://php.sdk.modelcontextprotocol.io/advanced/extensions/). Do not claim notification support forces an external ChatGPT App to refresh.

Use **bounded freshness**: capture safe compatibility/catalog evidence on connection/reconnect or on demand, invalidate when source identity/version/schema/grants change, and refresh stale evidence without fan-out to every Target during fleet listing or each public `tools/list`. Never use cached metadata as permission. If the implementation cannot establish schema/version continuity for execution, it rejects or explicitly refreshes rather than silently invoking an incompatible operation. Cache scope and negative-result behavior must be compatible with Target and client principals.

Current real-world performance risks include WP legacy session establishment and an extra Ability catalog/classification call before execution, repeated SFTP login for each inline range, HTTP response decoding, and OAuth metadata bursts. Optimize against representative round trips, p50/p95 latency, peak PHP worker RAM, database queries, connection count, concurrent active work and total failure outcomes; do not speculate that a particular cache, bigger constant or additional server fixes them.

## 5. Results, file transfer and resource economics

**Separate control and data planes when evidence warrants it.** Typed small JSON/UTF-8 and bounded previews remain cheap single-call results. File/media/document/ZIP transfers use one client-neutral shared permission, integrity, quota, progress/error and cleanup semantic layer, with **appropriate client and Target adapters**; WordPress native operations and SSH SFTP wire mechanics stay connector-owned. Transfer is not automatic ZIP installation, extraction or code execution.

A **configured maximum is not reserved capacity**. Resource use follows actual bytes and necessary framing/encoding/session overhead. Separate ceilings for inline request/decoded reply, bounded stream buffer/chunk, overall finite transfer, active Target connections, memory/temporary disk and operation lifetime. An inline 16KiB cap from a small-SFTP PR is not a universal file-size limit. A 10KiB input under a higher validated ceiling should not reserve a full maximum-size buffer; unknown-length streams use finite read buffers and enforce limits as bytes arrive.

Client input-byte availability and Target-to-**actual model-readable** or user-downloadable result must each be tested on the supported host. Returned file paths, URLs and opaque handles are not synonymous with file delivery. Preserve byte count/SHA-256 (when specified), source/destination identity, safe overwrite, short reads/writes and `outcome_unknown`; never invent a replay-safe resume mechanism. See [REMOTE-IO-CONTRACT.md](./REMOTE-IO-CONTRACT.md), #123, #147 and #112 for contract and acceptance evidence.

## 6. Failure, concurrency and fleet scale

- Every mutation runs only with the real authorization at dispatch; an interruption after dispatch may yield `outcome_unknown`, **never blind replay**.
- Read-only errors distinguish permission, incompatible protocol, unreachable Target, stale capability catalog, partial/incomplete data and safe oversize/timeout outcomes without revealing protected Target existence or secrets.
- Target inventory and Admin pages are server-side filtered, indexed, bounded, cursor/paged and authorized before serialization. Idle registered Targets incur near-zero dynamic cost, not polling, permanent sessions or per-Target workers.
- Health and activity evidence are bounded. Page views do not fan out remote connectivity tests; a recent successful operation and an explicit connection check are separate forms of evidence.
- Secure login/metadata caches may reduce verified repeated work, but they must have bounded freshness, safe invalidation and no privilege impact.
- Optimize CI for signal: narrow checks during active edits; exact-candidate broad/contract/security checks on stable changes based on affected surface and project policy. Never disable a required gate to save time.

## 7. Compatibility, deployment and documentation ownership

- Keep Composer lockfile pinned; verify dependency/protocol upgrades with relevant WordPress/SSH/OAuth/MCP tests. SDK `mcp/sdk` and OAuth `league/oauth2-server` remain vendor adapters, not domain models.
- Public protocol implementation metadata should reflect current release/build truth, not a stale bootstrap placeholder. Preserve existing supported client and downstream protocol generations; new revisions are **negotiated**, not assumed universally supported.
- Deployment/update packaging, backup/restore and historical breaking migration rules are in [DEPLOYMENT.md](./DEPLOYMENT.md), [TARGET-TRANSITION-RUNBOOK.md](./TARGET-TRANSITION-RUNBOOK.md) and release notes. Do not infer production deployment from a Git merge or Release.
- Current release instructions belong in [README.md](../README.md); repeatable validation in [DEVELOPMENT.md](./DEVELOPMENT.md). Active work and gates live in [#106](https://github.com/AChWorks/mcp-gateway/issues/106), [#108](https://github.com/AChWorks/mcp-gateway/issues/108), [#110](https://github.com/AChWorks/mcp-gateway/issues/110), [#112](https://github.com/AChWorks/mcp-gateway/issues/112), [#123](https://github.com/AChWorks/mcp-gateway/issues/123), [#130](https://github.com/AChWorks/mcp-gateway/issues/130) and [#147](https://github.com/AChWorks/mcp-gateway/issues/147). AI Server Agent #111 stays paused.

Changing a connector or client should normally require **only the adapter and evidence genuinely different for that consumer**, not a new Gateway identity domain, a cloned authorization/transfer engine, one public tool per Target, or an expensive infrastructure prerequisite. Future work remains compatible with the existing single-host PHP deployment until a measured need or accepted product change says otherwise.
