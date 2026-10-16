# Target and connector foundation — implementation contract

**Role:** developer-facing contract for the Gateway's common Target model and connector boundary. Product purpose/constraints belong to [MASTER-SPEC.md](MASTER-SPEC.md); present layering and application operation seams belong to [ARCHITECTURE.md](ARCHITECTURE.md); concrete onboarding and external provider conformance to [CONNECTOR-INTEGRATION-GUIDE.md](CONNECTOR-INTEGRATION-GUIDE.md). **Read source and installed release for actual support.** Historical Site→Target conversion belongs to the [legacy transition runbook](TARGET-TRANSITION-RUNBOOK.md) and Git history, not this living contract.

## 1. Stable identity and storage ownership

A **Target** is one explicitly enrolled, individually authorizable downstream system. Never equate its identity with its hostname, URL, WordPress site name, IP or connector label.

- The internal `targets.id` record key is for relational persistence; the stable Gateway-facing **`target_id`** is the immutable 64-character-bounded lowercase slug used for selection and access. Connector type is immutable after registration; changing protocol family means a separately enrolled Target.
- A connector may have its own authenticated remote identity or canonical endpoint key; do not invent a generic immutable instance ID where the provider lacks one. Endpoint/host/credential change is an explicit connector-controlled **rebinding** with suitable confirmation and identity/authorization invalidation; it must not silently reassign an existing grant to another server.
- The shared Target record contains only genuinely shared display, connector and lifecycle/health metadata. Protocol origins, SSH host pins, login data, verified peer IP, rotating OAuth state and other connector-owned state belong in connector-owned durable storage.
- Store encrypted credentials bound to the exact Target, connector and **credential purpose**. On Admin input they are write-only: no old-form flashing, query-string exposure, Activity/log capture or return in inventory/context. A connector may maintain distinct encrypted credential purposes and separate revocation/refresh intent state when its contract justifies them.
- Registered-but-idle Targets use database state, not an always-on process/socket, a timer per Target or a public MCP tool per Target. Lists and searches are indexed, permission-filtered, bounded and paginated.

## 2. Registered connectors and lifecycle API

**Current integrated built-in families:** `wp_ai_bridge` and `ssh_direct`, allowlisted by [`TargetConnectorRegistry`](../app/Application/Targets/TargetConnectorRegistry.php). Unknown/stored unsupported types fail closed. The historical Agent connector was canceled; it is neither installed nor a required future type.

The actual [`TargetConnectorAdapter`](../app/Application/Targets/TargetConnectorAdapter.php) currently covers these lifecycle/metadata responsibilities (use the live interface signature, not this prose, when implementing):

| Concern | Existing adapter method/family |
| --- | --- |
| identity / registration | `type`, `registrationRules`, `safeOldInputFields`, `register`, `registrationStatus` |
| revision-safe changes | `configurationRules`, `configurationRevision`, `updateConfiguration` |
| credential/connection lifecycle | `connect`, `reconnect`, `disconnect`, `test`, `hasPendingDeletion` |
| bounded presentation | `adminDetails`, `publicMetadata` |

**These methods do not currently constitute a generic action dispatcher.** WordPress Ability and SSH command/file/Job handlers remain family-specific; the future common execution/application use case must be extracted from a real second entry consumer under [#200](https://github.com/AChWorks/mcp-gateway/issues/200), without putting domain authorization in MCP Tool schemas or Blade controllers.

Selection uses server-authoritative registered connector types. Do not accept caller-provided PHP classes, arbitrary URL hosts, a new plugin marketplace, unreviewed transports or scripts as adapters. Each connector owns its protocol identity, enrollment, authorization check, schema discovery, executable semantics, health and safe remote results.

### Endpoint changes and secrets

- Admin Target configuration updates require actual current authorization, required Owner reauthentication for sensitive connector changes and optimistic revision safeguards against stale credential/endpoint edits; never preserve an old verified identity after material rebinding.
- WP AI Bridge canonical HTTPS origin changes must follow safe pending-flow/disconnect/revocation recovery and a **new downstream authorization**, not a copied OAuth refresh token bound to the previous site.
- SSH Target endpoint, port, OS user, password/private key and independently pinned host key changes require exact-Target revalidation. Preserve a still-valid encrypted secret only according to that connector's explicit secure unchanged-secret semantics. A new host key must be verified **before** sending credentials.
- `registration` does **not** automatically grant the registering user or other users Target reachability or functional execution rights.

## 3. Shared permission and Target-scoping rules

Source ownership: [`GatewayPermission`](../app/Domain/Access/GatewayPermission.php), [`AccessControl`](../app/Application/Access/AccessControl.php), scoped Target/group persistence and server-side policies. **Do not derive authorization from a Tool description, client-provided annotation, hidden UI control or role display label.**

- Enforce the actual authenticated Gateway principal, client profile and exact protocol identity where present, explicit selected Target and connector family, global/role ceiling, Target-scope membership, group/direct deny rules, current account/access state, Target Pause and downstream principal. A Gateway grant can only narrow the authenticated remote principal's authority.
- Role grants are ceilings; explicit global/group/per-Target denials and reachability remain independent. Target Groups express membership and restrictions, not a duplicate authentication engine. A direct denied Target cannot become available merely through another Group.
- `targets.create` is Gateway-wide because the new Target does not yet exist; lifecycle and execution operations are appropriately Target-scoped based on explicit policy metadata, not only permission string prefixes. Inventory and Activity must never reveal out-of-scope Target identities, credentials or private addresses.
- `ssh.command.run`, `ssh.file.read`, `ssh.file.write` are distinct Gateway capabilities, not OS sandboxing. Existing/new non-Owner users must not gain SSH access accidentally; approved grants require appropriate selected-Target scope and Owner review/confirmation. An authorized arbitrary shell command may modify files even without the SFTP Tool grant.
- WordPress current execution classes are `readonly`, `mutating`, `destructive`, `unclassified`, plus Ability inspection. **Unclassified is an explicitly grantable existing class**, not blanket name-based denial. Effect classes do **not** prove a fine-grained “only publish posts” right; a restricted business delegation must have an actual enforceable trusted semantic contract and preserve all existing denials.
- Broad delegation may permit new **compatible** discovered downstream operations without per-name Gateway code/approval, but only when deliberately granted broad Target execution **and** downstream authority. A changed operation name or missing annotation must neither invent new permission nor force an arbitrary static blacklist.

High-trust policy and group changes that lift SSH denials, change broad scope or alter credential binding need real authenticated confirmation and stale-revision-safe persistence. New adapter behavior must not silently expand historical non-Owner rights.

## 4. Connection, credential and health state

**Connected** means a bounded recorded connector relationship, **not a live remote heartbeat**. **Stale** is old health evidence, **not terminal OAuth revocation**. Endpoint compatibility/discovery, authenticated health, refresh expiry, revocation certainty and Gateway Pause are distinct observable states.

- Connector-owned credential lifecycle decides whether a renewable offline grant exists, when due-work refresh is needed, and whether the provider permits an exact bounded single-use recovery. A name-token or SSH password connector must not inherit WordPress OAuth periodic refresh requirements. Shared maintenance scales with **actually due credentials**, not idle Target count.
- Network/authentication errors, timeouts and unknown responses are not automatically proof that a rotating grant was revoked or that a mutation did not happen. Keep generation-fenced intent/recovery, with remote network I/O **outside** long DB locks/transactions and conditional finalize to avoid stale results overwriting revocation/changes.
- Local credential **forgetting**, verified provider **revocation** and Target **disconnection** have different guarantees. Never label a remote grant revoked merely because local encrypted material was deleted. Pending/uncertain remote revocation uses connector-specific recoverable state and operator-safe diagnostics.
- The current Owner-operated **Target Pause** denies *new* Gateway-mediated remote operation stages while retaining Target identity/credentials/authorized inventory. It does not cancel/rollback already-dispatched effects or prove an external service stopped.
- Registered inventory and Admin overview do not synchronously contact every Target. An explicitly initiated `test` uses the strongest safe supported current-credential evidence; unauthenticated metadata reachability alone is not authenticated health.

See [CONNECTOR-INTEGRATION-GUIDE.md](CONNECTOR-INTEGRATION-GUIDE.md) for WordPress idle OAuth recovery and conformance details, [CLIENT-PROFILE-RUNBOOK.md](CLIENT-PROFILE-RUNBOOK.md) for the client edge and [TARGET-DISCONNECT-RECOVERY.md](TARGET-DISCONNECT-RECOVERY.md) for WordPress disconnection.

## 5. Public MCP, downstream discovery and compatibility

The public endpoint stays stable; its **Gateway-owned MCP Tool catalog** scales with reviewed capability families, not with registered Targets or each WordPress plugin operation. Source: [`GatewayMcpEndpoint.php`](../app/Infrastructure/Mcp/GatewayMcpEndpoint.php). In the integrated source this includes core Target inventory/context, dynamic WordPress Ability discovery/execution, and SSH command, SFTP and Job families; public capability/available file modes still depend on installed version, feature enablement and effective permissions.

- Every remote execution uses explicit `target_id`; no mutable conversation-wide Target selection, caller-selected arbitrary SSH IP, arbitrary URL proxy, or untrusted `call-anything` escape hatch. SSH `target-context` and inventory expose only **authorized** bounded IP/username/port and honest verified-vs-provisional-vs-stale peer status.
- WordPress's supported dynamically discovered Abilities may add new names/compatible schemas without a Gateway release; the actual Ability metadata, input and downstream permissions remain authoritative. Unsupported connector behavior is **unsupported**, not falsely labeled a security denial.
- A registered authenticated generic MCP-speaking Target using standard `tools/list`/`tools/call` may eventually use **one** shared discover/execute connector adapter under actual broad grants. **This generic connector is not currently in `TargetConnectorRegistry`.** New protocol methods/extensions require real peer negotiation and sometimes SDK/edge changes; they cannot be inferred from Tool names.
- Existing PHP MCP SDK and approved outbound clients should remain replaceable protocol adapters, not the application domain. WordPress's necessary downstream MCP session/auth behavior must not force SSH (non-MCP) or a future stateless MCP Target to use the same transport lifecycle.
- Discovery metadata/caches are bounded and identity/version/scope aware, never a permission cache. An unverified changed operation schema must be refreshed or rejected honestly before invocation. Do not fan out downstream `tools/list` for every public listing or at each Target inventory view.

## 6. Results, large data, audit and future actions

Every operation retains exact authenticated actor/client where available, Target and capability, admission and remote outcome certainty. A downstream mutation with an uncertain response is **`outcome_unknown`**, not replay-safe just because HTTP returned an error. Cross-hop diagnostics must identify the first evidenced layer, not guess missing provider codes; public user errors need not disclose private infrastructure. Activity records safe bounded correlation, Target and outcome; a logger failure does not retroactively change a remote result.

A shared typed resource policy distinguishes finite inline/decoded response bounds, temporary stream windows, whole-object transfer, host/proxy limitations, concurrency and logical Job lifetime. A connector's SFTP window must not become another connector's complete-file ceiling. Integrity, Target/client binding and actual receiving-client evidence govern byte delivery, not merely a returned server-side handle. Detailed semantics live in [REMOTE-IO-CONTRACT.md](REMOTE-IO-CONTRACT.md), [DIRECT-SSH-CONNECTOR.md](DIRECT-SSH-CONNECTOR.md) and [WHOLE-FILE-EXCHANGE.md](WHOLE-FILE-EXCHANGE.md).

Admin and MCP are separate entry adapters to one **future application-owned** operation admission/dispatch/outcome path, not two independent engines. A future multi-Target group action must resolve explicit authorized members, recheck at dispatch, retain per-Target successes/failures/unknown effects, and never blindly retry writes. Existing completed bounded group **health-check** work is not evidence of content publishing; the future scoped publisher pilot is tracked in [#200](https://github.com/AChWorks/mcp-gateway/issues/200). Do not introduce a generic job framework, new long-running daemon or duplicated transfer engine merely to pre-build the future.

## 7. Implementing another supported connector

Use the [connector integration guide](CONNECTOR-INTEGRATION-GUIDE.md) as the **single** onboarding and test checklist. Admit the smallest actual connector/identity/protocol adapter only after confirming current AChWorks/native/standard MCP reuse and a real upstream provider contract. Reuse Gateway Target/Groups/policy, credential primitives, operation/error/integrity policy and existing client interface; do not manufacture placeholder features or extract an independent Foundation without a second proven consumer.

A compatible Target operation name/schema change is normally Target-owned metadata, not a new public MCP Tool or mandatory Gateway release. A genuinely new protocol/authentication type may need a reviewed adapter; a new MCP wire extension may need an SDK/edge change. Validate only the capability families actually supported by that connector: registration/health/credentials, exact Target identity and grants, authorized and denied execution, unknown post-dispatch outcomes, transfer/host modes where relevant, and small/bounded real resource behavior. Keep current implementation and external feature claims tied to actual source/CI/release/installed evidence rather than this document alone.
