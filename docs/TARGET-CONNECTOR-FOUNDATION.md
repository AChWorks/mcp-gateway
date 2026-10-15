# MCP Gateway Target & Connector Foundation

Status: Accepted durable Target/connector architecture contract, with historical transition design.
Program owner: [Issue #106](https://github.com/AChWorks/mcp-gateway/issues/106) (completed); outstanding installed exceptional acceptance is tracked under [#112](https://github.com/AChWorks/mcp-gateway/issues/112).

MCP Gateway v2.2.1 **ships WordPress/WP AI Bridge and Direct SSH**. SSH commands and SFTP are available; optional OAuth-scoped HTTPS whole-file transfer is disabled by default. The historical `ai_server_agent` Target identity exists only for non-destructive stored-record compatibility; the proposed Agent connector was canceled (#111).

This document preserves the durable connector-neutral identity, credential, permission and lifecycle contract plus historical design rationale. The integrated code and [current architecture](ARCHITECTURE.md), GitHub Releases and active Issues are authoritative for what actually runs, ships and remains unverified. Earlier pre-implementation sequences below are historical, not instructions to rebuild the shipped Target foundation; the original v1 Site to v2 Target transition is still a breaking data/reset boundary.

Conversation history is not required to recover this design.

## 1. Why this change exists

MCP Gateway began with WordPress/WP AI Bridge as its first concrete backend. That proved the product but left generic application concepts named and shaped around a "Site".

Direct SSH (`ssh_direct`) is the first shipped non-WordPress connector: it uses SSH/SFTP rather than downstream MCP and runs arbitrary commands as the configured OS account once Gateway Target/tool authorization permits. The shared core must be transport-neutral.

This is the point where the generic domain must become truly connector-neutral rather than accumulating WordPress exceptions.

## 2. Core vocabulary

The shared control-plane noun is **Target**.

A Target is one registered downstream system that MCP Gateway can identify, authorize, inspect and route to through one declared connector.

The shared vocabulary is:

| Legacy shared term | Target-state term |
| --- | --- |
| Site | Target |
| site_id | target_id |
| Sites | Targets |
| Site Registry | Target Registry |
| Site Inventory | Target Inventory |
| Site Health | Target Health |
| Site Connection | Target Connection |
| Site Credential | Target Credential |
| Site Group | Target Group |
| site-scoped access | target-scoped access |
| site check operation | target check operation |

Connector-specific nouns remain connector-specific. WordPress may use site terminology, while SSH uses host and OS-account semantics.

The core must not translate every downstream concept into Target. "Target" identifies the routable registered backend; it does not erase connector semantics.

### Target identity invariants

A Target always has two core identities and may also have a connector-owned verified remote identity:

1. the database primary key, used only as an internal relational identity;
2. immutable Gateway-local `target_id`, used by Admin/MCP/application routing;
3. when the connector exposes one, a connector-specific remote identity such as a connector-specific authenticated instance ID.

The shared core must not invent a fake immutable remote identity for a connector that does not expose one. For WP AI Bridge, canonical origin/resource metadata can remain the connector's endpoint/resource binding without pretending it is an opaque permanent instance ID.

`target_id` must remain a stable, bounded human-readable machine identifier. Keep the existing 64-character lowercase slug shape unless implementation evidence proves a concrete need to widen it.

Public MCP/Admin validation must use the same 64-character bound; do not advertise a wider 128-character public identifier while persistence accepts only 64.

Never derive `target_id` from hostname, URL, IP address, WordPress site URL, connector label, or another mutable endpoint.

`connector_type` is immutable for an existing Target. Changing a Target from one connector family to another means registering a new Target rather than mutating the security/credential interpretation of the old record.

Downstream duplicate/reservation rules are connector-scoped. A canonical remote identity or connector-owned canonical target key is unique only according to that connector's real semantics; do not make one global URL hash prohibit unrelated connector families that legitimately share the same origin.

Endpoint changes are explicit reassignments. When a connector exposes a trustworthy stable remote identity, reconnect/reassignment must fail closed if the endpoint resolves to a different identity unless the operator intentionally performs the supported reassignment flow. Connectors without such an identity must define an equally explicit connector-owned rebinding/reauthorization rule rather than relying on a shared guess.

## 3. Breaking compatibility decision

This redesign is a deliberate clean break.

The owner accepts manually reconnecting the current small target inventory. The implementation must therefore prefer the simplest correct future model over dual legacy/current compatibility.

Not required solely for existing target data:

- `Site*` compatibility classes;
- duplicate `site_*` and `target_*` schema;
- aliases for old MCP tool names;
- old credential payload readers;
- automatic preservation of current WP target credentials;
- transitional UI routes that indefinitely preserve `/admin/sites`.

Historical migrations and published releases remain immutable history. Do not edit old released migrations as if the old schema never existed.

The breaking upgrade must instead have one explicit, deterministic transition that:

1. preserves unrelated product state where safe and intended;
2. removes/replaces obsolete target-specific state;
3. creates the new Target foundation;
4. leaves operators with clear instructions to reconnect Targets;
5. fails closed if the transition cannot be proven complete.

Administrator accounts, Gateway client-facing OAuth/signing identity and other non-Target state are not automatically disposable merely because Target connection data is.

## 4. Long-lived control-plane boundary

The durable application model is:

```text
Admin / MCP / future API or automation
                |
                v
        Application services
                |
                v
+--------------------------------------+
| Target identity / inventory          |
| Access / Target Groups               |
| Connection / credential lifecycle    |
| Stored health evidence               |
| Activity / operation state           |
| Connector selection                  |
+------------------+-------------------+
                   |
                   v
          Explicit connector
```

Transport adapters must reuse these rules. MCP handlers and Admin controllers must not become separate sources of target authorization or lifecycle truth.

## 5. Target persistence model

The common `targets` record should contain only data that is genuinely shared across connector types.

Expected shared fields include the conceptual equivalent of:

- immutable internal record identity;
- stable `target_id`;
- display name;
- `connector_type`;
- common connection/lifecycle state;
- bounded common health/error evidence;
- timestamps.

Do not keep adding unrelated nullable connector fields to `targets`.

Connector-specific durable configuration belongs behind connector-owned persistence, for example conceptually:

```text
targets
wp_ai_bridge_target_config
target_credentials
...
```

Exact table names/normalization may be refined during implementation, but the ownership rule is fixed:

> shared table for shared semantics; connector-owned storage for connector-specific semantics.

### Credential storage

Target credentials are encrypted at rest and bound to:

- exact Target identity;
- exact connector type;
- exact credential purpose/version as required by the connector.

Core code may own encryption/storage mechanics. It must not assume that every credential is an OAuth access/refresh token.

The generic credential store must be **purpose-aware**, not permanently one-row-per-Target. A connector may currently use one credential, but the durable uniqueness boundary should support `Target + connector + credential purpose` so future rotation, signing identity, delegated principals, or another connector requirement does not force another schema redesign.

Examples:

- WP AI Bridge: access/refresh authorization material;

Connector-owned OAuth flows, refresh-recovery state, authorization metadata, or other temporary credential state do not become generic Target fields merely because WP AI Bridge needs them.

Secrets never belong in Target list/context responses, normal activity, logs or UI diagnostics.

Connector onboarding that accepts a secret through the Admin UI treats that field as write-only: never repopulate it through `old()`/validation session flashing, never include it in activity or request diagnostics, and never persist plaintext outside the immediate request-to-encrypted-custody flow. A validation failure must ask the operator to re-enter the secret rather than echoing it back.

## 6. Connector contract

Supported connectors are built-in, explicitly registered implementations.

Current built-in connectors: `wp_ai_bridge` and `ssh_direct`. Direct SSH includes commands, bounded SFTP and optional off-by-default whole-file transfer ([PR #166](https://github.com/AChWorks/mcp-gateway/pull/166)); verified external-client bytes do not establish ChatGPT attachment/model consumption (#147/#112). Only currently implemented connectors may be registered:

```text
wp_ai_bridge
ssh_direct
```

A small explicit registry/factory/container mapping selects a connector from the stored `connector_type`.

This is **not**:

- dynamic PHP class loading from database values;
- a marketplace;
- arbitrary user-supplied executable connector code;
- a universal HTTP proxy;
- a generic URL/method runner.

Unsupported connector types fail closed.

Each registered connector should expose the smallest **static implementation descriptor** the shared lifecycle and Admin actually need: stable connector type, label, supported lifecycle capabilities, and reviewed capability/permission families. This is not a per-downstream-tool manifest or executable plugin loader. The **runtime Target-owned operation/schema catalog** is separate and may evolve safely without expanding the static registry.

Shared code must not scatter `if connector_type == ...` decisions across controllers, authorization, Admin views and MCP handlers. Selection happens at the connector boundary, while business rules that truly span connectors stay in the application layer.

### What is allowed to become common

Extract only capabilities evidenced by the actual three connectors; not every connector must implement every downstream operation. Share Target identity, authorization and lifecycle mechanics where genuinely common, while keeping SSH TCP/SFTP, Agent MCP and WordPress OAuth/tool semantics connector-owned.

Likely shared application-level needs include:

- validate/register Target;
- report bounded Target context/health;
- establish/open connector credential material;
- test connection;
- disconnect/revoke when supported;
- expose connector capability/tool families;
- execute one explicit connector operation against one explicit Target.

The exact interface must remain small. Do not create placeholder methods for speculative future services.

## 7. Shared remote MCP client

WP AI Bridge uses downstream MCP. Direct SSH does **not** speak MCP and must use an independent SSH/SFTP transport adapter instead of being forced into the HTTP MCP client.

Protocol mechanics that are truly generic belong behind a Gateway-owned remote MCP adapter/client under `Infrastructure/Mcp`.

Responsibilities may include:

- supported Streamable HTTP request framing;
- negotiated/compatible MCP protocol metadata;
- modern stateless calls;
- legacy/session flow only where the downstream contract requires it;
- `tools/list`;
- `tools/call`;
- bounded body/response handling;
- timeout/cancellation behavior;
- safe authentication header injection supplied by the connector;
- correlation identity;
- secret redaction;
- protocol error normalization.

Use the maintained MCP PHP SDK client/transport where it can provide these semantics correctly instead of maintaining parallel hand-written JSON-RPC/session framing. Any remaining adapter code must stay small and protocol-focused.

Protocol interoperability must follow verified downstream MCP negotiation; only an actually supported MCP Target uses the shared remote MCP client, while SSH uses its dedicated SSH/SFTP adapter.

The remote MCP client and generic outbound HTTP policy must read connector-neutral timeout/body-limit/network configuration. Generic infrastructure must not depend on `bridge.*` configuration merely because WP AI Bridge was the first consumer.

Response/request bounds need a shared absolute safety ceiling plus connector/tool-specific bounded limits. Do not copy WP AI Bridge's current 64 KiB response limit onto SSH tools, and do not raise the global Gateway limit to match a large payload. Use connector/tool-specific finite ceilings and the honest continuation/transfer rules in `REMOTE-IO-CONTRACT.md`.

Timeouts are likewise connector/tool-aware. Do not reuse WordPress request timeouts for SSH commands; retained SSH jobs support longer work; any synchronous timeout remains bounded, and a timed-out mutation with uncertain remote completion is reported as `outcome_unknown` rather than automatically retried.


The remote MCP client must not know WordPress Ability or SSH OS-account authorization semantics.

Connectors remain responsible for interpreting downstream tools/capabilities and mapping them into Gateway-owned product behavior.

## 8. MCP tool architecture

The public Gateway tool surface must scale with **supported capability families**, not Target count.

Never create one tool set per registered Target.

Every Target-specific call uses explicit `target_id`.

Selection of a write, destructive or privilege-sensitive Target must never rely only on conversational "current target" state.

### Public tool naming and metadata

The breaking redesign uses a stable family prefix and explicit Target identity. The accepted initial public names are:

```text
Core:
targets-list
target-context

WordPress / WP AI Bridge:
wordpress-abilities-read
wordpress-ability-execute

Direct SSH (Target-scoped):
ssh-command-run
ssh-file-stat
ssh-file-list
ssh-file-read
ssh-file-write
```

No compatibility alias for the old `sites-*` names is required unless a new external compatibility requirement is accepted before implementation.

Every Target-specific operation requires explicit `target_id`. Do not use a *raw unauthenticated/unscoped* `call-any-tool` escape hatch to bypass actual user/client/Target permissions, downstream authentication, schema/transport integrity or destination restrictions. A **properly authenticated Target-scoped generic operation family** with dynamic discovery and bounded arguments is compatible with this foundation: the operator may use real newly discovered capabilities without a Gateway code update or a hard-coded per-name allowlist. No one tool per Target or per remote operation.

Every public tool must carry behaviorally correct MCP annotations. Read-only/destructive/idempotent/open-world hints describe **tool behavior**, not authorization level. In particular, a connector operation can be read-only yet still security-sensitive (for example reading a host file), so annotations must never substitute for Gateway permission checks.

When a single tool can dispatch operations with different safety classes, its static annotation is conservative. `wordpress-ability-execute` can execute destructive/unclassified downstream Abilities, so its public MCP annotation must not advertise it as read-only or non-destructive merely because some individual Ability calls are safe. Runtime classification still controls Gateway authorization.


Use stable output schemas for structured Gateway-owned responses where practical. Return only user/model-relevant product data. Internal correlation/request/session/trace IDs, raw downstream endpoints, credential metadata and other implementation telemetry stay server-side by default; if a future support reference is genuinely needed, design it explicitly rather than leaking internal tracing fields.


**Direct SSH has such a concrete use case: preventing wrong-host selection before shell/file operations.** Authorized `targets-list`/`target-context` must expose a bounded, non-secret SSH identity projection with `target_id`, display name, normalized configured/verified IP, TCP port, SSH username, optional hostname and IP verification/freshness status. An IP literal can be displayed before connection but is not host-key-verified; hostname records show only the actual policy-approved, host-key-verified TCP peer IP as verified evidence (or an honest unknown/stale label). SSH-specific endpoint identity belongs in connector-owned persistence, not in the common `targets` schema, and must not be visible to unauthorized principals/clients.

### Core tools

`targets-list` is bounded, authorization-filtered, deterministically pageable/searchable and may filter by connector type/connection state without contacting Targets.


For Direct SSH Targets, bounded local authorization-filtered search also matches normalized IPv4/IPv6, optional IP:port and configured hostname. Multiple authorized Targets sharing one IP but differing in username/port remain separate selectable choices. No list/search remote probe or implicit selection; command/SFTP calls require exact `target_id` rather than a caller-provided IP.

`target-context` returns bounded common Target state plus only explicitly safe connector-specific context. It must not expose credentials, authorization endpoints, raw internal transport details, or arbitrary downstream metadata merely because those values are stored.

### WP AI Bridge family

The WordPress tools keep WP Ability semantics behind the connector and use the `wordpress-*` family names above.

Do not force other connectors into WP Ability vocabulary.

### Direct SSH family

`ssh-command-run` deliberately supports unrestricted remote OS account commands (including OS-permitted `sudo`/root); it is mutation-capable and cannot be constrained by shell-string allowlists. `ssh.file.read`/`ssh.file.write` apply to SFTP tool exposure, **not** a sandbox around users with `ssh.command.run`. Common Target authorization, exact host identity, outbound TCP policy and result bounds still apply. See `DIRECT-SSH-CONNECTOR.md` and `REMOTE-IO-CONTRACT.md`.

### Target catalog evolution and minimal-upgrade rule

The Gateway maintains **separate MCP protocol support, public Gateway tool families and authenticated Target-owned operation catalogs**. A generic registered MCP-speaking Target with standard `tools/list`/`tools/call` can expose newly added tool names (including new business categories) through one authenticated Target-scoped discover/execute interface **when the caller already has deliberately granted broad execution authority**. A narrow read-only/no-root grant does not silently expand when the Target adds an operation; missing business-category mapping is not an excuse for a hard-coded name blacklist or mandatory Gateway code change.  A Target may add operations (including names unknown to Gateway) within a compatible existing invocation/permission contract without a Gateway release; WordPress Ability discovery demonstrates this. A new MCP protocol feature/extension is an independent negotiated capability and is not an operation in the WordPress catalog. Missing effect metadata maps to the applicable *existing* execution class/permission (including explicit WordPress `unclassified` grants), **not an invented automatic name blacklist**. Enforce actual user/client/Target/credential and downstream permission, genuine schema/protocol validity and resource controls; distinguish `forbidden` from unsupported adapters/extensions. Built-in connector code selection remains explicit and not dynamically loaded from untrusted input. Canonical decision: [MASTER-SPEC.md](./MASTER-SPEC.md) §4.9 and [ARCHITECTURE.md](./ARCHITECTURE.md) §4.

Negotiated core methods/extensions, cached catalog snapshots, schema change detection and optional version-appropriate MCP subscriptions belong to reusable transport adapters. The runtime must not network-fan-out on public `tools/list` or inventory, and must not depend on a host automatically refreshing tools. Protocol extensions are enabled only when implemented and negotiated, not silently synthesized from a changed backend tool name. A new supported client authentication profile still requires reviewed identity/configuration; a new ordinary downstream Ability within an existing family does not. Future connector admission should prefer extending the Target-side adapter/declared family to duplicating core auth, routing, transfer or tool plumbing.

## 10. Admin and frontend foundation

The shared Admin product surface becomes Target-oriented.

Primary navigation and shared screens use:

- Targets;
- Target Groups;
- Target access;
- Target connection/health/activity.

### Add Target flow

The first decision is connector type.

Conceptually:

```text
Add Target
  -> WordPress / WP AI Bridge
  -> Direct SSH (password/key)
  -> future supported connector
```

The common shell owns Target identity and generic lifecycle presentation.

Only shipped, implemented connector types appear in Add Target: WordPress/WP AI Bridge and Direct SSH. The server rejects fabricated connector types and unsupported historical Agent records remain non-executable.

Connector-specific steps own their own fields, authorization/setup flow, diagnostics and help text.

### Permission-screen presentation

User restrictions, Target Group restrictions and per-Target overrides must distinguish **role ceiling**, **Target reachability** and **denial-only capability restrictions**. Render permission keys from the same `GatewayPermission` definitions used by the server, grouped by Gateway administration, shared Target lifecycle, and connector-specific WordPress/SSH families. Include the true `Gateway-wide` versus `Target-scoped` action badge; this is orthogonal to connector type.

Only implemented connector capabilities are exposed as interactive controls. Preserve historical unknown denial rows without representing them as active features; never expose an unsupported connector as enrollable or executable.


**Existing Target configuration edits:** Common `target_id`, connector type and all ACL/group/client references stay stable. Mutable SSH connector-owned host/port/username/pinned server PUBLIC key and encrypted login credential may be changed through an Owner/password-confirmed, auditable, revision-fenced rotation that invalidates previous SSH verification and blocks commands/SFTP until a new pinned-key/login verification succeeds. WordPress origin editing requires completed OAuth disconnect and revocation/recovery, a fresh bounded HTTPS discovery, and new authorization; never carry tokens to a different origin. An in-flight OAuth flow must disable the origin edit UI as well as block server mutation. These are candidate behaviors only, not claims about an already deployed stable version.

### Target detail

A Target detail page should separate:

**Common**

- Target ID;
- display name;
- connector type;
- connection state;
- stored health evidence;
- access/Target Groups;
- activity/operation evidence.

**Connector-specific**

- WordPress/WP AI Bridge connection details; or
- Direct SSH registered host, normalized configured IPv4/IPv6 or policy-approved host-key-verified effective connection IP (with freshness/unknown status), SSH username, TCP port and pinned host-key verification state. Show `display name — username@IP:port — target_id` (IPv6 in brackets) also on inventory, Target pickers, test and connect/reconnect/operation destination confirmation; or
- another future connector's own information.

Keep Laravel/Blade/server-rendered administration. Progressive JS is acceptable where it improves a bounded interaction. Do not introduce an SPA solely because connector count increases.

Client-facing Gateway OAuth and downstream connector authentication must remain visibly separate concepts in code/config/UI. WP AI Bridge's additional-client metadata, JWKS and callback are connector-owned surfaces and should move under an unambiguous WP-connector namespace during the breaking redesign rather than defining generic Gateway OAuth naming. The browser/client-facing Gateway OAuth server remains the generic edge.

### Client-neutral MCP authorization edge

ChatGPT is the first supported remote MCP/AI client, not the permanent core identity model.

The client-facing edge must distinguish:

1. Gateway local user/principal;
2. stable Gateway-supported `client_profile_key`;
3. exact authenticated protocol/OAuth client ID;
4. external AI account/workspace subject **only when a supported protocol actually authenticates one**.

Do not infer an external ChatGPT/OpenAI/other-provider account from source IP, User-Agent, product branding or client name.

Use a small explicit supported-client profile registry. A profile may define:

- stable local profile key;
- operator-facing label;
- optional provider/product presentation labels;
- exact protocol client ID;
- reviewed client-authentication strategy;
- bounded metadata/JWKS policy when that strategy needs remote metadata.

The initial profile is the current ChatGPT Client ID Metadata + `private_key_jwt` / RS256 contract.

Each exact protocol/OAuth `client_id` maps to exactly one supported profile; duplicate identities fail closed. Client-specific refresh/authentication quirks remain profile-owned rather than becoming universal Gateway semantics. Authorization-server metadata advertises only the grants/authentication methods/algorithms actually implemented by the active supported profile set.

Provider/product labels are never authorization. Unknown clients fail closed. A future client requiring materially different authentication gets a reviewed adapter/profile rather than weakening the current boundary.

The registry is not Dynamic Client Registration, an arbitrary metadata URL fetcher, a provider plugin marketplace or runtime authentication-class loader.

Remote metadata/JWKS retrieval must come only from an explicit supported profile and use bounded HTTPS/origin/DNS-rebinding/redirect/size/time policies. The current single ChatGPT implementation is safe partly because its client metadata URL is fixed; generalization must not turn that constant into an SSRF input.

Authorization codes, tokens, refresh state, assertion replay state, revocation and rate limits remain bound to the exact authenticated client. One client profile must not be able to replay or revoke another client's state.

Authenticated request context exposes the safe client-profile identity for Activity/audit, rate limiting and exact approval binding. MCP Target permissions/tool semantics do not branch on OpenAI/ChatGPT versus another provider.

Issue #117 owns the authenticated client-profile edge; no canceled connector depends on additional permission or identity plumbing.

Accessibility, keyboard behavior, responsive layout, dark/light support and clear destructive-action confirmation remain required.

## 11. Authorization model

Authorization evaluates the user against a Target, not a WordPress site.

Role/global/Target Group/direct Target narrowing semantics remain server-authoritative.

Rename the shared domain and persistence to Target semantics rather than keeping a permanent Site abstraction underneath Target-labelled UI.

Shared permissions use Target vocabulary and connector operation permissions are namespaced by connector family rather than pretending every backend has WP Abilities or the same risk model.

Accepted permission identifiers for the breaking foundation are:

```text
Gateway-wide/common:
dashboard.view
gateway.connection.view
activity.view
users.view
users.manage
security.manage

Target inventory/lifecycle:
targets.view
targets.create
targets.update
targets.remove
targets.connect
targets.reconnect
targets.disconnect
targets.test

WordPress:
wordpress.abilities.inspect
wordpress.abilities.execute.readonly
wordpress.abilities.execute.mutating
wordpress.abilities.execute.destructive
wordpress.abilities.execute.unclassified

Direct SSH:
ssh.command.run
ssh.file.read
ssh.file.write
```

Permission scope is defined by policy metadata, not inferred from the string prefix: for example `targets.create` is Gateway-wide because the Target does not yet exist, while `targets.update/remove/connect/test` and connector operation permissions are Target-scoped.

Exact role bundles must be explicit and tested; adding a connector permission never becomes implicitly allowed through a wildcard. MCP tool annotations are not authorization.

Direct SSH follows the same explicit permission framework without command-string restrictions: Owner has all SSH permissions; Administrator and Operator role ceilings may include `ssh.command.run`, `ssh.file.read` and `ssh.file.write`, but **all SSH permissions default denied for every new non-owner** until deliberately enabled by the Owner and narrowed to assigned Targets. Viewer has no SSH permissions. These toggles control **Gateway tool exposure**, not OS/sudo or filesystem access for a user already granted arbitrary shell commands.

Historical migration-seeded Agent denials are inactive but retained. SSH remains default-denied to non-Owners until Owner-approved grants; removal of unsupported permission definitions must not erase historical stored denials or widen unrelated access.

Input-sensitive authorization must close privilege-composition gaps. SSH jobs must recheck Gateway user/Target rights before issuing a new command and must not create a path around OS-account privileges.

During the breaking Site -> Target migration, existing users/roles must not become more privileged accidentally. Preserve users and role identity, translate one-to-one generic permission denials where semantics remain identical, reset Target/group-specific membership with the intentionally discarded Target inventory, and leave selected-scope users with an empty Target set until explicitly reassigned. Any permission mapping whose semantics changed or are ambiguous must fail closed or require explicit administrator reconciliation rather than being silently dropped.

The known one-to-one permission renames are explicit: `connection.view -> gateway.connection.view`, `sites.* -> targets.*`, Site-scoped `connections.connect/reconnect/disconnect/test -> targets.connect/reconnect/disconnect/test`, and `abilities.* -> wordpress.abilities.*`. This translation preserves existing WordPress authority while preserving historical, inactive denial rows.

New connector permissions are especially sensitive: an existing non-owner account that previously administered WordPress must not silently gain Linux command/root/file/browser authority merely because Direct SSH was added. The migration/default-role plan must preserve equal-or-narrower effective authority for existing non-owner accounts until those new connector capabilities are explicitly enabled through the supported access-management model.

Connector-specific downstream authorization remains independent:

```text
Gateway user permission
       AND
Target scope
       AND
connector/downstream authorization
       =
allowed operation
```

The Gateway may only narrow downstream authority.

## 12. Health and connection semantics

The core may own a small common lifecycle/health vocabulary when it represents genuinely shared operator state.

Do not assume every connector has OAuth, refresh tokens, an issuer URL, or WordPress-style reconnect semantics.

Connector-owned code determines:

- how credentials are established;
- whether refresh exists;
- whether revocation exists;
- how compatibility is tested;
- how connector-specific failures map to bounded common state;
- what extra diagnostics are safe to persist/display.

Connection removal must distinguish **local credential forgetting** from **confirmed downstream revocation**. The Gateway must never report a Target as safely disconnected/revoked merely because its encrypted local credential row was deleted while the downstream principal may still be valid. Each connector must define one of these explicit outcomes:

- revocation confirmed by the downstream authority, after which local credential removal may finalize; or
- remote revocation unavailable/unconfirmed, in which case the Gateway forgets/local-disables only under an explicit operator-visible state and continues to report that downstream revocation may still be required.


Ordinary Target list/dashboard rendering reads stored evidence only and never fans out across all Targets.

Keep **endpoint compatibility/discovery** distinct from **authenticated connection health**. Registering or rediscovering a connector can prove that an endpoint speaks a compatible contract; a UI/API action named "Test connection" for an already connected Target should perform the strongest safe non-mutating end-to-end check the connector supports, including current credential use where applicable. Do not report "connected/healthy" merely because unauthenticated metadata is reachable.

Stored evidence may keep bounded timestamps/error classifications for these dimensions when operators need to distinguish them, without turning health into continuous polling.

### Lifecycle concurrency and remote I/O

Do not hold a database transaction, row lock, or scarce database connection open across downstream HTTP/MCP/OAuth calls.

The current Site-era implementation contains network calls inside lifecycle row-lock transactions. The Target foundation must replace that pattern with short durable phases such as:

```text
prepare / claim under lock
        -> commit
remote I/O outside transaction
        -> finalize under lock using intent/generation/attempt identity
```

The exact state machine varies by connector, but it must preserve credential rotation/revocation correctness, target reassignment ownership, unknown mutation outcomes, and recovery after process interruption.

Connection/health defaults that are truly generic belong in connector-neutral configuration. Connector-specific stale/refresh/discovery rules stay with the connector.

## 13. Performance and capacity invariants

Performance is a design requirement, not a later cleanup phase.

### Idle inventory

A registered but idle Target should impose approximately durable-storage cost only.

Connector-required credential/lifecycle maintenance may run as bounded shared work when a real connector contract requires it (for example, expiring renewable credentials). That exception must remain proportional and must not turn into permanent per-Target runtime infrastructure.

Do not require:

- one persistent connection per Target;
- one worker per Target;
- one recurring polling loop/job per Target;
- tool registration per Target.

### Hot paths

Single-Target routing must use indexed stable Target identity.

Inventory must be:

- server-side filtered;
- bounded;
- deterministically ordered;
- paged/cursor-based;
- projection-aware;
- policy-filtered before serialization.

Machine discovery must be able to enumerate every authorized Target without returning the entire fleet.

### Remote call discipline

Do not perform remote discovery/`tools/list` on every operation when the connector contract allows compatibility/capability evidence to be established during registration, reconnect or explicit test and safely cached as bounded metadata.

Do not add speculative caches that can become an authorization source of truth.

### Bulk work

Fan-out work must be explicitly bounded.

If a workflow cannot safely complete in one request:

- represent operation state durably;
- define retry/idempotency semantics;
- define partial failure;
- process bounded work units;
- add a queue backend only if measurements justify it.

### Validation workloads

At minimum retain representative mixed-connector fixtures around:

- 100 Targets;
- 200 Targets;
- 500 Targets.

When cheap/practical also exercise 1,000 / 3,000 / 10,000 Targets to find nonlinear query/memory/serialization behavior.

Those numbers are evidence fixtures, not universal capacity guarantees.

Measure:

- query count and plans;
- memory/serialized response size;
- bounded page/tool behavior;
- indexed Target lookup;
- authorization query shape;
- active downstream operation overhead;
- concurrency-sensitive credential/lifecycle paths.

Correctness, security and maintainability cannot be traded for an unrepresentative benchmark.

## 14. Outbound network security

All remote connectors use the Gateway's bounded outbound security layer or an equivalently strict connector-specific path.

Preserve:

- public HTTPS requirements where applicable;
- DNS rebinding defenses;
- redirect restrictions;
- target/host identity validation;
- connect/request timeouts;
- response-size bounds;
- TLS verification;
- credential/host binding;
- safe error mapping.

Adding a future reviewed remote-MCP connector must not create a general internal-network SSRF tunnel.

If a future product requires private/internal Targets, that trust/topology change is a separate explicit security decision.


Direct SSH uses TCP-specific DNS/egress policy plus a verified, pinned server host key **before** authentication. A private/VPN Target is allowed only by a deliberate operator-approved scoped network policy, never by passing arbitrary destinations in a tool call. This is a host/transport control, not a command or sudo restriction.

## 14a. Error and outcome contract

The public Gateway error/outcome model is small and connector-neutral. Connector-specific remote text never becomes an unbounded public error contract.

Use stable common categories where semantics are shared, including the equivalents of:

```text
target_not_found        # also used where needed to avoid unauthorized Target enumeration
target_not_connected
target_unavailable
connector_incompatible
authorization_denied
approval_required       # with bounded structured approval details
invalid_input
rate_limited
outcome_unknown         # mutation may have completed remotely; never blind-retry
response_too_large      # finite decoded-size ceiling exceeded; safe diagnostics
```

A connector may retain a bounded namespaced diagnostic code such as `wordpress.*` or `ssh.*` in server-side activity/health evidence when it materially helps diagnosis. Publicly return connector-specific detail only when it is stable, safe and actionable for the client; never forward arbitrary downstream exception strings, stack traces, host details or secret-bearing payloads.

Authorization filtering preserves the existing anti-enumeration rule: an out-of-scope Target must not become distinguishable from a nonexistent Target through MCP error detail.

## 15. Observability and activity

Activity must remain bounded and secret-safe.

Generic activity records identify:

- acting Gateway principal;
- Target identity;
- connector type;
- operation family/name;
- outcome;
- correlation ID;
- bounded non-secret error classification.

Do not log downstream authorization headers, bearer values, refresh tokens, private keys or raw secret payloads.

Connector-specific audit evidence may be added only when it materially helps operations and remains bounded.

Activity persistence failure must not rewrite an already authoritative downstream operation result.

## 16. Upgrade and data-reset contract

This program intentionally permits loss of existing registered Target/connection data.

The exact implementation must still be engineered as a deterministic upgrade:

- no rewrite of published historical migrations;
- no hidden best-effort partial conversion;
- no accidental loss of unrelated Admin/Gateway OAuth/signing state;
- explicit preflight;
- explicit operator-visible breaking note and deliberate confirmation for the Target/connection reset;
- exact target-data ownership list and, where practical, a preflight count/summary of affected Target records;
- tested updater behavior from the immediately preceding stable release as well as any retained historical baselines;
- fail-closed recovery semantics.

The existing browser updater's private recovery backup is a **code/files backup, not a database backup**. The major breaking update must not present it as protection for a destructive schema migration. Release/update guidance and acceptance must require a consistent operator-restorable database backup before migration starts, or introduce an independently verified database-backup mechanism if the product later chooses to automate that requirement.

If a migration has started, existing updater rules about unknown database state continue to apply. Do not invent a blind rollback.

The release notes for the breaking release must state that Targets need to be re-added/reconnected.

## 17. Test strategy

The implementation program must prove at least:

### Foundation

- Target schema/domain/access naming is internally consistent;
- no generic code path requires WordPress fields;
- connector selection rejects unsupported types;
- common inventory/access behavior works across connector types.

### WP regression

- registration/connect/reconnect/disconnect/test still works;
- Ability discovery/execution still respects authorization;
- existing direct WP AI Bridge behavior remains independent from Gateway.

### Direct SSH

- SSH Target inventory/pickers/MCP context show bounded IPv4/IPv6 + port + username + display name + stable `target_id` and actual validated TCP peer IP verification/freshness; handle unresolved DNS, shared-IP ambiguity and unauthorized IP disclosure safely, without permitting IP-as-Target command routing;
- shell/SFTP operations require the explicit authorized Target and the pinned host key; network policy/IP drift never silently chooses a different endpoint;
- SSH password/key, unrestricted authorized OS-account command execution, bounded SFTP, file streaming and failure/`outcome_unknown` handling meet `DIRECT-SSH-CONNECTOR.md` and `REMOTE-IO-CONTRACT.md` acceptance.

### Client edge

- current ChatGPT profile remains compatible;
- at least one controlled second supported client profile can coexist without shared authorization/token state;
- client-profile identity is visible in safe request/audit evidence;
- cross-client code/access/refresh/assertion/revocation confusion fails closed;
- arbitrary client metadata/JWKS URLs cannot become an SSRF surface;
- no external AI account/workspace identity is invented without authenticated protocol evidence.

### Security

- SSRF/rebinding/redirect/TLS policies;
- credential isolation;
- secret redaction;
- unauthorized Target access;
- connector-type confusion;
- mutation retry/outcome-unknown behavior.

### Scale

- bounded mixed inventory;
- tool registry independent of Target count;
- representative query plans;
- no N+1 connector/config/credential lookup on Target pages or routing;
- active-work concurrency;
- no fleet-wide page/render fan-out;
- no database row lock held while waiting on downstream network I/O.

### Upgrade/release

- clean fresh install;
- supported historical update baseline(s) to the breaking release;
- intentional Target-data reset with fail-closed user/access translation;
- preservation of unrelated persistent state;
- release/server implementation versions are derived from the real release identity rather than hard-coded placeholder versions;
- WP exact-contract CI path filters follow the new shared/connector paths after the refactor;
- `achworks.yaml`, Composer metadata, README, deployment guidance and release notes are reconciled when runtime support actually lands;
- because public MCP tools/routes/schema are intentionally breaking, release versioning must use the project's next major-version boundary rather than presenting this as a compatible 1.x minor/patch;
- package/update integrity and recovery gates.

## 18. Future connector admission rule

The practical [connector integration guide](CONNECTOR-INTEGRATION-GUIDE.md) documents supported built-in adapter requirements, correct long-lived credential renewal, error classes and future-connector acceptance. In particular, Stale health never expires an authorized connection, access-token TTL must not force unnecessary idle refresh-token rotation, and a connector without renewable credentials gets no periodic OAuth maintenance.

A fourth or later connector should not require another generic-domain rename. The third accepted connector is `ssh_direct`.

Before adding one, document:

- Gateway-local Target identity and any connector-owned remote identity/canonical target key;
- supported network/topology and SSRF trust boundary;
- connector authentication/credential lifecycle;
- registration/discovery;
- health;
- capability/tool semantics;
- authorization authority;
- mutation classification;
- retry/idempotency/unknown-outcome behavior;
- payload/timeout bounds;
- scale characteristics;
- direct-mode compatibility when applicable;
- required Admin UX;
- required test/acceptance evidence.

Then fit only genuinely shared behavior into the existing connector contract.

If the new connector proves a current abstraction wrong, change the abstraction based on that concrete evidence rather than preserving a bad interface for theoretical stability.

## 19. Dependency and execution order

Program owner: #106

Expected implementation dependency order:

1. Target domain/schema/access/data-reset foundation.
2. Connector registry and shared remote MCP client.
3. Generic Target connection/credential/health lifecycle.
4. Client-neutral MCP authorization edge (#117), which supplies authenticated client context.
5. Target-neutral Admin + MCP surfaces.
6. Direct SSH (#123 and current #181 improvements) after common foundations; #122 owns the historical oversized-response fix.
7. Mixed-connector + mixed-client performance/security/upgrade/release acceptance (#112), including SSH only after its candidate is implemented.

## 20. Completion test

The foundation is successful when a future engineer can add a fourth or later well-defined connector without:

- renaming the core domain again;
- adding connector-specific columns to the shared Target record by default;
- duplicating Admin authorization/inventory logic;
- duplicating low-level MCP transport unnecessarily;
- registering tools per Target;
- creating fleet-wide idle runtime work;
- bypassing connector/downstream authority;
- hard-coding ChatGPT as the only possible authenticated MCP client in shared authorization/request/audit code;
- treating mutable Server IP/hostname/endpoint as Target or Agent instance identity;
- reading chat history to understand why the architecture exists.
