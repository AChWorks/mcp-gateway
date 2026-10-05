# MCP Gateway Target & Connector Foundation

Status: Accepted pre-implementation architecture contract  
Program owner: [Issue #106](https://github.com/AChWorks/mcp-gateway/issues/106)

This document defines the breaking foundation that MCP Gateway will implement before adding AI Server Agent as its second production connector.

It is intentionally written as a **target-state design contract**, not a claim that the current `main` implementation already matches it. Until Issue #106 and its child work are integrated, `docs/ARCHITECTURE.md` and current source remain authoritative for the running implementation.

Conversation history is not required to recover this design.

## 1. Why this change exists

MCP Gateway began with WordPress/WP AI Bridge as its first concrete backend. That proved the product but left generic application concepts named and shaped around a "Site".

The second real connector is AI Server Agent. It is materially different from WordPress:

- it represents one Linux host rather than one CMS site;
- its downstream authorization is a dedicated Agent credential rather than WP OAuth;
- it exposes host/server capabilities rather than WP Abilities;
- it has its own destructive-operation and approval semantics;
- it may be used directly without Gateway;
- it is stateless on the current MCP endpoint while WP compatibility includes older session-oriented behavior.

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

Connector-specific nouns remain connector-specific. A WordPress connector may still call a WordPress concept a site inside its own implementation. AI Server Agent may use Agent, host, job or server terminology inside its own implementation.

The core must not translate every downstream concept into Target. "Target" identifies the routable registered backend; it does not erase connector semantics.

### Target identity invariants

A Target always has two core identities and may also have a connector-owned verified remote identity:

1. the database primary key, used only as an internal relational identity;
2. immutable Gateway-local `target_id`, used by Admin/MCP/application routing;
3. when the connector exposes one, a connector-specific remote identity such as AI Server Agent `instance_id`.

The shared core must not invent a fake immutable remote identity for a connector that does not expose one. For WP AI Bridge, canonical origin/resource metadata can remain the connector's endpoint/resource binding without pretending it is an opaque permanent instance ID.

`target_id` must remain a stable, bounded human-readable machine identifier. Keep the existing 64-character lowercase slug shape unless implementation evidence proves a concrete need to widen it.

Public MCP/Admin validation must use the same 64-character bound; do not advertise a wider 128-character public identifier while persistence accepts only 64.

Never derive `target_id` from hostname, URL, IP address, WordPress site URL, Agent label, or another mutable endpoint.

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
ai_server_agent_target_config
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
- AI Server Agent: dedicated named Agent credential.

Connector-owned OAuth flows, refresh-recovery state, authorization metadata, or other temporary credential state do not become generic Target fields merely because WP AI Bridge needs them.

Secrets never belong in Target list/context responses, normal activity, logs or UI diagnostics.

Connector onboarding that accepts a secret through the Admin UI treats that field as write-only: never repopulate it through `old()`/validation session flashing, never include it in activity or request diagnostics, and never persist plaintext outside the immediate request-to-encrypted-custody flow. A validation failure must ask the operator to re-enter the secret rather than echoing it back.

## 6. Connector contract

Supported connectors are built-in, explicitly registered implementations.

Initial connector set after Issue #106:

```text
wp_ai_bridge
ai_server_agent
```

A small explicit registry/factory/container mapping selects a connector from the stored `connector_type`.

This is **not**:

- dynamic PHP class loading from database values;
- a marketplace;
- arbitrary user-supplied executable connector code;
- a universal HTTP proxy;
- a generic URL/method runner.

Unsupported connector types fail closed.

Each registered connector should expose only the smallest static descriptor needed by shared code, such as stable connector type, operator-facing label, supported lifecycle capabilities, and connector-owned permission/tool families. This descriptor is metadata for built-in code; it is not an executable plugin manifest.

Shared code must not scatter `if connector_type == ...` decisions across controllers, authorization, Admin views and MCP handlers. Selection happens at the connector boundary, while business rules that truly span connectors stay in the application layer.

### What is allowed to become common

Extract only capabilities that both real connectors demonstrate are common.

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

Both first connectors ultimately need MCP client behavior, but their downstream protocol details are not identical.

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

For Program #106, the compatibility evidence must cover both real downstream generations: the modern stateless MCP path used by current AI Server Agent and the legacy/session path still required by the pinned WP AI Bridge contract. Prefer the modern stateless path when the downstream server negotiates/supports it; do not pay an initialize/session/close round-trip tax merely because the first connector needed sessions. Exact supported MCP revisions belong in current compatibility tests/release evidence rather than being frozen forever in this architecture document.

The remote MCP client and generic outbound HTTP policy must read connector-neutral timeout/body-limit/network configuration. Generic infrastructure must not depend on `bridge.*` configuration merely because WP AI Bridge was the first consumer.

Response/request bounds need a shared absolute safety ceiling plus connector/tool-specific bounded limits. Do not copy WP AI Bridge's current 64 KiB response limit onto AI Server Agent tools whose existing direct contract can return much larger command/file output, and do not raise the global Gateway limit for every connector merely to match the largest Agent payload.

Timeouts are likewise connector/tool-aware. Do not apply the current short WP metadata/request timeout blindly to Agent command/browser/setup operations. Long-running user work should prefer the Agent's persistent job mechanism; any synchronous timeout remains bounded, and a timed-out mutation with uncertain remote completion is reported as `outcome_unknown` rather than automatically retried.

Prefer bounded/chunked machine contracts for potentially large Agent data. Persistent job output already has offset/limit semantics; the Agent-side Gateway contract should add similarly machine-readable bounds/truncation/range information where needed so normal Gateway calls remain memory/network efficient under concurrency.

The remote MCP client must not know WordPress Ability semantics or AI Server Agent root-approval semantics.

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

AI Server Agent:
agent-environment
agent-run-command
agent-run-root-command
agent-start-job
agent-job-status
agent-job-output
agent-job-stop
agent-read-file
agent-write-file
agent-browser-setup
agent-browser-run
```

No compatibility alias for the old `sites-*` names is required unless a new external compatibility requirement is accepted before implementation.

Every connector-specific tool requires explicit `target_id`. Do not expose a public `call-any-tool(target_id, name, arguments)` escape hatch: it would discard stable schemas, annotations, authorization mapping and reviewable product semantics.

Every public tool must carry behaviorally correct MCP annotations. Read-only/destructive/idempotent/open-world hints describe **tool behavior**, not authorization level. In particular, a connector operation can be read-only yet still security-sensitive (for example reading a host file), so annotations must never substitute for Gateway permission checks.

When a single tool can dispatch operations with different safety classes, its static annotation is conservative. `wordpress-ability-execute` can execute destructive/unclassified downstream Abilities, so its public MCP annotation must not advertise it as read-only or non-destructive merely because some individual Ability calls are safe. Runtime classification still controls Gateway authorization.

The Agent tools follow the same rule. Arbitrary `agent-run-command` is mutation-capable even as the unprivileged worker and must carry a destructive-capable annotation; `agent-run-root-command`, job start/stop, file write, browser setup/run are likewise mutation-capable. Read/status/output/file-read tools may remain read-only annotations while still enforcing their separate security permissions.

Use stable output schemas for structured Gateway-owned responses where practical. Return only user/model-relevant product data. Internal correlation/request/session/trace IDs, raw downstream endpoints, credential metadata and other implementation telemetry stay server-side by default; if a future support reference is genuinely needed, design it explicitly rather than leaking internal tracing fields.

### Core tools

`targets-list` is bounded, authorization-filtered, deterministically pageable/searchable and may filter by connector type/connection state without contacting Targets.

`target-context` returns bounded common Target state plus only explicitly safe connector-specific context. It must not expose credentials, authorization endpoints, raw internal transport details, or arbitrary downstream metadata merely because those values are stored.

### WP AI Bridge family

The WordPress tools keep WP Ability semantics behind the connector and use the `wordpress-*` family names above.

Do not force other connectors into WP Ability vocabulary.

### AI Server Agent family

The Gateway surfaces the supported Agent capability set through the `agent-*` names above without registering copies for every Agent Target.

The connector preserves downstream Agent semantics rather than reimplementing host execution. Extra tools that appear on a newer Agent are **not** automatically proxied; support is added deliberately through the Gateway connector contract.

## 9. AI Server Agent safety boundary

Agent-side requirements are owned by:
https://github.com/ach1992/ai-server-agent/issues/47

The Gateway must treat AI Server Agent as an independently secured downstream authority.

Required behavior:

- Gateway credential is independently revocable from direct Agent access;
- Agent remains one-host-per-instance;
- direct MCP use of the Agent remains supported;
- Gateway cannot bypass protected resources;
- `approval_required` must round-trip to the upstream caller;
- an approval obtained for one Target/operation must never be reusable for another Target or materially different request;
- before the Gateway forwards downstream `approval=true`, the upstream approval must be bound to the authenticated Gateway user/client context, exact `target_id`, exact Gateway tool, canonical security-relevant arguments, short expiry, and one-time/replay-safe use;
- that binding may be supplied by a compatible Agent exact-operation grant (ai-server-agent #40) or by an equivalent Gateway-owned narrowing challenge; either way the Agent still re-evaluates its own policy and remains the final host safety authority;
- a later approved retry must still pass Agent-side policy;
- root authority is never inferred merely because the caller came through Gateway;
- unknown mutating results are not blindly retried;
- Agent errors are bounded/redacted without hiding meaningful safety state.

Gateway-level authorization can deny more. It must never grant more than the Agent permits.

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
  -> AI Server Agent
  -> future supported connector
```

The common shell owns Target identity and generic lifecycle presentation.

Connector-specific steps own their own fields, authorization/setup flow, diagnostics and help text.

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
- AI Server Agent endpoint/instance/capability details; or
- another future connector's own information.

Keep Laravel/Blade/server-rendered administration. Progressive JS is acceptable where it improves a bounded interaction. Do not introduce an SPA solely because connector count increases.

Client-facing Gateway OAuth and downstream connector authentication must remain visibly separate concepts in code/config/UI. WP AI Bridge's additional-client metadata, JWKS and callback are connector-owned surfaces and should move under an unambiguous WP-connector namespace during the breaking redesign rather than defining generic Gateway OAuth naming. The browser/client-facing Gateway OAuth server remains the generic edge.

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

AI Server Agent:
agent.environment.read
agent.command.run
agent.root_command.run
agent.job.start
agent.job.read
agent.job.stop
agent.file.read
agent.file.write
agent.browser.setup
agent.browser.run
```

Permission scope is defined by policy metadata, not inferred from the string prefix: for example `targets.create` is Gateway-wide because the Target does not yet exist, while `targets.update/remove/connect/test` and connector operation permissions are Target-scoped.

Exact role bundles must be explicit and tested; adding a connector permission never becomes implicitly allowed through a wildcard. MCP tool annotations are not authorization.

The accepted initial role ceiling for Agent capabilities is intentionally conservative:

- Owner retains the existing recovery rule and can exercise every permission;
- Administrator's role ceiling includes the full Agent permission family, but a newly created Administrator defaults to only `agent.environment.read` and `agent.command.run` enabled; root/job/file/browser Agent permissions start as explicit global denials until deliberately enabled;
- Operator's role ceiling adds only `agent.environment.read` and `agent.command.run`;
- Viewer adds only `agent.environment.read`.

Existing non-owner accounts are migrated with explicit global denials for every newly introduced `agent.*` permission that would otherwise enter their role ceiling, so an upgrade never grants even a low-risk Agent capability implicitly. The access UI then lets an authorized Owner deliberately remove the relevant denials within the role ceiling. This uses the existing denial model instead of inventing a second grant engine.

Input-sensitive authorization must close privilege-composition gaps. In particular, `agent-start-job` with `root=true` requires both `agent.job.start` and `agent.root_command.run`; possession of the job-start permission must never become an alternate path to root. The same rule applies to any future tool whose arguments materially elevate the operation above its base permission.

During the breaking Site -> Target migration, existing users/roles must not become more privileged accidentally. Preserve users and role identity, translate one-to-one generic permission denials where semantics remain identical, reset Target/group-specific membership with the intentionally discarded Target inventory, and leave selected-scope users with an empty Target set until explicitly reassigned. Any permission mapping whose semantics changed or are ambiguous must fail closed or require explicit administrator reconciliation rather than being silently dropped.

The known one-to-one permission renames are explicit: `connection.view -> gateway.connection.view`, `sites.* -> targets.*`, Site-scoped `connections.connect/reconnect/disconnect/test -> targets.connect/reconnect/disconnect/test`, and `abilities.* -> wordpress.abilities.*`. This translation preserves existing WordPress authority while keeping new Agent permissions separate.

New connector permissions are especially sensitive: an existing non-owner account that previously administered WordPress must not silently gain Linux command/root/file/browser authority merely because AI Server Agent was added. The migration/default-role plan must preserve equal-or-narrower effective authority for existing non-owner accounts until those new connector capabilities are explicitly enabled through the supported access-management model.

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

For AI Server Agent, the accepted initial contract is narrower: the dedicated Gateway principal exposes a bounded authenticated **self-revocation** operation that can revoke only the credential authenticating that request. Gateway Disconnect/Remove calls that connector-internal lifecycle operation, verifies success, and only then deletes its encrypted local copy. It must not gain credential enumeration or arbitrary-principal revocation authority.

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

Adding AI Server Agent must not create a general internal-network SSRF tunnel.

If a future product requires private/internal Targets, that trust/topology change is a separate explicit security decision.

The first AI Server Agent connector therefore uses a public HTTPS Agent endpoint that satisfies the existing outbound policy. Agent local/private direct-client modes remain valid Agent features, but they are not implicitly Gateway-reachable and must not be used as a reason to relax RFC1918/loopback/link-local protections.

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
```

A connector may retain a bounded namespaced diagnostic code such as `wordpress.*` or `agent.*` in server-side activity/health evidence when it materially helps diagnosis. Publicly return connector-specific detail only when it is stable, safe and actionable for the client; never forward arbitrary downstream exception strings, stack traces, host details or secret-bearing payloads.

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

### AI Server Agent

- Target registration/test works;
- stable non-secret Agent instance identity is verified and remains bound to the Target across reconnects;
- dedicated Agent credential stays secret and Target-bound;
- modern stateless MCP path is exercised without unnecessary session churn;
- required Agent tool names/input-output contracts are compatibility-checked using bounded evidence;
- extra unknown Agent tools are not automatically exposed;
- complete supported Agent capability family routes correctly;
- machine-readable structured Agent results are consumed rather than parsing human-readable text;
- `approval_required` round-trip works;
- direct Agent use remains valid;
- no Gateway route bypasses Agent safety.

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
- exact AI Server Agent compatibility evidence is tied to a known Agent candidate/release;
- `achworks.yaml`, Composer metadata, README, deployment guidance and release notes are reconciled when runtime support actually lands;
- because public MCP tools/routes/schema are intentionally breaking, release versioning must use the project's next major-version boundary rather than presenting this as a compatible 1.x minor/patch;
- package/update integrity and recovery gates.

## 18. Future connector admission rule

A third connector should not require another generic-domain rename.

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
4. Target-neutral Admin + MCP surfaces.
5. AI Server Agent connector.
6. Mixed-connector performance/security/upgrade/release acceptance.

AI Server Agent side:
https://github.com/ach1992/ai-server-agent/issues/47

The Gateway connector must not claim support before the exact compatible Agent release/candidate satisfies that contract.

## 20. Completion test

The foundation is successful when a future engineer can add a third well-defined connector without:

- renaming the core domain again;
- adding connector-specific columns to the shared Target record by default;
- duplicating Admin authorization/inventory logic;
- duplicating low-level MCP transport unnecessarily;
- registering tools per Target;
- creating fleet-wide idle runtime work;
- bypassing connector/downstream authority;
- reading chat history to understand why the architecture exists.
