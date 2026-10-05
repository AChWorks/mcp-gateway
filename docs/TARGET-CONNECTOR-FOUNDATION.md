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

Examples:

- WP AI Bridge: access/refresh authorization material;
- AI Server Agent: dedicated named Agent credential.

Secrets never belong in Target list/context responses, normal activity, logs or UI diagnostics.

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

The remote MCP client must not know WordPress Ability semantics or AI Server Agent root-approval semantics.

Connectors remain responsible for interpreting downstream tools/capabilities and mapping them into Gateway-owned product behavior.

## 8. MCP tool architecture

The public Gateway tool surface must scale with **supported capability families**, not Target count.

Never create one tool set per registered Target.

Every Target-specific call uses explicit `target_id`.

Selection of a write, destructive or privilege-sensitive Target must never rely only on conversational "current target" state.

### Core tools

The breaking redesign should use Target-neutral core names, including at minimum the equivalents of:

```text
targets-list
target-context
```

No compatibility alias for `sites-list` or `site-context` is required unless a new external compatibility requirement is accepted before implementation.

### WP AI Bridge family

WordPress-specific operation names may remain visibly WordPress/Ability-oriented. They must accept explicit `target_id`.

Do not force other connectors into WP Ability vocabulary.

### AI Server Agent family

The Gateway must surface the supported Agent capability set without registering copies for every Agent Target.

The connector must cover the Agent capability families currently represented by:

- `agent_environment`;
- `run_command`;
- `run_root_command`;
- `start_job`;
- `job_status`;
- `job_output`;
- `job_stop`;
- `read_file`;
- `write_file`;
- `browser_setup`;
- `browser_run`.

Gateway-facing naming/schema may add explicit `target_id`, but the connector must preserve downstream semantics rather than reimplementing host execution.

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

Accessibility, keyboard behavior, responsive layout, dark/light support and clear destructive-action confirmation remain required.

## 11. Authorization model

Authorization evaluates the user against a Target, not a WordPress site.

Role/global/Target Group/direct Target narrowing semantics remain server-authoritative.

Rename the shared domain and persistence to Target semantics rather than keeping a permanent Site abstraction underneath Target-labelled UI.

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

Ordinary Target list/dashboard rendering reads stored evidence only and never fans out across all Targets.

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
- explicit operator-visible breaking note;
- exact target-data ownership list;
- tested updater behavior;
- fail-closed recovery semantics.

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
- dedicated Agent credential stays secret and Target-bound;
- complete supported Agent capability family routes correctly;
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
- active-work concurrency;
- no fleet-wide page/render fan-out.

### Upgrade/release

- clean fresh install;
- supported historical update baseline(s) to the breaking release;
- intentional Target-data reset;
- preservation of unrelated persistent state;
- package/update integrity and recovery gates.

## 18. Future connector admission rule

A third connector should not require another generic-domain rename.

Before adding one, document:

- Target identity;
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
