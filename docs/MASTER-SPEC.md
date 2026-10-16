# MCP Gateway — Master Specification

**Status:** Canonical, durable product specification  
**Repository:** `AChWorks/mcp-gateway`

This document defines **what MCP Gateway must be and what constraints govern its evolution**, not the implementation backlog, a release note, an issue log, a deployment report, or a version-specific configuration manual. [ARCHITECTURE.md](ARCHITECTURE.md) describes how currently integrated components fit these goals. Concrete connector, protocol, resource and migration contracts live in their dedicated documents. Current delivery and outstanding acceptance belong to GitHub source, Issues, PRs, CI, releases and the actual host.

## 1. Product identity and desired outcome

MCP Gateway is a **lightweight, self-hosted, connector-neutral access and operations platform** for a fleet of explicitly registered remote systems (**Targets**). Its durable job is to let authorized humans and machine clients **discover available capabilities, select Targets, invoke supported actions, inspect outcomes and administer access** through one coherent application security and operation model.

It is simultaneously:
- a stable authenticated MCP-facing entry point for supported AI clients;
- an administration and, progressively, an **operator-facing action surface** for direct human use;
- an application core that can serve other explicitly supported API/automation consumers without duplicating Target or authorization logic.

The Gateway is **not merely a protocol proxy** and its Admin is **not permanently restricted to connection management**. Equally, it must **not** become a replacement CMS, WordPress business-logic clone, universal hosting panel, arbitrary network proxy, always-on agent fleet, or speculative all-purpose workflow platform.

**Success:** an authorized user can reach many Targets of supported types using a single stable Gateway, perform only actions permitted by both Gateway and the actual Target authority, and obtain trustworthy outcomes. A capability already expressible through a supported connector contract can evolve at the Target without a Gateway code release for each new operation. AI and Admin use the same effective authority and operation path.

## 2. Product boundary and authority of connected systems

The Gateway owns **stable Target identity**, connector registration, groups/scopes, client and user identities, access policy, credential custody, capability discovery/routing, admission, applicable resource controls, operation/outcome coordination, and safe activity and diagnostics.

A connector owns the Target-specific authentication/lifecycle, remote identity, discovery and schema translation, transport, and actual invocation protocol. The **Target remains authoritative** for its own content, permissions, validation, side effects and state. Gateway may narrow a principal's effective power; it must never synthesize additional downstream authority.

The Gateway should prefer **coordination and authorization** over copying business data, reimplementing provider features, maintaining a shadow CMS or routing all large data bodies through PHP. Client-independent shared mechanisms are extracted only from proven common semantics; similar-looking Target operations need not have identical implementation.

An AChWorks ecosystem capability or future Foundation may be consumed where it demonstrably reduces total cost; Gateway-specific runtime behavior belongs to this product. Koinon owns AChWorks-wide discovery/governance, not Gateway's runtime or product decisions. Independent projects and their repositories are not implicitly writable dependencies.

## 3. Actors, clients, Targets and groups

Distinguish the **Gateway human principal**, actual authenticated **client application/profile** and its exact protocol identity, immutable registered **Target**, Target Group or other explicitly authorized collection, **connector type**, and **downstream principal**. A display name, requested hostname, AI conversation, or convenient role label is not authority.

Every Target-specific operation is bound to the exact authorized Target identity. Group operations resolve an explicit, authorized **set of Targets**; they must not rely on a mutable conversation-wide “active Target,” ambiguous aliases or client-supplied arbitrary endpoints.

Gateway-wide permissions, resource-scoped grants/denials and downstream permissions form one server-authoritative decision. Roles are understandable bundles; they do not substitute for policy evaluation. Target Groups are a grouping and access mechanism, not an independent authorization engine.

Registered idle Targets must not generate permanent sessions, per-Target processes, one tool registration per Target, or mandatory fleet polling. Group membership/visibility and capability access must be scoped, searchable and bounded.

## 4. One application operation path, multiple entry points

**Admin UI, MCP/AI, and later approved APIs or automations are entry adapters to common application operations**, not independent business engines. Core authorization, selected Target binding, execution admission, resource policy, outcome interpretation and activity recording must remain reusable and authoritative below the entry adapter.

An Admin action must not need to call its own public MCP endpoint to execute a local application operation. An MCP tool must not be the exclusive owner of business behavior later needed by Admin. Inbound adapters may differ in authentication, request schema and presentation, while invoking the same capability and Target-owned executor with the same effective privileges.

This is a **target-state boundary, not a claim that current MCP and Admin controllers already share every operation**. Evolve incrementally from real consumers; do not pre-build a universal operation engine or move all current code for architectural aesthetics.

The Gateway's public MCP tool set is bounded by **capability families**, not fleet size, plugin count or each downstream operation. Each relevant call names its Target(s) explicitly. Supported direct-to-Target client modes remain usable independently when the connector offers them; Gateway participation is additive, not mandatory replacement.

## 5. Capability discovery and connector evolution

Separate three axes:
1. **Existing Target capability changes.** New operation names, schemas and compatible functionality published by an already supported/authenticated Target must normally work through that connector's existing discovery/invocation contract without a Gateway release, per-name allowlist, per-plugin review or newly registered MCP tool. A name or unfamiliar annotation alone is not a security denial.
2. **MCP protocol/client capability evolution.** Wire-method revisions and optional protocol extensions require actual version/capability negotiation and compatible adapters. New wire behavior can require an SDK or Gateway edge change, but need not rewrite every Target connector. Unsupported is not unauthorized.
3. **New connector family, trust model or identity protocol.** Introduce the smallest explicit, reviewed adapter and reuse the existing identity/access/operation services; a new unrelated protocol is not magically supported merely because the Gateway has a generic domain model.

A registered and authenticated **MCP-speaking Target** should eventually be able to use reusable, Target-scoped standard `tools/list` / `tools/call` discovery/invocation where its actual protocol, identity and granted delegation permit; not one hard-coded gateway implementation per remote tool. WordPress's Ability discovery is an existing family-specific example, **not evidence that generic downstream MCP registration is already implemented**.

Connectors may support different capability families, direct modes, authentication, file transfer, async execution, privilege classes and lifecycle semantics. Discovery must honestly advertise **effective** availability after connector support, configured enablement, real client compatibility and principal permissions. Cache metadata with bounded identity-aware freshness/invalidation; cached descriptions never replace live authorization at execution.

The supported connector registry must not execute caller-supplied arbitrary code, dynamically load unknown PHP classes or act as an unrestricted outbound proxy. Published connector implementation/conformance guidance must make it possible for third parties to integrate without reconstructing Gateway internals.

## 6. Delegated access: broad and restricted

A deliberate, trusted **broad execution delegation** may allow new Target-advertised compatible operations through an existing generic invocation path, always limited by the actual Gateway user/client/Target grant and authenticated downstream principal.

A **restricted delegation** must be able to narrow reach to particular Targets/Groups and action types or enforceable semantics when needed by real workflows (for example, selected publishing operations, not unrestricted site administration). This is a durable **direction**, not an assertion that today's coarse WordPress effect classes already implement semantic per-Ability or per-content delegation.

An operation's effective permissions must be enforced by stable, trusted policy evidence and, where appropriate, the Target's own authorization. Tool names, mutable annotations, caller-supplied operation parameters and hidden UI buttons are **not sufficient proof** of semantic restrictions. If a narrow promise cannot be technically verified/enforced, do not advertise it. Unknown or unclassified effects use explicitly configured authority without turning novelty into an automatic ban or covert grant broadening.

AI clients and users must not gain extra Target or operation authority by changing entry points. Where a workflow warrants it, explicit owner-configurable approval can distinguish proposed from committed high-impact actions without introducing an unconditional ban. No privilege aggregation or accidental cross-Target credential sharing.

## 7. Operation outcomes and multi-Target work

**Single-Target actions** must identify actor, client when applicable, exact Target, capability/schema, grant and execution identity. Distinguish request rejected **before dispatch**, confirmed result, provider-reported error, and **unknown outcome after possible side effects**. Never blindly retry uncertain mutations, and never claim remote rollback or absence of effects without evidence.

**Multi-Target actions** (for example publishing or editing content on a selected group of websites) are a supported **future product direction**, not proof of current delivery. They must reuse the same per-Target permission, connector admission and execution path; record per-Target success/failure/unknown outcomes and useful remote object identities when available. Partial success is a first-class result; neither an all-or-nothing fiction nor automatic replay of already dispatched writes is acceptable.

For long-running, bulk or interrupted work, introduce minimal durable operation/job identity, progress, cancellation and idempotency/repair semantics when the first real workflow requires them. Cancellation means only what the connector confirms; avoid turning an active operation into a mandatory long-lived HTTP/PHP request. Do not install a universal workflow engine or per-Target worker as a prerequisite.

**One-time multi-Target publishing** and **persistent synchronization/conflict resolution** are different product behaviors. The latter is not implied by the former and requires a separate accepted contract, ownership model and evidence.

## 8. Results, data and file exchange

Use one common, typed contract for **permission, identity binding, capacity, integrity, availability, error/outcome and cleanup**; implement wire formats and native capabilities in the appropriate client/connector adapters.

Small structured results should remain cheap single-call JSON/UTF-8 responses. Larger objects may use bounded windows, streaming, connector-native continuation, direct storage/Target handoff or a retained job according to the **actual supported client and Target modes**. Do not force a universal inline body size, Base64 duplication, shared long-lived socket or one connector's SFTP window onto another connector's legal workload.

Transfer success requires actual byte/length/hash and receiving-client evidence where relevant. A server-side path, handle, file ID or URL alone does not prove that an AI model consumed bytes or a human received a file. Bidirectional host-specific modes need independent acceptance; never claim one host's extension is universally available.

Provider/Target remains system of record for its content. Gateway retains only operational metadata and data actually justified by its workflow; retention, private spool and cleanup are bounded and operator-visible where appropriate.

[REMOTE-IO-CONTRACT.md](REMOTE-IO-CONTRACT.md) governs protocol/transfer details, typed limits and cross-hop failure semantics; current measured effective limits and supported implementations must be established separately.

## 9. Proportional performance, budgets and operational cost

**Performance and resource efficiency are requirements, not reasons to invent feature restrictions.** Limits must reflect actual resource, host, protocol and security constraints, remain finite and measured, and be **independently typed** for inline request, decoded/encoded response, stream window, whole object, temporary disk, memory, concurrency and distinct operation lifetimes.

Separate **maximum admissible budget** from **actual allocation**: a permitted large transfer should not preallocate that maximum for a small action. The owner should be able to adjust legitimate operational budgets through a single coherent, typed policy within real host/protocol/safety bounds; avoid code rewrites and one new settings subsystem per connector. Security invariants and provider credential-recovery fences are not user-tunable performance knobs.

Registered-but-idle fleet inventory should incur approximately durable database cost only; ordinary Admin and machine listing must be indexed, paged, filtered and permission-scoped, without fleet-wide remote fan-out. Active workload, not stored fleet count, determines needed runtime resources.

Measure representative latency, round trips, throughput, PHP worker CPU/RSS, remote connections, database cost, temporary disk, concurrent operations and failure rates before adding queues, Redis, daemons, search clusters or other services. Optimize total lifecycle/maintenance cost as well as raw throughput. Reuse mature maintained libraries and native capabilities when they fit, avoiding both needless dependencies and bespoke reimplementations.

## 10. Security as a capability-enabling boundary

Security controls **permit authorized high-impact work**, rather than silently excluding useful Target functionality by name, format or perceived risk. Owner-configurable, explicit, well-audited risk acceptance is appropriate for legitimate actions, including privileged SSH operations, provided it does not bypass another principal's authority or non-negotiable trust constraints.

Always preserve secure administrator password hashing, authenticated sessions with production cookie/CSRF protections, reasonable rate limiting, exact MCP OAuth state/PKCE/client/resource binding, and reviewed client profiles; never trust a client display label as authorization. Keep signing/encryption keys private outside the web root, maintain key-aware backup/recovery guidance, and avoid leaking passwords, bearer/refresh tokens or full sensitive content into logs, Activity or errors.

Always preserve correct Gateway/client authentication and consent, exact user/client/Target authorization, encrypted and segregated secrets, downstream permission enforcement, verified remote endpoint and peer (HTTPS/TLS/DNS/SSRF or pinned SSH host key as applicable), data protection, request validity, finite host/resource admission and safe logs. A remote shell with administrative OS rights is real administrative power; do not present tool-family toggles as a sandbox.

Revoked authorization, changed identities, known unsafe destinations and unauthorized cross-scope access fail closed. A new capability unknown to Gateway is not automatically deemed malicious; offer a truthful unsupported/permission explanation and appropriate explicit delegation instead of hardcoded feature bans.

Any high-impact approval or confirmation must be bound to the exact authenticated principal, selected Target(s), intended action and meaningful request identity; it must not become a reusable cross-Target approval token. **Only a suitably authorized Owner may control a global or Target-wide Pause/Resume gate** where that policy is part of the supported product; new remote stages recheck it, but in-flight remote side effects are not revoked or rolled back by pausing.

Approval/confirmation, pause, disconnect, job cancellation and remote revocation have **different effects**. Pausing Gateway-mediated new operations does not retroactively undo in-flight Target changes; user acknowledgment cannot invent a remote rollback. Preserve recovery from partial/uncertain results without leaking secrets or encouraging unsafe replay.

## 11. Credential lifecycle, diagnostics and evidence

Connection authorization, last authenticated health observation and operational availability are separate facts. **Stale health is not credential revocation**. Connector-owned, renewable offline grants use bounded due-work maintenance and authorized single-use recovery where supported; never assume SSH passwords have OAuth refresh semantics or that an unverified host Cron is running.

Use a single safe, connector-neutral correlation and diagnostics path. Identify the **first evidenced** failure stage, preserve a stable external error contract and distinguish Gateway admission/transport, adapter/protocol, provider (only with evidence), capacity/wire and actual client handoff. When intermediaries strip upstream error codes, report original cause as unknown rather than parsing arbitrary translated text or guessing.

Operator-facing diagnostics and authorized Activity may be more detailed than end-user MCP errors, but must remain appropriately scoped, bounded and free of credentials, arbitrary full payloads or protected Target exposure. Administrative/security audit and high-volume operational events may require different retention semantics; avoid a duplicate logging database by default.

Source implementation, passing CI, public release, installation and user/client behavior are **separate evidence claims**. None proves the next automatically.

## 12. Supported operating model and evolution

The initial and continuing primary product is a **private self-hosted deployment for a trusted owner/small workspace**, not a public multi-tenant SaaS. Preserve a simple PHP/Laravel application usable on ordinary compatible PHP hosting, with MariaDB/MySQL-compatible persistence, HTTPS, private credentials, server-rendered Admin and no mandatory Docker, Redis, Node runtime, separate agent, message broker or long-running daemon.

Provide safe fresh-install and update packages for hosts without SSH/Composer and an advanced source-based deployment route. Fresh installers require HTTPS, an empty provisioned database, private secret handling and an irreversible installer lock after first success. Temporary browser updaters require existing authorized administrator session and CSRF/HTTPS admission, verified package identity, private staging, preservation of existing private environment/state, explicit managed-file ownership, cleanup of temporary public entry points, safe schema-migration boundaries and a separately verified database restore plan. A code backup is not a verified database restore. Public web access is confined to the intended public document root. Environment settings actually supported by this product must be discoverable consistently in the operator template and reference; dangerous/optional settings are clearly commented or safely defaulted, not silently enabled on an upgraded host.

Do not mandate a SPA, Kubernetes, public tenancy, billing, enterprise hierarchy, permanent data replication, generic host/file/SQL console, arbitrary URL proxy, dynamic connector marketplace or premature Foundation extraction. These are distinct future product decisions, not hidden requirements of extensibility.

Compatibility for existing authenticated clients, Target identities, credentials, direct connector use and public contracts is preserved where feasible; deliberate breaking changes require an explicit migration and recovery contract. Add external clients, connectors, richer Admin operations, groups, storage adapters and workload infrastructure **as concrete demand and measured evidence justify them**, without rewriting the shared core.

## 13. Acceptance and growth rules

Product evolution must be evidenced by representative, authorized real operations, not only mocks or a passing source build:
- an existing supported Target adds a compatible capability that becomes discoverable/invocable **without changing Gateway code**, while narrower and downstream denials remain enforced;
- identical authorized operations initiated through **MCP and Admin** converge on common policy, execution and outcome semantics once the Admin execution surface is implemented;
- authorized multi-Target work produces individually truthful partial/unknown results with no duplicate unsafe mutation;
- new connector families and reviewed clients reuse shared identity/access/operation/data contracts rather than duplicating the core;
- small/large payloads and mixed workloads obey effective measured boundaries without unrelated connector limits; real client handoff is distinguished from server-side byte storage;
- idle fleet growth does not force proportional workers, polling or per-Target registrations; meaningful work remains observable, bounded and recoverable;
- authorized high-risk operations remain possible within real downstream authority and immutable trust boundaries;
- a fresh maintainer can recover **intent here**, **architecture in the technical docs**, **unresolved work from Issues**, **code identity from Git**, and **shipped/installed facts from the actual release/runtime** without prior chat state.

These are enduring acceptance **directions**, not a declaration that every future capability is shipped. The archived WordPress-first V1 scope and criteria are preserved in [HISTORICAL-V1-ACCEPTANCE.md](HISTORICAL-V1-ACCEPTANCE.md) solely for provenance.

## 14. Sources of truth and change policy

- **This MASTER-SPEC:** lasting product intent, invariants, supported operating model and non-goals.
- **ARCHITECTURE / TARGET-CONNECTOR-FOUNDATION / REMOTE-IO-CONTRACT / connector guides:** current design, executable boundaries, standards and adapter contracts, including implementation status when explicitly marked.
- **Git source, PRs and exact CI:** implementation and review evidence.
- **GitHub Issues:** current acceptance gaps, sequencing, dependencies and owner decisions pending execution.
- **Releases and actual environments:** shipped artifact and installed/runtime truth.
- **README:** short public introduction, installation entry and usage navigation **only**; **not a project specification, durable architecture document, issue tracker, recovery log or authoritative implementation proof**.
- **Koinon:** ecosystem-wide governance/asset discovery, not this product's live backlog or runtime.

Change the MASTER-SPEC only for a materially accepted change to product purpose, lasting behavior, authority/trust model, deployment commitments or non-goals. Do not put SHAs, PR status, current versions, implementation subtasks, release timelines or arbitrary numeric tuning settings here. Specifics belong to their nearest owner. Changes to dependent architecture and Issues must be reconciled before implementation claims are made.
