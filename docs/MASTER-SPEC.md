# MCP Gateway — Master Specification

Status: Canonical project specification

Repository: `AChWorks/mcp-gateway`

### AChWorks ecosystem relationship

**Koinon** (`AChWorks/koinon`) owns ecosystem-level governance, discovery, and generic cross-project contracts. This repository remains authoritative for MCP Gateway product intent, architecture, implementation, Issues/PRs/CI, releases, and deployment behavior.

**AChrix** (`AChWorks/achrix`) is not currently a runtime dependency. Any future Foundation consumption or capability promotion must be justified by current executable Foundation evidence and real multi-consumer convergence rather than by organization membership alone.

## 1. Purpose

MCP Gateway is a small self-hosted **connector-neutral Target control plane with a client-neutral MCP edge**. One stable Gateway endpoint can serve explicitly supported remote MCP client applications, and each authenticated client can reach many explicitly registered backend systems through supported first-class connectors.

WordPress/WP AI Bridge was the first connector and proved the original operational problem: connecting ChatGPT directly to many independent backends creates one client/App connection per backend. MCP Gateway provides one stable public MCP endpoint and a bounded administration surface so Targets can be added, removed, connected, tested, authorized, and routed without creating another ChatGPT App for every Target.

The accepted next foundation adds AI Server Agent as the second real connector, replaces generic Site/WordPress-shaped core concepts with Target-oriented domain/persistence/access/Admin/MCP contracts, and removes the single-ChatGPT assumption from the shared client authorization boundary. ChatGPT remains the first supported client profile. The detailed breaking design is owned by `docs/TARGET-CONNECTOR-FOUNDATION.md`, Program Issue #106, and client-edge Issue #117 until implementation is integrated.

The project must remain simple enough to deploy on an ordinary aaPanel host or compatible shared PHP hosting while keeping clean connector boundaries so future clients, administration/automation surfaces, and backend connector types can be added without rewriting the core.

The Gateway is a lightweight control plane, not a permanently WordPress-specific proxy and not a universal infrastructure proxy. Growth must preserve simple operation and low idle cost: a larger registered Target fleet must not by itself require proportionally more application workers, remote connections, background polling, tool registrations, or auxiliary infrastructure.

## 2. Primary outcome

The durable product outcome is that an operator can deploy one MCP Gateway instance, register many Targets of supported connector types, connect one or more explicitly supported MCP/AI client applications to the same stable Gateway endpoint, and safely inspect or operate an explicitly selected Target through that connector's own authorization and safety boundaries.

The completed V1 proof used multiple WP AI Bridge sites through ChatGPT. The accepted next breaking foundation generalizes that proof into Target semantics, adds AI Server Agent as the second connector, and generalizes the client edge so future supported clients do not require a second Gateway authorization core. Adding/removing a Target never requires another Gateway endpoint; adding a new supported client profile likewise does not create another Target fleet.

V1-specific WordPress success criteria remain historical product evidence below; they do not define the generic core domain for new development.

## 3. Intended operator and deployment model

V1 is a private, self-hosted gateway for a trusted operator or small trusted workspace, not a public multi-tenant SaaS product.

Primary deployment target:

- aaPanel-managed Linux host with OpenLiteSpeed, or compatible shared PHP hosting;
- PHP 8.4;
- MariaDB 10.11 as the primary database target, with MySQL retained as an officially supported compatibility target;
- a dedicated HTTPS domain or subdomain such as `gateway.example.com`;
- a deployment-ready fresh-install ZIP with production Composer dependencies bundled as the recommended operator installation path;
- a separate release update ZIP for existing deployment-ZIP installations, runnable through a temporary authenticated browser updater without SSH, Git, or Composer on the target host;
- every official deployment ZIP must be assembled from a clean production-only staging tree and contain only installation/runtime application files, required dependency runtime/license material, version identity, and empty writable runtime scaffolding; repository/development/test/generated state is forbidden and this invariant must remain CI-enforced for future releases;
- Git + Composer + Artisan source deployment remains a supported advanced path;
- the web server must expose only the application's `public/` directory;
- no required Docker, Redis, Node.js runtime, message broker, queue daemon, or separate microservice.

The application must remain usable on a conventional shared-style PHP request lifecycle. Long-running daemons must not be required for normal V1 operation.

The recommended fresh-install experience should remain intentionally small: upload/extract the official deployment ZIP, point the HTTPS domain at `public/`, open the one-page installer, provide an empty MariaDB database (recommended) or MySQL-compatible database plus first-administrator details, and finish. The installer must not become a general hosting control plane or command runner, and after a successful installation it must fail closed against reinstallation.

The recommended manual-update experience should likewise remain small: upload the named update ZIP into the existing application root, extract it there without overwriting the running application, open a temporary `/update/` page, authenticate with the existing Gateway administrator session, review the preflight, and confirm the update. The updater must validate before mutation, preserve `.env` and persistent `storage/`, use the release-bundled dependency tree, replace managed files deterministically, run required migrations/postflight checks, and remove/disable its temporary web/staging surface after success so it cannot be reused. It must fail closed without pretending that an unknown or partial database migration can be rolled back automatically. Because `public/` is shared with the hosting layer, updater ownership there is file-scoped: only explicitly declared Gateway-owned public paths may be replaced/restored, historical owned paths must remain declared for stale cleanup, and unknown/host-managed public state must survive update and pre-migration recovery unchanged without requiring filesystem ownership/protection changes.

Release packaging is a standing product/deployment requirement, not release-by-release cleanup. Runtime correctness and license/notice preservation take precedence over minimizing bytes, but dependency docs/examples/tests, development tooling/configuration, repository metadata, generated test keys/sessions/caches/logs, and source-checkout-only material must not be shipped when they are not needed to install or operate the application. The repository-owned package builder/verifier is the authoritative implementation of this boundary.

## 4. Product principles

### 4.1 Keep the Gateway a routing and connection plane

MCP Gateway does not replace WordPress, WP AI Bridge, or a target system's own authorization model. It owns connection registration, client authentication, target selection, protocol routing, credential custody, and gateway-level operational controls.

The target connector remains authoritative for target-specific permissions and behavior.

For WP AI Bridge this means WordPress identity, WordPress capabilities, Bridge access groups, provider permission callbacks, and Bridge operation schemas remain authoritative. The Gateway must never manufacture additional WordPress authority.

### 4.2 One stable client-facing endpoint

The public MCP endpoint is stable independently of the number or connector types of registered Targets. Target additions are data/configuration changes, not new MCP server deployments.

The Gateway exposes a deliberately bounded tool surface whose size scales with supported capability families, **not** Target inventory size. Target identity must be explicit in every Target-specific operation. A mutable implicit "active target" must not be required for correctness, especially for writes, destructive actions, or privilege-sensitive operations.

### 4.3 Preserve supported direct connector operation

Gateway integration is additive where a supported backend already has a valid direct-client mode.

WP AI Bridge must continue to work directly with ChatGPT exactly as it does without the Gateway. AI Server Agent must likewise retain its supported direct MCP connection modes when its Gateway connector is added.

The Gateway must not require an operator to disable a backend's supported direct endpoint or abandon an existing supported direct connection merely to register that backend as a Target.

Future connectors must state explicitly whether a direct mode exists; the core must not invent one where the downstream product has none.

### 4.4 Simple now, extensible later

The application must avoid hard-coding the shared control plane to ChatGPT, WordPress, WP AI Bridge, or any one backend family.

WP AI Bridge is the first connector. AI Server Agent is the accepted second connector and is the concrete trigger for the Target/connector foundation described in `docs/TARGET-CONNECTOR-FOUNDATION.md`. Common connector contracts must be extracted from these real implementations rather than hypothetical providers.

Future MCP clients and non-MCP administration/automation surfaces may reuse the same Target identity, authorization, inventory, lifecycle, activity, and routing rules without bypassing connector authorization.

Do not build a plugin marketplace, dynamic connector loader, workflow engine, or universal API proxy merely for extensibility. Introduce abstractions only when current connector evidence, measured scale pressure, or a concrete consumer makes them useful.

### 4.5 Scale with active work, not registered inventory

The Gateway has no fixed product-level maximum Target count. Capacity is an engineering property to be measured against the supported deployment profile, not a marketing promise inferred from a synthetic fixture.

Registered but idle Targets should have near-zero dynamic cost beyond durable database storage. A connector may perform bounded credential/lifecycle maintenance only when its real contract requires it; that must not imply a dedicated worker, persistent connection, or continuous polling loop per Target. Target inventory queries, client responses, administration pages, activity views, and future management surfaces must remain bounded rather than loading or rendering the whole fleet by default.

Near-term validation should prove comfortable operation for the fleet sizes that are realistically expected next (currently hundreds of registered Targets). Larger synthetic fixtures may be used to expose query, memory, response-size, or indexing limits and preserve growth headroom, but they do not create a universal supported-Target-count guarantee.

Infrastructure should scale only when active workload justifies it. Redis, dedicated queue workers, search services, extra application nodes, or similar components remain optional escalation mechanisms rather than prerequisites for storing a larger inventory.

### 4.6 Permission-first administration

Administrative authorization must be expressed through explicit permissions/policies at the application boundary. Named roles are convenience bundles of permissions, not hard-coded business rules.

The initial product may remain operationally simple, but the architecture must permit multiple local administrator/operator accounts and a small number of understandable access levels without replacing the authentication model. Resource scoping through Target Groups and direct per-Target access must use the same policy boundary rather than being reimplemented by controllers, connector code, or transport adapters.

Complex organization hierarchies, public tenancy, billing, and enterprise identity governance are not implied by this requirement.

### 4.7 Connector-neutral control plane

A registered **Target** has stable Gateway identity independent of its connector implementation. WordPress/WP AI Bridge and AI Server Agent are connector-specific implementations, not definitions of the core domain.

Shared application state and rules use Target semantics. Connector-specific discovery, credentials, protocol details, health semantics, setup flows, capability vocabulary, and execution logic remain behind explicit connector boundaries. Shared rules may depend on declared connector capabilities, but must not silently assume OAuth, WordPress concepts, WP AI Bridge Abilities, Linux/server semantics, or any other connector-specific contract.

Connector selection is explicit and server-authoritative. The Gateway supports built-in connector implementations through a small registry/factory; it is not a dynamic third-party code loader.

The Gateway remains a control plane by default. Large backup archives, media, exports, and similar data-plane payloads should normally move directly between the Target and an appropriate storage/destination when the downstream system supports that pattern; the Gateway should retain bounded status/metadata rather than becoming an unnecessary bandwidth or storage bottleneck.

### 4.8 Prefer maintained building blocks where they fit

Use Laravel/framework facilities and mature maintained libraries for security-sensitive or commodity capabilities when they fit the required semantics and reduce custom code without creating disproportionate lock-in or operational burden.

Examples include authentication/authorization primitives, queue abstractions, storage adapters, and protocol libraries. Third-party adoption must still be justified by compatibility, maintenance quality, security posture, migration cost, and the actual product need. Do not add a dependency merely because it exists, and do not reimplement a mature capability merely to avoid a small well-bounded dependency.

## 5. V1 scope

This section records the integrated WordPress-first V1 baseline and remains useful regression/compatibility evidence. Program #106 intentionally replaces generic Site-shaped core terminology for the next breaking foundation; the V1 nouns below are not requirements to preserve Site as the future shared domain.

### 5.1 Administration panel

Provide a small server-rendered web panel with:

- administrator sign-in/sign-out;
- dashboard summary;
- site list;
- add/edit/remove site metadata;
- connect/reconnect/disconnect a WP AI Bridge site;
- test connection and show actionable connection state;
- view bounded recent activity;
- view the Gateway MCP endpoint and client connection information;
- minimal application settings that are genuinely required.

V1 does not require complex organization hierarchy or enterprise RBAC. The integrated baseline already supports multiple local users with lightweight Owner/Administrator/Operator/Viewer permission bundles plus denial-only resource narrowing through the same server-side authorization boundary; the Target transition must preserve that capability without turning it into a second policy engine.

### 5.2 WP AI Bridge site registration

An operator adds a site using a human-readable name and its HTTPS WordPress base URL.

The Gateway must derive or safely discover the expected WP AI Bridge MCP/OAuth endpoints rather than asking the user to paste many implementation URLs.

Registration must validate the target before persisting a usable connection. The Gateway must never turn an operator-supplied URL into an unrestricted server-side HTTP proxy.

### 5.3 Site authorization

Each connected WordPress site has an independent authorization relationship with the Gateway.

The expected user experience is:

1. Add site.
2. Gateway discovers/validates WP AI Bridge.
3. Operator selects Connect.
4. Browser is sent to the site's WordPress authorization/consent flow.
5. The operator authorizes the Gateway as a WordPress user.
6. Gateway receives and stores the resulting credentials securely.
7. Site becomes connected and can be tested.

No WordPress username or password is stored by MCP Gateway.

Disconnect/revocation for one site must not affect other sites.

### 5.4 Client-facing MCP service

Expose one public remote MCP endpoint over HTTPS.

The endpoint must use a current supported MCP HTTP transport and proper authentication. Authentication between an MCP client and the Gateway is separate from authentication between the Gateway and a target site.

For ChatGPT, V1 must support the current custom MCP App OAuth flow, including refreshable access when required by the current ChatGPT integration contract.

For the Program #106 breaking foundation, ChatGPT remains the first supported client profile but must no longer define the shared client-authorization core. The Gateway must support an explicit registry of reviewed MCP client profiles so future supported AI/MCP clients can coexist without another authorization-domain rewrite. Provider/product labels are presentation metadata, not permission sources.

The implementation must follow current MCP and client platform specifications at implementation time rather than preserving obsolete protocol assumptions in custom code.

### 5.5 Stable WordPress routing contract

The Gateway must expose a compact WordPress routing surface sufficient to:

- list configured/available sites without exposing credentials;
- inspect one selected site's context/connection state;
- discover the selected WP AI Bridge operation/Ability contracts;
- inspect an exact operation schema when needed;
- execute an exact selected WP AI Bridge operation with explicit `site_id` and input.

The Gateway must preserve downstream authorization and validation errors accurately enough for the client and operator to understand why an operation was denied or unavailable.

Every target-specific call must identify the site explicitly. Write or destructive operations must never be routed using only conversational or request-local "current site" state.

### 5.6 Connector boundary

WordPress-specific protocol knowledge belongs in one WP AI Bridge connector boundary rather than being spread through controllers, UI, OAuth code, and MCP handlers.

The durable Gateway identity is the registered site/target plus its declared connector type. Shared site inventory, authorization, routing, activity, and future operation-management rules must remain usable without requiring WordPress-specific fields or semantics from every connector.

The internal connector contract should remain small and evidence-driven. It may cover capabilities such as discovery, connection health, schema/capability inspection, execution, and disconnect/revocation where the backend supports them. Do not invent capability methods for future systems until an actual connector or consumer requires them.

Do not expose arbitrary connector-supplied URLs, HTTP methods, database queries, shell commands, or filesystem paths as a generic Gateway operation.

## 6. Authentication and authorization boundaries

There are independent trust relationships at the client edge and at every downstream Target connector:

```text
Remote MCP client (initially ChatGPT)
        |
        | OAuth / authenticated MCP
        v
MCP Gateway
        |
        | connector-specific, Target-bound credential
        v
Explicit Target
```

Examples include Gateway-to-WP-AI-Bridge OAuth credentials and a dedicated Gateway-to-AI-Server-Agent credential. Core Target authorization must not assume that every connector uses OAuth.

### 6.1 Client to Gateway

The Gateway authenticates remote MCP clients before serving protected MCP operations. Token issuance, refresh, revocation, discovery metadata, PKCE/client authentication, and redirect validation must use maintained protocol implementations or libraries where practical; do not create an ad-hoc authentication protocol.

The durable identity model separates:

- the Gateway local user/principal;
- the Gateway-supported client profile;
- the exact authenticated protocol/OAuth client identity;
- any external AI account/workspace subject only when the supported client protocol actually authenticates one.

Current ChatGPT Client ID Metadata + `private_key_jwt` is one supported client profile, not the definition of all clients. Future client families may use different explicitly reviewed authentication adapters. Unknown/unconfigured clients fail closed, and arbitrary request-supplied client metadata/JWKS URLs are never treated as trusted onboarding input.

Client application/provider labels never grant Target permissions. Authorization/token/revocation/assertion state remains exact-client bound, and one supported client must not be able to replay or revoke another client's state.

Browser administrator sessions are a separate security boundary from MCP bearer authorization.

### 6.2 Gateway to Target

Stored downstream credentials are scoped and cryptographically bound to the exact Target, connector, and supported credential purpose. Credentials must not be reusable across unrelated Targets.

Credential establishment, refresh/rotation, revocation, expiry, reconnect semantics, and maintenance are connector-owned capabilities. The shared core may provide safe encrypted storage and lifecycle orchestration but must not manufacture OAuth semantics for connectors that do not use OAuth.

A failed/revoked Target credential must fail closed for that Target without breaking unrelated Targets.

### 6.3 No privilege aggregation

The Gateway may narrow authority but must never manufacture downstream authority.

For WP AI Bridge, a WordPress/WP-AI-Bridge denial remains denied. For AI Server Agent, Agent-side protected-resource, root-policy, and `approval_required` semantics remain authoritative. Future connectors follow the same rule: the Gateway routes only what the downstream principal and connector contract authorize.

### 6.4 Administrative authorization

Administrator authentication answers who is signed in; authorization independently decides which Gateway action that principal may perform.

Server-side application policies/permissions are authoritative. UI visibility may reflect those decisions but must never be the enforcement boundary. Role names may provide convenient default bundles such as owner, administrator, operator, or viewer, but application code should authorize capabilities/resources rather than branching on those names.

The first installed administrator must retain a recoverable ownership path. Changes to users, roles/permissions, security settings, credentials, and other high-impact administration state require appropriate authorization and bounded audit evidence when multi-user administration is enabled.

## 7. Security requirements

Security is part of the V1 behavior, not a post-release hardening phase.

At minimum:

- production operation requires HTTPS;
- administrator passwords use a current password hash through the application framework;
- administrator forms use CSRF protection;
- login and sensitive endpoints have reasonable rate limiting;
- MCP authorization validates tokens, client/resource binding, redirect URIs, state/PKCE and applicable OAuth metadata according to the supported flow;
- supported MCP client profiles are explicit and fail closed; client/provider labels do not authorize, cross-client token/code/refresh/assertion/revocation confusion is rejected, and client metadata/JWKS retrieval cannot become an arbitrary SSRF surface;
- session cookies use secure production settings;
- secrets, private keys, access tokens, refresh tokens, authorization codes, and password material are never written to normal activity logs;
- stored target credentials are encrypted at rest with application-controlled encryption; token lookup material that does not need recovery should be one-way hashed where practical;
- signing private keys are stored outside the public web root with restrictive filesystem permissions;
- losing the application encryption key is treated as loss of access to encrypted target credentials; backup guidance must include the key material needed for recovery;
- outbound target URLs are validated against SSRF, redirect-to-private-network, DNS rebinding, unexpected scheme, and host-change risks;
- downstream HTTP calls have bounded connect/request timeouts and response/body limits;
- the Gateway does not automatically retry a target mutation/tool execution whose idempotency is unknown;
- when a downstream safety model requires explicit approval, a user approval for one Target/operation cannot be replayed onto another Target or materially different request; any Gateway approval challenge is exact-operation-bound, short-lived and replay-safe while downstream policy remains authoritative;
- the Gateway never holds a database row lock/transaction open across remote HTTP/MCP/OAuth work; stateful connector operations use short durable prepare/claim and finalize phases around remote I/O;
- public MCP tools expose correct behavioral annotations and bounded structured outputs; read-only annotations never replace authorization checks;
- Target identifiers, credentials, and responses from one Target must not leak into another Target's request;
- errors returned to MCP clients are useful but do not expose secrets or unnecessary internal stack/configuration data;
- destructive administration actions in the web panel require deliberate user interaction and preserve recoverable target-side state when the downstream system supports revocation rather than silent deletion;
- every administration mutation is authorized server-side through the applicable permission/policy boundary; hiding a button is not authorization;
- changes to administrative users, permission assignments, credentials, and security-sensitive configuration must produce bounded non-secret audit evidence when those features are enabled;
- the fresh-install web installer accepts secrets only over HTTPS, does not log or redisplay them, only writes outside-public-root secret material, requires a dedicated empty database, and locks itself after successful installation;
- the temporary browser updater requires HTTPS plus the existing administrator session and CSRF boundary before mutation, keeps the full update payload outside the document root, uses only a minimal temporary public entrypoint, validates exact package identity before mutation, and removes/disables its temporary staging and web entry after successful completion.

## 8. Data and persistence requirements

Use Laravel migrations that remain compatible with MariaDB (primary) and MySQL for durable schema changes.

V1 needs only the data required for:

- administrator users/sessions as required by the framework;
- lightweight administrative role/permission assignments when multi-user administration is enabled;
- registered Targets, connector identity, and only common metadata genuinely shared across supported implementations; connector-specific durable configuration belongs to connector-owned persistence; for AI Server Agent this includes server inventory context such as hostname and normalized primary IPv4/IPv6 when known rather than adding server-only columns to the shared Target record;
- encrypted Target-bound connector credentials and only the lifecycle metadata needed by their supported connector contract;
- purpose-aware credential identity so a connector can safely own more than one credential purpose without another shared-schema redesign;
- connector-specific temporary authorization/discovery/refresh state in connector-owned persistence rather than universal OAuth columns on the shared Target row;
- Gateway OAuth/client authorization state required for authenticated MCP access;
- bounded operational activity and security/audit metadata appropriate to their distinct purposes;
- minimal application settings.

Do not persist full MCP request or response payloads by default.

Do not introduce a second datastore or cache service unless an evidenced requirement later justifies it.

## 9. Activity, health, and diagnostics

The operator must be able to distinguish at least:

- Gateway application is healthy/unhealthy;
- a Target is configured but never connected;
- a Target connection is usable or requires operator attention;
- connector credentials are expired/revoked/unavailable according to that connector's lifecycle;
- a Target endpoint is unreachable or incompatible;
- a Gateway-routed operation succeeded, failed, was denied, or has an unknown mutation outcome where applicable.

Activity records should contain bounded metadata such as time, Gateway actor identity, stable supported client-profile identity when available, safe protocol-client evidence, Target ID, connector type, operation identity, outcome, and a correlation/request identifier. They must not contain access tokens, refresh tokens, bearer credentials, authorization codes, client assertions, private keys, passwords, or full arbitrary content/tool payloads.

Do not invent or log an external AI account/workspace identity unless a supported protocol actually authenticated that subject.

Correlation/request/trace identifiers are operational evidence and should remain server-side by default. Public MCP tool results should return product-relevant state rather than internal telemetry identifiers unless a separately justified user-visible support reference is deliberately designed.

Operational activity and administrative/security audit have different purposes and may require different retention/query behavior. As the administration model grows, the implementation must preserve that distinction instead of turning one ever-growing table or log stream into the authoritative record for every concern.

Dashboard and health views must use stored/bounded state and cheap local queries. Merely opening an administration page must not fan out live requests to every registered Target.

V1 does not require an external monitoring stack or metrics service.

## 10. Compatibility and protocol policy

- Use maintained official or standards-aligned MCP components where practical rather than implementing JSON-RPC/MCP framing from scratch.
- Treat the MCP PHP SDK as a replaceable protocol adapter behind a small application boundary; it is not the application's domain model.
- Use the maintained SDK client/transport for downstream MCP where it satisfies the connector contract; keep any compatibility shim small and protocol-focused rather than maintaining a second hand-written MCP stack.
- Pin Composer dependencies in `composer.lock` and validate compatible protocol behavior before upgrades.
- Support the MCP protocol generations required by every currently supported client profile and connector. ChatGPT remains the first live client compatibility profile; Program #106 additionally requires a controlled second client-profile fixture so the shared client edge is proven non-singular without claiming an unsupported commercial provider. Downstream validation must cover modern stateless MCP used by AI Server Agent and the legacy/session contract still required by the pinned WP AI Bridge integration.
- Prefer modern stateless downstream operation when negotiated/supported; do not require initialize/session/close churn for a stateless connector merely because another connector needs sessions.
- Exact supported protocol revisions are compatibility/release evidence and must be revalidated when SDK/client/connector contracts change; do not hard-code one historical revision as the permanent product architecture.
- Public Gateway server/client implementation metadata must report the actual release identity rather than a stale placeholder version.
- Preserve backwards-compatible Gateway public behavior within a release line unless a documented breaking change is intentionally accepted. Program #106 is such an accepted breaking boundary and therefore belongs on the next major-version release line.
- Adding a Target must not change the public Gateway tool list.
- Adding a supported connector family may intentionally add a bounded connector tool family and may require client tool refresh; tool count must never scale with Target inventory.

## 11. Scalability, capacity, and cost policy

There is intentionally no fixed fleet-size promise in this specification. The supported capacity of a release must be derived from representative evidence on the supported deployment shape and the actual workload mix.

The near-term engineering goal is that ordinary inventory and administration remain comfortably usable for hundreds of registered Targets (roughly the 200–500 range is a practical current planning workload, not a product ceiling). Tests may additionally exercise 1,000, 3,000, 10,000, or other larger synthetic inventories when useful for identifying headroom and nonlinear behavior. Those fixtures are diagnostic evidence, not an assertion that every shared host can sustain the same count or concurrent workload.

Scale-sensitive implementation must follow these rules:

- list/search/filter/sort paths are server-side, bounded, and supported by query/index evidence appropriate to their real access patterns;
- MCP and other machine-facing inventory responses are bounded and deterministically pageable/searchable so every authorized target remains discoverable without oversized responses;
- ordinary single-target lookup and credential routing use indexed stable identities and do not scan the fleet;
- inactive registered Targets require no persistent outbound connection and no mandatory per-target polling/background job;
- dashboard/overview requests do not synchronously contact the entire fleet;
- memory and response size should scale primarily with the requested page/work unit rather than total registered inventory;
- query counts, representative latency, memory, and database behavior are measured before introducing structural performance dependencies;
- bulk/fan-out work that cannot safely fit one bounded request should move behind explicit operation/job state when a real workflow requires it, with idempotency, partial-failure, retry, and progress semantics designed for that workflow;
- Laravel/database-backed background execution is a valid first escalation when it satisfies measured workload; Redis or additional workers/nodes become requirements only when evidence shows the simpler supported shape is no longer sufficient;
- external search infrastructure is introduced only when indexed MariaDB/MySQL query-layer search cannot meet evidenced product needs;
- large backup/media/export payloads should avoid transiting or residing in the Gateway by default when target-to-storage transfer is feasible.

Performance improvements must not weaken authorization, connector isolation, correctness, recoverability, or deployment simplicity merely to achieve a benchmark number.

## 12. Non-goals for V1

V1 deliberately does not provide:

- public multi-tenant SaaS hosting;
- billing/subscriptions;
- complex RBAC or organization hierarchy;
- Redis, queues, workers, WebSockets, or scheduled background processing as mandatory infrastructure;
- Docker/Kubernetes as a deployment requirement;
- React/Vue/SPA administration UI;
- arbitrary HTTP proxying;
- raw SQL or database consoles;
- generic Gateway-owned shell/SSH command execution outside an explicitly supported connector's bounded downstream capability contract;
- generic Gateway-owned server filesystem access outside an explicitly supported connector's bounded downstream capability contract;
- credential extraction from WordPress;
- bypasses around WP AI Bridge or WordPress capabilities;
- automatic installation/modification of WP AI Bridge on remote sites;
- copying all downstream WordPress operations into Gateway-specific implementations;
- a workflow/orchestration engine;
- a marketplace or dynamic third-party code loader;
- a generic hosting control panel or reusable arbitrary-command facility in the installer.

## 13. Future evolution

The integrated baseline already includes lightweight multi-user roles, scoped Site Groups, bounded stored health evidence, and a selected-site bulk health-check operation. Program #106 renames/generalizes those capabilities into Target semantics; they are not future promises.

Beyond that current baseline, the architecture must permit:

- additional reviewed MCP/AI client profiles beyond ChatGPT and non-MCP administration/API/automation consumers that reuse the same application authorization and Target rules without changing the Target/connector domain;
- richer Target grouping/tags or organization aids beyond the current flat Group model when a real workflow needs them;
- additional backend connector types beyond WP AI Bridge and AI Server Agent, such as other MCP servers or deliberately supported APIs/services;
- connector capability discovery without forcing every connector into WordPress/WP AI Bridge semantics;
- richer stored health/usage reporting while preserving the no-fleet-wide-render-fan-out rule;
- additional explicit bulk-operation/job workflows when publishing, editing, backup, maintenance, or similar multi-Target work justifies asynchronous execution;
- storage integrations for backup/media/export workflows where the Gateway should coordinate rather than become the data path;
- webhooks or automation where a concrete use case justifies them;
- optional queue/cache/search infrastructure and additional application nodes when measured active workload requires them;
- horizontal/runtime scaling without changing stable Target identity or weakening authorization boundaries.

Future features must preserve the core trust rule: the Gateway routes explicitly authorized capabilities; it does not silently convert connector access into unrestricted infrastructure access. They must also preserve the preference for the smallest reliable deployment that satisfies measured workload.

## 14. V1 success criteria

These criteria record the completed/integrated WordPress-first V1 acceptance baseline. They remain regression evidence for future releases, but they are not the completion criteria for the active connector-neutral Target program; Program #106 owns that next outcome.

V1 is successful when all of the following are demonstrated against supported test/deployment environments:

1. The application installs on the target PHP 8.4 + OpenLiteSpeed/shared-PHP + MariaDB-primary/MySQL-compatible deployment model using the official deployment ZIP and simple web installer; the Git/Composer/Artisan installation path remains supported for advanced operators.
2. The administration panel can securely create an administrator session and manage multiple site records.
3. At least two independent WP AI Bridge sites can be authorized and remain separately revocable.
4. One ChatGPT custom MCP App can authenticate to the Gateway and discover the stable Gateway tools.
5. ChatGPT can list sites, inspect the selected site's available WP AI Bridge operations, and execute authorized read and write operations against either site by explicit `site_id`.
6. A permission denied by WordPress/WP AI Bridge remains denied through the Gateway.
7. A disconnected/revoked site fails closed without breaking other connected sites.
8. Adding a third site does not require another ChatGPT App or a new Gateway MCP endpoint.
9. Direct ChatGPT-to-WP-AI-Bridge operation remains available for sites that use it.
10. Sensitive credentials are not exposed through the panel, installer, updater, MCP responses, application logs, or activity records.
11. A fresh developer/Master can recover project intent, architecture, current work, and validation expectations from the repository and GitHub without relying on prior chat history.
12. An existing deployment-ZIP installation can be upgraded with the official update ZIP through the authenticated one-time browser flow without SSH, Git, or Composer while preserving `.env` and persistent private state, removing stale managed files, exercising migrations/postflight validation against a real older packaged release, and removing/disabling the temporary updater after success.

V1 success criteria intentionally do not claim a fixed maximum fleet size. Capacity and growth evidence are governed by Section 11 and the current scalability work tracked in GitHub.

## 15. Source-of-truth model

Use these sources for different kinds of truth:

- `docs/MASTER-SPEC.md` — project purpose, durable requirements, constraints, non-goals, and V1 completion criteria.
- `docs/ARCHITECTURE.md` — current integrated technical architecture and component boundaries derived from this specification.
- `docs/TARGET-CONNECTOR-FOUNDATION.md` — accepted breaking Target/connector target-state design for Program Issue #106 until that design is integrated and folded into the current architecture.
- `README.md` — user-facing project overview, prerequisites, installation, usage, and release-level information; it is not an authoritative project-state, architecture, or recovery source.
- GitHub Issues — active work, dependencies, acceptance criteria, risk, and current task state.
- Pull requests/commits — implementation identity and review history.
- CI/test evidence — validation truth for a specific commit.
- deployment/release system — production/release truth when delivery is later authorized.

Conversation history is not an authoritative project source.

## 16. Change rule

Change this specification only when accepted project-level intent, supported deployment constraints, security boundaries, non-goals, or completion criteria materially change.

Implementation details, transient task state, branch/SHA information, and ordinary bug fixes belong in their nearer authoritative sources and must not turn this file into a work log.