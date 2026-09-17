# MCP Gateway — Master Specification

Status: Canonical project specification

Repository: `ach1992/mcp-gateway`

## 1. Purpose

MCP Gateway is a small self-hosted web application that lets one remote MCP client connection reach many explicitly connected backend systems, starting with WordPress sites running WP AI Bridge.

The immediate problem is operational: connecting ChatGPT directly to many WordPress sites creates one ChatGPT custom App per site. MCP Gateway provides one stable public MCP endpoint and a small administration panel so sites can be added, removed, connected, tested, and routed without creating another ChatGPT App for every site.

The project must remain simple enough to deploy on an ordinary aaPanel host or compatible shared PHP hosting while keeping clean extension boundaries so future clients and backend connector types can be added without rewriting the core.

## 2. Primary outcome

For V1, an operator can deploy one MCP Gateway instance, connect multiple WP AI Bridge sites, create one ChatGPT custom MCP App that points to the Gateway, and safely ask the client to inspect or operate an explicitly selected WordPress site through that site's existing WP AI Bridge permissions.

Adding or removing a WordPress site must not require creating another ChatGPT App or changing the Gateway's public MCP endpoint.

## 3. Intended operator and deployment model

V1 is a private, self-hosted gateway for a trusted operator or small trusted workspace, not a public multi-tenant SaaS product.

Primary deployment target:

- aaPanel-managed Linux host with OpenLiteSpeed, or compatible shared PHP hosting;
- PHP 8.4;
- MySQL-compatible database, with MySQL as the primary target;
- a dedicated HTTPS domain or subdomain such as `gateway.example.com`;
- a deployment-ready fresh-install ZIP with production Composer dependencies bundled as the recommended operator installation path;
- a separate release update ZIP for existing deployment-ZIP installations, runnable without Git or Composer on the target host;
- every official deployment ZIP must be assembled from a clean production-only staging tree and contain only installation/runtime application files, required dependency runtime/license material, version identity, and empty writable runtime scaffolding; repository/development/test/generated state is forbidden and this invariant must remain CI-enforced for future releases;
- Git + Composer + Artisan source deployment remains a supported advanced path;
- the web server must expose only the application's `public/` directory;
- no required Docker, Redis, Node.js runtime, message broker, queue daemon, or separate microservice.

The application must remain usable on a conventional shared-style PHP request lifecycle. Long-running daemons must not be required for normal V1 operation.

The recommended fresh-install experience should remain intentionally small: upload/extract the official deployment ZIP, point the HTTPS domain at `public/`, open the one-page installer, provide an empty MySQL database plus first-administrator details, and finish. The installer must not become a general hosting control plane or command runner, and after a successful installation it must fail closed against reinstallation.

The recommended manual-update experience should likewise remain small: download/extract the named update ZIP outside the live application directory and run one explicit updater command against the installed Gateway root. The updater must validate before mutation, preserve `.env` and persistent `storage/`, use the release-bundled dependency tree, replace managed files deterministically, run required migrations/postflight checks, and fail closed without pretending that an unknown or partial database migration can be rolled back automatically.

Release packaging is a standing product/deployment requirement, not release-by-release cleanup. Runtime correctness and license/notice preservation take precedence over minimizing bytes, but dependency docs/examples/tests, development tooling/configuration, repository metadata, generated test keys/sessions/caches/logs, and source-checkout-only material must not be shipped when they are not needed to install or operate the application. The repository-owned package builder/verifier is the authoritative implementation of this boundary.

## 4. Product principles

### 4.1 Keep the Gateway a routing and connection plane

MCP Gateway does not replace WordPress, WP AI Bridge, or a target system's own authorization model. It owns connection registration, client authentication, target selection, protocol routing, credential custody, and gateway-level operational controls.

The target connector remains authoritative for target-specific permissions and behavior.

For WP AI Bridge this means WordPress identity, WordPress capabilities, Bridge access groups, provider permission callbacks, and Bridge operation schemas remain authoritative. The Gateway must never manufacture additional WordPress authority.

### 4.2 One stable client-facing endpoint

The public MCP endpoint is stable independently of the number of connected sites. Site additions are data/configuration changes, not new MCP server deployments.

V1 should expose a deliberately small, stable Gateway tool surface. Site identity must be explicit in every target-specific operation. A mutable implicit "active site" must not be required for correctness.

### 4.3 Preserve direct WP AI Bridge operation

WP AI Bridge must continue to work directly with ChatGPT exactly as it does without the Gateway. Gateway support is additive and optional.

The Gateway must not require a site owner to disable the site's direct MCP endpoint or change existing ChatGPT connections.

### 4.4 Simple now, extensible later

V1 implements only the abstractions that the current product needs. Internal boundaries must nevertheless avoid hard-coding the entire application to ChatGPT or WordPress.

The first backend connector is WP AI Bridge. Future connector types may be added later through explicit connector implementations. Future MCP clients may also be supported without changing stored site connections or core routing semantics.

Do not build a plugin marketplace, generic integration framework, workflow engine, or universal API proxy in V1.

## 5. V1 scope

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

V1 does not require complex role management. The data model may leave room for more users later, but the interface should optimize for one trusted administrator.

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

The internal connector contract should remain small and evidence-driven. It may cover capabilities such as discovery, connection health, schema inspection, execution, and disconnect/revocation where the backend supports them.

Do not expose arbitrary connector-supplied URLs, HTTP methods, database queries, shell commands, or filesystem paths as a generic Gateway operation.

## 6. Authentication and authorization boundaries

There are two independent trust relationships:

```text
Remote MCP client (initially ChatGPT)
        |
        | OAuth / authenticated MCP
        v
MCP Gateway
        |
        | independent per-site OAuth credentials
        v
WP AI Bridge / WordPress
```

### 6.1 Client to Gateway

The Gateway authenticates remote MCP clients before serving protected MCP operations. Token issuance, refresh, revocation, discovery metadata, PKCE/client authentication, and redirect validation must use maintained protocol implementations or libraries where practical; do not create an ad-hoc authentication protocol.

Browser administrator sessions are a separate security boundary from MCP bearer authorization.

### 6.2 Gateway to site

A site's stored access/refresh credentials are scoped to that exact site/resource/client relationship. They must not be reused across sites.

The Gateway may refresh an expired site credential when the site's authorization server permits it. A failed or revoked site authorization must fail closed for that site only.

### 6.3 No privilege aggregation

The Gateway is not a WordPress superuser. If the authorizing WordPress principal or WP AI Bridge access settings deny an operation, the Gateway must report that denial and must not seek a lower-level bypass.

## 7. Security requirements

Security is part of the V1 behavior, not a post-release hardening phase.

At minimum:

- production operation requires HTTPS;
- administrator passwords use a current password hash through the application framework;
- administrator forms use CSRF protection;
- login and sensitive endpoints have reasonable rate limiting;
- MCP authorization validates tokens, client/resource binding, redirect URIs, state/PKCE and applicable OAuth metadata according to the supported flow;
- session cookies use secure production settings;
- secrets, private keys, access tokens, refresh tokens, authorization codes, and password material are never written to normal activity logs;
- stored target credentials are encrypted at rest with application-controlled encryption; token lookup material that does not need recovery should be one-way hashed where practical;
- signing private keys are stored outside the public web root with restrictive filesystem permissions;
- losing the application encryption key is treated as loss of access to encrypted target credentials; backup guidance must include the key material needed for recovery;
- outbound target URLs are validated against SSRF, redirect-to-private-network, DNS rebinding, unexpected scheme, and host-change risks;
- downstream HTTP calls have bounded connect/request timeouts and response/body limits;
- the Gateway does not automatically retry a target mutation/tool execution whose idempotency is unknown;
- target identifiers, credentials, and responses from one site must not leak into another site's request;
- errors returned to MCP clients are useful but do not expose secrets or unnecessary internal stack/configuration data;
- destructive administration actions in the web panel require deliberate user interaction and preserve recoverable target-side state when the downstream system supports revocation rather than silent deletion;
- the fresh-install web installer accepts secrets only over HTTPS, does not log or redisplay them, only writes outside-public-root secret material, requires a dedicated empty database, and locks itself after successful installation.

## 8. Data and persistence requirements

Use MySQL migrations for durable schema changes.

V1 needs only the data required for:

- administrator users/sessions as required by the framework;
- registered sites and connector metadata;
- encrypted per-site authorization credentials and expiry state;
- Gateway OAuth/client authorization state required for authenticated MCP access;
- bounded activity/audit metadata;
- minimal application settings.

Do not persist full MCP request or response payloads by default.

Do not introduce a second datastore or cache service unless an evidenced requirement later justifies it.

## 9. Activity, health, and diagnostics

The operator must be able to distinguish at least:

- Gateway application is healthy/unhealthy;
- site is configured but never connected;
- site authorization is connected;
- credentials are expired/revoked/refresh failed;
- site endpoint is unreachable or incompatible;
- a Gateway-routed operation succeeded or failed.

Activity records should contain bounded metadata such as time, actor/client identity when available, site ID, operation identity, outcome, and a correlation/request identifier. They must not contain access tokens, refresh tokens, authorization codes, private keys, passwords, or full arbitrary content/tool payloads.

V1 does not require an external monitoring stack or metrics service.

## 10. Compatibility and protocol policy

- Use maintained official or standards-aligned MCP components where practical rather than implementing JSON-RPC/MCP framing from scratch.
- Treat the official MCP PHP SDK as a replaceable protocol adapter behind a small application boundary; it is not the application's domain model.
- Pin Composer dependencies in `composer.lock` and validate compatible protocol behavior before upgrades.
- Support the protocol revision(s) required by the current ChatGPT custom MCP App and current WP AI Bridge deployment at the time of implementation.
- Preserve backwards-compatible Gateway public behavior within a release line unless a documented breaking change is intentionally accepted.
- Adding a site must not change the public Gateway tool list.
- Adding a future connector family may intentionally add new tools and may require client tool refresh; do not distort V1 WordPress contracts solely to avoid every future MCP schema change.

## 11. Non-goals for V1

V1 deliberately does not provide:

- public multi-tenant SaaS hosting;
- billing/subscriptions;
- complex RBAC or organization hierarchy;
- Redis, queues, workers, WebSockets, or scheduled background processing as mandatory infrastructure;
- Docker/Kubernetes as a deployment requirement;
- React/Vue/SPA administration UI;
- arbitrary HTTP proxying;
- raw SQL or database consoles;
- shell/SSH command execution;
- generic server filesystem access;
- credential extraction from WordPress;
- bypasses around WP AI Bridge or WordPress capabilities;
- automatic installation/modification of WP AI Bridge on remote sites;
- copying all downstream WordPress operations into Gateway-specific implementations;
- a workflow/orchestration engine;
- a marketplace or dynamic third-party code loader;
- a generic hosting control panel or reusable arbitrary-command facility in the installer.

## 12. Future evolution

The architecture must permit, without requiring V1 implementation:

- additional remote MCP clients beyond ChatGPT;
- multiple Gateway administrator accounts and scoped access;
- site grouping/tags;
- additional backend connector types such as other MCP servers or deliberately supported services;
- more detailed health/usage reporting;
- webhooks or automation where a concrete use case justifies them;
- horizontal/runtime scaling if actual load later requires it.

Future features must preserve the core trust rule: the Gateway routes explicitly authorized capabilities; it does not silently convert connector access into unrestricted infrastructure access.

## 13. V1 success criteria

V1 is successful when all of the following are demonstrated against supported test/deployment environments:

1. The application installs on the target PHP 8.4 + OpenLiteSpeed/shared-PHP + MySQL deployment model using the official deployment ZIP and simple web installer; the Git/Composer/Artisan installation path remains supported for advanced operators.
2. The administration panel can securely create an administrator session and manage multiple site records.
3. At least two independent WP AI Bridge sites can be authorized and remain separately revocable.
4. One ChatGPT custom MCP App can authenticate to the Gateway and discover the stable Gateway tools.
5. ChatGPT can list sites, inspect the selected site's available WP AI Bridge operations, and execute authorized read and write operations against either site by explicit `site_id`.
6. A permission denied by WordPress/WP AI Bridge remains denied through the Gateway.
7. A disconnected/revoked site fails closed without breaking other connected sites.
8. Adding a third site does not require another ChatGPT App or a new Gateway MCP endpoint.
9. Direct ChatGPT-to-WP-AI-Bridge operation remains available for sites that use it.
10. Sensitive credentials are not exposed through the panel, installer, MCP responses, application logs, or activity records.
11. A fresh developer/Master can recover project intent, architecture, current work, and validation expectations from the repository and GitHub without relying on prior chat history.
12. An existing deployment-ZIP installation can be upgraded with the official update ZIP without Git or Composer while preserving `.env` and persistent private state, removing stale managed files, and exercising migrations/postflight validation through CI against a real older packaged release.

## 14. Source-of-truth model

Use these sources for different kinds of truth:

- `docs/MASTER-SPEC.md` — project purpose, durable requirements, constraints, non-goals, and V1 completion criteria.
- `docs/ARCHITECTURE.md` — current technical architecture and component boundaries derived from this specification.
- `README.md` — user-facing project overview, prerequisites, installation, usage, and release-level information; it is not an authoritative project-state, architecture, or recovery source.
- GitHub Issues — active work, dependencies, acceptance criteria, risk, and current task state.
- Pull requests/commits — implementation identity and review history.
- CI/test evidence — validation truth for a specific commit.
- deployment/release system — production/release truth when delivery is later authorized.

Conversation history is not an authoritative project source.

## 15. Change rule

Change this specification only when accepted project-level intent, supported deployment constraints, security boundaries, non-goals, or completion criteria materially change.

Implementation details, transient task state, branch/SHA information, and ordinary bug fixes belong in their nearer authoritative sources and must not turn this file into a work log.
