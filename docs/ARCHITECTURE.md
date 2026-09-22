# MCP Gateway Architecture

This document derives the current technical architecture from [`MASTER-SPEC.md`](./MASTER-SPEC.md). The specification owns product intent and durable constraints; this file owns the implementation shape. Active work and task state belong in GitHub Issues.

## 1. Architecture summary

MCP Gateway is a single deployable PHP web application with a server-rendered administration panel, one public MCP endpoint, one MariaDB-primary/MySQL-compatible database, and explicit connector modules.

V1 topology:

```text
                          ChatGPT
                             |
                  OAuth + Streamable HTTP MCP
                             |
                             v
                  +-----------------------+
                  |      MCP Gateway      |
                  |                       |
                  |  Web Admin Panel      |
                  |  OAuth boundary       |
                  |  MCP Server           |
                  |  Site Registry        |
                  |  Router               |
                  |  WP AI Bridge Client  |
                  +-----------+-----------+
                              |
                independent OAuth + MCP per site
                  +-----------+-----------+
                  |           |           |
                  v           v           v
               Site A      Site B      Site C
             WP AI Bridge WP AI Bridge WP AI Bridge
                  |           |           |
               WordPress   WordPress   WordPress

                             |
                             v
                     MariaDB / MySQL
```

The Gateway is a modular monolith. There is one application process model and one database. Modules are code ownership boundaries, not separately deployed services.

WordPress/WP AI Bridge is the first concrete connector path, but the long-lived core is a connector-neutral control plane over stable registered target identity, authorization, inventory, routing, activity, and future operation state. Fleet size is not encoded as a fixed architecture ceiling; capacity is proven incrementally on the supported single-host shape before auxiliary infrastructure is introduced.

## 2. Technology baseline

### Runtime

- PHP 8.4.
- Laravel 13 as the web application framework.
- Blade for the administration UI.
- MariaDB 10.11 as the primary database target; MySQL remains an officially supported compatibility target.
- Composer for dependency management with committed `composer.lock`.
- OpenLiteSpeed/LSAPI as the production web server/runtime path under aaPanel.
- HTTPS on a dedicated domain/subdomain.

Laravel is chosen because this application needs secure session authentication, CSRF protection, validation, migrations, encryption, rate limiting, logging, configuration, testing, and a small server-rendered UI. Using those maintained facilities is lower-risk than rebuilding them in a custom PHP script while still keeping the deployment as one PHP application.

### MCP

Prefer the official `modelcontextprotocol/php-sdk` (`mcp/sdk`) for MCP server/client framing and Streamable HTTP support. Keep all direct SDK usage behind Gateway-owned protocol adapter classes so an SDK change does not leak across the domain/application layers.

The SDK is pre-1.0/experimental at the time this architecture is established. Implementation must therefore pin an exact compatible dependency through Composer, exercise the required server/client paths in tests, and review release notes before SDK upgrades.

The current MCP protocol revision used by V1 is `2026-07-28`. Its primary request path is stateless: request-level protocol/client metadata and capabilities travel in `_meta`, routing uses the required MCP headers such as `Mcp-Method`/`Mcp-Name`, and the modern path does not depend on `initialize` or `Mcp-Session-Id`. The official PHP SDK `0.8.1` supports this modern era and also retains the 2025-era handshake/session compatibility path.

Legacy 2025-era Streamable HTTP compatibility still spans multiple HTTP requests. A PHP-FPM/LSAPI request lifecycle cannot use the SDK's default in-memory session store for that legacy path because the next request may execute in a different process. The single-host V1 compatibility layer therefore uses the SDK file session store in private application storage with bounded TTL and garbage collection. Modern `2026-07-28` requests do not require that store. Horizontal multi-host support for legacy sessions remains outside V1 unless explicitly introduced later.

The SDK Streamable HTTP transport also applies DNS-rebinding protection with localhost-oriented defaults. The public `/mcp` implementation explicitly allows the configured canonical Gateway host while retaining that protection; do not disable host validation merely to make a deployed hostname work.

The official PHP SDK acts as an OAuth Resource Server and can delegate to an authorization server; it intentionally does not mint OAuth tokens itself. MCP Gateway therefore must not assume that `mcp/sdk` is its complete authorization server.

### OAuth implementation rule

Use `league/oauth2-server` `9.4.1` for the in-process authorization-server lifecycle: authorization codes, S256 PKCE validation, access/refresh-token issuance, refresh rotation primitives, and repository-backed revocation state. Token issuance and authorization-code/refresh-token cryptography must remain library-owned rather than controller-owned.

The library does not natively implement the `private_key_jwt` client authentication used by the current ChatGPT/WP AI Bridge contract: its confidential-client path expects a client secret. Keep that responsibility in a narrow Gateway-owned OAuth client-authentication adapter that validates the exact client identity, Client ID Metadata/JWKS, signed client assertion, audience, expiry, and replay state at the League grant boundary. In `league/oauth2-server` `9.4.1`, the Gateway authorization-code and refresh grant adapters may additionally apply the smallest refresh-token eligibility/scope-continuity policy required by the fixed ChatGPT contract, but token generation, encryption, persistence, rotation primitives, revocation, and the rest of the grant lifecycle remain library-owned. Do not route requests through an unadapted grant, reimplement token cryptography/lifecycle in controllers, or downgrade this boundary to a shared secret or unauthenticated public client merely to fit the default library behavior.

The edge adapter is an authentication boundary, not a second token issuer. Persistence adapters implement the League repository contracts so authorization artifacts remain bound to the authenticated client and can be revoked durably. `firebase/php-jwt` `7.1.x` owns JWK parsing and RS256 signature verification; the Gateway owns claim/audience/lifetime/replay policy and persists only a hash of assertion `jti` values for replay prevention.

### HTTP client

Use a PSR-18-compatible HTTP client supported by the MCP SDK/framework. Outbound WP AI Bridge traffic must go through one Gateway HTTP policy layer that owns timeouts, target validation, redirect policy, size bounds, TLS verification, and safe error mapping.

### Deliberately absent infrastructure

V1 has no required:

- Redis;
- queue worker;
- message broker;
- WebSocket server;
- Node.js production runtime;
- SPA frontend;
- Docker/Kubernetes deployment;
- separate auth microservice;
- separate MCP daemon.

Introduce any of these only after an evidenced requirement makes the added operational burden worthwhile.

## 3. Application boundaries

Recommended application ownership:

```text
app/
  Domain/
    Sites/
    Connections/
    Activity/
  Application/
    Sites/
    Routing/
    OAuth/
  Infrastructure/
    Mcp/
    OAuth/
    Http/
    Connectors/
      WpAiBridge/
  Http/
    Controllers/
    Middleware/

resources/views/
database/migrations/
routes/
tests/
```

Exact folders may follow Laravel conventions as implementation evolves. The important constraint is dependency direction:

```text
Web/MCP entrypoints
        -> application services
        -> Gateway domain contracts
        -> infrastructure adapters/connectors
```

Controllers and MCP handlers must not contain raw WP AI Bridge HTTP/OAuth logic.

### Control-plane evolution boundary

The application/domain layer is the long-lived control-plane boundary. MCP, the server-rendered admin UI, and any future API/automation surface are adapters over explicit target identity, lifecycle, authorization, credential, health, activity, and operation rules; transport-specific entrypoints must not become the only owner of those rules.

The project still stops short of a speculative provider framework, but the current scalability evidence in Issue #53 is now a concrete trigger for the first small extraction: admin and MCP inventory consumers need one shared, bounded site-inventory/query boundary instead of independently loading or filtering the fleet. That boundary should own reusable search/filter/order/page semantics and selected projections while remaining an application query service, not a generic repository framework.

Connector generalization remains trigger-driven. Keep the current concrete `WpAiBridge` implementation behind its connector boundary, and introduce only the smallest connector-selection/capability abstraction required by real callers. A second connector/provider is the normal trigger for broader connector contracts; do not invent empty capability methods in advance.

Keep these invariants:

- every target operation retains explicit `site_id`/target identity and authorization boundaries;
- adapters cannot turn the Gateway into a generic privileged HTTP/shell/SQL proxy;
- admin/API/MCP surfaces reuse common inventory, authorization, and application rules rather than reimplementing them;
- administration authorization is permission/policy based; role names are bundles rather than business-logic branches;
- connector-specific behavior stays behind connector boundaries and shared domain rules do not require WordPress semantics;
- inventory/list responses are bounded and deterministic; registered-but-idle targets create no mandatory outbound/background work;
- queues/background workers remain optional workload mechanisms, not baseline dependencies;
- simple single-host PHP + MariaDB/MySQL shared-hosting deployment remains supported until evidence requires otherwise;
- tenant/workspace, bulk-operation, provider-plugin, external search, or microservice abstractions are introduced only for measured use cases.

When bulk/fan-out workflows become concrete, introduce explicit operation/target execution state at the application layer rather than keeping a long synchronous HTTP request alive across many remote sites. That future operation boundary must own idempotency, partial failure, retry eligibility, and progress semantics before a queue backend becomes an implementation detail.

## 4. Core components

### 4.1 Admin Panel

Owns human administration only:

- authenticated local user session;
- dashboard;
- bounded/searchable/paged Sites inventory;
- Sites CRUD;
- Connect/Reconnect/Disconnect/Test actions;
- bounded activity/audit views;
- Gateway connection/settings view;
- lightweight user/access management when the multi-admin workstream is implemented.

Use Blade and ordinary form submissions. Add small progressive JavaScript only where it materially improves a flow. Do not introduce a frontend framework merely for scale; server-side query boundaries own large-list behavior.

All mutations and protected views authorize server-side. Template visibility is a usability layer, never the permission boundary.

### 4.2 Administrative Authorization Boundary

Laravel authentication owns local user/session identity. Gateway permissions registered through Laravel Gates own whether that identity may perform an action, and the shared `AccessControl` application service owns the resource-scope calculation used by both Admin and MCP. Blade visibility mirrors those decisions for usability but is never the enforcement boundary.

The implemented role vocabulary is `owner`, `administrator`, `operator`, and `viewer`. These names are operator-facing bundles only: application behavior checks explicit permissions rather than branching on role names. A role is the maximum permission ceiling. User-level and site-level rules are denial-only narrowing layers and can never manufacture authority absent from the role.

Site authorization is deliberately split into two questions:

1. is the site in the principal's scope; and
2. is the requested capability allowed on that site?

A non-owner principal may use `all` scope with explicit site exclusions or `selected` scope with explicit site inclusions. Direct per-site permission denials are evaluated after scope membership. This separation permits cases such as an Operator who may mutate one selected site while read/catalog access is denied on that same site. The effective rule is:

```text
effective capability
= role permission ceiling
AND no global permission denial
AND site belongs to principal scope
AND no site-specific permission denial
```

The first installed/CLI-created account is the recoverable Owner. An enabled Owner always has all-site authority without global/site denials, and the access-management transaction prevents demoting or disabling the last enabled Owner. Subsequent CLI-created administrators use the Administrator bundle. During the upgrade that introduces this model, every pre-existing local user is preserved as an enabled all-site Administrator and the oldest existing user is promoted to Owner, so the migration does not silently remove access that authenticated users had before authorization was introduced. Fresh post-migration users still start from the least-privilege defaults unless created through an explicit administrator flow. Security-sensitive user/permission/site-rule changes require the acting administrator's current password and write required bounded Activity evidence in the same database transaction; an audit persistence failure rolls back the local security change. Ordinary routed-operation Activity remains best-effort so observability failure can never change an already-authoritative remote result.

Disabling a local user terminates new Admin authentication, invalidates an existing authenticated Admin/OAuth-consent browser session when it is next used, and causes bearer-protected MCP requests to reject existing access tokens because the current user row is re-evaluated on every MCP request. Site-scope and permission changes likewise affect existing MCP access tokens without minting broader replacement credentials.

The Gateway evaluated `spatie/laravel-permission` against the Laravel 13/PHP 8.4 baseline. Because site scope and per-site denial semantics are Gateway domain rules, package-global RBAC would still require a second custom authorization state model. The current implementation therefore uses Laravel Gates plus the smallest explicit Gateway-owned persistence model rather than two competing semantic authorization systems.

Future site groups may contribute another source of site membership without replacing this boundary. Direct per-site rules remain the final narrowing layer so a broad group can later be restricted for one site. This does not imply public tenancy, organization hierarchy, billing, or an enterprise policy engine.

### 4.3 Site Registry

Owns durable target identity.

A registered site/target record has at least:

- internal immutable numeric/UUID/ULID identity;
- stable human-facing slug or short identifier suitable for MCP and administration input;
- display name;
- canonical base/target identity appropriate to the supported connector;
- connector type (`wp_ai_bridge` in V1);
- current connection state metadata;
- timestamps.

The human-facing `site_id`/slug used by MCP should be stable and must not be inferred from the host on every request.

The current V1 schema may contain WP AI Bridge-specific discovered endpoint fields because only that connector exists. New shared application behavior must not make those fields universal connector requirements. When a concrete second connector needs materially different durable configuration, prefer a narrow connector-owned configuration/table boundary over indefinitely widening the common `sites` row with unrelated nullable columns.

Site records never contain plaintext passwords or plaintext OAuth tokens.

### 4.4 Site Inventory Query Boundary

One application-level query service owns fleet discovery semantics shared by Admin, MCP, and future read-only API/automation consumers.

Responsibilities:

- bounded server-side search, filter, deterministic order, and pagination/cursor behavior;
- explicit maximum page sizes and selected-column/projection choices;
- query shapes that can be supported by measured MariaDB-primary/MySQL-compatible indexes;
- policy-aware filtering when resource-scoped administration is later introduced;
- machine-facing continuation metadata sufficient to discover every authorized target without returning the whole fleet.

The admin UI may use page-oriented navigation where that is clearer for humans. MCP/machine discovery should prefer deterministic cursor/keyset continuation when it avoids deep-offset or mutation-order ambiguity. Exact strategy remains evidence-driven, but the whole fleet must never be loaded merely to render or serialize one page.

Scale fixtures and query measurements belong in tests/Issue evidence, not in this service as hard-coded product limits.

### 4.5 Credential Store

Owns recoverable secrets required to call target sites and any Gateway-held OAuth server state that must be confidential.

Rules:

- encrypt recoverable target access/refresh tokens using application-controlled encryption;
- one-way hash opaque bearer/refresh/authorization artifacts when lookup can be performed by hash and plaintext recovery is unnecessary;
- keep signing private keys outside the public web root with restrictive filesystem permissions;
- never expose secret fields through model serialization, admin pages, logs, exceptions, or MCP results;
- token/credential rows are bound to the exact site and OAuth client/resource relationship.

### 4.6 MCP Server Adapter

Owns the single public MCP endpoint, expected initially at:

```text
https://gateway.example.com/mcp
```

Responsibilities:

- HTTP/MCP transport handling;
- MCP protocol version negotiation/compatibility through the SDK;
- authenticated principal/context injection;
- registration of the stable Gateway tools;
- bounded request sizes and safe origin/host handling;
- mapping application/domain errors to useful MCP errors without leaking secrets.

MCP handlers call application services; they do not make raw downstream HTTP requests.

### 4.7 Client Authorization Boundary

Owns `remote MCP client -> Gateway` authorization.

The V1 public surfaces are:

```text
/.well-known/oauth-protected-resource/mcp
/.well-known/oauth-authorization-server
/oauth/authorize
/oauth/token
/oauth/revoke
/mcp
```

The protected-resource metadata path follows RFC 9728 path insertion for the exact resource URI `/mcp`. The authorization-server metadata, authorization, token, revocation and MCP paths must remain stable and internally consistent.

V1 ChatGPT requirements:

- authorization code flow;
- PKCE where required;
- correct client authentication for the current ChatGPT MCP App contract;
- exact redirect validation;
- resource binding/audience validation;
- `mcp` as the required resource scope;
- the required `mcp` authorization is refreshable for the fixed ChatGPT client so connectivity survives bounded access-token expiry even when ChatGPT omits `offline_access`; `offline_access` remains accepted and advertised for client compatibility, while refresh rotation, replay protection, expiry, and authorization-wide revocation remain enforced;
- RFC 9207 `iss` on authorization responses to reduce authorization-server mix-up risk;
- revocation;
- expiry and rotation semantics;
- no authorization without a valid local Gateway administrator/operator identity and explicit consent/connection flow.

Do not couple administrator browser sessions to bearer-token validation simply because both use the same application database.

### 4.8 WP AI Bridge Connector

The first connector encapsulates every WordPress-specific integration detail.

Responsibilities:

- validate/discover the canonical WP AI Bridge endpoint and OAuth metadata;
- build the site authorization request;
- complete the OAuth callback/token exchange;
- refresh/revoke site credentials where supported;
- connect to the remote MCP endpoint;
- discover Bridge MCP tools/Abilities;
- execute only the expected bounded Bridge MCP contract;
- translate connectivity/auth/protocol errors into Gateway connector errors;
- expose a small health/status result.

The connector does not bypass WP AI Bridge by calling unrelated WordPress endpoints to obtain additional authority.

### 4.9 Connector Selection Boundary

Connector selection is centralized from the stored `connector_type` to a concrete, explicitly supported connector implementation. A small registry/factory or container mapping is sufficient while the connector set is small.

This is not a dynamic third-party plugin loader. Callers cannot supply class names, URLs, HTTP methods, or executable connector code. Unsupported connector types fail closed.

A second real connector is the trigger to extract only the common contracts/capabilities that both implementations actually share. Until then, keep `WpAiBridge` concrete rather than designing a broad theoretical provider SDK.

### 4.10 Router

The Router accepts an explicit `site_id`, loads the exact site/credential record, resolves the site's declared connector through the connector-selection boundary, and performs the requested bounded connector operation.

Routing invariants:

1. No target-specific action without explicit `site_id`.
2. `site_id` resolves exactly one stored enabled site.
3. The stored canonical target owns the outbound host/resource; callers cannot replace it with a request URL.
4. Credential lookup is scoped to that exact site.
5. Target mutation/tool execution is sent once unless the operation is explicitly known to be idempotent; authentication refresh may be handled separately.
6. The downstream denial remains a denial.
7. Every result/error retains enough site/correlation identity for diagnosis without exposing secrets.

## 5. Public MCP tool surface for V1

Keep the client-facing surface deliberately small and stable. Exact naming may be normalized during implementation, but the semantic contract should remain equivalent to:

### `sites-list`

Returns bounded non-secret identity/status information for configured sites available to the authenticated Gateway principal.

The contract must support deterministic continuation once the fleet exceeds one response. Bounded search/filter fields and a capped requested limit may be exposed where they materially improve discovery. A no-argument call may preserve the simple first-page behavior for compatibility, but a truncation flag without a continuation/search path is not sufficient.

No credentials, token expiry secrets, private internal paths, or sensitive configuration.

### `site-context`

Input: explicit `site_id`.

Returns useful target/connector context and current connection availability. It must distinguish configured, connected, unreachable, unauthorized/revoked, and incompatible states where evidence allows.

### `site-abilities-read`

Input: explicit `site_id`, with optional exact ability name/filter/pagination fields.

Uses the site's WP AI Bridge discovery contract to return the real operation identity/schema/delegation information instead of copying every WordPress operation into the Gateway.

### `site-ability-execute`

Input:

- explicit `site_id`;
- exact downstream Ability/operation identity;
- its input payload.

The Gateway calls the selected site's existing WP AI Bridge execution contract. It does not loosen the site's WordPress/Bridge authorization. It must not accept a URL, HTTP method, raw route, SQL statement, shell command, or filesystem path as a substitute for an Ability identity.

### Why this surface is stable

Sites are data. Adding Site D changes `sites-list`, not the MCP tool registry. ChatGPT therefore keeps one Gateway App and one Gateway endpoint as the site fleet changes.

A future non-WordPress connector may add a deliberately designed tool family if its semantics cannot be represented honestly by the WordPress Ability contract. Do not force every future system through `site-ability-execute` merely to avoid a future tool refresh.

## 6. OAuth flows

### 6.1 ChatGPT -> Gateway

```text
ChatGPT
  -> discovers Gateway protected-resource / authorization metadata
  -> starts authorization request
  -> Gateway authenticates the local operator
  -> operator authorizes client
  -> Gateway issues authorization code
  -> ChatGPT exchanges code using required client authentication + PKCE
  -> Gateway issues bounded access token + refresh token when allowed
  -> ChatGPT calls /mcp with Bearer token
  -> Gateway validates token/resource/scopes/current authorization
```

The implementation must verify current OpenAI client metadata/client assertion behavior rather than assuming an old ChatGPT OAuth shape forever. As verified on 2026-09-14, the configured current client identity is `https://chatgpt.com/oauth/client.json`, with the exact ChatGPT connector redirect URI, `private_key_jwt`, RS256 assertions, authorization-code + refresh-token grants, and JWKS at the metadata-advertised same-origin URI. No signing key is hard-coded; the Gateway refreshes the bounded metadata/JWKS cache when assertion verification requires current keys.

### 6.2 Gateway -> WP AI Bridge

Preferred compatibility direction is to reuse WP AI Bridge's existing OAuth security model rather than add a weaker shared-password bypass.

Expected flow:

```text
Gateway hosts an HTTPS OAuth client metadata document + public verification key
  -> operator adds WordPress site
  -> Gateway discovers WP AI Bridge metadata
  -> Gateway builds authorization request with PKCE and exact site resource
  -> WordPress user logs in and approves
  -> callback returns to exact Gateway redirect URI
  -> Gateway authenticates itself to the Bridge token endpoint
  -> Gateway stores encrypted site access/refresh credentials
  -> Gateway calls the site's MCP endpoint with that site's Bearer token
```

At architecture creation time, WP AI Bridge's direct OAuth implementation is ChatGPT-client-specific. The cross-repository compatibility task must preserve the existing direct ChatGPT client while adding the smallest safe mechanism for an administrator-approved Gateway client. The preferred design is to generalize the existing HTTPS client-metadata/private-key assertion model to explicitly approved clients rather than introducing a generic unauthenticated client or WordPress password exchange.

The Gateway must not depend on that preferred implementation detail until the WP AI Bridge task confirms its exact contract.

## 7. Outbound request security

A central Gateway creates SSRF and cross-target risks that do not exist in the same way for a browser-only panel. All outbound site communication therefore passes through one target policy.

Required behavior:

- only `https` target schemes in production;
- normalize and persist a canonical host/resource during site onboarding;
- reject userinfo, fragments, malformed ports, and ambiguous hosts;
- reject loopback, link-local, private, multicast, unspecified, metadata-service, and other non-public addresses for V1;
- validate every resolved address, not only the originally typed hostname;
- re-evaluate DNS/address safety before outbound connections where the HTTP stack allows it;
- do not follow a redirect to a different/unapproved host or to a disallowed address class;
- TLS verification remains enabled;
- bounded redirect count, connect timeout, total request timeout, response size and SSE buffer;
- never allow MCP input to override the connector's stored endpoint with an arbitrary URL.

If future requirements include private-network sites, that is a product/security change requiring an explicit supported-network design; do not silently relax V1 SSRF rules.

## 8. Persistence model

Initial/current logical tables may include:

```text
users
sessions                       # framework-dependent
roles / permissions            # only when lightweight multi-admin authorization is enabled
sites
connector-specific state       # dedicated only when a connector requires durable fields beyond shared identity
site_credentials
mcp_authorizations             # if useful as an authorization aggregate
mcp_access_tokens              # exact storage depends on chosen OAuth library
mcp_refresh_tokens             # exact storage depends on chosen OAuth library
activity_events
audit_events                   # when distinct security/admin audit semantics are required
settings                       # only if settings do not fit config or dedicated tables
operation / operation_targets  # only when real asynchronous/bulk workflows require durable job state
```

Do not create a generic key/value database for domain state merely to avoid migrations. Do not add speculative tables merely because they appear in this future-capable logical model; each table must be introduced by a concrete accepted feature.

Use foreign keys/unique constraints where they enforce real invariants. Site deletion/disconnect semantics must deliberately handle credentials rather than leaving orphaned live tokens.

## 9. Activity and diagnostics

### Application logs

Use structured/contextual logging for operational diagnosis. Include a generated correlation ID on inbound MCP and important connector operations.

Never log bearer tokens, refresh tokens, authorization codes, private keys, passwords, client assertions, or full arbitrary MCP payloads.

### Activity records

Activity is operator-facing audit metadata, distinct from debug logs. Record only what is needed to answer who/what/where/outcome:

- timestamp;
- Gateway actor/client identity when available;
- site ID when targeted;
- Gateway operation/downstream Ability identity;
- result class/status;
- correlation ID;
- concise safe error category.

Retention targets are bounded by configuration. The current defaults prune Activity older than 30 days and overflow beyond 5,000 rows through `ACTIVITY_RETENTION_DAYS` and `ACTIVITY_MAX_ROWS`; because enforcement is scheduled, short-lived row-count overshoot between prune runs is expected.

Retention enforcement must not become a fleet/concurrency bottleneck. The routed-request hot path performs one bounded Activity insert and does not acquire the global retention lock, run a full count, or scan overflow. Scheduled/manual pruning serializes only competing prune runs and processes deletion candidates in fixed-size batches, so retention maintenance remains outside unrelated routed operations.

Security/admin audit may use separate retention/storage semantics when multi-user administration requires durable accountability. Do not make debug logs the authoritative audit record.

### Health

Provide a cheap application health endpoint that proves the application can boot and reach required local dependencies as appropriate. Do not make it call every remote site.

Dashboard/list views use stored connection/last-health state. Opening an overview must never trigger synchronous fleet-wide health probes.

Per-site health is explicit/on-demand in the panel and connector layer. If periodic fleet health checks become a real requirement, run them as chunked/bounded work with persisted status rather than coupling them to page rendering.

## 10. Failure semantics

### Authentication failure

Fail closed. Do not route the MCP request.

### Site token expired

Refresh only through the supported site OAuth refresh flow. If refresh fails, mark/report the connection as requiring reconnection; do not reuse a failed credential or authenticate through another site.

### Network failure

Return a bounded target-unavailable error with site identity and correlation ID. Do not retry an unknown write automatically.

### Downstream permission denial

Return the denial as a permission/authorization outcome. Do not convert it into a missing-tool result and do not search for a lower-level bypass.

### Protocol incompatibility

Report it separately from authentication or network failure and surface enough version/capability evidence for the operator to upgrade the correct component.

## 11. Deployment architecture

Expected aaPanel layout conceptually:

```text
/www/wwwroot/gateway.example.com/
  app/
  bootstrap/
  config/
  database/
  public/        <- OpenLiteSpeed document root
  resources/
  routes/
  storage/       <- writable application data/logs/private key material as designed
  vendor/
  .env           <- never under public document root
```

Production rules:

- document root is `public/`, never repository root;
- PHP 8.4 selected for the site;
- Composer dependencies installed without development packages for production after validation;
- application key generated and backed up securely;
- database user has only the privileges the application requires on its own database;
- writable permissions limited to Laravel-required storage/cache paths and explicitly owned private key paths;
- debug mode disabled;
- HTTPS enforced;
- backup/restore guidance covers database plus application encryption/signing material needed to recover encrypted connections;
- deployment does not require Node, Redis, Supervisor, or Docker for normal V1 requests.

OpenLiteSpeed-specific buffering/streaming behavior must be validated against the selected MCP protocol/SDK during implementation. Do not assume development-server behavior proves production Streamable HTTP behavior.

## 12. Testing architecture

At minimum provide:

- unit tests for URL/SSRF policy, site routing and credential isolation;
- application tests for administrator auth/CSRF and site lifecycle;
- OAuth tests for valid/invalid client, redirect, state, PKCE, expiry, refresh and revocation;
- MCP server contract tests;
- WP AI Bridge connector tests with controlled fixtures/mocks for failure behavior;
- real integration tests against supported WP AI Bridge test installations for the final compatibility path;
- cross-site isolation tests using at least two sites;
- tests proving a denied downstream WordPress/Bridge operation remains denied;
- tests proving mutation execution is not blindly retried;
- scale fixtures/benchmarks that exercise realistic near-term inventories in the hundreds (including representative 200–500-site cases) and record query count, response bounding, runtime/memory, and relevant MariaDB-primary/MySQL-compatible query-plan/index evidence;
- larger synthetic inventory stress cases such as 1,000 / 3,000 / 10,000 sites when useful to expose nonlinear behavior or preserve headroom; these are diagnostics, not supported-capacity promises;
- tests proving Admin and MCP inventory consumers do not load/serialize the full fleet and that machine continuation can discover targets beyond the first response;
- contention/performance evidence for Activity retention changes when the write hot path is modified;
- a production-like OpenLiteSpeed/PHP 8.4 smoke check before declaring V1 deployment-ready.

Performance assertions should focus on bounded behavior, query counts/plans, memory growth, and regressions under comparable workloads rather than brittle wall-clock thresholds from unrelated CI hardware.

CI should run the highest-signal repository checks that can run deterministically on GitHub-hosted infrastructure. Do not reproduce aaPanel itself in CI merely for ceremony.

## 13. Dependency and upgrade policy

- Commit `composer.lock`.
- Prefer current maintained major versions compatible with PHP 8.4.
- Review changelogs for MCP/OAuth/security-sensitive dependencies before upgrades.
- Do not spread vendor APIs through domain code; wrap MCP SDK, OAuth-server, and target HTTP details in infrastructure boundaries.
- Do not automatically update major protocol/auth dependencies in production without tests tied to the resulting lockfile.
- For commodity authorization/queue/storage capabilities, evaluate maintained Laravel/framework-aligned components before custom implementations; accept a dependency only when its security, compatibility, maintenance, migration, and operational cost is lower than owning equivalent custom code.
- Keep application Policies/Gates and application job/operation semantics as Gateway-owned boundaries even when a package/framework owns persistence or transport mechanics.

## 14. Architecture invariants for future work

A future change must not casually violate these invariants:

1. One Gateway deployment and one stable public MCP endpoint serve many configured targets.
2. Site/target identity is explicit for every routed target operation.
3. Per-site credentials are isolated.
4. Gateway authorization cannot grant downstream authority the target principal/connector does not possess.
5. Direct WP AI Bridge operation remains independent of Gateway availability.
6. No arbitrary HTTP/SQL/shell/filesystem proxy is introduced as a shortcut.
7. Security-sensitive OAuth/token behavior is standards/library-backed and tested.
8. V1 stays a normal PHP + MariaDB-primary/MySQL-compatible web application with no mandatory auxiliary services.
9. WP AI Bridge-specific behavior stays behind its connector boundary; the core target/inventory/authorization model remains connector-neutral.
10. Administrative authorization is permission/policy based; role names are replaceable bundles, not distributed business logic.
11. Fleet discovery and administration are bounded; registered-but-idle sites do not create mandatory remote work.
12. The Gateway scales infrastructure from measured active workload rather than from a fixed registered-site-count assumption.
13. Heavy backup/media/export data stays off the Gateway data path by default when direct target-to-storage flow is possible.
14. Active task/status truth stays in GitHub Issues/PRs, not this document.

## 15. Bootstrap decisions and remaining verification points

The first implementation workstream established these dependency boundaries with executable/source evidence:

- `mcp/sdk` `0.8.1` on PHP 8.4, isolated behind Gateway infrastructure adapters;
- Laravel/Symfony HTTP Foundation to PSR HTTP conversion through `symfony/psr-http-message-bridge` `8.1.x`;
- `league/oauth2-server` `9.4.1` for authorization-code/PKCE/token/refresh/revocation lifecycle primitives, preceded by a Gateway-owned `private_key_jwt` client-authentication adapter.

The ChatGPT-facing workstream adds the concrete RFC 9728 resource metadata, authorization-server metadata, authenticated operator consent boundary, League-backed authorization-code/S256 PKCE/token/refresh/revocation persistence, current ChatGPT CIMD/JWKS `private_key_jwt` verification, and bearer-protected `/mcp` endpoint with the stable four-tool registry. Administrator login UI remains owned by the administration-panel workstream rather than being duplicated in the OAuth layer.

The following remain implementation/deployment verification points:

- live ChatGPT workspace interoperability after the administrator login UI and production-like deployment path exist;
- the exact WP AI Bridge extension needed to approve the Gateway as an additional client while preserving existing ChatGPT behavior;
- OpenLiteSpeed/LSAPI buffering and Streamable HTTP behavior on the selected production stack.

Downstream work must preserve the established boundaries and resolve the remaining points with executable evidence rather than assumptions.