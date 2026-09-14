# MCP Gateway Architecture

This document derives the current technical architecture from [`MASTER-SPEC.md`](../MASTER-SPEC.md). The specification owns product intent and durable constraints; this file owns the implementation shape. Active work and task state belong in GitHub Issues.

## 1. Architecture summary

MCP Gateway is a single deployable PHP web application with a server-rendered administration panel, one public MCP endpoint, one MySQL database, and explicit connector modules.

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
                           MySQL
```

The Gateway is a modular monolith. There is one application process model and one database. Modules are code ownership boundaries, not separately deployed services.

## 2. Technology baseline

### Runtime

- PHP 8.4.
- Laravel 13 as the web application framework.
- Blade for the administration UI.
- MySQL as the primary database.
- Composer for dependency management with committed `composer.lock`.
- OpenLiteSpeed/LSAPI as the production web server/runtime path under aaPanel.
- HTTPS on a dedicated domain/subdomain.

Laravel is chosen because this application needs secure session authentication, CSRF protection, validation, migrations, encryption, rate limiting, logging, configuration, testing, and a small server-rendered UI. Using those maintained facilities is lower-risk than rebuilding them in a custom PHP script while still keeping the deployment as one PHP application.

### MCP

Prefer the official `modelcontextprotocol/php-sdk` (`mcp/sdk`) for MCP server/client framing and Streamable HTTP support. Keep all direct SDK usage behind Gateway-owned protocol adapter classes so an SDK change does not leak across the domain/application layers.

The SDK is pre-1.0/experimental at the time this architecture is established. Implementation must therefore pin an exact compatible dependency through Composer, exercise the required server/client paths in tests, and review release notes before SDK upgrades.

The official PHP SDK acts as an OAuth Resource Server and can delegate to an authorization server; it intentionally does not mint OAuth tokens itself. MCP Gateway therefore must not assume that `mcp/sdk` is its complete authorization server.

### OAuth implementation rule

Use a maintained OAuth 2.x/OAuth 2.1-compatible authorization-server library or a proven framework integration for token issuance, authorization codes, refresh tokens, PKCE, revocation, and token lifecycle. `league/oauth2-server` is the initial preferred in-process candidate because V1 must remain a single self-hosted PHP application, but the first implementation task must verify that the selected version can satisfy the current ChatGPT MCP client contract without weakening required client authentication semantics.

Do not hand-roll signing, authorization-code storage, refresh-token rotation, or bearer-token validation when a maintained component can own those semantics.

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

## 4. Core components

### 4.1 Admin Panel

Owns human administration only:

- administrator session;
- dashboard;
- Sites CRUD;
- Connect/Reconnect/Disconnect/Test actions;
- bounded activity view;
- Gateway connection/settings view.

Use Blade and ordinary form submissions. Add small progressive JavaScript only where it materially improves a flow. Do not introduce a frontend framework for V1.

### 4.2 Site Registry

Owns durable target identity.

A WordPress site record has at least:

- internal immutable numeric/UUID identity;
- stable human-facing slug or short identifier suitable for MCP input;
- display name;
- canonical HTTPS base URL;
- connector type (`wp_ai_bridge` in V1);
- discovered canonical MCP resource URL;
- current connection state metadata;
- timestamps.

The human-facing `site_id`/slug used by MCP should be stable and must not be inferred from the host on every request.

Site records never contain plaintext passwords or plaintext OAuth tokens.

### 4.3 Credential Store

Owns recoverable secrets required to call target sites and any Gateway-held OAuth server state that must be confidential.

Rules:

- encrypt recoverable target access/refresh tokens using application-controlled encryption;
- one-way hash opaque bearer/refresh/authorization artifacts when lookup can be performed by hash and plaintext recovery is unnecessary;
- keep signing private keys outside the public web root with restrictive filesystem permissions;
- never expose secret fields through model serialization, admin pages, logs, exceptions, or MCP results;
- token/credential rows are bound to the exact site and OAuth client/resource relationship.

### 4.4 MCP Server Adapter

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

### 4.5 Client Authorization Boundary

Owns `remote MCP client -> Gateway` authorization.

Expected public surfaces include the standards-required equivalents of:

```text
/.well-known/oauth-protected-resource
/.well-known/oauth-authorization-server
/oauth/authorize
/oauth/token
/oauth/revoke
/mcp
```

Exact paths must remain internally consistent and standards-compliant.

V1 ChatGPT requirements:

- authorization code flow;
- PKCE where required;
- correct client authentication for the current ChatGPT MCP App contract;
- exact redirect validation;
- resource binding/audience validation;
- `offline_access`/refresh token support when the current ChatGPT contract needs refreshable access;
- revocation;
- expiry and rotation semantics;
- no authorization without a valid local Gateway administrator/operator identity and explicit consent/connection flow.

Do not couple administrator browser sessions to bearer-token validation simply because both use the same application database.

### 4.6 WP AI Bridge Connector

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

### 4.7 Router

The Router accepts an explicit `site_id`, loads the exact site/credential record, resolves the site's connector, and performs the requested bounded connector operation.

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

The implementation must verify current OpenAI client metadata/client assertion behavior rather than assuming an old ChatGPT OAuth shape forever.

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

Initial logical tables may include:

```text
users
sessions                       # framework-dependent
sites
site_credentials
mcp_authorizations             # if useful as an authorization aggregate
mcp_access_tokens              # exact storage depends on chosen OAuth library
mcp_refresh_tokens             # exact storage depends on chosen OAuth library
activity_logs
settings                       # only if settings do not fit config or dedicated tables
```

Do not create a generic key/value database for domain state merely to avoid migrations.

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

### Health

Provide a cheap application health endpoint that proves the application can boot and reach required local dependencies as appropriate. Do not make it call every remote WordPress site.

Per-site health is explicit/on-demand in the panel and connector layer.

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
- MySQL user has only the privileges the application requires on its own database;
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
- a production-like OpenLiteSpeed/PHP 8.4 smoke check before declaring V1 deployment-ready.

CI should run the highest-signal repository checks that can run deterministically on GitHub-hosted infrastructure. Do not reproduce aaPanel itself in CI merely for ceremony.

## 13. Dependency and upgrade policy

- Commit `composer.lock`.
- Prefer current maintained major versions compatible with PHP 8.4.
- Review changelogs for MCP/OAuth/security-sensitive dependencies before upgrades.
- Do not spread vendor APIs through domain code; wrap MCP SDK, OAuth-server, and target HTTP details in infrastructure boundaries.
- Do not automatically update major protocol/auth dependencies in production without tests tied to the resulting lockfile.

## 14. Architecture invariants for future work

A future change must not casually violate these invariants:

1. One Gateway deployment and one stable public MCP endpoint serve many configured sites.
2. Site identity is explicit for every routed site operation.
3. Per-site credentials are isolated.
4. Gateway authorization cannot grant WordPress authority the target user/Bridge does not possess.
5. Direct WP AI Bridge operation remains independent of Gateway availability.
6. No arbitrary HTTP/SQL/shell/filesystem proxy is introduced as a shortcut.
7. Security-sensitive OAuth/token behavior is standards/library-backed and tested.
8. V1 stays a normal PHP + MySQL web application with no mandatory auxiliary services.
9. WP AI Bridge-specific behavior stays behind its connector boundary.
10. Active task/status truth stays in GitHub Issues/PRs, not this document.

## 15. Known implementation verification points

The following are intentionally implementation tasks rather than assumptions baked into the architecture:

- exact compatible `mcp/sdk` version and Laravel/PSR integration path on PHP 8.4;
- exact OAuth authorization-server library integration needed for current ChatGPT client authentication, refresh and revocation behavior;
- exact WP AI Bridge extension needed to approve the Gateway as an additional client while preserving existing ChatGPT behavior;
- OpenLiteSpeed response buffering/Streamable HTTP behavior under the selected MCP protocol revision.

The first implementation workstream must resolve these with executable evidence before downstream tasks rely on them.