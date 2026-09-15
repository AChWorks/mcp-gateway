# MCP Gateway Development

This document owns the repeatable development and validation workflow. User-facing installation belongs in `README.md` once a production release exists.

## Baseline

The current bootstrap is intentionally a conventional PHP application:

- PHP 8.4.1 or newer within the PHP 8.4-compatible dependency range;
- Laravel 13;
- Composer 2;
- MySQL as the production database;
- Blade/server-rendered frontend;
- no required Node.js build, Redis, queue worker, Docker, broker, or separate MCP daemon.

CI uses MySQL 8.4 only in the dedicated path-filtered MySQL validation workflow. Application tests may use SQLite in memory when the test does not depend on MySQL-specific behavior.

## Install a development checkout

From the repository root:

```bash
composer install
cp .env.example .env
php artisan key:generate
```

Edit only the database values in `.env` for the local MySQL database and account you created:

```dotenv
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=mcp_gateway
DB_USERNAME=mcp_gateway
DB_PASSWORD=your-local-password
```

Then initialize and validate the application:

```bash
php artisan migrate
php artisan gateway:check
composer check
```

Run the local web server when needed:

```bash
composer dev
```

The health endpoint is `/up`.

## Administrator bootstrap

After migrations, create an administrator from the application host:

```bash
php artisan gateway:admin:create
```

Name and email may be supplied as non-secret options when useful:

```bash
php artisan gateway:admin:create --name="Gateway Admin" --email="admin@example.test"
```

The password is always requested interactively through a hidden prompt and is never accepted as a command-line option. It must contain at least 12 characters with mixed case, a number, and a symbol. The command normalizes the email address and relies on the `User` model's framework hashing cast; there is no committed/default administrator password, public registration route, or password-reset flow in V0.1.

Once the application is running, administrator sign-in is available at `/admin/login`. The admin routes use Laravel's stateful web session and CSRF middleware. Production continues to require the secure session settings checked by `gateway:check`; do not weaken HTTPS-only, encrypted, HTTP-only, or SameSite cookie behavior to make local authentication easier.

## Proportional validation and review cadence

Optimize for finished, verified changes rather than repeated ceremony.

During implementation:

- run the narrowest tests or static checks that can detect regressions in the surface being changed;
- do not rerun an already-green broad suite after every small edit when that edit cannot invalidate its evidence;
- keep the pull request closed until the implementation is functionally complete and self-review is clean, unless PR-based evidence is specifically needed earlier;
- avoid independent review while the implementation is still moving materially.

At candidate freeze:

- inspect the full effective diff and acceptance criteria;
- run one full repository CI for the frozen candidate when the Issue/contract requires broad exact-candidate evidence;
- run the exact WP AI Bridge contract only when the effective change can affect Bridge/OAuth/MCP/site-routing/connector/HTTP compatibility; presentation-only, documentation-only, CSS-only, or unrelated administration changes do not justify a manual Bridge-contract rerun;
- request independent review only after the candidate identity and required validation are stable.

After a review finding or late change:

- validate only the remediation delta first;
- rerun broader checks only when the delta can invalidate their prior evidence or when exact-candidate policy requires a final full run;
- a fresh review should focus on the changed delta and closure of prior findings unless scope, assumptions, risk, or target identity changed materially;
- reuse unaffected green evidence when the later delta does not touch or invalidate what that evidence proved; do not replay identical checks just because the commit SHA changed;
- if the Issue explicitly requires exact-final-candidate broad CI, complete expected edits before that final run instead of repeatedly refreezing after cosmetic cleanup.

After integration:

- verify the integrated commit/tree and intended effective change;
- when a squash merge onto the unchanged target produces the same tree as the reviewed and validated candidate, do not manually repeat the same full validation solely for ceremony;
- repository-triggered `main` CI may still run as a safety net, but do not rerun successful jobs or repeatedly inspect full logs unless a failure, drift, or new evidence requires it.

If a validation layer fails, diagnose the smallest root cause and run the discriminating check first. Do not bounce between full CI and broad review while implementation is still incomplete.

## Deterministic validation

The normal repository checks are:

```bash
composer validate --strict
composer audit --locked
composer lint
composer analyse
composer test
```

`composer check` runs style, static analysis, and tests together. Common CI runs these broad application checks plus runtime-readiness checks without starting MySQL. The dedicated path-filtered `MySQL Concurrency` workflow owns MySQL 8.4 `migrate:fresh` and the `mysql-concurrency` test group only when persistence/OAuth/site-lifecycle surfaces can invalidate that evidence. The exact WP AI Bridge contract remains a separate path-filtered compatibility gate. Draft pull requests skip these heavy jobs until they are marked ready for review.

## MCP bootstrap compatibility fixture

`/_internal/mcp-bootstrap` exists only to prove the Laravel/PSR/MCP SDK integration during bootstrap. It is disabled by default and returns `404` unless both of these test-only settings are supplied:

```dotenv
MCP_BOOTSTRAP_FIXTURE_ENABLED=true
MCP_BOOTSTRAP_FIXTURE_TOKEN=an-ephemeral-test-token
```

Do not enable this fixture in production. The integration test starts an isolated local Laravel process, sends an explicit bearer token through the official MCP PHP client, exercises Streamable HTTP, lists the controlled fixture tool, and then shuts the process down.

The production MCP endpoint is implemented by the ChatGPT-facing workstream, not by promoting this fixture.

The production `/mcp` path is modern-first on MCP `2026-07-28`. Modern requests are stateless, carry request metadata/capabilities in `_meta`, and use the required MCP routing headers (`Mcp-Method` and `Mcp-Name` where applicable); they do not rely on `initialize` or `Mcp-Session-Id`. Integration tests exercise modern `tools/list` and `tools/call` and verify that no session ID is returned.

The same endpoint intentionally retains SDK compatibility with 2025-era handshake clients. Only that legacy path needs cross-request session continuity. Because the SDK in-memory store does not survive ordinary PHP worker/request boundaries, legacy compatibility uses `FileSessionStore` under `storage/framework/mcp-sessions` with bounded TTL (`MCP_SESSION_TTL_SECONDS`, default `3600`). That directory is private application state and ignored by Git. A future multi-host deployment would need shared durable storage only if legacy session compatibility is retained across hosts.

For the production endpoint, preserve the SDK's DNS-rebinding/Host protection and configure the exact canonical Gateway hostname. Localhost-oriented defaults are appropriate for the bootstrap fixture but are not a reason to disable host validation.

## Locked protocol dependencies

The bootstrap deliberately isolates protocol packages behind `app/Infrastructure` adapters.

- `mcp/sdk` `0.8.1` — official PHP MCP SDK; owns MCP server/client framing and Streamable HTTP behavior.
- `symfony/psr-http-message-bridge` `8.1.x` — converts Laravel/Symfony HTTP Foundation requests and responses at the SDK boundary.
- `league/oauth2-server` `9.4.1` — owns authorization-code, PKCE, access/refresh-token issuance, rotation primitives, signed access tokens, and token/code revocation semantics.
- `firebase/php-jwt` `7.1.x` — owns JWK parsing and RS256 client-assertion signature verification; Gateway policy still validates exact client/claims/audience/lifetime/replay.

Composer's lockfile is authoritative for transitive versions. Dependency upgrades require release-note review plus the focused MCP/OAuth compatibility tests; do not widen these constraints casually while the MCP SDK remains pre-1.0.

## OAuth boundary selected by bootstrap

`league/oauth2-server` does not natively authenticate OAuth clients with `private_key_jwt`. Its confidential-client path expects a client secret, while the current ChatGPT/WP AI Bridge contract uses Client ID Metadata plus signed `private_key_jwt` client assertions.

Therefore the Gateway authorization server uses this split:

1. a Gateway-owned OAuth edge adapter validates the exact approved client identity, metadata/JWKS, `private_key_jwt`, audience, signature, expiry, and replay rules;
2. only a successfully authenticated request may reach the League authorization-server lifecycle;
3. League owns authorization-code/PKCE validation and access/refresh-token issuance/rotation primitives;
4. Gateway persistence adapters implement League repository interfaces and durable revocation state;
5. token issuance, authorization-code cryptography, and refresh-token generation are not reimplemented by application controllers.

The ChatGPT-facing implementation preserves that split: only adapted authorization-code/refresh grants are exposed, raw token/code/assertion values are not stored as application records, and revocation invalidates the durable authorization that all related token records reference.

## ChatGPT-facing OAuth/MCP development

Generate a local/test signing pair outside the public web root before running runtime readiness checks:

```bash
php artisan gateway:oauth-keygen --env=testing --force
php artisan gateway:check --env=testing
```

Production must use its own generated keypair and must not reuse test keys. `gateway:check` verifies a matched readable keypair, restricted key-file permissions, location outside `public/`, private filesystem non-serving, encrypted administrator sessions, HTTPS `APP_URL` and HTTPS-only session cookies when `APP_ENV=production`.

The stable public protocol paths are:

```text
/.well-known/oauth-protected-resource/mcp
/.well-known/oauth-authorization-server
/oauth/authorize
/oauth/token
/oauth/revoke
/mcp
```

`/oauth/authorize` assumes an already authenticated Gateway operator session and performs explicit consent. The login/logout UI remains owned by the administration-panel workstream; do not add a second authentication stack to the OAuth controller. Authorization responses include RFC 9207 `iss` and the authorization-server metadata advertises that behavior.

The required OAuth resource scope is `mcp`. `offline_access` is optional and is the only condition under which the Gateway issues a refresh token. A refresh request may narrow from `mcp offline_access` to `mcp`; the replacement access token remains valid but no new refresh token is issued, so refresh authority cannot survive a deliberate scope reduction.

The V0.1 MCP tool registry is stable even before site routing is implemented:

```text
sites-list
site-context
site-abilities-read
site-ability-execute
```

The site-routing workstream replaces the application handlers behind those names; it does not add one MCP tool or endpoint per WordPress site.

To verify the currently configured public ChatGPT CIMD/JWKS contract without printing key material:

```bash
php artisan gateway:oauth-client-check --refresh
```

As verified on 2026-09-14, the current ChatGPT client metadata advertises the Client ID `https://chatgpt.com/oauth/client.json`, one connector redirect URI, `private_key_jwt`, RS256 and same-origin JWKS. The command intentionally reports only safe compatibility metadata and usable-key counts, never JWK values or assertions.

OAuth integration tests use generated controlled RSA keys and a mocked ChatGPT CIMD/JWKS fixture. They cover resource/scope/redirect binding, S256 PKCE, wrong client/signing key/algorithm/key ID, assertion audience/expiry/`jti` replay rejection, authorization-code expiry/single use, refresh rotation/reuse/scope narrowing, RFC 9207 issuer stamping, modern MCP `2026-07-28` stateless routing, legacy 2025-era compatibility, MCP bearer validation/tool discovery/calls and revocation without requiring owner credentials.

The Laravel `local` filesystem points at `storage/app/private` and **must keep `serve=false`**. Enabling Laravel's local-disk serving would expose private application storage through generated routes and is prohibited.

## OpenLiteSpeed note

The official MCP SDK emits Streamable HTTP/SSE responses and sets response headers intended to discourage buffering. The exact OpenLiteSpeed/LSAPI buffering and long-response behavior must still be verified on the deployment stack before production delivery. Do not infer nginx-specific directives as an OpenLiteSpeed configuration.
