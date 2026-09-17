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

Common application tests may use SQLite in memory when the test does not depend on MySQL-specific behavior. MySQL 8.4 is used by dedicated workflows where the evidence depends on production database semantics, including the path-filtered concurrency gate and the real packaged browser-update integration gate.

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

The password is always requested interactively through a hidden prompt and is never accepted as a command-line option. It must contain at least 12 characters with mixed case, a number, and a symbol. The command normalizes the email address and relies on the `User` model's framework hashing cast; there is no committed/default administrator password, public registration route, or password-reset flow in V1.

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

`composer check` runs style, static analysis, and tests together. Common CI runs these broad application checks plus runtime-readiness checks without starting MySQL. The dedicated path-filtered `MySQL Concurrency` workflow owns MySQL 8.4 `migrate:fresh` and the `mysql-concurrency` test group only when persistence/OAuth/site-lifecycle surfaces can invalidate that evidence. The `Update Package` workflow independently owns the MySQL-backed released-package-to-candidate browser update proof. The exact WP AI Bridge contract remains a separate path-filtered compatibility gate. Draft pull requests skip these heavy jobs until they are marked ready for review.

## Release package validation

The official deployment ZIP has a permanent clean-artifact invariant. Do not handcraft a release ZIP and do not copy the development checkout or its existing `vendor/`, `storage/`, or `bootstrap/cache/` into a release artifact.

Use the repository-owned path:

```bash
bash bin/build-release-package.sh mcp-gateway-local
bash bin/verify-release-package.sh dist/mcp-gateway-local.zip mcp-gateway-local
```

`build-release-package.sh` creates a new staging tree, installs the committed lockfile directly with `composer install --no-dev`, prunes only demonstrably non-runtime dependency material, emits empty writable runtime directories, and creates a deterministic ordered ZIP. `verify-release-package.sh` extracts that ZIP and fails closed on unexpected top-level files, repository/development metadata, dependency dev/docs/example material, transient storage state, source-only Composer metadata, or broken runtime behavior.

For the browser-update artifact, build it from the already verified runtime staging tree and then verify its fail-closed package shape:

```bash
bash bin/build-update-package.sh mcp-gateway-update-local dist/mcp-gateway-local
bash bin/verify-update-package.sh dist/mcp-gateway-update-local.zip
```

The update ZIP must contain only private root `update/` staging and the minimal temporary `public/update/` entrypoint. Extracting it into an installed application root must not replace any normal application-managed path before the administrator explicitly confirms the update in the browser. The full production runtime payload stays under private `update/payload/`; `.env` and `storage/` are never included in that payload.

`bin/update-managed-public-paths.txt` is the canonical, append-only ownership list for normal public runtime files. Add every newly shipped `public/` file to it. Do not remove an old Gateway-owned file path merely because the current payload no longer ships that file; retaining the path lets later updaters remove stale Gateway files without claiming the rest of `public/`.

The MySQL-backed `Update Package` workflow downloads the real released `v1.1.2` deployment artifact, installs it, stages the candidate update ZIP exactly as an operator would, authenticates through the real administrator login, obtains normal CSRF state, and exercises `/update/` through both browser-update phases. The integration test verifies:

- the live application remains unchanged immediately after ZIP extraction;
- guest `/update/` access cannot trigger mutation and is redirected to administrator login;
- installed/target version and integrity/preflight state are exposed only through the authenticated flow;
- `.env` and persistent private state survive unchanged;
- a protected, non-Gateway `public/.user.ini` plus an unknown file inside a shared public subdirectory survive both successful update and forced pre-migration restore unchanged;
- stale application-managed files absent from the new release are removed;
- a conflict on an explicitly Gateway-owned public file is rejected pre-mutation with the exact path while unknown public paths are ignored;
- Laravel maintenance/cache/migration/`gateway:check` postflight completes;
- the private code backup exists, excludes host-managed public state, and backup count remains bounded;
- a different pre-migration installed-runtime failure automatically restores only from a separately revalidated intact backup, leaves migration state unchanged, resumes service, and clears updater state;
- `bin/test-update-backup-integrity.sh` separately removes and content-corrupts a backed-up managed file after staging and proves both rejected backups stop before migration, do not trigger destructive restore, keep the candidate runtime unchanged, retain maintenance mode/state/backup evidence, and leave migration state unchanged;
- same-version, downgrade, tampered-package, symlink-package, and invalid-target cases fail before mutation;
- successful completion removes private update state, root `update/`, temporary `public/update/`, and the exact canonical uploaded update ZIP/checksum, leaving `/update/` unavailable.

The fresh-install verifier also boots Laravel from the extracted package, rebuilds the Laravel package manifest, checks routes and Composer runtime identities, runs the web-installer preflight, and performs a migration smoke test. Dependency license/notice files and runtime resources are intentionally retained even when they add size.

Normal CI runs both artifact builders/verifiers after the application test steps. Release publication must repeat **both** the real `v1.1.2` browser-update integration (`bin/test-update-package.sh`) and the backup-integrity fail-safe regression (`bin/test-update-backup-integrity.sh`) against the exact candidate artifacts before publishing a new release. This is deliberate: tests generate ephemeral keys/cache/session state in the development checkout, release packaging must prove that none of that state can leak into operator artifacts, and the updater's recovery boundary must remain fail-safe when its own backup is missing or corrupted.

The browser-updater recovery semantics are one state machine across implementation, tests, operator documentation, and release notes. Any change to that state machine must update `README.md`, `docs/DEPLOYMENT.md`, the relevant repository-owned updater regressions, and release-note behavior in the same reviewed change. Any future change that alters application runtime files, Composer dependencies, updater logic, package scripts, or release packaging must keep these gates green. If a new legitimate runtime file is required, update the builder/verifier intentionally in the same reviewed change rather than weakening the hygiene checks broadly.

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

The V1 MCP tool registry is stable even before site routing is implemented:

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
