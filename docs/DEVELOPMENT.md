# MCP Gateway Development

This document owns the repeatable development and validation workflow. User-facing installation belongs in `README.md` once a production release exists.

## Baseline

The current bootstrap is intentionally a conventional PHP application:

- PHP 8.4.1 or newer within the PHP 8.4-compatible dependency range;
- Laravel 13;
- Composer 2;
- MariaDB 10.11 as the primary production/development database target, with MySQL retained as a supported compatibility target;
- Blade/server-rendered frontend;
- no required Node.js build, Redis, queue worker, Docker, broker, or separate MCP daemon.

Common application tests may use SQLite in memory when the test does not depend on MariaDB/MySQL database semantics. MariaDB 10.11 is the primary CI database for database-sensitive evidence, including the path-filtered concurrency gate and the real packaged browser-update/release integration gates. MySQL remains a supported compatibility target and must not be broken by MariaDB-first implementation choices.

## Install a development checkout

From the repository root:

```bash
composer install
cp .env.example .env
php artisan key:generate
```

Edit only the database values in `.env` for the local MariaDB database and account you created (use `DB_CONNECTION=mysql` instead when explicitly testing MySQL compatibility):

```dotenv
DB_CONNECTION=mariadb
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

The first local account created by the installer or `gateway:admin:create` is an enabled `owner` with all-Target recovery authority. Later CLI-created accounts are enabled `administrator` users with all-Target scope; use Admin access controls for least-privilege Operator/Viewer accounts and Target-specific restrictions.

Once the application is running, administrator sign-in is available at `/admin/login`. Owner-only user/access management is under `/admin/users`. Roles are permission ceilings; global permission checkboxes and per-Target rules only narrow authority. Target access is edited through a bounded, paginated fleet view, so access administration does not load the full Target fleet into one request. Per-Target rules support inherit/allow/deny scope plus capability denials, including read/write distinctions beneath the role ceiling.

Access-control mutations require the acting Owner's current password, preserve at least one enabled recoverable Owner, and record required bounded Activity evidence transactionally. Disabling a user blocks new login, invalidates existing Admin/OAuth-consent sessions on their next request, and makes existing MCP bearer tokens unusable because current user state is rechecked. The admin routes continue to use Laravel's stateful web session and CSRF middleware. Production continues to require the secure session settings checked by `gateway:check`; do not weaken HTTPS-only, encrypted, HTTP-only, or SameSite cookie behavior to make local authentication easier.

### Shared Target endpoint preflight and actionable errors

The connector-neutral **Add Target → Check endpoint from Gateway** action
is authenticated, CSRF-protected, separately rate-limited and **read-only**.
The Admin controller routes through the explicit `TargetConnectorRegistry`
to an implemented adapter opting into `TargetEnrollmentPreflight`.
That optional interface defines only its non-secret preflight validation
rules and returns a `TargetPreflightResult`. A future connector does not
inherit an arbitrary network probe just by existing in the registry.

`TargetEndpointPreflight` is the common transport-aware service reused
by the current supported connectors:

- **HTTPS** (`wp_ai_bridge` today): public HTTPS URL/origin, effective A/AAAA
  resolution, public-IP/SSRF policy. No HTTP request to the downstream
  WordPress site, TLS handshake, Bridge discovery or OAuth credential check.
- **SSH TCP** (`ssh_direct` today): the registered SSH host and port are
  parsed through `SshRegisteredEndpoint` and its existing
  `SshDialAddressPolicy`, including the public-address and maximum-DNS-answer
  rules. No TCP connection, independently pinned host-key check, SSH login,
  remote command or credential use. A result is not a trusted SSH peer.

A successful preflight displays the exact checked endpoint and binds the
result to the selected connector and its reviewed endpoint input fields.
Changing the connector, host, URL or SSH port invalidates the old success
in the shared Admin form, even if the operator later restores the same text.
No checked destination is retained as dispatch authorization.

DNS preflight is a **time-of-check snapshot**, never a cached authorization.
Every registration/operation must repeat its appropriate trust checks, DNS
and actual peer binding. HTTP and SSH retain their distinct protocol policies;
do not apply HTTPS/TLS semantics to SSH or use a generic caller-selected
host/URL to bypass connector admission.

All Target registration, preflight and origin-configuration redirects
reuse `TargetFormInput` to replay only allowlisted non-secret fields, and
never retain URL userinfo, query tokens, fragments or malformed origins in
session old input. Shared connection redirects also retain only
`OperationDiagnostics::safeContext` so the browser diagnostic panel can
present observed facts rather than generic fallbacks.

A policy rejection retains existing machine codes (`unsafe_target` for
HTTP, `egress_denied` for SSH) while carrying allowlisted, bounded
`outbound_rejection_reason`, an observed rejected numeric IP when relevant,
and its address class. A finite `outbound_address_source` differentiates
configured numeric IP literals (no DNS lookup) from actual resolver answers,
so a configured localhost address is not incorrectly blamed on /etc/hosts.
`incompatible_metadata` keeps its machine identity while displaying any
proven underlying outbound-policy cause. `OperationDiagnostics` is the shared boundary for
operator-visible summaries, concrete next steps, diagnostic references and
redacted evidence in logs; no per-connector diagnostic stack is added.
A loopback result identifies actual Gateway DNS/local override evidence and
suggests checking `/etc/hosts` when appropriate. User input, URLs with
credentials or signed query components, remote response bodies and
authentication secrets must not be copied into a diagnostic merely to
explain an error. Do not infer a remote effect or classify it safe to
retry from a local DNS rejection: the multi-step OAuth/SSH operation owns
its own effect/recovery certainty. New connector families reuse these
shared components when their real protocol and trust policy fit; unsupported
preflight stays explicitly unavailable, not guessed or silently successful.

## Admin UI foundation

The administration panel uses one small server-rendered visual system in `public/css/admin.css`. New Admin views must reuse this foundation rather than falling back to browser-native controls or creating a second page-specific design system.

**Required UI acceptance contract:** [Admin UI Quality Standard](ADMIN-UI-QUALITY.md). This covers every Admin page and future UI change, not just the screen that first exposed a layout defect. Before integration, check the shared spacing and form/action rules, narrow/mobile and desktop composition, keyboard/focus, error/empty/loading feedback, localization, dark mode and reduced motion in all affected states. Do not fix a repeated component defect with a new page-specific CSS margin; repair the shared selector/token and add targeted regression coverage.

Use these shared conventions:

- design values belong in the existing `--ui-*` tokens; avoid one-off colors, borders, radii, focus treatments, or control heights when an existing token fits;
- top-level sibling `.panel` cards must be separated by `.main-content > .panel + .panel` using `--ui-panel-stack-gap`, including the Edit Target and AI clients pages; do not add per-page margin fixes to make adjacent cards appear separate;
- normal two-column form rows use `.form-grid`; `.content-grid` is reserved for intentionally asymmetric content/aside layouts;
- text/select controls belong in `.field`; selects use the shared custom appearance and must not rely on the browser-default arrow/chrome;
- boolean choices use the shared `.checkbox-option` treatment so the full label is the click target and checked/focus/disabled states remain consistent;
- permission-denial lists use `admin.partials.permission-option`. Human title, scope, and behavioral help come from `GatewayPermission`; do not duplicate permission explanations in individual Blade views;
- permission help must explain whether the permission is Gateway-wide or Target-scoped and, for Target-scoped permissions, that the effective Target scope comes from the user's scope mode, direct Target rules, and assigned Target groups. Permission descriptions must not imply creator ownership unless the authorization model actually enforces it;
- filters use `.filter-grid` + `.filter-actions`; tabular fleet/access views use `.table-wrap`, shared badges, and `.table-footer` for explanatory text plus actions;
- keyboard focus must remain visible, label/control hit targets must remain usable at narrow widths, and light/dark plus reduced-motion behavior must be preserved;
- the admin stylesheet URL is versioned from `VERSION`, so an application update cannot intentionally serve new Blade markup with a stale cached pre-update stylesheet.

Prefer a small markup adjustment that lets multiple pages share an existing component over adding view-specific CSS. A new reusable Admin interaction should extend this section and the shared stylesheet/partial at the same time.

## Proportional validation and review cadence

Optimize for finished, verified changes rather than repeated ceremony.

During implementation:

- run the narrowest tests or static checks that can detect regressions in the surface being changed;
- do not rerun an already-green broad suite after every small edit when that edit cannot invalidate its evidence;
- keep actively changing work on an isolated branch; open a PR when it can benefit from review or PR-based CI, then request final independent review only after the meaningful candidate has stabilized;
- avoid independent review while the implementation is still moving materially.

Useful targeted commands include:

```bash
# One test file or one test method while iterating.
composer test -- tests/Feature/Admin/TargetManagementAdminTest.php
composer test -- --filter=test_specific_behavior

# Changed PHP files only when a whole-project pass adds no signal yet.
vendor/bin/pint --test app/Http/Controllers/Admin/TargetController.php tests/Feature/Admin/TargetManagementAdminTest.php
vendor/bin/phpstan analyse app/Http/Controllers/Admin/TargetController.php --memory-limit=1G
```

Use the normal broader commands at candidate freeze when their evidence is required. Do not add custom wrappers merely to hide standard Laravel/PHPUnit/Pint/PHPStan syntax.

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

## Fast, capability-driven changes without hiding regressions

When extending a supported Target/client, first distinguish **new Target inventory**, **new operation in a reviewed capability family**, **new connector transport**, **new security/permission class** and **new client OAuth identity**:

- A new registered Target or WordPress Ability (including an unfamiliar name) should need **no** Gateway public-tool/schema code or deployment change. Use a controlled changed downstream catalog and prove the existing family discovery/execute path works **when the user has the existing configured execution permission and WordPress permits it**. An unfamiliar or unclassified Ability is not a categorical denial: the latter uses the existing explicitly grantable `unclassified` permission. Separately prove a deliberately denied user remains denied.
- For a future MCP-speaking connector, discover real authenticated Target operation names/schemas and reuse protocol adapters; do not duplicate transport, permission/transfer logic or create one Gateway tool for each downstream version. Novel names and missing effect annotations should use the existing configured broad/unclassified permission when applicable, not an invented per-name ban. Still reject actual unauthorized privilege, identity or invalid protocol/schema requests.
- Test changed-operation-name/schema fixtures separately from a **new MCP protocol extension**: the first must not force Gateway code changes under the supported family; the second works when the required protocol method is actually implemented and both peers negotiate it. Exercise stale schemas, actual user/Target denials, wrong client/Target, feature-not-supported fallback and realistic hot-path calls. Cache metadata cannot grant permission; subscriptions are protocol-version-dependent and never guarantee external App refresh.
- Establish a representative performance baseline **before** adding abstractions, increasing or lowering payload ceilings or requiring extra services. Compare actual small payloads under a higher permitted cap, medium files, concurrent operations, round trips/SSH sessions, p50/p95 latency, PHP peak memory, CPU and transient disk. A tiny fixed cap is not a performance optimization by itself.
- Keep related fixes in one coherent slice; run targeted checks during editing, exact affected broad/security/contract checks only for a stable candidate, and preserve still-valid evidence. A documentation-only change does not justify manually rerunning SFTP/WordPress integration suites unless the changed material actually affects executable acceptance.

For product invariants, implementation boundaries and resource semantics use the [Master Specification](MASTER-SPEC.md), [Architecture](ARCHITECTURE.md) and [Remote I/O contract](REMOTE-IO-CONTRACT.md). Avoid numeric section citations that become stale when these documents are reorganized.

## CI evidence and integration decisions

A GitHub check is **not universally required** for every PR or merge. Apply review and tests to the actual changed behavior and risk. Reuse passing, exact-source evidence when unchanged code/contract remains covered; run the smallest useful targeted check when implementation changes, or stronger affected security, migration, transport and packaged-release checks when those surfaces change. Never waive checks that the repository currently requires or merge a known failing relevant check.

Documentation-only wording/navigation edits normally need Markdown/link/provenance inspection, not the whole PHP, SSH, MariaDB and update suites. A docs-only change that alters a runnable instruction or accepted contract still needs the appropriate focused verification. Release publication has its own exact-artifact validation and Owner authorization independent of ordinary PR/merge cadence.

GitHub workflow jobs may be path-filtered or advisory. Do not configure an unconditional required-status gate that blocks an otherwise acceptable docs-only PR for checks that legitimately did not run. Maintainer review and preserved relevant test evidence, not the raw count of green CI jobs, determine merge readiness. Commit attribution is a separate author-identity provenance control; do not confuse it with an unconditional full-CI mandate.

## Deterministic validation

The normal repository checks are:

```bash
composer validate --strict
composer audit --locked
composer lint
composer analyse
composer test
```

`composer check` runs style, static analysis, and tests together. Common CI runs these broad application checks plus runtime-readiness checks without starting a database service. The dedicated path-filtered `MariaDB Concurrency` workflow owns MariaDB 10.11 `migrate:fresh` and the `database-concurrency` test group only when persistence/OAuth/site-lifecycle surfaces can invalidate that evidence. The `Update Package` workflow independently owns the MariaDB-backed released-package-to-candidate browser update proof and runs only for updater/package/schema/dependency surfaces that can invalidate that proof; the historical released baseline may still use Laravel's `mysql` driver against the MariaDB server so backward compatibility is exercised honestly. Ordinary application-code edits rely on normal application tests plus package build/verification and receive the full browser-update proof at the applicable release gate. MySQL remains a supported compatibility target. The exact WP AI Bridge contract remains a separate path-filtered compatibility gate for Bridge-facing MCP/site-connection/client-identity behavior rather than every Gateway OAuth/internal HTTP edit. Draft pull requests skip these heavy jobs until they are marked ready for review.

Do not shard a retained long-running suite by default. First compare fixed runner/service/setup cost with the test body. Introduce shards only when non-overlapping isolated shards materially shorten the same-workload critical path after trigger/duplication cleanup, and verify aggregate completeness and isolation. Keep exact timing evidence in the active optimization Issue/PR rather than hard-coding transient runner measurements into this durable workflow guide.

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

The MariaDB-backed `Update Package` workflow downloads and checksum-verifies every explicitly supported published deployment baseline (including the most recent stable), installs each baseline independently, stages the candidate update ZIP as an operator would, authenticates through the administrator login, obtains normal CSRF state, and exercises `/update/` through both browser-update phases. The canonical `bin/test-released-baseline-parity.py` guard keeps both publication and CI upgrade loops in sync with official released baselines. The integration test verifies:

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

Normal CI runs both artifact builders/verifiers after the application test steps. Release publication must repeat the real browser-update integration (`bin/test-update-package.sh`) and the backup-integrity fail-safe regression (`bin/test-update-backup-integrity.sh`) against **all configured** published baselines and the exact candidate artifacts before publishing a new release. This is deliberate: tests generate ephemeral keys/cache/session state in the development checkout, release packaging must prove that none of that state can leak into operator artifacts, the current production upgrade path must be exercised directly, and the updater's recovery boundary must remain fail-safe when its own backup is missing or corrupted.

`RELEASE_NOTES.md` owns the operator-visible notes for the version currently declared in `VERSION`. CI and release publication require its heading to identify that exact version so a future VERSION bump cannot silently publish stale release highlights.

The browser-updater recovery semantics are one state machine across implementation, tests, operator documentation, and release notes. Any change to that state machine must update `README.md`, `docs/DEPLOYMENT.md`, the relevant repository-owned updater regressions, and release-note behavior in the same reviewed change. Any future change that alters application runtime files, Composer dependencies, updater logic, package scripts, or release packaging must keep the applicable gates green at the candidate/release boundary that owns that proof. Ordinary runtime-code iteration does not require the full released-package browser-update integration on every synchronization when updater/package/schema/dependency behavior is unchanged; release publication still requires the exact-candidate browser-update and backup-integrity proofs. If a new legitimate runtime file is required, update the builder/verifier intentionally in the same reviewed change rather than weakening the hygiene checks broadly.

## Real Chromium Admin external-authorization regression

The Admin CSP intentionally retains `form-action 'self'`, so an HTTP assertion about a 302 redirect alone cannot prove that browser authorization works. The source-controlled `Admin External Authorization Browser` GitHub workflow uses a loopback-only disposable Laravel/SQLite instance, its own signing keys, a simulated HTTPS provider, and real Chromium. It checks **POST → 303 → internal GET → external provider**, production-equivalent Admin security headers, no duplicate POST, JavaScript-disabled mobile navigation and rejection of unrelated cross-origin forms. No live WordPress or Production host is used.

Run it locally only in a disposable development checkout with Composer, Node, the pinned `playwright@1.61.1` package and its Chromium browser installed:

```bash
npm install --no-save --no-package-lock --no-audit --no-fund playwright@1.61.1
npx playwright install chromium
bash bin/check-admin-external-authorization-browser.sh
```

The same command first runs a controlled **multi-worker HTTP race** using independent loopback PHP listeners sharing encrypted file-backed sessions and atomic file cache. Two simultaneous handoff GETs must produce exactly one provider document; a delayed unrelated Admin session writer deliberately restores an old handoff entry, which must still be rejected. To run only this HTTP concurrency regression with PHP and Python (without Node/Chromium), use `bash bin/check-admin-external-authorization-browser.sh concurrency-only`. The default command always runs both the race and actual Chromium. The harness explicitly enables the isolated `tests/Support/external-authorization-browser-router.php` router, binds `127.0.0.1` only, creates ephemeral credentials/database/cache and removes the temporary fixture at exit. This development check is not a production dependency, replaces no unit/feature/OAuth-contract tests, and cannot establish real WordPress consent acceptance.

## MCP bootstrap compatibility fixture

`/_internal/mcp-bootstrap` exists only to prove the Laravel/PSR/MCP SDK integration during bootstrap. It is disabled by default and returns `404` unless both of these test-only settings are supplied:

```dotenv
MCP_BOOTSTRAP_FIXTURE_ENABLED=true
MCP_BOOTSTRAP_FIXTURE_TOKEN=an-ephemeral-test-token
```

Do not enable this fixture in production. The integration test starts an isolated local Laravel process, sends an explicit bearer token through the official MCP PHP client, exercises Streamable HTTP, lists the controlled fixture tool, and then shuts the process down.

The production `/mcp` endpoint is independently implemented by [`GatewayMcpEndpoint`](../app/Infrastructure/Mcp/GatewayMcpEndpoint.php) under [`routes/mcp.php`](../routes/mcp.php); do not promote the test-only bootstrap fixture into the production request path.

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

The required OAuth resource scope is `mcp`. For the fixed ChatGPT client, an approved `mcp` authorization is refreshable even when ChatGPT omits `offline_access`, because the client must be able to renew the bounded access token without a manual reconnect. `offline_access` remains accepted and advertised for compatibility. Refresh rotation, replay protection, expiry, exact client/resource/user binding, and authorization-wide revocation remain mandatory. If a refresh credential authorized for `mcp offline_access` is explicitly narrowed to an `mcp` access token, the Gateway does not issue a successor refresh token: RFC 6749 permits the narrower access token, while any replacement refresh token would have to retain the predecessor refresh token's identical scope.

The complete public Gateway MCP Tool names, schemas, annotations and limits belong to [`GatewayMcpEndpoint.php`](../app/Infrastructure/Mcp/GatewayMcpEndpoint.php) in the **selected source revision**. Its Target inventory/context, WordPress Ability discovery/execution, SSH command/file and retained Job families are deliberately independent of the registered Target count. Do not maintain a second dated four-tool catalog in this development guide, restore retired `sites-*` aliases or register a public Tool per Target or downstream WordPress Ability. A compatible new WordPress Ability is discovered through the existing authenticated Target-scoped family, not a public Gateway Tool publication.

To verify the currently configured public ChatGPT CIMD/JWKS contract without printing key material:

```bash
php artisan gateway:oauth-client-check --refresh
```

The command validates the *currently published* compatible ChatGPT client metadata/JWKS identity against the reviewed Gateway profile and reports only safe compatibility metadata and usable-key counts—not JWK values, private keys or assertions. Never embed a previously observed external client's live redirect/JWKS snapshot as a permanent development assumption.

OAuth integration tests use generated controlled RSA keys and a mocked ChatGPT CIMD/JWKS fixture. They cover resource/scope/redirect binding, S256 PKCE, wrong client/signing key/algorithm/key ID, assertion audience/expiry/`jti` replay rejection, authorization-code expiry/single use, refresh rotation/reuse/scope narrowing, RFC 9207 issuer stamping, modern MCP `2026-07-28` stateless routing, legacy 2025-era compatibility, MCP bearer validation/tool discovery/calls and revocation without requiring owner credentials.

The Laravel `local` filesystem points at `storage/app/private` and **must keep `serve=false`**. Enabling Laravel's local-disk serving would expose private application storage through generated routes and is prohibited.

## OpenLiteSpeed note

The official MCP SDK emits Streamable HTTP/SSE responses and sets response headers intended to discourage buffering. The exact OpenLiteSpeed/LSAPI buffering and long-response behavior must still be verified on the deployment stack before production delivery. Do not infer nginx-specific directives as an OpenLiteSpeed configuration.
