# MCP Gateway v2.3.0 — Targets post-upgrade acceptance

**Evidence date:** 2026-10-16. **Tracking:** [Issue #192](https://github.com/AChWorks/mcp-gateway/issues/192). This is a bounded test record, **not** a claim of production acceptance or deployment. The only Owner-reported Gateway was upgraded in the Admin browser, but the installed binary/version, migrations, cron and logs have not been directly verified on its host.

## Evidence boundaries

- **Released source:** `main@a9427694a5ec6ec63e22a57e99f9ad5e55656a51`, tree `ded1c1ddd6ecb1277da1f67c59b93af3542d0170`, official stable v2.3.0.
- **Live read-only:** existing production-connected MCP Gateway tools; non-mutating HTTPS `/up`; only current authorized Targets. One SSH Target was *already paused by the Owner*, not by this test.
- **Disposable:** separate development worktree, SQLite preview database, synthetic Owner and Targets, localhost-only Laravel/Chromium. No production database, credential, Pause/Resume setting, file, connection, WordPress content or remote OS command was changed.
- **Source branch:** `fix/targets-inventory-ui-20261016`. All source fixes and browser experiments are **unreleased** until separately reviewed, merged and published.

## Test matrix

| Scenario | Environment | Expected | Actual evidence | Result |
| --- | --- | --- | --- | --- |
| GitHub version/commit | GitHub + dev checkout | Stable source/checkout consistent | `main` and remote match v2.3.0 published source SHA/tree | PASS |
| Public liveness | Installed Gateway, GET only | HTTP healthy | `GET /up` -> HTTP 200 | PASS |
| Installed version, migrations, scheduler, maintenance and log health | Operator host | Version 2.3.0; all operational checks clean | No privileged operator-host read-only evidence yet | NOT TESTED |
| Authorized inventory | Installed MCP | Two SSH and one WordPress | Three entries, current connection and pause flags returned | PASS |
| Paused Target metadata | Installed MCP | Visible, `connected`, `operations_paused=true` | `targets-list` and `target-context` preserved stored metadata | PASS |
| Paused SSH command | Installed MCP | Block before remote command | Harmless command probe returned `target_paused`, not execution | PASS |
| Paused SFTP | Installed MCP | Block before remote file I/O | Read-only root-directory stat returned `target_paused` | PASS |
| Other SSH unaffected | Installed MCP | Nonpaused Target remains usable | Read-only SFTP directory stat succeeded using configured nondefault port | PASS |
| Server-side search, connector/state filter | Installed MCP | Correct Target scoping | Name search returned one paused target; connected SSH returned two; WP error filter returned zero | PASS |
| WordPress Ability discovery | Installed MCP | Authorized metadata available | Catalog read succeeded, total 225 Abilities | PASS |
| WordPress OAuth longevity / refresh and revocation | Disposable staging required | Secure refresh and recoverability | Only metadata enumeration verified; no token-expiry/revocation induction | NOT TESTED |
| Production SSH jobs, failed login, host-key mismatch | Disposable staging required | Bounded/fail-closed operations | No negative remote operations on real Targets | NOT TESTED |
| Browser whole-file transfer with optional enablement | Disposable Gateway required | Binary SHA-256 parity, auth, overwrite safety | Production-safe transfer flag not enabled or changed; no enabled-mode transfer performed | NOT TESTED |
| Native ChatGPT attachment/model file handoff | Separate [Issue #147](https://github.com/AChWorks/mcp-gateway/issues/147) | Real host-side exchange | Not proven by browser picker or SFTP stat | NOT TESTED |
| Blade status separation and role controls | Isolated PHPUnit | Correct connection/OAuth/pause; Owner-only actions | Focused feature tests with synthetic data; connection and credential presence differ correctly | PASS |
| Live-rendered Admin UI | Local disposable Laravel + Chromium | Legible layout and truthful labels | Logged-in 4-Target fixture; correct per-row states; Inspect, two-step confirmation and filter observed | PASS |
| Responsive document overflow | Local Chromium | No page-level horizontal overflow | Measured difference `documentElement.scrollWidth-clientWidth=0` at 375, 768 and 1366 px | PASS |
| Production Admin visual acceptance after installing changes | Operator host | Correct updated page | No production deployment performed | NOT TESTED |

## Source correction and UX contract

In the v2.3.0 source, the Targets list called `TargetRecoveryPresentation::describe` with `hasCredential=false` unconditionally. This made a connected, credential-bearing WordPress Target show **WordPress authorization required** even when stored OAuth material existed. The fix performs a **bounded credential-existence-only lookup on authorized paginated WordPress Targets**; it never decrypts secrets or claims to have probed remote token validity. Pending refresh/revocation takes precedence in the existing presentation policy. The UI now shows separate connection evidence, WordPress OAuth/recovery evidence, Gateway operations, and permission-aware actions. `Connected` is a recorded connection status, not a continuous health check.

Desktop uses a compact five-column table; smaller viewports use labeled Target cards. The Owner must expand a native, keyboard-accessible disclosure before submitting a CSRF-protected Pause/Resume form. Server-side Owner gates, idempotence, Activity logging, and all existing operations remain unchanged.

## Future completion gates

1. Run independent, author-separated, strictly read-only review of the **exact frozen PR candidate** and inspect exact-head GitHub Actions.
2. Obtain applicable Owner approval before merge/public Release; no GitHub reviewer assignments.
3. **Separate operator approval and backup readiness** for any production deployment. Inspect installed version/migrations/cron/logs using read-only, authorized channels, and perform post-install responsive Admin acceptance.
4. Test negative SSH jobs/credentials/host keys and optional binary transfer only against disposable environments. Do not resume the Owner-paused SSH Target or revoke/disconnect live WordPress credentials merely for testing.
5. Record PR/review/CI/final evidence under [#192](https://github.com/AChWorks/mcp-gateway/issues/192) so another Master can resume without chat history.
