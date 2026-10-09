# Target Foundation Transition — implementation and recovery runbook

Status: **IN DEVELOPMENT (#107)**. This is a proposed major-version breaking transition, **not** supported by current `main` or production builds. The new migration and Target models on `feat/target-foundation-107` are not sufficient for a working Gateway until every Site-era application/Admin/MCP route, connector flow, access rule and Activity query has been reconciled. **Do not merge/deploy this isolated implementation.**

Owning contract: [Issue #107](https://github.com/AChWorks/mcp-gateway/issues/107), [Program #106](https://github.com/AChWorks/mcp-gateway/issues/106), [Target foundation](./TARGET-CONNECTOR-FOUNDATION.md). The Direct SSH architecture is integrated through merged [PR #124](https://github.com/AChWorks/mcp-gateway/pull/124); Direct SSH runtime execution is not yet implemented.

## Post-#117 integration checkpoint (2026-10-09)

- Owner-authorized PR [#126](https://github.com/AChWorks/mcp-gateway/pull/126) was independently HIGH_ASSURANCE **APPROVED** and squash-merged as `main@359c0666ccd3e8fd3fa08328170fa8efccdce185`. Exact approved OAuth candidate `8a451540ac19db585196a0c5113d65fd8a342a74`, reviewed tree `4c753db22c55adcefc2e87056e7e1342ad1aae62` matched the merged tree. All required exact-candidate CI/MariaDB/Update Package checks passed. This is **integration only**, not released/deployed or real-provider enrollment.
- The #107 WIP branch `feat/target-foundation-107` has **NOT** yet merged/reconciled the new OAuth foundation; its existing implementation checkpoint before this documentation update was `301cd809bc91e5315b1e2a1f2b0d9ac4bb3f2c32`.
- A **read-only `git merge-tree --write-tree HEAD origin/main` preflight**, with WIP at that checkpoint and new main, identified **three nontrivial source conflicts**: `app/Infrastructure/Activity/ActivityFeed.php`, `app/Infrastructure/Activity/ActivityRecorder.php`, `resources/views/admin/activity/index.blade.php`. No merge was attempted; index/worktrees remain intact. AppServiceProvider, admin layout and routes were automatically reconcilable by the preflight, but must still be functionally checked after a real integration.
- The next Master must reconcile the Target-identity and OAuth-client-profile Activity semantics together; **do not choose one side of the Activity conflicts mechanically**. Preserve immutable Target record snapshots, exact OAuth client identity in audit, user/Target ACL, safe filters and escaping. Use the existing clean isolated WIP worktree, refresh both refs, reconcile without reset/force-push, and run focused/Broad validation before any PR/review.
- Separately, #107 remains **not merge-ready** because legacy Site-era credential/OAuth/refresh/revoke, check-operation, old Admin and public MCP handlers/routes still reference removed Site schema; prior whole-project PHPStan reported **46 errors**. Its destructive migration may be tested only in a disposable database with explicit nonproduction safety gates. **No approval** to merge this WIP, release, deploy, run privileged SSH or reset production Target data.

## Why this must be an explicit operator-visible upgrade

Site-era tables combine registered WP AI Bridge Targets, OAuth credentials, local user Target assignments, groups and check operations. A clean `Target` foundation is a breaking replacement. The owner has accepted discarding and manually reconnecting that **Target-owned state**, **not** administrator accounts, Gateway client-facing OAuth/session signing identity, refresh recovery records or unrelated product state.

The existing browser-updater recovery archive protects application **files/code**. It is **not a consistent database backup** and is never proof of database recovery after this migration. Migration DDL in MariaDB/MySQL is not transactionally reversible.

Before the final major upgrade is released, the operator must put the application in maintenance mode, create a **consistent, restorable database backup** outside the application/code backup, and ensure the rollback procedure is understood. Database backup and restoration must be tested in a non-production environment. Explicit values in the migration configuration confirm that the operator performed those steps; they are attestations, not an automatic backup.

## Legacy state intentionally reset

The transition migration explicitly drops and recreates these Target-owned tables, **not by relying on cascade side effects**:

`site_check_operation_targets`, `site_check_operations`, `site_group_permission_denials`, `site_group_sites`, `site_group_users`, `site_groups`, `user_site_permission_denials`, `user_site_access`, `site_oauth_flows`, `site_credentials`, `site_revocation_intents`, `site_target_reservations`, `sites`.

Events in `activity_events` with a non-null legacy `site_id` are deleted to prevent them from being mistaken for a newly created Target with the same public slug. Gateway-wide Activity with null `site_id` and `activity_retention_state` remain. The new `activity_events` shape includes public Target slug plus nullable immutable internal Target ULID and connector-type snapshot, so delete/recreate cycles can be distinguished by query policy; **application-level Activity writer and scoped feed updates are now present and tested on the #107 WIP branch; Admin/public endpoint reconciliation and full upgrade acceptance remain open**.

User `site_scope_mode` becomes `target_scope_mode`, preserving each user's current mode; the selected-scope membership set starts empty. Users, role identity, global permission-denial table, Gateway OAuth authorization/access/refresh tokens, client assertions, OAuth refresh-recovery records and persistent keys remain intact.

Only known one-to-one denial strings are mapped (Gateway connection, `sites.*`/common Target rights, former `connections.*` and WP `abilities.*`). Unknown legacy permission denies and unsupported role names **abort before DDL**, requiring explicit administrator reconciliation rather than accidental widening. Migration inserts mapped denials before removing legacy aliases, and seeds new `agent.*` / `ssh.*` denials for **existing non-owner users**. Newly created non-owner accounts now receive conservative Agent/SSH default denials in the WIP access service, and routine profile edits preserve connector denials. Explicit Owner enablement UI remains outstanding and no production compatibility is claimed.

## Deliberate confirmation gate — only after full integration and review

When any legacy Target-owned rows or Target-scoped Activity exist, the migration requires both config-backed environment values:

```dotenv
GATEWAY_TARGET_RESET_ACKNOWLEDGED=RESET_TARGET_STATE
GATEWAY_TARGET_RESET_DATABASE_BACKUP_VERIFIED=RESTORABLE_DATABASE_BACKUP_VERIFIED
```

Do **not** configure these in a running production Gateway now. They are only valid for the explicitly approved, operator-prepared major upgrade. They are not passwords or recovery material and do not create or verify the backup.

If confirmation is missing or the old schema/denials/roles do not match the supported transition, the migration fails **before destructive DDL**. Once DDL begins, failures may leave an **unknown partial schema**; do not retry blindly, do not run `migrate:rollback`, do not reinstall over the existing database. Stop the updater and recover through the operator's independently verified database backup. Migration `down()` deliberately refuses to suggest a reversible restoration.

## First implementation slice and evidence

The separate unmerged branch implements the explicit schema reset, generic `Target`/credential/group domain models, and WP-specific endpoint/config storage; it does not yet wire them into the old Laravel Site-era runtime.

Focused tests on an isolated SQLite database verify clean schema creation, rejection without backup acknowledgment, preservation of Gateway OAuth and users while discarding Target-owned records, strict denial translation/seeding, and Target identity immutability/connector-owned config. An **isolated unprivileged MariaDB 11.8** instance on a local-only Unix socket also passed both fresh schema creation and a seeded legacy data conversion, including the no-ack preflight, Account/OAuth/Gateway-wide Activity preservation, and Agent/SSH denial seeding. The temporary server was stopped after validation; no host-wide service or production database was touched. This is valuable early DB-specific evidence, but **does not replace primary MariaDB 10.11/MySQL compatibility checks, restoration evidence, exact historical packaged updater tests or whole-application verification** before release.

## Recovered WIP checkpoint (2026-10-09)

The `feat/target-foundation-107` branch was reconciled with the integrated `main` through a **non-rewriting merge**. AccessControl/UserAccessManager/TargetGroupManager, TargetInventory, ActivityRecorder/ActivityFeed, user/group admin route forms and installer/admin creation fields have been moved toward Target-domain persistence. Connector-specific permission families (`wordpress.*`, `agent.*`, `ssh.*`) now have explicit role ceilings; SSH permissions require Selected Target scope and connector-family matching is enforced before authorization. Target Activity is keyed by the immutable ULID plus a connector snapshot to prevent slug-reuse misattribution.

Focused validation on a disposable local Unix-socket MariaDB 11.8 instance passed **15 tests / 96 assertions**, including new access/Activity, mixed-connector inventory, Admin HTTP form and Target schema tests. Focused PHP lint/PHPStan also passed. Tests were **not** a full CI or historical upgrade regression. The app still contains Site-era WordPress runtime/MCP paths and is **not merge-ready**; these cannot be assumed fixed by the domain/UI progress.

## Connector registration and Target Admin checkpoint (2026-10-09)

The WIP branch now contains a connector-owned WordPress registration service that validates immutable Target IDs before outbound HTTP, performs existing bounded/public HTTPS OAuth discovery, and atomically writes the shared Target plus WP-specific configuration using a connector-scoped canonical endpoint reservation. No bearer/refresh/SSH/Agent credential is created by registration. A duplicate endpoint, duplicate ID, existing reservation or missing Bridge metadata fails without a partial Target record.

A new Target-native Admin inventory and details view, WordPress-only registration form and generic dashboard/navigation use Target-domain identity and ACL-filtered paging. The Admin intentionally does **not** expose nonfunctional Agent/SSH registration, WordPress connection authorization or execution controls. The Target inventory service also accepts a strict built-in connector-type filter for future bounded MCP/locator work.

Validation: an isolated Unix-socket MariaDB 11.8 focused suite passed **22 tests / 163 assertions** (initial complete Target Admin and connector registration slice). Project-wide Laravel Pint passed **228 files**; targeted PHPStan for new classes/views' controllers passed. Whole-project PHPStan still reports **46 errors** from legacy Site-era runtime, a release blocker. The later connector-filter change passed its focused inventory test (2 tests / 14 assertions); no full historical acceptance or PR CI is claimed. Branch has **no PR** and must not be merged.

**Next non-optional integration boundary:** replace old Site-era OAuth connection, credential/refresh/revoke, check-operation and public MCP handlers/routes. Ensure `targets-list` / `target-context` and connector-owned tool families use exact Target authorization, and complete independent destructive upgrade evidence. Client-profile PR #126 (#117) is already approved and integrated into main as `359c0666ccd3e8fd3fa08328170fa8efccdce185`; the #107 WIP branch still requires an explicit conflict-aware integration of that main change, not a reset.

## Remaining #107 work before the candidate can be reviewed or merged

The existing Site-era runtime must be changed **atomically within the integration candidate**, so that no Admin/MCP endpoint or Laravel service continues accessing dropped Site tables:

- Move generic domain/application/controller/routes/views/tests/public tools to Target terminology without a permanent Site compatibility façade; keep truly WordPress concepts inside the WP AI Bridge connector.
- Reconcile all actual WP connector lifecycle, credential vault, discovery, OAuth callback and canonical-target reassignment paths against connector-owned persistence and purpose-aware Target credentials. Keep remote network I/O outside database row locks.
- Implement Target access/rules, Target Groups, default-denial behavior for **new** non-owners and first-edit denial preservation; prove exact Target-scoped MCP access and no Agent/SSH privilege escalation.
- Write immutable record identity and connector snapshots when recording Target Activity; filter Activity for current Target by immutable record identity rather than reusable public slug. Preserve Gateway-wide Activity.
- Validate public `target_id` to the exact same 64-character bound as persistence, preserve bounded inventory/check-operation semantics and index-backed MariaDB/MySQL queries.
- Run fresh-install, realistic **historical upgrade**, protected unrelated OAuth/admin state, and required WP regressions. A high-assurance review and explicit owner gate are required for any actual destructive migration/major integration; this branch's schema tests alone are **not** sufficient.
