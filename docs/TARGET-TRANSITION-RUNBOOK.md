# Target Foundation Transition — implementation and recovery runbook

Status: **IN DEVELOPMENT (#107)**. This is a proposed major-version breaking transition, **not** supported by current `main` or production builds. The new migration and Target models on `feat/target-foundation-107` are not sufficient for a working Gateway until every Site-era application/Admin/MCP route, connector flow, access rule and Activity query has been reconciled. **Do not merge/deploy this isolated implementation.**

Owning contract: [Issue #107](https://github.com/AChWorks/mcp-gateway/issues/107), [Program #106](https://github.com/AChWorks/mcp-gateway/issues/106), [Target foundation](./TARGET-CONNECTOR-FOUNDATION.md). The planned Direct SSH extension is in [PR #124](https://github.com/AChWorks/mcp-gateway/pull/124) until integrated.

## Why this must be an explicit operator-visible upgrade

Site-era tables combine registered WP AI Bridge Targets, OAuth credentials, local user Target assignments, groups and check operations. A clean `Target` foundation is a breaking replacement. The owner has accepted discarding and manually reconnecting that **Target-owned state**, **not** administrator accounts, Gateway client-facing OAuth/session signing identity, refresh recovery records or unrelated product state.

The existing browser-updater recovery archive protects application **files/code**. It is **not a consistent database backup** and is never proof of database recovery after this migration. Migration DDL in MariaDB/MySQL is not transactionally reversible.

Before the final major upgrade is released, the operator must put the application in maintenance mode, create a **consistent, restorable database backup** outside the application/code backup, and ensure the rollback procedure is understood. Database backup and restoration must be tested in a non-production environment. Explicit values in the migration configuration confirm that the operator performed those steps; they are attestations, not an automatic backup.

## Legacy state intentionally reset

The transition migration explicitly drops and recreates these Target-owned tables, **not by relying on cascade side effects**:

`site_check_operation_targets`, `site_check_operations`, `site_group_permission_denials`, `site_group_sites`, `site_group_users`, `site_groups`, `user_site_permission_denials`, `user_site_access`, `site_oauth_flows`, `site_credentials`, `site_revocation_intents`, `site_target_reservations`, `sites`.

Events in `activity_events` with a non-null legacy `site_id` are deleted to prevent them from being mistaken for a newly created Target with the same public slug. Gateway-wide Activity with null `site_id` and `activity_retention_state` remain. The new `activity_events` shape includes public Target slug plus nullable immutable internal Target ULID and connector-type snapshot, so delete/recreate cycles can be distinguished by query policy; **application-level recording/query updates remain an open #107 task**.

User `site_scope_mode` becomes `target_scope_mode`, preserving each user's current mode; the selected-scope membership set starts empty. Users, role identity, global permission-denial table, Gateway OAuth authorization/access/refresh tokens, client assertions, OAuth refresh-recovery records and persistent keys remain intact.

Only known one-to-one denial strings are mapped (Gateway connection, `sites.*`/common Target rights, former `connections.*` and WP `abilities.*`). Unknown legacy permission denies and unsupported role names **abort before DDL**, requiring explicit administrator reconciliation rather than accidental widening. Migration inserts mapped denials before removing legacy aliases, and seeds new `agent.*` / `ssh.*` denials for **existing non-owner users**. Newly created non-owner accounts and first-edit denial preservation are still owned by the subsequent RBAC/UI refactor and **are not yet implemented by this migration alone**.

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

## Remaining #107 work before the candidate can be reviewed or merged

The existing Site-era runtime must be changed **atomically within the integration candidate**, so that no Admin/MCP endpoint or Laravel service continues accessing dropped Site tables:

- Move generic domain/application/controller/routes/views/tests/public tools to Target terminology without a permanent Site compatibility façade; keep truly WordPress concepts inside the WP AI Bridge connector.
- Reconcile all actual WP connector lifecycle, credential vault, discovery, OAuth callback and canonical-target reassignment paths against connector-owned persistence and purpose-aware Target credentials. Keep remote network I/O outside database row locks.
- Implement Target access/rules, Target Groups, default-denial behavior for **new** non-owners and first-edit denial preservation; prove exact Target-scoped MCP access and no Agent/SSH privilege escalation.
- Write immutable record identity and connector snapshots when recording Target Activity; filter Activity for current Target by immutable record identity rather than reusable public slug. Preserve Gateway-wide Activity.
- Validate public `target_id` to the exact same 64-character bound as persistence, preserve bounded inventory/check-operation semantics and index-backed MariaDB/MySQL queries.
- Run fresh-install, realistic **historical upgrade**, protected unrelated OAuth/admin state, and required WP regressions. A high-assurance review and explicit owner gate are required for any actual destructive migration/major integration; this branch's schema tests alone are **not** sufficient.
