# MCP Gateway v2.0.0 — Breaking Target candidate (NOT PUBLISHED)

**Development-only release candidate on the Target foundation branch.** No GitHub Release, production deployment, upgrade or database reset has been authorized. This major version replaces the Site model and is not backward-compatible with existing Site-era API paths or saved connections.

## Intended first major package

- Generic immutable Target domain, ACL/Target Groups and scoped Activity, with real Target Admin inventory, registration, detail, display-name editing, checked metadata diagnostics and guarded removal.
- WordPress Target OAuth with target-bound encrypted PKCE credentials, signed client identity, confirmed remote revocation, bounded rotating refresh-token recovery and scheduled idle renewal.
- Authorized exact-Target MCP inventory/context plus WordPress Ability catalog and safety-class-gated execute; existing client-neutral ChatGPT OAuth remains supported.
- Intentional retirement of old Site-only routes and bulk-check pages; Agent and Direct SSH runtime remain **unimplemented** and are not advertised.

## Mandatory operator warning

The upgrade from published v1.2.1 replaces the legacy Site schema, invalidates incompatible Gateway OAuth grants and token generations, and requires fresh WordPress and ChatGPT authorization. It **preserves local administrators/users/roles, security keys, global authorization denials and unrelated Gateway data**, not the old connector registrations or Site groups. A consistent **independently restorable database backup** and explicit operator reset+backup acknowledgment are required *before destructive DDL*. The browser updater's code backup **is not** a database backup. A partial MariaDB DDL failure requires restoring the independent database backup; never assume rollback or automatically retry.

## Release gates (not yet satisfied)

Current isolated SQLite/MariaDB test results are not release authorization. Complete real browser-ZIP upgrade and recovery checks from the **published v1.2.1 deployment**, real non-production WordPress Target E2E and ChatGPT reconnection, exact-candidate CI and independent HIGH_ASSURANCE review. Require owner approval before merge, publication and production upgrade. See docs/TARGET-TRANSITION-RUNBOOK.md and Issue #107.

---

# MCP Gateway v1.2.1

This is a backward-compatible feature release built on the v1.1.10 browser-update baseline. v1.2.0 was used only as a pre-release validation candidate and was not published as a stable release.

## Highlights

- MariaDB 10.11 is now the primary database target while MySQL compatibility remains supported.
- Multi-administrator access control adds owner/admin/operator/viewer roles with site-scoped authorization.
- Site Groups add reusable group-scoped access and site membership management.
- Site Health stores bounded connection evidence and exposes explicit single-site diagnostics.
- Selected-site bulk health checks add bounded multi-target operations with durable per-target status and partial-failure handling.
- Fleet inventory and Activity hot paths are better bounded for larger site counts.
- OAuth refresh/recovery diagnostics and continuity behavior are more robust while remaining secret-safe.
- Repository and WP AI Bridge namespace references are normalized under AChWorks.
- The Admin UI now uses a shared visual foundation for selects, checkboxes, filters, tables, access controls, responsive states, and dark mode.
- Permission controls now show human-readable titles, Gateway-wide vs site-scoped level, and concise behavioral help derived from the authoritative permission model.

## Upgrade compatibility

The official browser updater remains the supported path for deployment-ZIP installations. Release validation covers both the historical v1.1.2 baseline and the current v1.1.10 production baseline before publication.

A pre-release v1.2.0 candidate may also be upgraded normally to v1.2.1 because the final candidate advances the installed version instead of relying on a same-version replacement.
