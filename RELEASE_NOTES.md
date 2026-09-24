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
