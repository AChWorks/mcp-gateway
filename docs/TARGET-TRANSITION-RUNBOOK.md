# Site-era to Target-era upgrade — operator safety and recovery

**Use only when upgrading a genuinely legacy Site-era Gateway installation (v1.x) to the reviewed Target-era major version.** This is a high-impact, destructive **historical compatibility path**, not current development work, a guide for ordinary v2.x updates, or an instruction to reapply migrations on an already upgraded Gateway. For routine installation/updating and web-updater recovery use [DEPLOYMENT.md](DEPLOYMENT.md); use the exact [published release and release notes](../RELEASE_NOTES.md) for source-version compatibility. Relevant completed design/evidence: [#107](https://github.com/AChWorks/mcp-gateway/issues/107) and [#112](https://github.com/AChWorks/mcp-gateway/issues/112). The original full migration development diary is retained in Git history and Issue comments—not as a second live specification.

## What the breaking migration actually means

- The core identity changes from legacy **Site** to immutable Gateway **Target**. Site registrations and their credentials, Site Groups, Site-specific rights, Site check operation records and dependent flow/revocation state are **deliberately reset**, not silently converted into apparently equivalent new Targets.
- Existing Gateway OAuth client authorizations, issued access/refresh tokens and pending authorization/recovery state are intentionally invalidated so a previously connected AI client cannot inherit rights over newly registered Targets without fresh consent.
- Gateway **users, roles, global denials, private encryption/signing keys, unrelated activity and host-managed files** must remain protected. A user's scope mode maps to the Target-era mode, but Selected membership starts empty until Owner approval assigns Targets.
- Only known compatible permission denials are mapped. Unknown roles or denial identifiers fail the migration **before destructive DDL**, rather than silently expanding access. Existing non-Owner SSH capabilities remain conservatively denied until explicitly authorized. The historical Agent connector was canceled and is not a current supported Target family.
- The authoritative full list of legacy tables, guards and exact preservation behavior is the **already shipped migration source**, [`2026_10_09_000000_transition_site_domain_to_targets.php`](../database/migrations/2026_10_09_000000_transition_site_domain_to_targets.php), verified against the actual **selected release**. Do not copy old migration code or invent a shortcut based on its former Issue state.

## Mandatory preflight before an owner-authorized v1-to-v2 upgrade

1. **Identify the installed artifact and database migration state** using authorized read-only evidence. Check the actual installed version, current schema and whether the Site-to-Target migration has already been applied. A published release, successful CI or a document does **not** establish installed state. **Never rerun a recorded migration** to reproduce a test.
2. Review the exact starting release and planned destination using official asset/checksum and [deployment/update instructions](DEPLOYMENT.md); do not mix prerelease ZIPs, bypass version checks, copy one `VERSION` file or use a fresh-install package over an existing database.
3. Schedule maintenance and protect **all** required assets: consistent database dump, private `.env`, `APP_KEY`, both OAuth/Bridge signing-keypairs, required private runtime files, old release identity, and host-managed public files. **Independently restore the database backup to a disposable database and verify rows/schema**; the browser updater's code/files backup is **not a database backup**.
4. Inventory Site/credential/group memberships and existing Gateway client grants; accept that the old Target-scoped relationships and tokens will be discarded. Arrange post-upgrade WordPress Target enrollment and AI-client consent again. Record who authorized the reset and how recovery is performed. Do not export credentials into documentation or activity logs.
5. Rehearse the *exact* authenticated browser/update and SQL path on a sanitized, version-matched disposable copy if the installed starting version has not already been covered by compatible upgrade evidence. MariaDB/MySQL DDL may not be transactionally reversible.

## Exact confirmation gate

**Only** as part of the explicitly approved and prepared major transition, when the actual migration preflight reports that reset is required, the code recognizes these two config-backed acknowledgments:

```dotenv
GATEWAY_TARGET_RESET_ACKNOWLEDGED=RESET_TARGET_STATE
GATEWAY_TARGET_RESET_DATABASE_BACKUP_VERIFIED=RESTORABLE_DATABASE_BACKUP_VERIFIED
```

They are **operator attestations, not backup creation, backup verification, credentials or an upgrade authorization substitute**. Do **not** add them to an ordinary live installation. Clear the one-time flags when the migration is finished and independently verified. Existing installations that have completed the transition must never re-enable them for routine upgrades.

A missing acknowledgment, unexpected historical schema, unknown role/denial, or partial Target schema should stop before or safely block destructive work according to the exact source. The absence of an HTTP response or a stalled web-updater screen is not proof that SQL did not execute.

## Partial failure and recovery

If **no destructive migration began**, retain original data and use the updater's authenticated, documented preflight/recovery state rather than replacing files manually. If DDL **might have started**, **stop**: never blindly rerun the migration, call `migrate:rollback`, delete current tables, or reinstall over an uncertain database. Identify the last proven stage and recover from the **separately verified consistent database backup** under an authorized operator restoration plan; code-only rollback cannot restore dropped Site records.

After a proven successful transition, verify migrated users/global denials, absence of unexpected grants, correct schema and retained private keys before registering new Targets and reauthorizing WordPress and AI clients. Audit Target-scoped permissions/Groups anew; a successful connection is not evidence all access policies are correct.

**Where truth lives:** present installed state in the actual host; supported migration guards in source; durable Target identity/authorization in [ARCHITECTURE.md](ARCHITECTURE.md) and [TARGET-CONNECTOR-FOUNDATION.md](TARGET-CONNECTOR-FOUNDATION.md); completed v1-v2 rehearsal evidence in Git/closed [#107](https://github.com/AChWorks/mcp-gateway/issues/107) and [#112](https://github.com/AChWorks/mcp-gateway/issues/112). This runbook deliberately does not reproduce 2026 pre-release branches, candidate SHA diaries, historical migration conflicts, or superseded next-step prompts.
