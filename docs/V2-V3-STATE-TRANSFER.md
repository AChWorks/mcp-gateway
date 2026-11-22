# One-off data transfer: MCP Gateway v2 to a separately installed v3

This procedure is **not** an in-place upgrade. The v3 database must already have the official v3 migrations applied and an initial Owner. The legacy schema and v3 schema remain separate until accepted cutover.

The command `bin/migrate-v2-to-v3-state.php` is an **operator-only** MariaDB transfer helper for the known v2/v3 schema pair. It does not change the Laravel runtime, remote Targets, ChatGPT connector or the application encryption key.

## Preflight and recovery gates

1. Verify the old/new version, database schema, target and user identities, and installed v3 migrations. Check the old and newly installed Owner have **matching numeric ID and email**; the script will refuse a mismatched Owner instead of guessing a remapping.
2. Securely back up **both** application directories, `.env` and signing keys, both MariaDB schemas, scheduled-task/reverse-proxy configuration and the old/new `APP_KEY` values. Restrict backup access, verify integrity and **restore both databases and application files in isolation**. The helper deliberately does not create backups or modify keys.
3. Use the native **v3** Vault classes on cloned records with the **old** `APP_KEY` to check complete per-Target/Relay bindings, not just cryptographic decode. Preserve original Target/Relay record IDs and SSH trust pins.
4. Before live import, examine active remote SSH Jobs, WordPress refresh due-state, Relay/Reverse state and the effect of running both installed Gateways simultaneously. Keep the old Gateway reachable until the new ChatGPT connection and independent management route are verified.
5. Take a final live pre-import backup under an approved maintenance/cutover window. Obtain the current production-write authorization and independent review for consequential migration code.

## Data policy

- **Preserve:** non-Owner users, roles, legacy credential identity and encrypted payloads, Target configs and stable identifiers, Relay settings/identity, Groups, explicit Denies/grants, operational settings/history, Reverse SSH configuration/retired-port records, and Activity events where structurally compatible.
- **Preserve new v3 bootstrap:** existing Owner login/password, new v3-only operational settings, schema migration history, signing-key files, maintenance/scheduler state and new OAuth client profile.
- **Exclude:** legacy ChatGPT OAuth authorizations, tokens, assertions, Client/Profile/DCR state, transient admission leases; historical SSH Jobs (also never replay); ephemeral in-flight Target checks, WordPress OAuth/refresh/revoke intents, Reverse enrollment and reservations. If any excluded non-ChatGPT transient is outstanding, investigate it independently; do not silently retry it.
- Imported v2 Administrators receive v3 `self_created_target_access=0` to avoid expanding privileges. The original v3 Owner is not replaced.

## Operator workflow

The helper connects through a local MariaDB root Unix socket (default `/tmp/mysql.sock`); use `--socket` if needed. Use an existing privileged local operator shell; never put DB passwords or `APP_KEY` values in commands or logs. The command reports counts and validation outcomes, **not secret values**.

After creating/validating separately named test databases restored from old/new backups:

```bash
php bin/migrate-v2-to-v3-state.php --source=legacy_stage --destination=fresh_stage --mode=plan
php bin/migrate-v2-to-v3-state.php --source=legacy_stage --destination=fresh_stage --mode=migrate
php bin/migrate-v2-to-v3-state.php --source=legacy_stage --destination=fresh_stage --mode=verify
```

The `migrate` mode writes **only to the destination schema**, in one InnoDB transaction, and compares source/destination shared data before committing. A failed validation rolls back. A second identical run is safe and skips already imported rows; it does not overwrite the new Owner.

After approved real cutover:

1. Back up both live sites/schemas and record source write snapshot. Recheck destination OAuth tables are empty. Do not import old OAuth.
2. Reuse the **old** `APP_KEY` on the new v3 *only if* cloned native Vault tests, new installation encryption-dependent state and independent fresh OAuth signing files have been checked. Change just that one `.env` entry; preserve both original keys for rollback, update Laravel config cache and verify the deployed config. This step is **separate** from the helper.
3. Execute `--mode=migrate` on the actual old/new schema pair. Check the helper's committed result, exact counts, Admin/Group/Target Deny and provider record bindings; verify no legacy SSH Job or ChatGPT authorization/token entered v3. Never make blind retries after an ambiguous database result; inspect destination first.
4. Run native Vault and safe read-only application/Target checks. Document any WordPress/provider OAuth reauthorization caused by host or callback changes. If there is a failure, use tested recovery, do not force import or repeat remote jobs.
5. Ask the Owner to connect ChatGPT **fresh** to the new `/mcp` URL. Test a read-only MCP request and independent management route while old Gateway is still available.
6. Retire the old installation **only under a later, separate destructive approval** after new acceptance and recovery verification.

**Source activity can change while the old Gateway remains online.** Read-only post-import comparison with a later source snapshot may correctly report newly added events. Arrange a final delta or explicitly document the cutover snapshot; do not treat continuing legacy writes as proof of an import defect.

Workflow and approvals: [Issue #339](https://github.com/AChWorks/mcp-gateway/issues/339). Never put production credentials, private backup paths, runtime host inventory or keys in public GitHub records.
