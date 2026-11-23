# MCP Gateway v2 to separately installed v3: data transfer and cutover

**Work item:** https://github.com/AChWorks/mcp-gateway/issues/339

This is a one-off data-only transfer between an existing legacy MariaDB schema and an independently installed fresh v3. Do not run v3 migrations on the v2 DB, overwrite the new DB with the old one, or import legacy ChatGPT authentication.

## Authority and recovery gates

Production database, APP_KEY, vhost, scheduler and destructive changes require current exact Owner authorization. An approved GitHub PR alone is not authorization to touch Production. A separate exact Owner authorization will be needed to retire the old installation after successful new ChatGPT acceptance.

Before any live write:

1. Verify current old/new versions, schema, Owners, Users, Targets, Groups, explicit Denies, provider credentials, outstanding SSH Jobs, WordPress refresh state, Reverse/Relay state and cron/worker processes.
2. Establish an **independent, proven out-of-band management channel**. If the current ChatGPT connector uses the old Gateway, that connector will not work while the old site is frozen.
3. Take access-controlled backups of BOTH MariaDB databases, BOTH complete application trees, private .env/APP_KEY and OAuth/Bridge signing keys, installer marker, config caches, Nginx/vhost config, cron/worker configuration and relevant file-backed state. Verify hashes and demonstrate independent **full application + database + matching key** restoration. Keep both original APP_KEYs recoverable. An off-host protected copy is recommended before deleting the old installation.
4. Rehearse this **exact reviewed candidate** on new disposable database copies restored from both backups. Verify native v3 Vault opens, Owner authentication, permission/Denies, retry, induced error rollback, exact data comparison and post-commit rollback.
5. Plan a coordinated source write freeze and maintenance window. Without a freeze or an independently proven lossless delta strategy, **do not perform live import**.

## Mandatory source freeze / authoritative cutoff

Before final source snapshot and live import, block all old Gateway HTTP/API write entrypoints at an approved maintenance boundary, stop old cron / schedule:run / queues / provider maintenance and reconcile any genuine unfinished remote SSH Jobs. Do not blindly cancel, retry or resume uncertain remote effects. Verify the old site and its background workers cannot write. Where operationally feasible, revoke or suspend old application's DB write grants until deliberate rollback. Merely observing unchanged row counts or running artisan down is not a complete freeze.

Pause the **new v3 scheduler and all provider/background workers** before importing. Imported WordPress due-refresh timestamps, Target connected labels, Reverse SSH enabled flags or Relay keys must not automatically cause new remote/provider effects. Do not run both old and new schedulers against the same credentials during cutover.

With source and destination frozen, take a **new final paired backup and record stable source counts**. The helper obtains READ locks on *all* legacy tables from a separate MariaDB session while the destination InnoDB transaction imports and checks data; a concurrent legacy writer is blocked. These locks are released when the helper exits. **The external source freeze must remain in place after commit** until the new Gateway is accepted. Run a fresh locked verify after commit. If source changes after the authoritative cutoff, freeze/diagnose again and reconcile the delta; never silently accept stale data.

The helper's --ack-source-quiesced and --ack-destination-scheduler-paused flags attest operator verification. They do not suspend services by themselves.

## Transfer policy

- Copy stable non-Owner User identities, roles, Target/Relay record IDs, registered Target/Relay configuration, encrypted credentials, SSH pinned host keys, Groups, explicit Allow/Deny grants, Reverse settings, operational settings/history and compatible Activity/audit events.
- Keep the new v3 Owner **and its password**. Imported Administrators have self_created_target_access=0; destination non-Owner expanded scope is rejected. Unknown destination Users, Targets, Groups or permission records fail. Imported Targets are not assigned invented created_by_user_id grants.
- Preserve v3-only fields, OAuth/Bridge signing files, installer marker, migration table, v3 OAuth client profile, new Batch/maintenance state and scheduler counters.
- Exclude historical SSH Jobs, legacy ChatGPT tokens/authorizations/Client/Profile/Consent/DCR state, password-reset tokens, and transient Target checks, WordPress OAuth/refresh/revocation intents or Reverse enrollment. Nonempty legacy transient queues cause a hard failure for explicit reconciliation; never replay remote effects.
- Non-ChatGPT WordPress/Arvan credential fields may decrypt correctly yet require external reauthorization due to changed endpoint/issuer/callback configuration.

## APP_KEY and operational order

Native v3 Vault compatibility with the old APP_KEY has been demonstrated for SSH, WordPress, ArvanCloud and Relay encrypted fields. Before changing the live new installation, confirm that no new-v3 OAuth grant/access/refresh/recovery or other encrypted state depends on its original APP_KEY; keep paired restorations of **both** keys and databases. Reuse only the old APP_KEY entry in the new .env. Do **not** overwrite the new .env wholesale, signing key files, installer marker, new Owner or v3 migrations. Laravel uses APP_KEY to derive OAuth cryptographic keys, even when OAuth signing RSA files are separate. Clear/rebuild any cached Laravel configuration in the approved window and verify the running site reads the intended key without printing it.

The migration script itself intentionally does not edit .env or call remote providers.

## Operator CLI

Run from an approved local operator shell with local MariaDB socket authentication. Default socket: /tmp/mysql.sock. Use --socket=/actual/absolute/mysql.sock if different. The old schema name may contain a hyphen; the script quotes SQL identifiers.

~~~bash
php bin/migrate-v2-to-v3-state.php --source=legacy_stage --destination=fresh_stage --mode=plan
php bin/migrate-v2-to-v3-state.php --source=legacy_stage --destination=fresh_stage --mode=migrate --ack-source-quiesced --ack-destination-scheduler-paused
php bin/migrate-v2-to-v3-state.php --source=legacy_stage --destination=fresh_stage --mode=verify
php bin/migrate-v2-to-v3-state.php --source=legacy_stage --destination=fresh_stage --mode=migrate --ack-source-quiesced --ack-destination-scheduler-paused
~~~

A failed validation rolls back the destination transaction. Existing matching rows are reused on idempotent runs; conflicting or extra destination records are rejected. All copied tables must be InnoDB. Source READ locks are acquired only in migrate/verify, and a separate verify after the live commit is mandatory.

For synthetic fixture QA only, --qa-lock-delay-ms accepts a short delay when BOTH schema names start achgw_qa_. The executable regression suite bin/test-v2-v3-state-transfer-qa.php requires disposable achgw_qa_* schemas already seeded and migrated with synthetic data. It tests byte-exact field comparisons, privilege and destination extras, intentional FK failure rollback, InnoDB requirement, post-commit source drift, idempotence, nonempty transient rejection, and a concurrent source writer blocked while migration locks are held. **Synthetic QA is not a substitute** for exact-candidate rehearsal against restored private production snapshots and native credential checks.

### Reproducing the synthetic regression on an isolated lab

Use a local, isolated MariaDB server (never the production socket), PHP 8.4+ and project Composer dependencies. Create **two empty databases** named with the `achgw_qa_` prefix and apply the official v3 migrations to each. Convert **only the synthetic source** to v2-shaped schema by dropping `targets.created_by_user_id` (after its FK), `users.self_created_target_access`, the eight v3-only operational columns, and the four v3-only tables (`target_batches`, `target_batch_items`, `ssh_job_maintenance_progress`, `wp_credential_maintenance_progress`). Never run this downgrade on a real database.

Run `bin/seed-v2-v3-state-transfer-qa.php --source=achgw_qa_source --destination=achgw_qa_destination --socket=/isolated/mysql.sock` on fresh disposable schemas. This seeds generated synthetic SSH, WordPress, Arvan and Relay secrets, one old SSH Job, old ChatGPT OAuth records, a due WordPress refresh and intentionally restrictive permissions. Execute the exact candidate `--mode=plan`, `--mode=migrate` with both cutover acknowledgment flags, and `--mode=verify`. Then run:

~~~bash
php bin/test-v2-v3-state-transfer-qa.php --source=achgw_qa_source --destination=achgw_qa_destination --socket=/isolated/mysql.sock
php bin/test-v2-v3-native-access-qa.php --database=achgw_qa_destination --socket=/isolated/mysql.sock
~~~

The native AccessControl QA verifies selected Target scope, group and User Deny precedence and Owner access against the real v3 authorization code. Run native v3 Vault opening tests on these imported fixtures as part of acceptance. Synthetic tests exercise the migration contract but **do not establish** restored live-application functionality, provider readiness, real-production-backup rehearsal or approval to change the live installation.

## Acceptance after import and before fresh ChatGPT connection

With old writers frozen and new scheduler still paused, require:

- Fresh verify after commit reports exact source/destination correspondence in BOTH directions, stable final snapshot counts, valid FKs and no unknown destination grants.
- Fresh v3 Owner login and password unchanged; Administrator selected-scope, Denies and Group permissions enforced; v3-only creator-scope flags remain restrictive.
- All Target/Relay ciphertext opens through native v3 Vault verification and identity/endpoint bindings match. SSH pinned host trust and provider credentials are verified via safe read-only operations where authorized.
- v3-only migrations/installer state, signing keys and OAuth client profile intact; no imported old ChatGPT tokens/consents or historical SSH Jobs. Activity history and setting changes reconciled.
- Imported Target connected flags, due WordPress refresh state, Reverse SSH host/publication and Relay routing individually checked in the new installation; imported labels alone do not prove readiness.
- The management route independent of the old ChatGPT connector has been tested, and health, read-only capability and diagnostics are acceptable.

**Then** ask Owner to connect ChatGPT from scratch to the new Gateway /mcp endpoint and verify harmless authenticated MCP calls. Old Gateway must remain installed/restorable, with its writers still frozen during cutover. Activate only the appropriate new background/provider processes after new authority/routing has been validated; avoid simultaneous conflicting old work.

## Failures, rollback, roll-forward and decommission

If an import commits but subsequent **pre-acceptance** validation fails, do not restart old writers immediately. Restore the **paired** pre-import fresh-v3 database, original new APP_KEY, installer marker, OAuth/Bridge signing files and config cache; validate fresh Owner authentication and original new empty Target state. The old database/key remains unchanged. Under explicit operator decision, re-enable old site/cron/provider work after verifying its restored state. Do not attempt row-by-row rollback of encrypted identities.

If new v3 has already generated OAuth tokens, remote changes, provider refreshes or other accepted effects, restoring the old new-v3 backup may lose new state; preserve current evidence and explicitly **roll forward** instead. Never replay unknown old SSH Jobs.

Only after the user confirms new ChatGPT connection and acceptance should the old Gateway be retired, under **separate explicit destructive authorization** and protected backup retention. Keep host-specific private identifiers, backup paths, keys and validation output in the protected private continuity record, not public GitHub issues or PRs.
