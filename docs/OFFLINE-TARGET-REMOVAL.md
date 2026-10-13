# Offline Target removal — local-only Owner recovery

**Status:** source-integrated and independently security-reviewed under [Target lifecycle Issue #109](https://github.com/AChWorks/mcp-gateway/issues/109), but **not included in public v2.1.2**. Its availability on an installed Gateway still requires a separately Owner-approved public release and operator upgrade. This is a deliberate irreversible exception to normal connector disconnect, not a DNS/OAuth/network troubleshooting shortcut. Never delete an operator's Target in place without explicit instruction and backup.

## Two distinct operations

1. **Disconnect / normal Remove:** use whenever the remote connector is reachable and the Gateway can finish its existing credential revocation/cleanup. Normal `DELETE /admin/targets/{target_id}` is still blocked while credentials, active state, OAuth callbacks, refresh or revocation intents remain. This protects WordPress rotating offline grants against blind replay or false revocation.
2. **Remove locally without remote revocation:** a separate Owner-only `DELETE /admin/targets/{target_id}/forget` endpoint that requires `targets.remove` and `security.manage`, verifies current Owner role and password, an exact typed Target ID and *two separate explicit acknowledgments*. This operation intentionally does **not** call WordPress, an SSH host or any other remote provider; it succeeds even when DNS, TLS, the upstream host or local stored credentials are unavailable.

Only use the second path if the operator knowingly accepts that the remote account/client OAuth authorization **may remain valid** until separately revoked, and any already executing remote operation cannot be undone.

## Irreversible local effects

In one database transaction under a locked immutable Target-record ID, Gateway writes a **required** `target-forget-local` Activity entry with `remote_revocation_unverified`, the actor, connector type and Target snapshot; only after a successful audit insert does it delete the stored Target. Existing FK cascades remove that Target's encrypted credentials, WordPress config and OAuth/refresh/revoke pending intents, SSH config, direct user grants/denials and Target Group membership. Historical Activity and bulk-check Target snapshot records remain for audit/history; no external records are modified.

If the audit/database removal fails, the transaction rolls back; it must not show a success message. The same public `target_id` can be intentionally registered later, but its new ULID/database identity inherits **none** of the removed access assignments or secrets. The old WordPress OAuth grant should never be interpreted as safely revoked or reattached.

## WordPress-specific external cleanup

When the WordPress origin becomes reachable, the Owner must assess remote OAuth authorization separately. In WP AI Bridge, changing/removing a **shared approved Gateway client identity** may invalidate authorizations used by other clients or sites; assess those effects and preserve recovery evidence first. Merely seeing a Gateway Target disappear does not prove the remote token or possible unknown refreshed successor was revoked. Do not restart a previous uncertain refresh or press repeated Disconnect as a cleanup strategy.

For SSH, removing the local Target does **not** revoke the remote Unix account, server-authorized keys, external client sessions or access from other tools; rotate/remove SSH server-side credentials separately when appropriate.

## Operator/UI safety

The local-only form is shown only when **normal safe removal is blocked**, only to an Owner with the matching permission. It presents the exact Target ID, independent irreversible and remote-non-revocation acknowledgments, current Owner password and a distinct destructive button. The usual metadata/edit/Disconnect security checks are unchanged. All forms remain web-authenticated and CSRF protected. No password, encrypted token, private key or OAuth response is shown in the UI or Activity.

**Validation:** in addition to ordinary Target-management regressions, cover a disconnected-but-pending and network-failed WordPress Target with encrypted credential/refresh/revocation/OAuth state, fail-closed password/role/ID/ack refusals, FK cleanup/audit preservation, paused/SSH connector cases, no remote HTTP traffic and rollback when a database deletion fails. Source PHPUnit assertions are not a production host integration test.

**Release boundary:** The source feature does not update an installed `v2.1.2` Gateway or fix the original `dns_lookup` incident. Separate exact-candidate independent security review, Owner merge approval and explicit public-release/operator deployment gates still apply.
