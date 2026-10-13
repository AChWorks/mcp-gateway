# WordPress Target disconnect recovery — Issue #173

**Version availability:** these source-integrated recovery actions are **not in v2.1.2**. Consult the exact approved public GitHub Release and the actual installed Gateway version before assuming they are available. Publishing a release never upgrades an operator host automatically. Do not test the actions against a working production Target without explicit authorization.

The Target Details recovery panel separates public WordPress metadata reachability, OAuth authorization, pending operations, and diagnostic history. Public metadata success is not OAuth success, proof of remote revocation, or proof that an authenticated WordPress Ability can run.

## Guided workflow

1. Open **Targets → Target Details → Connection and recovery**. Review **Ongoing operation** before choosing an action.
2. **Finish disconnect** is available only when the ledger proves the next revoke request was never dispatched. Already acknowledged tokens are never resent. **Finish confirmed disconnect** completes only local cleanup; no new WordPress POST.
3. If the remote outcome is **unknown** or **legacy unknown**, do not retry revoke, refresh, reconnect, or trust the stored credential. Contact the Gateway Owner for WordPress-side reconciliation.
4. **Cancel pending disconnect** is Owner-only and available only with durable proof of *zero* dispatched revocations, *zero* acknowledgments, unchanged credential generation, no pending refresh/callback, and an unexpired access bearer. Owner must confirm the exact Target ID and Gateway password. The Gateway then performs an authenticated **read-only WordPress Ability catalog** request using the existing token. Public metadata alone cannot authorize cancellation. Verification failure preserves the pending fence.
5. After confirmed disconnect, **Authorize WordPress** starts fresh OAuth. Restarting an unconsumed OAuth browser flow invalidates its older callback state.

## Owner WordPress-side recovery when remote result cannot be proven

1. Open the exact WordPress origin shown on the Target Details page; authenticate directly to WordPress.
2. In WP AI Bridge's **OAuth Clients**, **REMOVE the Gateway client ID from Approved OAuth Clients and SAVE**. Merely revoking one old token or signing out does not rule out unknown rotating-token successors. Removing an approved additional client may also revoke other non-ChatGPT OAuth clients approved for that site.
3. Independently confirm the saved remote change and preserve authorized evidence. Ensure any in-flight revoke/refresh has settled.
4. Use the Owner-only WordPress-side recovery form. Type the exact Target ID, check both explicit attestations (client approval removed; other clients affected), and enter your current Owner password.
5. A required transactionally persisted audit records an **operator-attested** result. Gateway clears its **local** credential and intent. This is NOT independently verified remote revocation. Then reapprove the client in WordPress and start new Gateway authorization.

PR #172's Owner-only local forget is a distinct last-resort operation and never proves WordPress-side revocation.

## Durable revocation state machine

| Phase | Evidence | Permitted automated action |
| --- | --- | --- |
| legacy_unknown | Existing pre-upgrade intent has no dispatch ledger | No replay/cancel; Owner external attestation |
| in_flight | A revoke slot was reserved; remote result not yet known | No replay/cancel; Owner external attestation after settling |
| retryable (0 acknowledged) | The first revoke was definitively not sent | Resume matching intent; optionally Owner authenticated-catalog cancellation |
| retryable (1+ acknowledged) | Earlier token(s) confirmed; next was definitively not sent | Retry next token only; cancel forbidden |
| unknown | A revoke may have reached WordPress | No replay/cancel; Owner external attestation |
| verify_in_flight | Owner cancel is validating existing bearer | Block other lifecycle mutations |
| confirmed | All remote tokens acknowledged; cleanup incomplete | Final local cleanup without network revoke |

Operations bind exact Target ID, intent ID, credential ID and generation inside row locks. HTTP requests happen **outside DB transactions**, and each remote acknowledgment is durably committed before another token is sent. A lost HTTP response or failed DB acknowledgment remains fenced, not automatically retried. New intent creation and successful cleanup have required transactional audit. The refresh-token ambiguity fence is separate and takes priority.

A source migration adds the replay ledger; **all old intents become legacy_unknown**, with no fabricated safe replay evidence. Rollback is blocked while any intent exists. The migration also adds independent metadata check evidence; older metadata observations stay unknown until rechecked.

## DNS/OpenLiteSpeed incident prevention

aaPanel/OpenLiteSpeed PHP LSAPI can have an effective VHost php_admin_value open_basedir restriction that blocks the React DNS resolver from reading /etc/resolv.conf or /etc/hosts, even when WordPress HTTPS works from an unrestricted terminal. The expected operation diagnostics are network_failure, failure_stage=dns_lookup and request_not_sent=true. This no-send proof belongs to **that specific request**, never to an earlier OAuth revoke.

An Owner can open **Operations → Outbound DNS compatibility preflight** for effective PHP readability checks (not a network check). If failed, correct only the affected PHP VHost's approved file-path allowlist using aaPanel, including real symlink destinations where required, and reload the applicable worker after reviewed host changes. Repeat the PHP preflight, metadata test, then an authenticated catalog operation separately.

Do not globally disable open_basedir, relax TLS/SSRF protections, add arbitrary public DNS fallback, or assume a previously modified public/.user.ini has been restored. Inspect actual host configuration before changing it.

## Acceptance boundary

Use isolated disposable WordPress and MariaDB, covering pre-dispatch failure, unknown/partial outcomes, repeat and concurrent submits, stale action, owner-only access, metadata/OAuth distinction, failed audit, expired token, refresh generation and real authenticated catalog execution. Passing CI does not establish live host acceptance, indefinite OAuth durability or permission for production changes. Merge, release and deployment require separate Owner authorization and independent high-assurance review.
