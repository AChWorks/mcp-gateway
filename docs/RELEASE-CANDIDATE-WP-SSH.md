# WordPress + SSH Gateway combined release-candidate acceptance

Owner: [Issue #112, Revision 34](https://github.com/AChWorks/mcp-gateway/issues/112).
This is a **test-candidate runbook**, not a public Release, production
installation, or authorization to merge/publish. The accepted release remains
**v2.0.3** until the Owner separately authorizes a specific reviewed main SHA,
VERSION, and release action.

## Release-line reconciliation

- The v2.0.3 maintenance branch is not a direct ancestor of the unreleased
  WordPress/SSH main branch. Its maintenance-fix commits include browser-updater
  host-worker permission diagnostics, manual finalization progress, WordPress
  catalog error classification, and bounded idle OAuth refresh. Do not reset
  either branch, force-merge a divergent release tag, or copy VERSION alone.
- Candidate VERSION **2.1.2-rc.6** is a distinct **unpublished prerelease
  identity**, strictly newer than previous deployed test candidates 2.1.0,
  2.1.1 and GitHub-distributed 2.1.2-rc.1 / 2.1.2-rc.2 / 2.1.2-rc.3 / 2.1.2-rc.4 / 2.1.2-rc.5 artifacts. CI
  correctly rejected reusing rc.1 across two different PR HEADs, proving the
  immutable candidate-identity gate. Planned public stable is **2.1.2**, never assigned
  to a test candidate.
  Later test rounds must increase `-rc.N` rather than reuse a deployed VERSION.
  PHP `version_compare` maintains the order `2.1.1 < 2.1.2-rc.1 <
  2.1.2-rc.2 < 2.1.2`. Candidate artifact generation validates this identity;
  manual public Release dispatch still rejects prerelease versions. CI
  also compares the intended candidate identity against every currently retained
  GitHub Actions artifact and rejects any same `-rc.N` used by a different
  PR HEAD; GitHub expires test artifacts, so owners must still never recycle
  older prerelease numbers after artifact retention ends. Promotion
  to stable requires changing VERSION to 2.1.2, completing exact-stable-source
  gates, independent review and a separate Owner publication authorization.
  GitHub CI retains the live ChatGPT OAuth/JWKS compatibility check as a hard
  gate, with one bounded 5-second retry on a transient public-provider fetch
  failure; it never promotes an unverified JWKS or disables compatibility validation.
  The notes retain exact public v2.0.3 history before v2.0.2.
- Verified at branch creation: the active updater, updater browser index,
  update regression scripts, and release-note renderer match v2.0.3 byte for
  byte; the WordPress connection/transport paths on main contain subsequent
  enhancements and are not byte-identical. A successful fresh installation
  plus actual v2.0.3 Target-era update tests are required to verify behavior.
- Both release workflows now cover the **actual published 2.0.2 and 2.0.3**
  deployment ZIPs in addition to older release baselines, including backup
  integrity cases. The v2.0.3 Target-era fixture now seeds and verifies
  encrypted Target credentials, Target-group ACLs, denial layers, users and
  ChatGPT authorizations rather than merely installing an empty database.
- **Public Release is no longer coupled to VERSION pushes or PR merges.**
  `.github/workflows/release-package.yml` uses a manual dispatch on main with
  the exact reviewed SHA and approved version. It refuses a changed main ref,
  mismatched version or existing unreleased tag collision. This does not
  replace the required human release approval.

## Exact-source mixed WordPress + SSH acceptance

Run the existing `tests/Support/installed-mixed/run.sh` isolated test, not
against a production WordPress/SSH/Gateway host. The harness creates a
short-lived private MariaDB socket, a net namespace containing genuine
WordPress HTTPS, Gateway HTTPS, and an SSH daemon, and then destroys its owned
Unix SSH user, database and fixture. It fails closed for dirty/uncommitted
Gateway source and mismatched input SHA-256.

Both compatible WordPress lanes must be checked on the same candidate HEAD:

1. **Published Bridge v0.5.1:** use the default fixture/manifest from
   `tests/Support/installed-mixed/fixture-pins.sha256`; tests existing and
   novel native Abilities, OAuth, per-Target authorization and both binary
   clients.
2. **Merged Bridge source after PR #145 (not a new public Bridge release):**
   the immutable Bridge source commit is
   `c522ae99bd11926eb74c007d187354013202fc4c`. From a READ_ONLY
   local checkout containing that object, build the reproducible test-only ZIP:
   `bash tests/Support/installed-mixed/build-bridge-source-fixture.sh
   <readonly-Bridge-repo> <private-zip-path>`.
   Set `MIXED_BRIDGE_PROFILE=merged-main-c522ae9` and
   `MIXED_WP_BRIDGE_ARCHIVE=<private-zip-path>`; the separate
   `fixture-pins-bridge-main-c522ae9.sha256` fails closed on any different
   byte sequence. This lane adds actual `content-read` testing for a
   >128 KiB UTF-8 WordPress post across bounded source-hash continuations,
   byte-for-byte assembled by an authenticated external MCP PHP SDK client,
   including rejection of an incorrect continuation hash. It does not imply
   model ingestion or attachment support.

Retain `identity.txt`, `report.json`, `client.json`,
`file-client.json`, `python-file-client.json`, and `cleanup.txt` from each
lane as local sanitized evidence; record exact Gateway HEAD and tree, Bridge
ZIP SHA, PHP/MariaDB versions, byte counts, digests, limits, denial responses
and cleanup status. The two external clients independently verify complete
binary receipt over TLS, including empty, 256 KiB, ~1 MiB, PDF, PNG, ZIP and
UTF-8 fixtures. Client-side SHA/length are mandatory: server-side staging
alone is insufficient.

## Owner-edited connector configuration safety

The installed Admin `Targets → Target details → Edit Target` page has
separate low-risk display-name editing and high-trust connector configuration.
Owners must supply their **current Gateway password** before modifying an
implemented connector's endpoint, trust pin or credential. The request carries
an opaque optimistic revision: concurrent verification, disconnect, credential
rotation or another configuration edit makes a stale form fail without applying
its content. Sensitive passwords/private keys/passphrases are **write-only**
and are not flashed after validation errors.

- **Direct SSH:** host/IP, TCP port, OS username, independently verified
  PUBLIC OpenSSH server host key, and either password or PRIVATE login key
  can be changed in place. With the same login method, leaving the secret
  blank retains its encrypted material, but **rebinds and re-encrypts it to
  the new endpoint and pin**. Changing methods requires the new secret.
  Invalid fresh private keys/passphrases are rejected before mutation.
  Any actual configuration or secret change atomically clears the old
  verification, observed peer and connection health. Executing SSH
  commands or SFTP requires a subsequent genuine pinned-host-key/login
  **Verify**; stale in-flight verification cannot overwrite the rotated
  state. A no-op cannot silently reset healthy state.
- **WordPress:** its canonical public HTTPS origin may be edited only with
  all active/pending local OAuth credentials, callbacks, refresh and
  revocation intents cleared via the supported safe Disconnect/Recovery
  workflow. Never copy an existing token to the changed origin. Perform the
  existing bounded SSRF-safe same-origin OAuth metadata discovery before
  committing. Then reauthorize via the normal WordPress OAuth flow.
  If remote revocation cannot be confirmed, leave the original Target
  unchanged and blocked, not silently re-pointed.
- **Stable identity:** target_id, connector type, User/Target Group
  memberships, direct ACLs, historical grant references and deny policies
  remain unchanged. Stored Agent Targets do not obtain new editor capabilities.

Shared User creation still defaults to **SSH deny**: all three command/SFTP
denial checkboxes render checked. The Owner can intentionally uncheck a selected
capability during **Add User** (or **Edit User**) only after explicit confirmation
and reauthentication, with **Selected** Target scope. The submitted form must
also carry the actual SSH-permissions-reviewed marker: a standalone confirmation
flag on a legacy/unreviewed form cannot lift default SSH denials. An unreviewed/legacy form
or failed confirmation never silently creates an SSH grant. Target reachability
still requires an explicit User → Target allow or assigned Target Group; roles
without the requested capability cannot be elevated. Widening to **All** Target
scope revokes non-Owner SSH grants, even when the account previously had them.

All permission contexts now share the same checked=DENY explanation and show
**live** SSH controls instead of a misleading "reserved definitions" list:
**Add/Edit User** manages global denials/grants; **User → Target access** adds
Target-scoped denials and a separately Owner-confirmed reachability rule;
**Add/Edit Target Group** adds only denials and never confers a capability.
Changing a Group denial or an SSH Target scope/denial requires explicit Owner
confirmation and password, because removing a denial or adding reachability
can widen an already-authorized user's SSH access.
Deleting a Target Group or changing its User/Target membership can also lift
SSH denials or activate already Owner-approved SSH rights, even with overlapping
group membership. Require the explicit `confirm_ssh_group_changes` checkbox,
`security.manage` authority and Owner password for changes involving SSH
Targets or SSH denial groups, with the required confirmation checked again
under a locked DB group row immediately before mutation. Non-SSH changes and
true no-ops remain functional without SSH-specific acknowledgement. Regression
must exercise deny lifting via overlapping groups, both assignment directions,
stale denial edits and the positive preauthorized SSH case. SSH unrestricted OS shell
authority can modify files even when SFTP tools are denied. Agent permission
identifiers remain paused and **read-only**; do not activate nonexistent tools.
Add Target itself only registers a connector endpoint; it never creates
positive User-to-Target scope rows. A Selected-scope creator is redirected
to their permitted Target list, not an inaccessible Target detail page, and
receives instructions to request explicit Owner assignment through User →
Target access or a Target Group. Only after that assignment can previously
Owner-approved global connector capabilities be used on the new Target.
Existing All-scope users and Owners retain their separately assigned scope.
OAuth-origin edit UI also suppresses the form while a WordPress authorization
flow is pending, matching the server-side reject.

**Whole-Gateway error/reporting acceptance:** Admin Target errors and stored
Target health show a human explanation and next check, while API/MCP errors
retain machine-readable reasons with additive safe next steps. HTTP requests,
Activity and application logs share a correlation ID. Network failures carry
finite DNS/TCP/TLS/timeout stages when actually known, while WordPress OAuth
revocation intent, refresh uncertainty, SSH trust and unknown remote file
writes continue to fail closed. No raw credentials, command contents or
network payloads enter logs. Fresh install and standalone browser updater
failures have PHP-host-log references. See [deployment diagnostics](DEPLOYMENT.md#production-diagnostics-runbook).
These are local candidate features, not yet proof of an installed upgrade.

Editor regression evidence must include password-only and private-key
rotation, both credential-preserving host/port edits and disconnected
credential reinsertion, wrong Owner password, stale edit and trusted-key
rejection, in-flight verification fence, blocked command/SFTP before
re-verification, safe WordPress revocation/origin switch, and preserved
Target/Group/User ACLs. Actual operator-host update and post-install tests
are separate production gates, not implied by disposable fixtures.

## Real released-baseline browser update

Obtain `mcp-gateway-v2.0.3.zip` and the companion `.sha256` from
[the v2.0.3 Release](https://github.com/AChWorks/mcp-gateway/releases/tag/v2.0.3).
Verify SHA-256 **before** using it. Build the candidate deployment and browser
update ZIP using `bin/build-release-package.sh` and
`bin/build-update-package.sh`; verify with both `verify-*-package.sh`
scripts and hash the final archives. Use disposable MariaDB and:

```bash
bash bin/test-update-package.sh /path/to/candidate-update.zip /path/to/mcp-gateway-v2.0.3.zip
bash bin/test-update-backup-integrity.sh /path/to/candidate-update.zip /path/to/mcp-gateway-v2.0.3.zip
```

For operators who already installed a 2.1.0 or 2.1.1 candidate, the
2.1.2-rc.6 update package must additionally pass the same authenticated
browser-update test against a **verified unaltered candidate fresh-install ZIP**
from each earlier installed GitHub Actions run (verify its original checksum, provenance
and hash). The credential/Target/grant preservation assertions must run for
both the published 2.0.x Target-era baselines and the distributed 2.1.0,
2.1.1 and the already distributed 2.1.2-rc.1/rc.2/rc.3/rc.4/rc.5 candidates where required. The updater intentionally rejects same-version/downgrade attempts:
**never** edit an installed VERSION, bypass that comparison, rename a ZIP to
pretend it is newer, or overwrite production files with a fresh-install ZIP.
If a 2.1.0 -> 2.1.0 attempt was rejected during preflight, it must not be
treated as a completed upgrade or replayed. Before attempting a new candidate, confirm
that no earlier update is staged/in progress and make a separately restorable
DB/config/key backup. Replace only the rejected *temporary updater staging*
with the newer prerelease update ZIP, following updater status/recovery instructions
if any state exists.

These run the real authenticated browser-update workflow, preserve
`.env`, OAuth and Bridge signing keys, private runtime state, host-managed
public files and seeded Target-era credentials/grants; verify preflight
rejections, protected-file handling, pre-migration recovery, cleanup, and
corrupt/missing recovery backup rejection before migration. The updated backup
test supports an explicitly constrained `UPDATE_TEST_DB_SOCKET` so isolated
Unix-socket MariaDB can be used without a shared host TCP database.

Separately take a transaction-consistent **disposable** MariaDB backup and
restore it into a different disposable database; compare the complete table
set plus populated User/Target/credential/Target Group/ACL counts. Application
**code** backup is not a **database** backup. For a real update, save and
test-restorable the database, `.env`, all relevant encryption/signing keys,
and an isolated roll-forward path **before** staging. An interrupted update
after possible DB mutation must not be blindly retried or automatically
rolled back on guessed database state.

## Tested profile versus outstanding host gates

The development test profile uses PHP 8.4, WordPress 6.9, MCP Adapter 0.7.0,
temporary MariaDB and a PHP built-in HTTPS backend, with TLS verification and
real OpenSSH host-key pinning. The optional SSH binary transfer mode is
enabled **only inside the disposable fixture** and remains disabled by
default on ordinary installations. The example chosen profile has a bounded
4 MiB SFTP transfer budget and 30-second limit; it is not a global Gateway,
WordPress, Agent or AI-client file-size ceiling.

Observed local byte receipts, per-client memory, latency, disk space, inodes
and PHP CLI settings must be recorded as **test-host evidence only**.
A production host's PHP-FPM worker memory/CPU/deadline, reverse-proxy body
and buffering policy, slow/cancelled ingress spool admission, TLS offload,
concurrency under pressure, disk/inode quota, idle maintenance and actual
end-user attachment receipt **cannot be inferred from a local PHP built-in
server**. Do not raise global safety limits or claim server-side staging is
client receipt. These need environment-specific owner/operator measurements;
a missing production host is marked **UNVERIFIED**, not quietly passed.

## Integration, independent review and public release gates

Run complete PHP tests, Pint, PHPStan, MariaDB concurrency, verified package
and upgrade checks, both installed WP+SSH lanes, and GitHub CI against the
**exact final PR HEAD**. The PR must capture source and package SHA identities
and evidence and remain unmerged until a single fresh **author-separated,
STRICTLY_READ_ONLY, HIGH_ASSURANCE** independent review returns an acceptable
verdict. The independent reviewer must inspect the actual effective diff,
release-line reconciliation, WP dynamic classification, binary safety,
cross-layer budgets, tests, docs, operational compatibility and honest host
limits. Subsequent changes invalidate an exact-HEAD verdict unless separately
reviewed. Finally, a **new Owner approval** is required for merge and an
**independent explicit Owner release approval** for public publication.
Production installation requires its own authorization. Do not close deferred
#97, #123, #130, #135, #147, #153, #154, or paused #111 just to make this
candidate look complete.
