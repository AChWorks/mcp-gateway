# Installed mixed WordPress + Direct/Relay SSH acceptance

This is a **repeatable real installed-provider integration test runbook**, not a production deployment procedure or release status report. The parallel [synthetic PHP acceptance fixture](../tests/Feature/Mcp/MixedTargetAuthenticatedAcceptanceTest.php) cannot replace real WordPress, HTTPS and OpenSSH testing.

The isolated binary-client lanes use an official PHP MCP SDK plus an independently implemented Python HTTPS/MCP client to verify authenticated bidirectional SSH file bytes and SHA-256. The SSH binary sidecar is enabled only in the ephemeral Gateway. They do **not** establish ChatGPT-native file-parameter/model ingestion. See the [binary transport contract](WHOLE-FILE-EXCHANGE.md).

Both independently authored client implementations first call `target-context` over their real MCP session and verify the Target-specific advertised binary routes and effective SSH Owner budget; the PHP SDK client additionally confirms that the installed WordPress Target has **no** fabricated SSH binary mode. The independent Python client reconstructs a real local binary file.

## Scope and containment

The installed runner starts one fresh MariaDB on a private Unix socket,
one installed Gateway copy with real migrations and generated OAuth keys,
one installed WordPress 6.9 with real WP AI Bridge and MCP Adapter,
and one real host-key-pinned OpenSSH/SFTP server. A separately pinned native OpenSSH control server and loopback SOCKS5 client are added inside the same private namespace for the Relay stage. A separate PHP process
loads the official MCP SDK without booting the Laravel application and calls
the actual Gateway HTTPS `/mcp` endpoint.

The runner uses a private Linux network namespace with addresses
`11.22.33.44` (WordPress), `11.22.33.45` (Gateway) and `11.22.33.46`
(OpenSSH) and `11.22.33.47` (Relay control SSHD). These public-looking addresses exist **only in that disposable
namespace** to exercise ordinary production public-address/SSRF checks.
There is no host-bound test listener. Both HTTPS endpoints use a generated
IP-SAN certificate. Real peer/hostname verification remains enabled and
only the disposable copy's certificate bundle is extended.

The isolated installed Gateway registers a **test-only pinned OAuth client
provider** (absent from production boot), with one approved identity, one
revoked signed identity, and an enabled never-granted identity (whose bearer
issuance must fail). Gateway client bearer setup is performed via its real
internal OAuth authorization repositories, **not** via a complete external
Gateway authorization-code onboarding flow. The standalone SDK nevertheless
uses real signed bearers over authenticated HTTPS. WordPress registers the Gateway's real
OAuth client identity using its own approved-clients setting. Login,
nonce-protected browser consent, authorization code, PKCE, signed JWT
client assertion and downstream bearer exchange are all real requests.
The installed Owner changes the existing typed operational settings through
the normal settings service to prove DB overrides (3s connect, 9s request,
96 KiB normal and 512 KiB readonly), plus 4 MiB/30 seconds for
the optional SSH whole-file profile, distinct from the disposable
configuration fallback. The fixture also sets the existing 512 KiB SSH command/output and inline file windows and a 1024 KiB WordPress Ability input setting. The installed Bridge's own native request and response budgets are configured independently (1024 KiB request, 512 KiB response and 128 KiB text windows). The independent HTTP body limit remains in force.
No production account, web property, server listener, credential or SSRF
policy is changed. Do not run on user-owned/production sites.

## Running on an isolated Linux fixture host

Prerequisites: root authorization for `unshare` and a temporary Unix SSH
account, PHP 8.4 plus Composer dependencies, MariaDB, OpenSSH, `socat`,
`ip`, `openssl`, `runuser`, WP-CLI, and a compatible Linux kernel.

The runner uses deliberately pinned fixtures: WordPress 6.9 core archive, WP-CLI v2.12.0 PHAR, WordPress MCP Adapter v0.7.0 release ZIP and WP AI Bridge v0.7.4 release ZIP. Obtain the **actual required byte-identical artifacts** from the [official WordPress release archive](https://wordpress.org/download/releases/), [WP-CLI](https://github.com/wp-cli/wp-cli/releases/tag/v2.12.0), [MCP Adapter](https://github.com/WordPress/mcp-adapter/releases/tag/v0.7.0) and [WP AI Bridge](https://github.com/AChWorks/wp-ai-bridge/releases/tag/v0.7.4) when the runner's pinned fixtures require them. Existing plugin installation directories are **not** acceptable inputs.

The [Installed Mixed Acceptance workflow](../.github/workflows/installed-mixed-acceptance.yml) runs on a disposable GitHub-hosted Linux runner when the fixture or its workflow changes, and can be dispatched separately for a selected revision. It fetches the official pinned inputs and runs the same script as a separately authorized Linux fixture host. The suite is deliberately not a full installed-provider test on every unrelated PR. Use it for relevant provider acceptance and before recording a final installed compatibility claim. Never run it on a production host.

The committed `tests/Support/installed-mixed/fixture-pins.sha256` is the
**single authoritative pin manifest**. The archive/PHAR digests match
published GitHub release-asset SHA-256 values. WordPress.org publishes the
6.9 tarball SHA-1 separately; that SHA-1 was checked against the original
official file before recording its SHA-256 pin. The runner validates each
**actual input's SHA-256 before provisioning anything**, records all four
actual SHA-256 digests in `identity.txt`, and rejects missing/changed inputs
(even when an environment override points to them). A new fixture version
requires reviewed pin changes, not relaxed validation. No runtime downloads
or unverified installed plugin folders are allowed.

From a **clean, committed** authorized Gateway candidate worktree
(the runner refuses dirty sources so the reported tree and installed code
actually match):

```bash
sudo bash tests/Support/installed-mixed/run.sh
```

The runner accepts these environment overrides. Defaults are relative to the checkout or the host's temporary directory; input and evidence directories can be outside the checkout.

| Environment variable | Expected source artifact or setting |
| --- | --- |
| `MIXED_WORDPRESS_ARCHIVE` | Pinned official WordPress 6.9 `.tar.gz` |
| `MIXED_WP_CLI_PHAR` | Pinned WP-CLI v2.12.0 `.phar` |
| `MIXED_WP_BRIDGE_ARCHIVE` | Pinned WP AI Bridge v0.7.4 release ZIP |
| `MIXED_MCP_ADAPTER_ARCHIVE` | Pinned MCP Adapter v0.7.0 release ZIP |
| `MIXED_INPUT_DIR` | Directory of four pinned artifacts; defaults to sibling mcp-gateway-installed-inputs |
| `MIXED_EVIDENCE_DIR` | Private evidence destination; defaults to sibling mcp-gateway-installed-evidence |
| `MIXED_WORK_ROOT` | Existing temporary parent; defaults to TMPDIR or /tmp |
| `MIXED_WORKER_USER` | Existing non-root fixture user; defaults to SUDO_USER or aiworker |
| `MIXED_SSH_LONG_SECONDS` | Optional isolated long execution test: 0 (default), 350 or 590 |
| `MIXED_SSH_LONG_MODE` | `native` (default) or `staged` |
| `MIXED_SSH_LONG_ROUTE` | `direct` (default); `relay` for staged mode only |

Use byte-identical, pinned artifacts at an alternate trusted local path if
the default path is unavailable. Unsupported versions or a changed archive
**must fail** before user/database/network setup. The test establishes
compatibility only for the exact pinned versions in `identity.txt`, not
arbitrary current WordPress/Adapter releases. The previously observed interoperability defect
was a missing required JSON-object `capabilities` field in the downstream MCP
`initialize` request; the real Adapter rejects that malformed request,
whereas an older HTTP mock silently accepted it. A source regression test
now asserts the exact object shape.

Before provisioning, the runner checks for tracked changes and uses
**`git archive HEAD`** for the installed Gateway: Git-ignored `.env`, compiled
views, MCP sessions, private runtime files and preexisting caches are not
included. The install fails closed if tracked input attempts to inject `.env`,
`.git` or preexisting `vendor`. Composer dependencies are freshly installed against the committed
`composer.lock` in the isolated target, never copied from checkout `vendor`.
All writable `storage` paths and `bootstrap/cache` are re-created **empty**
after dependency installation, then checked for remaining files. The runner
records this in `source-export.txt` and the sanitized installed identity. A focused source-isolation regression may include harmless ignored sentinel files: Git status stays clean, but no sentinel may enter the installed Gateway.

Every run creates new credentials, a fresh installed package and a fresh
MariaDB directory. After success or failure, the test namespace exits and
the owned SSH account, database, listeners and private files are removed.
Do not preserve sensitive fixture data for debugging.

The runner prints the actual private sanitized evidence destination under its configured `MIXED_EVIDENCE_DIR`. The hosted workflow reports only explicitly selected sanitized files, not fixture state, tokens, keys or raw HTTP logs.
Review `identity.txt`, `source-export.txt`, `report.json`, `client.json`,
`relay.json`, `oauth-lifecycle.json`, `revoked.txt` and `cleanup.txt` (all owner-readable with private permissions). The report
includes effective Owner settings and finite HTTP limits; the client report
includes actual wire body sizes, SFTP byte size, digest, representative latency and peak SDK memory. The Bridge effective settings are recorded separately in `wp-policy.json`. Repeat the command to prove clean reproducibility.

## Required same-runtime assertions

- Real Gateway readiness, real WordPress discovery and OAuth consent.
- Real installed Bridge execution of a permitted existing read-only Ability.
- Introduce a **new** WordPress mu-plugin native Ability while the
  independent SDK session is already established; rediscover and execute it
  without touching Gateway allowlists. Another provider Ability must deny.
- Compare direct Adapter and routed MCP discovery/results using the same real
  downstream WordPress grant and principal. A disposable native read-only
  Ability hashes 1,000,000 input bytes and reports its WordPress principal;
  both routes must return the exact expected size, SHA-256 and identity.
- Read a complete native Unicode document through source-bound 128 KiB windows
  and verify its SHA-256, completion and wrong-hash continuation rejection.
- Compare native draft creation and updates under the same downstream grant:
  independently observe stored author, draft status and content digest; reject
  stale state and withdrawn Builder permission without changing stored state.
  Enable the necessary Builder permission only in the disposable fixture.
- Qualify the pinned provider's private-transfer input lifecycle (empty and
  multi-window staging, invalid offset, verify, native stored digest, cancel).
  A verified input is not a readable output. Separately create an authorized
  native Media export, reconstruct it through both paths, verify every offset
  and digest, and dispose of the verified export using `cancel`. The pinned
  provider reserves `release` for native-effect receipts; verify that it
  rejects release of an unconsumed verified export. Check actual cleanup.
- Preserve the provider's mixed-effect classification even for its read action:
  an operator without destructive authority must not read or cancel the lease.
  Compare actual decoded MCP response envelopes against 64 KiB default and
  96 KiB fixture Gateway ordinary budgets and the effective provider budget.
  Require exact results within budget and truthful unknown-effect diagnostics
  for over-budget mixed-effect replies, without blind retry or automatic budget
  increases. Verify complete smaller-window reads under both Gateway budgets.
- After Direct capacity and file-transfer checks, register an actual native
  Relay with an independently pinned control host/key and permitted forwarding
  only to the two fixture endpoints. Register a separate Relay SSH Target and
  explicitly bind the existing WordPress Target, revoke its prior disposable
  grant, perform fresh nonce-protected consent and real token exchange. Compare
  same-grant 1,000,000-byte WordPress digest and principal, 512 KiB SFTP exact
  read/write and 512 KiB staged script through Relay. Stop the real SOCKS
  listener: both direct controls stay reachable and selected routes fail,
  without silent fallback. Restart the exact control tunnel, verify and read
  again, then explicitly detach and disable the Relay while retaining the
  new WordPress grant. Report sanitized per-operation byte/latency/route
  evidence. Same temporary Unix account, distinct SSHD/control and Target
  credentials, one private namespace: this is not a production WAN, real
  multi-host throughput, retained Relay Job or offline Admin browser test.
- After the normal installed SDK and file-transfer cases, exercise the actual
  downstream OAuth grant with controlled age shifts of its exact expiry records
  in the disposable provider and Gateway only. No host-clock or provider-code
  change. Verify the real 1-hour access / 30-day refresh lifetime, 15-day idle
  renewal delay, expired direct bearer refusal, one on-demand refresh and two
  successive due renewals through real `schedule:run` child processes. Non-due
  scheduler dispatch must scan/rotate nothing, including when access has expired.
  Preserve grant/route/scope identity and exact native principal; verify consumed
  old refresh records and direct/routed reads with each actual successor.
  Revoke the exact disposable provider refresh artifact and require terminal
  rejection, retained no-replay fence and no later scheduled rotation. Record
  sanitized `oauth-lifecycle.json` and fixture cleanup.
- Verified OpenSSH host key, SSH command, real 512 KiB inline SFTP write/stat/read,
  byte and SHA-256 equality; denied path and cross-Target misuse.
- Independently captured 512 KiB stdout and stderr through real HTTPS MCP,
  truthful truncation when stdout exceeds its window by one byte, and exit 7.
- Measure native SSH exec input at 64 KiB, 131071, 131072 and 512 KiB, with
  the exact output marker after the padding and authentic exit 7. The 64 KiB
  control must pass; larger results are **observations**, not a declaration
  that the selected host supports the configured maximum. A possibly
  dispatched command is never replayed to recover a missing result.
  Confirm a fresh ordinary command still works after the measurement.
- Preserve the separate PHP and Python whole-file transfer proofs.
- Default deny, signed user/Target isolation and ungranted client-profile
  rejection; a previously valid bearer must be rejected after user disable.
- Bounded HTTP deadlines, representative latency, transferred bytes,
  resource use and sanitized diagnostics, with no secrets in evidence.

## Boundaries and review gate

The isolated clients can prove that **their own** authenticated inbound/outbound SSH file bytes are complete; they cannot prove full external OAuth client enrollment, every reverse-proxy/DNS topology, arbitrary third-party host compatibility, arbitrary WordPress-native raw binary transfer or actual ChatGPT model-file ingestion. The provider-private staging and Media export assertions cover the pinned provider's implemented lifecycle, not an arbitrary host file service or every Ability. The near-1 MiB native read-only Ability is not a proof for every mutating Ability, arbitrary request encoding, SSH maximum command input or detached Job script size. The optional manual workflow dispatch with `extended=true` runs the same fixture on two separate disposable runners. With `extended_mode=native` (default), both runs use Direct native exec, retaining the existing 350/360s and 590/600s workload/selected-timeout observations. With `extended_mode=staged`, use the same exact 512 KiB staged script workload and assertions as the short tests, including a 350-second sleep on Direct (360-second timeout) or a 590-second sleep on Relay (600-second timeout), then require verified staging/launch, exact stdout/stderr, exit 7, complete result, measured duration and confirmed temporary cleanup. The extended SDK and PHP worker deadlines are explicitly sized for the selected case; these are fixture choices, not product limits. No long wait occurs in ordinary PR/push validation. The manual staged lane does not repeat the earlier long native workloads. Its evidence identifies route, mode, selected timeout and actual client/Gateway durations. No production setting changes. Host proxy limits, maximum concurrency and actual external client capacity require separate evidence. Use distinct real-host acceptance for those properties.

The OAuth fixture shifts stored expiry records rather than waiting actual days. It proves actual scheduled child-process dispatch and real provider rotation/terminal rejection in this isolated installation, not continuous operator-host Cron, elapsed idle time, or every lost-response/concurrency/recovery scenario. The exact pinned provider contract and targeted regressions cover separate ambiguity paths.

The Gateway source `VERSION` and public release tags must be reported
separately from installed identities; passing tests is not deployment.

Source test/package and independent review requirements belong to [Development](DEVELOPMENT.md), with author and integration authorization handled by the applicable PR and repository gates. Never merge, publish or operate on production solely from these isolated results.
