# Installed mixed WordPress + Direct SSH acceptance

Controlling issue: #112. Companion protocol/permission fixture:
`tests/Feature/Mcp/MixedTargetAuthenticatedAcceptanceTest.php`. That fixture
remains synthetic for WordPress; **it does not substitute for this test**.

## Scope and containment

The installed runner starts one fresh MariaDB on a private Unix socket,
one installed Gateway copy with real migrations and generated OAuth keys,
one installed WordPress 6.9 with real WP AI Bridge and MCP Adapter,
and one real host-key-pinned OpenSSH/SFTP server. A separate PHP process
loads the official MCP SDK without booting the Laravel application and calls
the actual Gateway HTTPS `/mcp` endpoint.

The runner uses a private Linux network namespace with addresses
`11.22.33.44` (WordPress), `11.22.33.45` (Gateway) and `11.22.33.46`
(OpenSSH). These public-looking addresses exist **only in that disposable
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
96 KiB normal and 512 KiB readonly), distinct from the disposable
configuration fallback. The fixed 8 MiB body bound remains enforced.
No production account, web property, server listener, credential or SSRF
policy is changed. Do not run on user-owned/production sites.

## Running on the disposable agent worker

Prerequisites: root authorization for `unshare` and a temporary Unix SSH
account, PHP 8.4 plus Composer dependencies, MariaDB, OpenSSH, `socat`,
`ip`, `openssl`, `runuser`, WP-CLI, and a compatible Linux kernel.

The default disposable agent inputs are the official WordPress 6.9 archive,
WP-CLI v2.12.0 PHAR, WordPress MCP Adapter v0.7.0 **release ZIP**, and WP AI
Bridge v0.5.1 **release ZIP**. The two existing archive/PHAR inputs and Adapter
ZIP are under `/srv/ai-workspace/wpai-r004-agent-runtime/downloads`. The
verified Bridge release ZIP is under
`/srv/ai-workspace/mcp-gateway-acceptance-20261012/inputs/wp-ai-bridge-0.5.1.zip`.
These are read-only **input artifacts**, never a previously installed plugin
folder. The Bridge ZIP can be obtained from the immutable [v0.5.1 release](https://github.com/AChWorks/wp-ai-bridge/releases/tag/v0.5.1)
and Adapter ZIP from [v0.7.0](https://github.com/WordPress/mcp-adapter/releases/tag/v0.7.0).
WordPress core is from the [official 6.9 archive](https://wordpress.org/download/releases/)
and WP-CLI from [v2.12.0](https://github.com/wp-cli/wp-cli/releases/tag/v2.12.0).

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

The runner accepts optional read-only fixture input paths (defaults are
current disposable agent artifact locators, never modified in place):

| Environment variable | Expected source artifact |
| --- | --- |
| `MIXED_WORDPRESS_ARCHIVE` | Pinned official WordPress 6.9 `.tar.gz` |
| `MIXED_WP_CLI_PHAR` | Pinned WP-CLI v2.12.0 `.phar` |
| `MIXED_WP_BRIDGE_ARCHIVE` | Pinned WP AI Bridge v0.5.1 release ZIP |
| `MIXED_MCP_ADAPTER_ARCHIVE` | Pinned MCP Adapter v0.7.0 release ZIP |
| `MIXED_EVIDENCE_DIR` | writable private evidence destination |

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
included. Composer dependencies are freshly installed against the committed
`composer.lock` in the isolated target, never copied from checkout `vendor`.
All writable `storage` paths and `bootstrap/cache` are re-created **empty**
after dependency installation, then checked for remaining files. The runner
records this in `source-export.txt` and the sanitized installed identity. For
R1 verification, run with harmless ignored sentinel files in the source
checkout: Git status remains clean but no sentinel can enter the installed
Gateway (no retained source runtime content is permitted).

Every run creates new credentials, a fresh installed package and a fresh
MariaDB directory. After success or failure, the test namespace exits and
the owned SSH account, database, listeners and private files are removed.
Do not preserve sensitive fixture data for debugging.

The runner prints the path to sanitized evidence files under
`/srv/ai-workspace/mcp-gateway-acceptance-20261012/real-installed-mixed-112-*`.
Review `identity.txt`, `source-export.txt`, `report.json`, `client.json`,
`revoked.txt` and `cleanup.txt` (all owner-readable with private permissions). The report
includes effective Owner settings and finite HTTP limits; the client report
includes SFTP byte size, digest, representative latency and peak SDK
memory. Repeat the command to prove clean reproducibility.

## Required same-runtime assertions

- Real Gateway readiness, real WordPress discovery and OAuth consent.
- Real installed Bridge execution of a permitted existing read-only Ability.
- Introduce a **new** WordPress mu-plugin native Ability while the
  independent SDK session is already established; rediscover and execute it
  without touching Gateway allowlists. Another provider Ability must deny.
- Verified OpenSSH host key, SSH command, real SFTP write/stat/read,
  byte and SHA-256 equality; denied path and cross-Target misuse.
- Default deny, signed user/Target isolation and ungranted client-profile
  rejection; a previously valid bearer must be rejected after user disable.
- Bounded HTTP deadlines, representative latency, transferred bytes,
  resource use and sanitized diagnostics, with no secrets in evidence.

## Boundaries and review gate

This proves the actual PHP MCP SDK over HTTPS, **not** a complete external
Gateway client onboarding flow, installed hostname DNS-rebinding handling
(the test uses public-looking numeric namespace IPs), ChatGPT runtime
compatibility, arbitrary clients, client-visible bidirectional file delivery
(#147) or speculative one-hour streaming. #97 retains long-idle/deployed
OAuth acceptance; #154 retains effective-limit/client compatibility evidence.
The Gateway source `VERSION` and public release tags must be reported
separately from installed identities; passing tests is not deployment.

After installed acceptance: run the relevant complete PHP suite, Pint,
PHPStan, MariaDB tests and exact-candidate CI. Independently review the
full effective PR diff. Request one fresh author-separated HIGH_ASSURANCE
review only once the complete deliverable is stable. Do not merge/publish
without an explicit Owner gate.
