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
provider** (absent from actual production boot), with one approved identity, one revoked signed identity,
and one enabled never-granted identity (whose bearer issuance must fail). WordPress registers the Gateway's real
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

The server currently has read-only source-artifact locators under
`/srv/ai-workspace/wpai-r004-agent-runtime`: WordPress 6.9 tarball,
WP-CLI PHAR, installed Bridge and MCP Adapter directories. The runner
copies the artifacts into an isolated installation. **Confirm existence
and ownership of these inputs; never mutate the old fixture.**

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
| `MIXED_WORDPRESS_ARCHIVE` | WordPress `.tar.gz` installation archive |
| `MIXED_WP_CLI_PHAR` | WP-CLI executable `.phar` |
| `MIXED_WP_BRIDGE_PLUGIN_DIR` | unpacked `wp-ai-bridge` plugin directory |
| `MIXED_MCP_ADAPTER_PLUGIN_DIR` | unpacked `mcp-adapter` plugin directory |
| `MIXED_EVIDENCE_DIR` | writable evidence destination (no secret fixture data) |

Supply equivalent **trusted, verified** local artifacts when the default
historical fixture is unavailable. The acceptance is only valid for the
versions recorded in its actual `identity.txt`, not every future WordPress
or MCP Adapter combination. The previously observed interoperability defect
was a missing required JSON-object `capabilities` field in the downstream MCP
`initialize` request; the real Adapter rejects that malformed request,
whereas an older HTTP mock silently accepted it. A source regression test
now asserts the exact object shape.

Every run creates new credentials, a fresh installed package and a fresh
MariaDB directory. After success or failure, the test namespace exits and
the owned SSH account, database, listeners and private files are removed.
Do not preserve sensitive fixture data for debugging.

The runner prints the path to sanitized evidence files under
`/srv/ai-workspace/mcp-gateway-acceptance-20261012/real-installed-mixed-112-*`.
Review `identity.txt`, `report.json`, `client.json`, `revoked.txt` and
`cleanup.txt` (all owner-readable with private permissions). The report
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

This proves the actual PHP MCP SDK over HTTPS, **not** ChatGPT runtime
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
