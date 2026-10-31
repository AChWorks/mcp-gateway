# Downstream MCP wire transport (first bounded source slice)

Status: **source-level primitive only** (Issue [#257](https://github.com/AChWorks/mcp-gateway/issues/257)). This does not register a new Target connector, enroll an external endpoint, create a product-linked user account, add Admin UI, expose an inbound Gateway MCP tool, or establish a production installation. The existing `wp_ai_bridge` (session-oriented, provider-specific Ability wrapper) and `ssh_direct` connectors are unchanged.

## Verified contract and supported subset

The first implementation is `App\Infrastructure\Mcp\RequestOnlyMcpClient`, with a short-lived `BoundMcpTarget` holding the owning, persisted Gateway Target identity, explicit HTTPS resource URL, and the actual product-bound downstream bearer provided by an owning connector. The initial supported wire profile is **request-only, stateless Streamable HTTP 2026-07-28** from the existing [AChrix Bridge contract](https://github.com/AChWorks/achrix/blob/main/bridge/README.md), tested upstream through its [contract suite](https://github.com/AChWorks/achrix/blob/main/bridge/contract_test.go) and the official Go SDK v1.8.0.

- One JSON-RPC object per HTTPS POST; `Accept: application/json, text/event-stream`, `Mcp-Protocol-Version`, `Mcp-Method`, and matching `Mcp-Name` for calls.
- Per-request `params._meta` identifies protocol version, client capabilities and client information. `server/discover` verifies the supported version, followed by one bounded `tools/list` page and a single `tools/call`.
- Modern results must be JSON, match the request ID, carry `resultType: complete`, and have no `Mcp-Session-Id`. Discovery/catalog additionally require `cacheScope` and nonnegative integer `ttlMs`; tool calls require a valid `content` list and may return any JSON `structuredContent` value, including a scalar or null. `input_required` and other unsupported incomplete profiles fail conservatively with UNKNOWN after dispatch, never as successful writes. No GET/SSE session, subscription, idle heartbeat, scheduled worker, automatic negotiation fallback, or implicit response/event replay.
- The existing shared `SafeHttpClient` owns HTTPS-only canonical egress, public-IP DNS pinning, TLS validation, no redirects, response collection, runtime deadlines, and connection-failure classification. Additional transport-local limits: 64 KiB request JSON, 1 MiB requested response, 128 tools per catalog page, 256-byte cursor and 128-byte ASCII tool name.
- An unfamiliar compatible tool name is **not** an implicit authorization denial. It still requires the provider's actual schema, the Gateway's effective user/Target/client/action grant, any required mutation classification, and the owning product's current policy.
- Input validation and local Target mismatch/pause are `not_executed`. For a remotely dispatched effectful request with a lost or malformed response, HTTP error or uncertain transport: **`unknown`**, no automatic replay. A verified AChrix Bridge tool fault may carry its explicit `not_executed`, `not_committed`, `succeeded`, or `unknown` outcome and authorized reference. Gateway must preserve safe failure code, phase, trace/correlation and a protected underlying cause. All downstream-supplied diagnostic fields (including reference, request ID and `X-Request-ID`) are checked for direct bearer echoes; matching identifiers are dropped rather than exposing credentials.

**Not currently supported in this new library:** the separate **2025-11-25** legacy initialization handshake (the upstream AChrix Bridge supports it); sessionful/older WordPress semantics; generic SSE streaming; provider OAuth/grant issuance, storage, credential refresh or revocation; arbitrary URLs or generic Target registration; domain operation routing from human/Admin or inbound AI. No implication of current integration or end-to-end client compatibility.

## Ownership and boundaries for the next integration

1. The code-owned registered Target adapter must resolve its immutable Target-to-verified-endpoint association and actual, authorized **product user + client + resource + site** credential. This library accepts those **trusted internal parameters**, not an Admin/AI-supplied URL, claimed actor or generic Gateway access token. Binding construction is **not** proof of authorization by itself. Reject mismatched endpoint/issuer, resource/audience, changed grants, disabled channel, and unauthorized operation before use.
2. Continue to run the shared Gateway user/Group/Target/client access checks and fresh Target pause/revocation gates. No cache can borrow a session or token from a different user/Target/product/site. The product is final authority for current business permissions; discovery annotations are never grants.
3. A connector should own protocol-specific compatibility, credential rotation and protected diagnostic retention, and should expose one reviewed shared application operation service for both a human and an AI caller. Provider-fixed operation names can be dynamically discovered subject to the existing broad/restricted delegation contract; there is no permission to auto-enroll unknown endpoints.
4. Run a **real isolated bridge HTTP conformance fixture** (both authenticated 2026 and separately verified 2025 versions), wrong-resource grants, input/schema failures, cross-user impersonation, remote revocation, lost write acknowledgements, and WordPress/SSH regressions before activating a built-in connector. The current Laravel HTTP fake tests only validate local wire construction, transport boundaries and controlled failure behavior; they are not a real Go Bridge interoperability pass.
5. AChrix [#5](https://github.com/AChWorks/achrix/issues/5), Rixa [#49](https://github.com/AChWorks/rixa/issues/49), Gateway [#86](https://github.com/AChWorks/mcp-gateway/issues/86) own the separate actual product-user linking, OAuth, application authority and reconciliation acceptance. They are **not delivered by this transport slice**.

## Local validation

```bash
php artisan test --filter=RequestOnlyDownstreamMcpTest
php artisan test --filter=WordpressTargetMcpRegressionTest
php artisan test --filter=SshCommandMcpTest
php vendor/bin/pint --test
```

Source, CI and independent review are separate from any installed-host or release acceptance. No change to `v2.5.1` and no Production action is authorized by this document.
