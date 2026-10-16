# Connector integration and durable connection guide

This is the implementer/operator contract for connecting a new Target to MCP Gateway. See [Target foundation](TARGET-CONNECTOR-FOUNDATION.md), [master specification](MASTER-SPEC.md), and [deployment](DEPLOYMENT.md). Live WordPress durability work is tracked in [Gateway #97](https://github.com/AChWorks/mcp-gateway/issues/97) and [WP AI Bridge #92](https://github.com/AChWorks/wp-ai-bridge/issues/92).

## 1. Choose the correct integration boundary

| Scenario | Required path |
| --- | --- |
| New WordPress plugin/theme Ability | Existing WordPress discovery and execution family, governed by caller and remote WordPress permissions; NO new Gateway connector or per-Ability-name allowlist |
| New Target protocol or service | Add a reviewed built-in connector and register its stable connector type; NOT an arbitrary URL or dynamic PHP class |
| A different AI/MCP client accessing Gateway | Existing client-neutral MCP endpoint, authenticated client profile, authorized Target selection and permissions; NOT a separate client-specific Gateway |
| Existing SSH password/key server | The ssh_direct connector with verified pinned server host key; NO OAuth token-rotation scheduler |
| A new downstream MCP-over-HTTPS service | Connector-owned credential/lifecycle and shared HTTP MCP transport where appropriate; WordPress-specific OAuth is not a universal requirement |

Current source connector types are declared in app/Application/Targets/TargetConnectorRegistry.php. Only `wp_ai_bridge` and `ssh_direct` are supported built-in connector types; unsupported stored types are rejected for registration, inventory filters and execution. An architecture entry does not mean a released or deployed capability.

## 2. Implement an integrated Target connector

1. Choose one immutable Gateway Target record identity, a stable connector type and display label. Store changeable remote URL/IP, principal, certificate/host key and authentication details behind the connector; do not add connector-specific fields to the shared Target row without evidence.
2. Implement App\Application\Targets\TargetConnectorAdapter: type, registrationRules, safeOldInputFields, register, registrationStatus, connect, reconnect, disconnect, test, adminDetails, publicMetadata and hasPendingDeletion. The first two real examples are WpAiBridgeTargetAdapter and SshDirectTargetAdapter.
3. Register the actual adapter in TargetConnectorRegistry::IMPLEMENTED. Shared Admin/UI/MCP inventory, user/client/Target access and immutable Target identity remain Gateway-owned. Unsupported connector types must reject safely. Credentials and private endpoint details must not appear in user-flashed old form input, API inventory, logs or Activity.
4. Expose only the adapter's supported tool/capability families. Every request names the authorized Target; also check the actual downstream user/principal and operation. Do not create tool definitions per Target, duplicate generic transport, impersonate ChatGPT or add per-client special authorization rules.
5. State the connector's remote discovery, protocol negotiation, authentication and test semantics. Add credential maintenance only when the connector truly supports renewable credentials; never require an OAuth issuer/refresh URL for an SSH or named-token Target.
6. Provide source-level, independent review/CI, exact released-artifact and installed-environment evidence independently before advertising feature availability.

## 3. Connection lifetime, authentication and Stale health

A connection is a stored, authorized relationship, not a permanently open socket. These facts are independent:

| Status or event | Correct meaning |
| --- | --- |
| Connected | Bound credential/authorization has not been confirmed terminal; does NOT assert current remote availability |
| Stale | Time since the last proven authenticated healthy operation exceeded the health threshold; must NOT revoke/delete/reconnect credentials |
| Access-token expiration | Only a short-lived bearer expired; a valid offline grant may transparently renew it when needed |
| Refresh-token expiration | This specific rotating offline credential has a provider-limited lifetime; the required renewal path must act before this deadline |
| DNS failure, connection reset, timeout or 5xx | Operational failure; not proof the user revoked consent or an old rotating refresh token is safe to replay |
| Confirmed invalid/revoked grant, lost user capability, changed binding | Potential terminal authorization condition; fail closed and explain the actual recovery requirement |

**Product requirement:** A previously authorized, renewable connection remains usable through days/months of inactivity, including old Stale health evidence, **provided the remote grant remains valid and required host-side bounded refresh maintenance is running**. The next operation should resume without interactive WordPress sign-in or new Gateway registration. With finite refresh credentials and no running maintenance process, unbounded inactivity past the refresh lifetime cannot be promised. Never substitute non-expiring bearer tokens to conceal that prerequisite.

## 4. Provider OAuth: only if this connector supports it

- Establish initial OAuth client identity, exact issuer/resource/redirect URI, PKCE, allowed scope and client authentication. The WP AI Bridge-approved Gateway uses HTTPS Client ID Metadata Document, JWKS RS256 private_key_jwt, PKCE S256 and mcp:use plus offline_access. Never reuse another client's identity.
- Persist rotating credentials encrypted and bound to immutable Target record identity, connector purpose/version, client, issuer/resource and authorized scope/principal. WordPress browser logout is NOT offline OAuth revocation.
- Prefer short access tokens and finite rotating refresh tokens. For current WP Bridge, access TTL is one hour and refresh TTL is 30 days. Access TTL must not control the IDLE proactive rotation cadence. When an access token expires during a real operation, renew it on demand. When idle, schedule well ahead of the refresh token's OWN advertised expiry using the current most recent refresh_token_expires_in (e.g. half of refresh lifetime), recalculating after every rotation. Without that hint, fall back conservatively; do not pretend refresh grants never expire.
- Connector-specific maintenance must be bounded, query due credentials only, have a functioning deployment scheduler, and require neither active Admin browser nor per-Target always-on worker. Do not send network I/O under a DB transaction or run remote refresh every 30 minutes simply because an access token lasts an hour while offline grant lasts weeks.
- Do not infer grant revocation from HTTP status alone. The pinned WordPress Bridge can return HTTP 400 invalid_client on transient approved-client metadata/JWKS outages BEFORE consuming any refresh token; keep the exact encrypted credential and reconnect-free logical authorization, clear only the initial generation-fenced intent, and defer a subsequent retry by a bounded interval. Do not retry immediately on every MCP call; pending outage is not permission to use an expired access bearer. If an initial request's outcome was already ambiguous, a later invalid_client cannot prove that the first rotation failed: retain the unresolved fence. Bridge also uses HTTP 400 temporarily_unavailable at multiple phases including possible recovery-after-consumption, so treat it as an uncertain outcome, never as proof of a reusable old token. Explicit invalid_grant and rejected scope/resource binding remain terminal. The 60-second provider recovery budget is not an Admin-tunable login extension.
- A successful provider rotation can commit before its response reaches Gateway. Persist a target/credential/generation-bound intent before the attempt. Apply ONLY provider-authorized exact old-token recovery under a fresh, same-client/resource/scope assertion and finite window. WP Bridge currently permits one single-use recovery within 60 seconds; no third replay, arbitrary retry, or grace beyond the provider guarantee. See [Bridge #92](https://github.com/AChWorks/wp-ai-bridge/issues/92) for evaluation of more durable provider recovery.
- Terminal revoked/invalid user, approval, issuer, resource, client or scope must fail closed. A provider outage, Stale evidence, WordPress logout or one missing HTTP response must not itself erase a grant. Conversely, never falsely claim an unknown rotation succeeded. Local credential forgetting and confirmed remote revocation are different actions; Owner attestation is not an automatic "Refresh" action.

## 5. Security, scale, performance and diagnostics

- Connector transport must enforce its own approved egress identity: public HTTPS origin and redirect/DNS restrictions for MCP, or pinned authenticated host key and approved TCP egress for SSH. No attacker-selected arbitrary destination or cross-Target secret reuse.
- Use the prepare-under-short-lock, remote-call-outside-lock, conditional-finalize pattern with generation/intent/time fences. Preserve behavior under concurrent requests, revoked authorization, crashed workers and lost DB sessions; do not blindly retry a mutation with unknown remote outcome.
- Separate current connection authorization from health timestamps. Show accurate bounded diagnostic categories: temporary/unreachable, terminal authorization, uncertain refresh outcome, permission denied, incompatible service. Log correlation and safe failure status only; never tokens, signed assertions, passwords, raw upstream response body or sensitive personal data.
- Work scales with ACTUALLY due credentials, not the count of all registered Targets. Do not register one timer, daemon or background heartbeat per Target or incorrectly poll SSH named credentials. Prefer the existing shared MCP runtime, response ceilings, and [remote I/O design](REMOTE-IO-CONTRACT.md) where relevant.
- Confirm deployed scheduler and operation: the Laravel schedule includes gateway:wordpress-credentials-maintain and the host must invoke artisan schedule:run every minute. Use php artisan schedule:list for read-only inspection; presence in source is NOT proof host cron ran. Diagnose request-failure timing/HTTP status and scheduler last execution without leaking secrets.

## 6. Representative acceptance before claiming compatibility

- [ ] One owner-approved connection remains Connected as health becomes Stale; authenticated read after long idle resumes transparently without new consent while the grant remains valid.
- [ ] Short access expiry renews on demand; no unnecessary half-hour idle rotation for a 30-day refresh token.
- [ ] Simulated idleness beyond a refresh-token TTL remains recoverable WITH a correctly functioning bounded maintenance scheduler; absent cron has an actionable, truthful operator diagnostic.
- [ ] Actual logout does not revoke an offline grant, but genuine remote revocation, deleted user/role, invalid client, changed issuer/resource/scope or expired unrenewable grant fails closed.
- [ ] Lost refresh response and transient network errors get only provider-approved, single-use, bounded recovery; exhausted and terminal cases do not duplicate rotations or silently destroy authorization.
- [ ] Cross-Target, cross-user, cross-client and wrong-resource/host assertions fail; no secret or private URL leakage.
- [ ] Test parallel refresh/revoke, crashes, recovery deadlines, old-bearer renewals, Stale presentation and one real isolated authenticated Target end-to-end check. Mark mocked, source, released and installed results distinctly.
- [ ] Security-sensitive change receives independent exact-diff review, required exact-candidate CI and separate owner merge/release gates.

This is the implemented-connector guide, not permission to register unimplemented protocol services or promise mathematically permanent authorization without a renewable trust contract.
