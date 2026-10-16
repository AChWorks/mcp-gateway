# OAuth client profiles — security and recovery

**Audience:** the Gateway deployment operator and developers working on client authentication. Client profiles identify a **reviewed authenticated application**, not an AI provider account, a connected Target or an execution permission. The exact local Gateway user's role, Target scope and downstream principal continue to govern every operation.

## Client identity and protocol trust

The client-facing MCP edge implements an exact protected resource and OAuth authorization-server relationship:

- `/.well-known/oauth-protected-resource/mcp` and `/.well-known/oauth-authorization-server` identify the same canonical HTTPS resource/issuer;
- authorization-code consent uses S256 PKCE, validated redirect/client/resource binding, issuer (`iss`) validation, rate limits and replay controls;
- tokens/refresh/revocation are bound to the exact authenticated client profile, immutable protocol `client_id` and current profile generation;
- a public client display name, IP address, User-Agent or provider label is **not** user/Target identity.

A stable `client_profile_key` is local security identity. Exactly one reviewed profile may own a particular protocol `client_id`. A client profile describes an explicit authentication strategy, not a whitelist of WordPress Abilities or other Target operation names. A compatible Target-side operation change does not require a new OAuth profile, while a genuinely new client authentication strategy needs explicit review.

[`config/oauth.php`](../config/oauth.php) is the static reviewed registry; arbitrary Dynamic Client Registration, user-supplied JWKS URLs and unbounded remote metadata fetching are not substitutes. Supported ChatGPT identity uses approved CIMD with RS256 `private_key_jwt`, exact-origin remote metadata validation, bounded fetch/cache and protocol JWT verification. **Actual installed configuration controls enabled profiles**; a controlled test identity is not support for an external provider.

For deliberately pinned public-key profiles, require the runtime verifier's valid canonical RS256 JWK rules: no more than 16 keys, unique `kid`, public RSA modulus/exponent without private components, and 2048-bit minimum RSA keys. Registry rows bind stable profile key, client ID, auth strategy and monotonically increasing generation; the registration cannot silently resurrect an intentionally disabled identity.

Bearer middleware validates the persisted authorization/client generation at resource access. Profile disable increments generation and invalidates existing codes, grants, bearer and refresh tokens. **Re-enable requires fresh consent**; it never revives old tokens. Remote metadata retrieval does not occur on every bearer request.

## Safe deployment checks

Before any approved client-profile upgrade, verify the installed build, backed-up database/config/signing keys, intended migration and exact approved client identities. Code and DB generation state must be restored together if rollback becomes necessary; rolling back only PHP files is not a secure grant rollback.

Read-only discovery and validation:

```bash
php artisan gateway:oauth-client-profile list
php artisan gateway:oauth-client-profile check
php artisan gateway:check
```

A missing active profile, duplicated client IDs, wrong method/ID binding, bad pinned JWK, or disabled/removed identity that was not correctly retired is a **readiness failure**. Resolve using the actual registry/configuration—not a synthetic replacement profile or copied signing key.

Explicit operator-approved state changes (never run just for a test):

```bash
php artisan gateway:oauth-client-profile register <reviewed-profile-key> --confirm
php artisan gateway:oauth-client-profile disable <reviewed-profile-key> --confirm
php artisan gateway:oauth-client-profile enable <reviewed-profile-key> --confirm
```

To retire a reviewed profile, durably disable/revoke its credentials/grants **before** removing the static allowlist entry. Never reuse an immutable profile key for another client or authentication scheme. A new supported external vendor needs real protocol/identity compatibility validation, not merely a registered test profile.

Owners holding `security.manage` may inspect `/admin/oauth-clients` and revoke **one exact** authorization with current-password confirmation. That is different from disabling an entire profile. Unprivileged users cannot enumerate another application's authorizations; Activity includes only bounded non-secret client-profile identity, not JWT assertions, bearer tokens or keys.

## Reverse-proxy trust and rate limits

**Direct connection:** leave `GATEWAY_TRUSTED_PROXIES` unset unless an actual trusted reverse proxy is deployed. The Gateway uses the real network peer for edge limits and must not let caller-supplied `X-Forwarded-For`, `Forwarded` or `X-Forwarded-Host` spoof authenticated source identity.

**Explicit trusted proxy:** set the reviewed exact IPv4/IPv6 proxy peer addresses only, for example:

```dotenv
# Example only: actual trusted proxy network peers, not clients
GATEWAY_TRUSTED_PROXIES=192.0.2.10,2001:db8::10
```

Restrict direct origin access to those proxies, and require them to sanitize/overwrite inbound `X-Forwarded-For` and `X-Forwarded-Proto`. Never trust a blanket wildcard/range, arbitrary `REMOTE_ADDR`, `Forwarded` or `X-Forwarded-Host` as an authorization shortcut. Validate bypass/spoofing against an isolated, approved environment before production enablement.

Authenticated MCP rate-limit identity derives from verified client profile, exact protocol client ID and Gateway principal; display labels and arbitrary IP headers grant no additional rights. The single-host file-backed cache uses short per-key locks for limiter counters where necessary, while other cache drivers retain their own documented behaviors. No Redis requirement follows merely from a trusted-proxy deployment.

## Failure and recovery

- **Unexpected profile/authentication failure:** use the read-only check, known client identity/configuration and bounded server-side diagnostic evidence. Do not turn off client signature, origin or issuer validation to obtain a green health result.
- **Compromised client:** explicitly disable the exact profile, confirm its code/bearer/refresh paths fail closed, and require independently approved fresh enrollment/consent for replacement.
- **Wrong individual grant:** revoke only that authorization; verify other client profiles and Target grants remain unaffected.
- **Ambiguous upgrade or partial database state:** stop mutation, preserve private keys and state, and recover from matching verified database/code/config backups. Do not force an older PHP binary to interpret a newer client-generation state.
- **Target credential problems:** WordPress/SSH downstream credentials have their **own** lifecycle; client profile re-enrollment alone is not Target reauthorization or recovery.

Regression validation must distinguish profile identity isolation, JWT/JWKS quality, grant binding, two independent clients, generation revocation, reverse-proxy spoof resistance, valid Token/PKCE flows and preserved Target-scoped permissions. Record whether evidence came from source tests, a controlled external client, a published artifact or the actual installed environment, without making a second history report in this runbook.
