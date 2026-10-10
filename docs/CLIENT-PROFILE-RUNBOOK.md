# Gateway OAuth client-profile recovery, security and rollout

**Status:** the client-profile implementation from [PR #126](https://github.com/AChWorks/mcp-gateway/pull/126) is integrated and shipped with the [v2.0.0 Target release](https://github.com/AChWorks/mcp-gateway/releases/tag/v2.0.0). The only reviewed preconfigured AI client application is ChatGPT; this does **not** claim support for additional external AI providers. Issue #112 remains open for the wider future WP + Direct SSH acceptance, not as a prerequisite to this already-shipped ChatGPT profile. The authority for Target access remains the Gateway user and Target ACL; an approved AI client application is not an authenticated AI account/workspace and conveys **no** Target, Agent or SSH permission.

## Trust and identity contract

- `client_profile_key` is a local stable security identifier. An exact HTTPS protocol `client_id` belongs to one immutable profile/authentication strategy, never to multiple profiles. Display names can change; provider labels are not policy inputs.
- `config/oauth.php` is the reviewed, explicit allowlist. Production supports the existing ChatGPT CIMD/RS256 `private_key_jwt` path. A reviewed future client may have **pinned**, static redirect URIs and RS256 JWKS; it is not created by arbitrary Dynamic Client Registration. Do not expose client onboarding to request-supplied metadata/JWKS URLs.
- Pinned RSA/RS256 profiles must provide at most 16 public signing JWKs with unique `kid` values, canonical base64url RSA modulus/exponent (`n`/`e`), and at least 2048-bit RSA public keys; private RSA key components are forbidden. Configuration/bootstrap and `gateway:oauth-client-profile check` use the runtime verifier's JWK parser and reject unusable, ambiguous or weak keys before authentication traffic. Do not bypass a failing readiness check by registering an invalid profile.
- Registry database rows bind the immutable profile key, client ID, authentication strategy and monotonically increasing generation. Registration cannot silently revive a disabled entry. Disable increments generation, invalidating existing authorization codes, access and refresh tokens. Explicit re-enable does **not** resurrect those tokens. A new consent is needed.
- The bearer middleware checks the exact current client profile and the persisted authorization's generation on every resource access. It does not fetch remote metadata/JWKS. ChatGPT remote metadata uses exact origin checks, bounded sizes/timeouts and per-document cache locks. Pinned profiles do not fetch metadata.
- Only the Gateway principal/user's permissions, not the client profile name, determine effective Target authority. Any future client-specific permission ceiling must explicitly **narrow** and undergo a separate design/review.

## Install and upgrade (non-production evidence first)

Before migrating an existing deployment, back up and verify the database and OAuth signing keys, deploy code/config as an atomic release, and use a maintenance window for rollback. Never run these commands on production without explicit authorization.

1. Use the existing normal migration workflow to apply the additive OAuth client-profile migration. It creates `oauth_client_profiles`, binds historical ChatGPT `oauth_authorizations` to `chatgpt` generation 1, and adds nullable, safe Activity profile keys. It does **not** change legacy WordPress Site-to-Target migration; that belongs to #107.
2. Confirm reviewed configuration. The default `chatgpt` row is created and backed by the migration. Any later reviewed/pinned profile must be **explicitly registered**; configuring it alone is intentionally insufficient.
3. Perform deployment health: `php artisan gateway:oauth-client-profile check`. This must succeed after DB migration and before enabling traffic. A config profile missing an active registration, unexpected ID/method rebinding, removed-but-not-revoked registration, or no active profile must stop rollout. Also run `php artisan gateway:check` for the existing environment requirements.
4. Run client-specific OAuth/MCP integration and regression checks, including ChatGPT (current compatibility), a separately signed controlled second profile, profile disable/re-enable, exact-grant revoke and reverse-proxy spoof tests. A built-in profile is not necessarily a new supported external vendor: follow an explicit adapter review for each family.

## Read-only discovery and explicit lifecycle

```bash
php artisan gateway:oauth-client-profile list
php artisan gateway:oauth-client-profile check
```

The following mutate persistent authorization state and are **approval-gated operations**, shown only as operator documentation:

```bash
php artisan gateway:oauth-client-profile register <reviewed-profile-key> --confirm
php artisan gateway:oauth-client-profile disable <reviewed-profile-key> --confirm
php artisan gateway:oauth-client-profile enable <reviewed-profile-key> --confirm
```

Disabling a profile makes new consent, exchange, bearer usage, replay recovery and refresh fail closed. Enabling preserves the incremented generation and requires fresh consent/tokens; it is never an undo of revocation. Never repurpose a profile key, client ID or strategy in-place. Revoke a profile durably **before** removing it from the static allowlist.

In Admin, an Owner with `security.manage` may inspect `/admin/oauth-clients` and revoke one exact authorization after entering their current password. Other users may not enumerate clients' authorizations. This does not disable a whole profile or revoke another application's grants. Activity stores a non-secret profile key plus existing hashed client evidence; it never stores client assertions, bearer tokens or private keys.

## Direct ingress and explicit reverse proxy

- **Direct/default:** `GATEWAY_TRUSTED_PROXIES` unset/empty. Rate-limit client IP uses the actual network peer; attacker-controlled `X-Forwarded-For`, `Forwarded` or `X-Forwarded-Host` is ignored for the edge identity.
- **Trusted reverse proxy:** provision `GATEWAY_TRUSTED_PROXIES=192.0.2.10,2001:db8::10` (illustrative only) using only exact IPv4/IPv6 *proxy peers*, never arbitrary `*`, ranges, `REMOTE_ADDR`, or unverified origin. Network ACL/firewall must restrict application origin access to the designated reverse proxy. The proxy must overwrite/sanitize inbound `X-Forwarded-For` and `X-Forwarded-Proto`, and configure a coherent chain if more than one proxy is used. Only these two headers are trusted from configured peers; arbitrary `Forwarded` and `X-Forwarded-Host` do not control rate-limit identity.
- Verify with controlled spoof requests against a non-production instance. Authenticated MCP limiting hashes the exact verified profile + protocol client ID + local Gateway user; labels, IP and User-Agent do not confer privilege or merge all proxy clients into a single authenticated bucket.
- File-cache storage remains the supported default for the single-host deployment. Concurrent Laravel FileStore::increment() updates can lose rate-limit hits, so the Gateway wraps only file-backed limiter counter increments in short per-key locks. The array/other cache drivers retain native behavior. Concurrent metadata cache misses use per-document single-flight locks. A local 6-worker/120-hit measurement saw **83-100** accounted hits before the limiter fix and **120/120** in three runs after it; these are functional checks, not a production throughput benchmark. Continue representative load checks during #112, without making Redis mandatory.

## Recovery and rollback

- **Bad/unknown profile:** `gateway:oauth-client-profile check` fails closed. Review config/registry binding; never repair by force-reusing an immutable key/client ID.
- **Compromised client:** explicitly disable the exact profile and verify fresh/bearer/refresh attempts are denied. Document any re-enable approval separately; all earlier grants stay unusable.
- **Wrong individual grant:** revoke only that authorization from the Owner-only Admin page and verify other client grants remain active.
- **Failed upgrade:** stop traffic, restore **matched** database, code/config and signing-key backups. Reverting only PHP source while leaving the new authorization/profile generation state is not a verified rollback. The migration's `down()` exists for isolated testing, not a promise of safe production rollback after client lifecycle changes.
- **Risk boundaries:** #107's destructive Site-to-Target migration, #110/#111 Agent authorization/approvals, #123 SSH, and #112 multi-client release acceptance are independent gates. No SSH or privileged host operation is authorized by these steps.

## Evidence and test ownership

The merged #117 feature tests use generated ephemeral RS256 keys and an entirely controlled pinned second-client fixture; they do not enroll a real Gemini/Claude provider or infer a remote user's account. They cover code/refresh/bearer binding, Client A/B revocation isolation, generation non-resurrection, Owner authorization UI, bad metadata/duplicate IDs, direct/trusted-proxy spoof controls, and existing ChatGPT flow. The implementation was merged in [PR #126](https://github.com/AChWorks/mcp-gateway/pull/126) and included in the published Target release; retain exact PR/CI/review evidence for later security changes. A controlled second-client fixture is not permission or proof to enroll a real external provider.
