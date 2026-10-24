# OAuth client registration: CIMD and DCR

**Purpose:** ChatGPT-to-Gateway OAuth client registration and recovery. This does not change WordPress/Target OAuth, Agent access, or Gateway tool permissions. The current GitHub source/release and installed host are distinct; this guide does not authorize production changes.

## Parallel client strategies

Both modes share the exact Gateway resource, OAuth authorization-code + PKCE S256, human sign-in and consent, authorization store, token issuance, refresh rotation, permission checks, and token revocation. They differ **only in how the OAuth application identifies and authenticates itself**.

| Method | Identity and discovery | Token and revocation authentication | External ChatGPT metadata dependency |
| --- | --- | --- | --- |
| CIMD | Prior fixed ChatGPT metadata URL; stable configured profile | RSA/RS256 private_key_jwt with exact audience, expiry, key ID and anti-replay; published JWKS | Required on cache miss and key rotation |
| DCR | Public, bounded registration endpoint; fresh durable immutable client and profile | Per-client high-entropy secret through client_secret_post, stored as one-way digest | None for subsequent token exchanges |

Every DCR registration gets its own stored client ID, profile key and credential. No new registration inherits existing CIMD permissions, access, refresh tokens or Target access. Existing CIMD connections remain valid when their original metadata/JWKS and token state are valid.

DCR registration permits only approved HTTPS ChatGPT callback forms, authorization_code and refresh_token grants, and fixed server-side client labeling. The callback must match exactly on consent and exchange. Untrusted client-provided names are not trusted as display identity. Runtime access to Gateway data still requires a separately granted Gateway user's AI access and consent.

Public registration is explicitly opt-in and **does not require a logged-in Gateway administrator or an approved OAuth consent**. The initial DCR registration and its durable client ID/secret happen *before* the human Login/Consent flow; registration alone never grants MCP/Target access. This is required for the automatic ChatGPT DCR handshake and is not evidence of an authorized connection.

Registration has three distinct defenses: **5 incoming requests/minute/IP** (including invalid requests); **15 successful new registrations/hour across the whole Gateway**, under the serialized MariaDB admission lock (invalid metadata does not consume this global success quota); and a **512-unretired-client ceiling**. Global success quota returns HTTP 429 with Retry-After, while full capacity without reclaimable slots returns 503. Existing DCR clients and refresh traffic are not subject to *new registration* admission limits.

At the 512-client boundary, a new registration attempts **bounded automatic retirement of the oldest never-authorized DCR clients at least 24 hours old** (up to eight per admission). This checks that *no authorization has ever existed*, including revoked grants, and rechecks against in-flight consent under the same durable profile/DCR locks used by OAuth approval. Each retired client stays permanently disabled and its identity/secret digest/history remain stored; nothing is deleted. **Every DCR client that ever gained consent is excluded, even if its grant was later revoked.** New clients that have not completed consent and are younger than 24 hours are retained; a user who leaves a DCR flow unfinished beyond that grace and encounters real capacity pressure may need to start a fresh registration. This is capacity-pressure recovery, **not** an unconditional expiry timer.

Keeping anonymous registration permanently open still lets an adversary consume the public hourly allowance, consume database tombstone space over time, or temporarily exhaust capacity; a public RFC-compliant DCR endpoint cannot prove the registering party owns a Gateway account. Keep registration closed outside planned onboarding where practical; monitor registrations and apply host/edge ingress protections. Previously registered clients remain usable after registration closes. Never relax cryptographic checks to bypass a metadata outage.

## Configuration

| Key | New-install default | Meaning |
| --- | --- | --- |
| OAUTH_DCR_REGISTRATION_ENABLED | false | Include and enable the registration endpoint for new ChatGPT DCR clients when true |
| OAUTH_CHATGPT_CIMD_ADVERTISE | true | Advertise fixed CIMD registration for new connections; setting false leaves old CIMD identities and credentials intact |
| OAUTH_ACCESS_TOKEN_TTL_SECONDS | 3600 | One-hour short-lived bearer token |
| OAUTH_REFRESH_TOKEN_TTL_SECONDS | 15552000 | 180-day rotating refresh token **new issuance** lifetime |

The existing private installed .env **is not automatically rewritten** by an update. Changes to these values do not extend old tokens retroactively. Each successful refresh rotation issues a new refresh token whose expiry is relative to that issuance time, so ordinary continued use renews authorization without forcing repeat consent. A connection unused beyond the effective refresh expiration still must reauthorize. The 180-day refresh lifetime does not turn the bearer Access Token into a six-month credential.

## Safe recovery when OpenAI CIMD/JWKS returns 404

1. Verify and retain the installed release identity. Preserve and back up the private .env, APP_KEY, signing keys, database and existing grants. Apply only a separately independently-reviewed release through the existing updater. The additive DCR migration must succeed before any registration can run.
2. After deployment, edit only these keys in the private installed .env:

   ~~~dotenv
   OAUTH_DCR_REGISTRATION_ENABLED=true
   OAUTH_CHATGPT_CIMD_ADVERTISE=false
   OAUTH_REFRESH_TOKEN_TTL_SECONDS=15552000
   ~~~

   Reload the existing PHP/Laravel configuration and run the documented Gateway health/preflight check as the application user; never reveal secrets in tickets or chat.
3. Read-only verify OAuth authorization-server metadata advertises a canonical HTTPS registration_endpoint, code_challenge_methods_supported including S256, **both** token and revocation endpoint auth methods including client_secret_post and private_key_jwt, and client_id_metadata_document_supported set false. RSA RS256 signing remains advertised for private_key_jwt; protected resource issuer/resource must not change.
4. In the ChatGPT custom-plugin creation flow, **create a new connection and explicitly choose DCR**. The previous CIMD connection cannot be repaired just by clicking Reconnect or swapping identities. Do not paste registration secrets anywhere; ChatGPT stores the returned client secret for that exact connection.
5. Complete Gateway account login/AI access consent. Verify tool discovery, an authorized read-only MCP call, then a fresh token refresh through the DCR client. Correlate any failure with the Gateway Activity correlation ID. Distinguish real ChatGPT client behavior from mocked automated test results.
6. After the DCR client is registered, closing public registration (setting OAUTH_DCR_REGISTRATION_ENABLED=false) **does not invalidate** that existing client or its refresh tokens. CIMD advertising can be restored later without migrating identities.

## Client lifecycle, permissions and rollback

- Admin → AI clients shows configured profiles and **50 DCR client profiles per page** (newest first); filter by the exact profile key to locate older entries. The read-only gateway:oauth-client-profile list command also reports registered DCR profiles. Neither view shows plaintext secrets.
- `gateway:oauth-client-profile disable EXACT_DCR_PROFILE_KEY --confirm` invalidates prior grants through the stored generation. Disabled DCR identities cannot be re-enabled. The client needs a **new registration** to reconnect.
- At capacity, **automatic retirement applies only to never-authorized registrations older than 24 hours**; it does not delete records, retire ever-authorized identities or replace the following explicit Owner procedure. To retire a truly unused client not eligible for the automatic no-consent path, or to reclaim a slot manually, use the security-reviewed steps below:
  1. Run `gateway:oauth-client-profile list` as the authorized application operator. Locate the exact immutable `dcr_...` **profile key**, distinguish it from the client ID, and verify the client is no longer needed.
  2. Run `gateway:oauth-client-profile disable EXACT_DCR_PROFILE_KEY --confirm`. This invalidates its profile generation and is not reversible for DCR.
  3. In **Admin -> AI clients**, filter by that profile key; if any consent remains unrevoked, revoke each separately with Owner password confirmation. Do not delete OAuth code/refresh/access/recovery records manually.
  4. Run `gateway:oauth-client-profile retire EXACT_DCR_PROFILE_KEY --confirm`. The command refuses if the profile is not disabled, any authorization remains unrevoked or identity is inconsistent. The same MariaDB anchor lock serializes public registration with retirement.
  5. Repeat `gateway:oauth-client-profile list` and verify the status `retired (permanent)`. The original client ID, secret verifier, generation, revoked grants and token/recovery histories remain stored; only `retired_at` changes. The 512 **unretired** occupancy falls by one. A new registration creates a new random ID/profile/secret. Never recycle a retired identity.
- Pending OAuth consent is also serialized against disable/retirement: approval takes the current durable profile row lock (and the corresponding DCR registration lock), then rechecks exact client identity, method, generation, disabled status and the DCR retirement tombstone before persisting a grant. A pre-retirement consent page cannot create an unrevoked historical grant after the Owner retires that client. It fails closed as invalid_client rather than surfacing a generic server error.
- Authorization codes, access tokens, refresh tokens and recovery responses are FK-bound to a parent authorization. Once the client profile is disabled and all its authorizations are revoked, these credentials cannot be used, even if historical rows have not expired. Retirement retains those histories and does not bypass the generation fence. Automatic or manual capacity recovery does not relax the per-IP/global admission quotas or open registration when `OAUTH_DCR_REGISTRATION_ENABLED=false`.
- Individual Gateway user authorization revocation remains independent of client-profile revocation; do not disable every client to remove a single user's consent.
- Existing CIMD private_key_jwt verification, client profile IDs, user grants and tokens are unchanged. Separate profiles cannot exchange each other's codes or refresh tokens.
- A code rollback to a build lacking DCR requires disabling live DCR clients, and would render their connections unusable. Do not drop the oauth_dcr_clients table while any DCR client remains in use; losing durable registration rows is a stateful migration, not disposable data.
- Existing one-time authenticated lost-response refresh recovery is preserved for both CIMD and DCR clients with exact client/authorization/resource/scope binding, limited to the bounded recovery window and replay count.
- Distinguish deterministic unit/feature correctness from *live* CIMD upstream compatibility. The read-only `gateway:oauth-client-check --refresh` reports sanitized upstream HTTP 404/503 when known or classifies transport failure without echoing raw URLs/bodies; the separate failing upstream canary remains visible. Do not fabricate metadata/JWKS or claim production restoration based only on tests.

References: https://developers.openai.com/plugins/build/auth and RFC 7591 https://www.rfc-editor.org/rfc/rfc7591 . The current ChatGPT plugin configuration and transport choices require an actual client-side acceptance test.
