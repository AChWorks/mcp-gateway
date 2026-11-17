# ArvanCloud API connector — dynamic REST/OpenAPI Target

## Purpose and truthful support boundary

The built-in `arvancloud` connector attaches **one Owner-registered HTTPS API root** to a Gateway Target, encrypted Machine User API key and the existing Gateway User/Group/Target/AI client authorization model. It does not deploy a second service, register arbitrary external MCP servers, or expose a credential-forwarding proxy.

The stable MCP operation surface is:

- `arvan-api-catalog`: read an **optional** public OpenAPI 3.x JSON/YAML description from the configured URL and page/filter path, method, parameters and requestBody. A description is explanatory, not executable authority.
- `arvan-api-request`: call the selected Target's **registered** API origin/base path with a relative path, HTTP method, optional structured query and optional JSON request body. It works with newly released compatible HTTP endpoints **even if OpenAPI metadata has not yet been updated or provided**.

An Arvan REST API change to paths, query arguments, JSON schemas or HTTP methods should not require a Gateway release. A different *origin* or API version/base path is a Target configuration change and may require a different key. Completely different protocols, transport authentication, multipart/file streaming or provider-side signing (such as S3 AWS Signature V4) require additional adapter capabilities; they cannot be safely promised by arbitrary read/write alone.

Current authenticated request profile: `Authorization: Apikey <key>` over HTTPS, JSON request/response and fixed selected Target. The selected Machine User's real Arvan-side API scopes remain authoritative. Header name/prefix are deliberately connector-owned and do not come from MCP arguments; a different authentication contract needs an explicitly reviewed provider adapter change.

## Enroll from Gateway

1. In ArvanCloud, create a **Machine User** with appropriate provider-side Access Policy and generate an API key. Never paste it into ChatGPT, a GitHub issue, PR or log.
2. In Gateway, sign in as **Owner**. Navigate to **Targets → Add Target → ArvanCloud API**. Enter a stable Target ID and label.
3. Enter the specific product's **API base URL**, including a version prefix if required, e.g. `https://napi.arvancloud.ir/cdn/4.0`. Each other API root, product or region can have its own registered Target without code changes.
4. Optionally enter the product's **public OpenAPI YAML/JSON description URL**, e.g. `https://www.arvancloud.ir/api-docs/cdn-4.0.yml`. No API key is ever sent to that documentation endpoint. You can leave it blank; request execution does not require it.
5. Enter a **known read-only GET probe path**, e.g. `/domains`, to enable authenticated connection testing. Do not set a mutating probe path. This is configuration rather than a hardcoded product endpoint.
6. Enter the API key and current Gateway Owner password. Submit, assign Gateway Target or Target Group access as intended, then run **Connect/Test**. A successful historical GET probe does not mean every product API path works or that the key is still live later.
7. Connect ChatGPT to the Gateway using the existing OAuth setup. As an authorized Gateway user, call `targets-list`, `target-context`, `arvan-api-catalog`, then `arvan-api-request`. Set and enforce Target-specific grants through the existing Admin controls.

The key is encrypted inside the existing `target_credentials` model and is bound to immutable Target record ID, public Target ID and exact approved API base URL. It is never returned to the client. Replacing the API origin requires a **new** key and Owner password; replacing a key resets the previous connected evidence. **Disconnect** deletes only the local key; revoke the original Machine User key in ArvanCloud separately when needed.

## Request examples

Inspect a catalog:

```json
{"target_id":"arvan-cdn","offset":0,"limit":20,"search":"dns"}
```

Read a domain list using the configured CDN API root:

```json
{"target_id":"arvan-cdn","method":"GET","path":"/domains","query":{"page":2}}
```

A JSON mutation (shown as a **shape example**, not authorization to execute it):

```json
{"target_id":"arvan-cdn","method":"PATCH","path":"/domains/EXAMPLE-ID/config","body_json":"{\"enabled\":true}"}
```

Never put the API key, `Authorization` header or a full URL in tool arguments. Method and relative path are caller inputs; **destination host, key and transport policy are not**. The registered API base path cannot be escaped with `..`, encoded slash/backslash or `//` authority replacement.

## Permissions, effects and safety

These are additional **Target-scoped** permissions. All still require a role ceiling, effective selected/group Target scope, explicit deny precedence, AI-access/OAuth client authorization, and a non-paused Target:

| Permission | HTTP methods |
| --- | --- |
| `arvan.api.inspect` | Inspect configured public OpenAPI document |
| `arvan.api.read` | `GET`, `HEAD`, `OPTIONS` |
| `arvan.api.write` | `POST`, `PUT`, `PATCH` |
| `arvan.api.destructive` | `DELETE` |
| `arvan.api.unclassified` | Any other supported non-TRACE/CONNECT method (requires high-trust grant) |

This *HTTP-verb* classification is provisional: a provider API that uses `POST` to **delete** must be treated as destructive by the caller, and API key restrictions should cover it; the Gateway does not infer safe business effects from arbitrary provider documentation. Existing admin permission groups remain effective. The Gateway checks live Target grants, stored key/binding and Target pause immediately before dispatch. Admin **Connect**, **Reconnect**, and **Test** all respect the same fresh Pause boundary; **Disconnect** remains available for local credential removal during a pause. A successful GET probe changes the recorded connection state only if its exact API configuration and encrypted credential remain unchanged at the moment of settlement. A concurrent rotation, disconnect or pause invalidates the old probe evidence; the database lock is held only for the final local state check, not across HTTP I/O.

An uncertain mutating request or provider non-2xx response is recorded as **unknown**; do not automatically retry until remote state has been reconciled. The existing scoped Activity/diagnostic lookup retains the method, selectively redacted relative path, SHA-256 path fingerprint, observed HTTP status, and available provider request ID for **success, provider failure, and transport-uncertain outcome**. Credential-equivalent URL encodings (including partially and repeatedly percent-encoded values), JSON-escaped slashes/Unicode, and mixed URL-then-JSON representations are inspected before persistent diagnostics or provider data are returned. An affected opaque response body or request ID is replaced with `[REDACTED]` when its safe fields cannot be retained reliably; unrelated path segments, status, method, path fingerprint and safe request IDs remain available. Sanitization never modifies the outbound request URL, request body or authorization header. It intentionally does **not** store API keys, query parameters, request bodies, Authorization headers or full external URLs. Find the matching diagnostic reference in Admin Activity or `operation-diagnostics-read`; the latter is subject to current Target/actor/client authorization.

The HTTP transport reuses the shared Gateway DNS/public-IP egress policy, DNS pinning, real TLS verification, redirect rejection, no arbitrary authentication headers, bounded response collection and structured diagnostic/error reporting. A docs URL cannot select the execution endpoint or grant permissions. All returned OpenAPI content is untrusted input.

Server-configurable memory budgets (bounded further by SafeHttpClient's existing absolute ceiling) are:

- `GATEWAY_API_DOCUMENT_MAX_BYTES` — default 2 MiB for OpenAPI YAML/JSON descriptions
- `GATEWAY_API_RESPONSE_MAX_BYTES` — default 1 MiB for ordinary JSON API responses
- Existing Gateway HTTP connect/request timeouts and host memory/server request limits still apply

These are bounded *response buffers*, not arbitrary API version restrictions. Large binary/object transfers need a separately designed streaming/transfer interface rather than returning an unbounded object in one MCP tool result.

## Reuse in later connectors

`App\Infrastructure\Http\Api\ApiHttpTransport` is the shared fixed-base URL, safe relative path, JSON REST request substrate.

`App\Infrastructure\Http\Api\OpenApiOperationCatalog` is a pure generic JSON/YAML OpenAPI catalog reader; no keys, roles, network or provider-specific code.

The `arvancloud` adapter owns its Machine User credential format, connection verification, Target-specific lifecycle and gateway permissions. Another REST provider should reuse these narrow primitives behind its **own registered connector and identity boundary**. Do not introduce a second ACL/credential database or reuse Arvan's API key in another connector. The existing downstream stateless MCP transport is a separate protocol and does not automatically enroll arbitrary MCP Targets.

## Acceptance and limitations

Feature validation requires: unit/catalog tests; registered Target/credential/permission/URL transport tests with no real provider writes; Admin form/visibility tests; WordPress/SSH regression tests; exact-head CI; independent review. A real Arvan account and API key are **not** present in CI. Only a production-target Owner with an appropriately scoped Machine User can do a final live *read-only* authentication acceptance, followed by explicitly authorized writes.

Source issue: [#310](https://github.com/AChWorks/mcp-gateway/issues/310).
