# MCP Gateway — Master Specification

## 1. Purpose

MCP Gateway is a **self-hosted, connector-neutral platform for controlled access to and operations on registered external systems** (Targets). It gives authorized people, AI clients and other explicitly supported application clients a coherent way to discover capabilities, choose the correct Target, execute permitted work and understand the result.

The product has **one application-owned security and operation model**, exposed through multiple suitable interfaces: a stable authenticated MCP entry for AI clients, a practical human administration/action interface and deliberately supported programmatic integrations. These interfaces differ in presentation and authentication but must not create competing business logic or permission systems.

Gateway is a **coordination, authorization and interoperability layer**. It is not a replacement for the connected applications' business logic, a duplicate content-management system, a public multitenant service, a universal network proxy or an unrestricted plugin marketplace.

**Integration must preserve independent supported direct access.** Registering or operating a Target through Gateway must not require disabling, altering or breaking an existing supported direct client-to-backend connection. This guarantees coexistence where the downstream system genuinely offers a direct mode; it does not invent a direct mode where none exists or bypass either path's authentication and authorization.

### Product outcomes

A successful Gateway enables an authorized principal to:
- identify the intended system unambiguously, even among many similar Targets;
- discover and use genuine capabilities that the selected Target and client support;
- act within both Gateway-granted authority and the downstream system's own permissions;
- use either human or machine entry points with equivalent effective policy and outcome semantics;
- perform bounded work on one or several authorized Targets without hiding partial results or uncertain remote effects;
- transfer or retrieve supported data and files with proven integrity and actual receiving-client compatibility;
- diagnose and recover from failures without disclosing sensitive infrastructure to ordinary users;
- operate and maintain the system without requiring heavyweight infrastructure for idle connections.

## 2. Identity, authority and responsibility

A **Target** is an explicitly enrolled, independently selectable and authorizable downstream system. Its Gateway-local identifier is stable and independent of mutable labels, hostnames, IP addresses, URLs or transport credentials. A connector family is an explicit, reviewed adapter to the Target's real protocol and trust boundary.

Maintain clear separation between:
- the authenticated Gateway user or service principal;
- the exact authenticated client identity and profile, where applicable;
- the selected Target or explicitly resolved authorized collection of Targets;
- the connector and its separately authenticated downstream principal;
- the requested capability, effect class and any additional approval required for that operation.

Gateway owns Target identity, registration, scoping and groups, access decisions, credential custody, execution admission, coherent operation outcomes and safe diagnostics. **The downstream system retains authority over its own objects, user rights, business rules, validation and side effects.** Gateway can narrow that authority, never manufacture or elevate it.

A Target Group is a convenient authorized membership and restriction mechanism, not a second permission engine. A group-level operation evaluates each actual Target and its effective grants; membership alone does not grant executable capability. Display labels, tool annotations, AI context or supplied remote addresses never substitute for server-authoritative identity.

## 3. One shared application operation model

Admin, AI/MCP and other supported clients are **entry adapters** to common application operations. Authentication/presentation may be interface-specific, but Target selection, effective permission, risk checks, resource admission, dispatch, result certainty and Activity belong to reusable application logic.

An Admin operation must not depend on calling Gateway's own public MCP endpoint. A public MCP Tool must not become the only place that enforces business rules needed by a human action. Connector-specific protocols remain behind reviewed adapters; a common operation model does **not** imply one universal wire format, one remote API or one generalized command executor.

Extract shared code only from real common behavior and preserve small, replaceable adapters. Do not pre-build an unrelated workflow platform, duplicate authorization/credential stores or introduce one new remote transport/worker for every connector.

## 4. Capabilities and extensibility

Keep **three separate evolution boundaries**:

1. **Target-side capabilities:** a compatible new operation or schema advertised by an existing connected system should become discoverable and usable within that connector's authenticated invocation contract, **without requiring Gateway code or a public MCP Tool per downstream operation**. Real input validation, operation authority and downstream policy still apply.
2. **Client-facing MCP/protocol capabilities:** methods, extensions and client-specific file/interaction modes require honest support and, when necessary, protocol negotiation or a reviewed adapter. Changing a downstream business operation is not equivalent to introducing a new MCP wire extension.
3. **New connector families:** introduce an explicit trusted connector only when the protocol or security model actually differs, reusing the established Target, credential, access, operation, result and diagnostics foundations. Do not dynamically execute provider-supplied code or trust arbitrary request-selected destinations.

The public capability surface scales with **families of supported work**, not the number of Targets or installed plugins. Authenticated discovery may be dynamic, but advertised capabilities must reflect the actual connector, client, configuration, Target state and principal permissions. A schema or discovery cache is not an authorization cache.

For a standards-compliant authenticated MCP-speaking Target, prefer shared standards-based discovery/invocation over one hard-coded Gateway implementation for every remote tool—without weakening endpoint identity, protocol version checks or scoped execution grants. Other protocols, including SSH and application-native APIs, retain their appropriate native adapters.

Unsupported client/protocol behavior, lack of authorization and Target/provider failure are distinct conditions and must never be mislabeled as one another.

## 5. Delegation and safe high-impact work

Support **deliberately broad** Target-capability delegation when the operator authorizes it and the authenticated downstream principal also has that power. The addition of a compatible Target operation must not silently widen a previously restricted grant.

Support **narrow, enforceable** delegation when a workflow requires particular Targets, action classes, business operations or content scope. A promise such as “publish selected content, but cannot administer the site” is valid only when real trusted operation semantics and/or downstream policy enforce it. A tool name, mutable annotation, inferred description or hidden UI button is not a security control.

Role ceilings, user/client Target scope, group restrictions, explicit denials, connector-specific grants and downstream checks must combine consistently across every interface. Unfamiliar operations are not forbidden merely for being new, nor are unclassified effects silently granted without deliberate policy. Principal disabling, revocation, Target changes and explicit operation-pause gates must be rechecked at the relevant admission point.

**Legitimate high-privilege work remains possible.** An authorized SSH operator can execute arbitrary commands permitted by the configured remote OS account, including OS-authorized sudo/root work. Gateway capability toggles for SFTP are **not** a sandbox around granted shell rights. Security gates preserve exact identity, consent, trust, authorization and audit; they must not invent superficial string-based command bans or bypass real downstream permissions.

Approval is bound to the authenticated actor, exact Target(s), intended action and a meaningful request identity. Confirmation does not retroactively undo a remote effect, and pausing new Gateway-mediated work does not cancel already-dispatched remote activity.

## 6. Operations, partial results and recovery

Every operation has an identifiable principal, selected Target(s), requested capability, actual admission decision and outcome certainty. Distinguish:

- **Not dispatched:** authorization, schema, rate, health, budget or safety admission stopped the request before an effectful remote stage.
- **Confirmed:** a real source reports a verifiable completed result, with the applicable completeness limits.
- **Partial:** some independently identified work or outputs succeeded, with the remainder explicitly recorded as incomplete or failed.
- **Unknown after dispatch:** the Target **may** have acted despite a lost response, timeout or canceled connection. This is neither confirmed failure nor permission for blind replay.

A multi-Target action explicitly resolves permitted members, rechecks authorization and Target state before each meaningful dispatch and retains **per-Target outcomes and remote identities where available**. It does not pretend multiple independent Targets participate in one atomic transaction. Retrying, reconciliation, cancellation and compensation require evidence for the specific operation; a canceled request is not evidence the remote side effect disappeared.

Provide durable operation identity, status, progress, retention and safe continuation **when** the actual workload warrants them. Logical work may outlast an HTTP request, but this is not an excuse to require one worker, remote agent or live connection per registered Target. One-time group actions do not imply continuous replication/synchronization or automatic cross-site conflict resolution.

## 7. Results, files and effective resource policy

Provide one common semantic policy for identity-bound data access, size/time/concurrency limits, integrity, failure classification, cleanup and honest availability—**not** one mandatory binary transport for every connector.

Small structured operations should be inexpensive single-call responses. Large structured results require source-supported projection, pagination, continuation or truthful oversize handling; never truncate malformed JSON or invent a cursor. A non-repeatable command's truncated output is not resumable unless a genuine retained backing result exists.

For binary or large files, select a **supported**, authorized and bounded client/Target route: range, stream, whole-object exchange, provider-native transfer or appropriately retained work. Keep inline-body budgets, response encoding overhead, per-window limits, total object limits, transient disk/memory/concurrency and logical operation lifetime **independent and correctly dimensioned**. An internal 16 KiB window must never be mistaken for a universal total-file limit.

Transfer claims require the actual bytes, source/destination identity, size and integrity evidence at the stages that can be verified. A path, URL, handle, server spool or successfully executed tool is **not proof** that a human received the content or that an AI model can consume it. Connector-native transport support and host/client-specific file handoff must be verified separately. Downloads and uploads have independent directions, permissions and completion semantics.

Avoid unnecessary data duplication, long-lived Gateway storage and compulsory PHP-host transit for every large file. Source applications remain systems of record. Temporary data is private, bounded, subject to actual host capacity and cleaned up safely.

## 8. Security, credentials and diagnostics

Authentication, client identity and Target selection must be cryptographically and authoritatively bound where appropriate. Protect Gateway sessions, consent, client OAuth/PKCE and token lifecycle, secret encryption and private storage, rate and resource admission, anti-enumeration access, outbound HTTPS/TLS/DNS/SSRF policy and independently pinned SSH host key/verified peer identity. No ordinary client may choose an arbitrary remote destination or cause unapproved credential forwarding.

Credential refresh, reauthorization, local forgetting, confirmed remote revocation, recorded connection health and Gateway operational pause are **different states**. Connector-owned rotating credentials need bounded due-work maintenance, generation fencing and provider-permitted recovery. Do not hold database locks across long remote network operations or treat a stale health timestamp as revoked authority.

Safe and coherent diagnostics identify the **first evidenced** failing layer: Gateway admission, outbound transport, connector protocol, downstream result or receiving-client boundary. If an intermediary strips structured provider errors, original provider cause remains unknown rather than being guessed from free-form messages. Ordinary end-user errors are understandable and do not expose infrastructure topology, private paths, provider internals, stack traces or credentials. Appropriately authorized operators receive bounded actionable stage/correlation evidence via a shared Activity and diagnostic model, not cloned per-connector logging systems.

Avoid logging secrets, private keys, bearer/refresh tokens, raw large outputs or arbitrary command and content bodies. An Activity persistence failure must not change a completed remote operation's authoritative result.

## 9. Efficiency, scale and supported operation

The primary model is a manageable **single-installation private workspace**, deployable on ordinary compatible PHP hosting with a relational database, HTTPS, private runtime state and a usable server-rendered Admin. Support hosts without shell/Composer access through trustworthy install/update packages, while retaining an advanced source deployment route.

Idle registered Targets should impose nearly only indexed database storage cost: no mandatory background polling, per-Target process, permanent SSH/MCP connection or Tool registration for each Target. Workload-dependent mechanisms should be proportional, measured, bounded and maintainable. Optimize end-to-end latency, number of remote round trips, throughput, worker memory/CPU, database overhead, private temporary storage, concurrency and operational cost before adding caches, queues, brokers, daemons or orchestration systems.

Finite Owner-configurable operational budgets belong to **one coherent typed policy** where legitimate workloads need adjustment. Maximum allowed size is not preallocated capacity; effective limits depend on the whole authenticated client–Gateway–Target path. Never expose immutable trust, permission or provider recovery invariants as performance tuning switches.

Install/update procedures protect existing credentials, users and unrelated state, authenticate and verify packages, preserve private files, apply migrations with explicit compatibility boundaries, and support an **independently verified database restoration path**. A code-file backup is not a database backup; upgrades or rollback must not invent remote mutation reversibility. Supported environment settings must be discoverable and documented once with safe defaults and clear opt-in for dangerous options.

## 10. Product acceptance principles

A product change is acceptable when it preserves the following properties relevant to its scope:

- **Usable authority:** the intended real operation succeeds under an approved user/client/Target/downstream grant, while negative scopes and permission boundaries remain enforced.
- **One policy across interfaces:** equivalent Admin and machine actions share admission, dispatch and truthful outcome semantics rather than diverging in authorization or diagnostics.
- **Adaptive interoperability:** compatible new Target operations need not multiply Gateway Tool names or require per-name Gateway releases; incompatible protocols/extensions are reported accurately.
- **Extensible without duplication:** a new supported connector reuses common identity, access, credential, result and resource mechanisms where they are truly shared, while retaining necessary protocol-specific code.
- **Safe group work:** multi-Target operations record independently attributable partial or unknown outcomes without duplicate or unapproved effects.
- **Real data delivery:** size, integrity and receiver/client compatibility are demonstrated for the supported mode; no claim of delivered or model-readable files from server-side handles alone.
- **Efficient operation:** small workloads stay cheap, idle fleets do not create proportional runtime work and measured larger workloads can use appropriate bounded modes.
- **Recoverable trust:** authentication/secret boundaries, exact remote identity, consent, revoke/unknown-result semantics, audit and independently restorable application data remain intact.
- **Operational clarity:** an administrator can deploy, grant, observe, diagnose and recover the system without reverse-engineering its internals or interpreting ordinary user errors as internal infrastructure details.

New capabilities, infrastructure and compatibility obligations should have a real consumer and evidence of need. Preserve these product guarantees rather than adding speculative platform abstractions or restrictions that merely appear safer.
