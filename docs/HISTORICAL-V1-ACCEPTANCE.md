# MCP Gateway — Historical WordPress-first V1 acceptance

> **HISTORICAL ONLY; not the current canonical product contract or current runtime status.** This record preserves the previously accepted WordPress-first V1 scope and acceptance evidence when the canonical [MASTER-SPEC](MASTER-SPEC.md) was refocused on durable product identity. For the present architecture read [ARCHITECTURE.md](ARCHITECTURE.md); for unfinished work read current GitHub Issues; for actual delivery read GitHub Releases and the installed host. Neither this archive nor README overrides those sources.

## 5. V1 scope

This section records the integrated WordPress-first V1 baseline and remains useful regression/compatibility evidence. Program #106 intentionally replaces generic Site-shaped core terminology for the next breaking foundation; the V1 nouns below are not requirements to preserve Site as the future shared domain.

### 5.1 Administration panel

Provide a small server-rendered web panel with:

- administrator sign-in/sign-out;
- dashboard summary;
- site list;
- add/edit/remove site metadata;
- connect/reconnect/disconnect a WP AI Bridge site;
- test connection and show actionable connection state;
- view bounded recent activity;
- view the Gateway MCP endpoint and client connection information;
- minimal application settings that are genuinely required.

V1 does not require complex organization hierarchy or enterprise RBAC. The integrated baseline already supports multiple local users with lightweight Owner/Administrator/Operator/Viewer permission bundles plus denial-only resource narrowing through the same server-side authorization boundary; the Target transition must preserve that capability without turning it into a second policy engine.

### 5.2 WP AI Bridge site registration

An operator adds a site using a human-readable name and its HTTPS WordPress base URL.

The Gateway must derive or safely discover the expected WP AI Bridge MCP/OAuth endpoints rather than asking the user to paste many implementation URLs.

Registration must validate the target before persisting a usable connection. The Gateway must never turn an operator-supplied URL into an unrestricted server-side HTTP proxy.

### 5.3 Site authorization

Each connected WordPress site has an independent authorization relationship with the Gateway.

The expected user experience is:

1. Add site.
2. Gateway discovers/validates WP AI Bridge.
3. Operator selects Connect.
4. Browser is sent to the site's WordPress authorization/consent flow.
5. The operator authorizes the Gateway as a WordPress user.
6. Gateway receives and stores the resulting credentials securely.
7. Site becomes connected and can be tested.

No WordPress username or password is stored by MCP Gateway.

Disconnect/revocation for one site must not affect other sites.

### 5.4 Client-facing MCP service

Expose one public remote MCP endpoint over HTTPS.

The endpoint must use a current supported MCP HTTP transport and proper authentication. Authentication between an MCP client and the Gateway is separate from authentication between the Gateway and a target site.

For ChatGPT, V1 must support the current custom MCP App OAuth flow, including refreshable access when required by the current ChatGPT integration contract.

For the Program #106 breaking foundation, ChatGPT remains the first supported client profile but must no longer define the shared client-authorization core. The Gateway must support an explicit registry of reviewed MCP client profiles so future supported AI/MCP clients can coexist without another authorization-domain rewrite. Provider/product labels are presentation metadata, not permission sources.

The implementation must follow current MCP and client platform specifications at implementation time rather than preserving obsolete protocol assumptions in custom code.

### 5.5 Stable WordPress routing contract

The Gateway must expose a compact WordPress routing surface sufficient to:

- list configured/available sites without exposing credentials;
- inspect one selected site's context/connection state;
- discover the selected WP AI Bridge operation/Ability contracts;
- inspect an exact operation schema when needed;
- execute an exact selected WP AI Bridge operation with explicit `site_id` and input.

The Gateway must preserve downstream authorization and validation errors accurately enough for the client and operator to understand why an operation was denied or unavailable.

Every target-specific call must identify the site explicitly. Write or destructive operations must never be routed using only conversational or request-local "current site" state.

### 5.6 Connector boundary

WordPress-specific protocol knowledge belongs in one WP AI Bridge connector boundary rather than being spread through controllers, UI, OAuth code, and MCP handlers.

The durable Gateway identity is the registered site/target plus its declared connector type. Shared site inventory, authorization, routing, activity, and future operation-management rules must remain usable without requiring WordPress-specific fields or semantics from every connector.

The internal connector contract should remain small and evidence-driven. It may cover capabilities such as discovery, connection health, schema/capability inspection, execution, and disconnect/revocation where the backend supports them. Do not invent capability methods for future systems until an actual connector or consumer requires them.

Do not expose arbitrary connector-supplied URLs, HTTP methods, database queries, shell commands, or filesystem paths as a **generic** Gateway operation. The expressly supported `ssh_direct` connector instead allows an authorized Gateway user to execute **any** command against their explicitly registered SSH Target as its configured OS account, including permitted `sudo`/root. This is never a request-supplied arbitrary-host shell proxy.

## 14. V1 success criteria

These criteria record the completed/integrated WordPress-first V1 acceptance baseline. They remain regression evidence for future releases, but they are not the completion criteria for the active connector-neutral Target program; Program #106 owns that next outcome.

V1 is successful when all of the following are demonstrated against supported test/deployment environments:

1. The application installs on the target PHP 8.4 + OpenLiteSpeed/shared-PHP + MariaDB-primary/MySQL-compatible deployment model using the official deployment ZIP and simple web installer; the Git/Composer/Artisan installation path remains supported for advanced operators.
2. The administration panel can securely create an administrator session and manage multiple site records.
3. At least two independent WP AI Bridge sites can be authorized and remain separately revocable.
4. One ChatGPT custom MCP App can authenticate to the Gateway and discover the stable Gateway tools.
5. ChatGPT can list sites, inspect the selected site's available WP AI Bridge operations, and execute authorized read and write operations against either site by explicit `site_id`.
6. A permission denied by WordPress/WP AI Bridge remains denied through the Gateway.
7. A disconnected/revoked site fails closed without breaking other connected sites.
8. Adding a third site does not require another ChatGPT App or a new Gateway MCP endpoint.
9. Direct ChatGPT-to-WP-AI-Bridge operation remains available for sites that use it.
10. Sensitive credentials are not exposed through the panel, installer, updater, MCP responses, application logs, or activity records.
11. A fresh developer/Master can recover project intent, architecture, current work, and validation expectations from the repository and GitHub without relying on prior chat history.
12. An existing deployment-ZIP installation can be upgraded with the official update ZIP through the authenticated one-time browser flow without SSH, Git, or Composer while preserving `.env` and persistent private state, removing stale managed files, exercising migrations/postflight validation against a real older packaged release, and removing/disabling the temporary updater after success.

V1 success criteria intentionally do not claim a fixed maximum fleet size. Capacity and growth evidence are governed by Section 11 and the current scalability work tracked in GitHub.
