# MCP Gateway v1.3.0

This backward-compatible update provides an earlier, **testable WordPress + ChatGPT release** without waiting for the unfinished Site-to-Target redesign or Direct SSH implementation. It builds on the existing supported Site-based WordPress connector and the integrated client-neutral OAuth edge.

## What changed since v1.2.1

- Support administrator-approved OAuth client profiles, with separate client authorization, token identity, refresh/revocation generation and consent identity. The existing ChatGPT OAuth client remains supported.
- Harden request limits and actionable failures for bounded WordPress MCP read-only results, including oversized downstream responses.
- Retain the working Site-based WordPress registration/authorization, Site Groups, per-user permissions, and MCP tools: `sites-list`, `site-context`, `site-abilities-read`, `site-ability-execute`.
- Retain browser-updater support and existing administrator credentials. This release **does not** expose incomplete `targets-*`, SSH, or AI Server Agent runtime tools.

## Browser upgrade and fresh connection test

Upgrade a supported MCP Gateway deployment (including v1.2.1) using the published **mcp-gateway-update-v1.3.0.zip** from the GitHub Release. Place/extract it in the existing application root, open `https://YOUR-GATEWAY/update/`, sign in as the existing administrator, review the preflight, and perform the browser update. Use the package verification hash and a restorable backup when updating a real installation.

**The updater does not automatically erase existing accounts, WordPress Site registration, or ChatGPT OAuth grants.** This release deliberately avoids a destructive schema reset. If you want to start with clean connections, disconnect/revoke the old WordPress connection in Gateway Admin and reconnect/authorize the WordPress Site. Then revoke or remove the earlier Gateway authorization/connector from the ChatGPT side and connect it again, completing fresh OAuth consent. Re-register the WordPress Site only if needed, using Gateway Admin's existing Site management controls.

Gateway-facing ChatGPT authorization and downstream WordPress authorization are **two separate connection steps**. Verify both: authorize/connect WP AI Bridge to the Gateway, then authorize ChatGPT to access the Gateway, list the permitted Sites and execute a small permitted WordPress Ability. Finally test disconnect/revocation and access denial. Keep WordPress/Gateway credentials and signing keys private.

## Compatibility and scope

- No Site-to-Target migration or loss of existing Site records in this release. Operator accounts, existing encryption/signing keys, existing database and Gateway configuration are retained by the normal updater.
- A later major release can introduce the new Target foundation and require intentionally fresh connections. The unfinished Target/SSH/Agent branch is **not** part of v1.3.0.
- Production interoperability with a particular WordPress installation or a new ChatGPT connector session is verified **after** the operator installs and reauthorizes; passing CI alone is not that proof.
