# MCP Gateway Project Map

This file is the maintainer/agent navigation entry point for recovering and continuing the project. It is intentionally separate from `README.md`, which is reserved for the user-facing project overview, installation, and usage guidance.

## Authoritative sources

Use the source that owns the kind of truth you need:

- [`MASTER-SPEC.md`](./MASTER-SPEC.md) — canonical project purpose, durable requirements, constraints, non-goals, security boundaries, and V1 completion criteria.
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — current integrated technical architecture, component boundaries, protocol flows, persistence, deployment shape, and testing direction.
- [`TARGET-CONNECTOR-FOUNDATION.md`](./TARGET-CONNECTOR-FOUNDATION.md) — accepted breaking Target/connector target-state design for Program #106; authoritative for that transition until integrated into current architecture.
- [`REMOTE-IO-CONTRACT.md`](./REMOTE-IO-CONTRACT.md) — bounded responses, command outputs and file-transfer design (#122).
- [`DIRECT-SSH-CONNECTOR.md`](./DIRECT-SSH-CONNECTOR.md) — owner-accepted direct SSH password/key, OS-account commands and SFTP design (#123).
- [`DEVELOPMENT.md`](./DEVELOPMENT.md) — repeatable local setup, dependency boundaries, and repository validation workflow.
- [`DEPLOYMENT.md`](./DEPLOYMENT.md) — supported V1 aaPanel/OpenLiteSpeed/PHP deployment with MariaDB primary and MySQL compatibility, validation, backup, upgrade, rollback, and operational safety boundaries.
- [`../achworks.yaml`](../achworks.yaml) — stable machine-readable AChWorks component identity, capabilities, interfaces, and source pointers; it must not mirror live work/runtime state.
- [Koinon (`AChWorks/koinon`)](https://github.com/AChWorks/koinon) — ecosystem-level governance, discovery, and generic cross-project contracts; it is not an MCP Gateway runtime dependency.
- [GitHub Issues](https://github.com/AChWorks/mcp-gateway/issues) — active work, dependencies, acceptance criteria, task state, risk, and current execution contracts.
- [Program Issue #106](https://github.com/AChWorks/mcp-gateway/issues/106) — active connector-neutral Target + client-neutral MCP edge + AI Server Agent + Direct SSH program and dependency graph.
- [Program Issue #1](https://github.com/AChWorks/mcp-gateway/issues/1) — historical completed V1 execution program and dependency graph; it is not the current-work index.
- Pull requests and commits — implementation identity, review history, and integrated changes.
- GitHub Actions / CI — validation evidence tied to exact commits.
- [GitHub Releases](https://github.com/AChWorks/mcp-gateway/releases) — immutable public release identity and release notes; deployment state remains separate production truth when deployment is explicitly authorized.

`README.md` is not a project-state, architecture, or recovery source. It is the public/user-facing project page.

## Cross-repository dependency

The initial WordPress connector compatibility work was established through:

- [`AChWorks/wp-ai-bridge#54`](https://github.com/AChWorks/wp-ai-bridge/issues/54) — approved MCP Gateway OAuth-client support while preserving direct ChatGPT behavior;
- [`mcp-gateway#4`](https://github.com/AChWorks/mcp-gateway/issues/4) — the completed Gateway-side site registry and secure pairing work.

These closed Issues are historical contract provenance, not active task owners. If the Bridge/Gateway connector contract changes materially, recover the current code/release evidence in both repositories and create/update the natural current Issue rather than treating closed Issue #4 as live state.

The accepted non-WordPress connectors are AI Server Agent (MCP-over-HTTPS) and independent Direct SSH:

- [`mcp-gateway#106`](https://github.com/AChWorks/mcp-gateway/issues/106) — Gateway-side breaking Target foundation and connector program;
- [`mcp-gateway#117`](https://github.com/AChWorks/mcp-gateway/issues/117) — client-neutral MCP authorization edge; ChatGPT remains the first supported profile while future clients can be added without another core auth rewrite;
- [`ai-server-agent#47`](https://github.com/ach1992/ai-server-agent/issues/47) — Agent-side optional Gateway integration, independent credential lifecycle, preserved direct modes, and Agent-authoritative safety.
- [`mcp-gateway#123`](https://github.com/AChWorks/mcp-gateway/issues/123) — SSH Target without Agent installation; password/key and arbitrary commands under OS account authority.
- [`mcp-gateway#122`](https://github.com/AChWorks/mcp-gateway/issues/122) — finite oversize-response handling and reusable data contract; coordinates with WP AI Bridge #100.

Neither repository's Issue grants mutation authority in the other repository. Recover both contracts and current exact implementation/release evidence before cross-repository compatibility work.

## Recovery path

A replacement Master or developer should recover in this order:

1. Read `docs/MASTER-SPEC.md` only as needed to establish or verify project-level intent, durable constraints, and completion/growth rules.
2. Read `docs/ARCHITECTURE.md` for the current integrated implementation boundaries.
3. If Program #106 is still active, read `docs/TARGET-CONNECTOR-FOUNDATION.md`, `docs/DIRECT-SSH-CONNECTOR.md` and `docs/REMOTE-IO-CONTRACT.md` for the accepted target-state and data/SSH contracts.
4. Inspect the repository's current open GitHub Issues to identify active work, dependencies, and acceptance criteria; use closed Program Issue #1 only when historical V1 context is specifically needed.
5. Read only the relevant current Issue/Task Contract and its direct dependencies, including AI Server Agent #47 when working on that connector and #117 when working on client-facing MCP/OAuth identity.
6. Inspect the corresponding branch/PR/commit and exact CI evidence before changing or integrating implementation.
7. Use `docs/DEPLOYMENT.md` plus the applicable GitHub Release and deployment evidence when installation, upgrade, or delivery becomes relevant.

Conversation history is not an authoritative project source and is not required to continue the project.

## Documentation ownership rule

Keep information in its natural owner:

- user-facing overview, installation, and usage -> `README.md`;
- durable project intent -> `docs/MASTER-SPEC.md`;
- current architecture and engineering structure -> `docs/ARCHITECTURE.md`; accepted Program #106 breaking target-state design -> `docs/TARGET-CONNECTOR-FOUNDATION.md` until integration;
- development workflow -> `docs/DEVELOPMENT.md`;
- deployment/upgrade/rollback procedure -> `docs/DEPLOYMENT.md`;
- navigation/recovery topology -> this file;
- live work/status/dependencies -> GitHub Issues/PRs/CI;
- release/deployment truth -> release/deployment systems.

Do not mirror live task status into documentation files.
