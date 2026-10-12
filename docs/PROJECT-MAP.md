# MCP Gateway Project Map

This file is the maintainer/agent navigation entry point for recovering and continuing the project. It is intentionally separate from `README.md`, which is reserved for the user-facing project overview, installation, and usage guidance.

## Authoritative sources

Use the source that owns the kind of truth you need:

- [`MASTER-SPEC.md`](./MASTER-SPEC.md) — canonical project purpose, durable requirements, constraints, non-goals, security boundaries, and V1 completion criteria.
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — current Target-era structure, capability discovery/evolution, shared controls and connector boundaries. Obsolete V1 Site-era diagrams remain in Git history only.
- [`TARGET-CONNECTOR-FOUNDATION.md`](./TARGET-CONNECTOR-FOUNDATION.md) — detailed accepted Target/connector capability, identity, credential, security and future extension contract; historical transition sequencing must not override current source/PR/Issue truth.
- [`REMOTE-IO-CONTRACT.md`](./REMOTE-IO-CONTRACT.md) — canonical proportional resource and failure semantics (#122/#123/#147); distinct from effective-limit measurements in #154.
- [`WHOLE-FILE-EXCHANGE.md`](./WHOLE-FILE-EXCHANGE.md) — source-integrated optional SSH binary transfer wire contract, `target-context` discovery, verified external-client E2E, and separately gated release/host enablement (#147).
- [`DIRECT-SSH-CONNECTOR.md`](./DIRECT-SSH-CONNECTOR.md) — owner-accepted direct SSH password/key, OS-account commands and SFTP design (#123).
- [`DEVELOPMENT.md`](./DEVELOPMENT.md) — repeatable local setup, dependency boundaries, and repository validation workflow.
- [`DEPLOYMENT.md`](./DEPLOYMENT.md) — supported aaPanel/OpenLiteSpeed/PHP deployment with MariaDB primary and MySQL compatibility, validation, backup, upgrade, rollback, and operational safety boundaries.
- [`../achworks.yaml`](../achworks.yaml) — stable machine-readable AChWorks component identity, capabilities, interfaces, and source pointers; it must not mirror live work/runtime state.
- [Koinon (`AChWorks/koinon`)](https://github.com/AChWorks/koinon) — ecosystem-level governance, discovery, and generic cross-project contracts; it is not an MCP Gateway runtime dependency.
- [Connector integration and durability guide](./CONNECTOR-INTEGRATION-GUIDE.md) — implementer steps for future connectors, identity, permissions, durable idle authorization, Stale health, finite credential renewal and safe recovery.
- [GitHub Issues](https://github.com/AChWorks/mcp-gateway/issues) — active work, dependencies, acceptance criteria, task state, risk, and current execution contracts.
- [Program Issue #106](https://github.com/AChWorks/mcp-gateway/issues/106) — overarching Target/client-neutral program; Agent #111 is owner-paused. Read current #123/#112/#147 before assuming integrated features are shipped.
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

The non-WordPress connector tracks are independent Direct SSH (active) and AI Server Agent (owner-paused):

- [`mcp-gateway#106`](https://github.com/AChWorks/mcp-gateway/issues/106) — Gateway-side breaking Target foundation and connector program;
- [`mcp-gateway#117`](https://github.com/AChWorks/mcp-gateway/issues/117) — client-neutral MCP authorization edge; ChatGPT remains the first supported profile while future clients can be added without another core auth rewrite;
- [`mcp-gateway#97`](https://github.com/AChWorks/mcp-gateway/issues/97) — post-integration WordPress OAuth refresh durability and real installed-host/cron proof, not generic lifecycle redesign.
- [`ai-server-agent#47`](https://github.com/ach1992/ai-server-agent/issues/47) — Agent-side optional Gateway integration, independent credential lifecycle, preserved direct modes, and Agent-authoritative safety.
- [`mcp-gateway#123`](https://github.com/AChWorks/mcp-gateway/issues/123) — SSH Target without Agent installation; password/key and arbitrary commands under OS account authority.
- [`mcp-gateway#122`](https://github.com/AChWorks/mcp-gateway/issues/122) — completed finite oversize-response foundation; do not reopen for generic file transfer.
- [`mcp-gateway#130`](https://github.com/AChWorks/mcp-gateway/issues/130) — existing WordPress direct-versus-Gateway Ability parity; not general file ingress.
- [`mcp-gateway#147`](https://github.com/AChWorks/mcp-gateway/issues/147) — shared, client-neutral **real bidirectional file/data transfer**, adaptive quotas and demonstrated host input/model output; does not duplicate #123 SSH backend.
- [Gateway Issue #153](https://github.com/AChWorks/mcp-gateway/issues/153) — measured operational budgets and single Owner Admin settings module, distinct from security/provider invariants.
- [Gateway Issue #154](https://github.com/AChWorks/mcp-gateway/issues/154) — per-layer effective payload/format/capacity and Bridge/client compatibility matrix, not a duplicate data plane.
- [`mcp-gateway#112`](https://github.com/AChWorks/mcp-gateway/issues/112) — mixed WordPress + SSH final acceptance and release evidence; Agent does not gate current acceptance.

Neither repository's Issue grants mutation authority in the other repository. Recover both contracts and current exact implementation/release evidence before cross-repository compatibility work.

## Recovery path

A replacement Master or developer should recover in this order:

1. Read `docs/MASTER-SPEC.md` only as needed to establish or verify project-level intent, durable constraints, and completion/growth rules.
2. Read `docs/ARCHITECTURE.md` for the current integrated implementation boundaries.
3. Use `docs/TARGET-CONNECTOR-FOUNDATION.md` and the appropriate `docs/DIRECT-SSH-CONNECTOR.md` / `docs/REMOTE-IO-CONTRACT.md` sections only for the current connector/transfer work. The canonical capability-evolution policy is in Master Spec §4.9 and Architecture §4; historical sequencing in long Issue bodies is not today's source state.
4. Inspect current open GitHub Issues for active work, dependencies and acceptance; first read each issue's latest controlling status and current code/PR/release evidence. Older dated `NEXT`/`BLOCKED` notes are historical unless explicitly still current. Use closed Program #1 only for V1 provenance.
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
