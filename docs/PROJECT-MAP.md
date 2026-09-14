# MCP Gateway Project Map

This file is the maintainer/agent navigation entry point for recovering and continuing the project. It is intentionally separate from `README.md`, which is reserved for the user-facing project overview, installation, and usage guidance.

## Authoritative sources

Use the source that owns the kind of truth you need:

- [`MASTER-SPEC.md`](./MASTER-SPEC.md) — canonical project purpose, durable requirements, constraints, non-goals, security boundaries, and V1 completion criteria.
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — current technical architecture, component boundaries, protocol flows, persistence, deployment shape, and testing direction.
- [GitHub Issues](https://github.com/ach1992/mcp-gateway/issues) — active work, dependencies, acceptance criteria, task state, risk, and current execution contracts.
- [Program Issue #1](https://github.com/ach1992/mcp-gateway/issues/1) — V0.1 execution program and dependency graph.
- Pull requests and commits — implementation identity, review history, and integrated changes.
- GitHub Actions / CI — validation evidence tied to exact commits.
- Release/deployment state — production truth when delivery is explicitly authorized later.

`README.md` is not a project-state, architecture, or recovery source. It is the public/user-facing project page.

## Cross-repository dependency

The initial WordPress connector depends on WP AI Bridge compatibility work tracked in:

- [`ach1992/wp-ai-bridge#54`](https://github.com/ach1992/wp-ai-bridge/issues/54) — allow explicitly approved MCP Gateway OAuth clients while preserving existing direct ChatGPT behavior.

The Gateway-side consumer of that contract is:

- [`mcp-gateway#4`](https://github.com/ach1992/mcp-gateway/issues/4) — site registry and secure WP AI Bridge pairing.

If the Bridge-side contract changes materially, reconcile Issue #4 and its dependents before implementation relies on stale assumptions.

## Recovery path

A replacement Master or developer should recover in this order:

1. Read `docs/MASTER-SPEC.md` only as needed to establish or verify project-level intent and completion criteria.
2. Read `docs/ARCHITECTURE.md` for the current durable implementation boundaries.
3. Open Program Issue #1 to locate the active workstream and dependency path.
4. Read only the relevant current Issue/Task Contract and its dependencies.
5. Inspect the corresponding branch/PR/commit and exact CI evidence before changing or integrating implementation.
6. Use deployment/release evidence separately when delivery becomes authorized.

Conversation history is not an authoritative project source and is not required to continue the project.

## Documentation ownership rule

Keep information in its natural owner:

- user-facing overview, installation, and usage -> `README.md`;
- durable project intent -> `docs/MASTER-SPEC.md`;
- architecture and engineering structure -> `docs/ARCHITECTURE.md` and other focused docs when genuinely needed;
- navigation/recovery topology -> this file;
- live work/status/dependencies -> GitHub Issues/PRs/CI;
- release/deployment truth -> release/deployment systems.

Do not mirror live task status into documentation files.