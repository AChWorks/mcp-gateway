# MCP Gateway — documentation map and recovery path

**Purpose:** tell a developer/operator/AI Master **where to find the one authoritative answer**, not replicate the specification, current project status, release notes or Issues. `README.md` is the **public introduction, installation entry and usage navigation**, **not** the product or architectural specification.

## What to read for a concrete question

| Question | Authoritative source |
| --- | --- |
| **Why the product exists, enduring behavior, constraints and non-goals** | [MASTER-SPEC.md](MASTER-SPEC.md) |
| **How the currently integrated Gateway is structured; clearly labeled future seams** | [ARCHITECTURE.md](ARCHITECTURE.md) and actual implementation |
| **What one Target and registered connector must guarantee** | [TARGET-CONNECTOR-FOUNDATION.md](TARGET-CONNECTOR-FOUNDATION.md) |
| **How an external product/adapter can integrate and prove compatibility** | [CONNECTOR-INTEGRATION-GUIDE.md](CONNECTOR-INTEGRATION-GUIDE.md) |
| **What makes results, file exchange, quotas, errors and retry safe** | [REMOTE-IO-CONTRACT.md](REMOTE-IO-CONTRACT.md) |
| **Specific SSH operations, Jobs and OS trust boundaries** | [DIRECT-SSH-CONNECTOR.md](DIRECT-SSH-CONNECTOR.md) |
| **Actual SSH complete-binary HTTP endpoints and testable wire semantics** | [WHOLE-FILE-EXCHANGE.md](WHOLE-FILE-EXCHANGE.md) |
| **Operator settings, effective examples and safety defaults** | [CONFIGURATION.md](CONFIGURATION.md) and actual `.env.example`/configuration source |
| **Installation, update, backup, rollback and production incident procedures** | [DEPLOYMENT.md](DEPLOYMENT.md) |
| **Rare, explicit legacy v1 Site → Target data-reset upgrade** | [TARGET-TRANSITION-RUNBOOK.md](TARGET-TRANSITION-RUNBOOK.md) |
| **Disconnection/credential revocation recovery** | [TARGET-DISCONNECT-RECOVERY.md](TARGET-DISCONNECT-RECOVERY.md) |
| **Local-only Target removal when remotely unavailable** | [OFFLINE-TARGET-REMOVAL.md](OFFLINE-TARGET-REMOVAL.md) |
| **OAuth client identity, reverse proxy and recovery procedures** | [CLIENT-PROFILE-RUNBOOK.md](CLIENT-PROFILE-RUNBOOK.md) |
| **Develop, validate, reproduce and test with isolated real providers** | [DEVELOPMENT.md](DEVELOPMENT.md), [INSTALLED-MIXED-WP-SSH-ACCEPTANCE.md](INSTALLED-MIXED-WP-SSH-ACCEPTANCE.md) |
| **Shared Admin UI and accessibility conventions** | [ADMIN-UI-QUALITY.md](ADMIN-UI-QUALITY.md) and [AGENTS.md](../AGENTS.md) |

A link from a specialist guide to the canonical contract is intentional **navigation**, not permission to copy the same requirement into a second maintained version. If a detail has a clearer natural owner, edit there and point readers to it.

## Recovery in a new Master/chat

1. Read [MASTER-SPEC](MASTER-SPEC.md) to establish enduring accepted intent; do **not** infer shipping or completion from design text.
2. Read [ARCHITECTURE](ARCHITECTURE.md) plus the **smallest relevant specialist contract** for the task. Source code and the immutable relevant Git ref control implemented behavior.
3. Query [open Issues](https://github.com/AChWorks/mcp-gateway/issues?q=is%3Aissue+is%3Aopen) and [PRs](https://github.com/AChWorks/mcp-gateway/pulls) for **current** ownership, requirements and dependencies. Completed one-off acceptance belongs to the closed Issue, PR/CI and Git history, **not a parallel version-specific living Markdown status report**.
4. Check exact source/PR SHA and its own applicable [GitHub Actions](https://github.com/AChWorks/mcp-gateway/actions) when validating code. [Releases](https://github.com/AChWorks/mcp-gateway/releases) prove published assets; **only installed-host evidence** proves the active version, enabled modes, migrations and health.
5. Read [DEPLOYMENT](DEPLOYMENT.md) only when installation, update, backup/restore or operator actions are in scope; require appropriate separate authorization and risk gates.

Never rely on chat summaries, a stale status paragraph or `README.md` to supersede GitHub/CI/installed evidence.

## External and historical ownership

- [Koinon](https://github.com/AChWorks/koinon) owns AChWorks-wide discovery/governance and optional Foundation-promotion rules. Gateway product/runtime/Issues remain here. [`achworks.yaml`](../achworks.yaml) is a stable metadata pointer, not another status database.
- [WP AI Bridge](https://github.com/AChWorks/wp-ai-bridge) owns its WordPress/provider implementation and permissions; [AChrix](https://github.com/AChWorks/achrix) and actual application consumers own their optional application Bridge decisions. Cross-repo dependencies do **not** grant mutation authority.
- Completed WordPress-first V1 criteria, former Site-era migration work, historic RC8 release tests and older release identities remain in **Git history, closed GitHub Issues/PRs, exact CI and immutable Releases**. They do not need new permanent “historical acceptance” files alongside maintained docs.
- Future architecture and product work have explicit controlling open Issues. A reference to an unmerged PR is a proposed candidate, never integrated functionality.

**Document rule:** one stable product specification; one current architecture; concise specialist operator/connector/data documents with a real reader/use case; Issues for unfinished work; Git/CI/Releases for evidence. Do not add duplicate architectural copies, transient handoff snapshots or dated acceptance documents without an exceptional concrete operational need.
