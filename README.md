# MCP Gateway

MCP Gateway is a small self-hosted PHP gateway that exposes one remote MCP endpoint and routes explicitly selected operations to multiple connected backend systems, starting with WordPress sites running [WP AI Bridge](https://github.com/ach1992/wp-ai-bridge).

The V1 goal is simple: one ChatGPT custom MCP App, one Gateway endpoint, and many independently authorized WordPress sites.

## Target deployment

- aaPanel
- OpenLiteSpeed
- PHP 8.4
- MySQL
- HTTPS domain/subdomain
- Composer deployment

V1 is intentionally a single PHP web application. Redis, Docker, Node.js runtime, queues, message brokers, and microservices are not required.

## Project map

Use the nearest authoritative source instead of chat history:

- [`MASTER-SPEC.md`](./MASTER-SPEC.md) — canonical project purpose, scope, constraints, non-goals, security boundaries, and V1 success criteria.
- [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) — current technical architecture, component boundaries, protocol flows, persistence, deployment, and testing direction.
- [GitHub Issues](https://github.com/ach1992/mcp-gateway/issues) — active work, dependencies, acceptance criteria, risk, and task state.
- Pull requests and commits — implementation/review identity.
- CI — validation evidence for the exact candidate commit.

Conversation history is not required to recover or continue this project.

## Core architecture

```text
ChatGPT / remote MCP client
           |
           v
       MCP Gateway
       /    |     \
  Admin   Router   OAuth
           |
           v
   WP AI Bridge connector
      /      |      \
   Site A  Site B  Site C
```

Every routed site operation uses an explicit site identifier. WP AI Bridge and WordPress remain authoritative for WordPress permissions; the Gateway does not create extra WordPress authority.

## Status

The repository is in initial project bootstrap. Current implementation work is tracked in GitHub Issues; this README intentionally does not mirror live task status.