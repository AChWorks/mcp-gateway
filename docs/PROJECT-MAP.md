# Documentation guide

This index helps contributors and operators find the **appropriate maintained reference** without repeating its content. The public `README.md` introduces Gateway and points to installation/usage; product and engineering contracts live in the documents below.

## Product and engineering contracts

| Need | Read |
| --- | --- |
| Product purpose, supported operating principles, boundaries and enduring acceptance | [Master Specification](MASTER-SPEC.md) |
| Actual code layers, request paths, trust boundaries and extension seams | [Architecture](ARCHITECTURE.md) |
| Stable Target identity, connector registry/lifecycle and authorization rules | [Target and connector foundation](TARGET-CONNECTOR-FOUNDATION.md) |
| New provider/Target adapter integration and conformance | [Connector integration guide](CONNECTOR-INTEGRATION-GUIDE.md) |
| Result completeness, independently typed limits, file integrity and outcome uncertainty | [Remote I/O contract](REMOTE-IO-CONTRACT.md) |
| SSH trust, OS execution, Jobs and SFTP | [Direct SSH connector](DIRECT-SSH-CONNECTOR.md) |
| Authenticated SSH whole-file binary protocol and safety | [Whole-file exchange](WHOLE-FILE-EXCHANGE.md) |
| OAuth client-profile identity and recovery | [Client-profile runbook](CLIENT-PROFILE-RUNBOOK.md) |

## Running and maintaining Gateway

| Need | Read |
| --- | --- |
| Production installation, backup, update and incident recovery | [Deployment](DEPLOYMENT.md) |
| Supported environment settings and safe changes | [Configuration](CONFIGURATION.md) |
| Local development, tests and release-quality validation | [Development](DEVELOPMENT.md) |
| Reproducible disposable, installed WordPress/SSH integration tests | [Installed mixed acceptance runner](INSTALLED-MIXED-WP-SSH-ACCEPTANCE.md) |
| Shared Admin accessibility and visual rules | [Admin UI quality](ADMIN-UI-QUALITY.md) |
| Recover WordPress connection/revocation uncertainty | [Target disconnect recovery](TARGET-DISCONNECT-RECOVERY.md) |
| Owner-authorized local removal of an unreachable Target | [Offline Target removal](OFFLINE-TARGET-REMOVAL.md) |
| Upgrade an actual legacy Site-era installation with an explicit data reset | [Legacy Target transition runbook](TARGET-TRANSITION-RUNBOOK.md) |

## Authority and maintenance

- **Product intent** lives only in the Master Specification; **technical structure** in Architecture; **specific protocols, authorization and operations** in the appropriate specialist contract or runbook. Do not copy large requirement sections between them.
- **Implementation** is established by source code at the actual selected Git revision and its relevant tests; **unresolved acceptance and work** by open GitHub Issues; **candidate changes** by PRs and exact commit checks; **published artifacts** by releases; **installed behavior** by real host evidence. Do not maintain parallel dated status documents.
- A one-off release candidate, completed test diary or previous decision does not need another Markdown archive. Use Git/PR/Issue history and release evidence when provenance is genuinely relevant.
- New documents require a distinct reader and reusable task that an existing document cannot reasonably serve. A reference should direct the reader to a useful **contract or procedure**, not to proof that some unrelated milestone once happened.

Related systems own their own application/provider behavior; their repositories and controls do not become part of Gateway's writable scope just because the connectors interact with them.
