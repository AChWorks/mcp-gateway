# MCP Gateway

MCP Gateway is a small self-hosted web application that provides one stable MCP endpoint for connecting AI clients to multiple backend systems.

The first supported backend is [WP AI Bridge](https://github.com/ach1992/wp-ai-bridge). The goal is to let one ChatGPT custom MCP App work with many independently authorized WordPress sites instead of creating a separate ChatGPT App for every site.

## What it does

MCP Gateway is designed to provide:

- one public MCP endpoint for many connected sites;
- a small web panel for adding, connecting, testing, and removing sites;
- independent authorization for each WordPress site;
- explicit site selection for every routed operation;
- secure credential storage without storing WordPress passwords;
- compatibility with direct WP AI Bridge connections;
- room for additional MCP clients and backend connector types in future versions.

WP AI Bridge and WordPress remain responsible for WordPress permissions. The Gateway does not grant additional WordPress capabilities or bypass Bridge access controls.

## Planned V1 environment

MCP Gateway is intended to run as a conventional PHP web application on:

- PHP 8.4;
- MySQL;
- OpenLiteSpeed;
- aaPanel or an equivalent PHP hosting environment;
- HTTPS domain or subdomain;
- Composer-based installation.

V1 is intentionally lightweight. It does not require Redis, Docker, Node.js, queues, message brokers, or separate microservices for normal operation.

## Typical usage

The intended workflow is:

1. Install MCP Gateway on an HTTPS domain or subdomain.
2. Sign in to the Gateway administration panel.
3. Add a WordPress site that has WP AI Bridge installed.
4. Authorize the Gateway from that WordPress site.
5. Repeat for additional WordPress sites.
6. Connect one ChatGPT custom MCP App to the Gateway MCP endpoint.
7. Select the desired site explicitly when inspecting or executing site operations.

Each connected site keeps its own authorization and can be disconnected independently.

## Installation

MCP Gateway is currently under initial development and does not yet have a production-ready release or finalized installation procedure.

Installation and upgrade commands will be documented here once the first usable release is available. Until then, the repository should not be treated as a deployable production package.

## Status

Initial V1 development is in progress.

The first release will focus on the PHP 8.4 + MySQL + OpenLiteSpeed deployment model and multi-site WP AI Bridge connectivity.

## License

A license has not yet been published for the project. Do not assume reuse or redistribution terms until a license file is added.
