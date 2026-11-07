# Connection Relays — simple native OpenSSH connection

**Status:** Source-only development. A successful CI check is not proof of an installed, working Gateway -> Relay -> Target link. This document replaces the older privileged helper / firewall / attestation protocol.

## Purpose

One reusable SSH intermediary can carry SSH/SFTP and WordPress HTTPS connections for several Targets. The Relay is **not** a new connector, a VPN, a Gateway security appliance or a per-Target tunnel. Its geographic location is irrelevant.

    Gateway PHP -> 127.0.0.1:<local-port> SOCKS5
        -> standard OpenSSH client (-N -D)
        -> standard SSHD on the Relay server
        -> Target TCP address
        -> normal SSH login / SFTP or HTTPS TLS + WordPress OAuth

The Gateway reuses its existing outbound destination checks and Target authentication. An enabled Target binding always keeps its chosen Relay unless the Owner changes it. If the Relay is disconnected, the Target's next connection/test receives a normal connection error; no custom failover, automatic Direct switching, new background retry policy or special renewal loop is implemented.

## One-time setup

1. Ensure the Gateway host has a standard OpenSSH client and the intermediary is reachable by SSH. The intermediary needs working SSHD and a login permitted to forward TCP connections; no Gateway-specific software or firewall management is required.
2. In **System > Connection Relays**, register the Relay ID, name, server/port, SSH account, *independently checked server public host key* and an unused Gateway local SOCKS5 port. Saving does not run a command.
3. Copy and run **Prepare a local SSH key and pinned host key** on the Gateway under the Unix account that will run the tunnel. The command uses per-Relay files in that account's \`~/.ssh/mcp-gateway-relays/\`. It prints the **public client key**; add it to the Relay SSH account's \`authorized_keys\`. Never put private keys in the web UI, Issue, logs or on the Relay.
4. Copy and run **Connect Gateway to Relay** on the Gateway. It uses \`ssh -N -T -D 127.0.0.1:<port>\` with the stored host-key pin, \`BatchMode\` and \`ExitOnForwardFailure\`. This runs in the foreground. Use an **existing** process manager/supervisor to keep the command running across terminal closure or reboot, according to that hosting environment. Gateway deliberately does not create systemd services, Unix users, firewall rules or hidden host resources.
5. In the Admin Relay card, choose **Test local Relay connection**. This checks only the SOCKS5 greeting and may run while disabled. Then **Enable Relay**. On SSH or WordPress Target creation/edit, select that Relay and test normal Target connectivity and authentication. Multiple Targets may select the same Relay.

**Important:** A pinned *server host key* authenticates the SSH intermediary; a separate *client key* is the Gateway's login to it. The Target's real SSH server key or HTTPS certificate/OAuth remains independently verified, just as for Direct.

## Everyday use and recovery

- **Connected:** use the Target normally; the Gateway's native clients send approved numeric destinations through the selected SOCKS5 route.
- **Disconnected / timeout / failure:** run Test again, inspect/restart the existing SSH process or normal Target connection, and retry. The feature does not pick another route automatically. If that Relay is unusable, the Owner can select a different registered Relay on the Target.
- **Edit host / port / account / pinned key / local SOCKS port:** Disable the Relay, stop its old SSH process, edit saved settings (assigned Targets may stay assigned), rerun the appropriate setup command and restart the SSH process. Then Enable and Test. No root-only rotation receipt or permanent lifecycle fence.
- **Rename:** change the display name without stopping the SSH process.
- **Disable:** stops Gateway routing through that Relay and invalidates stale Target binding epochs; it does not kill the OS SSH process. Assigned Targets stay assigned, and can be retested after re-enabling.
- **Delete:** Disable, explicitly detach/reassign all Targets, then confirm the exact Relay ID and Owner password and delete the Gateway registration. This does **not** need the intermediary reachable or a special host cleanup receipt. Stop the old SSH process and remove its files separately as appropriate. No remote resources are claimed to be removed.

## Operational boundaries

The generated SSH command binds TCP only to **127.0.0.1**. On a multi-tenant host, loopback does **not** prevent unrelated local Unix users from reaching that port. **This is a hosting trust consideration**, not a reason to build another Gateway firewall management framework. Use an adequately trusted host or existing OS isolation when that distinction matters.

A stored record, enabled flag or local SOCKS5 greeting is not proof of a successful Target connection. SSH/SFTP must still check the actual Target's pinned host key and login; WordPress HTTPS must check hostname, TLS certificate and OAuth credentials. Existing Direct and Reverse SSH connection modes must remain independent.

If an older experimental privileged \`connection-relay-gateway.py\` or \`connection-relay-peer.py\` installation exists on a **real host**, removing these files from source does **not** stop, upgrade or remove its old root-owned systemd/firewall/key resources. Do not blindly delete live host files: identify the actual existing instance and remove it using a separately approved, scoped host cleanup/migration plan. No such installation has been established or changed by this source refactor.

## Acceptance

- Real Gateway -> one standard OpenSSH intermediary -> two or more Targets, with SSH/SFTP and WordPress HTTPS tests on a permitted isolated environment.
- Normal disconnect, reconnect and retry, including a downed intermediary and explicit Owner-driven Relay change.
- Create, edit, enable, disable, test, Target binding/unbinding and delete without a custom privileged host protocol.
- Keep authentication, Owner permissions, client destination validation, existing Direct and Reverse SSH intact.
- Exact-candidate source tests and independent review before Owner-approved Merge. Production/privileged host deployment requires its own approval.

[Current work and accepted Owner decisions](https://github.com/AChWorks/mcp-gateway/issues/284)
