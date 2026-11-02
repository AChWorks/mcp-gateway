# Owner-enrolled Reverse SSH — operator runbook (Issue #267)

**Deployment is a separate approval gate.** This document contains illustrative
configuration ONLY: do not execute on production or a live target without a
specific Owner-approved change plan, measured impact, rollback and evidence.
Never reuse the manual experimental root/password forwarding session as a
persistent access channel.

## Architecture and two identities

An inbound-blocked **Target** can open an outbound OpenSSH control session to
the **NL Gateway server's SSH daemon**, using a dedicated non-root key. That
control session registers a **remote** listener on NL loopback only:

```text
Target host sshd (127.0.0.1:22, pinned host key)
          ^ localhost SSH endpoint (not NL)
          | remote-forwarded TCP data
Target ssh client (outbound OpenSSH -R; restricted key)
          | control SSH/TCP connection to NL sshd (separate pinned NL key)
NL sshd --> 127.0.0.1:24023 (one explicit loopback port)
          ^ local TCP connection
NL Gateway PHP/phpseclib --> original Target's pinned host key --> login --> command/SFTP/Jobs
```

There are **two different SSH authentications**. The **Target SSH client**
authenticates to NL as a limited **tunnel operator OS account**; Gateway
authenticates **through the forwarded socket to the original Target OS
username**, after checking its separately enrolled end-to-end **host-key pin**.
Neither credential nor key is shared between the two. NL sshd's
host key belongs only in the remote OpenSSH client's trusted known_hosts;
Gateway's pinned key belongs to the remote Target sshd.

The Target's Gateway identity stays its registered stable `target_id`, true
host, port, OS username and pin. NL loopback is **never reported as the
remote host IP**.

## One-time approvals and provisioning — do not execute without approval

For illustration ONLY, assume a named `example-target`, a unique NL loopback
port `24023`, a distinct account `gateway-reverse-example`, and a separately
approved operator label `example-forward`. Substitute verified values in an
approved change plan. Reserve one dedicated port/key/account policy per Target
to prevent accidental ownership collisions.

**NL SSHd configuration** should restrict that dedicated account to key-only
and remote forwarding with a single exact listener:

```text
Match User gateway-reverse-example
    AuthenticationMethods publickey
    PasswordAuthentication no
    AllowTcpForwarding remote
    PermitListen 127.0.0.1:24023
    GatewayPorts no
    PermitOpen none
    PermitTTY no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
```

Use a dedicated OS account without privileged interactive shell/sudo access.
Limit the account's `authorized_keys` entry to the single independently
verified **public** client key, e.g.:

```text
restrict,port-forwarding,permitlisten="127.0.0.1:24023" ssh-ed25519 AAAA... separately-verified-key
```

Do not use a broad `AllowTcpForwarding yes`, wildcard `PermitListen`,
`GatewayPorts clientspecified/yes`, root/password control authentication,
generic `ProxyJump`, or a network-wide loopback/SSRF exemption. Check the
effective restrictions with `sshd -T -C user=...,host=...,addr=...` for the
**approved** client and verify the listener binds exclusively to `127.0.0.1`
with the permitted OS identity. SSHd directives/key options and account
restrictions must be validated against the installed OpenSSH build before
application to a host. The listener is not a public SSH service.

**Target outbound tunnel** is operated by an ordinary approved OS user and a
purpose-specific private key, independent of Gateway Target credentials:

```bash
ssh -N -T -p 2222 \
  -i /home/reverse-initiator/.ssh/nl-reverse-key \
  -o BatchMode=yes -o IdentitiesOnly=yes \
  -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=/home/reverse-initiator/.ssh/known_hosts \
  -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=20 -o ServerAliveCountMax=3 \
  -R 127.0.0.1:24023:127.0.0.1:22 \
  gateway-reverse-example@gateway.example.test
```

The NL endpoint, port, remote username, trusted NL host-key entry and key path
must be operator verified before use. The command is an illustration: *never*
copy the sample port or host onto production unreviewed. `-R` has explicit
loopback listen and real remote 127.0.0.1:22 connect address; it is not a
third relay. Each side independently pins its *own* SSH host key.

For persistence, a separately approved systemd service on the **Target**
may use a persistent `ssh -NT -R ...` process with `Restart=always` and
`RestartSec=10`, `ExecStart` with exact parameters above, an unprivileged
`User`, and supervised bounded backoff. Establish log retention and ensure
`ExitOnForwardFailure` stops a failed port allocation. Autoreconnect and
reboot success must be demonstrated on specifically approved test hosts;
they are NOT established by the old interactive manual trial or isolated CI.

## NL Gateway configuration and Owner enrollment

An authorized NL operator adds exactly one mapping to its *private* local
`.env`, after actual account/port ownership is independently approved:

```dotenv
SSH_REVERSE_APPROVED_ROUTES='{"example-target":{"port":24023,"tunnel_identity":"example-forward"}}'
```

This is strict JSON (one unique listener per Target), not a global private-IP
allowlist. Refresh Laravel config cache using the installed release's normal
controlled change process. A missing, malformed, duplicated, revoked or
mismatched mapping blocks Reverse rather than dialing a fallback address.

In the Gateway Admin, the Owner enrolls the **real** Target endpoint and
its separately verified end-host public key, chooses **Owner-approved Reverse
SSH**, enters its unique port and operator label, and confirms their Owner
password. Configure Direct the same as before for Targets not using Reverse.
Registration never opens SSH. The **Verify SSH host and login** action proves
the Target's end-to-end pinned host key and credential across the approved
listener, without running a shell command. Command/SFTP/retained Job rights
still require exact Target authorization.

## Qualification, logs and rollback

Evidence required before separate production rollout: approved key/account
permissions, exact effective sshd configuration, `ss -lntp` loopback-only
ownership, operator-controlled systemd restart/reboot and idle recovery,
independent end-host public-key fingerprint, Gateway Verify result, command
and SFTP fixture, retained Job start/list/status/output/cancel under the same
original user/client/Target binding, listener-stop fail-closed behavior,
rejected wrong pins, audit/diagnostic references, and a route-rotation test
with unresolved Jobs. A green test run on GitHub alone is not runtime
qualification on an installed gateway.

Read-only troubleshooting **on authorized hosts only**: inspect the service
journal, OpenSSH auth logs, the tunnel client's `ExitOnForwardFailure`
messages, and the exact loopback TCP listener. A successful TCP handshake
to the listener does not prove that a client is connected or remote SSH
authentication succeeds. Distinguish `reverse_route_not_approved` (NL config
mismatch), `reverse_listener_conflict` (port already enrolled),
`reverse_listener_unavailable` (no listener), and `host_key_mismatch`
(wrong actual remote server, **no credential sent**). Do not disclose private
keys, passwords, signed sessions or private Target addresses in public Issues.

Rollback by authorized operators must first **pause effectful work**, inspect
any uncertain retained Jobs against the **original** route, and reconcile
remote spool and unit ownership without replay. Then rotate the Owner Target
back to Direct via the password/revision-gated form, remove the independent
NL allowlist mapping, stop the approved Target tunnel service, revoke its
dedicated key/account and listener using the agreed host change plan, and
verify no unexpected listener remains. The schema rollback refuses while
any Reverse route or retained Job exists; do not bypass journal protections.

No tunnel/account/systemd/SSHd/firewall modifications are performed by the
Gateway code or by this development PR.

Every change to the SSH endpoint, pin, username, authentication method, or
route increments the **monotonic binding revision**. Returning to a previous
Direct/Reverse configuration cannot resurrect an old Job's binding. Untouched
legacy Direct Targets keep their original encrypted credential and Job hash.
