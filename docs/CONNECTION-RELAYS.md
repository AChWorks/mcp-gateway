# Connection Relays — owner/operator runbook (Issue #284)

**Source under review; not deployed.** Production host setup, firewall edits, SSH identity creation, installation, migrations, integration and release require distinct approvals and verification. A saved Relay alone does not mean a tunnel is running or that the actual Target is authenticated.

## Intent and architecture

Connection Relay is a reusable per-Target transport route, not a third connector, a per-Target tunnel, a generic HTTP proxy or a VPN. Direct remains the default. Existing Managed and Manual Reverse SSH remain intact and cannot be combined with the new Relay for the same SSH Target.

    Gateway dedicated PHP-FPM UID -> 127.0.0.1:<relay-SOCKS-port>
    -> restricted Gateway OpenSSH client -D -> Iran restricted SSH control user
    -> validated numeric public Target IP:port
    -> end-to-end SSH host-key pin or HTTPS TLS SNI and certificate check

Each Relay requires one control-plane SSH identity/key completely distinct from the Target login credential and the existing Reverse SSH control identities. The Gateway performs bounded public DNS and numeric destination approval locally, sends only numeric SOCKS5 CONNECT, preserves the real SSH Target host key or HTTPS certificate, and never treats the SOCKS reply as verified remote peer identity. No automatic fallback to Direct. Only deliberate Target operations use a relay; ChatGPT signed-file ingress and unrelated Gateway services remain Direct.

## User workflow

1. Open **System > Connection Relays**. Register stable Relay ID, display name, Iran control SSH endpoint and independently verified *public* SSH host key, dedicated user and reserved NL local SOCKS5 port (46000–60999). The metadata is saved disabled, without changing hosts.
2. Obtain separately authorized host setup. The privileged operator provisions dedicated identities, daemon and ACL below. Only the *public* client key may be sent to Iran; private keys stay out of the web root and logs. Perform isolation/egress/host-key tests before the operator signs a root-owned attestation.
3. Enable with the Owner password. The app rejects missing or stale attestation and does not claim remote connectivity. The optional control listener test checks only that SOCKS5 responds.
4. On **Targets > Add Target**, choose SSH or WordPress connector, then optionally a ready Relay, and confirm Owner password. For SSH, choose Direct rather than Managed/Manual Reverse. Authenticate/test the actual Target separately.
5. On Target Edit, change route only after disconnect and reconciliation. The Owner/password-gated workflow increments a persistent route epoch and re-seals SSH login secret. WordPress requires no active OAuth credential/flow/refresh/revoke intent. A->B->A cannot reactivate historical retained SSH Jobs.
6. Disabling a Relay fails closed and fences every bound Target. Repair/reenable does not silently declare Targets Connected.

## Required separate NL host approval

The inspected NL Gateway host shares one PHP-FPM Unix UID with several other websites. A loopback-only SOCKS5 listener is **not isolated** in this arrangement. Approval to use this feature must include a deployment-specific host change plan and rollback. In order:

- Give Gateway its own dedicated non-root PHP-FPM pool and UID, not shared with any unrelated website or the SSH control client. Its PHP CLI scheduler/queue must run with the same appropriately isolated identity, or dedicated owner-verified equivalent to avoid failed route attestations. Verify real process credentials, application paths and permissions; retain safe return to previous PHP pool. Do not weaken other sites.
- Create a distinct low-privilege SSH client identity, Ed25519 control key in root-controlled non-web directory, pinned independently obtained Iran SSHD public host key, and supervised systemd client connecting NL -> Iran using sessionless OpenSSH dynamic local SOCKS5. Use BatchMode, IdentitiesOnly, StrictHostKeyChecking, ExitOnForwardFailure, ServerAlive, and a fixed bind of 127.0.0.1:port only. Do not edit the current dedicated Reverse SSHD instance or its port.
- Extend the **existing** nftables/iptables/aaPanel firewall with narrowly owned rules: only the dedicated Gateway PHP UID can connect to this exact loopback port; unrelated UIDs are denied. An output-chain socket UID condition is an implementation possibility, **not an approved production command**. Prove the actual firewall order, IPv4/IPv6 scope, persistence and rollback before use. Reject or drop access from all unrelated site Unix identities, even if they can open localhost TCP sockets. Do not turn off the host firewall to simplify setup.
- Verify in different *actual OS identities* that Gateway PHP can connect and unrelated websites cannot; allow the root-owned attestation path through any effective PHP open_basedir policy without relaxing other filesystem restrictions; ensure rules survive daemon restart/reboot and are enforced before the SOCKS client starts. Check a downed tunnel fails without Direct, without opening public listeners.

## Required separate Iran host approval

Install a dedicated non-root, public-key-only SSH control user, no shell/TTY/password/sudo, agent/X11/StreamLocal forwarding or unrelated authorized keys. Require SSH local forwarding only; validate effective sshd settings and relevant per-key policy with the actual OpenSSH build. Dynamic -D connects via direct-tcpip. PermitOpen applies to fixed destinations, but shared future Target routing may require several hosts and ports. Therefore restrict this principal using an independently approved Iran host/network egress policy to the intended TCP ports and public IP space, denying loopback, RFC1918, link-local, metadata, multicast, local and reserved addresses. Test permitted and denied cases, concurrency, restart and log fidelity. Gateway public-IP SSRF policy is mandatory second-layer validation, not a substitute for host ACL.

Iran setup must not require the Iran server to download a script from NL or foreign CDN. Use an independently available transfer path for approved code/public keys, with pinned checksum and provenance. Never store Relay private keys, password or opaque credentials in GitHub issue comments, web forms or normal diagnostic logs.

## Root-owned readiness evidence

The Admin backend reads **two** independently privileged, root-owned files for each Relay:

    /etc/mcp-gateway/connection-relays/<relay-id>.policy
    /etc/mcp-gateway/connection-relays/<relay-id>.json

The parent directories and both files must be root-owned, non-symlink and not group/world writable. The `.policy` file is a single fresh, unpredictable 256-bit generation (64 lowercase hex characters, optional trailing newline). A privileged operator rotates it **before** changing the relevant FPM/CLI identity, service, SSH principal, firewall, routing, egress or binding policy. Host operations must fail closed until post-change verification and renewed evidence. Neither file is written by the Gateway PHP process.

The manifest has exactly **10** keys (illustrative schema, not real values; never copy as-is):

    {
      "relay_id": "iran-1",
      "host_fingerprint": "<current 64-hex configuration fingerprint>",
      "gateway_php_uid": 1001,
      "dedicated_php_uid_verified": true,
      "socks_access_acl_verified": true,
      "relay_egress_verified": true,
      "verified_boot_id": "<current /proc/sys/kernel/random/boot_id UUID>",
      "policy_generation": "<identical 64-hex content of relay-id.policy>",
      "verified_at_unix": 1793822400,
      "expires_at_unix": 1793865600
    }

The manifest is accepted only while the actual PHP effective UID matches, the running Linux boot ID and policy generation match, its verification timestamp is not in the future (except up to 60 seconds of clock tolerance), its age is under 24 hours, and its expiry is strictly in the future, within 24 hours of verification. The privileged verifier must regularly re-check the effective host controls and renew the manifest **before** expiry; no PHP action may silently renew or infer that effective firewall enforcement is intact. A reboot always invalidates the prior boot's manifest. Independent host configuration drift must trigger policy rotation and re-verification even if the short lease has not yet expired; **static file checks alone cannot detect unreported host drift**.

`host_fingerprint` is generated by `ConnectionRelay::hostFingerprint()` from the immutable Relay identity, endpoint, control key, local port and `configuration_revision`, separated with NUL bytes; it is **not** a login-key fingerprint. Every effective Enable or Disable advances the separate monotonic `lifecycle_revision` used by Owner action forms, invalidating prepared Enable/Disable requests after any intervening action. Each effective Disable also advances `configuration_revision` and atomically fences bound Targets, invalidating the old host manifest. Enable does **not** change the attested configuration fingerprint; the independently verified manifest remains current for the same unchanged host policy until expiry. Re-enabling after a Disable requires a new privileged verification and manifest for the new configuration fingerprint. A repeated Disable while already disabled is a no-op only with the latest lifecycle revision. No production host setup, verifier implementation, attestation or socket supervision is provided by this application source; the host operator owns their separate approval, persistence, exact host policy and recovery.

## Acceptance, diagnostics and rollback

- Record three separate states: saved/disabled or enabled, host attestation and local SOCKS greeting, then successful end-to-end Target authentication. A SOCKS greeting alone cannot greenlight an SSH/WordPress Target.
- Validate real Target SSH host-key mismatch before login; HTTPS TLS hostname and SNI; DNS rebinding/non-public DNS refusal; denied egress; request size/deadline; retained Job and stale OAuth outcome fencing; reconnection/reboot; multiple simultaneous Targets.
- A failed/missing Relay blocks only its selected Targets, with a specific diagnostic and no Direct fallback. Do not auto-retry effectful remote operations after uncertain dispatch.
- Rollback: disable Relay via Owner UI first to fence Target epochs; independently verify pending Job/OAuth outcome reconciliation; stop only that Relay's controlled service; remove only positively owned host firewall rules, identity, key and attestation under separate authorization. Do not roll back DB columns while historical epoch-bound Target entries or retained SSH Jobs exist.
- **Gates:** full source diff + exact-head CI + independent high-assurance review; separate authorized NL/Iran host preflight, rollout and real end-to-end tests; explicit Owner merge/deploy approval. No production claim before those facts exist.
