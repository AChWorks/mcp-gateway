# Connection Relays — two complete host commands

**Version scope:** This describes the candidate after v2.6.0, not the currently published release. Do not assume these instructions work on an installed Gateway until the source has been independently reviewed, released and installed. See [Issue #284](https://github.com/AChWorks/mcp-gateway/issues/284).

## How Relay routing works

Gateway PHP → localhost SOCKS5 → native OpenSSH on the Gateway → existing intermediary SSHD → selected SSH/SFTP or WordPress HTTPS Target. Multiple Targets may share one intermediary. A Target that selects a Relay never silently falls back to Direct on failure; Direct SSH and Reverse SSH remain separate connection modes.

## First-time setup

1. On the intended Relay server, confirm that an existing SSH account and the selected port permit SSH key login and TCP forwarding. Get the server's **public SSH host key** using its trusted local console; for an existing Ed25519 SSHD key, run:
   ```bash
   sudo awk '{print $1, $2}' /etc/ssh/ssh_host_ed25519_key.pub
   ```
   Compare its SHA256 fingerprint independently before trusting it. A network scan alone is not identity verification. This key identifies the SSHD server; it is **not** the Gateway client login key.
2. In **System → Connection Relays**, enter Relay ID, name, SSH endpoint/port, existing Unix username, verified public **server** host key, and unused Gateway-local SOCKS5 port. Save as Owner. The Gateway generates an Ed25519 client **login** keypair; its private half remains encrypted with the Gateway APP_KEY and never appears on the page or in the two commands. For a Relay registered before this feature, use the Owner-approved **Prepare the two complete setup commands** button; it does not modify an existing running tunnel.
3. Copy **Command 1 — run on Relay server** and run it in a trusted shell on the intermediary. It installs the generated public **client** login key into that existing account's authorized_keys, without overwriting other entries or changing the system SSHD.
4. Copy **Command 2 — run on Gateway server** and run it in a trusted shell on the Gateway, never on the intermediary. It selects an already-installed compatible PHP CLI and runs the Gateway's own Artisan installer with sudo. This reads the encrypted login key locally, writes a protected SSH identity and independently pinned server key under /etc/mcp-gateway-relays/ID, installs an OpenSSH systemd service, starts it and enables startup after reboot. Neither command requires a manual key copy between machines or an open terminal afterward.
5. Select **Test local Relay connection**, then **Enable Relay for Targets**, and verify the real SSH/SFTP or WordPress Target separately. An Enabled registration is only a route choice; local SOCKS5 success is not Target authentication.

### Prerequisites and expected failures

The Relay host must already have SSHD, the named Unix account, permission for public-key login, and TCP forwarding. The Gateway host must already have OpenSSH client, an application-compatible CLI PHP, a functioning systemd service manager and the appropriate sudo rights. The two commands do not install/change SSHD, firewall or user accounts. Missing prerequisites generate explicit errors; do not claim unattended setup where they are absent.

**Port conflict:** A pre-existing manually started foreground SSH tunnel may still use the selected SOCKS5 port. The new Gateway installer refuses to take over the port when it does not already own the service. Stop only that exact old task-owned foreground process, verify the port is free, then rerun the single Gateway command. Do not stop unrelated services.

## Operating and removing a Relay

- A successful persistent service is named mcp-gateway-relay-ID.service on the **Gateway** host. It starts after reboot and restarts on ordinary SSH process failure. Inspect its exact status and logs with systemctl status and journalctl -u when diagnosing issues.
- To edit routing details, Disable Relay in Admin, edit the endpoint/host key/port and rerun the applicable complete commands. The Gateway command is idempotent and updates its **own** service configuration. Always independently verify a changed SSHD host key.
- Disable in Gateway Admin blocks new routed Target operations but deliberately does **not** stop the host SSH service; existing Target selections remain. This distinction prevents silent Direct fallback.
- To permanently delete a Relay record, Disable it and deliberately detach/reassign its Targets, then confirm exact ID and Owner password. A successful Gateway DB deletion does **not** assert that any host service or authorized_keys entry was removed, or require contacting the intermediary. Stop and remove the exact known host-owned service, key and authorized_keys entry separately under authorized host maintenance, without touching unrelated services or keys.
- Existing pre-v2.6 experimental helper/firewall/root-owned host resources, if installed, are not managed by this new native OpenSSH flow. Identify and reconcile them separately; never blindly delete live host-owned files.

## Security and acceptance boundary

A pinned **Relay SSHD host key** authenticates the intermediary. The real SSH Target key or WordPress TLS/OAuth remains independently validated after the SOCKS5 hop. Binding to 127.0.0.1 does not isolate other local Unix users on a shared host; use existing OS isolation if the environment requires it. Preserve encrypted keys and APP_KEY together for recovery. Never send private login credentials through the web form, terminal chat, or logs.

**Still to verify for this candidate:** real two-command installation on isolated hosts, terminal closure and reboot recovery, SSH/SFTP/WordPress authenticated Target operations, no-Direct fallback, safe offline deletion, and independently reviewed exact-candidate release. A source test or Release does not prove a Production deployment.

[Issue #284: Connection Relay acceptance](https://github.com/AChWorks/mcp-gateway/issues/284) · [Issue #303: Admin UI issues](https://github.com/AChWorks/mcp-gateway/issues/303)
