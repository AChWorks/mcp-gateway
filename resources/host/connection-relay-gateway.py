#!/usr/bin/env python3
"""Privileged, explicitly invoked Gateway-side Relay retirement helper.

This is NOT an SSH client installer or a remote Iran cleanup tool. Runtime
CLI paths are fixed; PHP never invokes it and cannot issue retirement proofs.
The expected fields come from the Owner-facing command and are checked against
owned resources. Do not use it to adopt third-party systemd/firewall state.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


class Refusal(Exception):
    pass


@dataclass(frozen=True)
class Relay:
    relay_id: str
    record_id: str
    fingerprint: str
    revision: int
    local_port: int

    def validate(self) -> None:
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?", self.relay_id):
            raise Refusal("Invalid Relay ID.")
        if not re.fullmatch(r"[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{26}", self.record_id):
            raise Refusal("Expected exact 26-character Relay record ULID.")
        if not re.fullmatch(r"[0-9a-f]{64}", self.fingerprint):
            raise Refusal("Invalid configuration fingerprint.")
        if not 1 <= self.revision <= 4294967295:
            raise Refusal("Invalid configuration revision.")
        if not 46000 <= self.local_port <= 60999:
            raise Refusal("Local SOCKS5 port outside the reserved range.")

    @property
    def firewall_table(self) -> str:
        return "mcp_gateway_relay_" + hashlib.sha256(self.record_id.encode()).hexdigest()[:12]

    @property
    def unit_name(self) -> str:
        return "mcp-gateway-relay-" + self.relay_id + ".service"


@dataclass(frozen=True)
class Layout:
    """Fixed production namespace; a test may inject a disposable root."""

    root: Path = Path("/")
    owner_uid: int = 0

    def at(self, relative: str) -> Path:
        return self.root / relative.lstrip("/")

    @property
    def evidence_dir(self) -> Path:
        return self.at("/etc/mcp-gateway/connection-relays")

    def evidence(self, relay: Relay, extension: str) -> Path:
        return self.evidence_dir / (relay.relay_id + extension)

    def unit(self, relay: Relay) -> Path:
        return self.at("/etc/systemd/system") / relay.unit_name

    def key_dir(self, relay: Relay) -> Path:
        return self.at("/var/lib/mcp-gateway-relays") / relay.relay_id

    def lock_path(self, relay: Relay) -> Path:
        return self.at("/run/mcp-gateway-relays") / (relay.relay_id + ".lock")


def trusted(path: Path, directory: bool, uid: int, required: bool = False) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        if required:
            raise Refusal("Missing expected host resource: " + str(path))
        return False
    if info.st_uid != uid or info.st_mode & 0o022:
        raise Refusal("Unsafe ownership/permissions: " + str(path))
    if directory and not stat.S_ISDIR(info.st_mode):
        raise Refusal("Unsafe non-directory path: " + str(path))
    if not directory and not stat.S_ISREG(info.st_mode):
        raise Refusal("Unsafe non-file path: " + str(path))
    return True


def owned_parents(path: Path, layout: Layout) -> None:
    # The production root and each new file parent are privileged namespaces.
    current = path
    while current != layout.root and current.is_relative_to(layout.root):
        if current.exists() or current.is_symlink():
            trusted(current, True, layout.owner_uid, True)
        current = current.parent


def make_privileged_directory(path: Path, layout: Layout) -> None:
    parents = []
    current = path
    while not current.exists() and not current.is_symlink():
        parents.append(current)
        if current == layout.root:
            break
        current = current.parent
    trusted(current, True, layout.owner_uid, True)
    for folder in reversed(parents):
        folder.mkdir(mode=0o755)
        trusted(folder, True, layout.owner_uid, True)
    owned_parents(path, layout)


def run_checked(argv: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv, capture_output=True, text=True, timeout=12, check=False,
            env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Refusal("Local tool is unavailable or timed out: " + argv[0]) from error


class Retirement:
    def __init__(
        self, relay: Relay, layout: Layout = Layout(),
        run: Callable[[list[str]], subprocess.CompletedProcess[str]] = run_checked,
    ):
        relay.validate()
        self.relay = relay
        self.layout = layout
        self.run = run

    def _owned(self, path: Path, directory: bool = False) -> bool:
        return trusted(path, directory, self.layout.owner_uid)

    def _json(self, path: Path, max_bytes: int = 4096) -> dict:
        if not self._owned(path):
            raise Refusal("Missing expected root-owned host record: " + str(path))
        if path.stat().st_size > max_bytes:
            raise Refusal("Host record too large: " + str(path))
        try:
            data = json.loads(path.read_text(encoding="utf8"))
        except (OSError, UnicodeError, ValueError) as error:
            raise Refusal("Invalid host record: " + str(path)) from error
        if not isinstance(data, dict):
            raise Refusal("Invalid host record object: " + str(path))
        return data

    def _manifest(self) -> dict | None:
        path = self.layout.evidence(self.relay, ".managed.json")
        if not self._owned(path):
            return None
        manifest = self._json(path)
        expected = {
            "version": 1,
            "relay_record_id": self.relay.record_id,
            "relay_id": self.relay.relay_id,
            "service_unit": self.relay.unit_name,
            "firewall_table": self.relay.firewall_table,
        }
        for key, value in expected.items():
            if manifest.get(key) != value:
                raise Refusal("Managed host resource ownership does not match this Relay: " + key)
        port = manifest.get("local_socks_port")
        if not isinstance(port, int) or not 46000 <= port <= 60999:
            raise Refusal("Invalid local port in managed host claim.")
        if set(manifest) != set(expected) | {"local_socks_port"}:
            raise Refusal("Unrecognized fields in managed host claim.")
        return manifest

    def _check_unmanaged_namespaces(self, managed: dict | None) -> None:
        unit = self.layout.unit(self.relay)
        keydir = self.layout.key_dir(self.relay)
        if managed is None and (unit.exists() or unit.is_symlink() or
                                keydir.exists() or keydir.is_symlink()):
            raise Refusal("Owned-style service/key namespace exists without a root-owned matching claim. Refusing to adopt it.")
        if managed is None and self._nft_table_exists():
            raise Refusal("Relay firewall table exists without a root-owned matching claim.")
        if managed is None and any(
            self.layout.evidence(self.relay, ext).exists()
            or self.layout.evidence(self.relay, ext).is_symlink()
            for ext in (".policy", ".json")
        ):
            raise Refusal(
                "Unclaimed active host evidence exists. Reconcile the legacy "
                "manual transport locally before claiming complete cleanup."
            )
        if managed is not None:
            if self._owned(unit):
                # Ownership alone is insufficient: refuse unrelated unit bodies.
                marker = "# MCP-GATEWAY-CONNECTION-RELAY " + self.relay.record_id + " " + self.relay.relay_id
                if marker not in unit.read_text(encoding="utf8", errors="replace").splitlines():
                    raise Refusal("Unexpected systemd unit content for this Relay.")
            if self._owned(keydir, True):
                # The next setup helper must keep this privileged namespace
                # bounded. Never use recursive deletion on unknown files.
                known = {"control_key", "control_key.pub", "known_hosts", "owner.json"}
                for entry in keydir.iterdir():
                    if entry.name not in known or not self._owned(entry):
                        raise Refusal("Unknown or unsafe Relay private file: " + str(entry))

    def _nft_table_exists(self) -> bool:
        response = self.run(["nft", "-j", "list", "tables"])
        if response.returncode != 0:
            raise Refusal("Cannot inspect nftables: " + response.stderr[:140])
        try:
            data = json.loads(response.stdout)
            if not isinstance(data, dict) or not isinstance(data.get("nftables"), list):
                raise Refusal("Invalid nftables inventory structure.")
            return any(
                isinstance(x, dict)
                and isinstance(x.get("table"), dict)
                and x["table"].get("family") == "inet"
                and x["table"].get("name") == self.relay.firewall_table
                for x in data["nftables"]
            )
        except (ValueError, AttributeError) as error:
            raise Refusal("Invalid nftables inventory.") from error

    def _unit_active(self) -> bool:
        result = self.run(["systemctl", "is-active", self.relay.unit_name])
        if result.returncode == 0 and result.stdout.strip() == "active":
            return True
        if result.stdout.strip() in {"inactive", "failed", "unknown"} and result.returncode != 0:
            return False
        # systemd's unknown/not-found exit often has no output or 4; verify
        # exact states instead of pretending transport failure is inactivity.
        if result.returncode in {3, 4} and result.stdout.strip() in {"", "inactive", "failed", "unknown"}:
            return False
        raise Refusal("Cannot prove Relay systemd service is inactive.")

    def _unit_enabled(self) -> bool:
        result = self.run(["systemctl", "is-enabled", self.relay.unit_name])
        state = result.stdout.strip()
        if state in {"enabled", "enabled-runtime", "linked", "linked-runtime", "alias"}:
            return True
        if state in {"disabled", "masked", "masked-runtime", "static", "not-found"}:
            return False
        if result.returncode in {1, 3, 4} and state in {"", "unknown"}:
            return False
        raise Refusal("Cannot prove the Relay systemd service cannot restart automatically.")

    def _listening(self, ports: set[int]) -> bool:
        result = self.run(["ss", "-H", "-lnt"])
        if result.returncode != 0:
            raise Refusal("Cannot inspect local TCP listeners.")
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) < 4:
                raise Refusal("Malformed local TCP listener inventory.")
            local = fields[3]
            if any(local.endswith(":" + str(port)) for port in ports):
                return True
        return False

    def _preflight(self) -> dict | None:
        self.relay.validate()
        owned_parents(self.layout.evidence_dir, self.layout)
        owned_parents(self.layout.unit(self.relay).parent, self.layout)
        self._owned(self.layout.evidence_dir, True)
        for ext in [".managed.json", ".policy", ".json", ".retired.json"]:
            self._owned(self.layout.evidence(self.relay, ext))
        owned_parents(self.layout.key_dir(self.relay), self.layout)
        managed = self._manifest()
        self._check_unmanaged_namespaces(managed)
        evidence = self.layout.evidence(self.relay, ".json")
        if self._owned(evidence) and self._json(evidence).get("relay_id") != self.relay.relay_id:
            raise Refusal("Host attestation does not belong to this Relay.")
        return managed

    def preview(self) -> str:
        managed = self._preflight()
        return (
            "LOCAL PREVIEW: Relay=" + self.relay.relay_id
            + ", resource claim=" + ("verified" if managed else "absent")
            + ", active unit=" + ("yes" if self._unit_active() else "no")
            + ", reserved listener=" + ("present" if self._listening({self.relay.local_port}) else "absent")
            + ". No remote Iran access is attempted."
        )

    def retire(self) -> str:
        if os.geteuid() != self.layout.owner_uid:
            raise Refusal("Explicit root/sudo privileges are required.")
        make_privileged_directory(self.layout.evidence_dir, self.layout)
        make_privileged_directory(self.layout.lock_path(self.relay).parent, self.layout)
        lockpath = self.layout.lock_path(self.relay)
        if self._owned(lockpath):
            pass
        # O_NOFOLLOW and trusted root-owned parents prevent a link escape.
        fd = os.open(lockpath, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            if not self._owned(lockpath):
                raise Refusal("Unsafe Relay lock ownership.")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            managed = self._preflight()
            unit = self.layout.unit(self.relay)
            ports = {self.relay.local_port}
            if managed:
                ports.add(managed["local_socks_port"])
                # Check ownership of every managed artifact *before* side effects.
                if self._owned(unit) or self._unit_active():
                    stopped = self.run(["systemctl", "disable", "--now", self.relay.unit_name])
                    if stopped.returncode != 0:
                        raise Refusal("Could not stop/disable the exact Relay service; inspect systemd and retry.")
                if self._unit_active():
                    raise Refusal("Relay systemd service remains active after stop.")
                # Keep the deny/allow firewall ACL in effect until the
                # listener is proven gone. Otherwise an unknown process
                # could keep an open proxy while the ACL is removed.
                if self._listening(ports):
                    raise Refusal("A local listener remains after stop. Firewall ACL was preserved.")
                if self._nft_table_exists():
                    removed = self.run(["nft", "delete", "table", "inet", self.relay.firewall_table])
                    if removed.returncode != 0:
                        raise Refusal("Could not delete the owned Relay nftables table.")
                if self._nft_table_exists():
                    raise Refusal("Relay firewall table still exists after deletion.")
                if self._listening(ports):
                    raise Refusal("A local port is still listening; do not issue false cleanup evidence.")
                if self._owned(unit):
                    unit.unlink()
                # A prior interrupted attempt may have unlinked the unit
                # before reload completed. Repeat reload even when missing
                # so stale systemd unit caches cannot strand recovery.
                daemon = self.run(["systemctl", "daemon-reload"])
                if daemon.returncode != 0:
                    raise Refusal("systemd daemon-reload failed; retry cleanup.")
                if self._unit_enabled():
                    raise Refusal("Relay systemd service remains enabled after local cleanup.")
                keydir = self.layout.key_dir(self.relay)
                if self._owned(keydir, True):
                    for entry in list(keydir.iterdir()):
                        if not self._owned(entry):
                            raise Refusal("Unsafe Relay key file.")
                        entry.unlink()
                    keydir.rmdir()
                self.layout.evidence(self.relay, ".managed.json").unlink()
            else:
                if self._unit_active():
                    raise Refusal("A Relay service is still active without a recognized owned claim.")
                if self._listening(ports):
                    raise Refusal("SOCKS5 listener is still active; refuse false retirement proof.")
            for ext in [".json", ".policy"]:
                path = self.layout.evidence(self.relay, ext)
                if self._owned(path):
                    path.unlink()
            if self._unit_active() or self._unit_enabled() or self._nft_table_exists() or self._listening(ports):
                raise Refusal("Cleanup verification did not reach the disabled/inactive/absent state.")
            self._receipt()
            return ("RETIREMENT VERIFIED for Gateway Relay " + self.relay.relay_id
                    + ". Iran was not contacted, and its cleanup was not asserted.")
        except BlockingIOError as error:
            raise Refusal("Another operator is changing this Relay; do not overlap operations.") from error
        finally:
            os.close(fd)

    def _receipt(self) -> None:
        boot = self.layout.at("/proc/sys/kernel/random/boot_id").read_text().strip()
        uptime = self.layout.at("/proc/uptime").read_text().split()[0]
        if not re.fullmatch(r"[a-f0-9-]{36}", boot):
            raise Refusal("Invalid live boot identity.")
        try:
            seconds = int(uptime.split(".")[0])
        except ValueError as error:
            raise Refusal("Invalid boot uptime.") from error
        now = int(time.time())
        proof = {
            "relay_record_id": self.relay.record_id,
            "relay_id": self.relay.relay_id,
            "host_fingerprint": self.relay.fingerprint,
            "configuration_revision": self.relay.revision,
            "verified_boot_id": boot,
            "verified_at_unix": now,
            "verified_at_boot_seconds": seconds,
            "expires_at_unix": now + 600,
            "gateway_cleanup_verified": True,
        }
        output = self.layout.evidence(self.relay, ".retired.json")
        fd, tempname = tempfile.mkstemp(prefix=".relay-retired-", dir=output.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as dest:
                json.dump(proof, dest, sort_keys=True, separators=(",", ":"))
                dest.write("\n")
                dest.flush()
                os.fsync(dest.fileno())
            os.replace(tempname, output)
            parent_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        finally:
            if os.path.lexists(tempname):
                os.unlink(tempname)


def main() -> int:
    parser = argparse.ArgumentParser(description="MCP Gateway local-only Relay retirement; never contacts Iran.")
    parser.add_argument("action", choices=("preflight", "retire"))
    parser.add_argument("--relay-id", required=True)
    parser.add_argument("--record-id", required=True)
    parser.add_argument("--fingerprint", required=True)
    parser.add_argument("--revision", required=True, type=int)
    parser.add_argument("--local-port", required=True, type=int)
    args = parser.parse_args()
    try:
        relay = Relay(args.relay_id, args.record_id, args.fingerprint, args.revision, args.local_port)
        layout = Layout()
        if os.geteuid() != 0:
            raise Refusal("Run this trusted installed helper explicitly with sudo/root.")
        operation = Retirement(relay, layout)
        print(operation.preview() if args.action == "preflight" else operation.retire())
        return 0
    except (Refusal, OSError, UnicodeError) as error:
        print("FAIL CLOSED: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
