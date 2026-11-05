#!/usr/bin/python3
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
import secrets
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

    def fence(self, relay: Relay) -> Path:
        # A durable per-record tombstone: an old CLI command must stay
        # fenced even after the DB row is deleted or a Relay ID is reused.
        return self.evidence_dir / ".fences" / (relay.record_id + ".json")


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


def make_privileged_directory(
    path: Path, layout: Layout, php_traversable: bool = False,
) -> None:
    parents = []
    current = path
    while not current.exists() and not current.is_symlink():
        parents.append(current)
        if current == layout.root:
            break
        current = current.parent
    trusted(current, True, layout.owner_uid, True)
    for folder in reversed(parents):
        # mkdir is umask-sensitive. Ensure fresh evidence directories can be
        # traversed by the unprivileged PHP UID (receipt carries no secrets);
        # keep runtime locks private to root.
        mode = 0o755 if php_traversable else 0o700
        folder.mkdir(mode=mode)
        folder.chmod(mode)
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
            "version": 2,
            "relay_record_id": self.relay.record_id,
            "relay_id": self.relay.relay_id,
            "service_unit": self.relay.unit_name,
            "firewall_table": self.relay.firewall_table,
            "host_fingerprint": self.relay.fingerprint,
            "configuration_revision": self.relay.revision,
        }
        for key, value in expected.items():
            if manifest.get(key) != value:
                raise Refusal("Managed host resource ownership does not match this Relay: " + key)
        port = manifest.get("local_socks_port")
        if not isinstance(port, int) or not 46000 <= port <= 60999:
            raise Refusal("Invalid local port in managed host claim.")
        integrity = {"unit_sha256", "unit_exec_sha256", "firewall_sha256", "host_generation"}
        if set(manifest) != set(expected) | {"local_socks_port"} | integrity:
            raise Refusal("Managed host claim must include exact v2 resource digests and generation.")
        if any(not isinstance(manifest[k], str)
               or re.fullmatch(r"[a-f0-9]{64}", manifest[k]) is None
               for k in integrity):
            raise Refusal("Invalid resource checksum or host generation in managed claim.")
        generation = self._generation()
        if (generation is None or generation["state"] != "provisioning"
            or manifest["host_generation"] != generation["host_generation"]):
            raise Refusal("Managed host claim does not match a provisioning host generation.")
        return manifest

    def _generation(self) -> dict | None:
        path = self.layout.evidence(self.relay, ".generation.json")
        if not self._owned(path):
            return None
        value = self._json(path, 1024)
        expected = {"version", "relay_record_id", "relay_id", "host_generation", "state"}
        if (set(value) != expected or value["version"] != 1
            or value["relay_record_id"] != self.relay.record_id
            or value["relay_id"] != self.relay.relay_id
            or not isinstance(value["host_generation"], str)
            or re.fullmatch(r"[0-9a-f]{64}", value["host_generation"]) is None
            or value["state"] not in {"provisioning", "retired"}):
            raise Refusal("Invalid or mismatched root-owned Relay host generation record.")
        return value

    def _fence(self) -> dict | None:
        path = self.layout.fence(self.relay)
        owned_parents(path.parent, self.layout)
        if not self._owned(path.parent, True):
            return None
        if not self._owned(path):
            return None
        fence = self._json(path, 1024)
        expected = {"version", "relay_record_id", "relay_id", "host_fingerprint",
                    "configuration_revision", "host_generation", "intent"}
        if (set(fence) != expected or fence["version"] != 1
            or fence["relay_record_id"] != self.relay.record_id
            or fence["relay_id"] != self.relay.relay_id
            or fence["intent"] not in {"delete", "rotate"}
            or not isinstance(fence["configuration_revision"], int)
            or not 1 <= fence["configuration_revision"] <= 4294967295
            or not isinstance(fence["host_fingerprint"], str)
            or re.fullmatch(r"[a-f0-9]{64}", fence["host_fingerprint"]) is None
            or not isinstance(fence["host_generation"], str)
            or re.fullmatch(r"[a-f0-9]{64}", fence["host_generation"]) is None):
            raise Refusal("Invalid or unowned durable Relay lifecycle fence.")
        return fence

    def _require_mutable_revision(self) -> None:
        fence = self._fence()
        if fence and (fence["intent"] == "delete"
                      or self.relay.revision <= fence["configuration_revision"]):
            raise Refusal("This Relay record/revision was permanently fenced; stale operator commands cannot provision it.")

    def _write_json_atomic(self, path: Path, payload: dict) -> None:
        # Root-owned, world-readable non-secret host state. Never overwrite
        # an untrusted inode/symlink; existing ancestors are root-controlled.
        self._owned(path)
        fd, tempname = tempfile.mkstemp(prefix=".relay-host-", dir=path.parent)
        try:
            with os.fdopen(fd, "w") as dest:
                json.dump(payload, dest, sort_keys=True, separators=(",", ":"))
                dest.write("\n")
                dest.flush()
                os.fchmod(dest.fileno(), 0o644)
                os.fsync(dest.fileno())
            os.replace(tempname, path)
            parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        finally:
            if os.path.lexists(tempname):
                os.unlink(tempname)

    def _advance_generation(self, state: str) -> str:
        self._generation()
        token = secrets.token_hex(32)
        self._write_json_atomic(
            self.layout.evidence(self.relay, ".generation.json"),
            {"version": 1, "relay_record_id": self.relay.record_id,
             "relay_id": self.relay.relay_id, "host_generation": token,
             "state": state},
        )
        return token

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
        if managed is None:
            # A previously loaded or foreign same-name systemd definition
            # may survive even when no owned unit file exists on disk.
            self._assert_no_loaded_same_name_unit()
        if managed is not None:
            if self._owned(unit):
                marker = "# MCP-GATEWAY-CONNECTION-RELAY " + self.relay.record_id + " " + self.relay.relay_id
                if marker not in unit.read_text(encoding="utf8", errors="replace").splitlines():
                    raise Refusal("Unexpected systemd unit content for this Relay.")
                if hashlib.sha256(unit.read_bytes()).hexdigest() != managed["unit_sha256"]:
                    raise Refusal("Owned systemd unit bytes differ from the claimed immutable definition.")
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

    @staticmethod
    def _canonical_exec(value: str) -> str:
        # systemctl show ExecStart includes volatile start/stop times, PID,
        # exit code and status. Digest ONLY the fixed executable, argv and
        # ignore_errors of the one reviewed OpenSSH process. Unknown formats
        # or multiple ExecStart actions fail closed.
        if not value.startswith("{ ") or not value.endswith(" }"):
            raise Refusal("Unrecognized effective systemd ExecStart format.")
        tokens = value[2:-2].split(" ; ")
        keys = ("path", "argv[]", "ignore_errors", "start_time",
                "stop_time", "pid", "code", "status")
        if len(tokens) != len(keys):
            raise Refusal("Unexpected systemd ExecStart fields.")
        parts = []
        for token, key in zip(tokens, keys):
            if not token.startswith(key + "="):
                raise Refusal("Unexpected systemd ExecStart field or order.")
            parts.append(token[len(key)+1:])
        if (not re.fullmatch(r"/[A-Za-z0-9/_\.-]+", parts[0])
            or not parts[1].startswith(parts[0])
            or parts[2] != "no"):
            raise Refusal("Untrusted systemd ExecStart command definition.")
        return json.dumps(
            {"path": parts[0], "argv": parts[1], "ignore_errors": parts[2]},
            sort_keys=True, separators=(",", ":"),
        )

    def _systemd_info(self) -> dict[str, str]:
        fields = ("Id", "LoadState", "ActiveState", "FragmentPath",
                  "DropInPaths", "NeedDaemonReload", "Transient", "ExecStart")
        result = self.run([
            "systemctl", "show", self.relay.unit_name,
            "--property=" + ",".join(fields), "--no-pager",
        ])
        if result.returncode != 0:
            raise Refusal("Cannot inspect effective systemd unit definition.")
        info = {}
        for line in result.stdout.splitlines():
            if "=" not in line:
                raise Refusal("Invalid systemd show output.")
            key, value = line.split("=", 1)
            if key not in fields or key in info:
                raise Refusal("Unexpected systemd property response.")
            info[key] = value
        # systemctl omits ExecStart entirely for an unknown unit; that
        # is safe only when LoadState is verifiably not-found.
        if info.get("LoadState") == "not-found" and "ExecStart" not in info:
            info["ExecStart"] = ""
        if set(info) != set(fields) or info["Id"] != self.relay.unit_name:
            raise Refusal("Could not prove the effective systemd unit identity.")
        if info["Transient"] != "no" or info["DropInPaths"]:
            raise Refusal("Unowned transient or drop-in systemd configuration.")
        if info["LoadState"] not in {"loaded", "not-found"}:
            raise Refusal("Ambiguous or masked systemd unit load state.")
        if info["ActiveState"] not in {"active", "inactive", "failed"}:
            raise Refusal("Ambiguous systemd activation state.")
        expected = str(self.layout.unit(self.relay))
        if info["FragmentPath"] not in {"", expected}:
            raise Refusal("Loaded same-name systemd unit has a foreign FragmentPath.")
        return info

    def _assert_no_loaded_same_name_unit(self) -> None:
        info = self._systemd_info()
        if (info["LoadState"] != "not-found" or info["FragmentPath"]
            or info["ExecStart"]):
            raise Refusal("A same-name systemd unit remains loaded; retirement is unverified.")

    def _verify_effective_systemd(self, managed: dict) -> bool:
        """Return True only when a verified owned unit may be disabled."""
        unit = self.layout.unit(self.relay)
        file_present = self._owned(unit)
        info = self._systemd_info()
        if file_present:
            # If a prior initial load never completed, allow a harmless
            # daemon-reload, but never stop an unproven effective definition.
            if info["LoadState"] == "not-found":
                reload = self.run(["systemctl", "daemon-reload"])
                if reload.returncode != 0:
                    raise Refusal("Could not reload existing root-owned Relay unit.")
                info = self._systemd_info()
            if (info["LoadState"] != "loaded"
                or info["FragmentPath"] != str(unit)
                or info["NeedDaemonReload"] != "no"
                or hashlib.sha256(self._canonical_exec(info["ExecStart"]).encode()).hexdigest() != managed["unit_exec_sha256"]):
                raise Refusal("Effective loaded systemd definition differs from owned Relay unit.")
            return True
        # A previous interrupted cleanup may have unlinked the unit but
        # failed daemon-reload. Recover ONLY when the still-loaded definition
        # is the expected former path, is inactive and matches the claim.
        if info["LoadState"] == "loaded":
            if (info["FragmentPath"] != str(unit)
                or info["ActiveState"] == "active"
                or hashlib.sha256(self._canonical_exec(info["ExecStart"]).encode()).hexdigest() != managed["unit_exec_sha256"]):
                raise Refusal("Loaded systemd unit cannot be safely retired without its owned file.")
            reload = self.run(["systemctl", "daemon-reload"])
            if reload.returncode != 0:
                raise Refusal("Could not reload systemd after interrupted Relay retirement.")
            info = self._systemd_info()
        if (info["LoadState"] != "not-found"
            or info["ActiveState"] == "active" or info["FragmentPath"]):
            raise Refusal("A same-name systemd service remains loaded without an owned unit file.")
        return False

    def _nft_policy_digest(self) -> str:
        result = self.run(["nft", "-j", "list", "table", "inet", self.relay.firewall_table])
        if result.returncode != 0:
            raise Refusal("Cannot inspect exact effective Relay firewall policy.")
        try:
            data = json.loads(result.stdout)
            if not isinstance(data, dict) or not isinstance(data.get("nftables"), list):
                raise Refusal("Invalid full nftables policy structure.")
            entries = []
            table_count = 0
            chains = 0
            for item in data["nftables"]:
                if not isinstance(item, dict) or len(item) != 1:
                    raise Refusal("Unknown entry in effective nftables policy.")
                kind, value = next(iter(item.items()))
                if kind == "metainfo":
                    continue
                if kind not in {"table", "chain", "rule"} or not isinstance(value, dict):
                    raise Refusal("Unexpected nftables policy object.")
                if (value.get("family") != "inet"
                    or value.get("name" if kind == "table" else "table") != self.relay.firewall_table):
                    raise Refusal("Foreign nftables object in Relay table.")
                if kind == "table":
                    table_count += 1
                elif kind == "chain":
                    chains += 1
                normalized = {k: v for k, v in value.items() if k != "handle"}
                entries.append({kind: normalized})
            if table_count != 1 or chains < 1:
                raise Refusal("Missing expected table/chain in Relay nftables policy.")
            canonical = json.dumps(entries, sort_keys=True, separators=(",", ":"))
            return hashlib.sha256(canonical.encode()).hexdigest()
        except (ValueError, TypeError, AttributeError) as error:
            raise Refusal("Invalid effective nftables JSON document.") from error

    def _verify_effective_nft(self, managed: dict) -> bool:
        if not self._nft_table_exists():
            return False
        if self._nft_policy_digest() != managed["firewall_sha256"]:
            raise Refusal("Effective nftables table has unowned or modified rules; refusing deletion.")
        return True

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
        # Inspect the durable fence even when no active host claim exists.
        # The fence itself is never removed by Gateway-host cleanup.
        self._fence()
        for ext in [".managed.json", ".policy", ".json", ".retired.json", ".generation.json"]:
            self._owned(self.layout.evidence(self.relay, ext))
        owned_parents(self.layout.key_dir(self.relay), self.layout)
        managed = self._manifest()
        self._generation()
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
        make_privileged_directory(self.layout.evidence_dir, self.layout, php_traversable=True)
        # A pre-existing directory may be root-owned but mode 0700. Do not
        # silently broaden its permissions or claim PHP can read the proof.
        for dirname in ("/etc", "/etc/mcp-gateway", "/etc/mcp-gateway/connection-relays"):
            directory = self.layout.at(dirname)
            if (directory.lstat().st_mode & 0o001) == 0:
                raise Refusal(
                    "Root-owned Relay evidence path is not searchable by the "
                    "non-root PHP identity: " + dirname + ". Reconcile access explicitly."
                )
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
            self._require_mutable_revision()
            managed = self._preflight()
            unit = self.layout.unit(self.relay)
            ports = {self.relay.local_port}
            if managed:
                ports.add(managed["local_socks_port"])
                # Prove effective loaded service and full nftables policy
                # BEFORE any service stop, firewall mutation or file deletion.
                should_disable = self._verify_effective_systemd(managed)
                self._verify_effective_nft(managed)
                if should_disable:
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
                if self._verify_effective_nft(managed):
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
            # A systemd daemon-reload can expose a foreign replacement unit
            # under the same name. Never issue a clean-host proof while any
            # effective definition is still loaded, even if inactive.
            self._assert_no_loaded_same_name_unit()
            # Preserve the v2 ownership claim until final host checks pass;
            # a foreign unit discovered after daemon-reload must remain
            # diagnosable and must not be mistaken for an unclaimed draft.
            if managed:
                self.layout.evidence(self.relay, ".managed.json").unlink()
            generation = self._advance_generation("retired")
            self._receipt(generation)
            return ("RETIREMENT VERIFIED for Gateway Relay " + self.relay.relay_id
                    + ". Iran was not contacted, and its cleanup was not asserted.")
        except BlockingIOError as error:
            raise Refusal("Another operator is changing this Relay; do not overlap operations.") from error
        finally:
            os.close(fd)

    def _receipt(self, host_generation: str) -> None:
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
            "host_generation": host_generation,
            "verified_boot_id": boot,
            "verified_at_unix": now,
            "verified_at_boot_seconds": seconds,
            "expires_at_unix": now + 600,
            "gateway_cleanup_verified": True,
        }
        self._write_json_atomic(self.layout.evidence(self.relay, ".retired.json"), proof)

    def seal(self, intent: str) -> str:
        """Irreversible host-side barrier, issued BEFORE DB rotation/delete.

        Both Seal and Setup take the SAME root-only per-Relay flock. After
        sealing revision N, no old command for revision <=N can restart it;
        a delete seal fences every revision of this immutable record ULID.
        A later record ULID has a different fence, never erasing the old one.
        """
        if intent not in {"delete", "rotate"}:
            raise Refusal("Unknown Relay lifecycle fence intent.")
        if os.geteuid() != self.layout.owner_uid:
            raise Refusal("Explicit root/sudo privileges are required.")
        make_privileged_directory(self.layout.evidence_dir, self.layout, php_traversable=True)
        make_privileged_directory(self.layout.lock_path(self.relay).parent, self.layout)
        lockpath = self.layout.lock_path(self.relay)
        fd = os.open(lockpath, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            if not self._owned(lockpath):
                raise Refusal("Unsafe Relay lock ownership.")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            prior = self._fence()
            if prior:
                if (prior["intent"] == "delete"
                    or prior["configuration_revision"] > self.relay.revision
                    or (prior["configuration_revision"] == self.relay.revision
                        and (prior["intent"] != intent
                             or prior["host_fingerprint"] != self.relay.fingerprint))):
                    # An already sealed delete may be re-verified only for
                    # the exact same record/configuration, never converted.
                    if not (prior["intent"] == intent == "delete"
                            and prior["configuration_revision"] == self.relay.revision
                            and prior["host_fingerprint"] == self.relay.fingerprint):
                        raise Refusal("Conflicting or stale Relay lifecycle fence; refusing replacement.")
            managed = self._preflight()
            if managed is not None:
                raise Refusal("Cannot seal a Relay with a managed host claim; retire first.")
            if (self._unit_active() or self._unit_enabled() or self._nft_table_exists()
                or self._listening({self.relay.local_port})):
                raise Refusal("Cannot seal Relay while its local service, listener or firewall exists.")
            self._assert_no_loaded_same_name_unit()
            generation = self._generation()
            if generation is None or generation["state"] != "retired":
                raise Refusal("Host retirement generation is missing; run verified cleanup first.")
            receipt = self._json(self.layout.evidence(self.relay, ".retired.json"), 2048)
            if (receipt.get("relay_record_id") != self.relay.record_id
                or receipt.get("relay_id") != self.relay.relay_id
                or receipt.get("host_fingerprint") != self.relay.fingerprint
                or receipt.get("configuration_revision") != self.relay.revision
                or receipt.get("host_generation") != generation["host_generation"]
                or receipt.get("gateway_cleanup_verified") is not True):
                raise Refusal("Retirement proof does not match the exact Relay being sealed.")
            if prior and prior["configuration_revision"] == self.relay.revision:
                if prior["host_generation"] != generation["host_generation"]:
                    raise Refusal("Host generation changed after a lifecycle fence; refusing to renew.")
            else:
                make_privileged_directory(self.layout.fence(self.relay).parent,
                                          self.layout, php_traversable=True)
                self._write_json_atomic(self.layout.fence(self.relay), {
                    "version": 1, "relay_record_id": self.relay.record_id,
                    "relay_id": self.relay.relay_id,
                    "host_fingerprint": self.relay.fingerprint,
                    "configuration_revision": self.relay.revision,
                    "host_generation": generation["host_generation"],
                    "intent": intent,
                })
            # Safe idempotent renewal if DB processing failed or timed out.
            # Never rotate generation or lift the permanent fence.
            self._receipt(generation["host_generation"])
            return ("LIFECYCLE FENCE VERIFIED for Gateway Relay " + self.relay.relay_id
                    + " (" + intent + "). Old host setup commands are permanently rejected; "
                    "Iran was not contacted.")
        except BlockingIOError as error:
            raise Refusal("Another operator is changing this Relay.") from error
        finally:
            os.close(fd)

    def prepare_setup(self) -> str:
        """Root-only invalidation barrier; must precede ANY new provisioning."""
        if os.geteuid() != self.layout.owner_uid:
            raise Refusal("Explicit root/sudo privileges are required.")
        make_privileged_directory(self.layout.evidence_dir, self.layout, php_traversable=True)
        make_privileged_directory(self.layout.lock_path(self.relay).parent, self.layout)
        fd = os.open(self.layout.lock_path(self.relay), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            if not self._owned(self.layout.lock_path(self.relay)):
                raise Refusal("Unsafe Relay lock ownership.")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._require_mutable_revision()
            if self._preflight() is not None:
                raise Refusal("Managed Relay claim exists; retire it before new Setup.")
            if self._unit_active() or self._unit_enabled() or self._nft_table_exists() or self._listening({self.relay.local_port}):
                raise Refusal("Begin Setup only after local service, listener and policy are absent.")
            # Order is security-critical: old PHP receipt invalid even if
            # power loss occurs before its file is unlinked.
            self._advance_generation("provisioning")
            receipt = self.layout.evidence(self.relay, ".retired.json")
            if self._owned(receipt):
                receipt.unlink()
            return ("OLD RETIREMENT PROOF INVALIDATED for Relay " + self.relay.relay_id
                    + ". New host setup must use the same generation.")
        except BlockingIOError as error:
            raise Refusal("Another operator is changing this Relay.") from error
        finally:
            os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser(description="MCP Gateway local-only Relay retirement; never contacts Iran.")
    parser.add_argument("action", choices=("preflight", "retire", "prepare-setup", "seal-delete", "seal-rotate"))
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
        if args.action == "preflight":
            print(operation.preview())
        elif args.action == "prepare-setup":
            print(operation.prepare_setup())
        elif args.action.startswith("seal-"):
            print(operation.seal(args.action.removeprefix("seal-")))
        else:
            print(operation.retire())
        return 0
    except (Refusal, OSError, UnicodeError) as error:
        print("FAIL CLOSED: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
