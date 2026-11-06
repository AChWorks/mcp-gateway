#!/usr/bin/python3
"""Privileged, explicitly invoked Gateway-side Relay retirement and local audit.

This is NOT an SSH client installer, readiness issuer or remote Iran cleanup tool. Runtime
CLI paths are fixed; PHP never invokes it and cannot issue retirement proofs.
The expected fields come from the Owner-facing command and are checked against
owned resources. Do not use it to adopt third-party systemd/firewall state.
"""
from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import json
import os
import pwd
import re
import secrets
import shlex
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

    @property
    def ssh_user(self) -> str:
        # Record ULID, not mutable display/route name: new record means a
        # different OS identity, even when a human reuses the Relay ID.
        return "mcp-relay-" + hashlib.sha256(self.record_id.encode()).hexdigest()[:20]


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
        prior_fingerprint: str | None = None,
    ):
        relay.validate()
        if prior_fingerprint is not None and (
            relay.revision <= 1
            or not isinstance(prior_fingerprint, str)
            or re.fullmatch(r"[a-f0-9]{64}", prior_fingerprint) is None
            or prior_fingerprint == relay.fingerprint
        ):
            raise Refusal("Invalid prior host identity for a one-revision Disable transition.")
        self.relay = relay
        self.layout = layout
        self.run = run
        # A disabled DB record is revision N+1, while its still-owned host
        # resources may have been installed at N. Only retire accepts this
        # specifically asserted previous fingerprint, never Setup or Seal.
        self.prior_fingerprint = prior_fingerprint

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
        }
        for key, value in expected.items():
            if manifest.get(key) != value:
                raise Refusal("Managed host resource ownership does not match this Relay: " + key)
        identities = {(self.relay.revision, self.relay.fingerprint)}
        if self.prior_fingerprint is not None:
            identities.add((self.relay.revision - 1, self.prior_fingerprint))
        if (manifest.get("configuration_revision"), manifest.get("host_fingerprint")) not in identities:
            raise Refusal("Managed host revision/fingerprint does not match the current or exact prior installed identity.")
        port = manifest.get("local_socks_port")
        if not isinstance(port, int) or port != self.relay.local_port:
            raise Refusal("Invalid local port in managed host claim.")
        integrity = {"unit_sha256", "unit_exec_sha256", "firewall_sha256", "host_generation"}
        if set(manifest) != set(expected) | {"local_socks_port", "host_fingerprint", "configuration_revision"} | integrity:
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
            + ", resource claim=" + (("verified installed revision " + str(managed["configuration_revision"])) if managed else "absent")
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
        if self.prior_fingerprint is not None:
            raise Refusal("Prior host identity is permitted only during retirement.")
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
        if self.prior_fingerprint is not None:
            raise Refusal("Prior host identity is permitted only during retirement.")
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



class GatewayPolicyAudit(Retirement):
    """Read-only, fail-closed audit of provisioned Gateway host resources.

    This is deliberately NOT readiness issuance. A matching root-owned claim
    and effective local controls cannot prove the independent Iran egress
    policy, dedicated FPM-pool ownership, or a fully authenticated Target.
    The future Setup/Repair path must first create these owned resources;
    there is no mechanism here to adopt foreign state.
    """

    @staticmethod
    def _uid_match(expr: object, uid: int, op: str) -> bool:
        return (isinstance(expr, dict) and expr.get("match") == {
            "left": {"meta": {"key": "skuid"}}, "op": op, "right": uid,
        })

    @staticmethod
    def _port_match(expr: object, port: int) -> bool:
        if not isinstance(expr, dict) or not isinstance(expr.get("match"), dict):
            return False
        match = expr["match"]
        return (match.get("left") == {"payload": {
            "protocol": "tcp", "field": "dport",
        }} and match.get("op") == "==" and match.get("right") == port)

    @staticmethod
    def _loopback_match(expr: object) -> bool:
        return (isinstance(expr, dict) and expr.get("match") == {
            "left": {"meta": {"key": "oifname"}}, "op": "==", "right": "lo",
        })

    def _require_effective_acl(self, php_uid: int) -> None:
        """An inet/output hook with a pre-accept reject for every other UID.

        Reject only the exact reviewed shape; a general nft digest may attest
        a modified *insecure* policy otherwise. This single UID/port guard
        applies to IPv4 and IPv6. Actual socket-negative tests are still an
        independent acceptance requirement.
        """
        result = self.run(["nft", "-j", "list", "table", "inet", self.relay.firewall_table])
        if result.returncode:
            raise Refusal("Cannot read live Relay nftables rules for ACL audit.")
        try:
            doc = json.loads(result.stdout)
            values = doc["nftables"]
        except (ValueError, KeyError, TypeError) as error:
            raise Refusal("Malformed live Relay nftables ACL.") from error
        chains = []
        rules = []
        for item in values:
            if not isinstance(item, dict):
                raise Refusal("Malformed ACL rule.")
            if "chain" in item:
                chains.append(item["chain"])
            if "rule" in item:
                rules.append(item["rule"])
        if len(chains) != 1:
            raise Refusal("Relay ACL must have exactly one dedicated output chain.")
        chain = chains[0]
        if (chain.get("name") != "output_guard" or chain.get("type") != "filter"
            or chain.get("hook") != "output"
            or chain.get("policy") != "accept"
            or type(chain.get("prio")) is not int
            or chain["prio"] != -150):
            raise Refusal("Relay ACL has no verified inet/output base-chain hook.")
        # This audited protocol has exactly ONE owned filter chain and ONE
        # deny rule. A second rule could reject the legitimate PHP UID even
        # though both the first rule and complete manifest digest agree.
        if len(rules) != 1:
            raise Refusal("Relay ACL has unsupported trailing or foreign rules.")
        deny = rules[0]
        if deny.get("chain") != "output_guard" or not isinstance(deny.get("expr"), list):
            raise Refusal("First ACL rule is not a dedicated loopback deny.")
        expr = deny["expr"]
        if not (
            len(expr) == 4
            and self._loopback_match(expr[0])
            and self._port_match(expr[1], self.relay.local_port)
            and self._uid_match(expr[2], php_uid, "!=")
            and expr[3] == {"reject": {"type": "icmpx", "expr": "admin-prohibited"}}
        ):
            raise Refusal("IPv4/IPv6 loopback SOCKS access is not denied to unrelated UIDs.")

    def _require_ssh_invocation(self, effective: str, owner: dict) -> None:
        # Match the WHOLE effective OpenSSH command, rather than a trusted
        # digest of arbitrary but internally consistent generated bytes.
        # The future Setup must render this exact argument contract.
        host = owner["control_host"]
        port = owner["control_port"]
        user = owner["control_user"]
        if (not isinstance(host, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}", host) is None
            or ".." in host or host.endswith(".")
            or type(port) is not int or not 1 <= port <= 65535
            or not isinstance(user, str)
            or re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.+-]{0,127}", user) is None):
            raise Refusal("Invalid owner-bound SSH control endpoint.")
        credential_root = "/run/credentials/" + self.relay.unit_name
        expected = [
            "/usr/bin/ssh", "-F", "/dev/null", "-N", "-T",
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", "ExitOnForwardFailure=yes",
            "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
            "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
            "-o", "ControlMaster=no", "-o", "ProxyCommand=none",
            "-o", "ProxyJump=none",
            "-o", "UserKnownHostsFile=" + credential_root + "/known_hosts",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3",
            "-o", "ConnectTimeout=10",
            "-i", credential_root + "/control_key",
            "-D", "127.0.0.1:" + str(self.relay.local_port),
            "-p", str(port), "-l", user, host,
        ]
        try:
            actual = shlex.split(json.loads(self._canonical_exec(effective))["argv"])
        except (ValueError, TypeError, KeyError) as error:
            raise Refusal("Malformed effective OpenSSH invocation.") from error
        if actual != expected:
            raise Refusal("Effective OpenSSH arguments violate the reviewed single-loopback forwarding contract.")

    def _require_principal_isolation(self, owner: dict) -> None:
        """Reject NSS aliases and shared UIDs across root-owned Relay claims."""
        expected = self.relay.ssh_user
        try:
            primary = pwd.getpwuid(owner["ssh_uid"])
            accounts = pwd.getpwall()
        except (KeyError, OSError) as error:
            raise Refusal("Cannot prove exclusive system SSH UID ownership.") from error
        if primary.pw_name != expected or any(
            entry.pw_uid == owner["ssh_uid"] and entry.pw_name != expected
            for entry in accounts
        ):
            raise Refusal("Dedicated SSH UID is reused by another system account.")
        parent = self.layout.key_dir(self.relay).parent
        owned_parents(parent, self.layout)
        if not self._owned(parent, True):
            raise Refusal("Cannot inspect Relay SSH principal reservations.")
        entries = list(parent.iterdir())
        if len(entries) > 1024:
            raise Refusal("Too many Relay principal reservations to audit safely.")
        for entry in entries:
            if not self._owned(entry, True):
                raise Refusal("Untrusted sibling Relay principal namespace.")
            if entry == self.layout.key_dir(self.relay):
                continue
            sibling_owner = entry / "owner.json"
            if not self._owned(sibling_owner):
                raise Refusal("Sibling Relay lacks root-owned principal ownership proof.")
            sibling = self._json(sibling_owner, 4096)
            record = sibling.get("relay_record_id")
            if (sibling.get("version") != 2
                or sibling.get("relay_id") != entry.name
                or not isinstance(record, str)
                or re.fullmatch(r"[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{26}", record) is None
                or sibling.get("ssh_user") !=
                   "mcp-relay-" + hashlib.sha256(record.encode()).hexdigest()[:20]
                or type(sibling.get("ssh_uid")) is not int
                or sibling["ssh_uid"] < 1):
                raise Refusal("Sibling Relay principal ownership proof is incomplete or malformed.")
            if (record == self.relay.record_id
                or sibling["ssh_user"] == expected
                or sibling["ssh_uid"] == owner["ssh_uid"]):
                raise Refusal("Dedicated SSH principal or UID is reused by another Relay.")

    def _require_control_key_pair(self, keydir: Path) -> None:
        private = keydir / "control_key"
        public = keydir / "control_key.pub"
        pubbytes = public.read_bytes()
        if len(pubbytes) > 1024:
            raise Refusal("Relay SSH public key exceeds bounded Ed25519 key length.")
        try:
            fields = pubbytes.decode("ascii").strip().split()
        except UnicodeDecodeError as error:
            raise Refusal("Relay SSH public key is not valid ASCII.") from error
        if (len(fields) != 2 or fields[0] != "ssh-ed25519"
            or re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", fields[1]) is None):
            raise Refusal("Relay SSH public key must be an exact Ed25519 key without comment.")
        try:
            blob = base64.b64decode(fields[1], validate=True)
        except ValueError as error:
            raise Refusal("Invalid Relay SSH public-key encoding.") from error
        if (len(blob) != 51 or blob[:4] != b"\x00\x00\x00\x0b"
            or blob[4:15] != b"ssh-ed25519"):
            raise Refusal("Relay SSH public-key wire format is invalid.")
        response = self.run(["/usr/bin/ssh-keygen", "-y", "-P", "", "-f", str(private)])
        if response.returncode != 0:
            raise Refusal("Cannot derive public SSH key from the root-controlled private key.")
        derived = response.stdout.strip().split()
        if len(derived) < 2 or derived[:2] != fields:
            raise Refusal("Relay SSH public key does not match the private control key.")

    def _require_effective_listener(self, main_pid: int) -> None:
        # Every listener owned by the service PID must be accounted for, not
        # just sockets on the expected port. A second -D bound publicly is a
        # false-positive if only the first port is inspected.
        response = self.run(["ss", "-H", "-lntp"])
        if response.returncode:
            raise Refusal("Cannot inspect root-visible listening processes.")
        expected = "127.0.0.1:" + str(self.relay.local_port)
        service_listeners: list[str] = []
        reserved_listeners: list[str] = []
        for line in response.stdout.splitlines():
            parts = line.split(maxsplit=5)
            if len(parts) < 5 or parts[0] != "LISTEN":
                raise Refusal("Malformed socket-listener inventory.")
            address = parts[3]
            owners = parts[5] if len(parts) > 5 else ""
            # Root must see the owning PID/FD; unknown ownership on our
            # reserved port is ambiguous and cannot establish local readiness.
            matches = re.findall(r"\bpid=([0-9]+),fd=([0-9]+)\b", owners)
            if "pid=" in owners and not matches:
                raise Refusal("Cannot parse socket owner PID/FD.")
            pids = {int(pid) for pid, _ in matches}
            if address.rsplit(":", 1)[-1] == str(self.relay.local_port):
                reserved_listeners.append(address)
                if pids != {main_pid}:
                    raise Refusal("SOCKS listener does not belong uniquely to verified systemd MainPID.")
            if main_pid in pids:
                if pids != {main_pid}:
                    raise Refusal("SOCKS listener is shared with another process.")
                service_listeners.append(address)
        if reserved_listeners != [expected] or service_listeners != [expected]:
            raise Refusal("OpenSSH has unexpected, missing or non-loopback listening sockets.")

    def audit(self, php_uid: int) -> str:
        if os.geteuid() != self.layout.owner_uid:
            raise Refusal("The privileged Gateway host audit requires explicit root/sudo.")
        if type(php_uid) is not int or php_uid < 1:
            raise Refusal("A dedicated non-root Gateway PHP UID is required.")
        lock = self.layout.lock_path(self.relay)
        owned_parents(lock.parent, self.layout)
        if not self._owned(lock):
            raise Refusal("Root-owned Relay lifecycle lock is missing; cannot audit without a safe revision fence.")
        fd = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            return self._audit_locked(php_uid)
        except BlockingIOError as error:
            raise Refusal("Relay lifecycle maintenance is active; retry audit after the operation.") from error
        finally:
            os.close(fd)

    def _audit_locked(self, php_uid: int) -> str:
        # A root-owned active claim can survive a historical delete/rotation
        # fence due to interrupted host changes. Never let its local socket
        # checks imply a current, mutable Relay security identity.
        self._require_mutable_revision()
        managed = self._preflight()
        if managed is None:
            raise Refusal("No exact root-owned installed claim; run the separately approved Gateway Setup.")
        unit_path = self.layout.unit(self.relay)
        if not self._owned(unit_path):
            raise Refusal("No root-owned Relay service definition.")
        if hashlib.sha256(unit_path.read_bytes()).hexdigest() != managed["unit_sha256"]:
            raise Refusal("Relay systemd unit changed after its root-owned claim.")
        info = self._systemd_info()
        if (info["LoadState"] != "loaded" or info["ActiveState"] != "active"
            or info["FragmentPath"] != str(unit_path)
            or info["NeedDaemonReload"] != "no"
            or hashlib.sha256(self._canonical_exec(info["ExecStart"]).encode()).hexdigest()
                != managed["unit_exec_sha256"]):
            raise Refusal("Effective Relay systemd service is not the approved active definition.")
        if not self._unit_active() or not self._unit_enabled():
            raise Refusal("Relay service is stopped or cannot survive reboot.")
        keydir = self.layout.key_dir(self.relay)
        if not self._owned(keydir, True):
            raise Refusal("Dedicated SSH control credential namespace is missing.")
        required = {"control_key", "control_key.pub", "known_hosts", "owner.json"}
        if {entry.name for entry in keydir.iterdir()} != required:
            raise Refusal("Dedicated SSH credential namespace is incomplete or contains unknown files.")
        for name in required:
            if not self._owned(keydir / name):
                raise Refusal("Untrusted dedicated SSH control credential: " + name)
        if (keydir.stat().st_mode & 0o777) != 0o700 or (
            (keydir / "control_key").stat().st_mode & 0o777
        ) != 0o600:
            raise Refusal("Control private key is not isolated in the expected root-only directory.")
        owner = self._json(keydir / "owner.json", 4096)
        if (set(owner) != {"version", "relay_record_id", "relay_id", "ssh_user",
                           "ssh_uid", "gateway_php_uid", "control_host",
                           "control_port", "control_user",
                           "control_key_sha256", "control_key_pub_sha256",
                           "known_hosts_sha256"}
            or owner["version"] != 2
            or owner["relay_record_id"] != self.relay.record_id
            or owner["relay_id"] != self.relay.relay_id
            or owner["gateway_php_uid"] != php_uid
            or owner["ssh_user"] != self.relay.ssh_user
            or type(owner["ssh_uid"]) is not int
            or owner["ssh_uid"] < 1 or owner["ssh_uid"] == php_uid
            or any(not isinstance(owner[key], str)
                   or re.fullmatch(r"[a-f0-9]{64}", owner[key]) is None
                   for key in ("control_key_sha256", "control_key_pub_sha256",
                               "known_hosts_sha256"))
            or hashlib.sha256((keydir / "control_key").read_bytes()).hexdigest()
               != owner["control_key_sha256"]
            or hashlib.sha256((keydir / "control_key.pub").read_bytes()).hexdigest()
               != owner["control_key_pub_sha256"]
            or hashlib.sha256((keydir / "known_hosts").read_bytes()).hexdigest()
               != owner["known_hosts_sha256"]):
            raise Refusal("Relay SSH principal or key ownership record does not match live resources.")
        self._require_control_key_pair(keydir)
        self._require_ssh_invocation(info["ExecStart"], owner)
        self._require_principal_isolation(owner)
        if not self._verify_effective_nft(managed):
            raise Refusal("Exact claimed Relay nftables ACL is not loaded.")
        self._require_effective_acl(php_uid)
        # A second independent systemd query binds the live listener to this
        # one service instance rather than to any process reusing its port.
        result = self.run(["systemctl", "show", self.relay.unit_name,
                           "--property=MainPID,User,NoNewPrivileges,PrivateTmp",
                           "--no-pager"])
        if result.returncode:
            raise Refusal("Cannot inspect effective systemd execution identity.")
        lines = result.stdout.splitlines()
        if any(line.count("=") != 1 for line in lines):
            raise Refusal("Malformed systemd execution-identity response.")
        properties = dict(line.split("=", 1) for line in lines)
        if len(properties) != len(lines):
            raise Refusal("Duplicate systemd execution-identity property.")
        if set(properties) != {"MainPID", "User", "NoNewPrivileges", "PrivateTmp"}:
            raise Refusal("Incomplete systemd execution-identity evidence.")
        if (properties["User"] != self.relay.ssh_user
            or properties["NoNewPrivileges"] != "yes"
            or properties["PrivateTmp"] != "yes"):
            raise Refusal("Relay SSH service lacks its dedicated restricted principal.")
        try:
            principal = pwd.getpwnam(properties["User"])
        except KeyError as error:
            raise Refusal("Dedicated SSH service principal does not exist.") from error
        if (principal.pw_uid != owner["ssh_uid"] or principal.pw_uid <= 0
            or principal.pw_uid == php_uid
            or not principal.pw_shell.endswith(("/nologin", "/false"))):
            raise Refusal("Actual SSH service principal has unsafe identity or login shell.")
        try:
            pid = int(properties["MainPID"])
        except ValueError as error:
            raise Refusal("Invalid live Relay service PID.") from error
        if pid <= 1:
            raise Refusal("Relay service has no proven live MainPID.")
        # Cross-check the actual running process, not merely a name or
        # systemd's intended User property.
        try:
            status = self.layout.at("/proc/" + str(pid) + "/status").read_text()
            exe = os.readlink(self.layout.at("/proc/" + str(pid) + "/exe"))
        except (OSError, UnicodeError) as error:
            raise Refusal("Cannot inspect live Relay SSH process identity.") from error
        uid_line = next((line for line in status.splitlines() if line.startswith("Uid:")), "")
        ids = uid_line.split()[1:]
        if (len(ids) != 4 or any(not value.isdecimal() for value in ids)
            or any(int(value) != principal.pw_uid for value in ids)
            or exe != "/usr/bin/ssh"):
            raise Refusal("Actual Relay service process does not match the dedicated OpenSSH principal.")
        self._require_effective_listener(pid)
        generation = self._generation()
        if generation is None or generation["state"] != "provisioning":
            raise Refusal("Relay generation is no longer provisionable.")
        return ("GATEWAY LOCAL POLICY AUDIT PASS for " + self.relay.relay_id
                + ". NO READINESS ISSUED: dedicated PHP-FPM ownership, "
                "Iran egress restrictions and Target authentication still "
                "require independent verified evidence.")

def main() -> int:
    parser = argparse.ArgumentParser(description="MCP Gateway local-only Relay retirement; never contacts Iran.")
    parser.add_argument("action", choices=("preflight", "audit-gateway", "retire", "prepare-setup", "seal-delete", "seal-rotate"))
    parser.add_argument("--relay-id", required=True)
    parser.add_argument("--record-id", required=True)
    parser.add_argument("--fingerprint", required=True)
    parser.add_argument("--revision", required=True, type=int)
    parser.add_argument("--local-port", required=True, type=int)
    parser.add_argument("--php-uid", type=int, default=None,
                        help="Required for root-only Gateway local policy audit.")
    parser.add_argument("--prior-fingerprint", default=None,
                        help="Read-only preflight or retire: exact N-1 installed fingerprint after DB Disable.")
    args = parser.parse_args()
    try:
        relay = Relay(args.relay_id, args.record_id, args.fingerprint, args.revision, args.local_port)
        layout = Layout()
        if os.geteuid() != 0:
            raise Refusal("Run this trusted installed helper explicitly with sudo/root.")
        if args.prior_fingerprint is not None and args.action not in {"preflight", "retire"}:
            raise Refusal("Prior host fingerprint is allowed only for local preflight or retirement.")
        operation = Retirement(relay, layout, prior_fingerprint=args.prior_fingerprint)
        if args.action == "audit-gateway":
            if args.php_uid is None or args.prior_fingerprint is not None:
                raise Refusal("Gateway audit requires --php-uid and does not accept prior revisions.")
            print(GatewayPolicyAudit(relay, layout).audit(args.php_uid))
        elif args.php_uid is not None:
            raise Refusal("--php-uid is only accepted by audit-gateway.")
        elif args.action == "preflight":
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
