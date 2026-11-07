#!/usr/bin/python3
"""Privileged, explicitly invoked Gateway-side Relay operator actions.

The root-only helper supports manually confirmed host-readiness issuance, but is
NOT an SSH client installer or remote Relay peer cleanup tool. Runtime
CLI paths are fixed; PHP never invokes it and cannot issue retirement proofs.
The expected fields come from the Owner-facing command and are checked against
owned resources. Do not use it to adopt third-party systemd/firewall state.
"""
from __future__ import annotations

import argparse
import base64
import ipaddress
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


def account_generation_marker(relay: Relay, generation: str) -> str:
    # GECOS is a colon-delimited /etc/passwd field: useradd --comment must
    # never contain ':' (or newline). Restrict to these validated hex/ULID
    # and hyphen bytes for a portable durable account-generation marker.
    return "mcp-gateway-relay-" + relay.record_id + "-" + generation


def nft_policy_source(relay: Relay, php_uid: int) -> bytes:
    if type(php_uid) is not int or php_uid <= 0:
        raise Refusal("A dedicated non-root PHP UID is required for the ACL.")
    table = relay.firewall_table
    return (
        "add table inet " + table + "\n"
        "flush table inet " + table + "\n"
        "add chain inet " + table +
        " output_guard { type filter hook output priority -150; policy accept; }\n"
        "add rule inet " + table + " output_guard"
        " oifname \"lo\" tcp dport " + str(relay.local_port) +
        " meta skuid != " + str(php_uid) +
        " reject with icmpx type admin-prohibited\n"
    ).encode("ascii")


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


def fsync_privileged_directory(path: Path, layout: Layout) -> None:
    """Commit a trusted directory's metadata and namespace entries."""
    trusted(path, True, layout.owner_uid, True)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


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
        try:
            folder.mkdir(mode=mode)
        except FileExistsError:
            # Concurrent cold-boot recovery by another Relay may have just
            # created this shared parent. Accept it ONLY after root ownership,
            # true directory type and safe permissions are independently proven.
            trusted(folder, True, layout.owner_uid, True)
        else:
            folder.chmod(mode)
            trusted(folder, True, layout.owner_uid, True)
    owned_parents(path, layout)
    # fsync of a child file cannot make the child's newly created ancestor
    # directory entries durable. Flush every namespace from leaf to root,
    # including existing paths on retry after an interrupted parent fsync.
    current = path
    while current.is_relative_to(layout.root):
        fsync_privileged_directory(current, layout)
        if current == layout.root:
            break
        current = current.parent


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

    def _write_exact(self, path: Path, contents: bytes, mode: int) -> None:
        # Never overwrite a published path. Re-fsync exact existing files and
        # their parent on retry: a prior process may have crashed after the
        # hard link was made, but before its directory entry was committed.
        if self._owned(path):
            if path.read_bytes() != contents or path.stat().st_mode & 0o777 != mode:
                raise Refusal("Owned Relay Setup file differs from reviewed bytes: " + str(path))
            file_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(file_fd)
            finally:
                os.close(file_fd)
            self._fsync_directory(path.parent)
            return
        if path.exists() or path.is_symlink():
            raise Refusal("Untrusted existing Relay Setup file: " + str(path))
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            # Linux O_TMPFILE has no directory entry until linkat publishes it.
            # A crash before publication leaves no .relay-setup-* artifact to
            # strand Setup or Retirement. dir_fd forces linkat(AT_SYMLINK_FOLLOW)
            # on /proc/self/fd, preserving atomic no-clobber link semantics.
            try:
                temporary_fd = os.open(".", os.O_TMPFILE | os.O_WRONLY, 0o600,
                                       dir_fd=directory_fd)
            except OSError as error:
                raise Refusal("Relay Setup requires filesystem support for anonymous O_TMPFILE publication.") from error
            try:
                with os.fdopen(os.dup(temporary_fd), "wb") as destination:
                    destination.write(contents)
                    destination.flush()
                    os.fchmod(destination.fileno(), mode)
                    os.fsync(destination.fileno())
                os.link("/proc/self/fd/" + str(temporary_fd), path.name,
                        dst_dir_fd=directory_fd, follow_symlinks=True)
                os.fsync(directory_fd)
            except FileExistsError as error:
                raise Refusal("Concurrent Relay Setup file mutation; retry after operator review.") from error
            finally:
                os.close(temporary_fd)
        finally:
            os.close(directory_fd)

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

    def _unit_persistently_enabled(self) -> bool:
        """Readiness requires permanent boot enablement, not mere linkage.

        Keep _unit_enabled() conservative for Retirement/Setup: transient
        enablement and aliases are still resources that must be accounted for.
        Only systemctl's exact positive enabled state proves durable
        [Install] activation for the already-verified canonical unit.
        """
        result = self.run(["systemctl", "is-enabled", self.relay.unit_name])
        state = result.stdout.strip()
        if state == "enabled" and result.returncode == 0:
            return True
        if state in {"enabled-runtime", "alias", "static", "indirect", "generated",
                     "transient"} and result.returncode == 0:
            return False
        if state in {"linked", "linked-runtime", "masked", "masked-runtime", "disabled"} and result.returncode in {1, 3}:
            return False
        if state == "not-found" and result.returncode == 4:
            return False
        raise Refusal("Cannot positively verify permanent Relay systemd boot enablement.")

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
            + ". No remote Relay peer access is attempted."
        )

    def _require_unjournaled_legacy_safe(self) -> None:
        """An old managed claim does not own the new dedicated SSH principal.

        Without the root Setup journal, we cannot prove a same-name account's
        immutable UID or the origin of credential files. Preserve them and
        refuse a false Gateway-host retirement receipt. Empty, root-owned
        legacy key directories are safe to remove, but NOT their contents.
        """
        try:
            pwd.getpwnam(self.relay.ssh_user)
        except KeyError:
            pass
        except OSError as error:
            raise Refusal("Cannot verify absent dedicated SSH account without Setup journal.") from error
        else:
            raise Refusal("Dedicated SSH account exists without UID-bound Setup journal; refuse cleanup proof.")
        keydir = self.layout.key_dir(self.relay)
        if self._owned(keydir, True):
            if any(keydir.iterdir()):
                raise Refusal("Unjournaled Relay credential files cannot be proven owned; preserve them.")
        elif keydir.exists() or keydir.is_symlink():
            raise Refusal("Unknown unjournaled Relay credential namespace.")

    def _fsync_directory(self, path: Path) -> None:
        # A successful unlink/rmdir is NOT a durable cleanup barrier until
        # its parent namespace has been flushed to disk.
        fsync_privileged_directory(path, self.layout)

    def _unlink_owned_durable(self, path: Path) -> None:
        if self._owned(path):
            path.unlink()
            self._fsync_directory(path.parent)

    def _rmdir_owned_durable(self, path: Path) -> None:
        if self._owned(path, True):
            path.rmdir()
            self._fsync_directory(path.parent)

    def _owned_setup_for_retirement(self, managed: dict | None) -> dict | None:
        """Validate a durable Setup journal, including a pre-claim interruption."""
        journal_path = self.layout.evidence(self.relay, ".setup.json")
        nft_path = self.layout.evidence(self.relay, ".nft")
        if not self._owned(journal_path):
            if self._owned(nft_path):
                raise Refusal("Unknown Relay nftables persistence file without an owned Setup journal.")
            keydir = self.layout.key_dir(self.relay)
            if (self._owned(keydir, True)
                and self._owned(keydir / "owner.json")):
                raise Refusal("Dedicated SSH principal claim survives without its root-owned UID journal.")
            return None
        journal = self._json(journal_path)
        expected = {
            "version", "relay_record_id", "relay_id", "host_fingerprint",
            "configuration_revision", "host_generation", "ssh_user",
            "ssh_uid", "gateway_php_uid", "control_host", "control_port",
            "control_user", "host_key_sha256", "unit_sha256",
        }
        accepted = {(self.relay.revision, self.relay.fingerprint)}
        if self.prior_fingerprint is not None:
            accepted.add((self.relay.revision - 1, self.prior_fingerprint))
        generation = self._generation()
        if (set(journal) != expected or journal["version"] != 2
            or journal["relay_record_id"] != self.relay.record_id
            or journal["relay_id"] != self.relay.relay_id
            or (journal["configuration_revision"], journal["host_fingerprint"]) not in accepted
            or generation is None or generation["state"] != "provisioning"
            or journal["host_generation"] != generation["host_generation"]
            or journal["ssh_user"] != self.relay.ssh_user
            or (journal["ssh_uid"] is not None
                and (type(journal["ssh_uid"]) is not int or journal["ssh_uid"] < 1))
            or type(journal["gateway_php_uid"]) is not int
            or journal["gateway_php_uid"] < 1
            or not isinstance(journal["control_host"], str)
            or not isinstance(journal["control_user"], str)
            or type(journal["control_port"]) is not int
            or not 1 <= journal["control_port"] <= 65535
            or any(not isinstance(journal[k], str)
                   or re.fullmatch(r"[a-f0-9]{64}", journal[k]) is None
                   for k in ("host_key_sha256", "unit_sha256"))):
            raise Refusal("Incompatible Relay Setup journal; refusing host cleanup of unclaimed resources.")
        if managed is not None and (
            journal["configuration_revision"] != managed["configuration_revision"]
            or journal["host_fingerprint"] != managed["host_fingerprint"]
            or journal["host_generation"] != managed["host_generation"]
        ):
            raise Refusal("Managed claim and Setup journal have different host identities.")
        if self._owned(nft_path):
            if nft_path.read_bytes() != nft_policy_source(self.relay, journal["gateway_php_uid"]):
                raise Refusal("Relay nftables persistence source changed; refusing deletion.")
        unit = self.layout.unit(self.relay)
        if self._owned(unit):
            if hashlib.sha256(unit.read_bytes()).hexdigest() != journal["unit_sha256"]:
                raise Refusal("Staged Relay unit differs from the immutable Setup journal.")
        self._validate_setup_keydir(journal)
        return journal

    def _validate_setup_keydir(self, journal: dict) -> None:
        """Verify each staged private artifact BEFORE touching firewall/unit."""
        keydir = self.layout.key_dir(self.relay)
        if not self._owned(keydir, True):
            return
        if (keydir.stat().st_mode & 0o777) != 0o700:
            raise Refusal("Staged Relay credential directory must be mode 0700.")
        allowed = {"control_key", "control_key.pub", "known_hosts", "owner.json"}
        entries = {entry.name: entry for entry in keydir.iterdir()}
        if not set(entries).issubset(allowed):
            raise Refusal("Foreign file in interrupted Relay credential namespace.")
        for entry in entries.values():
            if not self._owned(entry):
                raise Refusal("Untrusted staged Relay private credential.")
        private = entries.get("control_key")
        public = entries.get("control_key.pub")
        if public is not None and private is None:
            # ssh-keygen may have been interrupted between writing the
            # public and private files. An exact root-owned Setup journal,
            # the private 0700 namespace and a valid, narrowly typed Ed25519
            # public blob are sufficient to retire this harmless partial
            # artifact; a complete owner.json would instead be inconsistent.
            if "owner.json" in entries:
                raise Refusal("Complete Relay principal claim has an orphaned public key.")
            if (public.stat().st_mode & 0o777) not in {0o600, 0o640, 0o644}:
                raise Refusal("Orphaned Relay public key has unsafe permissions.")
            try:
                fields = public.read_bytes().decode("ascii").strip().split()
                blob = base64.b64decode(fields[1], validate=True) if len(fields) == 2 else b""
            except (ValueError, UnicodeError):
                raise Refusal("Unrecognized orphaned Relay public key.")
            if (len(fields) != 2 or fields[0] != "ssh-ed25519"
                or len(blob) != 51 or blob[:4] != b"\x00\x00\x00\x0b"
                or blob[4:15] != b"ssh-ed25519"):
                raise Refusal("Unrecognized orphaned Relay public key.")
        if private is not None:
            if (private.stat().st_mode & 0o777) != 0o600:
                raise Refusal("Interrupted Relay private key has unsafe permissions.")
            derived = self.run(["/usr/bin/ssh-keygen", "-y", "-P", "", "-f", str(private)])
            if derived.returncode or len(derived.stdout.split()) < 2 or derived.stdout.split()[0] != "ssh-ed25519":
                raise Refusal("Unrecognized interrupted Relay SSH private key.")
            if public is not None:
                if ((public.stat().st_mode & 0o777) not in {0o600, 0o640, 0o644}
                    or public.read_text().split()[:2] != derived.stdout.split()[:2]):
                    raise Refusal("Interrupted Relay SSH public/private key mismatch.")
        known_hosts = entries.get("known_hosts")
        if known_hosts is not None:
            if known_hosts.stat().st_mode & 0o777 != 0o644:
                raise Refusal("Staged Relay pinned known_hosts permissions changed.")
            host = journal["control_host"]
            port = journal["control_port"]
            pin = known_hosts.read_bytes()
            identity = (host if port == 22 else "[" + host + "]:" + str(port))
            prefix = (identity + " ").encode("ascii")
            if (not pin.startswith(prefix) or not pin.endswith(b"\n")
                or hashlib.sha256(pin[len(prefix):-1]).hexdigest() != journal["host_key_sha256"]):
                raise Refusal("Staged Relay SSH host key no longer matches its journal pin.")
        owner = entries.get("owner.json")
        if owner is not None:
            claim = self._json(owner)
            if (claim.get("version") != 2
                or claim.get("relay_record_id") != self.relay.record_id
                or claim.get("relay_id") != self.relay.relay_id
                or claim.get("ssh_user") != self.relay.ssh_user
                or type(claim.get("ssh_uid")) is not int
                or claim["ssh_uid"] != journal["ssh_uid"]
                or claim.get("gateway_php_uid") != journal["gateway_php_uid"]
                or claim.get("control_host") != journal["control_host"]
                or claim.get("control_port") != journal["control_port"]
                or claim.get("control_user") != journal["control_user"]):
                raise Refusal("Relay owner.json identity disagrees with immutable setup SSH UID.")
            # An interrupted retirement may have already deleted files AFTER
            # userdel. Before account deletion, every ownership digest must
            # still match its exact material.
            try:
                account_exists = pwd.getpwnam(self.relay.ssh_user) is not None
            except KeyError:
                account_exists = False
            for name, field in (
                ("control_key", "control_key_sha256"),
                ("control_key.pub", "control_key_pub_sha256"),
                ("known_hosts", "known_hosts_sha256"),
            ):
                entry = entries.get(name)
                if entry is None:
                    if account_exists:
                        raise Refusal("Relay control credential missing before account retirement.")
                    continue
                if (not isinstance(claim.get(field), str)
                    or hashlib.sha256(entry.read_bytes()).hexdigest() != claim[field]):
                    raise Refusal("Relay owner.json credential digest mismatch.")

    def _retire_ssh_principal(self, journal: dict, remove: bool = True) -> dict:
        """Never delete a replaced same-name UID; retain journal until userdel."""
        try:
            account = pwd.getpwnam(self.relay.ssh_user)
        except KeyError:
            return journal  # Prior verified userdel or no account created yet.
        uid = account.pw_uid
        marker = account_generation_marker(self.relay, journal["host_generation"])
        expected_uid = journal["ssh_uid"]
        try:
            canonical = pwd.getpwuid(uid)
            names = pwd.getpwall()
        except (KeyError, OSError) as error:
            raise Refusal("Cannot prove exclusive Relay SSH identity before account removal.") from error
        if (uid < 1 or uid == journal["gateway_php_uid"]
            or (expected_uid is not None and expected_uid != uid)
            or account.pw_gecos != marker
            or not account.pw_shell.endswith(("/nologin", "/false"))
            or canonical.pw_name != self.relay.ssh_user
            or any(user.pw_uid == uid and user.pw_name != self.relay.ssh_user
                   for user in names)):
            raise Refusal("Refusing deletion of replaced/unclaimed Relay SSH username or UID.")
        if expected_uid is None:
            # Power may have failed immediately after useradd, before UID
            # journaling. The per-generation passwd marker proves which
            # creation attempt this exact username belongs to. Bind once.
            journal = {**journal, "ssh_uid": uid}
            self._write_json_atomic(self.layout.evidence(self.relay, ".setup.json"), journal)
        if not remove:
            return journal
        proc = self.layout.at("/proc")
        for entry in proc.iterdir():
            if not entry.name.isdecimal():
                continue
            try:
                content = (entry / "status").read_text()
            except FileNotFoundError:
                if not entry.exists():
                    continue
                raise Refusal("Process identity changed while verifying Relay account retirement.")
            except (OSError, UnicodeError) as error:
                raise Refusal("Cannot prove dedicated SSH principal has no live process.") from error
            line = next((line for line in content.splitlines() if line.startswith("Uid:")), "")
            fields = line.split()[1:]
            if len(fields) != 4 or any(not field.isdecimal() for field in fields):
                raise Refusal("Cannot inspect actual process UID before userdel.")
            if uid in (int(field) for field in fields):
                raise Refusal("Dedicated Relay SSH identity still owns a process; preserve account.")
        deleted = self.run(["/usr/sbin/userdel", self.relay.ssh_user])
        if deleted.returncode:
            raise Refusal("Could not retire dedicated Relay SSH user: " + deleted.stderr[:140])
        try:
            pwd.getpwnam(self.relay.ssh_user)
        except KeyError:
            return journal
        raise Refusal("Relay SSH account still resolves after userdel.")

    def _retire_unclaimed_stage(self, journal: dict) -> dict:
        """Rollback an interrupted Setup with a valid journal but NO managed claim.

        Never infer ownership merely from names. Check the journal's exact
        unit digest, effective SSH argv, known-host pin, keypair and strict
        single-rule nft policy before deleting anything. A foreign artifact
        is retained and causes a refusal, not a generalized purge.
        """
        if (self._owned(self.layout.evidence(self.relay, ".json"))
            or self._owned(self.layout.evidence(self.relay, ".policy"))):
            raise Refusal("Unclaimed readiness evidence exists; staged rollback cannot adopt it.")
        owned_parents(self.layout.key_dir(self.relay), self.layout)
        owned_parents(self.layout.unit(self.relay).parent, self.layout)
        journal = self._retire_ssh_principal(journal, remove=False)
        unit = self.layout.unit(self.relay)
        info = self._systemd_info()
        if info["LoadState"] == "loaded":
            if info["FragmentPath"] != str(unit):
                raise Refusal("A foreign loaded systemd unit occupies the staged Relay name.")
            # A unit could remain cached after a prior rollback crash between
            # unlink and daemon-reload. Validate the ENTIRE effective SSH
            # command before removing this cached definition.
            GatewayPolicyAudit(self.relay, self.layout, self.run)._require_ssh_invocation(info["ExecStart"], journal)
        elif info["ExecStart"] or info["FragmentPath"]:
            raise Refusal("Unexpected unloaded systemd definition in staged rollback.")
        if self._unit_active() or self._unit_enabled():
            raise Refusal("Unclaimed staged Relay service is active or enabled; refusing rollback.")
        if self._listening({self.relay.local_port}):
            raise Refusal("SOCKS listener remains on the reserved port; preserve ACL.")
        nft_source = self.layout.evidence(self.relay, ".nft")
        has_table = self._nft_table_exists()
        if has_table:
            if not self._owned(nft_source):
                raise Refusal("Live nftables table has no matching journal-owned persistence source.")
            GatewayPolicyAudit(self.relay, self.layout, self.run)._require_effective_acl(journal["gateway_php_uid"])
            # Reject additional foreign nftables structures, even when
            # a superficially matching output_guard rule was found.
            self._nft_policy_digest()
        if has_table:
            removed = self.run(["nft", "delete", "table", "inet", self.relay.firewall_table])
            if removed.returncode:
                raise Refusal("Could not delete exactly claimed partially staged nftables ACL.")
        if self._nft_table_exists():
            raise Refusal("Partial-stage nftables table remains after deletion.")
        if self._listening({self.relay.local_port}):
            raise Refusal("Local SOCKS listener appeared during partial rollback.")
        if self._owned(unit):
            if hashlib.sha256(unit.read_bytes()).hexdigest() != journal["unit_sha256"]:
                raise Refusal("Staged service file changed before rollback.")
            self._unlink_owned_durable(unit)
        # Reload is needed even if the unit file was already absent, because
        # systemd may still hold an inactive cached definition from a crash.
        reloaded = self.run(["systemctl", "daemon-reload"])
        if reloaded.returncode:
            raise Refusal("Could not unload partially staged Relay systemd unit.")
        if self._unit_active() or self._unit_enabled():
            raise Refusal("Partially staged Relay service remained enabled/active.")
        self._assert_no_loaded_same_name_unit()
        journal = self._retire_ssh_principal(journal, remove=True)
        self._delete_setup_keydir()
        self._unlink_owned_durable(nft_source)
        return journal

    def _delete_setup_keydir(self) -> None:
        """Discard only proven staged files, AFTER the SSH UID is retired."""
        keydir = self.layout.key_dir(self.relay)
        if not self._owned(keydir, True):
            return
        allowed = {"control_key", "control_key.pub", "known_hosts", "owner.json"}
        files = {entry.name: entry for entry in keydir.iterdir()}
        if not set(files).issubset(allowed):
            raise Refusal("Refusing to erase unrecognized files in staged Relay keydir.")
        # owner.json can disappear only after account deletion; the root-owned
        # journal still carries the exact numeric original SSH UID until the
        # final host cleanup verification completes.
        # Keep the private key until LAST. If power fails mid-cleanup, a
        # remaining private-only prefix can still be validated by ssh-keygen.
        # Removing private before public strands an unprovable orphaned pubkey.
        for name in ("owner.json", "control_key.pub", "known_hosts", "control_key"):
            entry = files.get(name)
            if entry is not None:
                if not self._owned(entry):
                    raise Refusal("Untrusted private Relay file during staged cleanup.")
                self._unlink_owned_durable(entry)
        self._rmdir_owned_durable(keydir)

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
            # _preflight rejects unclaimed unit/keydir/table namespaces by
            # design. An exact root-owned Setup journal is the ONLY narrow
            # exception, and its artifacts receive separate complete proof.
            owned_parents(self.layout.unit(self.relay).parent, self.layout)
            owned_parents(self.layout.key_dir(self.relay), self.layout)
            managed = self._manifest()
            setup_journal = self._owned_setup_for_retirement(managed)
            if managed is not None or setup_journal is None:
                self._preflight()
            if setup_journal is None:
                # A v2 managed claim alone cannot authenticate a later
                # dedicated account or mystery credentials. Check before
                # stopping any service, deleting ACL or writing a receipt.
                self._require_unjournaled_legacy_safe()
            if setup_journal is not None:
                # Catch replaced same-name UIDs and mismatched owner.json
                # BEFORE service stop, firewall mutation or file deletion.
                setup_journal = self._retire_ssh_principal(setup_journal, remove=False)
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
                self._unlink_owned_durable(unit)
                # A prior interrupted attempt may have unlinked the unit
                # before reload completed. Repeat reload even when missing
                # so stale systemd unit caches cannot strand recovery.
                daemon = self.run(["systemctl", "daemon-reload"])
                if daemon.returncode != 0:
                    raise Refusal("systemd daemon-reload failed; retry cleanup.")
                if self._unit_enabled():
                    raise Refusal("Relay systemd service remains enabled after local cleanup.")
                if setup_journal is not None:
                    setup_journal = self._retire_ssh_principal(setup_journal, remove=True)
                    persistence = self.layout.evidence(self.relay, ".nft")
                    self._unlink_owned_durable(persistence)
                self._delete_setup_keydir()
            elif setup_journal is not None:
                setup_journal = self._retire_unclaimed_stage(setup_journal)
            else:
                if self._unit_active():
                    raise Refusal("A Relay service is still active without a recognized owned claim.")
                if self._listening(ports):
                    raise Refusal("SOCKS5 listener is still active; refuse false retirement proof.")
            for ext in [".json", ".policy"]:
                path = self.layout.evidence(self.relay, ext)
                self._unlink_owned_durable(path)
            if self._unit_active() or self._unit_enabled() or self._nft_table_exists() or self._listening(ports):
                raise Refusal("Cleanup verification did not reach the disabled/inactive/absent state.")
            # A systemd daemon-reload can expose a foreign replacement unit
            # under the same name. Never issue a clean-host proof while any
            # effective definition is still loaded, even if inactive.
            self._assert_no_loaded_same_name_unit()
            if setup_journal is None:
                self._require_unjournaled_legacy_safe()
            # Preserve the v2 ownership claim until final host checks pass;
            # a foreign unit discovered after daemon-reload must remain
            # diagnosable and must not be mistaken for an unclaimed draft.
            if managed:
                self._unlink_owned_durable(self.layout.evidence(self.relay, ".managed.json"))
            # Keep the UID-bound root-owned Setup journal through ALL service,
            # keydir and account removal, and through final listener/systemd/
            # nft checks. If power is lost after managed-claim deletion but
            # before journal deletion, the pre-claim rollback path can resume.
            if setup_journal is not None:
                self._unlink_owned_durable(self.layout.evidence(self.relay, ".setup.json"))
            # The previous action might have crashed immediately after an
            # unlink and before its directory fsync. On retry, that path is
            # already absent in memory: flush ALL affected durable namespaces
            # again before changing the generation or issuing a receipt.
            for parent in (
                self.layout.unit(self.relay).parent,
                self.layout.key_dir(self.relay).parent,
                self.layout.evidence_dir,
            ):
                if self._owned(parent, True):
                    self._fsync_directory(parent)
            generation = self._advance_generation("retired")
            self._receipt(generation)
            return ("RETIREMENT VERIFIED for Gateway Relay " + self.relay.relay_id
                    + ". Relay peer was not contacted, and its cleanup was not asserted.")
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
                    "Relay peer was not contacted.")
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
            if self._owned(self.layout.evidence(self.relay, ".setup.json")):
                raise Refusal("A Relay Setup journal is active; resume the exact Setup or verified local retirement.")
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
    and effective local controls cannot prove the independent Relay peer egress
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

    def _audit_locked(self, php_uid: int, require_enabled: bool = True) -> str:
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
        if not self._unit_active() or (require_enabled and not self._unit_persistently_enabled()):
            raise Refusal("Relay service is stopped or has no verified permanent boot enablement.")
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
                "Relay peer egress restrictions and Target authentication still "
                "require independent verified evidence.")



    def _staged_public_key_locked(self) -> str:
        """Strict read-only validation of an inactive Setup under an already held lifecycle lock."""
        self._require_mutable_revision()
        managed = self._preflight()
        if managed is None:
            raise Refusal("No exact staged Relay resource claim; finish Gateway Setup before exporting the public key.")
        journal = self._owned_setup_for_retirement(managed)
        if (journal is None or journal["ssh_uid"] is None
            or journal["configuration_revision"] != self.relay.revision
            or journal["host_fingerprint"] != self.relay.fingerprint):
            raise Refusal("No current UID-bound Setup journal; refusing an unproven public key.")
        # Retirement intentionally keeps the managed claim and original
        # UID-bound journal until AFTER unit/ACL teardown and SSH-account
        # removal. They are necessary but insufficient evidence that a
        # Gateway Setup stage remains complete. Never use the reusable
        # _verify_effective_systemd(): it may daemon-reload as a Repair
        # side effect. A public-key handoff must be STRICTLY read-only.
        unit = self.layout.unit(self.relay)
        nft_source = self.layout.evidence(self.relay, ".nft")
        unit_digest = hashlib.sha256(unit.read_bytes()).hexdigest() if self._owned(unit) else None
        if (unit_digest is None
            or unit_digest != managed["unit_sha256"]
            or unit_digest != journal["unit_sha256"]):
            raise Refusal("Staged Relay systemd unit is missing or differs from its original journal and claim.")
        if (not self._owned(nft_source)
            or nft_source.read_bytes() != nft_policy_source(
                self.relay, journal["gateway_php_uid"])):
            raise Refusal("Staged Relay nftables persistence source is missing or changed.")
        info = self._systemd_info()
        if (info["LoadState"] != "loaded"
            or info["ActiveState"] != "inactive"
            or info["FragmentPath"] != str(unit)
            or info["NeedDaemonReload"] != "no"
            or hashlib.sha256(self._canonical_exec(info["ExecStart"]).encode()).hexdigest()
               != managed["unit_exec_sha256"]):
            raise Refusal("Effective staged Relay systemd definition is missing, stale or foreign.")
        if self._unit_active() or self._unit_enabled():
            raise Refusal("Relay service is not in its expected inactive, disabled staged state.")
        if not self._verify_effective_nft(managed):
            raise Refusal("Effective staged Relay nftables policy is absent; run controlled Setup/Repair.")
        self._require_effective_acl(journal["gateway_php_uid"])
        keydir = self.layout.key_dir(self.relay)
        required = {"control_key", "control_key.pub", "known_hosts", "owner.json"}
        if (not self._owned(keydir, True)
            or keydir.stat().st_mode & 0o777 != 0o700
            or {entry.name for entry in keydir.iterdir()} != required):
            raise Refusal("Staged Relay credential namespace is not complete and isolated.")
        owner = self._json(keydir / "owner.json")
        expected = {
            "version", "relay_record_id", "relay_id", "ssh_user",
            "ssh_uid", "gateway_php_uid", "control_host", "control_port",
            "control_user", "control_key_sha256", "control_key_pub_sha256",
            "known_hosts_sha256",
        }
        if (set(owner) != expected
            or owner["ssh_uid"] != journal["ssh_uid"]
            or owner["gateway_php_uid"] != journal["gateway_php_uid"]):
            raise Refusal("Staged Relay public key lacks its exact root-owned ownership claim.")
        self._require_control_key_pair(keydir)
        self._require_ssh_invocation(info["ExecStart"], owner)
        # Verify the local NSS identity without requiring an unrelated
        # sibling Relay's partially staged keydir to be fully provisioned.
        try:
            account = pwd.getpwnam(self.relay.ssh_user)
            canonical = pwd.getpwuid(account.pw_uid)
            accounts = pwd.getpwall()
        except (KeyError, OSError) as error:
            raise Refusal("Dedicated Relay SSH account cannot be verified for public-key export.") from error
        if (account.pw_uid != journal["ssh_uid"] or account.pw_uid <= 0
            or account.pw_gecos != account_generation_marker(self.relay, journal["host_generation"])
            or not account.pw_shell.endswith(("/nologin", "/false"))
            or canonical.pw_name != self.relay.ssh_user
            or any(user.pw_uid == account.pw_uid and user.pw_name != self.relay.ssh_user
                   for user in accounts)):
            raise Refusal("Dedicated Relay SSH account no longer matches its staged generation.")
        public = (keydir / "control_key.pub").read_bytes()
        if len(public) > 1024:
            raise Refusal("Staged public key exceeds reviewed Ed25519 length.")
        try:
            line = public.decode("ascii").strip()
        except UnicodeDecodeError as error:
            raise Refusal("Staged public key is not valid ASCII.") from error
        if (journal["configuration_revision"] != self.relay.revision
            or journal["host_fingerprint"] != self.relay.fingerprint
            or managed["configuration_revision"] != self.relay.revision
            or managed["host_fingerprint"] != self.relay.fingerprint
            or managed["host_generation"] != journal["host_generation"]):
            raise Refusal("Staged Relay enrollment identity is not current-generation bound.")
        return (
            "PUBLIC ONLY - OFFLINE RELAY PEER ENROLLMENT INPUT V2\n"
            "Relay: " + self.relay.relay_id + "\n"
            "Record: " + self.relay.record_id + "\n"
            "Configuration revision: " + str(self.relay.revision) + "\n"
            "Host fingerprint: " + self.relay.fingerprint + "\n"
            "Host generation: " + journal["host_generation"] + "\n"
            "Control endpoint: " + journal["control_host"] + ":" + str(journal["control_port"]) + "\n"
            "Control user on Relay peer: " + journal["control_user"] + "\n"
            "Ed25519 PUBLIC KEY (never copy the private key):\n" + line + "\n"
            "NOT ENROLLED. Restrict Relay peer SSHD forwarding and public egress separately; "
            "verify both hosts and issue independent readiness before enabling."
        )


    def public_enrollment(self) -> str:
        """Export only the exact staged Ed25519 public key for offline Relay peer setup.

        This is a read-only, current-generation inspection, NOT Relay peer
        enrollment, service activation, or host readiness attestation.
        """
        if os.geteuid() != self.layout.owner_uid:
            raise Refusal("Public Relay enrollment export requires explicit root execution.")
        lock = self.layout.lock_path(self.relay)
        owned_parents(lock.parent, self.layout)
        if not self._owned(lock):
            raise Refusal("Root-owned Relay lifecycle lock is missing; cannot export staged identity.")
        fd = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            return self._staged_public_key_locked()
        except BlockingIOError as error:
            raise Refusal("Relay lifecycle maintenance is active; retry public-key export afterward.") from error
        finally:
            os.close(fd)




class GatewayReadinessIssuer(GatewayPolicyAudit):
    """Privileged, explicit operator attestation, never an application action.

    Local host checks are performed by the trusted root helper under the
    lifecycle lock. FPM/CLI separation and intermediary egress are external
    operator acceptance tests, not inferred from an active SOCKS listener.
    """

    LEASE_SECONDS = 3600

    def activate(
        self, php_uid: int, php_fpm_cli_verified: bool,
        peer_egress_verified: bool,
    ) -> str:
        """Queue only a verified staged Relay unit; keep it disabled until audited.

        ExecStartPre re-acquires this same lifecycle lock. Starting the unit
        synchronously while locked would deadlock. An asynchronous start is
        enqueued under the lock, and the next explicit operator step proves
        the live service before enabling it and issuing readiness.
        """
        if (type(php_uid) is not int or php_uid < 1
            or php_fpm_cli_verified is not True or peer_egress_verified is not True):
            raise Refusal("The host operator must verify PHP identity isolation and intermediary egress before activation.")
        fd = self._locked()
        try:
            self._staged_public_key_locked()
            journal = self._owned_setup_for_retirement(self._manifest())
            if journal is None or journal["gateway_php_uid"] != php_uid:
                raise Refusal("Actual Gateway PHP UID does not match the staged Relay admission policy.")
            if (self._owned(self.layout.evidence(self.relay, ".json"))
                or self._owned(self.layout.evidence(self.relay, ".policy"))):
                raise Refusal("Revoke existing readiness evidence before a fresh activation.")
            started = self.run(["systemctl", "start", "--no-block", self.relay.unit_name])
            if started.returncode:
                raise Refusal("Unable to queue current Relay service start: " + started.stderr[:140])
            return (
                "RELAY START QUEUED, NOT READY for " + self.relay.relay_id
                + ". Unit remains DISABLED and no readiness was issued. "
                "Wait for verified active local OpenSSH and successful independent "
                "PHP/peer tests, then run the separate root issue-readiness action."
            )
        except BlockingIOError as error:
            raise Refusal("Relay lifecycle maintenance is active; no activation occurred.") from error
        finally:
            os.close(fd)

    def _locked(self) -> int:
        if os.geteuid() != self.layout.owner_uid:
            raise Refusal("Only an independent privileged Gateway host operator may issue or revoke readiness.")
        lock = self.layout.lock_path(self.relay)
        owned_parents(lock.parent, self.layout)
        if not self._owned(lock):
            raise Refusal("Current root-owned Relay lifecycle lock is missing.")
        fd = os.open(lock, os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except BlockingIOError as error:
            os.close(fd)
            raise Refusal("Relay lifecycle maintenance is active; retry readiness operation.") from error
        except BaseException:
            os.close(fd)
            raise

    def _policy_file(self, generation: str) -> None:
        # Reuse Setup's crash-consistent, anonymous no-clobber O_TMPFILE
        # publication. No named temporary artifacts survive power loss.
        self._write_exact(
            self.layout.evidence(self.relay, ".policy"),
            (generation + "\n").encode("ascii"), 0o644,
        )

    def _current_proof_path(self, php_uid: int, generation: str) -> Path:
        path = self.layout.evidence(self.relay, ".json")
        if self._owned(path):
            previous = self._json(path)
            keys = {
                "relay_id", "host_fingerprint", "gateway_php_uid",
                "dedicated_php_uid_verified", "socks_access_acl_verified",
                "relay_egress_verified", "verified_boot_id",
                "policy_generation", "verified_at_unix",
                "verified_at_boot_seconds", "expires_at_unix",
            }
            # Legacy 10-key evidence was never PHP-ready. A separately
            # verified root issuance can replace its same-identity contents
            # with the current 11-key boot-relative lease; PHP cannot.
            prior_keys = set(previous)
            if (prior_keys not in (keys, keys - {"verified_at_boot_seconds"})
                or previous["relay_id"] != self.relay.relay_id
                or previous["host_fingerprint"] != self.relay.fingerprint
                or previous["gateway_php_uid"] != php_uid
                or previous["policy_generation"] != generation):
                raise Refusal("Existing readiness evidence is not owned by the current Relay identity.")
        return path

    def _read_lease_clock(self) -> tuple[str, int, int]:
        """Read a single live boot/uptime/Unix sample; refuse invalid clocks."""
        boot = self.layout.at("/proc/sys/kernel/random/boot_id").read_text().strip()
        uptime = self.layout.at("/proc/uptime").read_text().strip()
        if not re.fullmatch(r"[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}", boot):
            raise Refusal("No valid current Gateway host boot ID.")
        match = re.fullmatch(r"([0-9]+)\.[0-9]+[ \t]+[0-9]+\.[0-9]+", uptime)
        if match is None:
            raise Refusal("No valid boot-relative Gateway host uptime.")
        seconds = int(match[1])
        now = int(time.time())
        if seconds < 0 or now < 1:
            raise Refusal("Invalid readiness verification clock.")
        return boot, seconds, now

    def issue(
        self, php_uid: int, php_fpm_cli_verified: bool,
        peer_egress_verified: bool,
    ) -> str:
        if (type(php_uid) is not int or php_uid < 1
            or php_fpm_cli_verified is not True or peer_egress_verified is not True):
            raise Refusal(
                "Independent host operator must first verify dedicated Gateway PHP-FPM/CLI UID "
                "isolation and positive/negative intermediary egress; both confirmations are mandatory."
            )
        fd = self._locked()
        try:
            self._require_mutable_revision()
            # Unlike PHP, the root operator reads live systemd, process,
            # credentials, nftables and listener evidence under this lock.
            # The first explicit activation starts the service but leaves it
            # disabled. Only a successful active-service audit may enable
            # persistence. No proof is published before both pass.
            # Verify the claimed revision, previous evidence and policy path
            # BEFORE enabling a running service. Foreign or malformed proof
            # files must not cause even a persistence side effect.
            generation = self._generation()
            if generation is None or generation["state"] != "provisioning":
                raise Refusal("No current provisioned host generation to attest.")
            policy = generation["host_generation"]
            path = self._current_proof_path(php_uid, policy)
            policy_path = self.layout.evidence(self.relay, ".policy")
            if (self._owned(policy_path)
                and policy_path.read_bytes() != (policy + "\n").encode("ascii")):
                raise Refusal("Existing root-owned readiness policy differs from the current generation.")
            # Clock readability/identity must fail closed before any new
            # persistent systemd mutation. The final lease uses a fresh
            # sample after the last successful effective host audit.
            self._read_lease_clock()
            if self._unit_persistently_enabled():
                self._audit_locked(php_uid)
            else:
                self._audit_locked(php_uid, require_enabled=False)
                enabled = self.run(["systemctl", "enable", self.relay.unit_name])
                if enabled.returncode:
                    raise Refusal("Cannot enable audited Relay service: " + enabled.stderr[:140])
                # Do not trust enable's exit status: systemd may still
                # report enabled-runtime, linked, alias or another state.
                # _audit_locked requires exact permanent enablement.
                self._audit_locked(php_uid)
            boot, seconds, now = self._read_lease_clock()
            proof = {
                "relay_id": self.relay.relay_id,
                "host_fingerprint": self.relay.fingerprint,
                "gateway_php_uid": php_uid,
                "dedicated_php_uid_verified": True,
                "socks_access_acl_verified": True,
                "relay_egress_verified": True,
                "verified_boot_id": boot,
                "policy_generation": policy,
                "verified_at_unix": now,
                "verified_at_boot_seconds": seconds,
                "expires_at_unix": now + self.LEASE_SECONDS,
            }
            self._policy_file(policy)
            self._write_json_atomic(path, proof)
            return (
                "ROOT OPERATOR READINESS ISSUED for " + self.relay.relay_id
                + " (one-hour lease). Gateway systemd/process/nft/listener passed live audit. "
                "Dedicated PHP-FPM/CLI isolation and intermediary egress were explicitly "
                "confirmed by the independent host operator, not proven by this source "
                "or by PHP. Target login is still a separate end-to-end test."
            )
        except BlockingIOError as error:
            raise Refusal("Relay lifecycle maintenance is active; no readiness was issued.") from error
        finally:
            os.close(fd)

    def revoke(self) -> str:
        """Immediately fail PHP readiness closed; do not modify the service."""
        fd = self._locked()
        try:
            self._require_mutable_revision()
            managed = self._manifest()
            if managed is None:
                raise Refusal("No current owned host generation for scoped readiness revocation.")
            policy = managed["host_generation"]
            owner = self._json(self.layout.key_dir(self.relay) / "owner.json")
            php_uid = owner.get("gateway_php_uid")
            if (owner.get("relay_record_id") != self.relay.record_id
                or owner.get("relay_id") != self.relay.relay_id
                or type(php_uid) is not int or php_uid < 1):
                raise Refusal("No current root-owned Relay PHP UID claim for readiness revocation.")
            self._current_proof_path(php_uid, policy)
            policy_path = self.layout.evidence(self.relay, ".policy")
            if self._owned(policy_path) and policy_path.read_bytes() != (policy + "\n").encode("ascii"):
                raise Refusal("Refusing to remove foreign readiness policy.")
            self._unlink_owned_durable(self.layout.evidence(self.relay, ".json"))
            self._unlink_owned_durable(policy_path)
            return (
                "GATEWAY READINESS REVOKED for " + self.relay.relay_id
                + ". The SSH transport service was NOT stopped by this evidence-only action; "
                "disable/restrict the Relay separately before host-policy changes."
            )
        except BlockingIOError as error:
            raise Refusal("Relay lifecycle maintenance is active; retry revocation.") from error
        finally:
            os.close(fd)


class GatewayAclRecovery(GatewayPolicyAudit):
    """Systemd ExecStartPre helper: refuse foreign ACLs, repair absence only."""

    def ensure(self, php_uid: int) -> str:
        if os.geteuid() != self.layout.owner_uid or type(php_uid) is not int or php_uid <= 0:
            raise Refusal("Gateway ACL recovery requires dedicated PHP UID and root execution.")

        # This helper is a systemd ExecStartPre command. The Setup action
        # stages a DISABLED unit and never starts it, so there is no need
        # for an unlocked fast path. Both the already-present and absent-
        # table cases must serialize against Retirement/Seal/Setup to avoid
        # a stale PASS while an external operator retires the Relay.
        lock = self.layout.lock_path(self.relay)
        owned_parents(lock.parent, self.layout)
        # /run is tmpfs on typical hosts: after a real reboot both the
        # directory and the lock inode can be missing. Recreate exactly the
        # SAME per-Relay lock used by Setup/Retire/Seal, under trusted root-
        # owned parents, before reading the generation or changing nftables.
        make_privileged_directory(lock.parent, self.layout)
        fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            if not self._owned(lock):
                raise Refusal("Untrusted Relay lifecycle lock after cold boot.")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._require_mutable_revision()
            managed = self._manifest()
            if managed is None:
                raise Refusal("No exact owned provisioned Relay claim for ACL recovery.")
            journal = self._json(self.layout.evidence(self.relay, ".setup.json"), 4096)
            if (journal.get("relay_record_id") != self.relay.record_id
                or journal.get("relay_id") != self.relay.relay_id
                or journal.get("configuration_revision") != self.relay.revision
                or journal.get("host_fingerprint") != self.relay.fingerprint
                or journal.get("host_generation") != managed["host_generation"]
                or journal.get("gateway_php_uid") != php_uid):
                raise Refusal("ACL recovery journal is inconsistent with current Relay ownership.")
            nft_file = self.layout.evidence(self.relay, ".nft")
            if not self._owned(nft_file) or nft_file.read_bytes() != nft_policy_source(self.relay, php_uid):
                raise Refusal("Pinned root-owned Relay nftables source is missing or modified.")
            unit = self.layout.unit(self.relay)
            if not self._owned(unit) or hashlib.sha256(unit.read_bytes()).hexdigest() != managed["unit_sha256"]:
                raise Refusal("Relay unit is missing or changed during ACL recovery.")

            if self._nft_table_exists():
                if not self._verify_effective_nft(managed):
                    raise Refusal("Relay ACL does not match its provisioned digest.")
                self._require_effective_acl(php_uid)
                return "RELAY ACL VERIFIED: existing exact owned IPv4/IPv6 guard preserved."

            result = self.run(["/usr/sbin/nft", "-f", str(nft_file)])
            if result.returncode != 0:
                raise Refusal("Could not restore exact Relay ACL: " + result.stderr[:140])
            if not self._verify_effective_nft(managed):
                raise Refusal("Restored Relay ACL differs from the claimed full policy.")
            self._require_effective_acl(php_uid)
            return "RELAY ACL RESTORED: exact owned IPv4/IPv6 output guard."
        except BlockingIOError as error:
            raise Refusal("Relay lifecycle maintenance is active; systemd can retry later.") from error
        finally:
            os.close(fd)


class GatewaySetup(GatewayPolicyAudit):
    """Explicit Owner-operated Gateway-only Setup/Repair. Never issues readiness.

    This helper owns the initial generation transition under the lifecycle
    lock and records a root-owned journal before allocating an account/files.
    A partial phase is resumable only for the same Relay, revision and inputs.
    """

    def __init__(
        self, relay: Relay, control_host: str, control_port: int,
        control_user: str, host_key: str, php_uid: int,
        layout: Layout = Layout(),
        run: Callable[[list[str]], subprocess.CompletedProcess[str]] = run_checked,
    ):
        super().__init__(relay, layout, run)
        if type(php_uid) is not int or php_uid < 1:
            raise Refusal("Gateway setup needs the actual dedicated non-root PHP UID.")
        try:
            ipaddress.ip_address(control_host)
        except ValueError:
            labels = control_host.split(".")
            if (len(control_host) > 253 or len(labels) < 2 or
                any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                    for label in labels)):
                raise Refusal("Gateway Setup requires an exact canonical SSH host.")
        if type(control_port) is not int or not 1 <= control_port <= 65535:
            raise Refusal("Gateway Setup control port is invalid.")
        if (not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.+-]{0,127}", control_user)
            or control_user == "root"):
            raise Refusal("Gateway Setup requires a dedicated non-root forwarding-only SSH control user.")
        if "\n" in host_key or "\\r" in host_key or len(host_key) > 4096:
            raise Refusal("Gateway Setup requires one independently pinned host key.")
        items = host_key.split(" ")
        allowed = {"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256",
                   "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}
        if len(items) != 2 or items[0] not in allowed:
            raise Refusal("Unsupported pinned SSH server host key.")
        try:
            binary = base64.b64decode(items[1], validate=True)
        except (ValueError, UnicodeError) as error:
            raise Refusal("Invalid pinned SSH host key.") from error
        label = items[0].encode()
        if (len(binary) < 16 or len(binary) > 3072
            or binary[:4] != len(label).to_bytes(4, "big")
            or binary[4:4 + len(label)] != label):
            raise Refusal("Pinned SSH host key algorithm and wire bytes differ.")
        canonical_key = items[0] + " " + base64.b64encode(binary).decode()
        expected_fingerprint = hashlib.sha256("\0".join((
            relay.relay_id, control_host, str(control_port), control_user,
            canonical_key, str(relay.local_port), str(relay.revision),
        )).encode()).hexdigest()
        if expected_fingerprint != relay.fingerprint:
            raise Refusal("Setup metadata does not match exact current Gateway registration fingerprint.")
        self.control_host = control_host
        self.control_port = control_port
        self.control_user = control_user
        self.host_key = canonical_key
        self.php_uid = php_uid

    @property
    def journal_path(self) -> Path:
        return self.layout.evidence(self.relay, ".setup.json")

    @property
    def nft_path(self) -> Path:
        return self.layout.evidence(self.relay, ".nft")

    def _journal_payload(self, generation: str) -> dict:
        return {
            "version": 2,
            "relay_record_id": self.relay.record_id,
            "relay_id": self.relay.relay_id,
            "host_fingerprint": self.relay.fingerprint,
            "configuration_revision": self.relay.revision,
            "host_generation": generation,
            "ssh_user": self.relay.ssh_user,
            "ssh_uid": None,  # Atomically bound immediately after useradd/NSS proof.
            "gateway_php_uid": self.php_uid,
            "control_host": self.control_host,
            "control_port": self.control_port,
            "control_user": self.control_user,
            "host_key_sha256": hashlib.sha256(self.host_key.encode()).hexdigest(),
            "unit_sha256": hashlib.sha256(self._unit_source()).hexdigest(),
        }

    def _nft_source(self) -> bytes:
        return nft_policy_source(self.relay, self.php_uid)

    def _ssh_argv(self) -> list[str]:
        credential_root = "/run/credentials/" + self.relay.unit_name
        return [
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
            "-p", str(self.control_port), "-l", self.control_user, self.control_host,
        ]

    def _unit_source(self) -> bytes:
        keydir = "/var/lib/mcp-gateway-relays/" + self.relay.relay_id
        # Use no arbitrary shell text: every rendered argument is strictly
        # validated, and the prestart nft command operates on only this table.
        source = (
            "# MCP-GATEWAY-CONNECTION-RELAY " + self.relay.record_id + " " + self.relay.relay_id + "\n"
            "[Unit]\n"
            "Description=Gateway Connection Relay " + self.relay.relay_id + "\n"
            "Wants=network-online.target\n"
            "After=network-online.target\n"
            "[Service]\n"
            "Type=simple\n"
            "User=" + self.relay.ssh_user + "\n"
            "NoNewPrivileges=yes\n"
            "PrivateTmp=yes\n"
            "ProtectSystem=strict\n"
            "ProtectHome=yes\n"
            "LoadCredential=control_key:" + keydir + "/control_key\n"
            "LoadCredential=known_hosts:" + keydir + "/known_hosts\n"
            "ExecStartPre=+/usr/local/sbin/mcp-gateway-relay ensure-acl"
            " --relay-id " + self.relay.relay_id +
            " --record-id " + self.relay.record_id +
            " --fingerprint " + self.relay.fingerprint +
            " --revision " + str(self.relay.revision) +
            " --local-port " + str(self.relay.local_port) +
            " --php-uid " + str(self.php_uid) + "\n"
            "ExecStart=" + " ".join(self._ssh_argv()) + "\n"
            "Restart=always\n"
            "RestartSec=5\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )
        return source.encode("ascii")

    def _expected_hostkey(self) -> bytes:
        # OpenSSH's default-port lookup uses the literal hostname/IP, while
        # nondefault ports require [host]:port (also for IPv6 literals).
        # A bracketed :22 entry does NOT match the default-port lookup.
        identity = (self.control_host if self.control_port == 22 else
                    "[" + self.control_host + "]:" + str(self.control_port))
        return (identity + " " + self.host_key + "\n").encode("ascii")

    def _identity(self, journal: dict) -> int:
        marker = account_generation_marker(self.relay, journal["host_generation"])
        expected_uid = journal["ssh_uid"]
        try:
            account = pwd.getpwnam(self.relay.ssh_user)
        except KeyError:
            account = None
        if account is None:
            if expected_uid is not None:
                raise Refusal("A journal-bound Relay SSH UID disappeared; refuse replacement or adoption.")
            # The unique generation is stored in the durable root journal
            # before useradd. An interrupted useradd can be recovered only if
            # the current account has this exact immutable GECOS marker.
            result = self.run(["/usr/sbin/useradd", "--system", "--no-create-home",
                               "--user-group", "--shell", "/usr/sbin/nologin",
                               "--comment", marker, self.relay.ssh_user])
            if result.returncode:
                raise Refusal("Unable to create the dedicated per-Relay SSH identity: " + result.stderr[:140])
            try:
                account = pwd.getpwnam(self.relay.ssh_user)
            except KeyError as error:
                raise Refusal("Created SSH account cannot be independently resolved.") from error
        try:
            canonical = pwd.getpwuid(account.pw_uid)
            accounts = pwd.getpwall()
        except (KeyError, OSError) as error:
            raise Refusal("Cannot prove dedicated Relay SSH UID ownership.") from error
        if (account.pw_uid < 1 or account.pw_uid == self.php_uid
            or (expected_uid is not None and account.pw_uid != expected_uid)
            or account.pw_gecos != marker
            or not account.pw_shell.endswith(("/nologin", "/false"))
            or canonical.pw_name != self.relay.ssh_user
            or any(user.pw_uid == account.pw_uid and user.pw_name != self.relay.ssh_user
                   for user in accounts)):
            raise Refusal("Dedicated Relay SSH principal differs from its root-owned generation/UID claim.")
        if expected_uid is None:
            # This record survives full/partial retirement even after owner.json
            # and the key directory are gone. No earlier UID may be overwritten.
            bound = {**journal, "ssh_uid": account.pw_uid}
            self._write_json_atomic(self.journal_path, bound)
        return account.pw_uid

    def _material(self, ssh_uid: int) -> None:
        parent = self.layout.key_dir(self.relay).parent
        owned_parents(parent, self.layout)
        make_privileged_directory(parent, self.layout)
        make_privileged_directory(self.layout.key_dir(self.relay), self.layout)
        keydir = self.layout.key_dir(self.relay)
        if keydir.stat().st_mode & 0o777 != 0o700:
            raise Refusal("Relay private key directory is not mode 0700.")
        required = {"control_key", "control_key.pub", "known_hosts", "owner.json"}
        if any(e.name not in required or not self._owned(e) for e in keydir.iterdir()):
            raise Refusal("Foreign file exists in Relay SSH material directory.")
        private = keydir / "control_key"
        public = keydir / "control_key.pub"
        if not self._owned(private):
            if self._owned(public):
                raise Refusal("Orphaned public key requires explicit operator recovery.")
            result = self.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519",
                               "-N", "", "-C", "", "-f", str(private)])
            if result.returncode:
                raise Refusal("Unable to generate dedicated root-controlled Relay SSH key.")
        if not self._owned(private) or private.stat().st_mode & 0o777 != 0o600:
            raise Refusal("Dedicated Relay private key is unsafe.")
        derived = self.run(["/usr/bin/ssh-keygen", "-y", "-P", "", "-f", str(private)])
        if derived.returncode or not derived.stdout.startswith("ssh-ed25519 "):
            raise Refusal("Cannot independently derive the Relay control public key.")
        pub_fields = derived.stdout.strip().split()
        if len(pub_fields) < 2:
            raise Refusal("Invalid derived Relay public key.")
        if self._owned(public):
            try:
                installed_fields = public.read_bytes().decode("ascii").strip().split()
            except UnicodeDecodeError as error:
                raise Refusal("Invalid installed Relay public key.") from error
            if (installed_fields != pub_fields[:2]
                or (public.stat().st_mode & 0o777) not in {0o600, 0o640, 0o644}):
                raise Refusal("Installed Relay public key differs from its private control key.")
        else:
            publine = " ".join(pub_fields[:2]) + "\n"
            self._write_exact(public, publine.encode("ascii"), 0o644)
        self._write_exact(keydir / "known_hosts", self._expected_hostkey(), 0o644)
        owner = {
            "version": 2, "relay_record_id": self.relay.record_id,
            "relay_id": self.relay.relay_id, "ssh_user": self.relay.ssh_user,
            "ssh_uid": ssh_uid, "gateway_php_uid": self.php_uid,
            "control_host": self.control_host, "control_port": self.control_port,
            "control_user": self.control_user,
            "control_key_sha256": hashlib.sha256(private.read_bytes()).hexdigest(),
            "control_key_pub_sha256": hashlib.sha256(public.read_bytes()).hexdigest(),
            "known_hosts_sha256": hashlib.sha256((keydir / "known_hosts").read_bytes()).hexdigest(),
        }
        self._write_exact(keydir / "owner.json",
                          (json.dumps(owner, sort_keys=True, separators=(",", ":")) + "\n").encode(), 0o644)

    def setup(self) -> str:
        if os.geteuid() != self.layout.owner_uid:
            raise Refusal("Explicit root execution is required to provision Gateway Relay resources.")
        lockpath = self.layout.lock_path(self.relay)
        owned_parents(lockpath.parent, self.layout)
        make_privileged_directory(lockpath.parent, self.layout)
        fd = os.open(lockpath, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            if not self._owned(lockpath):
                raise Refusal("Unsafe Relay Setup lock ownership.")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # A first-ever Gateway Setup has no /etc/mcp-gateway evidence
            # namespace. Create and check it before the first atomic
            # generation transition (which fsyncs the directory).
            make_privileged_directory(self.layout.evidence_dir, self.layout, php_traversable=True)
            self._require_mutable_revision()
            generation = self._generation()
            if generation is None or generation["state"] == "retired":
                # One Owner command owns both the generation barrier and
                # staged resources. Previously issued readiness/retirement
                # receipts are invalidated BEFORE host resources are added.
                if self._preflight() is not None:
                    raise Refusal("A managed Relay still exists; verified retirement is required.")
                if (self._unit_active() or self._unit_enabled() or self._nft_table_exists()
                    or self._listening({self.relay.local_port})):
                    raise Refusal("Cannot begin Setup while unclaimed host resources remain.")
                token = self._advance_generation("provisioning")
                retired = self.layout.evidence(self.relay, ".retired.json")
                if self._owned(retired):
                    retired.unlink()
                generation = self._generation()
                if generation is None or generation["host_generation"] != token:
                    raise Refusal("Could not establish current Relay Setup generation.")
            elif generation["state"] != "provisioning":
                raise Refusal("Invalid host generation state for a new Setup.")
            make_privileged_directory(self.layout.evidence_dir, self.layout, php_traversable=True)
            existing = self._owned(self.journal_path)
            expected = self._journal_payload(generation["host_generation"])
            if existing:
                journal = self._json(self.journal_path)
                expected_claim = {**expected, "ssh_uid": journal.get("ssh_uid")}
                if (journal != expected_claim
                    or (journal["ssh_uid"] is not None
                        and (type(journal["ssh_uid"]) is not int or journal["ssh_uid"] < 1))):
                    raise Refusal("Setup journal belongs to a different Relay configuration or SSH identity.")
            else:
                # A previously prepared generation is not permission to
                # claim a foreign listener, loaded unit or firewall. Refuse
                # any unjournaled resource BEFORE account or ACL changes.
                if (self._preflight() is not None
                    or self.layout.key_dir(self.relay).exists()
                    or self.layout.unit(self.relay).exists()
                    or self._nft_table_exists() or self.nft_path.exists()
                    or self._unit_active() or self._unit_enabled()
                    or self._listening({self.relay.local_port})):
                    raise Refusal("Unjournaled Relay port/service/firewall resources may not be adopted by Setup.")
                try:
                    pwd.getpwnam(self.relay.ssh_user)
                except KeyError:
                    pass
                else:
                    raise Refusal("Refusing to adopt a pre-existing SSH principal without a matching setup journal.")
                self._write_exact(self.journal_path,
                                  (json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n").encode(), 0o644)
                journal = expected
            # A crash between useradd and durable UID recording is recovered
            # through the exact per-generation passwd GECOS marker.
            uid = self._identity(journal)
            self._material(uid)
            self._write_exact(self.nft_path, self._nft_source(), 0o644)
            self._write_exact(self.layout.unit(self.relay), self._unit_source(), 0o644)
            reloaded = self.run(["systemctl", "daemon-reload"])
            if reloaded.returncode:
                raise Refusal("Could not reload newly staged Relay unit; exact journal retained for Repair.")
            info = self._systemd_info()
            if info["LoadState"] != "loaded" or info["FragmentPath"] != str(self.layout.unit(self.relay)):
                raise Refusal("systemd did not load the exact staged Relay unit.")
            self._require_ssh_invocation(info["ExecStart"], self._json(self.layout.key_dir(self.relay) / "owner.json"))
            managed = self._manifest()
            if managed is None:
                if not self._nft_table_exists():
                    created = self.run(["/usr/sbin/nft", "-f", str(self.nft_path)])
                    if created.returncode:
                        raise Refusal("Could not provision exact scoped nftables ACL: " + created.stderr[:140])
                # An interrupted staged setup may have loaded the table but
                # not yet written the claim. Reuse ONLY the single reviewed
                # rule shape and this exact root-owned journal, never flush a
                # foreign or malformed live table on retry.
                self._require_effective_acl(self.php_uid)
                token = generation["host_generation"]
                claim = {
                    "version": 2, "relay_record_id": self.relay.record_id,
                    "relay_id": self.relay.relay_id,
                    "service_unit": self.relay.unit_name,
                    "firewall_table": self.relay.firewall_table,
                    "local_socks_port": self.relay.local_port,
                    "host_fingerprint": self.relay.fingerprint,
                    "configuration_revision": self.relay.revision,
                    "host_generation": token,
                    "unit_sha256": hashlib.sha256(self.layout.unit(self.relay).read_bytes()).hexdigest(),
                    "unit_exec_sha256": hashlib.sha256(self._canonical_exec(info["ExecStart"]).encode()).hexdigest(),
                    "firewall_sha256": self._nft_policy_digest(),
                }
                self._write_exact(self.layout.evidence(self.relay, ".managed.json"),
                                  (json.dumps(claim, sort_keys=True, separators=(",", ":")) + "\n").encode(), 0o644)
            else:
                if not self._verify_effective_systemd(managed):
                    raise Refusal("Staged Relay unit is not the claimed effective service.")
                if not self._nft_table_exists():
                    restored = self.run(["/usr/sbin/nft", "-f", str(self.nft_path)])
                    if restored.returncode:
                        raise Refusal("Unable to restore missing owned Relay ACL.")
                if not self._verify_effective_nft(managed):
                    raise Refusal("Staged Relay ACL differs from its exact claim; refuse policy reset.")
                self._require_effective_acl(self.php_uid)
            # Deliberately do NOT enable or start the SOCKS transport here.
            # The Gateway's current PHP UID could be shared by sibling sites.
            # Opening even a loopback listener before independently proving
            # FPM/CLI isolation and Relay peer egress could grant those sites access.
            if self._unit_active() or self._unit_enabled():
                raise Refusal("Staged Relay service became active/enabled without verified admission; investigate host drift.")
            return ("GATEWAY RESOURCES STAGED INACTIVE for " + self.relay.relay_id
                    + ". Service intentionally DISABLED. Dedicated PHP-FPM isolation, "
                    "Relay peer egress, operator-controlled activation and separate "
                    "trusted attestation are still required. NO READINESS ISSUED.")
        except BlockingIOError as error:
            raise Refusal("Another Relay operation holds the lifecycle lock.") from error
        finally:
            os.close(fd)

def main() -> int:
    parser = argparse.ArgumentParser(description="MCP Gateway local-only Relay operator actions; never contacts Relay peer.")
    parser.add_argument("action", choices=("preflight", "audit-gateway", "setup-gateway", "public-enrollment",
                                            "activate-gateway", "issue-readiness", "revoke-readiness",
                                            "ensure-acl", "retire", "prepare-setup", "seal-delete", "seal-rotate"))
    parser.add_argument("--relay-id", required=True)
    parser.add_argument("--record-id", required=True)
    parser.add_argument("--fingerprint", required=True)
    parser.add_argument("--revision", required=True, type=int)
    parser.add_argument("--local-port", required=True, type=int)
    parser.add_argument("--php-uid", type=int, default=None,
                        help="Required for root-only Gateway audit or staged setup.")
    parser.add_argument("--control-host", default=None)
    parser.add_argument("--control-port", type=int, default=None)
    parser.add_argument("--control-user", default=None)
    parser.add_argument("--host-key", default=None,
                        help="Public SSH server host-key pin; never a secret/private key.")
    parser.add_argument("--confirm-php-fpm-cli-isolation", action="store_true",
                        help="Root operator has separately verified Gateway-only FPM and CLI identity.")
    parser.add_argument("--confirm-peer-egress", action="store_true",
                        help="Root operator has separately verified intermediary allowed/denied egress.")
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
        if (args.confirm_php_fpm_cli_isolation or args.confirm_peer_egress) and args.action not in {"activate-gateway", "issue-readiness"}:
            raise Refusal("Operator confirmations are accepted only by Gateway activation or readiness issuance.")
        if args.action == "activate-gateway":
            if (args.php_uid is None or args.prior_fingerprint is not None
                or any(value is not None for value in
                       (args.control_host, args.control_port, args.control_user, args.host_key))):
                raise Refusal("Gateway activation requires current Relay identity, --php-uid and two confirmations.")
            print(GatewayReadinessIssuer(relay, layout).activate(
                args.php_uid, args.confirm_php_fpm_cli_isolation, args.confirm_peer_egress,
            ))
        elif args.action == "issue-readiness":
            if (args.php_uid is None or args.prior_fingerprint is not None
                or any(value is not None for value in
                       (args.control_host, args.control_port, args.control_user, args.host_key))):
                raise Refusal("Readiness issuance takes the current Relay identity, --php-uid and two operator confirmations.")
            print(GatewayReadinessIssuer(relay, layout).issue(
                args.php_uid, args.confirm_php_fpm_cli_isolation, args.confirm_peer_egress,
            ))
        elif args.action == "revoke-readiness":
            if (args.php_uid is not None or args.prior_fingerprint is not None
                or any(value is not None for value in
                       (args.control_host, args.control_port, args.control_user, args.host_key))):
                raise Refusal("Readiness revocation takes only the current Relay identity.")
            print(GatewayReadinessIssuer(relay, layout).revoke())
        elif args.action == "audit-gateway":
            if (args.php_uid is None or args.prior_fingerprint is not None
                or any(value is not None for value in
                       (args.control_host, args.control_port, args.control_user, args.host_key))):
                raise Refusal("Gateway audit requires only --php-uid, never prior revisions.")
            print(GatewayPolicyAudit(relay, layout).audit(args.php_uid))
        elif args.action == "ensure-acl":
            if (args.php_uid is None or args.prior_fingerprint is not None
                or any(value is not None for value in
                       (args.control_host, args.control_port, args.control_user, args.host_key))):
                raise Refusal("ACL recovery takes only the exact Relay identity and Gateway PHP UID.")
            print(GatewayAclRecovery(relay, layout).ensure(args.php_uid))
        elif args.action == "setup-gateway":
            if (args.php_uid is None or args.prior_fingerprint is not None
                or any(value is None for value in
                       (args.control_host, args.control_port, args.control_user, args.host_key))):
                raise Refusal("Gateway staged Setup needs the exact control endpoint, pinned public key and dedicated PHP UID.")
            print(GatewaySetup(relay, args.control_host, args.control_port,
                               args.control_user, args.host_key, args.php_uid, layout).setup())
        elif (args.php_uid is not None
              or any(value is not None for value in
                     (args.control_host, args.control_port, args.control_user, args.host_key))):
            raise Refusal("Host setup identity options are accepted only by setup-gateway.")
        elif args.action == "public-enrollment":
            print(GatewayPolicyAudit(relay, layout).public_enrollment())
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
