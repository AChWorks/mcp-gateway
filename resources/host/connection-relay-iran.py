#!/usr/bin/python3
"""Offline Iran-side staging of a Gateway Relay's *public* control identity.

This deliberately stages ONLY root-owned, inert public metadata. It never
creates SSH accounts, touches sshd/authorized_keys, installs firewall rules,
starts a listener, contacts Gateway, issues readiness, or authorizes traffic.
A separate future, reviewed admission protocol must prove Iran egress before
these bytes can be installed into a live authentication/forwarding path.
"""
from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


class Refusal(Exception):
    pass


_HEADER = "PUBLIC ONLY - OFFLINE IRAN ENROLLMENT INPUT"
_KEY_HEADER = "Ed25519 PUBLIC KEY (never copy the private key):"
_TRAILER = ("NOT ENROLLED. Restrict Iran SSHD forwarding and public egress separately; "
            "verify both hosts and issue independent readiness before enabling.")
_ULID = re.compile(r"[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{26}\Z")
_RELAY = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\Z")
_USER = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.+-]{0,127}\Z")
_HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}\Z")
_KEY_B64 = re.compile(r"[A-Za-z0-9+/]+={0,2}\Z")


@dataclass(frozen=True)
class Snapshot:
    relay_id: str
    record_id: str
    control_host: str
    control_port: int
    control_user: str
    public_key: bytes

    def owner_record(self) -> dict:
        return {
            "version": 1,
            "relay_id": self.relay_id,
            "relay_record_id": self.record_id,
            "control_host": self.control_host,
            "control_port": self.control_port,
            "control_user": self.control_user,
            "public_key_sha256": hashlib.sha256(self.public_key).hexdigest(),
            "state": "staged-inactive",
        }


def parse_gateway_export(raw: bytes) -> Snapshot:
    """Parse EXACT current Gateway public-enrollment format, not arbitrary text."""
    if len(raw) > 4096 or b"\x00" in raw:
        raise Refusal("Public enrollment export exceeds bounds or contains binary data.")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise Refusal("Public enrollment export must be plain ASCII.") from error
    if (len(lines) != 8 or lines[0] != _HEADER
        or lines[5] != _KEY_HEADER or lines[7] != _TRAILER):
        raise Refusal("Expected the exact verified Gateway public-enrollment text.")
    fields = [
        ("Relay: ", lines[1]), ("Record: ", lines[2]),
        ("Control endpoint: ", lines[3]), ("Control user on Iran: ", lines[4]),
    ]
    if any(not line.startswith(prefix) for prefix, line in fields):
        raise Refusal("Public enrollment metadata fields are missing or out of order.")
    relay_id, record_id, endpoint, control_user = [
        line[len(prefix):] for prefix, line in fields
    ]
    if not _RELAY.fullmatch(relay_id) or not _ULID.fullmatch(record_id):
        raise Refusal("Invalid Relay ID or immutable record ID.")
    if ":" not in endpoint:
        raise Refusal("Control endpoint needs an explicit port.")
    host, port = endpoint.rsplit(":", 1)
    if (not _HOST.fullmatch(host) or ".." in host or host.endswith(".")
        or not port.isdecimal() or len(port) > 5 or not 1 <= int(port) <= 65535):
        raise Refusal("Invalid Iran control host or SSH port.")
    if not _USER.fullmatch(control_user) or control_user == "root":
        raise Refusal("Iran control principal must be a dedicated non-root identity.")
    public_fields = lines[6].split(" ")
    if (len(public_fields) != 2 or public_fields[0] != "ssh-ed25519"
        or not _KEY_B64.fullmatch(public_fields[1])):
        raise Refusal("Expected a single exact Ed25519 public key without options or comment.")
    try:
        decoded = base64.b64decode(public_fields[1], validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise Refusal("Invalid Ed25519 public key encoding.") from error
    if (len(decoded) != 51
        or decoded[:15] != b"\x00\x00\x00\x0bssh-ed25519"
        or decoded[15:19] != b"\x00\x00\x00\x20"):
        raise Refusal("Invalid Ed25519 wire-format key.")
    return Snapshot(relay_id, record_id, host, int(port), control_user,
                    (lines[6] + "\n").encode("ascii"))


@dataclass(frozen=True)
class Layout:
    root: Path = Path("/")
    owner_uid: int = 0

    @property
    def stages(self) -> Path:
        return self.root / "var/lib/mcp-gateway-iran-relays"

    @property
    def locks(self) -> Path:
        return self.root / "run/mcp-gateway-iran-relays"

    def stage(self, snapshot: Snapshot) -> Path:
        return self.stages / snapshot.record_id

    def lock(self, snapshot: Snapshot) -> Path:
        return self.locks / (snapshot.record_id + ".lock")


def owned(path: Path, layout: Layout, directory: bool, required: bool = True) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        if required:
            raise Refusal("Missing trusted root-owned resource: " + str(path))
        return False
    if (info.st_uid != layout.owner_uid or info.st_mode & 0o022
        or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))):
        raise Refusal("Unknown, foreign or writable Relay host resource: " + str(path))
    return True


def ensure_root_directory(path: Path, layout: Layout) -> None:
    # In production this checks /, /run, /var and /var/lib as well as our
    # dedicated directories. Disposable unit tests stop at their own root.
    parents = []
    current = path
    while current != layout.root:
        if current.exists() or current.is_symlink():
            owned(current, layout, True)
        else:
            parents.append(current)
        current = current.parent
        if not current.is_relative_to(layout.root):
            raise Refusal("Escaped the fixed Iran Relay namespace.")
    owned(layout.root, layout, True)
    for item in reversed(parents):
        item.mkdir(mode=0o700)
        item.chmod(0o700)
        owned(item, layout, True)
        sync_dir(item.parent, layout)


def sync_dir(path: Path, layout: Layout) -> None:
    owned(path, layout, True)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read_export(path: Path) -> Snapshot:
    # The transferred public input is untrusted data and may be user-owned;
    # reject symlinks and oversized/mutating input files, not its ownership.
    # O_NONBLOCK prevents a malicious FIFO input from hanging open() before
    # fstat can reject it; regular-file reads retain their usual semantics.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > 4096 or st.st_size < 40:
            raise Refusal("Invalid or oversized Gateway public-export input file.")
        raw = os.read(fd, 4097)
        if len(raw) != st.st_size:
            raise Refusal("Changed Gateway export during read.")
    finally:
        os.close(fd)
    return parse_gateway_export(raw)


def exact_stage(snapshot: Snapshot, layout: Layout, allow_retiring: bool = False) -> bool:
    base = layout.stage(snapshot)
    if not owned(base, layout, True, required=False):
        return False
    if base.stat().st_mode & 0o777 != 0o700:
        raise Refusal("Staged Iran public identity directory must be 0700.")
    names = {p.name for p in base.iterdir()}
    permitted = {"control_key.pub", "owner.json"} | ({"retiring.json"} if allow_retiring else set())
    if not names.issubset(permitted) or (not allow_retiring and names != permitted):
        raise Refusal("Unexpected or incomplete Iran Relay public staging namespace.")
    if "retiring.json" in names:
        if not allow_retiring:
            raise Refusal("Iran Relay stage is being retired; cannot inspect or adopt it.")
        marker = base / "retiring.json"
        owned(marker, layout, False)
        if marker.read_bytes() != _encode(snapshot.owner_record()):
            raise Refusal("Interrupted retirement belongs to different Iran Relay evidence.")
    else:
        if names != {"control_key.pub", "owner.json"}:
            raise Refusal("Partial staging without a retirement marker cannot be adopted.")
    if "control_key.pub" in names:
        key = base / "control_key.pub"
        owned(key, layout, False)
        if key.read_bytes() != snapshot.public_key:
            raise Refusal("Existing Iran Relay staged key differs from verified public export.")
    if "owner.json" in names:
        claim = base / "owner.json"
        owned(claim, layout, False)
        if claim.read_bytes() != _encode(snapshot.owner_record()):
            raise Refusal("Existing Iran Relay staged claim differs from public export.")
    return True


def _encode(payload: dict) -> bytes:
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def write_new(path: Path, content: bytes, mode: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=False) as out:
            out.write(content)
            out.flush()
            os.fsync(out.fileno())
    finally:
        os.close(fd)


def operate(action: str, snapshot: Snapshot, layout: Layout = Layout()) -> str:
    if os.geteuid() != layout.owner_uid:
        raise Refusal("Iran Relay staging requires explicit root execution.")
    ensure_root_directory(layout.locks, layout)
    ensure_root_directory(layout.stages, layout)
    lock = layout.lock(snapshot)
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        owned(lock, layout, False)
        info = os.fstat(fd)
        link = lock.lstat()
        if (info.st_dev, info.st_ino) != (link.st_dev, link.st_ino):
            raise Refusal("Iran Relay lock was replaced during open.")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        stage = layout.stage(snapshot)
        if action == "inspect":
            if not exact_stage(snapshot, layout):
                raise Refusal("Iran Relay has no exact, trusted staged public identity.")
            return "PUBLIC IDENTITY STAGED INACTIVE for " + snapshot.relay_id + ". NOT ENROLLED OR READY."
        if action == "retire":
            if not owned(stage, layout, True, required=False):
                return "NO IRAN STAGE PRESENT. No SSH account, firewall or service was changed."
            if stage.stat().st_mode & 0o777 != 0o700:
                raise Refusal("Staged Iran public identity directory must be 0700.")
            # A power loss after the final retirement marker unlink, but
            # before rmdir/fsync, may leave this exact private directory
            # EMPTY. Removing an empty trusted stage deletes no unknown data.
            if not any(stage.iterdir()):
                stage.rmdir()
                sync_dir(layout.stages, layout)
                return "EMPTY IRAN PUBLIC STAGE RETIRED. No live SSH policy was touched."
            exact_stage(snapshot, layout, allow_retiring=True)
            marker = stage / "retiring.json"
            if not marker.exists():
                write_new(marker, _encode(snapshot.owner_record()), 0o600)
                sync_dir(stage, layout)
            # A crash after the marker is durable can safely resume deletion
            # of only the two exact public staging files, never unknown files.
            for name in ("control_key.pub", "owner.json"):
                target = stage / name
                if owned(target, layout, False, required=False):
                    if target.read_bytes() != (
                        snapshot.public_key if name == "control_key.pub"
                        else _encode(snapshot.owner_record())
                    ):
                        raise Refusal("Staged public artifact changed before retirement.")
                    target.unlink()
                    sync_dir(stage, layout)
            marker.unlink()
            sync_dir(stage, layout)
            stage.rmdir()
            sync_dir(layout.stages, layout)
            return "IRAN PUBLIC STAGE RETIRED. No live SSH identity or network policy was touched."
        if action != "stage":
            raise Refusal("Unknown offline Iran staging operation.")
        if exact_stage(snapshot, layout, allow_retiring=False):
            return "ALREADY STAGED INACTIVE for " + snapshot.relay_id + ". NOT ENROLLED OR READY."
        prefix = ".pending-" + snapshot.record_id + "-"
        if any(item.name.startswith(prefix) for item in layout.stages.iterdir()):
            raise Refusal("Interrupted staging directory requires explicit root inspection.")
        tmp = Path(tempfile.mkdtemp(prefix=prefix, dir=layout.stages))
        # Failures leave only a scoped, inactive pending directory. Do not
        # recursively delete a possibly changed inode or silently adopt a
        # crash residue; explicit root-side inspection is required.
        tmp.chmod(0o700)
        write_new(tmp / "control_key.pub", snapshot.public_key, 0o644)
        write_new(tmp / "owner.json", _encode(snapshot.owner_record()), 0o644)
        sync_dir(tmp, layout)
        if stage.exists() or stage.is_symlink():
            raise Refusal("Concurrent foreign Iran Relay staging namespace.")
        os.rename(tmp, stage)
        sync_dir(layout.stages, layout)
        return "PUBLIC IDENTITY STAGED INACTIVE for " + snapshot.relay_id + ". NOT ENROLLED OR READY."
    except BlockingIOError as error:
        raise Refusal("Iran Relay lifecycle maintenance is active; retry afterward.") from error
    finally:
        os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline, inactive Iran Relay public-identity staging.")
    parser.add_argument("action", choices=("stage", "inspect", "retire"))
    parser.add_argument("--input", required=True, help="Exact public-only Gateway export text (never a private key).")
    args = parser.parse_args()
    try:
        snapshot = read_export(Path(args.input))
        print(operate(args.action, snapshot))
        return 0
    except (Refusal, OSError, UnicodeError) as error:
        print("FAIL CLOSED: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
