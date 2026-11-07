#!/usr/bin/python3
"""Offline-capable intermediary enrollment for a Gateway Relay public identity.

stage/inspect/retire preserve the original inert, public-only contract.
Explicit root setup/repair/audit/retire-live operate one dedicated principal,
OpenSSH control unit and IPv4/IPv6 egress guard. No action issues Gateway
readiness or changes shared sshd, host keys, legacy Relay or Reverse SSH state.
"""
from __future__ import annotations

import argparse
import base64
import errno
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path


class Refusal(Exception):
    pass


_HEADER = "PUBLIC ONLY - OFFLINE RELAY PEER ENROLLMENT INPUT V2"
_KEY_HEADER = "Ed25519 PUBLIC KEY (never copy the private key):"
_TRAILER = ("NOT ENROLLED. Restrict Relay peer SSHD forwarding and public egress separately; "
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
    revision: int
    host_fingerprint: str
    host_generation: str
    control_host: str
    control_port: int
    control_user: str
    public_key: bytes

    def owner_record(self) -> dict:
        return {
            "version": 2,
            "relay_id": self.relay_id,
            "relay_record_id": self.record_id,
            "configuration_revision": self.revision,
            "host_fingerprint": self.host_fingerprint,
            "host_generation": self.host_generation,
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
    if (len(lines) != 11 or lines[0] != _HEADER
        or lines[8] != _KEY_HEADER or lines[10] != _TRAILER):
        raise Refusal("Expected the exact verified Gateway public-enrollment text.")
    fields = [
        ("Relay: ", lines[1]), ("Record: ", lines[2]),
        ("Configuration revision: ", lines[3]),
        ("Host fingerprint: ", lines[4]),
        ("Host generation: ", lines[5]),
        ("Control endpoint: ", lines[6]), ("Control user on Relay peer: ", lines[7]),
    ]
    if any(not line.startswith(prefix) for prefix, line in fields):
        raise Refusal("Public enrollment metadata fields are missing or out of order.")
    relay_id, record_id, revision, fingerprint, generation, endpoint, control_user = [
        line[len(prefix):] for prefix, line in fields
    ]
    if not _RELAY.fullmatch(relay_id) or not _ULID.fullmatch(record_id):
        raise Refusal("Invalid Relay ID or immutable record ID.")
    if (not revision.isdecimal() or len(revision) > 10
        or not 1 <= int(revision) <= 4294967295
        or str(int(revision)) != revision
        or re.fullmatch(r"[a-f0-9]{64}", fingerprint) is None
        or re.fullmatch(r"[a-f0-9]{64}", generation) is None):
        raise Refusal("Missing or non-canonical Relay revision, fingerprint or generation.")
    if ":" not in endpoint:
        raise Refusal("Control endpoint needs an explicit port.")
    host, port = endpoint.rsplit(":", 1)
    if (not _HOST.fullmatch(host) or ".." in host or host.endswith(".")
        or not port.isdecimal() or len(port) > 5 or not 1 <= int(port) <= 65535):
        raise Refusal("Invalid Relay peer control host or SSH port.")
    if not _USER.fullmatch(control_user) or control_user == "root":
        raise Refusal("Relay peer control principal must be a dedicated non-root identity.")
    public_fields = lines[9].split(" ")
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
    return Snapshot(relay_id, record_id, int(revision), fingerprint, generation,
                    host, int(port), control_user, (lines[9] + "\n").encode("ascii"))


@dataclass(frozen=True)
class Layout:
    root: Path = Path("/")
    owner_uid: int = 0

    @property
    def stages(self) -> Path:
        return self.root / "var/lib/mcp-gateway-relay-peers"

    @property
    def locks(self) -> Path:
        return self.root / "run/mcp-gateway-relay-peers"

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
            raise Refusal("Escaped the fixed Relay peer namespace.")
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
        raise Refusal("Staged Relay peer public identity directory must be 0700.")
    names = {p.name for p in base.iterdir()}
    permitted = {"control_key.pub", "owner.json"} | ({"retiring.json"} if allow_retiring else set())
    if not names.issubset(permitted) or (not allow_retiring and names != permitted):
        raise Refusal("Unexpected or incomplete Relay peer public staging namespace.")
    if "retiring.json" in names:
        if not allow_retiring:
            raise Refusal("Relay peer stage is being retired; cannot inspect or adopt it.")
        marker = base / "retiring.json"
        owned(marker, layout, False)
        if marker.read_bytes() != _encode(snapshot.owner_record()):
            raise Refusal("Interrupted retirement belongs to different Relay peer evidence.")
    else:
        if names != {"control_key.pub", "owner.json"}:
            raise Refusal("Partial staging without a retirement marker cannot be adopted.")
    if "control_key.pub" in names:
        key = base / "control_key.pub"
        owned(key, layout, False)
        if key.read_bytes() != snapshot.public_key:
            raise Refusal("Existing Relay peer staged key differs from verified public export.")
    if "owner.json" in names:
        claim = base / "owner.json"
        owned(claim, layout, False)
        if claim.read_bytes() != _encode(snapshot.owner_record()):
            raise Refusal("Existing Relay peer staged claim differs from public export.")
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


def _link_anonymous_marker(source_fd: int, stage_fd: int) -> None:
    """Linux linkat(AT_EMPTY_PATH): publish a fully-fsynced O_TMPFILE once.

    An ordinary visible temporary name could survive a crash as an unknown
    entry inside the exact staging allowlist. No temporary pathname is used.
    On unsupported filesystems/OSes fail closed *before* public file removal.
    """
    import ctypes

    try:
        libc = ctypes.CDLL(None, use_errno=True)
        linkat = libc.linkat
    except (AttributeError, OSError) as error:
        raise Refusal("Linux anonymous retirement-marker publication is unavailable.") from error
    linkat.argtypes = [
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
        ctypes.c_char_p, ctypes.c_int,
    ]
    linkat.restype = ctypes.c_int
    at_empty_path = 0x1000  # Linux AT_EMPTY_PATH
    if linkat(source_fd, b"", stage_fd, b"retiring.json", at_empty_path) != 0:
        error_code = ctypes.get_errno()
        if error_code == errno.EEXIST:  # never replace or adopt an unknown marker
            raise Refusal("Existing retirement marker changed; refusing overwrite.")
        raise Refusal(
            "Cannot safely publish anonymous retirement marker: "
            + os.strerror(error_code)
        )


def publish_retiring_marker(stage: Path, snapshot: Snapshot, layout: Layout) -> None:
    """Durable *complete or absent* retirement marker, before any deletion.

    O_TMPFILE creates an unlinked inode. A crash during its write/fsync leaves
    no visible truncated marker. linkat(AT_EMPTY_PATH) atomically exposes its
    complete bytes only after file fsync, with no replace-on-existing behavior.
    A crash after link, before directory fsync, leaves either a valid marker
    or no marker; no public artifact is removed until directory fsync passes.
    """
    if not hasattr(os, "O_TMPFILE"):
        raise Refusal("Linux O_TMPFILE support is required for safe retirement.")
    try:
        fd = os.open(stage, os.O_TMPFILE | os.O_WRONLY | os.O_CLOEXEC, 0o600)
    except OSError as error:
        raise Refusal("Filesystem cannot safely stage an anonymous retirement marker.") from error
    try:
        os.fchmod(fd, 0o600)
        remaining = memoryview(_encode(snapshot.owner_record()))
        while remaining:
            written = os.write(fd, remaining)
            if written <= 0:
                raise OSError("Unable to complete retirement marker write.")
            remaining = remaining[written:]
        os.fsync(fd)
        stage_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            owned(stage, layout, True)
            actual = os.fstat(stage_fd)
            expected = stage.lstat()
            if ((actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino)
                or actual.st_mode & 0o777 != 0o700):
                raise Refusal("Relay peer public staging directory changed before marker publication.")
            _link_anonymous_marker(fd, stage_fd)
            os.fsync(stage_fd)
        finally:
            os.close(stage_fd)
    finally:
        os.close(fd)


def sync_existing_retiring_marker(stage: Path, snapshot: Snapshot, layout: Layout) -> None:
    """Re-establish the retry durability barrier before unlinking public artifacts.

    An earlier linkat may have succeeded even when the directory fsync failed.
    A visible, content-matching marker is therefore not proof of a durable
    directory entry. Re-fsync its exact trusted inode and parent on every retry.
    """
    marker = stage / "retiring.json"
    expected_bytes = _encode(snapshot.owner_record())
    marker_fd = os.open(
        marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
    )
    try:
        owned(marker, layout, False)
        actual = os.fstat(marker_fd)
        named = marker.lstat()
        if (not stat.S_ISREG(actual.st_mode)
            or actual.st_uid != layout.owner_uid
            or actual.st_mode & 0o777 != 0o600
            or (actual.st_dev, actual.st_ino) != (named.st_dev, named.st_ino)
            or actual.st_size != len(expected_bytes)
            or os.read(marker_fd, len(expected_bytes) + 1) != expected_bytes):
            raise Refusal("Existing retirement marker identity or contents changed.")
        os.fsync(marker_fd)
        stage_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            owned(stage, layout, True)
            current_stage = os.fstat(stage_fd)
            named_stage = stage.lstat()
            current_marker = marker.lstat()
            if ((current_stage.st_dev, current_stage.st_ino)
                != (named_stage.st_dev, named_stage.st_ino)
                or current_stage.st_uid != layout.owner_uid
                or current_stage.st_mode & 0o777 != 0o700
                or (actual.st_dev, actual.st_ino)
                != (current_marker.st_dev, current_marker.st_ino)):
                raise Refusal("Retirement marker namespace changed before durability sync.")
            os.fsync(stage_fd)
        finally:
            os.close(stage_fd)
    finally:
        os.close(marker_fd)


def operate(action: str, snapshot: Snapshot, layout: Layout = Layout()) -> str:
    if os.geteuid() != layout.owner_uid:
        raise Refusal("Relay peer staging requires explicit root execution.")
    ensure_root_directory(layout.locks, layout)
    ensure_root_directory(layout.stages, layout)
    lock = layout.lock(snapshot)
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        owned(lock, layout, False)
        info = os.fstat(fd)
        link = lock.lstat()
        if (info.st_dev, info.st_ino) != (link.st_dev, link.st_ino):
            raise Refusal("Relay peer lock was replaced during open.")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        stage = layout.stage(snapshot)
        if action == "inspect":
            if not exact_stage(snapshot, layout):
                raise Refusal("Relay peer has no exact, trusted staged public identity.")
            return "PUBLIC IDENTITY STAGED INACTIVE for " + snapshot.relay_id + ". NOT ENROLLED OR READY."
        if action == "retire":
            live = PeerEnrollment(snapshot, layout)
            if live.record.exists() or live.record.is_symlink():
                stored = read_export(live.record / "input.txt")
                enrolled = PeerEnrollment(stored, layout)
                enrolled._load(allow_retiring=True)
                if not (enrolled.record / "retiring.json").exists():
                    raise Refusal("Retire the live enrollment before deleting its inert public stage.")
                enrolled._retired_absent()
            if not owned(stage, layout, True, required=False):
                return "NO RELAY PEER STAGE PRESENT. No SSH account, firewall or service was changed."
            if stage.stat().st_mode & 0o777 != 0o700:
                raise Refusal("Staged Relay peer public identity directory must be 0700.")
            # A power loss after the final retirement marker unlink, but
            # before rmdir/fsync, may leave this exact private directory
            # EMPTY. Removing an empty trusted stage deletes no unknown data.
            if not any(stage.iterdir()):
                stage.rmdir()
                sync_dir(layout.stages, layout)
                return "EMPTY RELAY PEER PUBLIC STAGE RETIRED. No live SSH policy was touched."
            exact_stage(snapshot, layout, allow_retiring=True)
            marker = stage / "retiring.json"
            if marker.exists():
                sync_existing_retiring_marker(stage, snapshot, layout)
            else:
                publish_retiring_marker(stage, snapshot, layout)
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
            return "RELAY PEER PUBLIC STAGE RETIRED. No live SSH identity or network policy was touched."
        if action != "stage":
            raise Refusal("Unknown offline Relay peer staging operation.")
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
            raise Refusal("Concurrent foreign Relay peer staging namespace.")
        os.rename(tmp, stage)
        sync_dir(layout.stages, layout)
        return "PUBLIC IDENTITY STAGED INACTIVE for " + snapshot.relay_id + ". NOT ENROLLED OR READY."
    except BlockingIOError as error:
        raise Refusal("Relay peer lifecycle maintenance is active; retry afterward.") from error
    finally:
        os.close(fd)



# Live enrollment is a separate, explicit root action. The original public
# stage remains inert and is never adopted as evidence of a running policy.
_LIVE_USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
_SAFE_PATH = re.compile(r"/[A-Za-z0-9_./-]+\Z")
_IPV4_DENY = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
)
# Permit only currently allocated global-unicast space, then exclude its
# special-purpose ranges. IPv4-mapped connections use the IPv4 output guard.
_IPV6_DENY = ("2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20")


def canonical_export(snapshot: Snapshot) -> bytes:
    return (
        _HEADER + "\nRelay: " + snapshot.relay_id + "\nRecord: " + snapshot.record_id
        + "\nConfiguration revision: " + str(snapshot.revision)
        + "\nHost fingerprint: " + snapshot.host_fingerprint
        + "\nHost generation: " + snapshot.host_generation
        + "\nControl endpoint: " + snapshot.control_host + ":" + str(snapshot.control_port)
        + "\nControl user on Relay peer: " + snapshot.control_user + "\n"
        + _KEY_HEADER + "\n" + snapshot.public_key.decode("ascii") + _TRAILER + "\n"
    ).encode("ascii")


def command(argv: list[str], data: str | None = None, check: bool = True):
    import subprocess
    try:
        result = subprocess.run(
            argv, input=data if data is not None else "", text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Refusal("Cannot complete host command: " + argv[0]) from error
    if check and result.returncode:
        # Never return command stdout: getent shadow is an internal check.
        raise Refusal("Host command failed: " + argv[0] + " " + result.stderr[:400].strip())
    return result


def trusted_file(path: Path, layout: Layout, mode: int | None = None) -> bytes:
    current = path.parent
    if not path.is_absolute() or not path.is_relative_to(layout.root):
        raise Refusal("Host resource must be an absolute path within the host root.")
    while current != layout.root:
        owned(current, layout, True)
        current = current.parent
    owned(layout.root, layout, True)
    owned(path, layout, False)
    if mode is not None and stat.S_IMODE(path.lstat().st_mode) != mode:
        raise Refusal("Unexpected mode on trusted host file: " + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        named = path.lstat()
        if ((info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)
            or info.st_size > 131072):
            raise Refusal("Changed or oversized trusted host file.")
        data = os.read(fd, 131073)
        if len(data) != info.st_size:
            raise Refusal("Trusted host file changed while reading.")
        return data
    finally:
        os.close(fd)


def public_directory(path: Path, layout: Layout) -> None:
    """Create only new traversable ancestors; never widen existing directories."""
    parents = []
    current = path
    while current != layout.root:
        if current.exists() or current.is_symlink():
            owned(current, layout, True)
            if current.lstat().st_mode & 0o005 != 0o005:
                raise Refusal("Public SSH key directory is not traversable/readable: " + str(current))
        else:
            parents.append(current)
        current = current.parent
        if not current.is_relative_to(layout.root):
            raise Refusal("Escaped the public Relay namespace.")
    owned(layout.root, layout, True)
    for item in reversed(parents):
        item.mkdir(mode=0o755)
        item.chmod(0o755)
        sync_dir(item.parent, layout)


@contextmanager
def live_lock(snapshot: Snapshot | None, layout: Layout):
    if os.geteuid() != layout.owner_uid:
        raise Refusal("Live Relay peer operations require explicit root execution.")
    ensure_root_directory(layout.locks, layout)
    lock = layout.lock(snapshot) if snapshot is not None else layout.locks / "allocation.lock"
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        owned(lock, layout, False)
        info, named = os.fstat(fd), lock.lstat()
        if (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino):
            raise Refusal("Relay peer lifecycle lock changed.")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    except BlockingIOError as error:
        raise Refusal("Relay peer lifecycle maintenance is active; retry afterward.") from error
    finally:
        os.close(fd)


class PeerEnrollment:
    """One durable claim, one account, one sshd unit and one UID egress guard."""

    def __init__(self, snapshot: Snapshot, layout: Layout = Layout()):
        self.snapshot, self.layout = snapshot, layout
        self.record = layout.root / "var/lib/mcp-gateway-relay-peer-services" / snapshot.record_id
        self.public = layout.root / "etc/mcp-gateway/connection-relay-peers" / snapshot.record_id
        self.unit_name = "mcp-gateway-relay-peer-" + snapshot.record_id.lower() + ".service"
        self.unit = layout.root / "etc/systemd/system" / self.unit_name
        self.helper = layout.root / "usr/local/libexec/mcp-gateway-relay-peer/connection-relay-peer.py"
        self.table = "mcp_gateway_peer_" + hashlib.sha256(snapshot.record_id.encode()).hexdigest()[:12]
        self.owner = None

    def _marker(self) -> str:
        return "mcp-gateway-relay-peer-" + self.snapshot.record_id + "-" + self.snapshot.host_generation

    def _validate_spec(self, bind: str, host_key: str, fingerprint: str, ports: list[int]) -> dict:
        import ipaddress
        if not _LIVE_USER.fullmatch(self.snapshot.control_user) or self.snapshot.control_user == "root":
            raise Refusal("Live enrollment needs a dedicated lowercase Linux account name of at most 32 characters.")
        try:
            address = ipaddress.ip_address(bind)
        except ValueError as error:
            raise Refusal("Bind address must be one explicit canonical IPv4 or IPv6 address.") from error
        if (str(address) != bind or address.is_unspecified or address.is_multicast
            or "%" in bind or address.version == 6 and address.ipv4_mapped):
            raise Refusal("Wildcard, scoped, mapped or non-canonical bind address is not allowed.")
        if (not _SAFE_PATH.fullmatch(host_key) or str(Path(host_key)) != host_key
            or ".." in Path(host_key).parts):
            raise Refusal("Host key must have an absolute, canonical, shell-independent path.")
        if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", fingerprint):
            raise Refusal("An independently trusted Ed25519 SHA256 host-key fingerprint is required.")
        if (not 1 <= len(ports) <= 32 or any(type(port) is not int or not 1 <= port <= 65535 for port in ports)
            or len(set(ports)) != len(ports)):
            raise Refusal("Provide 1..32 distinct explicit allowed TCP destination ports.")
        return {"bind_address": bind, "host_key": host_key,
                "host_key_fingerprint": fingerprint, "allowed_ports": sorted(ports)}

    def _host_identity(self, owner: dict) -> None:
        key = Path(owner["host_key"])
        raw = trusted_file(key, self.layout)
        if key.lstat().st_mode & 0o077 or not raw:
            raise Refusal("Existing host private key must be root-only and nonempty.")
        result = command(["/usr/bin/ssh-keygen", "-y", "-f", str(key)])
        fields = result.stdout.strip().split()
        if len(fields) < 2 or fields[0] != "ssh-ed25519":
            raise Refusal("Selected existing host key is not Ed25519.")
        try:
            wire = base64.b64decode(fields[1], validate=True)
        except ValueError as error:
            raise Refusal("Invalid derived host public key.") from error
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(wire).digest()).decode().rstrip("=")
        if fingerprint != owner["host_key_fingerprint"]:
            raise Refusal("Existing intermediary host key differs from the independently trusted pin.")

    def _helper_digest(self) -> str:
        raw = trusted_file(self.helper, self.layout, 0o500)
        # The operator may invoke a verified open FD. Its bytes must still
        # match the fixed root-owned helper used by the systemd pre-start.
        if hashlib.sha256(Path(__file__).read_bytes()).digest() != hashlib.sha256(raw).digest():
            raise Refusal("Executing peer helper differs from its fixed root-owned installation.")
        return hashlib.sha256(raw).hexdigest()

    def _load(self, allow_retiring: bool = False) -> dict:
        if not owned(self.record, self.layout, True, required=False):
            raise Refusal("No exact live enrollment claim; run separately authorized setup first.")
        if stat.S_IMODE(self.record.lstat().st_mode) != 0o700:
            raise Refusal("Live enrollment journal must be 0700.")
        names = {item.name for item in self.record.iterdir()}
        if not {"owner.json", "input.txt"}.issubset(names) or not names <= {"owner.json", "input.txt", "retiring.json"}:
            raise Refusal("Unknown or incomplete live enrollment journal.")
        try:
            owner = json.loads(trusted_file(self.record / "owner.json", self.layout, 0o600))
        except (ValueError, TypeError) as error:
            raise Refusal("Malformed live enrollment journal.") from error
        expected = {"version", "binding", "bind_address", "host_key", "host_key_fingerprint",
                    "allowed_ports", "uid", "gid", "helper_sha256"}
        if (not isinstance(owner, dict) or set(owner) != expected or owner["version"] != 1
            or owner["binding"] != self.snapshot.owner_record()
            or type(owner["uid"]) is not int or type(owner["gid"]) is not int
            or not 20000 <= owner["uid"] <= 29999 or owner["gid"] != owner["uid"]
            or not isinstance(owner["helper_sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", owner["helper_sha256"])):
            raise Refusal("Live claim does not bind this exact Relay record, generation and UID.")
        if (not isinstance(owner["allowed_ports"], list)
            or any(not isinstance(owner[key], str) for key in ("bind_address", "host_key", "host_key_fingerprint"))):
            raise Refusal("Invalid live enrollment policy types.")
        spec = self._validate_spec(owner["bind_address"], owner["host_key"],
                                   owner["host_key_fingerprint"], owner["allowed_ports"])
        if any(owner[key] != value for key, value in spec.items()):
            raise Refusal("Non-canonical live enrollment policy.")
        if trusted_file(self.record / "input.txt", self.layout, 0o600) != canonical_export(self.snapshot):
            raise Refusal("Live enrollment public input has changed.")
        if "retiring.json" in names:
            if trusted_file(self.record / "retiring.json", self.layout, 0o600) != _encode(self.snapshot.owner_record()):
                raise Refusal("Foreign live retirement marker.")
            if not allow_retiring:
                raise Refusal("This Relay generation is retiring or retired; it cannot restart.")
        self.owner = owner
        return owner


    def _history(self) -> list[Snapshot]:
        """Exact old claims fence replay even if a crash preceded the new claim."""
        history = []
        if not self.record.parent.exists():
            return history
        owned(self.record.parent, self.layout, True)
        prefix = self.snapshot.record_id + ".retired-"
        for path in self.record.parent.iterdir():
            if not path.name.startswith(prefix):
                continue
            if not re.fullmatch(re.escape(prefix) + r"[0-9a-f]{64}", path.name):
                raise Refusal("Unexpected retired generation namespace requires inspection.")
            stored = read_export(path / "input.txt")
            if stored.record_id != self.snapshot.record_id or path.name != prefix + stored.host_generation:
                raise Refusal("Retired generation archive is not bound to this Relay record.")
            previous = PeerEnrollment(stored, self.layout)
            previous.record = path
            previous._load(allow_retiring=True)
            if not (path / "retiring.json").exists():
                raise Refusal("Unfenced prior generation cannot authorize new enrollment.")
            history.append(stored)
        return history

    def _newer_than(self, previous: list[Snapshot]) -> None:
        if any(self.snapshot.revision <= old.revision
               or self.snapshot.host_generation == old.host_generation for old in previous):
            raise Refusal("Re-enrollment needs a higher V2 revision and a new host generation; replay refused.")

    def _retired_absent(self) -> None:
        import grp
        import pwd
        if (self.public.exists() or self.public.is_symlink()
            or self.unit.exists() or self.unit.is_symlink()
            or any(entry.pw_name == self.snapshot.control_user for entry in pwd.getpwall())
            or any(entry.gr_name == self.snapshot.control_user for entry in grp.getgrall())
            or self._nft_present() or self._uid_processes()):
            raise Refusal("Prior live enrollment teardown is incomplete; resume retire-live first.")
        info = self._systemd()
        if info["LoadState"] != "not-found" or info["MainPID"] != "0" or info["ActiveState"] != "inactive":
            raise Refusal("Prior live service has not been completely retired.")

    def _advance_retired(self) -> None:
        stored = read_export(self.record / "input.txt")
        previous = PeerEnrollment(stored, self.layout)
        previous._load(allow_retiring=True)
        if not (previous.record / "retiring.json").exists():
            raise Refusal("A different live generation must be retired before re-enrollment.")
        self._newer_than([stored, *self._history()])
        previous._retired_absent()
        archived = self.record.with_name(self.snapshot.record_id + ".retired-" + stored.host_generation)
        if archived.exists() or archived.is_symlink():
            raise Refusal("Retired generation archive already exists; preserving both claims.")
        os.rename(self.record, archived)
        sync_dir(self.record.parent, self.layout)

    def _reserved_uids(self) -> set[int]:
        reserved = set()
        if not self.record.parent.exists():
            return reserved
        owned(self.record.parent, self.layout, True)
        pattern = r"[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{26}(?:\.retired-[0-9a-f]{64})?"
        for path in self.record.parent.iterdir():
            if path.name.startswith(".pending-"):
                # A pending directory has not published a claim and cannot
                # authorize account creation or be resumed by this helper.
                continue
            if not re.fullmatch(pattern, path.name):
                raise Refusal("Unknown live claim namespace blocks UID allocation.")
            stored = read_export(path / "input.txt")
            if path.name.split(".", 1)[0] != stored.record_id:
                raise Refusal("Foreign UID reservation does not match its record namespace.")
            previous = PeerEnrollment(stored, self.layout)
            previous.record = path
            reserved.add(previous._load(allow_retiring=True)["uid"])
            if stored.control_user == self.snapshot.control_user:
                if not (path / "retiring.json").exists():
                    raise Refusal("Dedicated peer principal is reserved by an unfinished or active claim.")
                previous._retired_absent()
        return reserved

    def _new_claim(self, spec: dict) -> None:
        # Account creation happens later, so passwd alone is not a UID
        # reservation. Serialize selection plus durable claim publication
        # across all Relay records and include unfinished/retired claims.
        with live_lock(None, self.layout):
            self._claim_with_uid_reserved(spec)

    def _claim_with_uid_reserved(self, spec: dict) -> None:
        self._newer_than(self._history())
        import grp
        import pwd
        user = self.snapshot.control_user
        for lookup in (pwd.getpwnam, grp.getgrnam):
            try:
                lookup(user)
            except KeyError:
                continue
            raise Refusal("Existing intermediary account/group is not owned by this enrollment.")
        if self.public.exists() or self.public.is_symlink() or self.unit.exists() or self.unit.is_symlink():
            raise Refusal("Existing live peer files have no ownership claim.")
        if self._nft_present():
            raise Refusal("Existing peer nftables table has no ownership claim.")
        info = self._systemd()
        if info["LoadState"] != "not-found" or info["ActiveState"] != "inactive" or info["MainPID"] != "0":
            raise Refusal("Existing service state has no exact enrollment claim.")
        occupied = ({entry.pw_uid for entry in pwd.getpwall()} | {entry.gr_gid for entry in grp.getgrall()}
                    | self._reserved_uids())
        uid = next((number for number in range(20000, 30000) if number not in occupied), None)
        if uid is None:
            raise Refusal("No unused dedicated UID/GID in the peer allocation range.")
        owner = {"version": 1, "binding": self.snapshot.owner_record(), **spec,
                 "uid": uid, "gid": uid, "helper_sha256": self._helper_digest()}
        self._host_identity(owner)
        ensure_root_directory(self.record.parent, self.layout)
        prefix = ".pending-" + self.snapshot.record_id + "-"
        if any(item.name.startswith(prefix) for item in self.record.parent.iterdir()):
            raise Refusal("Interrupted live claim publication needs explicit root inspection.")
        temporary = Path(tempfile.mkdtemp(prefix=prefix, dir=self.record.parent))
        temporary.chmod(0o700)
        write_new(temporary / "owner.json", _encode(owner), 0o600)
        write_new(temporary / "input.txt", canonical_export(self.snapshot), 0o600)
        sync_dir(temporary, self.layout)
        if self.record.exists() or self.record.is_symlink():
            raise Refusal("Concurrent live enrollment claim.")
        os.rename(temporary, self.record)
        sync_dir(self.record.parent, self.layout)
        self.owner = owner

    def _group(self, required: bool) -> bool:
        import grp
        import pwd
        owner = self.owner
        try:
            group = grp.getgrnam(self.snapshot.control_user)
        except KeyError:
            if required:
                raise Refusal("Dedicated peer group is missing.")
            if any(entry.gr_gid == owner["gid"] for entry in grp.getgrall()):
                raise Refusal("Planned peer GID was reused by another group.")
            return False
        if (group.gr_gid != owner["gid"] or group.gr_mem
            or grp.getgrgid(group.gr_gid).gr_name != group.gr_name
            or any(entry.gr_gid == owner["gid"] and entry.gr_name != group.gr_name for entry in grp.getgrall())
            or any(entry.pw_gid == owner["gid"] and entry.pw_name != self.snapshot.control_user for entry in pwd.getpwall())):
            raise Refusal("Dedicated peer group is shared, changed or has supplementary members.")
        return True

    def _account(self, required: bool) -> bool:
        import grp
        import pwd
        owner = self.owner
        try:
            account = pwd.getpwnam(self.snapshot.control_user)
        except KeyError:
            if required:
                raise Refusal("Dedicated peer account is missing.")
            if any(entry.pw_uid == owner["uid"] for entry in pwd.getpwall()):
                raise Refusal("Planned peer UID was reused by another account.")
            return False
        if (account.pw_uid != owner["uid"] or account.pw_gid != owner["gid"]
            or account.pw_gecos != self._marker() or account.pw_dir != "/nonexistent"
            or account.pw_shell != "/usr/sbin/nologin"
            or pwd.getpwuid(account.pw_uid).pw_name != account.pw_name
            or set(os.getgrouplist(account.pw_name, account.pw_gid)) != {account.pw_gid}
            or any(entry.pw_uid == owner["uid"] and entry.pw_name != account.pw_name for entry in pwd.getpwall())
            or any(account.pw_name in entry.gr_mem for entry in grp.getgrall())):
            raise Refusal("Dedicated peer principal has changed, shares a UID or has supplementary groups.")
        shadow = command(["/usr/bin/getent", "shadow", account.pw_name]).stdout.strip().split(":")
        if len(shadow) != 9 or shadow[0] != account.pw_name or shadow[1] != "*" or shadow[7] not in ("", "-1"):
            raise Refusal("Peer password/account status is not the exact non-password dedicated identity.")
        return True

    def _make_account(self) -> None:
        if not self._group(False):
            command(["/usr/sbin/groupadd", "--gid", str(self.owner["gid"]), self.snapshot.control_user])
        if not self._account(False):
            command(["/usr/sbin/useradd", "--system", "--no-create-home", "--no-log-init",
                     "--uid", str(self.owner["uid"]), "--gid", str(self.owner["gid"]),
                     "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin",
                     "--password", "*", "--comment", self._marker(), self.snapshot.control_user])
        self._group(True)
        self._account(True)

    def _config(self) -> bytes:
        owner, snapshot = self.owner, self.snapshot
        lines = [
            "Port " + str(snapshot.control_port), "AddressFamily any",
            "ListenAddress " + owner["bind_address"], "HostKey " + owner["host_key"],
            "PidFile /run/" + self.unit_name + ".pid",
            "AuthorizedKeysFile " + str(self.public / "authorized_keys"),
            "AuthorizedKeysCommand none", "AuthorizedPrincipalsFile none",
            "TrustedUserCAKeys none", "HostKeyAlgorithms ssh-ed25519",
            "PubkeyAcceptedAlgorithms ssh-ed25519", "AllowUsers " + snapshot.control_user,
            "AuthenticationMethods publickey", "PubkeyAuthentication yes",
            "PasswordAuthentication no", "KbdInteractiveAuthentication no",
            "HostbasedAuthentication no", "GSSAPIAuthentication no", "UsePAM no",
            "PermitRootLogin no", "PermitEmptyPasswords no", "StrictModes yes",
            "AllowTcpForwarding local", "PermitListen none",
            "PermitOpen " + " ".join("*:" + str(port) for port in owner["allowed_ports"]),
            "AllowStreamLocalForwarding no", "AllowAgentForwarding no", "X11Forwarding no",
            "PermitTunnel no", "PermitTTY no", "PermitUserRC no", "PermitUserEnvironment no",
            "MaxSessions 0", "MaxAuthTries 3", "LoginGraceTime 30",
            "UseDNS no", "LogLevel VERBOSE", "PrintMotd no",
        ]
        return ("\n".join(lines) + "\n").encode("ascii")

    def _unit_source(self) -> bytes:
        return (
            "[Unit]\nDescription=Restricted MCP Gateway Relay peer " + self.snapshot.record_id + "\n"
            "After=network.target nftables.service\n"
            "[Service]\nType=simple\nUser=root\nGroup=root\n"
            "ExecStartPre=/usr/bin/python3 -I " + str(self.helper) + " ensure-egress --input "
            + str(self.record / "input.txt") + "\n"
            "ExecStart=/usr/sbin/sshd -D -e -f " + str(self.public / "sshd_config") + "\n"
            "KillMode=control-group\nRestart=on-failure\nRestartSec=3\n"
            "TimeoutStartSec=45\nTimeoutStopSec=15\n"
            "[Install]\nWantedBy=multi-user.target\n"
        ).encode("ascii")

    def _files(self, allow_missing: bool = False) -> dict[Path, bytes]:
        expected = {
            self.public / "authorized_keys": b"restrict,port-forwarding " + self.snapshot.public_key,
            self.public / "sshd_config": self._config(),
            self.unit: self._unit_source(),
        }
        if self.public.exists() or self.public.is_symlink():
            owned(self.public, self.layout, True)
            if {item.name for item in self.public.iterdir()} - {"authorized_keys", "sshd_config"}:
                raise Refusal("Unknown file in the live peer public namespace.")
            current = self.public
            while current != self.layout.root:
                owned(current, self.layout, True)
                if current.lstat().st_mode & 0o005 != 0o005:
                    raise Refusal("Live peer public namespace is not traversable.")
                current = current.parent
        elif not allow_missing:
            raise Refusal("Live peer public namespace is missing.")
        for path, value in expected.items():
            if not owned(path, self.layout, False, required=False):
                if not allow_missing:
                    raise Refusal("Missing owned live peer source: " + str(path))
                continue
            if trusted_file(path, self.layout, 0o644) != value:
                raise Refusal("Live peer source differs from the exact owned policy: " + str(path))
        return expected

    def _make_files(self) -> None:
        expected = self._files(True)
        public_directory(self.public, self.layout)
        ensure_root_directory(self.unit.parent, self.layout)
        for path, value in expected.items():
            if not path.exists():
                write_new(path, value, 0o644)
                sync_dir(path.parent, self.layout)
        self._files()

    def _sshd_policy(self) -> None:
        config = str(self.public / "sshd_config")
        command(["/usr/sbin/sshd", "-t", "-f", config])
        result = command(["/usr/sbin/sshd", "-T", "-f", config, "-C",
                          "user=" + self.snapshot.control_user + ",host=peer,addr=127.0.0.1"])
        effective = {}
        for line in result.stdout.splitlines():
            key, separator, value = line.partition(" ")
            if separator:
                effective.setdefault(key, []).append(value)
        required = {
            "port": str(self.snapshot.control_port),
            "addressfamily": "any",
            "hostkey": self.owner["host_key"],
            "authorizedkeysfile": str(self.public / "authorized_keys"),
            "authorizedkeyscommand": "none", "authorizedprincipalsfile": "none",
            "trustedusercakeys": "none", "allowusers": self.snapshot.control_user,
            "authenticationmethods": "publickey", "pubkeyauthentication": "yes",
            "passwordauthentication": "no", "kbdinteractiveauthentication": "no",
            "hostbasedauthentication": "no", "gssapiauthentication": "no", "usepam": "no",
            "permitrootlogin": "no", "permitemptypasswords": "no", "strictmodes": "yes",
            "allowtcpforwarding": "local", "permitlisten": "none",
            "permitopen": " ".join("*:" + str(port) for port in self.owner["allowed_ports"]),
            "allowstreamlocalforwarding": "no", "allowagentforwarding": "no",
            "x11forwarding": "no", "permittunnel": "no", "permittty": "no",
            "permituserrc": "no", "permituserenvironment": "no", "maxsessions": "0",
            "hostkeyalgorithms": "ssh-ed25519", "pubkeyacceptedalgorithms": "ssh-ed25519",
        }
        address = self.owner["bind_address"]
        listen = ("[" + address + "]" if ":" in address else address) + ":" + str(self.snapshot.control_port)
        required["listenaddress"] = listen
        for key, value in required.items():
            if effective.get(key) != [value]:
                raise Refusal("Effective sshd restriction differs: " + key)

    def _nft_objects(self) -> list[dict]:
        table = {"family": "inet", "name": self.table}
        chain = {"family": "inet", "table": self.table, "name": "output",
                 "type": "filter", "hook": "output", "prio": 0, "policy": "accept"}
        guard = {"family": "inet", "table": self.table, "name": "peer_egress"}
        objects = [{"table": table}, {"chain": chain}, {"chain": guard}]


        def match(left, op, right):
            return {"match": {"op": op, "left": left, "right": right}}

        def rule(expressions):
            objects.append({"rule": {"family": "inet", "table": self.table,
                                    "chain": "peer_egress", "expr": expressions}})

        def reject():
            return {"reject": {"type": "icmpx", "expr": "admin-prohibited"}}

        # A negative skuid guard is unsafe for socketless kernel packets:
        # nft skips that rule when socket identity is unavailable. Only a
        # positive match may enter the dedicated restrictive chain.
        objects.append({"rule": {"family": "inet", "table": self.table, "chain": "output",
                                "expr": [match({"meta": {"key": "skuid"}}, "==", self.owner["uid"]),
                                         {"jump": {"target": "peer_egress"}}]}})
        # Only replies on an existing inbound control connection bypass the
        # destination filter. Original-direction Target traffic never does.
        rule([match({"ct": {"key": "direction"}}, "==", "reply"),
              match({"ct": {"key": "state"}}, "==", "established"),
              match({"payload": {"protocol": "tcp", "field": "sport"}}, "==", self.snapshot.control_port),
              {"accept": None}])
        rule([match({"fib": {"result": "type", "flags": ["daddr"]}}, "==", "local"), reject()])
        for cidr in _IPV4_DENY:
            address, length = cidr.split("/")
            rule([match({"payload": {"protocol": "ip", "field": "daddr"}}, "==",
                        {"prefix": {"addr": address, "len": int(length)}}), reject()])
        rule([match({"payload": {"protocol": "ip6", "field": "daddr"}}, "!=",
                    {"prefix": {"addr": "2000::", "len": 3}}), reject()])
        for cidr in _IPV6_DENY:
            address, length = cidr.split("/")
            rule([match({"payload": {"protocol": "ip6", "field": "daddr"}}, "==",
                        {"prefix": {"addr": address, "len": int(length)}}), reject()])
        ports = self.owner["allowed_ports"]
        rule([match({"payload": {"protocol": "tcp", "field": "dport"}}, "==",
                    ports[0] if len(ports) == 1 else {"set": ports}), {"accept": None}])
        rule([reject()])
        return objects

    def _nft_present(self) -> bool:
        result = command(["/usr/sbin/nft", "-j", "list", "tables"])
        try:
            document = json.loads(result.stdout)
            tables = document["nftables"]
            return any(item.get("table", {}).get("family") == "inet"
                       and item.get("table", {}).get("name") == self.table for item in tables)
        except (KeyError, TypeError, ValueError) as error:
            raise Refusal("Cannot parse nftables table inventory.") from error

    def _nft_exact(self, required: bool = True) -> bool:
        if not self._nft_present():
            if required:
                raise Refusal("Exact peer IPv4/IPv6 egress guard is missing.")
            return False
        result = command(["/usr/sbin/nft", "-j", "-n", "list", "table", "inet", self.table])
        try:
            objects = json.loads(result.stdout)["nftables"]
            objects = [{kind: {key: value for key, value in payload.items() if key != "handle"}}
                       for item in objects for kind, payload in item.items() if kind != "metainfo"]
        except (KeyError, TypeError, ValueError, AttributeError) as error:
            raise Refusal("Malformed effective peer nftables policy.") from error
        def canonical(items):
            import copy
            items = copy.deepcopy(items)
            # nft -n emits numeric kernel enums on some versions. Decode
            # only these exact typed expressions, not arbitrary numbers or
            # masks: e.g. established|related (6) must never equal 2.
            enum_matches = (
                ({"ct": {"key": "direction"}}, 1, "reply"),
                ({"ct": {"key": "state"}}, 2, "established"),
                ({"fib": {"result": "type", "flags": ["daddr"]}}, 2, "local"),
            )
            for item in items:
                for expression in item.get("rule", {}).get("expr", []):
                    match = expression.get("match", {})
                    for left, numeric, symbolic in enum_matches:
                        if (match.get("left") == left and match.get("op") == "=="
                            and type(match.get("right")) is int and match["right"] == numeric):
                            match["right"] = symbolic
                    if expression.get("reject") == {"type": "icmpx", "expr": 3}:
                        expression["reject"]["expr"] = "admin-prohibited"
            # nft lists rules beside their chain, while atomic creation
            # defines both chains before referencing the regular one.
            # Stable sorting groups chains without changing rule order
            # within any chain; extra/missing/changed objects still differ.
            def order(item):
                kind, value = next(iter(item.items()))
                return ({"table": 0, "chain": 1, "rule": 2}.get(kind, 3),
                        value.get("family", ""), value.get("table", ""),
                        value.get("chain", value.get("name", "")))
            return sorted(items, key=order)
        if canonical(objects) != canonical(self._nft_objects()):
            raise Refusal("Effective peer nftables policy is foreign or has drifted; refusing replacement.")
        return True

    def _ensure_nft(self) -> None:
        if not self._nft_exact(False):
            document = {"nftables": [{"add": item} for item in self._nft_objects()]}
            command(["/usr/sbin/nft", "-j", "-f", "-"], json.dumps(document))
        self._nft_exact()

    def _systemd(self) -> dict:
        keys = ("LoadState", "ActiveState", "MainPID", "FragmentPath", "DropInPaths",
                "NeedDaemonReload", "ExecStart", "ExecStartPre", "KillMode", "User",
                "ControlGroup", "UnitFileState", "Transient")
        result = command(["/usr/bin/systemctl", "show", self.unit_name,
                          "--property=" + ",".join(keys), "--all", "--no-pager"])
        rows = [line.split("=", 1) for line in result.stdout.splitlines()]
        if any(len(row) != 2 for row in rows) or len(rows) != len(set(row[0] for row in rows)):
            raise Refusal("Malformed effective peer systemd state.")
        info = dict(rows)
        # systemd 257 omits Exec properties for a nonexistent unit even with
        # --all. Normalize only these two after proving the exact absence
        # tuple; a loaded/active or otherwise incomplete reply must fail.
        missing = set(keys) - set(info)
        if (missing <= {"ExecStart", "ExecStartPre"}
            and info.get("LoadState") == "not-found"
            and info.get("ActiveState") == "inactive" and info.get("MainPID") == "0"
            and all(info.get(key) == "" for key in ("FragmentPath", "DropInPaths", "ControlGroup"))):
            for key in missing:
                info[key] = ""
        if set(info) != set(keys):
            raise Refusal("Incomplete effective peer systemd state.")
        return info

    def _unit_exact(self, active: bool = False, allow_absent: bool = False,
                    allow_reload: bool = False) -> dict:
        info = self._systemd()
        if allow_absent and info["LoadState"] == "not-found" and info["ActiveState"] == "inactive" and info["MainPID"] == "0":
            return info
        expected = "/usr/sbin/sshd -D -e -f " + str(self.public / "sshd_config")
        pre = "/usr/bin/python3 -I " + str(self.helper) + " ensure-egress --input " + str(self.record / "input.txt")
        def argv(value):
            return re.findall(r"argv\[\]=(.*?)(?: ;|;)", value)
        if (info["LoadState"] != "loaded" or info["FragmentPath"] != str(self.unit)
            or info["DropInPaths"] or info["KillMode"] != "control-group"
            or info["User"] != "root" or info["Transient"] != "no"
            or argv(info["ExecStart"]) != [expected] or argv(info["ExecStartPre"]) != [pre]
            or not allow_reload and info["NeedDaemonReload"] != "no"):
            raise Refusal("Effective peer service definition is missing, stale or foreign.")
        if active and (info["ActiveState"] != "active" or info["UnitFileState"] != "enabled"):
            raise Refusal("Peer service is not both active and persistently enabled.")
        return info

    def _uid_processes(self) -> list[int]:
        result = []
        for path in (self.layout.root / "proc").glob("[0-9]*/status"):
            try:
                line = next((line for line in path.read_text().splitlines() if line.startswith("Uid:")), "")
                if self.owner["uid"] in [int(value) for value in line.split()[1:]]:
                    result.append(int(path.parent.name))
            except FileNotFoundError:
                continue
        return result

    def _live_process(self, info: dict) -> None:
        pid = int(info["MainPID"]) if info["MainPID"].isdecimal() else 0
        if pid <= 1:
            raise Refusal("Peer service has no proven live sshd PID.")
        proc = self.layout.root / "proc" / str(pid)
        status = proc.joinpath("status").read_text()
        uids = next((line.split()[1:] for line in status.splitlines() if line.startswith("Uid:")), [])
        if uids != ["0", "0", "0", "0"] or os.readlink(proc / "exe") != "/usr/sbin/sshd":
            raise Refusal("Peer listener process is not the claimed root OpenSSH daemon.")
        group = info["ControlGroup"]
        if not group.startswith("/") or ".." in group.split("/") or not group.endswith("/" + self.unit_name):
            raise Refusal("Peer service has an unexpected cgroup.")
        def member(process):
            try:
                return ("0::" + group) in (self.layout.root / "proc" / str(process) / "cgroup").read_text().splitlines()
            except FileNotFoundError:
                return True  # process exited during the read-only audit
        if not member(pid) or any(not member(process) for process in self._uid_processes()):
            raise Refusal("Peer UID process exists outside the owned service cgroup.")
        self._listener(pid)

    def _listener(self, pid: int) -> None:
        import ipaddress
        owned_sockets = set()
        for fd in (self.layout.root / "proc" / str(pid) / "fd").iterdir():
            try:
                target = os.readlink(fd)
                if target.startswith("socket:["):
                    owned_sockets.add(target[8:-1])
            except FileNotFoundError:
                continue
        found = []
        for name in ("tcp", "tcp6"):
            path = self.layout.root / "proc/net" / name
            if not path.exists():
                continue
            for row in path.read_text().splitlines()[1:]:
                fields = row.split()
                if len(fields) < 10 or fields[3] != "0A" or fields[9] not in owned_sockets:
                    continue
                address, port = fields[1].split(":")
                raw = bytes.fromhex(address)
                if sys.byteorder == "little":
                    raw = b"".join(raw[index:index + 4][::-1] for index in range(0, len(raw), 4))
                found.append((str(ipaddress.ip_address(raw)), int(port, 16), fields[7]))
        if found != [(self.owner["bind_address"], self.snapshot.control_port, "0")]:
            raise Refusal("Live sshd listener does not match the exact bound endpoint and root process.")

    def _verify_static(self, missing: bool = False) -> None:
        if self._helper_digest() != self.owner["helper_sha256"]:
            raise Refusal("Root-controlled peer helper changed since enrollment.")
        self._host_identity(self.owner)
        self._files(missing)
        self._group(not missing)
        self._account(not missing)

    def ensure_egress(self) -> str:
        with live_lock(self.snapshot, self.layout):
            self._load()
            self._verify_static()
            self._sshd_policy()
            self._unit_exact()
            self._ensure_nft()
        return "PEER EGRESS VERIFIED: exact public IPv4/IPv6 TCP policy. NO READINESS ISSUED."

    def audit(self) -> str:
        with live_lock(self.snapshot, self.layout):
            self._load()
            self._verify_static()
            self._sshd_policy()
            self._nft_exact()
            self._live_process(self._unit_exact(active=True))
        return self._audit_message()

    def _audit_message(self) -> str:
        return ("PEER POLICY AUDIT PASS for " + self.snapshot.relay_id
                + ". Restricted live SSH control and public TCP egress verified. NO GATEWAY READINESS ISSUED.")

    def setup(self, spec: dict | None = None) -> str:
        with live_lock(self.snapshot, self.layout):
            if self.record.exists() or self.record.is_symlink():
                if spec is not None and read_export(self.record / "input.txt") != self.snapshot:
                    self._advance_retired()
            if self.record.exists() or self.record.is_symlink():
                owner = self._load()
                if spec is not None and any(owner[key] != value for key, value in spec.items()):
                    raise Refusal("Setup policy is immutable for this V2 binding; repair uses the original policy.")
            elif spec is None:
                raise Refusal("Repair needs an exact existing live enrollment claim.")
            else:
                self._new_claim(spec)
            # Check all surviving resources before any repair mutation.
            self._verify_static(missing=True)
            self._nft_exact(False)
            info = self._unit_exact(allow_absent=True, allow_reload=True)
            if (spec is not None and info["ActiveState"] == "active"
                and info["UnitFileState"] == "enabled" and info["NeedDaemonReload"] == "no"
                and all(path.exists() for path in self._files(True))
                and self._group(False) and self._account(False) and self._nft_present()):
                self._verify_static()
                self._sshd_policy()
                self._nft_exact()
                self._live_process(info)
                return self._audit_message()
            if info["ActiveState"] != "inactive":
                command(["/usr/bin/systemctl", "stop", self.unit_name])
            if self._uid_processes():
                raise Refusal("Dedicated UID still has processes; refusing account or policy repair.")
            self._make_account()
            self._make_files()
            self._sshd_policy()
            command(["/usr/bin/systemctl", "daemon-reload"])
            self._unit_exact()
            self._ensure_nft()
            command(["/usr/bin/systemctl", "enable", self.unit_name])
        # ExecStartPre takes the same lock. Never start while holding it.
        # A concurrent retire publishes its durable fence before stopping;
        # the pre-start refuses that generation, even after this unlock.
        command(["/usr/bin/systemctl", "start", self.unit_name])
        return self.audit()

    def retire(self) -> str:
        with live_lock(self.snapshot, self.layout):
            self._load(allow_retiring=True)
            self._verify_static(missing=True)
            self._nft_exact(False)
            info = self._unit_exact(allow_absent=True, allow_reload=True)
            marker = self.record / "retiring.json"
            if marker.exists():
                sync_existing_retiring_marker(self.record, self.snapshot, self.layout)
            else:
                publish_retiring_marker(self.record, self.snapshot, self.layout)
            # Stop the whole cgroup, including authenticated forwarders,
            # before removing the UID guard or the principal.
            if info["LoadState"] != "not-found":
                command(["/usr/bin/systemctl", "stop", self.unit_name])
                command(["/usr/bin/systemctl", "disable", self.unit_name])
            info = self._systemd()
            if info["MainPID"] != "0" or info["ActiveState"] not in ("inactive", "failed"):
                raise Refusal("Peer sshd has not stopped; keeping its egress guard and retirement fence.")
            group = info["ControlGroup"]
            if group:
                if not group.startswith("/") or ".." in group.split("/") or not group.endswith("/" + self.unit_name):
                    raise Refusal("Cannot prove retired peer service cgroup ownership.")
                cgroup = self.layout.root / "sys/fs/cgroup" / group.lstrip("/")
                for path in cgroup.glob("**/cgroup.procs"):
                    if path.read_text().strip():
                        raise Refusal("Peer cgroup still contains processes; retaining egress guard.")
            if self._uid_processes():
                raise Refusal("Peer UID still has processes; retaining egress guard and account.")
            if self._account(False):
                command(["/usr/sbin/userdel", self.snapshot.control_user])
            if self._group(False):
                command(["/usr/sbin/groupdel", self.snapshot.control_user])
            self._account(False)
            self._group(False)
            if self._nft_exact(False):
                command(["/usr/sbin/nft", "delete", "table", "inet", self.table])
            if self._nft_present():
                raise Refusal("Peer nftables table survived scoped removal.")
            for path in self._files(True):
                if path.exists():
                    path.unlink()
                    sync_dir(path.parent, self.layout)
            if self.public.exists():
                self.public.rmdir()
                sync_dir(self.public.parent, self.layout)
            command(["/usr/bin/systemctl", "daemon-reload"])
            final = self._systemd()
            if final["LoadState"] != "not-found" or final["MainPID"] != "0":
                raise Refusal("Retired peer unit still exists; keeping exact retirement journal.")
        return ("RELAY PEER RETIRED for " + self.snapshot.relay_id
                + ". Owned service, account and egress guard removed; durable generation fence retained. "
                "Inert staging and shared host resources preserved.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline public staging and separately authorized restricted Relay peer enrollment.")
    parser.add_argument("action", choices=("stage", "inspect", "retire", "setup", "repair",
                                          "audit", "ensure-egress", "retire-live"))
    parser.add_argument("--input", required=True, help="Exact public-only Gateway export text (never a private key).")
    parser.add_argument("--bind-address", help="Setup only: one explicit local IPv4/IPv6 listener address.")
    parser.add_argument("--host-key", help="Setup only: existing root-owned Ed25519 host private-key path.")
    parser.add_argument("--host-key-fingerprint", help="Setup only: independently trusted SHA256 host-key pin.")
    parser.add_argument("--allow-port", action="append", type=int, help="Setup only: allowed public TCP destination port (repeat, 1..32).")
    args = parser.parse_args()
    try:
        snapshot = read_export(Path(args.input))
        flags = (args.bind_address, args.host_key, args.host_key_fingerprint, args.allow_port)
        if args.action == "setup":
            if any(value is None for value in flags):
                raise Refusal("Setup requires bind address, existing host key, trusted fingerprint and allowed ports.")
            enrollment = PeerEnrollment(snapshot)
            spec = enrollment._validate_spec(*flags)
            print(enrollment.setup(spec))
        else:
            if any(value is not None for value in flags):
                raise Refusal("Only setup accepts enrollment policy; repair uses the exact existing claim.")
            if args.action in ("stage", "inspect", "retire"):
                print(operate(args.action, snapshot))
            else:
                enrollment = PeerEnrollment(snapshot)
                action = {"repair": enrollment.setup, "audit": enrollment.audit,
                          "ensure-egress": enrollment.ensure_egress, "retire-live": enrollment.retire}[args.action]
                print(action())
        return 0
    except (Refusal, OSError, UnicodeError) as error:
        print("FAIL CLOSED: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
