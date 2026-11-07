"""Offline Iran public-key staging tests; ALL resources are disposable fixtures."""
from __future__ import annotations

import base64
import fcntl
import importlib.util
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
source = Path(__file__).resolve().parents[2] / "resources/host/connection-relay-iran.py"
spec = importlib.util.spec_from_file_location("relay_iran_public_stage", source)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class IranOfflinePublicStageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)
        self.layout = mod.Layout(self.root, os.geteuid())
        key = self.root / "temporary-key"
        subprocess.run([
            "/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "",
            "-C", "", "-f", str(key),
        ], check=True, capture_output=True, text=True)
        self.key = " ".join(key.with_suffix(".pub").read_text().split()[:2])
        self.snapshot_bytes = self.export()
        self.snapshot = mod.parse_gateway_export(self.snapshot_bytes)
        self.input_path = self.root / "gateway-public-export.txt"
        self.input_path.write_bytes(self.snapshot_bytes)

    def export(self, record="01JAE000000000000000000077", relay="iran-stage",
               host="192.0.2.9", port=2222, user="relay-control", key=None,
               revision=1, fingerprint="a" * 64, generation="b" * 64):
        return ("\n".join([
            "PUBLIC ONLY - OFFLINE IRAN ENROLLMENT INPUT V2",
            "Relay: " + relay,
            "Record: " + record,
            "Configuration revision: " + str(revision),
            "Host fingerprint: " + fingerprint,
            "Host generation: " + generation,
            "Control endpoint: " + host + ":" + str(port),
            "Control user on Iran: " + user,
            "Ed25519 PUBLIC KEY (never copy the private key):",
            self.key if key is None else key,
            "NOT ENROLLED. Restrict Iran SSHD forwarding and public egress separately; "
            "verify both hosts and issue independent readiness before enabling.",
        ]) + "\n").encode("ascii")

    def stage(self):
        return mod.operate("stage", self.snapshot, self.layout)

    def inspect(self):
        return mod.operate("inspect", self.snapshot, self.layout)

    def retire(self):
        return mod.operate("retire", self.snapshot, self.layout)

    def test_real_ed25519_gateway_export_is_parsed_without_private_key(self):
        value = mod.read_export(self.input_path)
        self.assertEqual(self.snapshot, value)
        self.assertEqual(self.key + "\n", value.public_key.decode())
        self.assertEqual("iran-stage", value.relay_id)
        self.assertEqual("relay-control", value.control_user)
        self.assertEqual(2222, value.control_port)
        self.assertEqual(1, value.revision)
        self.assertEqual("a" * 64, value.host_fingerprint)
        self.assertEqual("b" * 64, value.host_generation)
        self.assertEqual(2, value.owner_record()["version"])
        self.assertEqual("relay-control", value.owner_record()["control_user"])
        self.assertNotIn("proposed_iran_user", value.owner_record())
        self.assertNotIn("PRIVATE KEY", value.public_key.decode())

    def test_only_inert_public_data_is_staged_and_claim_is_exact(self):
        self.assertIn("STAGED INACTIVE", self.stage())
        base = self.layout.stage(self.snapshot)
        self.assertEqual({"owner.json", "control_key.pub"}, {p.name for p in base.iterdir()})
        self.assertEqual(0o700, base.stat().st_mode & 0o777)
        self.assertEqual(0o644, (base / "control_key.pub").stat().st_mode & 0o777)
        self.assertEqual(self.snapshot.public_key, (base / "control_key.pub").read_bytes())
        self.assertEqual(mod._encode(self.snapshot.owner_record()), (base / "owner.json").read_bytes())
        self.assertIn("NOT ENROLLED OR READY", self.inspect())
        self.assertFalse((self.root / "etc").exists())
        self.assertFalse((self.root / "var/log").exists())
        self.assertFalse((self.root / "usr").exists())
        self.assertFalse(any(p.name == "authorized_keys" for p in self.root.rglob("*")))
        self.assertFalse(any(p.name.endswith(".service") for p in self.root.rglob("*")))

    def test_repeated_stage_is_idempotent_and_preserves_bytes(self):
        self.stage()
        base = self.layout.stage(self.snapshot)
        before = {entry.name: entry.read_bytes() for entry in base.iterdir()}
        self.assertIn("ALREADY STAGED INACTIVE", self.stage())
        self.assertEqual(before, {entry.name: entry.read_bytes() for entry in base.iterdir()})

    def test_changed_gateway_revision_or_generation_cannot_adopt_staged_identity(self):
        self.stage()
        stage = self.layout.stage(self.snapshot)
        before = {item.name: item.read_bytes() for item in stage.iterdir()}
        for kwargs in (
            {"revision": 2, "fingerprint": "c" * 64, "generation": "d" * 64},
            {"revision": 1, "fingerprint": "c" * 64},
            {"revision": 1, "generation": "d" * 64},
        ):
            with self.subTest(kwargs=kwargs):
                next_snapshot = mod.parse_gateway_export(self.export(**kwargs))
                with self.assertRaisesRegex(mod.Refusal, "differs"):
                    mod.operate("stage", next_snapshot, self.layout)
                with self.assertRaisesRegex(mod.Refusal, "differs"):
                    mod.operate("inspect", next_snapshot, self.layout)
                with self.assertRaisesRegex(mod.Refusal, "differs"):
                    mod.operate("retire", next_snapshot, self.layout)
                self.assertEqual(before, {item.name: item.read_bytes()
                                          for item in stage.iterdir()})
        self.assertIn("NOT ENROLLED", self.inspect())
        self.assertIn("STAGE RETIRED", self.retire())
        next_snapshot = mod.parse_gateway_export(
            self.export(revision=2, fingerprint="c" * 64, generation="d" * 64)
        )
        self.assertIn("STAGED INACTIVE", mod.operate("stage", next_snapshot, self.layout))
        self.assertEqual(2, next_snapshot.owner_record()["configuration_revision"])
        self.assertEqual("d" * 64, next_snapshot.owner_record()["host_generation"])
        self.assertEqual(2, next_snapshot.owner_record()["version"])

    def test_versioned_public_export_rejects_v1_and_noncanonical_generation(self):
        original = self.snapshot_bytes
        legacy_v1 = (
            original.replace(b" INPUT V2", b" INPUT")
            .replace(b"Configuration revision: 1\n", b"")
            .replace(b"Host fingerprint: " + b"a" * 64 + b"\n", b"")
            .replace(b"Host generation: " + b"b" * 64 + b"\n", b"")
        )
        self.assertEqual(8, len(legacy_v1.splitlines()))
        invalid = [
            legacy_v1,
            original.replace(b" INPUT V2", b" INPUT"),
            original.replace(b"Configuration revision: 1", b"Configuration revision: 0"),
            original.replace(b"Configuration revision: 1", b"Configuration revision: 01"),
            original.replace(b"Configuration revision: 1", b"Configuration revision: 4294967296"),
            original.replace(b"Configuration revision: 1", b"Configuration revision: -1"),
            original.replace(b"Configuration revision: 1", b"Configuration revision: 1.0"),
            original.replace(b"Host fingerprint: " + b"a" * 64,
                             b"Host fingerprint: " + b"A" * 64),
            original.replace(b"Host fingerprint: " + b"a" * 64,
                             b"Host fingerprint: " + b"a" * 63),
            original.replace(b"Host generation: " + b"b" * 64,
                             b"Host generation: " + b"b" * 63),
            original.replace(b"Host generation: " + b"b" * 64,
                             b"Host generation: " + b"g" * 64),
            original.replace(b"Host generation: ", b"Generation: "),
            original.replace(b"Host generation: " + b"b" * 64 + b"\n", b""),
            original.replace(b"Configuration revision: 1\n", b"Configuration revision: 1\n" * 2),
        ]
        for exported in invalid:
            with self.subTest(export=exported[:110]):
                with self.assertRaises(mod.Refusal):
                    mod.parse_gateway_export(exported)
        self.assertFalse(self.layout.stages.exists())

    def test_legacy_v1_staging_claim_is_not_silently_migrated_or_retired(self):
        self.stage()
        stage = self.layout.stage(self.snapshot)
        legacy_claim = self.snapshot.owner_record()
        legacy_claim["version"] = 1
        for name in ("configuration_revision", "host_fingerprint", "host_generation"):
            del legacy_claim[name]
        (stage / "owner.json").write_bytes(mod._encode(legacy_claim))
        before = {item.name: item.read_bytes() for item in stage.iterdir()}
        for action in (self.stage, self.inspect, self.retire):
            with self.subTest(action=action.__name__):
                with self.assertRaisesRegex(mod.Refusal, "differs"):
                    action()
                self.assertEqual(before, {item.name: item.read_bytes()
                                          for item in stage.iterdir()})
        self.assertFalse((stage / "retiring.json").exists())

    def test_cold_boot_missing_run_lock_can_be_recreated_without_changing_stage(self):
        self.stage()
        before = {
            p.name: p.read_bytes() for p in self.layout.stage(self.snapshot).iterdir()
        }
        shutil.rmtree(self.layout.locks)
        self.assertIn("NOT ENROLLED", self.inspect())
        self.assertTrue(self.layout.lock(self.snapshot).is_file())
        self.assertEqual(
            before, {p.name: p.read_bytes() for p in self.layout.stage(self.snapshot).iterdir()}
        )

    def test_same_relay_name_new_record_uses_separate_namespace(self):
        self.stage()
        other = mod.parse_gateway_export(self.export(record="01JAE000000000000000000078"))
        self.assertIn("STAGED INACTIVE", mod.operate("stage", other, self.layout))
        self.assertNotEqual(self.layout.stage(self.snapshot), self.layout.stage(other))
        self.assertEqual(self.snapshot.public_key, (self.layout.stage(self.snapshot) / "control_key.pub").read_bytes())
        self.assertTrue(self.layout.stage(other).is_dir())
        self.assertIn("NOT ENROLLED", self.inspect())

    def test_changed_key_or_control_endpoint_cannot_adopt_staged_record(self):
        self.stage()
        other_export = self.export(host="192.0.2.10")
        other = mod.parse_gateway_export(other_export)
        with self.assertRaisesRegex(mod.Refusal, "differs"):
            mod.operate("stage", other, self.layout)
        tampered = self.snapshot.public_key.decode().replace("ssh-ed25519 ", "ssh-ed25519 A")
        with self.assertRaises(mod.Refusal):
            mod.parse_gateway_export(self.export(key=tampered))
        self.assertIn("NOT ENROLLED", self.inspect())

    def test_incorrect_public_export_formats_fail_closed(self):
        invalid = [
            self.snapshot_bytes + b"UNEXPECTED EXTRA\n",
            self.snapshot_bytes.replace(b"Record: ", b"Rexord: "),
            self.snapshot_bytes.replace(b"iran-stage", b"../../root"),
            self.snapshot_bytes.replace(b"relay-control", b"root;touch"),
            self.snapshot_bytes.replace(b"relay-control", b"root"),
            self.snapshot_bytes.replace(b"192.0.2.9:2222", b"192.0.2.9:0"),
            self.snapshot_bytes.replace(b"192.0.2.9:2222", b"192.0.2.9:99999"),
            self.snapshot_bytes.replace(b"ssh-ed25519 ", b"ssh-rsa "),
            self.snapshot_bytes.replace(b"NOT ENROLLED.", b"ENROLLED."),
            self.snapshot_bytes.replace(b"PUBLIC ONLY", b"\x00PRIVATE"),
            self.snapshot_bytes + b"X" * 4097,
        ]
        for item in invalid:
            with self.subTest(item=item[:44]):
                with self.assertRaises(mod.Refusal):
                    mod.parse_gateway_export(item)
        self.assertFalse(self.layout.stages.exists())

    def test_real_gateway_public_export_roundtrips_into_inert_iran_stage(self):
        # Not a copied snapshot string: reuse the real Gateway helper with
        # its disposable staged systemd/UID/ACL fixture and Ed25519 keygen.
        from tests.Support.test_connection_relay_gateway_host import (
            GatewayStagedSetupTests, mod as gateway,
        )
        source_case = GatewayStagedSetupTests(
            "test_public_enrollment_exports_only_current_stage_public_key"
        )
        source_case.setUp()
        try:
            self.assertIn("NO READINESS ISSUED", source_case.setup.setup())
            text = gateway.GatewayPolicyAudit(
                source_case.relay, source_case.layout, source_case.fake
            ).public_enrollment()
            snapshot = mod.parse_gateway_export((text + "\n").encode("ascii"))
            self.assertEqual(source_case.relay.record_id, snapshot.record_id)
            self.assertEqual(source_case.relay.revision, snapshot.revision)
            self.assertEqual(source_case.relay.fingerprint, snapshot.host_fingerprint)
            self.assertEqual(
                source_case.setup._generation()["host_generation"], snapshot.host_generation,
            )
            self.assertEqual(
                (source_case.layout.key_dir(source_case.relay) / "control_key.pub").read_text().strip(),
                snapshot.public_key.decode().strip(),
            )
            self.assertIn("STAGED INACTIVE", mod.operate("stage", snapshot, self.layout))
            self.assertNotIn("PRIVATE KEY", (self.layout.stage(snapshot) / "owner.json").read_text())
            self.assertIn("NOT ENROLLED", mod.operate("inspect", snapshot, self.layout))
        finally:
            source_case.doCleanups()

    def test_ed25519_wire_field_length_must_be_exact(self):
        wire = base64.b64decode(self.key.split()[1])
        bad = wire[:15] + b"\x00\x00\x00\x1f" + wire[19:]
        key = "ssh-ed25519 " + base64.b64encode(bad).decode()
        with self.assertRaisesRegex(mod.Refusal, "wire-format"):
            mod.parse_gateway_export(self.export(key=key))

    def test_symlink_export_and_trusted_namespace_must_be_rejected(self):
        alias = self.root / "input-symlink"
        alias.symlink_to(self.input_path)
        with self.assertRaises(OSError):
            mod.read_export(alias)
        foreign = self.root / "foreign"
        foreign.mkdir()
        base = self.root / "var/lib"
        base.mkdir(parents=True)
        self.layout.stages.symlink_to(foreign, target_is_directory=True)
        with self.assertRaises(mod.Refusal):
            self.stage()
        self.assertEqual([], list(foreign.iterdir()))

    def test_fifo_export_rejected_without_blocking_or_staging(self):
        fifo = self.root / "untrusted-input-fifo"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(mod.Refusal, "Invalid or oversized"):
            mod.read_export(fifo)
        self.assertFalse(self.layout.stages.exists())

    def test_foreign_extra_file_and_symlink_inside_stage_are_preserved(self):
        self.stage()
        base = self.layout.stage(self.snapshot)
        foreign = base / "unknown"
        foreign.write_text("other actor")
        with self.assertRaisesRegex(mod.Refusal, "Unexpected"):
            self.inspect()
        with self.assertRaisesRegex(mod.Refusal, "Unexpected"):
            self.retire()
        self.assertEqual("other actor", foreign.read_text())
        foreign.unlink()
        public = base / "control_key.pub"
        public.unlink()
        public.symlink_to(self.input_path)
        with self.assertRaises(mod.Refusal):
            self.inspect()
        self.assertEqual(self.snapshot_bytes, self.input_path.read_bytes())

    def test_insecure_parent_or_private_stage_mode_fails_closed(self):
        self.stage()
        base = self.layout.stage(self.snapshot)
        base.chmod(0o755)
        with self.assertRaisesRegex(mod.Refusal, "0700"):
            self.inspect()
        base.chmod(0o700)
        self.layout.stages.chmod(0o777)
        with self.assertRaisesRegex(mod.Refusal, "writable"):
            self.inspect()

    def test_retirement_removes_only_exact_public_staging_and_is_repeatable(self):
        self.stage()
        sibling = self.layout.stages / "unrelated-root-owned-data"
        sibling.write_text("UNRELATED")
        self.assertIn("STAGE RETIRED", self.retire())
        self.assertFalse(self.layout.stage(self.snapshot).exists())
        self.assertEqual("UNRELATED", sibling.read_text())
        self.assertIn("NO IRAN STAGE PRESENT", self.retire())
        with self.assertRaisesRegex(mod.Refusal, "no exact"):
            self.inspect()
        self.assertFalse((self.root / "etc").exists())

    def test_retirement_wrong_snapshot_must_not_delete_other_record(self):
        self.stage()
        other = mod.parse_gateway_export(self.export(host="192.0.2.10"))
        with self.assertRaises(mod.Refusal):
            mod.operate("retire", other, self.layout)
        self.assertTrue(self.layout.stage(self.snapshot).is_dir())
        self.assertIn("NOT ENROLLED", self.inspect())

    def test_retirement_crash_during_marker_write_never_leaves_partial_name(self):
        self.stage()
        stage = self.layout.stage(self.snapshot)
        public = (stage / "control_key.pub").read_bytes()
        claim = (stage / "owner.json").read_bytes()
        native_write = os.write

        def interrupted_write(fd, data):
            native_write(fd, bytes(data[:3]))
            raise OSError("simulated power loss during anonymous marker write")

        with mock.patch.object(mod.os, "write", side_effect=interrupted_write):
            with self.assertRaisesRegex(OSError, "simulated power loss"):
                self.retire()
        self.assertFalse((stage / "retiring.json").exists())
        self.assertEqual(public, (stage / "control_key.pub").read_bytes())
        self.assertEqual(claim, (stage / "owner.json").read_bytes())
        self.assertEqual({"control_key.pub", "owner.json"}, {p.name for p in stage.iterdir()})
        self.assertIn("STAGE RETIRED", self.retire())

    def test_retirement_crash_before_anonymous_creation_preserves_stage(self):
        self.stage()
        stage = self.layout.stage(self.snapshot)
        real_open = mod.os.open

        def fail_tmpfile(path, flags, *args, **kwargs):
            if flags & os.O_TMPFILE == os.O_TMPFILE:
                raise OSError("simulated failure opening anonymous marker")
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(mod.os, "open", side_effect=fail_tmpfile):
            with self.assertRaisesRegex(mod.Refusal, "cannot safely stage|Filesystem cannot safely"):
                self.retire()
        self.assertEqual({"owner.json", "control_key.pub"}, {p.name for p in stage.iterdir()})
        self.assertIn("STAGE RETIRED", self.retire())

    def test_retirement_crash_after_marker_write_before_publish_is_recoverable(self):
        self.stage()
        stage = self.layout.stage(self.snapshot)
        with mock.patch.object(
            mod, "_link_anonymous_marker",
            side_effect=OSError("simulated crash before atomic link"),
        ):
            with self.assertRaisesRegex(OSError, "simulated crash"):
                self.retire()
        self.assertFalse((stage / "retiring.json").exists())
        self.assertEqual({"owner.json", "control_key.pub"}, {p.name for p in stage.iterdir()})
        self.assertIn("STAGE RETIRED", self.retire())

    def test_retirement_crash_after_marker_publish_is_recoverable(self):
        self.stage()
        stage = self.layout.stage(self.snapshot)
        real_link = mod._link_anonymous_marker

        def interrupted_link(source_fd, stage_fd):
            real_link(source_fd, stage_fd)
            raise OSError("simulated crash immediately after atomic publish")

        with mock.patch.object(mod, "_link_anonymous_marker", side_effect=interrupted_link):
            with self.assertRaisesRegex(OSError, "simulated crash"):
                self.retire()
        self.assertEqual(
            mod._encode(self.snapshot.owner_record()),
            (stage / "retiring.json").read_bytes(),
        )
        self.assertEqual({"owner.json", "control_key.pub", "retiring.json"},
                         {p.name for p in stage.iterdir()})
        self.assertIn("STAGE RETIRED", self.retire())

    def _retry_with_unproven_marker_directory_sync(self):
        self.stage()
        stage = self.layout.stage(self.snapshot)
        native_fsync = mod.os.fsync
        stage_identity = (stage.stat().st_dev, stage.stat().st_ino)

        def fail_first_marker_directory_sync(fd):
            info = os.fstat(fd)
            if ((info.st_dev, info.st_ino) == stage_identity
                and (stage / "retiring.json").exists()):
                raise OSError("simulated directory fsync failure after linkat")
            return native_fsync(fd)

        with mock.patch.object(mod.os, "fsync", side_effect=fail_first_marker_directory_sync):
            with self.assertRaisesRegex(OSError, "directory fsync failure after linkat"):
                self.retire()
        self.assertEqual(
            {"control_key.pub", "owner.json", "retiring.json"},
            {item.name for item in stage.iterdir()},
        )
        self.assertEqual(
            mod._encode(self.snapshot.owner_record()),
            (stage / "retiring.json").read_bytes(),
        )
        return stage

    def test_retirement_retry_reestablishes_marker_durability_before_first_unlink(self):
        stage = self._retry_with_unproven_marker_directory_sync()
        marker = stage / "retiring.json"
        marker_info, stage_info = marker.stat(), stage.stat()
        marker_identity = (marker_info.st_dev, marker_info.st_ino)
        stage_identity = (stage_info.st_dev, stage_info.st_ino)
        native_fsync = mod.os.fsync
        native_unlink = Path.unlink
        events = []

        def trace_fsync(fd):
            info = os.fstat(fd)
            identity = (info.st_dev, info.st_ino)
            if identity == marker_identity:
                events.append("marker_fsync")
            if identity == stage_identity:
                events.append("stage_fsync")
            return native_fsync(fd)

        def trace_unlink(path, *args, **kwargs):
            if path == stage / "control_key.pub":
                events.append("first_unlink")
            return native_unlink(path, *args, **kwargs)

        with (mock.patch.object(mod.os, "fsync", side_effect=trace_fsync),
              mock.patch.object(Path, "unlink", new=trace_unlink)):
            self.assertIn("STAGE RETIRED", self.retire())
        self.assertLess(events.index("marker_fsync"), events.index("stage_fsync"))
        self.assertLess(events.index("stage_fsync"), events.index("first_unlink"))
        self.assertFalse(stage.exists())

    def test_retirement_retry_fsync_failure_preserves_public_artifacts(self):
        stage = self._retry_with_unproven_marker_directory_sync()
        marker = stage / "retiring.json"
        marker_info, stage_info = marker.stat(), stage.stat()
        identities = {
            "marker": (marker_info.st_dev, marker_info.st_ino),
            "directory": (stage_info.st_dev, stage_info.st_ino),
        }
        before = {name: (stage / name).read_bytes()
                  for name in ("control_key.pub", "owner.json", "retiring.json")}
        native_fsync = mod.os.fsync

        for boundary in ("marker", "directory"):
            with self.subTest(boundary=boundary):
                def fail_retry_sync(fd):
                    info = os.fstat(fd)
                    if (info.st_dev, info.st_ino) == identities[boundary]:
                        raise OSError("simulated retry fsync failure")
                    return native_fsync(fd)

                with mock.patch.object(mod.os, "fsync", side_effect=fail_retry_sync):
                    with self.assertRaisesRegex(OSError, "simulated retry fsync failure"):
                        self.retire()
                self.assertEqual(before, {name: (stage / name).read_bytes()
                                          for name in before})
        self.assertIn("STAGE RETIRED", self.retire())
        self.assertFalse(stage.exists())

    def test_retirement_crash_at_each_artifact_boundary_recovers(self):
        native_unlink = Path.unlink
        for boundary in ("control_key.pub", "owner.json", "retiring.json"):
            with self.subTest(boundary=boundary):
                self.stage()
                stage = self.layout.stage(self.snapshot)

                def interrupt_unlink(path, *args, **kwargs):
                    native_unlink(path, *args, **kwargs)
                    if path == stage / boundary:
                        raise OSError("simulated crash after " + boundary)

                with mock.patch.object(Path, "unlink", new=interrupt_unlink):
                    with self.assertRaisesRegex(OSError, "simulated crash"):
                        self.retire()
                self.assertIn("STAGE RETIRED", self.retire())
                self.assertFalse(stage.exists())

    def test_retirement_crash_before_final_rmdir_and_after_rmdir_is_recoverable(self):
        self.stage()
        stage = self.layout.stage(self.snapshot)
        native_rmdir = Path.rmdir

        def refuse_rmdir(path, *args, **kwargs):
            if path == stage:
                raise OSError("simulated crash before rmdir")
            return native_rmdir(path, *args, **kwargs)

        with mock.patch.object(Path, "rmdir", new=refuse_rmdir):
            with self.assertRaisesRegex(OSError, "simulated crash"):
                self.retire()
        self.assertTrue(stage.is_dir())
        self.assertEqual([], list(stage.iterdir()))
        # Reset and repeat at the boundary *after* the final rmdir.
        self.assertIn("EMPTY IRAN PUBLIC STAGE RETIRED", self.retire())
        self.stage()
        real_sync = mod.sync_dir

        def refuse_sync(path, layout):
            if path == self.layout.stages and not stage.exists():
                raise OSError("simulated crash after final rmdir")
            return real_sync(path, layout)

        with mock.patch.object(mod, "sync_dir", side_effect=refuse_sync):
            with self.assertRaisesRegex(OSError, "simulated crash"):
                self.retire()
        self.assertFalse(stage.exists())
        self.assertIn("NO IRAN STAGE PRESENT", self.retire())

    def test_truncated_foreign_retirement_marker_is_preserved(self):
        self.stage()
        stage = self.layout.stage(self.snapshot)
        mod.write_new(stage / "retiring.json", b"{", 0o600)
        for action in (self.retire, self.inspect, self.stage):
            with self.assertRaises(mod.Refusal):
                action()
        self.assertEqual(b"{", (stage / "retiring.json").read_bytes())
        self.assertTrue((stage / "control_key.pub").is_file())
        self.assertTrue((stage / "owner.json").is_file())

    def test_interrupted_retirement_resumes_only_exact_owned_public_files(self):
        self.stage()
        base = self.layout.stage(self.snapshot)
        mod.write_new(base / "retiring.json", mod._encode(self.snapshot.owner_record()), 0o600)
        (base / "control_key.pub").unlink()
        self.assertIn("STAGE RETIRED", self.retire())
        self.assertFalse(base.exists())

    def test_empty_stage_left_by_interrupted_final_rmdir_is_recoverable(self):
        self.stage()
        base = self.layout.stage(self.snapshot)
        # Simulate a crash after all public artifacts and the durable
        # retirement marker were unlinked, before the final rmdir.
        for file in base.iterdir():
            file.unlink()
        self.assertIn("EMPTY IRAN PUBLIC STAGE RETIRED", self.retire())
        self.assertFalse(base.exists())

    def test_orphaned_partial_stage_without_retirement_marker_refused(self):
        self.stage()
        (self.layout.stage(self.snapshot) / "owner.json").unlink()
        with self.assertRaisesRegex(mod.Refusal, "Partial staging"):
            self.retire()
        with self.assertRaises(mod.Refusal):
            self.stage()

    def test_unknown_temporary_staging_crash_residue_blocks_adoption(self):
        path = self.layout.stages
        path.mkdir(parents=True)
        (path / (".pending-" + self.snapshot.record_id + "-leftover")).mkdir()
        with self.assertRaisesRegex(mod.Refusal, "Interrupted staging"):
            self.stage()
        self.assertTrue((path / (".pending-" + self.snapshot.record_id + "-leftover")).exists())

    def test_lifecycle_lock_contends_without_touching_staged_data(self):
        self.stage()
        lock = self.layout.lock(self.snapshot)
        fd = os.open(lock, os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(mod.Refusal, "maintenance is active"):
                self.inspect()
        finally:
            os.close(fd)
        self.assertIn("NOT ENROLLED", self.inspect())

    @staticmethod
    def _operator_runbook_scripts():
        """Execute the real documented Bash bodies with disposable test paths."""
        doc = (Path(__file__).resolve().parents[2] /
               "docs/CONNECTION-RELAYS.md").read_text()
        section = doc.split("## Offline Iran-side public-identity staging", 1)[1]
        section = section.split("## Gateway-local privileged policy audit", 1)[0]
        installer = section.split(
            "    /usr/bin/sudo /usr/bin/env -i PATH=/usr/sbin:/usr/bin LC_ALL=C "
            "/usr/bin/bash -c '\n", 1,
        )[1].split("\n    ' bash \"$PWD/connection-relay-iran.py\"", 1)[0]
        runner = section.split(
            "    iran_relay_public() {\n"
            "      /usr/bin/sudo /usr/bin/env -i PATH=/usr/sbin:/usr/bin "
            "LC_ALL=C /usr/bin/bash -c '\n", 1,
        )[1].split("\n      ' bash \"$@\"", 1)[0]
        import textwrap
        return textwrap.dedent(installer), textwrap.dedent(runner), section

    def _sandbox_operator_scripts(self):
        installer, runner, section = self._operator_runbook_scripts()
        uid = os.geteuid()
        root = self.root
        directory = root / "libexec/mcp-gateway-iran-relay"
        installer = (installer
                     .replace("base=/usr/local/libexec", "base=" + str(root / "libexec"))
                     .replace("for parent in / /usr /usr/local; do",
                              "for parent in " + str(root) + "; do")
                     .replace("-o root -g root", "")
                     .replace('")" = 0 &&', '")" = ' + str(uid) + ' &&')
                     .replace(')" = 0 &&', ')" = ' + str(uid) + ' &&'))
        runner = (runner
                  .replace("directory=/usr/local/libexec/mcp-gateway-iran-relay",
                           "directory=" + str(directory))
                  .replace('for parent in / /usr /usr/local /usr/local/libexec "$directory"; do',
                           'for parent in "$directory"; do')
                  .replace('")" = 0 &&', '")" = ' + str(uid) + ' &&')
                  .replace(')" = 0 &&', ')" = ' + str(uid) + ' &&'))
        return installer, runner, section, directory

    def _operator_shell(self, script, *args, env=None):
        return subprocess.run(
            ["/usr/bin/bash", "-c", script, "bash", *map(str, args)],
            text=True, capture_output=True, timeout=7,
            env=env or {"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"},
        )

    def test_documented_root_operator_contract_is_syntactically_valid(self):
        installer, runner, section = self._operator_runbook_scripts()
        for part in (installer, runner):
            syntax = subprocess.run(
                ["/usr/bin/bash", "-n"], input=part, text=True,
                capture_output=True, timeout=5,
            )
            self.assertEqual(0, syntax.returncode, syntax.stderr)
        self.assertIn("sudo /usr/bin/env -i", section)
        self.assertIn("root-owned", section)
        self.assertIn("test ! -L", section)
        self.assertIn("/usr/bin/ln --", installer)
        self.assertIn("/usr/bin/sha256sum --check --status", installer)
        self.assertIn("/usr/bin/sha256sum --check --status", runner)
        self.assertIn("exec 9< \"$destination\"", runner)
        self.assertIn("exec /usr/bin/python3 -I /proc/self/fd/9", runner)
        self.assertNotIn("sudo python3 connection-relay-iran.py", section)
        import hashlib
        sha = hashlib.sha256(source.read_bytes()).hexdigest()
        self.assertEqual(2, section.count("expected=" + sha))

    def test_documented_install_and_isolated_fd_execute_accept_pinned_source(self):
        installer, runner, section, directory = self._sandbox_operator_scripts()
        installed = directory / "connection-relay-iran.py"
        # The transferred source may reside next to a malicious Python module.
        transfer = self.root / "connection-relay-iran.py"
        transfer.write_bytes(source.read_bytes())
        (self.root / "hashlib.py").write_text(
            "raise RuntimeError('attacker-controlled transfer module imported')\n"
        )
        installed_result = self._operator_shell(installer, transfer)
        self.assertEqual(0, installed_result.returncode, installed_result.stderr)
        self.assertEqual(source.read_bytes(), installed.read_bytes())
        self.assertEqual(0o500, installed.stat().st_mode & 0o777)
        self.assertEqual(0o700, directory.stat().st_mode & 0o777)
        self.assertEqual({"connection-relay-iran.py"}, {p.name for p in directory.iterdir()})
        execution = self._operator_shell(
            runner, "--help",
            env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C",
                 "PYTHONPATH": str(self.root), "PYTHONINSPECT": "1"},
        )
        self.assertEqual(0, execution.returncode, execution.stderr)
        self.assertIn("Offline, inactive Iran Relay public-identity", execution.stdout)
        self.assertFalse((self.root / "var").exists())

    def test_documented_install_refuses_mismatch_and_existing_destination(self):
        installer, runner, section, directory = self._sandbox_operator_scripts()
        destination = directory / "connection-relay-iran.py"
        bad = self.root / "bad-iran-helper.py"
        bad.write_text("print('unknown code')\n")
        result = self._operator_shell(installer, bad)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("SHA256 mismatch", result.stderr)
        self.assertFalse(destination.exists())
        self.assertEqual([], list(directory.iterdir()))
        destination.write_bytes(b"untouched foreign helper")
        destination.chmod(0o500)
        result = self._operator_shell(installer, source)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("never overwritten", result.stderr)
        self.assertEqual(b"untouched foreign helper", destination.read_bytes())

    def test_documented_execution_refuses_untrusted_directory_and_drift(self):
        installer, runner, section, directory = self._sandbox_operator_scripts()
        self.assertEqual(0, self._operator_shell(installer, source).returncode)
        directory.chmod(0o777)
        bad = self._operator_shell(runner, "--help")
        self.assertNotEqual(0, bad.returncode)
        self.assertIn("Untrusted helper path", bad.stderr)
        directory.chmod(0o700)
        installed = directory / "connection-relay-iran.py"
        installed.chmod(0o600)
        installed.write_bytes(b"foreign code\n")
        installed.chmod(0o500)
        bad = self._operator_shell(runner, "--help")
        self.assertNotEqual(0, bad.returncode)
        self.assertIn("SHA256 mismatch", bad.stderr)

    def test_pinned_descriptor_runs_verified_inode_after_path_replacement(self):
        # Simulate a name swap AFTER opening/checking the trusted source.
        directory = self.root / "trusted"
        directory.mkdir(mode=0o700)
        installed = directory / "connection-relay-iran.py"
        installed.write_bytes(source.read_bytes())
        installed.chmod(0o500)
        fd = os.open(installed, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            import hashlib
            with open("/proc/self/fd/" + str(fd), "rb") as opened:
                self.assertEqual(
                    hashlib.sha256(source.read_bytes()).hexdigest(),
                    hashlib.sha256(opened.read()).hexdigest(),
                )
            replacement = directory / "unknown.py"
            replacement.write_text("raise SystemExit(66)\n")
            os.replace(replacement, installed)
            proc = subprocess.run(
                ["/usr/bin/python3", "-I", "/proc/self/fd/" + str(fd), "--help"],
                pass_fds=(fd,), text=True, capture_output=True, timeout=7,
                env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C",
                     "PYTHONPATH": str(self.root)},
            )
            self.assertEqual(0, proc.returncode, proc.stderr)
            self.assertIn("Offline, inactive Iran Relay public-identity", proc.stdout)
            self.assertEqual(b"raise SystemExit(66)\n", installed.read_bytes())
        finally:
            os.close(fd)

    def test_non_root_request_is_rejected_before_mutation(self):
        with mock.patch.object(mod.os, "geteuid", return_value=self.layout.owner_uid + 1):
            with self.assertRaisesRegex(mod.Refusal, "explicit root"):
                self.stage()
        self.assertFalse(self.layout.stages.exists())


if __name__ == "__main__":
    unittest.main()
