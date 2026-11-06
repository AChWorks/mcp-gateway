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
               host="192.0.2.9", port=2222, user="relay-control", key=None):
        return ("\n".join([
            "PUBLIC ONLY - OFFLINE IRAN ENROLLMENT INPUT",
            "Relay: " + relay,
            "Record: " + record,
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

    def test_non_root_request_is_rejected_before_mutation(self):
        with mock.patch.object(mod.os, "geteuid", return_value=self.layout.owner_uid + 1):
            with self.assertRaisesRegex(mod.Refusal, "explicit root"):
                self.stage()
        self.assertFalse(self.layout.stages.exists())


if __name__ == "__main__":
    unittest.main()
