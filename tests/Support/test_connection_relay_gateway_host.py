"""Isolated privileged-helper tests: no real systemd, firewall or host files."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shlex
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
source = pathlib.Path(__file__).resolve().parents[2] / "resources/host/connection-relay-gateway.py"
spec = importlib.util.spec_from_file_location("relay_gateway_host", source)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class FakeHost:
    """Exact but synthetic loaded systemd + nftables policy state."""

    def __init__(self, relay: mod.Relay):
        self.relay = relay
        self.active = False
        self.enabled = False
        self.nft = False
        self.listener = False
        self.fail_stop = False
        self.fail_daemon_reload = False
        self.stale_loaded = False
        self.foreign_fragment: str | None = None
        self.foreign_fragment_after_reload: str | None = None
        self.foreign_dropin = False
        self.foreign_exec = False
        self.unknown_nft_rule = False
        self.nft_policy_reads = 0
        self.mutate_policy_on_read = 0
        self.unit_path: pathlib.Path | None = None
        self.exec_start = ("{ path=/usr/bin/ssh ; argv[]=/usr/bin/ssh -D 127.0.0.1:46081"
                           " ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a]"
                           " ; pid=0 ; code=(null) ; status=0/0 }")
        self.calls: list[list[str]] = []

    def nft_json(self) -> dict:
        table = self.relay.firewall_table
        entries = [
            {"metainfo": {"version": "1.0"}},
            {"table": {"family": "inet", "name": table, "handle": 4}},
            {"chain": {"family": "inet", "table": table, "name": "loopback", "handle": 5,
                       "type": "filter", "hook": "input", "prio": -5, "policy": "accept"}},
            {"rule": {"family": "inet", "table": table, "chain": "loopback", "handle": 6,
                      "expr": [{"match": {"left": {"meta": {"key": "skuid"}}, "op": "==",
                                          "right": 8801}}, {"accept": None}]}},
        ]
        if self.unknown_nft_rule:
            entries.append({"rule": {"family": "inet", "table": table, "chain": "loopback",
                                     "expr": [{"accept": None}]}})
        return {"nftables": entries}

    def __call__(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(argv)
        if argv[:3] == ["nft", "-j", "list"]:
            if argv[3] == "tables":
                entries = ([{"table": {"family": "inet", "name": self.relay.firewall_table}}]
                           if self.nft else [])
                return subprocess.CompletedProcess(argv, 0, json.dumps({"nftables": entries}), "")
            if argv[3] == "table":
                self.nft_policy_reads += 1
                if self.mutate_policy_on_read == self.nft_policy_reads:
                    self.unknown_nft_rule = True
                return subprocess.CompletedProcess(
                    argv, 0 if self.nft else 1,
                    json.dumps(self.nft_json()) if self.nft else "", "" if self.nft else "not found",
                )
        if argv[:3] == ["nft", "delete", "table"]:
            if not self.nft:
                return subprocess.CompletedProcess(argv, 1, "", "not found")
            self.nft = False
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[0] == "systemctl":
            if argv[1] == "show":
                unit_present = self.unit_path is not None and self.unit_path.is_file()
                if unit_present:
                    self.stale_loaded = True
                loaded = unit_present or self.stale_loaded or self.foreign_fragment is not None
                frag = (self.foreign_fragment if self.foreign_fragment is not None
                        else str(self.unit_path) if loaded else "")
                props = {
                    "Id": self.relay.unit_name,
                    "LoadState": "loaded" if loaded else "not-found",
                    "ActiveState": "active" if self.active else "inactive",
                    "FragmentPath": frag,
                    "DropInPaths": "/etc/systemd/system/foreign.conf" if self.foreign_dropin else "",
                    "NeedDaemonReload": "yes" if self.stale_loaded and not unit_present else "no",
                    "Transient": "no",
                    "ExecStart": (self.exec_start.replace(
                        "-D 127.0.0.1:46081", "-D 0.0.0.0:46081"
                    ) if self.foreign_exec else self.exec_start) if loaded else "",
                }
                if not loaded:
                    del props["ExecStart"]  # Actual systemd omits this on not-found.
                return subprocess.CompletedProcess(argv, 0,
                    "".join(k + "=" + v + "\n" for k,v in props.items()), "")
            if argv[1] == "is-active":
                return subprocess.CompletedProcess(
                    argv, 0 if self.active else 3,
                    "active\n" if self.active else "inactive\n", "",
                )
            if argv[1] == "disable":
                if self.fail_stop:
                    return subprocess.CompletedProcess(argv, 1, "", "unit refused to stop")
                self.active = False
                self.enabled = False
                self.listener = False
                return subprocess.CompletedProcess(argv, 0, "", "")
            if argv[1] == "is-enabled":
                return subprocess.CompletedProcess(
                    argv, 0 if self.enabled else 1,
                    "enabled\n" if self.enabled else "disabled\n", "",
                )
            if argv[1] == "daemon-reload":
                if not self.fail_daemon_reload:
                    self.stale_loaded = self.unit_path is not None and self.unit_path.is_file()
                    if self.foreign_fragment_after_reload is not None:
                        self.foreign_fragment = self.foreign_fragment_after_reload
                return subprocess.CompletedProcess(
                    argv, 1 if self.fail_daemon_reload else 0, "",
                    "reload failed" if self.fail_daemon_reload else "",
                )
        if argv[:3] == ["ss", "-H", "-lnt"]:
            local = "127.0.0.1:" + str(self.relay.local_port) if self.listener else ""
            return subprocess.CompletedProcess(argv, 0,
                ("LISTEN 0 128 " + local + " 0.0.0.0:*\n") if local else "", "")
        raise AssertionError("Unexpected system command: " + str(argv))


class RetirementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.relay = mod.Relay(
            "iran-1", "01JAE000000000000000000001", "f" * 64, 2, 46081,
        )
        self.layout = mod.Layout(self.root, os.geteuid())
        for path in [
            self.root / "etc/mcp-gateway/connection-relays",
            self.root / "etc/systemd/system",
            self.root / "var/lib/mcp-gateway-relays",
            self.root / "proc/sys/kernel/random",
        ]:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        for access_dir in (
            self.root / "etc", self.root / "etc/mcp-gateway",
            self.root / "etc/mcp-gateway/connection-relays",
        ):
            access_dir.chmod(0o755)
        (self.root / "proc/sys/kernel/random/boot_id").write_text(
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n"
        )
        (self.root / "proc/uptime").write_text("3601.50 100.00\n")
        self.fake = FakeHost(self.relay)
        self.operator = mod.Retirement(self.relay, self.layout, self.fake)
        self.fake.unit_path = self.layout.unit(self.relay)

    def managed_claim(self) -> dict:
        """Host-owned v2 fixture; no live root or network resources."""
        gen = self.operator._advance_generation("provisioning")
        original = self.fake.nft
        self.fake.nft = True
        try:
            policy_digest = self.operator._nft_policy_digest()
        finally:
            self.fake.nft = original
        path = self.layout.unit(self.relay)
        unit_bytes = (path.read_bytes() if path.exists()
                      else b"# MCP-GATEWAY-CONNECTION-RELAY fixture unit\n")
        claim = {
            "version": 2,
            "relay_record_id": self.relay.record_id,
            "relay_id": self.relay.relay_id,
            "service_unit": self.relay.unit_name,
            "firewall_table": self.relay.firewall_table,
            "host_fingerprint": self.relay.fingerprint,
            "configuration_revision": self.relay.revision,
            "local_socks_port": self.relay.local_port,
            "host_generation": gen,
            "unit_sha256": hashlib.sha256(unit_bytes).hexdigest(),
            "unit_exec_sha256": hashlib.sha256(
                mod.Retirement._canonical_exec(self.fake.exec_start).encode()
            ).hexdigest(),
            "firewall_sha256": policy_digest,
        }
        return claim

    def write_managed_claim(self) -> None:
        self.layout.evidence(self.relay, ".managed.json").write_text(
            json.dumps(self.managed_claim())
        )


    def test_existing_private_evidence_path_fails_without_widening_permissions(self):
        directory = self.root / "etc/mcp-gateway"
        directory.chmod(0o700)
        try:
            with self.assertRaisesRegex(mod.Refusal, "not searchable by the non-root PHP"):
                self.operator.retire()
            self.assertEqual(0o700, directory.stat().st_mode & 0o777)
            self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())
        finally:
            directory.chmod(0o755)

    def test_fresh_proof_directory_is_php_traversable_under_restrictive_umask(self):
        new = self.root / "etc/mcp-gateway/fresh-proof"
        old_umask = os.umask(0o077)
        try:
            mod.make_privileged_directory(new, self.layout, php_traversable=True)
            private = self.root / "run/private-lock"
            mod.make_privileged_directory(private, self.layout)
        finally:
            os.umask(old_umask)
        self.assertEqual(0o755, new.stat().st_mode & 0o777)
        self.assertEqual(0o700, private.stat().st_mode & 0o777)

    def test_lock_namespace_avoids_world_writable_standard_run_lock(self):
        # Debian's /run/lock is mode 1777 and must not be trusted as a
        # privileged path parent. Use a dedicated root-owned /run subtree.
        self.assertEqual(
            self.root / "run/mcp-gateway-relays/iran-1.lock",
            self.layout.lock_path(self.relay),
        )
        self.assertNotIn("/run/lock/", str(self.layout.lock_path(self.relay)))

    def test_systemd_not_found_omits_execstart_without_falsely_blocking_retirement(self):
        self.assertFalse(self.fake.active)
        state = self.operator._systemd_info()
        self.assertEqual("not-found", state["LoadState"])
        self.assertEqual("", state["ExecStart"])

    def test_fresh_disabled_draft_can_retire_without_remote_host_or_any_network(self):
        self.assertIn("claim=absent", self.operator.preview().replace("resource claim", "claim"))
        self.assertEqual([], [x for x in self.fake.calls if x[0] in ("ssh", "curl")])
        result = self.operator.retire()
        self.assertIn("Iran was not contacted", result)
        output = self.layout.evidence(self.relay, ".retired.json")
        receipt = json.loads(output.read_text())
        self.assertEqual(set(receipt), {
            "relay_record_id", "relay_id", "host_fingerprint",
            "configuration_revision", "host_generation", "verified_boot_id", "verified_at_unix",
            "verified_at_boot_seconds", "expires_at_unix",
            "gateway_cleanup_verified",
        })
        self.assertEqual(self.relay.record_id, receipt["relay_record_id"])
        state = self.operator._generation()
        self.assertEqual("retired", state["state"])
        self.assertEqual(state["host_generation"], receipt["host_generation"])
        self.assertEqual(0o644, self.layout.evidence(self.relay, ".generation.json").stat().st_mode & 0o777)
        self.assertEqual(0o644, output.stat().st_mode & 0o777)
        self.assertTrue(receipt["gateway_cleanup_verified"])
        self.assertEqual(3601, receipt["verified_at_boot_seconds"])
        self.assertLessEqual(receipt["expires_at_unix"]-receipt["verified_at_unix"], 900)
        self.assertEqual([], [x for x in self.fake.calls if x[0] in ("ssh", "curl", "scp")])
        self.assertEqual(0, self.operator.retire().count("Iran was not contacted") - 1)

    def test_owned_managed_relay_is_removed_without_affecting_another(self):
        self.fake.active = self.fake.enabled = self.fake.listener = self.fake.nft = True
        unit = self.layout.unit(self.relay)
        unit.write_text(
            "# MCP-GATEWAY-CONNECTION-RELAY " + self.relay.record_id
            + " " + self.relay.relay_id + "\n[Unit]\nDescription=owned\n"
        )
        self.write_managed_claim()
        keys = self.layout.key_dir(self.relay)
        keys.mkdir(mode=0o700)
        (keys / "control_key").write_text("synthetic fixture key\n")
        policy = self.layout.evidence(self.relay, ".policy")
        policy.write_text("a" * 64)
        attestation = self.layout.evidence(self.relay, ".json")
        attestation.write_text(json.dumps({"relay_id": self.relay.relay_id}))

        # Sibling artifacts are strictly out of scope.
        sibling = self.layout.unit(mod.Relay(
            "iran-2", "01JAE000000000000000000002", "b"*64, 3, 46082))
        sibling.write_text("NEVER TOUCH")
        reverse = self.layout.unit(self.relay).parent / "mcp-gateway-reverse-ssh.service"
        reverse.write_text("Reverse SSH is unrelated and must be preserved")
        self.assertIn("resource claim=verified", self.operator.preview())
        self.assertIn("RETIREMENT VERIFIED", self.operator.retire())
        for old in (unit, keys, policy, attestation, self.layout.evidence(self.relay, ".managed.json")):
            self.assertFalse(old.exists(), str(old))
        self.assertEqual("NEVER TOUCH", sibling.read_text())
        self.assertEqual("Reverse SSH is unrelated and must be preserved", reverse.read_text())
        self.assertFalse(any("reverse-ssh" in " ".join(cmd) for cmd in self.fake.calls))
        self.assertFalse(self.fake.active)
        self.assertFalse(self.fake.nft)
        self.assertEqual(1, sum(1 for x in self.fake.calls if x[:3] == ["nft", "delete", "table"]))
        self.assertEqual(1, sum(1 for x in self.fake.calls if x[:2] == ["systemctl", "disable"]))

    def test_listener_refusal_preserves_firewall_even_after_service_stops(self):
        self.fake.nft = True
        self.fake.listener = True
        self.write_managed_claim()
        with self.assertRaisesRegex(mod.Refusal, "Firewall ACL was preserved"):
            self.operator.retire()
        self.assertTrue(self.fake.nft)
        self.assertFalse(any(x[:3] == ["nft", "delete", "table"] for x in self.fake.calls))
        self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())

    def test_enabled_unit_cannot_be_reported_retired_even_when_inactive(self):
        self.fake.enabled = True
        with self.assertRaisesRegex(mod.Refusal, "disabled/inactive/absent"):
            self.operator.retire()
        self.assertTrue(self.fake.enabled)
        self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())

    def test_unclaimed_legacy_attestation_is_not_misrepresented_as_cleanup(self):
        previous_policy = self.layout.evidence(self.relay, ".policy")
        previous_policy.write_text("b"*64)
        with self.assertRaisesRegex(mod.Refusal, "Unclaimed active host evidence"):
            self.operator.retire()
        self.assertEqual("b"*64, previous_policy.read_text())
        self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())

    def test_cleanup_refuses_unknown_unit_without_owned_manifest(self):
        unit = self.layout.unit(self.relay)
        unit.write_text("# Someone else's service\n")
        with self.assertRaisesRegex(mod.Refusal, "without a root-owned matching claim"):
            self.operator.retire()
        self.assertTrue(unit.exists())
        self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())

    def test_unclaimed_inactive_foreign_same_name_service_blocks_retirement_and_setup(self):
        # A file may be absent from the owned location while a foreign unit
        # with the same name remains loaded but inactive/disabled in systemd.
        self.fake.foreign_fragment = "/usr/lib/systemd/system/" + self.relay.unit_name
        with self.assertRaisesRegex(mod.Refusal, "same-name systemd"):
            self.operator.retire()
        with self.assertRaisesRegex(mod.Refusal, "same-name systemd"):
            self.operator.prepare_setup()
        self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())
        self.assertFalse(self.layout.evidence(self.relay, ".generation.json").exists())
        self.assertFalse(any(x[:2] == ["systemctl", "disable"] for x in self.fake.calls))

    def test_foreign_same_name_unit_loaded_after_reload_prevents_retirement_proof(self):
        unit = self.layout.unit(self.relay)
        unit.write_text("# MCP-GATEWAY-CONNECTION-RELAY " + self.relay.record_id +
                        " " + self.relay.relay_id + "\n[Unit]\nDescription=owned\n")
        self.write_managed_claim()
        self.fake.foreign_fragment_after_reload = (
            "/usr/lib/systemd/system/" + self.relay.unit_name
        )
        with self.assertRaisesRegex(mod.Refusal, "same-name systemd"):
            self.operator.retire()
        self.assertTrue(self.layout.evidence(self.relay, ".managed.json").exists())
        self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())
        self.assertEqual(1, sum(1 for x in self.fake.calls if x[:2] == ["systemctl", "daemon-reload"]))
        # A later operator can remove the unrelated unit separately and retry
        # the same scoped cleanup without losing the ownership claim.
        self.fake.foreign_fragment = None
        self.fake.foreign_fragment_after_reload = None
        self.assertIn("RETIREMENT VERIFIED", self.operator.retire())

    def test_legacy_v1_claim_is_not_silently_adopted_for_privileged_cleanup(self):
        self.layout.evidence(self.relay, ".managed.json").write_text(json.dumps({
            "version": 1,
            "relay_record_id": self.relay.record_id,
            "relay_id": self.relay.relay_id,
            "service_unit": self.relay.unit_name,
            "firewall_table": self.relay.firewall_table,
            "local_socks_port": self.relay.local_port,
        }))
        with self.assertRaisesRegex(mod.Refusal, "ownership does not match"):
            self.operator.retire()
        self.assertTrue(self.layout.evidence(self.relay, ".managed.json").exists())
        self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())

    def test_cleanup_refuses_claim_with_wrong_record_and_preserves_state(self):
        self.layout.evidence(self.relay, ".managed.json").write_text(json.dumps({
            "version": 1, "relay_record_id": "01JAE000000000000000000002",
            "relay_id": self.relay.relay_id, "service_unit": self.relay.unit_name,
            "firewall_table": self.relay.firewall_table,
            "local_socks_port": self.relay.local_port,
        }))
        with self.assertRaisesRegex(mod.Refusal, "ownership does not match"):
            self.operator.retire()
        self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())

    def test_cleanup_refuses_listener_or_unmanaged_firewall_and_never_mints_receipt(self):
        self.fake.listener = True
        with self.assertRaisesRegex(mod.Refusal, "still active"):
            self.operator.retire()
        self.fake.listener = False
        self.fake.nft = True
        with self.assertRaisesRegex(mod.Refusal, "without a root-owned matching claim"):
            self.operator.retire()
        self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())

    def test_cleanup_refuses_invalid_owned_unit_or_symlink_and_preserves_files(self):
        keydir = self.layout.key_dir(self.relay)
        keydir.mkdir(mode=0o700)
        outside = self.root / "do-not-touch"
        outside.write_text("keep\n")
        (keydir / "control_key").symlink_to(outside)
        self.write_managed_claim()
        with self.assertRaisesRegex(mod.Refusal, "Unsafe ownership/permissions|Unsafe non-file"):
            self.operator.retire()
        self.assertEqual("keep\n", outside.read_text())

    def test_foreign_loaded_same_name_service_refused_before_stop(self):
        unit = self.layout.unit(self.relay)
        unit.write_text("# MCP-GATEWAY-CONNECTION-RELAY " + self.relay.record_id +
                        " " + self.relay.relay_id + "\n[Unit]\nDescription=owned\n")
        self.write_managed_claim()
        self.fake.active = True
        self.fake.foreign_fragment = "/lib/systemd/system/" + self.relay.unit_name
        with self.assertRaisesRegex(mod.Refusal, "foreign FragmentPath"):
            self.operator.retire()
        self.assertFalse(any(x[:2] == ["systemctl", "disable"] for x in self.fake.calls))
        self.assertTrue(unit.exists())
        self.assertTrue(self.layout.evidence(self.relay, ".managed.json").exists())

    def test_foreign_systemd_dropin_refused_before_disabling_owned_unit(self):
        unit = self.layout.unit(self.relay)
        unit.write_text("# MCP-GATEWAY-CONNECTION-RELAY " + self.relay.record_id +
                        " " + self.relay.relay_id + "\n[Unit]\nDescription=owned\n")
        self.write_managed_claim()
        self.fake.foreign_dropin = True
        with self.assertRaisesRegex(mod.Refusal, "drop-in"):
            self.operator.retire()
        self.assertFalse(any(x[:2] == ["systemctl", "disable"] for x in self.fake.calls))

    def test_foreign_same_name_unit_with_missing_owned_file_refused_before_stop(self):
        # Exact R2 scenario: root-owned claim survived, expected file was
        # removed, but another loaded unit uses the identical service name.
        self.write_managed_claim()
        self.fake.active = True
        self.fake.foreign_fragment = "/lib/systemd/system/" + self.relay.unit_name
        with self.assertRaisesRegex(mod.Refusal, "foreign FragmentPath"):
            self.operator.retire()
        self.assertFalse(any(x[:2] == ["systemctl", "disable"] for x in self.fake.calls))
        self.assertTrue(self.layout.evidence(self.relay, ".managed.json").exists())

    def test_nft_policy_changed_between_preflight_and_delete_is_not_removed(self):
        self.fake.nft = True
        self.write_managed_claim()
        self.fake.nft_policy_reads = 0
        self.fake.mutate_policy_on_read = 2
        with self.assertRaisesRegex(mod.Refusal, "modified rules"):
            self.operator.retire()
        self.assertTrue(self.fake.nft)
        self.assertFalse(any(x[:3] == ["nft", "delete", "table"] for x in self.fake.calls))
        self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())

    def test_unexpected_nftables_rule_refused_without_firewall_removal_or_systemd_stop(self):
        self.fake.nft = True
        self.write_managed_claim()
        self.fake.unknown_nft_rule = True
        with self.assertRaisesRegex(mod.Refusal, "modified rules"):
            self.operator.retire()
        self.assertFalse(any(x[:3] == ["nft", "delete", "table"] for x in self.fake.calls))
        self.assertFalse(any(x[:2] == ["systemctl", "disable"] for x in self.fake.calls))
        self.assertTrue(self.fake.nft)
        self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())

    def test_deletion_fence_blocks_setup_exactly_after_receipt_verification_before_db_commit(self):
        # Deterministic interleaving: Gateway reads the root-owned proof and
        # fence, then a stale Owner command attempts new Setup BEFORE DB COMMIT.
        self.operator.retire()
        with self.assertRaisesRegex(mod.Refusal, "Missing expected root-owned host record"):
            self.operator._json(self.layout.fence(self.relay))
        self.assertIn("LIFECYCLE FENCE VERIFIED", self.operator.seal("delete"))
        fence = json.loads(self.layout.fence(self.relay).read_text())
        generation = self.operator._generation()
        receipt = json.loads(self.layout.evidence(self.relay, ".retired.json").read_text())
        self.assertEqual("delete", fence["intent"])
        self.assertEqual(generation["host_generation"], fence["host_generation"])
        self.assertEqual(receipt["host_generation"], fence["host_generation"])
        # PHP verifiedForDeletion returns TRUE here. Simulate host Setup on
        # this exact worker boundary and assert it cannot rotate generation.
        with self.assertRaisesRegex(mod.Refusal, "permanently fenced"):
            self.operator.prepare_setup()
        self.assertEqual(generation, self.operator._generation())
        with self.assertRaisesRegex(mod.Refusal, "permanently fenced"):
            self.operator.retire()
        # DB COMMIT would remove the row now. The same stale command is STILL
        # denied; the fence lives on the host and does not rely on the DB row.
        self.assertTrue(self.layout.fence(self.relay).exists())
        with self.assertRaisesRegex(mod.Refusal, "permanently fenced"):
            self.operator.prepare_setup()
        # An expired proof is renewable without lifting the permanent fence.
        # Simulate a later Owner retry; it still cannot enable stale Setup.
        original_expiry = receipt["expires_at_unix"]
        with mock.patch.object(mod.time, "time", return_value=original_expiry + 90):
            self.assertIn("LIFECYCLE FENCE VERIFIED", self.operator.seal("delete"))
        renewed = json.loads(self.layout.evidence(self.relay, ".retired.json").read_text())
        self.assertGreater(renewed["expires_at_unix"], original_expiry)
        self.assertEqual(generation, self.operator._generation())
        self.assertEqual(0o644, self.layout.fence(self.relay).stat().st_mode & 0o777)
        self.assertEqual(0o755, self.layout.fence(self.relay).parent.stat().st_mode & 0o777)
        # /run is ephemeral across reboots; a fresh lock must still honor the
        # durable /etc per-record tombstone.
        self.layout.lock_path(self.relay).unlink()
        with self.assertRaisesRegex(mod.Refusal, "permanently fenced"):
            mod.Retirement(self.relay, self.layout, self.fake).prepare_setup()

    def test_prepare_setup_winning_root_lock_invalidates_receipt_before_seal(self):
        import fcntl

        self.operator.retire()
        lock = self.layout.lock_path(self.relay)
        with lock.open("rb") as already_held:
            fcntl.flock(already_held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(mod.Refusal, "Another operator"):
                self.operator.seal("delete")
        self.assertFalse(self.layout.fence(self.relay).exists())
        self.operator.prepare_setup()
        with self.assertRaisesRegex(mod.Refusal, "retirement generation is missing"):
            self.operator.seal("delete")
        self.assertFalse(self.layout.fence(self.relay).exists())
        self.assertEqual("provisioning", self.operator._generation()["state"])

    def test_rotation_fence_blocks_old_revision_and_allows_only_new_revision(self):
        self.operator.retire()
        original = self.operator._generation()
        self.assertIn("LIFECYCLE FENCE VERIFIED", self.operator.seal("rotate"))
        with self.assertRaisesRegex(mod.Refusal, "permanently fenced"):
            self.operator.prepare_setup()
        with self.assertRaisesRegex(mod.Refusal, "permanently fenced"):
            self.operator.retire()
        updated = mod.Relay(self.relay.relay_id, self.relay.record_id, "e" * 64,
                            self.relay.revision + 1, self.relay.local_port)
        new_operator = mod.Retirement(updated, self.layout, self.fake)
        self.assertIn("PROOF INVALIDATED", new_operator.prepare_setup())
        self.assertEqual("provisioning", new_operator._generation()["state"])
        self.assertNotEqual(original["host_generation"], new_operator._generation()["host_generation"])
        with self.assertRaisesRegex(mod.Refusal, "permanently fenced"):
            self.operator.prepare_setup()
        self.assertEqual("rotate", json.loads(self.layout.fence(self.relay).read_text())["intent"])

    def test_delete_seal_is_irreversible_and_cannot_be_switched_to_rotation(self):
        self.operator.retire()
        self.operator.seal("delete")
        with self.assertRaisesRegex(mod.Refusal, "Conflicting or stale"):
            self.operator.seal("rotate")
        changed = mod.Relay(self.relay.relay_id, self.relay.record_id,
                            "e" * 64, self.relay.revision + 1, self.relay.local_port)
        with self.assertRaisesRegex(mod.Refusal, "permanently fenced"):
            mod.Retirement(changed, self.layout, self.fake).prepare_setup()
        self.assertEqual("delete", json.loads(self.layout.fence(self.relay).read_text())["intent"])

    def test_seal_refuses_live_owned_resources_and_untrusted_fence_path(self):
        self.write_managed_claim()
        with self.assertRaisesRegex(mod.Refusal, "managed host claim"):
            self.operator.seal("delete")
        self.assertFalse(self.layout.fence(self.relay).exists())
        self.fake.nft = False
        self.layout.evidence(self.relay, ".managed.json").unlink()
        self.operator.retire()
        fence = self.layout.fence(self.relay)
        fence.parent.mkdir()
        elsewhere = self.root / "unrelated.txt"
        elsewhere.write_text("PRESERVE")
        fence.symlink_to(elsewhere)
        with self.assertRaisesRegex(mod.Refusal, "Unsafe ownership/permissions|Unsafe non-file path"):
            self.operator.seal("delete")
        self.assertEqual("PRESERVE", elsewhere.read_text())

    def test_valid_retired_generation_invalidated_before_new_setup_and_refreshed(self):
        self.operator.retire()
        old_receipt = json.loads(self.layout.evidence(self.relay, ".retired.json").read_text())
        self.assertEqual("retired", self.operator._generation()["state"])
        result = self.operator.prepare_setup()
        self.assertIn("PROOF INVALIDATED", result)
        self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())
        fresh = self.operator._generation()
        self.assertEqual("provisioning", fresh["state"])
        self.assertNotEqual(old_receipt["host_generation"], fresh["host_generation"])
        self.assertIn("RETIREMENT VERIFIED", self.operator.retire())
        current = json.loads(self.layout.evidence(self.relay, ".retired.json").read_text())
        self.assertNotEqual(old_receipt["host_generation"], current["host_generation"])
        self.assertEqual(current["host_generation"], self.operator._generation()["host_generation"])

    def test_begin_setup_refuses_active_claim_without_rotating_or_deleting(self):
        self.write_managed_claim()
        before = self.operator._generation()
        with self.assertRaisesRegex(mod.Refusal, "Managed Relay claim exists"):
            self.operator.prepare_setup()
        self.assertEqual(before, self.operator._generation())
        self.assertTrue(self.layout.evidence(self.relay, ".managed.json").exists())

    def test_unowned_or_modified_unit_definition_is_never_disabled(self):
        unit = self.layout.unit(self.relay)
        unit.write_text("# MCP-GATEWAY-CONNECTION-RELAY " + self.relay.record_id +
                        " " + self.relay.relay_id + "\n[Unit]\nDescription=owned\n")
        self.write_managed_claim()
        unit.write_text(unit.read_text()+"ExecStart=unexpected\n")
        with self.assertRaisesRegex(mod.Refusal, "immutable definition"):
            self.operator.retire()
        self.assertFalse(any(x[:2] == ["systemctl", "disable"] for x in self.fake.calls))

    def test_runtime_execstart_pid_and_time_changes_do_not_reject_owned_service(self):
        unit = self.layout.unit(self.relay)
        unit.write_text("# MCP-GATEWAY-CONNECTION-RELAY " + self.relay.record_id +
                        " " + self.relay.relay_id + "\n[Unit]\nDescription=owned\n")
        self.write_managed_claim()
        self.fake.active = self.fake.nft = True
        self.fake.exec_start = self.fake.exec_start.replace(
            "start_time=[n/a]", "start_time=[Tue 2026-11-03 11:00:00 UTC]"
        ).replace("pid=0", "pid=1979").replace("status=0/0", "status=1/FAILURE")
        self.assertIn("RETIREMENT VERIFIED", self.operator.retire())

    def test_loaded_unit_with_foreign_execstart_is_never_disabled(self):
        unit = self.layout.unit(self.relay)
        unit.write_text("# MCP-GATEWAY-CONNECTION-RELAY " + self.relay.record_id +
                        " " + self.relay.relay_id + "\n[Unit]\nDescription=owned\n")
        self.write_managed_claim()
        self.fake.foreign_exec = True
        with self.assertRaisesRegex(mod.Refusal, "loaded systemd definition"):
            self.operator.retire()
        self.assertFalse(any(x[:2] == ["systemctl", "disable"] for x in self.fake.calls))

    def test_failed_systemd_reload_recovers_when_unit_was_already_removed(self):
        unit = self.layout.unit(self.relay)
        unit.write_text("# MCP-GATEWAY-CONNECTION-RELAY " + self.relay.record_id +
                        " " + self.relay.relay_id + "\n[Unit]\nDescription=owned\n")
        self.write_managed_claim()
        self.fake.fail_daemon_reload = True
        with self.assertRaisesRegex(mod.Refusal, "daemon-reload failed"):
            self.operator.retire()
        self.assertFalse(unit.exists(), "Partial cleanup must be explicitly recoverable.")
        self.assertTrue(self.layout.evidence(self.relay, ".managed.json").exists())
        self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())
        self.fake.fail_daemon_reload = False
        self.assertIn("RETIREMENT VERIFIED", self.operator.retire())
        self.assertGreaterEqual(
            sum(1 for x in self.fake.calls if x[:2] == ["systemctl", "daemon-reload"]), 2
        )

    def test_systemd_failure_keeps_claim_and_allows_safe_retry(self):
        self.fake.active = True
        self.fake.fail_stop = True
        self.layout.unit(self.relay).write_text(
            "# MCP-GATEWAY-CONNECTION-RELAY " + self.relay.record_id +
            " " + self.relay.relay_id + "\n[Unit]\nDescription=owned\n"
        )
        self.write_managed_claim()
        with self.assertRaisesRegex(mod.Refusal, "Could not stop"):
            self.operator.retire()
        self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())
        self.fake.fail_stop = False
        self.assertIn("RETIREMENT VERIFIED", self.operator.retire())

    def test_disable_retires_exact_previous_owned_host_then_seals_current_revision(self):
        # DB Disable fences revision N by advancing to N+1. The installed
        # v2 claim remains N until root-only local retirement is verified.
        unit = self.layout.unit(self.relay)
        unit.write_text("# MCP-GATEWAY-CONNECTION-RELAY " + self.relay.record_id +
                        " " + self.relay.relay_id + "\n[Unit]\nDescription=owned\n")
        self.write_managed_claim()
        self.fake.active = self.fake.nft = self.fake.enabled = self.fake.listener = True
        unrelated = self.root / "var/lib/unrelated-relay-key"
        unrelated.parent.mkdir(parents=True, exist_ok=True)
        unrelated.write_text("DO NOT TOUCH")
        current = mod.Relay(self.relay.relay_id, self.relay.record_id,
                            "e" * 64, self.relay.revision + 1, self.relay.local_port)
        operation = mod.Retirement(current, self.layout, self.fake,
                                   prior_fingerprint=self.relay.fingerprint)
        self.assertIn("verified installed revision " + str(self.relay.revision), operation.preview())
        self.assertIn("RETIREMENT VERIFIED", operation.retire())
        receipt = operation._json(self.layout.evidence(current, ".retired.json"))
        self.assertEqual(current.revision, receipt["configuration_revision"])
        self.assertEqual(current.fingerprint, receipt["host_fingerprint"])
        self.assertFalse(self.layout.evidence(current, ".managed.json").exists())
        self.assertEqual("DO NOT TOUCH", unrelated.read_text())
        # Seal is a distinct CLI invocation and never receives old identity.
        seal = mod.Retirement(current, self.layout, self.fake)
        self.assertIn("LIFECYCLE FENCE VERIFIED", seal.seal("delete"))
        fence = seal._fence()
        self.assertEqual(current.revision, fence["configuration_revision"])
        self.assertEqual(current.fingerprint, fence["host_fingerprint"])
        with self.assertRaisesRegex(mod.Refusal, "permanently fenced"):
            seal.prepare_setup()
        with self.assertRaisesRegex(mod.Refusal, "permanently fenced"):
            self.operator.prepare_setup()
        self.assertIn("LIFECYCLE FENCE VERIFIED", seal.seal("delete"))
        self.assertEqual("DO NOT TOUCH", unrelated.read_text())

    def test_previous_owned_host_cannot_be_retired_by_unrelated_fingerprint_or_stale_revision(self):
        self.write_managed_claim()
        self.fake.nft = True
        current = mod.Relay(self.relay.relay_id, self.relay.record_id,
                            "e" * 64, self.relay.revision + 1, self.relay.local_port)
        for previous in (None, "d" * 64):
            operation = mod.Retirement(current, self.layout, self.fake,
                                       prior_fingerprint=previous)
            with self.assertRaisesRegex(mod.Refusal, "revision/fingerprint"):
                operation.retire()
            self.assertTrue(self.layout.evidence(self.relay, ".managed.json").exists())
            self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())
        stale = mod.Relay(self.relay.relay_id, self.relay.record_id,
                          "a" * 64, self.relay.revision + 2, self.relay.local_port)
        with self.assertRaisesRegex(mod.Refusal, "revision/fingerprint"):
            mod.Retirement(stale, self.layout, self.fake,
                           prior_fingerprint=self.relay.fingerprint).retire()
        with self.assertRaisesRegex(mod.Refusal, "Invalid prior host identity"):
            mod.Retirement(self.relay, self.layout, self.fake, prior_fingerprint="x" * 64)
        with self.assertRaisesRegex(mod.Refusal, "permitted only during retirement"):
            mod.Retirement(current, self.layout, self.fake,
                           prior_fingerprint=self.relay.fingerprint).seal("delete")
        with self.assertRaisesRegex(mod.Refusal, "permitted only during retirement"):
            mod.Retirement(current, self.layout, self.fake,
                           prior_fingerprint=self.relay.fingerprint).prepare_setup()

    def test_previous_owned_host_retirement_recovers_after_interrupted_cleanup_and_rotate(self):
        unit = self.layout.unit(self.relay)
        unit.write_text("# MCP-GATEWAY-CONNECTION-RELAY " + self.relay.record_id +
                        " " + self.relay.relay_id + "\n[Unit]\nDescription=owned\n")
        self.write_managed_claim()
        self.fake.active = self.fake.nft = True
        current = mod.Relay(self.relay.relay_id, self.relay.record_id,
                            "e" * 64, self.relay.revision + 1, self.relay.local_port)
        operation = mod.Retirement(current, self.layout, self.fake,
                                   prior_fingerprint=self.relay.fingerprint)
        self.fake.fail_daemon_reload = True
        with self.assertRaisesRegex(mod.Refusal, "daemon-reload failed"):
            operation.retire()
        self.assertTrue(self.layout.evidence(current, ".managed.json").exists())
        self.assertFalse(self.layout.evidence(current, ".retired.json").exists())
        self.fake.fail_daemon_reload = False
        self.assertIn("RETIREMENT VERIFIED", operation.retire())
        sealed = mod.Retirement(current, self.layout, self.fake)
        self.assertIn("LIFECYCLE FENCE VERIFIED", sealed.seal("rotate"))
        with self.assertRaisesRegex(mod.Refusal, "permanently fenced"):
            sealed.prepare_setup()
        next_rev = mod.Relay(current.relay_id, current.record_id, "a" * 64,
                             current.revision + 1, current.local_port)
        self.assertIn("PROOF INVALIDATED", mod.Retirement(next_rev, self.layout, self.fake).prepare_setup())

    def test_invalid_operator_arguments_refuse_before_host_commands(self):
        for invalid in [
            mod.Relay("bad;whoami", self.relay.record_id, "f"*64, 2, 46081),
            mod.Relay("iran-1", "invalid", "f"*64, 2, 46081),
            mod.Relay("iran-1", self.relay.record_id, "x"*64, 2, 46081),
            mod.Relay("iran-1", self.relay.record_id, "f"*64, 0, 46081),
            mod.Relay("iran-1", self.relay.record_id, "f"*64, 2, 22),
        ]:
            with self.assertRaises(mod.Refusal):
                mod.Retirement(invalid, self.layout, self.fake)
        self.assertEqual([], self.fake.calls)


class FixedRootToolPathTests(unittest.TestCase):
    def test_local_system_tool_commands_never_use_owner_inherited_path(self):
        fake = subprocess.CompletedProcess(["nft", "-j", "list", "tables"], 0, "{}", "")
        with mock.patch.object(mod.subprocess, "run", return_value=fake) as run:
            mod.run_checked(["nft", "-j", "list", "tables"])
        options = run.call_args.kwargs
        self.assertEqual(
            {"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"},
            options["env"],
        )
        self.assertFalse(options["check"])


class PinnedInterpreterTests(unittest.TestCase):
    def test_privileged_helper_does_not_run_python_from_attacker_path(self):
        self.assertEqual("#!/usr/bin/python3", source.read_text().splitlines()[0])
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)
            executable = root / "relay-test"
            executable.write_bytes(source.read_bytes())
            executable.chmod(0o755)
            fake = root / "python3"
            marker = root / "executed-untrusted-python"
            fake.write_text("#!/bin/sh\necho bad > "+shlex.quote(str(marker))+"\nexit 4\n")
            fake.chmod(0o755)
            result = subprocess.run([str(executable), "--help"], capture_output=True,
                                    text=True, timeout=5,
                                    env={"PATH": str(root)+":/usr/bin:/usr/sbin"})
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertFalse(marker.exists())


class BootstrapShellTests(unittest.TestCase):
    """Exercise the real PHP nowdoc Bash body with only test paths/UID."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.sbin = self.root / "sbin"
        self.sbin.mkdir(mode=0o700)
        self.source = self.root / "source.py"
        self.source.write_bytes(source.read_bytes())
        self.target = self.sbin / "mcp-gateway-relay"
        self.hash = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.previous_bytes = b"exact previously issued trusted fixture helper\n"
        self.previous = hashlib.sha256(self.previous_bytes).hexdigest()

    def script(self, upgrade: bool = False) -> str:
        php = (source.parents[2] / "app/Infrastructure/Connectors/Relay/"
               "ConnectionRelayHostOperatorPlan.php").read_text()
        m = re.search(r"\$bootstrapScript = <<<'BASH'\n(.*?)\nBASH;", php, re.S)
        assert m is not None
        body = m.group(1)
        lock = self.sbin / ".helper-install.lock"
        replacements = {
            "source=__SOURCE__": "source=" + shlex.quote(str(self.source)),
            "expected=__SHA__": "expected=" + shlex.quote(self.hash),
            "previous=__PREVIOUS__": "previous=" + shlex.quote(self.previous),
            "mode=__MODE__": "mode=" + ("upgrade" if upgrade else "install"),
            "destination=/usr/local/sbin/mcp-gateway-relay":
                "destination=" + shlex.quote(str(self.target)),
            "for parent in / /usr /usr/local /usr/local/sbin; do":
                "for parent in " + shlex.quote(str(self.sbin)) + "; do",
            'test "$(stat -c %u "$parent")" = 0':
                'test "$(stat -c %u "$parent")" = ' + str(os.geteuid()),
            'install -o root -g root -m 0755':
                'install -m 0755',
            'temp="$(mktemp /usr/local/sbin/.mcp-gateway-relay.XXXXXXXX)"':
                'temp="$(mktemp ' + shlex.quote(str(self.sbin / '.relay.XXXXXXXX')) + ')"',
            'test "$(stat -c %u "$destination")" = 0':
                'test "$(stat -c %u "$destination")" = ' + str(os.geteuid()),
            "lock=/run/mcp-gateway-relay-helper-install.lock":
                "lock=" + shlex.quote(str(lock)),
            "test -d /run && test ! -L /run &&":
                "test -d " + shlex.quote(str(self.sbin)) +
                " && test ! -L " + shlex.quote(str(self.sbin)) + " &&",
            'test "$(stat -c %u /run)" = 0':
                'test "$(stat -c %u ' + shlex.quote(str(self.sbin)) + ')" = ' + str(os.geteuid()),
            'test -z "$(find /run -maxdepth 0 -perm /022 -print)"':
                'test -z "$(find ' + shlex.quote(str(self.sbin)) + ' -maxdepth 0 -perm /022 -print)"',
            'test "$(stat -c %u "$lock")" = 0':
                'test "$(stat -c %u "$lock")" = ' + str(os.geteuid()),
        }
        for old, new in replacements.items():
            self.assertIn(old, body)
            body = body.replace(old, new)
        return body

    def run_bash(self, body: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["bash", "-c", body], capture_output=True,
                              text=True, timeout=5, check=False)

    def test_real_bootstrap_body_installs_verified_copy_then_is_idempotent(self):
        body = self.script()
        first = self.run_bash(body)
        self.assertEqual(0, first.returncode, first.stderr)
        self.assertEqual(self.source.read_bytes(), self.target.read_bytes())
        self.assertEqual(0o755, self.target.stat().st_mode & 0o777)
        before = self.target.stat().st_ino
        again = self.run_bash(body)
        self.assertEqual(0, again.returncode, again.stderr)
        self.assertEqual(before, self.target.stat().st_ino, "Do not replace an identical installed tool.")

    def test_tampered_source_cannot_publish_or_replace_a_root_tool(self):
        body = self.script()
        self.source.write_bytes(b"untrusted replacement\n")
        rejected = self.run_bash(body)
        self.assertNotEqual(0, rejected.returncode)
        self.assertFalse(self.target.exists())
        # A separately installed foreign file is retained and never replaced.
        self.target.write_bytes(b"foreign command\n")
        again = self.run_bash(body)
        self.assertNotEqual(0, again.returncode)
        self.assertEqual(b"foreign command\n", self.target.read_bytes())

    def test_existing_symlink_is_rejected_without_following_or_overwriting(self):
        body = self.script()
        outside = self.root / "foreign"
        outside.write_text("preserve")
        self.target.symlink_to(outside)
        rejected = self.run_bash(body)
        self.assertNotEqual(0, rejected.returncode)
        self.assertEqual("preserve", outside.read_text())
        self.assertTrue(self.target.is_symlink())

    def test_explicit_upgrade_requires_exact_known_predecessor_and_is_idempotent(self):
        self.target.write_bytes(self.previous_bytes)
        first_inode = self.target.stat().st_ino
        # Cleanup/bootstrap never upgrades an existing, even known tool.
        refused = self.run_bash(self.script())
        self.assertNotEqual(0, refused.returncode)
        self.assertEqual(self.previous_bytes, self.target.read_bytes())
        upgraded = self.run_bash(self.script(upgrade=True))
        self.assertEqual(0, upgraded.returncode, upgraded.stderr)
        self.assertEqual(self.source.read_bytes(), self.target.read_bytes())
        self.assertNotEqual(first_inode, self.target.stat().st_ino,
                            "Verified upgrade must publish a new inode atomically.")
        self.assertEqual(0o755, self.target.stat().st_mode & 0o777)
        self.assertEqual([], list(self.sbin.glob(".relay.*")))
        again_inode = self.target.stat().st_ino
        retry = self.run_bash(self.script(upgrade=True))
        self.assertEqual(0, retry.returncode, retry.stderr)
        self.assertEqual(again_inode, self.target.stat().st_ino,
                         "A current tool must not be rewritten on retry.")

    def test_upgrade_refuses_unknown_binary_and_preserves_siblings(self):
        self.target.write_bytes(b"untrusted third party root executable\n")
        sibling = self.sbin / "unrelated-daemon"
        sibling.write_text("preserve unrelated code\n")
        res = self.run_bash(self.script(upgrade=True))
        self.assertNotEqual(0, res.returncode)
        self.assertIn("Unknown or outdated installed host tool", res.stderr)
        self.assertEqual(b"untrusted third party root executable\n", self.target.read_bytes())
        self.assertEqual("preserve unrelated code\n", sibling.read_text())

    def test_upgrade_rejects_tampered_source_without_changing_known_old_tool(self):
        self.target.write_bytes(self.previous_bytes)
        self.source.write_bytes(b"tampered source instead of pinned release\n")
        res = self.run_bash(self.script(upgrade=True))
        self.assertNotEqual(0, res.returncode)
        self.assertIn("Copied helper SHA256 differs", res.stderr)
        self.assertEqual(self.previous_bytes, self.target.read_bytes())
        self.assertEqual([], list(self.sbin.glob(".relay.*")))

    def test_upgrade_absent_tool_fails_closed_without_installing(self):
        res = self.run_bash(self.script(upgrade=True))
        self.assertNotEqual(0, res.returncode)
        self.assertIn("No known predecessor to upgrade", res.stderr)
        self.assertFalse(self.target.exists())
        first = self.run_bash(self.script())
        self.assertEqual(0, first.returncode, first.stderr)
        self.assertEqual(self.source.read_bytes(), self.target.read_bytes())

    def test_upgrade_rejects_untrusted_installer_lock(self):
        self.target.write_bytes(self.previous_bytes)
        lock = self.sbin / ".helper-install.lock"
        outside = self.root / "outside"
        outside.write_text("preserve")
        lock.symlink_to(outside)
        res = self.run_bash(self.script(upgrade=True))
        self.assertNotEqual(0, res.returncode)
        self.assertIn("Untrusted installer lock", res.stderr)
        self.assertEqual(self.previous_bytes, self.target.read_bytes())
        self.assertEqual("preserve", outside.read_text())

    def test_concurrent_installer_lock_fails_without_replacing_helper(self):
        self.target.write_bytes(self.previous_bytes)
        lock = self.sbin / ".helper-install.lock"
        with subprocess.Popen(
            ["flock", "-x", str(lock), "bash", "-c", 'printf "LOCKED\n"; read -r release'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        ) as holder:
            try:
                assert holder.stdout is not None
                self.assertEqual("LOCKED", holder.stdout.readline().strip())
                # Test the exact failure branch without waiting the production
                # 15-second bound; the installed helper must remain unchanged.
                body = self.script(upgrade=True).replace(
                    "flock -x -w 15 9", "flock -n 9"
                )
                res = self.run_bash(body)
                self.assertNotEqual(0, res.returncode)
                self.assertIn("Another Relay helper installer is active", res.stderr)
                self.assertEqual(self.previous_bytes, self.target.read_bytes())
            finally:
                assert holder.stdin is not None
                holder.stdin.write("release\n")
                holder.stdin.flush()
                holder.wait(timeout=3)

    def test_upgrade_rejects_symlink_and_writable_parent(self):
        outside = self.root / "foreign"
        outside.write_text("preserve")
        self.target.symlink_to(outside)
        res = self.run_bash(self.script(upgrade=True))
        self.assertNotEqual(0, res.returncode)
        self.assertEqual("preserve", outside.read_text())
        self.target.unlink()
        self.target.write_bytes(self.previous_bytes)
        self.sbin.chmod(0o777)
        try:
            res = self.run_bash(self.script(upgrade=True))
            self.assertNotEqual(0, res.returncode)
            self.assertIn("Untrusted host tool directory", res.stderr)
            self.assertEqual(self.previous_bytes, self.target.read_bytes())
        finally:
            self.sbin.chmod(0o700)




if __name__ == "__main__":
    unittest.main()
