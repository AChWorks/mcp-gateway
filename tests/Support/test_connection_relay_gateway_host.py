"""Isolated privileged-helper tests: no real systemd, firewall or host files."""
from __future__ import annotations

import fcntl
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
import time
import unittest
from unittest import mock
from types import SimpleNamespace

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
        # A legacy managed claim without the Setup UID journal may retire
        # an empty, safely owned key namespace. Arbitrary legacy key bytes
        # have no independent digest and must instead be preserved.
        keys = self.layout.key_dir(self.relay)
        keys.mkdir(mode=0o700)
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
            "destination=__DESTINATION__":
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
        self.target.chmod(0o755)
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
        self.target.chmod(0o755)
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





class VerifiedOperatorInvocationTests(unittest.TestCase):
    """Run the PHP-generated privileged operation body against isolated tools."""

    def setUp(self):
        self.installer = BootstrapShellTests("runTest")
        self.installer.setUp()
        self.addCleanup(self.installer.doCleanups)
        self.old_bytes = b'#!/bin/sh\nprintf "OLD_VERIFIED\\n"\n'
        self.new_bytes = b'#!/bin/sh\nprintf "NEW_VERIFIED\\n"\n'
        self.installer.previous_bytes = self.old_bytes
        self.installer.previous = hashlib.sha256(self.old_bytes).hexdigest()
        self.installer.source.write_bytes(self.new_bytes)
        self.installer.hash = hashlib.sha256(self.new_bytes).hexdigest()
        self.installer.target.write_bytes(self.old_bytes)
        self.installer.target.chmod(0o755)
        self.lock = self.installer.sbin / ".helper-install.lock"

    def invocation(self, expected: str) -> str:
        php = (source.parents[2] / "app/Infrastructure/Connectors/Relay/"
               "ConnectionRelayHostOperatorPlan.php").read_text()
        match = re.search(r"\$verifiedScript = <<<'BASH'\n(.*?)\nBASH;", php, re.S)
        self.assertIsNotNone(match)
        body = match.group(1)
        directory = shlex.quote(str(self.installer.sbin))
        changes = {
            "expected=__SHA__": "expected=" + shlex.quote(expected),
            "destination=__DESTINATION__":
                "destination=" + shlex.quote(str(self.installer.target)),
            "lock=/run/mcp-gateway-relay-helper-install.lock":
                "lock=" + shlex.quote(str(self.lock)),
            "for parent in / /usr /usr/local /usr/local/sbin /run; do":
                "for parent in " + directory + "; do",
            'test "$(stat -c %u "$parent")" = 0':
                'test "$(stat -c %u "$parent")" = ' + str(os.geteuid()),
            'test "$(stat -c %u "$lock")" = 0':
                'test "$(stat -c %u "$lock")" = ' + str(os.geteuid()),
            'test "$(stat -c %u "$destination")" = 0':
                'test "$(stat -c %u "$destination")" = ' + str(os.geteuid()),
            '"$destination" __ACTION__': '"$destination" test-operation',
        }
        for before, after in changes.items():
            self.assertIn(before, body)
            body = body.replace(before, after)
        return body

    def run_script(self, body: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["bash", "-c", body], text=True,
                              capture_output=True, check=False, timeout=5)

    def test_upgrade_blocked_between_successful_digest_and_helper_execution(self):
        # Exact race: command has verified the OLD digest, but has not yet
        # invoked the OLD helper. An EXCLUSIVE installer must be blocked while
        # the command still holds its SHARED installer lock.
        marker = self.installer.root / "checked"
        release = self.installer.root / "continue"
        old_body = self.invocation(self.installer.previous)
        old_body = old_body.replace(
            '"$destination" test-operation',
            'printf "DIGEST_CHECKED" > ' + shlex.quote(str(marker)) + '\n'
            'while test ! -e ' + shlex.quote(str(release)) +
            '; do sleep 0.02; done\n'
            '"$destination" test-operation',
        )
        self.assertIn("DIGEST_CHECKED", old_body)
        runner = subprocess.Popen(["bash", "-c", old_body],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True)
        try:
            for _ in range(100):
                if marker.exists():
                    break
                if runner.poll() is not None:
                    break
                time.sleep(0.025)
            self.assertTrue(marker.exists(), "Failed to reach the after-digest/ before-exec barrier.")
            self.assertIsNone(runner.poll())
            # Test the exact wait/refusal branch without a 15-second sleep.
            upgrade = self.installer.script(upgrade=True).replace(
                "flock -x -w 15 9", "flock -n 9"
            )
            refused = self.run_script(upgrade)
            self.assertNotEqual(0, refused.returncode)
            self.assertIn("Another Relay helper installer is active", refused.stderr)
            self.assertEqual(self.old_bytes, self.installer.target.read_bytes())
        finally:
            release.touch()
            stdout, stderr = runner.communicate(timeout=3)
        self.assertEqual(0, runner.returncode, stderr)
        self.assertEqual("OLD_VERIFIED", stdout.strip())
        upgraded = self.run_script(self.installer.script(upgrade=True))
        self.assertEqual(0, upgraded.returncode, upgraded.stderr)
        self.assertEqual(self.new_bytes, self.installer.target.read_bytes())
        # A stale command cannot run the new file based on its former digest.
        stale = self.run_script(self.invocation(self.installer.previous))
        self.assertNotEqual(0, stale.returncode)
        self.assertNotIn("NEW_VERIFIED", stale.stdout)
        self.assertIn("differs from the pinned release", stale.stderr)
        fresh = self.run_script(self.invocation(self.installer.hash))
        self.assertEqual(0, fresh.returncode, fresh.stderr)
        self.assertEqual("NEW_VERIFIED", fresh.stdout.strip())

    def test_correct_digest_without_executable_mode_never_reports_success(self):
        self.installer.target.write_bytes(self.new_bytes)
        self.installer.target.chmod(0o644)
        attempt = self.run_script(self.invocation(self.installer.hash))
        self.assertNotEqual(0, attempt.returncode)
        self.assertIn("non-executable installed Gateway Relay helper", attempt.stderr)
        self.assertNotIn("NEW_VERIFIED", attempt.stdout)
        # A matching digest with wrong permissions must not be accepted by
        # ordinary bootstrap or idempotent Upgrade either.
        for upgrade in (False, True):
            command = self.installer.script(upgrade=upgrade)
            rejected = self.run_script(command)
            self.assertNotEqual(0, rejected.returncode)
            self.assertIn("invalid executable permissions", rejected.stderr)
            self.assertEqual(self.new_bytes, self.installer.target.read_bytes())

    def test_legacy_helper_with_wrong_executable_permissions_is_preserved(self):
        self.installer.target.chmod(0o644)
        rejected = self.run_script(self.installer.script(upgrade=True))
        self.assertNotEqual(0, rejected.returncode)
        self.assertIn("Previous helper has invalid executable permissions", rejected.stderr)
        self.assertEqual(self.old_bytes, self.installer.target.read_bytes())
        self.assertEqual(0o644, self.installer.target.stat().st_mode & 0o777)


if __name__ == "__main__":
    unittest.main()


class AuditHost(FakeHost):
    """Synthetic effective host evidence; never creates a real socket."""

    def __init__(self, relay: mod.Relay):
        super().__init__(relay)
        self.active = True
        self.enabled = True
        self.nft = True
        self.listener = True
        self.php_uid = 1010
        self.main_pid = 7654
        self.user = relay.ssh_user
        self.no_new_privileges = "yes"
        self.private_tmp = "yes"
        self.loopback_guard = True
        self.chain_hook = "output"
        self.chain_prio = -150
        self.extra_acl = None
        self.listening_address = "127.0.0.1"
        self.listener_pid = 7654
        self.extra_listeners: list[tuple[str, int]] = []
        self.control_host = "192.0.2.1"
        self.control_port = 22
        self.control_user = "relay-control"
        credentials = "/run/credentials/" + relay.unit_name
        self.ssh_arguments = [
            "/usr/bin/ssh", "-F", "/dev/null", "-N", "-T",
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", "ExitOnForwardFailure=yes",
            "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
            "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
            "-o", "ControlMaster=no", "-o", "ProxyCommand=none",
            "-o", "ProxyJump=none",
            "-o", "UserKnownHostsFile=" + credentials + "/known_hosts",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3",
            "-o", "ConnectTimeout=10",
            "-i", credentials + "/control_key",
            "-D", "127.0.0.1:" + str(relay.local_port),
            "-p", str(self.control_port), "-l", self.control_user, self.control_host,
        ]
        self.refresh_exec_start()

    def refresh_exec_start(self):
        self.exec_start = (
            "{ path=/usr/bin/ssh ; argv[]=" + " ".join(self.ssh_arguments)
            + " ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a]"
            + " ; pid=0 ; code=(null) ; status=0/0 }"
        )

    def nft_json(self) -> dict:
        items = [
            {"metainfo": {"version": "1.0"}},
            {"table": {"family": "inet", "name": self.relay.firewall_table, "handle": 4}},
            {"chain": {"family": "inet", "table": self.relay.firewall_table,
                       "name": "output_guard", "handle": 5,
                       "type": "filter", "hook": self.chain_hook,
                       "prio": self.chain_prio, "policy": "accept"}},
            {"rule": {"family": "inet", "table": self.relay.firewall_table,
                      "chain": "output_guard", "handle": 6,
                      "expr": [
                          {"match": {"left": {"meta": {"key": "oifname"}},
                                     "op": "==", "right": "lo"}},
                          {"match": {"left": {"payload": {"protocol": "tcp", "field": "dport"}},
                                     "op": "==", "right": self.relay.local_port}},
                          {"match": {"left": {"meta": {"key": "skuid"}},
                                     "op": "!=" if self.loopback_guard else "==",
                                     "right": self.php_uid}},
                          {"reject": {"type": "icmpx", "expr": "admin-prohibited"}},
                      ]}},
        ]
        if self.extra_acl is not None:
            items.append({"rule": {"family": "inet", "table": self.relay.firewall_table,
                                   "chain": "output_guard", "handle": 7,
                                   "expr": self.extra_acl}})
        return {"nftables": items}

    def __call__(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        if argv[:2] == ["/usr/bin/ssh-keygen", "-y"]:
            self.calls.append(argv)
            return mod.run_checked(argv)
        if (argv[0] == "systemctl" and argv[1] == "show"
                and argv[3].startswith("--property=MainPID,")):
            self.calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, (
                f"MainPID={self.main_pid}\nUser={self.user}\n"
                f"NoNewPrivileges={self.no_new_privileges}\nPrivateTmp={self.private_tmp}\n"
            ), "")
        if argv == ["ss", "-H", "-lntp"]:
            self.calls.append(argv)
            listeners = []
            if self.listener:
                listeners.append((f"{self.listening_address}:{self.relay.local_port}",
                                  self.listener_pid))
            listeners.extend(self.extra_listeners)
            lines = [f'LISTEN 0 128 {address} 0.0.0.0:* '
                     + f'users:(("ssh",pid={pid},fd={i + 4}))'
                     for i, (address, pid) in enumerate(listeners)]
            return subprocess.CompletedProcess(argv, 0, "\n".join(lines) + "\n" if lines else "", "")
        return super().__call__(argv)


class GatewayPolicyAuditTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = pathlib.Path(tmp.name)
        self.relay = mod.Relay("iran-audit", "01JAE000000000000000000009", "e" * 64, 4, 46109)
        self.layout = mod.Layout(root, os.geteuid())
        for rel in ("etc/mcp-gateway/connection-relays", "etc/systemd/system",
                    "var/lib/mcp-gateway-relays", "run/mcp-gateway-relays"):
            path = root / rel
            path.mkdir(mode=0o755, parents=True, exist_ok=True)
        self.fake = AuditHost(self.relay)
        self.fake.unit_path = self.layout.unit(self.relay)
        self.op = mod.GatewayPolicyAudit(self.relay, self.layout, self.fake)
        self.layout.lock_path(self.relay).write_text("", encoding="ascii")
        keydir = self.layout.key_dir(self.relay)
        keydir.mkdir(mode=0o700)
        generated = subprocess.run(
            ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "",
             "-C", "", "-f", str(keydir / "control_key")],
            capture_output=True, text=True, check=True,
        )
        self.assertEqual("", generated.stderr)
        (keydir / "known_hosts").write_text("[192.0.2.1]:22 ssh-ed25519 synthetic-fixture")
        (keydir / "owner.json").write_text(json.dumps({
            "version": 2,
            "relay_record_id": self.relay.record_id, "relay_id": self.relay.relay_id,
            "ssh_user": self.relay.ssh_user, "ssh_uid": 1500, "gateway_php_uid": 1010,
            "control_host": self.fake.control_host, "control_port": self.fake.control_port,
            "control_user": self.fake.control_user,
            "control_key_sha256": hashlib.sha256((keydir / "control_key").read_bytes()).hexdigest(),
            "control_key_pub_sha256": hashlib.sha256((keydir / "control_key.pub").read_bytes()).hexdigest(),
            "known_hosts_sha256": hashlib.sha256((keydir / "known_hosts").read_bytes()).hexdigest(),
        }))
        (self.layout.at("/proc/7654")).mkdir(parents=True)
        (self.layout.at("/proc/7654/status")).write_text("Name:\tssh\nUid:\t1500\t1500\t1500\t1500\n")
        (self.layout.at("/proc/7654/exe")).symlink_to("/usr/bin/ssh")
        from types import SimpleNamespace
        principal = SimpleNamespace(
            pw_uid=1500, pw_name=self.relay.ssh_user, pw_shell="/usr/sbin/nologin",
            pw_gecos="",
        )
        self.nss = principal
        for name in ("getpwnam", "getpwuid", "getpwall"):
            patcher = mock.patch.object(
                mod.pwd, name,
                side_effect=(lambda *args, n=name: [self.nss] if n == "getpwall" else self.nss),
            )
            patcher.start()
            self.addCleanup(patcher.stop)
        self.layout.unit(self.relay).write_text(
            f"# MCP-GATEWAY-CONNECTION-RELAY {self.relay.record_id} {self.relay.relay_id}\n"
            "[Service]\nExecStart=/usr/bin/ssh -D 127.0.0.1:46109\n",
        )
        generation = self.op._advance_generation("provisioning")
        self.layout.evidence(self.relay, ".managed.json").write_text(json.dumps({
            "version": 2,
            "relay_record_id": self.relay.record_id,
            "relay_id": self.relay.relay_id,
            "service_unit": self.relay.unit_name,
            "firewall_table": self.relay.firewall_table,
            "local_socks_port": self.relay.local_port,
            "host_fingerprint": self.relay.fingerprint,
            "configuration_revision": self.relay.revision,
            "host_generation": generation,
            "unit_sha256": hashlib.sha256(self.layout.unit(self.relay).read_bytes()).hexdigest(),
            "unit_exec_sha256": hashlib.sha256(
                mod.Retirement._canonical_exec(self.fake.exec_start).encode(),
            ).hexdigest(),
            "firewall_sha256": self.op._nft_policy_digest(),
        }))

    def test_valid_local_host_checks_do_not_issue_false_ready_attestation(self):
        self.assertIn("GATEWAY LOCAL POLICY AUDIT PASS", self.op.audit(1010))
        self.assertFalse(self.layout.evidence(self.relay, ".json").exists())
        self.assertFalse(self.layout.evidence(self.relay, ".policy").exists())
        self.assertEqual([], [cmd for cmd in self.fake.calls if cmd[0] in ("ssh", "curl", "nft") and cmd[0:2] == ["nft", "add"]])

    def test_wrong_php_uid_or_unrestricted_acl_is_refused(self):
        with self.assertRaisesRegex(mod.Refusal, "key ownership record"):
            self.op.audit(1011)
        self.fake.loopback_guard = False
        self.op._write_json_atomic(self.layout.evidence(self.relay, ".managed.json"), {
            **self.op._manifest(),
            "firewall_sha256": self.op._nft_policy_digest(),
        })
        with self.assertRaisesRegex(mod.Refusal, "unrelated UIDs"):
            self.op.audit(1010)

    def test_ipv6_unsafe_input_chain_and_wrong_listener_both_fail(self):
        self.fake.chain_hook = "input"
        self.op._write_json_atomic(self.layout.evidence(self.relay, ".managed.json"), {
            **self.op._manifest(), "firewall_sha256": self.op._nft_policy_digest(),
        })
        with self.assertRaisesRegex(mod.Refusal, "base-chain hook"):
            self.op.audit(1010)
        self.fake.chain_hook = "output"
        self.fake.listening_address = "0.0.0.0"
        self.op._write_json_atomic(self.layout.evidence(self.relay, ".managed.json"), {
            **self.op._manifest(), "firewall_sha256": self.op._nft_policy_digest(),
        })
        with self.assertRaisesRegex(mod.Refusal, "unexpected, missing or non-loopback"):
            self.op.audit(1010)

    def test_unknown_identity_unowned_service_and_wrong_listener_pid_fail(self):
        self.fake.user = "www-data"
        with self.assertRaisesRegex(mod.Refusal, "restricted principal"):
            self.op.audit(1010)
        self.fake.user = self.relay.ssh_user
        self.fake.listener_pid = 9999
        with self.assertRaisesRegex(mod.Refusal, "systemd MainPID"):
            self.op.audit(1010)
        self.fake.listener_pid = 7654
        self.layout.unit(self.relay).write_text("OTHER UNIT")
        with self.assertRaisesRegex(mod.Refusal, "systemd unit"):
            self.op.audit(1010)

    def test_active_retirement_lock_blocks_audit(self):
        fd = os.open(self.layout.lock_path(self.relay), os.O_RDONLY)
        try:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(mod.Refusal, "maintenance is active"):
                self.op.audit(1010)
        finally:
            os.close(fd)

    def test_root_audit_refuses_hidden_process_privileges(self):
        self.layout.at("/proc/7654/status").write_text(
            "Name:\tssh\nUid:\t0\t1500\t0\t1500\n"
        )
        with self.assertRaisesRegex(mod.Refusal, "process does not match"):
            self.op.audit(1010)

    def test_owner_keys_fail_when_modified_without_claim_update(self):
        (self.layout.key_dir(self.relay) / "known_hosts").write_text("tampered host identity")
        with self.assertRaisesRegex(mod.Refusal, "key ownership record"):
            self.op.audit(1010)

    def test_unrecognized_credential_namespace_or_weak_private_mode_refuses(self):
        keydir = self.layout.key_dir(self.relay)
        (keydir / "unexpected").write_text("foreign secret")
        with self.assertRaisesRegex(mod.Refusal, "Unknown or unsafe Relay private file"):
            self.op.audit(1010)
        (keydir / "unexpected").unlink()
        (keydir / "control_key").chmod(0o644)
        with self.assertRaisesRegex(mod.Refusal, "private key"):
            self.op.audit(1010)

    def test_claimed_firewall_policy_drift_blocks_positive_audit(self):
        self.fake.loopback_guard = False
        with self.assertRaisesRegex(mod.Refusal, "unowned or modified rules"):
            self.op.audit(1010)

    def test_retired_generation_and_delete_fence_both_block_audit(self):
        self.op._advance_generation("retired")
        with self.assertRaisesRegex(mod.Refusal, "provisioning"):
            self.op.audit(1010)
        current = self.op._advance_generation("provisioning")
        self.op._write_json_atomic(self.layout.evidence(self.relay, ".managed.json"), {
            **self.op._json(self.layout.evidence(self.relay, ".managed.json")),
            "host_generation": current,
        })
        fence = self.layout.fence(self.relay)
        mod.make_privileged_directory(fence.parent, self.layout, php_traversable=True)
        self.op._write_json_atomic(fence, {
            "version": 1,
            "relay_record_id": self.relay.record_id,
            "relay_id": self.relay.relay_id,
            "host_fingerprint": self.relay.fingerprint,
            "configuration_revision": self.relay.revision,
            "host_generation": current,
            "intent": "delete",
        })
        with self.assertRaisesRegex(mod.Refusal, "fence"):
            self.op.audit(1010)

    def _sync_exec_claim(self) -> None:
        self.fake.refresh_exec_start()
        claim = self.op._json(self.layout.evidence(self.relay, ".managed.json"))
        claim["unit_exec_sha256"] = hashlib.sha256(
            mod.Retirement._canonical_exec(self.fake.exec_start).encode()
        ).hexdigest()
        self.op._write_json_atomic(self.layout.evidence(self.relay, ".managed.json"), claim)

    def _sync_nft_claim(self) -> None:
        claim = self.op._json(self.layout.evidence(self.relay, ".managed.json"))
        claim["firewall_sha256"] = self.op._nft_policy_digest()
        self.op._write_json_atomic(self.layout.evidence(self.relay, ".managed.json"), claim)

    def _sync_credential_claim(self) -> None:
        keydir = self.layout.key_dir(self.relay)
        owner = self.op._json(keydir / "owner.json")
        owner["control_key_sha256"] = hashlib.sha256((keydir / "control_key").read_bytes()).hexdigest()
        owner["control_key_pub_sha256"] = hashlib.sha256((keydir / "control_key.pub").read_bytes()).hexdigest()
        self.op._write_json_atomic(keydir / "owner.json", owner)

    def test_additional_public_or_private_listener_from_same_ssh_pid_is_refused(self):
        for address in ("0.0.0.0:48712", "[::]:48712", "127.0.0.1:48712", "[::1]:48712"):
            with self.subTest(address=address):
                self.fake.extra_listeners = [(address, self.fake.main_pid)]
                with self.assertRaisesRegex(mod.Refusal, "unexpected, missing or non-loopback"):
                    self.op.audit(1010)
        self.fake.extra_listeners = [("127.0.0.1:41000", 7999)]
        self.assertIn("AUDIT PASS", self.op.audit(1010))

    def test_extra_listener_same_reserved_port_but_foreign_pid_is_refused(self):
        self.fake.extra_listeners = [("127.0.0.1:46109", 8888)]
        with self.assertRaisesRegex(mod.Refusal, "uniquely to verified systemd MainPID"):
            self.op.audit(1010)

    def test_effective_ssh_arguments_must_match_exact_forwarding_contract(self):
        changes = [
            ("extra-dynamic-forward", ["-D", "0.0.0.0:48001"]),
            ("shell-request", ["-o", "PermitLocalCommand=yes"]),
            ("remote-reverse-forward", ["-R", "0.0.0.0:48002"]),
            ("proxy-override", ["-o", "ProxyCommand=/usr/bin/true"]),
        ]
        original = list(self.fake.ssh_arguments)
        for description, added in changes:
            with self.subTest(description=description):
                self.fake.ssh_arguments = original[:-1] + added + [original[-1]]
                self._sync_exec_claim()
                with self.assertRaisesRegex(mod.Refusal, "single-loopback forwarding contract"):
                    self.op.audit(1010)
        self.fake.ssh_arguments = original
        self._sync_exec_claim()
        self.assertIn("AUDIT PASS", self.op.audit(1010))

    def test_same_chain_reject_and_unrecognized_trailing_rules_fail_with_matching_digest(self):
        for trailing in (
            [{"match": {"left": {"meta": {"key": "skuid"}}, "op": "==",
                         "right": 1010}}, {"reject": {"type": "icmpx", "expr": "admin-prohibited"}}],
            [{"drop": None}],
            [{"return": None}],
            [{"jump": {"target": "other"}}],
            [{"accept": None}],
        ):
            with self.subTest(trailing=trailing):
                self.fake.extra_acl = trailing
                self._sync_nft_claim()
                with self.assertRaisesRegex(mod.Refusal, "unsupported trailing"):
                    self.op.audit(1010)
        self.fake.extra_acl = None
        self._sync_nft_claim()
        self.assertIn("AUDIT PASS", self.op.audit(1010))

    def test_nft_priority_drift_fails_even_with_matching_manifest_digest(self):
        self.fake.chain_prio = -5
        self._sync_nft_claim()
        with self.assertRaisesRegex(mod.Refusal, "base-chain hook"):
            self.op.audit(1010)

    def test_dedicated_principal_is_record_scoped_not_prefix_only(self):
        self.fake.user = "mcp-relay-foreign"
        owner_path = self.layout.key_dir(self.relay) / "owner.json"
        owner = self.op._json(owner_path)
        owner["ssh_user"] = self.fake.user
        self.op._write_json_atomic(owner_path, owner)
        with self.assertRaisesRegex(mod.Refusal, "key ownership record"):
            self.op.audit(1010)

    def test_sibling_relay_claim_cannot_reuse_ssh_uid(self):
        sibling = self.layout.key_dir(self.relay).parent / "unrelated"
        sibling.mkdir(mode=0o700)
        sibling_owner = sibling / "owner.json"
        sibling_record = "01JAE000000000000000000099"
        sibling_owner.write_text(json.dumps({
            "version": 2, "relay_record_id": sibling_record, "relay_id": sibling.name,
            "ssh_user": "mcp-relay-" + hashlib.sha256(sibling_record.encode()).hexdigest()[:20],
            "ssh_uid": 1500,
        }))
        with self.assertRaisesRegex(mod.Refusal, "reused by another Relay"):
            self.op.audit(1010)
        sibling_owner.unlink()
        with self.assertRaisesRegex(mod.Refusal, "lacks root-owned principal"):
            self.op.audit(1010)

    def test_sibling_with_distinct_principal_and_uid_remains_independent(self):
        sibling = self.layout.key_dir(self.relay).parent / "another-relay"
        sibling.mkdir(mode=0o700)
        sibling_record = "01JAE000000000000000000098"
        (sibling / "owner.json").write_text(json.dumps({
            "version": 2, "relay_record_id": sibling_record, "relay_id": sibling.name,
            "ssh_user": "mcp-relay-" + hashlib.sha256(sibling_record.encode()).hexdigest()[:20],
            "ssh_uid": 1600,
        }))
        self.assertIn("AUDIT PASS", self.op.audit(1010))

    def test_root_php_uid_and_login_shell_are_not_valid_ssh_service_identities(self):
        owner_path = self.layout.key_dir(self.relay) / "owner.json"
        owner = self.op._json(owner_path)
        for uid in (0, 1010):
            with self.subTest(uid=uid):
                owner["ssh_uid"] = uid
                self.op._write_json_atomic(owner_path, owner)
                with self.assertRaisesRegex(mod.Refusal, "key ownership record"):
                    self.op.audit(1010)
        owner["ssh_uid"] = 1500
        self.op._write_json_atomic(owner_path, owner)
        from types import SimpleNamespace
        self.nss = SimpleNamespace(
            pw_uid=1500, pw_name=self.relay.ssh_user, pw_shell="/bin/bash",
        )
        with self.assertRaisesRegex(mod.Refusal, "unsafe identity or login shell"):
            self.op.audit(1010)

    def test_nss_alias_for_same_uid_blocks_dedicated_identity(self):
        from types import SimpleNamespace
        original = self.nss
        self.nss = SimpleNamespace(pw_uid=1500, pw_name="foreign-alias",
                                   pw_shell="/usr/sbin/nologin")
        try:
            with self.assertRaisesRegex(mod.Refusal, "reused by another system account"):
                self.op.audit(1010)
        finally:
            self.nss = original

    def test_public_key_is_cryptographically_matched_not_only_digest_pinned(self):
        temp = self.layout.root / "other-identity"
        generated = subprocess.run(
            ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "",
             "-C", "", "-f", str(temp)],
            capture_output=True, text=True, check=True,
        )
        self.assertEqual("", generated.stderr)
        keydir = self.layout.key_dir(self.relay)
        original_pub = (keydir / "control_key.pub").read_bytes()
        original_key = (keydir / "control_key").read_bytes()
        (keydir / "control_key.pub").write_bytes((temp.parent / "other-identity.pub").read_bytes())
        self._sync_credential_claim()
        with self.assertRaisesRegex(mod.Refusal, "does not match the private"):
            self.op.audit(1010)
        (keydir / "control_key.pub").write_bytes(original_pub)
        (keydir / "control_key").write_bytes(temp.read_bytes())
        (keydir / "control_key").chmod(0o600)
        self._sync_credential_claim()
        with self.assertRaisesRegex(mod.Refusal, "does not match the private"):
            self.op.audit(1010)
        (keydir / "control_key").write_bytes(original_key)
        self._sync_credential_claim()
        self.assertIn("AUDIT PASS", self.op.audit(1010))

    def test_malformed_public_key_and_private_key_are_not_accepted(self):
        keydir = self.layout.key_dir(self.relay)
        (keydir / "control_key.pub").write_text("ssh-ed25519 not-base64")
        self._sync_credential_claim()
        with self.assertRaisesRegex(mod.Refusal, "Ed25519 key"):
            self.op.audit(1010)
        original_pub = subprocess.run(
            ["/usr/bin/ssh-keygen", "-y", "-P", "",
             "-f", str(keydir / "control_key")], capture_output=True,
            text=True, check=True,
        ).stdout
        keydir.joinpath("control_key.pub").write_text(" ".join(original_pub.split()[:2]) + "\n")
        keydir.joinpath("control_key").write_text("tampered private key")
        keydir.joinpath("control_key").chmod(0o600)
        self._sync_credential_claim()
        with self.assertRaises(mod.Refusal):
            self.op.audit(1010)

    def test_missing_install_claim_refuses_without_root_mutation(self):
        self.layout.evidence(self.relay, ".managed.json").unlink()
        with self.assertRaisesRegex(mod.Refusal, "claim"):
            self.op.audit(1010)


class StagedSetupHost(AuditHost):
    """Root-bound service/nft/useradd fixture with real disposable SSH keygen."""

    def __init__(self, relay: mod.Relay):
        super().__init__(relay)
        self.nft = False
        self.active = False
        self.enabled = False
        self.listener = False
        self.stopped = False
        self.user_created = False
        self.account_marker = ""
        self.nft_mutations = 0
        self.setup_fail_command = None

    def __call__(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        if argv[:2] == ["/usr/sbin/useradd", "--system"]:
            self.calls.append(argv)
            if self.setup_fail_command == "useradd":
                return subprocess.CompletedProcess(argv, 1, "", "simulated useradd failure")
            self.user_created = True
            self.account_marker = argv[argv.index("--comment") + 1]
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[:3] == ["/usr/bin/ssh-keygen", "-q", "-t"]:
            self.calls.append(argv)
            if self.setup_fail_command == "keygen":
                return subprocess.CompletedProcess(argv, 1, "", "simulated interrupted key generation")
            return mod.run_checked(argv)
        if argv[:2] == ["/usr/sbin/nft", "-f"]:
            self.calls.append(argv)
            assert pathlib.Path(argv[2]).is_file(), argv
            if self.setup_fail_command == "nft":
                return subprocess.CompletedProcess(argv, 1, "", "simulated nft load failure")
            self.nft = True
            self.nft_mutations += 1
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[:2] == ["/usr/sbin/userdel", self.relay.ssh_user]:
            self.calls.append(argv)
            self.user_created = False
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[:3] == ["systemctl", "enable", "--now"]:
            self.calls.append(argv)
            if self.setup_fail_command == "enable":
                return subprocess.CompletedProcess(argv, 1, "", "host unreachable; cannot connect yet")
            self.active = True
            self.enabled = True
            self.listener = True
            return subprocess.CompletedProcess(argv, 0, "", "")
        return super().__call__(argv)


class GatewayStagedSetupTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)
        self.hostkey = self.root / "server_ed25519"
        subprocess.run(
            ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "",
             "-C", "", "-f", str(self.hostkey)],
            capture_output=True, text=True, check=True,
        )
        self.pin = " ".join(self.hostkey.with_suffix(".pub").read_text().strip().split()[:2])
        self.endpoint = ("192.0.2.9", 2222, "relay-control")
        self.uid = 1010
        self.relay_id = "iran-stage"
        self.ulid = "01JAE000000000000000000077"
        self.port = 46177
        fp = hashlib.sha256("\0".join([
            self.relay_id, self.endpoint[0], str(self.endpoint[1]),
            self.endpoint[2], self.pin, str(self.port), "3",
        ]).encode()).hexdigest()
        self.relay = mod.Relay(self.relay_id, self.ulid, fp, 3, self.port)
        self.layout = mod.Layout(self.root, os.geteuid())
        for name in ("etc/mcp-gateway/connection-relays", "etc/systemd/system",
                     "var/lib/mcp-gateway-relays", "run/mcp-gateway-relays"):
            (self.root / name).mkdir(mode=0o755, parents=True, exist_ok=True)
        for rel in ("etc", "etc/mcp-gateway", "etc/mcp-gateway/connection-relays"):
            (self.root / rel).chmod(0o755)
        (self.root / "proc/sys/kernel/random").mkdir(parents=True)
        (self.root / "proc/sys/kernel/random/boot_id").write_text("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n")
        (self.root / "proc/uptime").write_text("3601.50 100.00\n")
        self.fake = StagedSetupHost(self.relay)
        self.fake.unit_path = self.layout.unit(self.relay)
        self.setup = self.make_setup()
        self.fake.ssh_arguments = self.setup._ssh_argv()
        self.fake.refresh_exec_start()
        self.principal = SimpleNamespace(
            pw_uid=1500, pw_name=self.relay.ssh_user, pw_shell="/usr/sbin/nologin",
        )
        def getpwnam(name):
            if self.fake.user_created and name == self.relay.ssh_user:
                self.principal.pw_gecos = self.fake.account_marker
                return self.principal
            raise KeyError(name)
        def getpwuid(uid):
            if self.fake.user_created and uid == self.principal.pw_uid:
                return self.principal
            raise KeyError(uid)
        for name, side_effect in (
            ("getpwnam", getpwnam), ("getpwuid", getpwuid),
            ("getpwall", lambda: [self.principal] if self.fake.user_created else []),
        ):
            patcher = mock.patch.object(mod.pwd, name, side_effect=side_effect)
            patcher.start()
            self.addCleanup(patcher.stop)
        # Real prepare-setup creates a root-owned lock and same generation.
        self.retirement = mod.Retirement(self.relay, self.layout, self.fake)
        self.retirement._advance_generation("provisioning")
        self.layout.lock_path(self.relay).write_text("")

    def make_setup(self, fingerprint=None, port=None, host_key=None):
        relay = (mod.Relay(self.relay_id, self.ulid, fingerprint, 3, self.port)
                 if fingerprint else self.relay)
        return mod.GatewaySetup(
            relay, self.endpoint[0], port or self.endpoint[1],
            self.endpoint[2], self.pin if host_key is None else host_key,
            self.uid, self.layout, self.fake,
        )

    def test_useradd_comment_is_valid_passwd_gecos_without_colon(self):
        self.setup.setup()
        account_create = next(x for x in self.fake.calls if x[:2] == ["/usr/sbin/useradd", "--system"])
        marker = account_create[account_create.index("--comment") + 1]
        self.assertTrue(marker.startswith("mcp-gateway-relay-"))
        self.assertNotIn(":", marker)
        self.assertNotIn("\\n", marker)
        self.assertEqual(self.fake.account_marker, marker)
        self.assertEqual(self.retirement._generation()["host_generation"], marker.split("-")[-1])

    def test_one_command_stages_new_registration_without_separate_prepare(self):
        generation = self.layout.evidence(self.relay, ".generation.json")
        generation.unlink()
        self.assertIn("NO READINESS ISSUED", self.setup.setup())
        self.assertTrue(self.setup.journal_path.exists())
        self.assertEqual("provisioning", self.retirement._generation()["state"])

    def test_open_ssh_known_hosts_matches_default_and_custom_control_ports(self):
        self.assertTrue(self.setup._expected_hostkey().startswith(b"[192.0.2.9]:2222 "))
        fp = hashlib.sha256("\0".join([
            self.relay_id, self.endpoint[0], "22",
            self.endpoint[2], self.pin, str(self.port), "3",
        ]).encode()).hexdigest()
        standard = mod.GatewaySetup(
            mod.Relay(self.relay_id, self.ulid, fp, 3, self.port),
            self.endpoint[0], 22, self.endpoint[2], self.pin,
            self.uid, self.layout, self.fake,
        )
        self.assertTrue(standard._expected_hostkey().startswith(b"192.0.2.9 "))
        self.assertNotIn(b"[192.0.2.9]:22 ", standard._expected_hostkey())
        file = self.root / "hostkeys-only"
        for result, query in ((standard, "192.0.2.9"), (self.setup, "[192.0.2.9]:2222")):
            file.write_bytes(result._expected_hostkey())
            found = subprocess.run(
                ["/usr/bin/ssh-keygen", "-F", query, "-f", str(file)],
                capture_output=True, text=True,
            )
            self.assertEqual(0, found.returncode, found.stderr)

    def test_generated_host_service_and_nft_scripts_are_scoped_and_stable(self):
        nft = self.setup._nft_source().decode()
        self.assertEqual(1, nft.count("add rule"))
        self.assertIn("meta skuid != 1010", nft)
        self.assertIn("flush table inet " + self.relay.firewall_table, nft)
        unit = self.setup._unit_source().decode()
        self.assertIn("User=" + self.relay.ssh_user, unit)
        self.assertIn("LoadCredential=control_key:/var/lib/mcp-gateway-relays/" + self.relay_id, unit)
        self.assertIn("ExecStartPre=+/usr/local/sbin/mcp-gateway-relay ensure-acl", unit)
        self.assertIn("-D 127.0.0.1:46177", unit)
        self.assertNotIn("0.0.0.0:46177", unit)
        self.assertNotIn("PermitLocalCommand=yes", unit)
        self.assertNotIn("PasswordAuthentication=yes", unit)

    def test_setup_creates_isolated_material_and_exact_claim_without_attesting(self):
        response = self.setup.setup()
        self.assertIn("NO READINESS ISSUED", response)
        self.assertTrue(self.fake.user_created)
        self.assertEqual(1, self.fake.nft_mutations)
        self.assertTrue(self.layout.unit(self.relay).exists())
        self.assertEqual(0o700, self.layout.key_dir(self.relay).stat().st_mode & 0o777)
        self.assertEqual(0o600, (self.layout.key_dir(self.relay) / "control_key").stat().st_mode & 0o777)
        self.assertEqual(0o644, self.setup.nft_path.stat().st_mode & 0o777)
        self.assertTrue(self.retirement._manifest())
        self.assertFalse(self.layout.evidence(self.relay, ".json").exists())
        self.assertFalse(self.layout.evidence(self.relay, ".policy").exists())
        self.assertEqual(self.pin, (self.layout.key_dir(self.relay) / "known_hosts").read_text().split(" ", 1)[1].strip())
        self.assertFalse(any(x[:3] == ["systemctl", "enable", "--now"] for x in self.fake.calls))
        self.assertFalse(self.fake.active)
        self.assertFalse(self.fake.enabled)


    def test_public_enrollment_exports_only_current_stage_public_key(self):
        self.setup.setup()
        before = len(self.fake.calls)
        result = mod.GatewayPolicyAudit(self.relay, self.layout, self.fake).public_enrollment()
        public = (self.layout.key_dir(self.relay) / "control_key.pub").read_text().strip()
        private = (self.layout.key_dir(self.relay) / "control_key").read_text()
        self.assertIn("PUBLIC ONLY", result)
        self.assertIn(public, result)
        self.assertIn(self.relay.record_id, result)
        self.assertIn("relay-control", result)
        self.assertIn("NOT ENROLLED", result)
        self.assertNotIn(private, result)
        self.assertNotIn("OPENSSH PRIVATE KEY", result)
        for argv in self.fake.calls[before:]:
            self.assertNotIn(argv[0], {"/usr/sbin/useradd", "/usr/sbin/userdel"})
            self.assertFalse(argv[:2] == ["systemctl", "daemon-reload"])
            self.assertFalse(argv[:2] == ["/usr/sbin/nft", "-f"])
        self.assertFalse(self.fake.active)
        self.assertFalse(self.fake.enabled)

    def test_public_enrollment_refuses_incomplete_stage_without_mutation(self):
        checker = mod.GatewayPolicyAudit(self.relay, self.layout, self.fake)
        with self.assertRaisesRegex(mod.Refusal, "staged Relay resource claim"):
            checker.public_enrollment()
        # Metadata/nft/systemd inventory reads are permitted; no host writes.
        for argv in self.fake.calls:
            self.assertNotIn(argv[0], {"/usr/sbin/useradd", "/usr/sbin/userdel"})
            self.assertFalse(argv[:2] == ["systemctl", "daemon-reload"])
        self.assertFalse(self.fake.user_created)
        self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())

    def test_public_enrollment_rejects_tampered_public_or_foreign_entries(self):
        self.setup.setup()
        keydir = self.layout.key_dir(self.relay)
        public = keydir / "control_key.pub"
        original = public.read_bytes()
        public.write_text("ssh-ed25519 AAAAFORGED")
        checker = mod.GatewayPolicyAudit(self.relay, self.layout, self.fake)
        with self.assertRaises(mod.Refusal):
            checker.public_enrollment()
        public.write_bytes(original)
        foreign = keydir / ".relay-setup-foreign"
        foreign.write_text("DO NOT DELETE")
        with self.assertRaisesRegex(mod.Refusal, "Unknown or unsafe Relay private file"):
            checker.public_enrollment()
        self.assertEqual("DO NOT DELETE", foreign.read_text())
        foreign.unlink()
        self.assertIn("PUBLIC ONLY", checker.public_enrollment())

    def test_public_enrollment_rejects_replaced_account_and_stale_fence(self):
        self.setup.setup()
        checker = mod.GatewayPolicyAudit(self.relay, self.layout, self.fake)
        self.principal.pw_uid = 1999
        with self.assertRaises(mod.Refusal):
            checker.public_enrollment()
        self.principal.pw_uid = 1500
        self.assertIn("PUBLIC ONLY", checker.public_enrollment())
        self.assertIn("RETIREMENT VERIFIED", self.retirement.retire())
        self.assertIn("LIFECYCLE FENCE VERIFIED", self.retirement.seal("delete"))
        with self.assertRaises(mod.Refusal):
            checker.public_enrollment()

    def test_public_enrollment_does_not_require_sibling_relay_setup_completion(self):
        self.setup.setup()
        sibling = self.layout.key_dir(self.relay).parent / "separately-staged"
        sibling.mkdir(mode=0o700)
        (sibling / "incomplete").write_text("SIBLING NOT YET PROVISIONED")
        result = mod.GatewayPolicyAudit(self.relay, self.layout, self.fake).public_enrollment()
        self.assertIn("PUBLIC ONLY", result)
        self.assertEqual("SIBLING NOT YET PROVISIONED", (sibling / "incomplete").read_text())
        self.assertTrue(self.fake.user_created)

    def test_public_enrollment_serializes_with_lifecycle_changes(self):
        self.setup.setup()
        checker = mod.GatewayPolicyAudit(self.relay, self.layout, self.fake)
        fd = os.open(self.layout.lock_path(self.relay), os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(mod.Refusal, "lifecycle maintenance"):
                checker.public_enrollment()
        finally:
            os.close(fd)
        self.assertIn("PUBLIC ONLY", checker.public_enrollment())

    def test_setup_retry_preserves_identity_key_and_owned_acl(self):
        self.setup.setup()
        key = (self.layout.key_dir(self.relay) / "control_key").read_bytes()
        self.assertIn("NO READINESS ISSUED", self.setup.setup())
        self.assertEqual(key, (self.layout.key_dir(self.relay) / "control_key").read_bytes())
        self.assertEqual(1, self.fake.nft_mutations)

    def test_interrupted_keygen_reuses_journal_without_new_generation(self):
        generation = self.retirement._generation()
        self.fake.setup_fail_command = "keygen"
        with self.assertRaisesRegex(mod.Refusal, "generate"):
            self.setup.setup()
        self.assertTrue(self.setup.journal_path.exists())
        self.assertTrue(self.fake.user_created)
        self.assertEqual(generation, self.retirement._generation())
        self.fake.setup_fail_command = None
        self.assertIn("NO READINESS ISSUED", self.setup.setup())
        self.assertEqual(1, self.fake.nft_mutations)

    def test_interrupted_claim_write_resumes_existing_owned_acl(self):
        original = self.setup._write_exact
        def fail_claim(path, content, mode):
            if path.name.endswith(".managed.json"):
                raise OSError("simulated interruption before committing claim")
            return original(path, content, mode)
        with mock.patch.object(self.setup, "_write_exact", side_effect=fail_claim):
            with self.assertRaisesRegex(OSError, "simulated interruption"):
                self.setup.setup()
        self.assertTrue(self.fake.nft)
        self.assertFalse(self.layout.evidence(self.relay, ".managed.json").exists())
        self.assertIn("NO READINESS ISSUED", self.setup.setup())
        self.assertEqual(1, self.fake.nft_mutations)

    def test_wrong_host_registration_fingerprint_and_mismatched_pin_fail_before_changes(self):
        with self.assertRaisesRegex(mod.Refusal, "fingerprint"):
            self.make_setup(fingerprint="b" * 64)
        with self.assertRaisesRegex(mod.Refusal, "fingerprint"):
            self.make_setup(port=22)
        with self.assertRaises(mod.Refusal):
            self.make_setup(host_key="ssh-ed25519 not-valid")
        self.assertFalse(self.setup.journal_path.exists())

    def test_reserved_port_owned_by_other_local_service_is_not_claimed(self):
        self.fake.listener = True
        with self.assertRaisesRegex(mod.Refusal, "Unjournaled Relay port/service"):
            self.setup.setup()
        self.assertFalse(self.fake.user_created)
        self.assertFalse(self.setup.journal_path.exists())

    def test_preexisting_foreign_loaded_systemd_unit_is_not_claimed(self):
        self.fake.foreign_fragment = "/etc/systemd/system/foreign-other.service"
        with self.assertRaisesRegex(mod.Refusal, "Foreign|foreign|FragmentPath"):
            self.setup.setup()
        self.assertFalse(self.fake.user_created)
        self.assertFalse(self.setup.journal_path.exists())

    def test_control_user_root_is_rejected_before_any_host_changes(self):
        with self.assertRaisesRegex(mod.Refusal, "non-root forwarding-only"):
            mod.GatewaySetup(self.relay, self.endpoint[0], self.endpoint[1],
                             "root", self.pin, self.uid, self.layout, self.fake)
        self.assertFalse(self.setup.journal_path.exists())

    def test_delete_fence_prevents_reprovisioning_after_verified_retirement(self):
        self.setup.setup()
        self.assertIn("RETIREMENT VERIFIED", self.retirement.retire())
        self.assertIn("LIFECYCLE FENCE VERIFIED", self.retirement.seal("delete"))
        with self.assertRaisesRegex(mod.Refusal, "permanently fenced"):
            self.setup.setup()
        self.assertFalse(self.fake.user_created)
        self.assertFalse(self.setup.nft_path.exists())

    def test_unrelated_preexisting_account_is_not_adopted(self):
        self.fake.user_created = True
        with self.assertRaisesRegex(mod.Refusal, "pre-existing SSH principal"):
            self.setup.setup()
        self.assertFalse(self.setup.journal_path.exists())

    def test_fence_or_lifecycle_lock_prevents_new_setup(self):
        lockpath = self.layout.lock_path(self.relay)
        fd = os.open(lockpath, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(mod.Refusal, "lifecycle lock"):
                self.setup.setup()
        finally:
            os.close(fd)
        self.assertFalse(self.setup.journal_path.exists())

    def test_setup_never_enables_service_before_php_and_iran_admission(self):
        result = self.setup.setup()
        self.assertIn("STAGED INACTIVE", result)
        self.assertIn("Service intentionally DISABLED", result)
        self.assertFalse(self.fake.active)
        self.assertFalse(self.fake.enabled)
        self.assertFalse(self.layout.evidence(self.relay, ".json").exists())
        self.assertFalse(self.layout.evidence(self.relay, ".policy").exists())
        self.assertIn("STAGED INACTIVE", self.setup.setup())
        self.fake.active = True  # out-of-band host activation is untrusted
        with self.assertRaisesRegex(mod.Refusal, "became active/enabled"):
            self.setup.setup()

    def test_ensure_acl_refuses_mismatch_and_restores_only_missing_table(self):
        self.setup.setup()
        verifier = mod.GatewayAclRecovery(self.relay, self.layout, self.fake)
        self.assertIn("VERIFIED", verifier.ensure(self.uid))
        self.assertEqual(1, self.fake.nft_mutations)
        self.fake.nft = False  # reboot cleared runtime table
        self.assertIn("RESTORED", verifier.ensure(self.uid))
        self.assertEqual(2, self.fake.nft_mutations)
        self.fake.extra_acl = [{"drop": None}]
        with self.assertRaises(mod.Refusal):
            verifier.ensure(self.uid)
        self.assertEqual(2, self.fake.nft_mutations)
        self.fake.extra_acl = None

    def _assert_partial_rollback(self):
        self.assertTrue(self.setup.journal_path.exists())
        self.assertFalse(self.layout.evidence(self.relay, ".managed.json").exists())
        # Even a failed halfway Setup must be retireable without Iran contact
        # and without leaving a privileged UID or an orphaned firewall table.
        self.fake.setup_fail_command = None
        self.fake.fail_daemon_reload = False
        result = self.retirement.retire()
        self.assertIn("RETIREMENT VERIFIED", result)
        self.assertFalse(self.fake.user_created)
        self.assertFalse(self.layout.unit(self.relay).exists())
        self.assertFalse(self.layout.key_dir(self.relay).exists())
        self.assertFalse(self.setup.journal_path.exists())
        self.assertFalse(self.setup.nft_path.exists())
        self.assertFalse(self.fake.nft)
        self.assertFalse(self.fake.active)
        self.assertFalse(self.fake.enabled)
        self.assertTrue(self.layout.evidence(self.relay, ".retired.json").exists())
        self.assertIn("LIFECYCLE FENCE VERIFIED", self.retirement.seal("delete"))
        with self.assertRaisesRegex(mod.Refusal, "permanently fenced"):
            self.setup.setup()

    def test_partial_setup_useradd_failure_retirement_and_seal(self):
        self.fake.setup_fail_command = "useradd"
        with self.assertRaisesRegex(mod.Refusal, "Unable to create"):
            self.setup.setup()
        self._assert_partial_rollback()

    def test_partial_setup_keygen_failure_retirement_and_seal(self):
        self.fake.setup_fail_command = "keygen"
        with self.assertRaisesRegex(mod.Refusal, "generate"):
            self.setup.setup()
        self._assert_partial_rollback()

    def test_orphaned_valid_public_key_after_interrupted_keygen_can_retire(self):
        self.fake.setup_fail_command = "keygen"
        with self.assertRaisesRegex(mod.Refusal, "generate"):
            self.setup.setup()
        public = self.layout.key_dir(self.relay) / "control_key.pub"
        public.write_bytes(self.hostkey.with_suffix(".pub").read_bytes())
        public.chmod(0o640)
        self._assert_partial_rollback()

    def test_orphaned_foreign_public_key_after_interrupted_keygen_is_preserved(self):
        self.fake.setup_fail_command = "keygen"
        with self.assertRaisesRegex(mod.Refusal, "generate"):
            self.setup.setup()
        public = self.layout.key_dir(self.relay) / "control_key.pub"
        public.write_text("foreign material, not an Ed25519 key")
        with self.assertRaisesRegex(mod.Refusal, "Unrecognized orphaned"):
            self.retirement.retire()
        self.assertTrue(public.is_file())
        self.assertTrue(self.fake.user_created)

    def test_partial_setup_unit_write_failure_retirement_and_seal(self):
        original = self.setup._write_exact
        def fail_unit(path, content, mode):
            if path.name == self.relay.unit_name:
                raise OSError("synthetic interrupted unit creation")
            return original(path, content, mode)
        with mock.patch.object(self.setup, "_write_exact", side_effect=fail_unit):
            with self.assertRaisesRegex(OSError, "unit creation"):
                self.setup.setup()
        self._assert_partial_rollback()

    def test_partial_setup_daemon_reload_failure_retirement_and_seal(self):
        self.fake.fail_daemon_reload = True
        with self.assertRaisesRegex(mod.Refusal, "reload"):
            self.setup.setup()
        self._assert_partial_rollback()

    def test_partial_setup_nft_load_failure_retirement_and_seal(self):
        self.fake.setup_fail_command = "nft"
        with self.assertRaisesRegex(mod.Refusal, "nftables ACL"):
            self.setup.setup()
        self._assert_partial_rollback()

    def test_partial_setup_claim_write_failure_retirement_and_seal(self):
        original = self.setup._write_exact
        def fail_managed(path, content, mode):
            if path.name.endswith(".managed.json"):
                raise OSError("synthetic interrupted managed claim")
            return original(path, content, mode)
        with mock.patch.object(self.setup, "_write_exact", side_effect=fail_managed):
            with self.assertRaisesRegex(OSError, "managed claim"):
                self.setup.setup()
        self.assertTrue(self.fake.nft)
        self._assert_partial_rollback()

    def test_power_cut_between_useradd_and_recording_uid_recovers_without_adoption(self):
        original = self.setup._write_json_atomic
        def fail_uid(path, content):
            if path == self.setup.journal_path and content.get("ssh_uid") is not None:
                raise OSError("synthetic crash before durable UID journal")
            return original(path, content)
        with mock.patch.object(self.setup, "_write_json_atomic", side_effect=fail_uid):
            with self.assertRaisesRegex(OSError, "durable UID"):
                self.setup.setup()
        self.assertTrue(self.fake.user_created)
        self.assertIsNone(self.retirement._json(self.setup.journal_path)["ssh_uid"])
        self._assert_partial_rollback()

    def test_partial_setup_retry_does_not_adopt_different_generation_account(self):
        self.fake.setup_fail_command = "keygen"
        with self.assertRaises(mod.Refusal):
            self.setup.setup()
        self.fake.account_marker = "a foreign identity marker"
        self.fake.setup_fail_command = None
        with self.assertRaisesRegex(mod.Refusal, "generation/UID claim"):
            self.setup.setup()
        with self.assertRaisesRegex(mod.Refusal, "replaced/unclaimed"):
            self.retirement.retire()
        self.assertFalse(any(x[:2] == ["/usr/sbin/userdel", self.relay.ssh_user] for x in self.fake.calls))
        self.assertTrue(self.setup.journal_path.exists())

    def test_partial_setup_foreign_keyfile_and_sibling_relay_are_preserved(self):
        self.fake.setup_fail_command = "keygen"
        with self.assertRaises(mod.Refusal):
            self.setup.setup()
        sibling = self.root / "var/lib/mcp-gateway-relays" / "unrelated-relay"
        sibling.mkdir()
        foreign = sibling / "owned-by-other"
        foreign.write_text("KEEP OTHER RELAY")
        intruder = self.layout.key_dir(self.relay) / "foreign.txt"
        intruder.write_text("KEEP UNKNOWN")
        with self.assertRaisesRegex(mod.Refusal, "Foreign file"):
            self.retirement.retire()
        self.assertEqual("KEEP UNKNOWN", intruder.read_text())
        self.assertEqual("KEEP OTHER RELAY", foreign.read_text())
        self.assertTrue(self.fake.user_created)
        intruder.unlink()
        self._assert_partial_rollback()
        self.assertEqual("KEEP OTHER RELAY", foreign.read_text())

    def test_replaced_same_name_uid_is_preserved_and_userdel_not_run(self):
        self.setup.setup()
        self.assertEqual(1500, self.retirement._json(self.setup.journal_path)["ssh_uid"])
        self.principal.pw_uid = 1555
        self.fake.calls.clear()
        with self.assertRaisesRegex(mod.Refusal, "replaced/unclaimed"):
            self.retirement.retire()
        self.assertFalse(any(x[:2] == ["/usr/sbin/userdel", self.relay.ssh_user] for x in self.fake.calls))
        self.assertTrue(self.fake.user_created)
        self.assertTrue(self.layout.unit(self.relay).exists())
        self.assertTrue(self.fake.nft)
        self.assertTrue((self.layout.key_dir(self.relay) / "owner.json").exists())

    def test_crash_after_userdel_before_keydir_cleanup_is_recoverable(self):
        self.setup.setup()
        original = self.retirement._delete_setup_keydir
        with mock.patch.object(self.retirement, "_delete_setup_keydir", side_effect=OSError("crash after userdel")):
            with self.assertRaisesRegex(OSError, "crash after userdel"):
                self.retirement.retire()
        self.assertFalse(self.fake.user_created)
        self.assertTrue(self.setup.journal_path.exists())
        self.assertEqual(1500, self.retirement._json(self.setup.journal_path)["ssh_uid"])
        self.assertIn("RETIREMENT VERIFIED", self.retirement.retire())
        self.assertFalse(self.setup.journal_path.exists())

    def test_crash_mid_keyfile_deletion_recovers_with_private_key_retained(self):
        self.setup.setup()
        keydir = self.layout.key_dir(self.relay)
        def crash_after_public_key_removed():
            (keydir / "owner.json").unlink()
            (keydir / "control_key.pub").unlink()
            raise OSError("power failed during staged key material cleanup")
        with mock.patch.object(self.retirement, "_delete_setup_keydir",
                               side_effect=crash_after_public_key_removed):
            with self.assertRaisesRegex(OSError, "power failed"):
                self.retirement.retire()
        self.assertFalse(self.fake.user_created)
        self.assertTrue((keydir / "control_key").is_file())
        self.assertTrue((keydir / "known_hosts").is_file())
        self.assertTrue(self.setup.journal_path.exists())
        self.assertIn("RETIREMENT VERIFIED", self.retirement.retire())
        self.assertFalse(keydir.exists())
        self.assertFalse(self.setup.journal_path.exists())

    def test_replaced_uid_is_rejected_even_if_keydir_was_removed_after_crash(self):
        self.setup.setup()
        keydir = self.layout.key_dir(self.relay)
        for entry in keydir.iterdir():
            entry.unlink()
        keydir.rmdir()
        self.principal.pw_uid = 2200
        self.fake.calls.clear()
        with self.assertRaisesRegex(mod.Refusal, "replaced/unclaimed"):
            self.retirement.retire()
        self.assertFalse(any(x[:2] == ["/usr/sbin/userdel", self.relay.ssh_user]
                             for x in self.fake.calls))
        self.assertTrue(self.fake.user_created)
        self.assertTrue(self.setup.journal_path.exists())

    def test_unjournaled_managed_with_surviving_ssh_user_is_not_retired(self):
        self.setup.setup()
        keydir = self.layout.key_dir(self.relay)
        self.setup.journal_path.unlink()
        self.setup.nft_path.unlink()
        for entry in list(keydir.iterdir()):
            entry.unlink()
        keydir.rmdir()
        self.fake.calls.clear()
        with self.assertRaisesRegex(mod.Refusal, "account exists without UID-bound Setup journal"):
            self.retirement.retire()
        self.assertTrue(self.fake.user_created)
        self.assertTrue(self.fake.nft)
        self.assertTrue(self.layout.unit(self.relay).is_file())
        self.assertTrue(self.layout.evidence(self.relay, ".managed.json").is_file())
        self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())
        self.assertFalse(any(command[:2] == ["/usr/sbin/userdel", self.relay.ssh_user]
                             or command[:3] == ["nft", "delete", "table"]
                             or command[:2] == ["systemctl", "disable"]
                             for command in self.fake.calls))

    def test_unjournaled_managed_without_account_preserves_ambiguous_credential_files(self):
        self.setup.setup()
        self.setup.journal_path.unlink()
        self.setup.nft_path.unlink()
        keydir = self.layout.key_dir(self.relay)
        (keydir / "owner.json").unlink()
        (keydir / "control_key").write_bytes(b"FOREIGN SECRET BYTES")
        self.fake.user_created = False
        self.fake.calls.clear()
        with self.assertRaisesRegex(mod.Refusal, "Unjournaled Relay credential files"):
            self.retirement.retire()
        self.assertEqual(b"FOREIGN SECRET BYTES", (keydir / "control_key").read_bytes())
        self.assertTrue(self.fake.nft)
        self.assertTrue(self.layout.unit(self.relay).exists())
        self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())
        self.assertFalse(any(command[:3] == ["nft", "delete", "table"] for command in self.fake.calls))

    def test_unjournaled_legacy_empty_key_namespace_is_retireable(self):
        self.setup.setup()
        self.setup.journal_path.unlink()
        self.setup.nft_path.unlink()
        keydir = self.layout.key_dir(self.relay)
        for entry in list(keydir.iterdir()):
            entry.unlink()
        self.fake.user_created = False
        self.assertIn("RETIREMENT VERIFIED", self.retirement.retire())
        self.assertFalse(keydir.exists())
        self.assertTrue(self.layout.evidence(self.relay, ".retired.json").exists())

    def test_fresh_setup_creates_missing_evidence_directory_before_generation(self):
        generation = self.layout.evidence(self.relay, ".generation.json")
        generation.unlink()
        self.layout.evidence_dir.rmdir()
        self.layout.evidence_dir.parent.rmdir()
        unrelated = self.layout.at("/etc/unrelated-service.conf")
        unrelated.write_text("KEEP")
        self.assertIn("NO READINESS ISSUED", self.setup.setup())
        evidence = self.layout.evidence_dir
        self.assertTrue(evidence.is_dir())
        self.assertEqual(self.layout.owner_uid, evidence.stat().st_uid)
        self.assertEqual(0o755, evidence.stat().st_mode & 0o777)
        self.assertTrue(generation.is_file())
        self.assertEqual("KEEP", unrelated.read_text())
        self.assertIn("RETIREMENT VERIFIED", self.retirement.retire())
        self.assertEqual("KEEP", unrelated.read_text())

    def test_fresh_evidence_parent_sync_failure_precedes_useradd_and_retry_resyncs(self):
        generation = self.layout.evidence(self.relay, ".generation.json")
        generation.unlink()
        evidence = self.layout.evidence_dir
        evidence.rmdir()
        evidence.parent.rmdir()
        unrelated = self.layout.at("/etc/unrelated-service.conf")
        unrelated.write_text("KEEP")
        original = mod.fsync_privileged_directory
        def fail_parent(path, layout):
            if path == evidence.parent:
                raise OSError("simulated crash at new evidence parent fsync")
            return original(path, layout)
        with mock.patch.object(mod, "fsync_privileged_directory", side_effect=fail_parent):
            with self.assertRaisesRegex(OSError, "evidence parent fsync"):
                self.setup.setup()
        self.assertTrue(evidence.is_dir())
        self.assertFalse(self.fake.user_created)
        self.assertFalse(self.setup.journal_path.exists())
        self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())
        seen = []
        def record_sync(path, layout):
            seen.append(path)
            return original(path, layout)
        with mock.patch.object(mod, "fsync_privileged_directory", side_effect=record_sync):
            self.assertIn("NO READINESS ISSUED", self.setup.setup())
        # Re-synchronize directories that already existed after interruption.
        self.assertIn(evidence, seen)
        self.assertIn(evidence.parent, seen)
        self.assertEqual("KEEP", unrelated.read_text())
        self.assertIn("RETIREMENT VERIFIED", self.retirement.retire())
        self.assertEqual("KEEP", unrelated.read_text())

    def test_private_key_directory_parent_sync_failure_recovers_from_journal(self):
        keydir = self.layout.key_dir(self.relay)
        original = mod.fsync_privileged_directory
        def fail_new_keydir_parent(path, layout):
            if path == keydir.parent and keydir.is_dir():
                raise OSError("simulated crash at credential parent fsync")
            return original(path, layout)
        with mock.patch.object(mod, "fsync_privileged_directory", side_effect=fail_new_keydir_parent):
            with self.assertRaisesRegex(OSError, "credential parent fsync"):
                self.setup.setup()
        self.assertTrue(self.fake.user_created)
        self.assertTrue(self.setup.journal_path.exists())
        self.assertEqual(1500, self.retirement._json(self.setup.journal_path)["ssh_uid"])
        self.assertEqual([], list(keydir.iterdir()))
        self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())
        self.assertIn("NO READINESS ISSUED", self.setup.setup())
        self.assertEqual(1, sum(cmd[:2] == ["/usr/sbin/useradd", "--system"] for cmd in self.fake.calls))
        self.assertIn("RETIREMENT VERIFIED", self.retirement.retire())

    def test_anonymous_publication_crash_before_link_leaves_no_temporary_name(self):
        original_link = mod.os.link
        def fail_before_link(source, destination, **kwargs):
            if destination == "known_hosts":
                raise OSError("simulated interruption before anonymous link")
            return original_link(source, destination, **kwargs)
        with mock.patch.object(mod.os, "link", side_effect=fail_before_link):
            with self.assertRaisesRegex(OSError, "before anonymous link"):
                self.setup.setup()
        keydir = self.layout.key_dir(self.relay)
        self.assertTrue(self.setup.journal_path.is_file())
        self.assertTrue(self.fake.user_created)
        self.assertFalse((keydir / "known_hosts").exists())
        self.assertFalse(any(name.startswith(".relay-setup-") for name in os.listdir(keydir)))
        self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())
        self.assertIn("NO READINESS ISSUED", self.setup.setup())
        self.assertEqual({"control_key", "control_key.pub", "known_hosts", "owner.json"},
                         {entry.name for entry in keydir.iterdir()})
        self.assertIn("RETIREMENT VERIFIED", self.retirement.retire())

    def test_anonymous_publication_crash_after_link_recovers_durable_existing_entry(self):
        keydir = self.layout.key_dir(self.relay)
        known = keydir / "known_hosts"
        original_fsync = mod.os.fsync
        def fail_after_link(fd):
            try:
                directory = os.readlink("/proc/self/fd/" + str(fd))
            except OSError:
                directory = ""
            if directory == str(keydir) and known.is_file() and not (keydir / "owner.json").exists():
                raise OSError("simulated crash after link before directory fsync")
            return original_fsync(fd)
        with mock.patch.object(mod.os, "fsync", side_effect=fail_after_link):
            with self.assertRaisesRegex(OSError, "after link before directory fsync"):
                self.setup.setup()
        self.assertTrue(known.is_file())
        self.assertEqual(self.setup._expected_hostkey(), known.read_bytes())
        self.assertFalse(any(name.startswith(".relay-setup-") for name in os.listdir(keydir)))
        self.assertTrue(self.setup.journal_path.exists())
        self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())
        seen = []
        def record_retry_fsync(fd):
            seen.append(os.readlink("/proc/self/fd/" + str(fd)))
            return original_fsync(fd)
        with mock.patch.object(mod.os, "fsync", side_effect=record_retry_fsync):
            self.assertIn("NO READINESS ISSUED", self.setup.setup())
        self.assertIn(str(known), seen)
        self.assertIn(str(keydir), seen)
        self.assertIn("RETIREMENT VERIFIED", self.retirement.retire())

    def test_foreign_and_symlinked_old_temp_names_remain_protected(self):
        self.fake.setup_fail_command = "keygen"
        with self.assertRaisesRegex(mod.Refusal, "generate"):
            self.setup.setup()
        keydir = self.layout.key_dir(self.relay)
        sibling = keydir.parent / "unrelated-relay"
        sibling.mkdir()
        unrelated = sibling / "unknown"
        unrelated.write_text("KEEP SIBLING")
        foreign = keydir / ".relay-setup-foreign"
        for symlink in (False, True):
            if symlink:
                foreign.symlink_to(unrelated)
            else:
                foreign.write_text("NOT PROVEN HELPER OUTPUT")
            with self.assertRaisesRegex(mod.Refusal, "Foreign file"):
                self.setup.setup()
            with self.assertRaisesRegex(mod.Refusal, "Foreign file"):
                self.retirement.retire()
            self.assertEqual("KEEP SIBLING", unrelated.read_text())
            self.assertTrue(foreign.is_symlink() if symlink else foreign.is_file())
            self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())
            foreign.unlink()
        self.assertIn("RETIREMENT VERIFIED", self.retirement.retire())
        self.assertEqual("KEEP SIBLING", unrelated.read_text())

    def test_unsupported_anonymous_publication_fails_closed_before_useradd(self):
        original_open = mod.os.open
        def no_tmpfile(path, flags, *args, **kwargs):
            if (flags & os.O_TMPFILE) == os.O_TMPFILE:
                raise OSError(95, "Operation not supported")
            return original_open(path, flags, *args, **kwargs)
        with mock.patch.object(mod.os, "open", side_effect=no_tmpfile):
            with self.assertRaisesRegex(mod.Refusal, "O_TMPFILE"):
                self.setup.setup()
        self.assertFalse(self.fake.user_created)
        self.assertFalse(self.setup.journal_path.exists())
        self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())
        self.assertIn("NO READINESS ISSUED", self.setup.setup())
        self.assertIn("RETIREMENT VERIFIED", self.retirement.retire())

    def test_durable_cleanup_syncs_each_file_and_parent_before_receipt(self):
        self.setup.setup()
        syncs = []
        original = self.retirement._fsync_directory
        def spy(path):
            syncs.append(path)
            return original(path)
        with mock.patch.object(self.retirement, "_fsync_directory", side_effect=spy):
            self.assertIn("RETIREMENT VERIFIED", self.retirement.retire())
        keydir = self.layout.key_dir(self.relay)
        evidence = self.layout.evidence_dir
        self.assertGreaterEqual(syncs.count(keydir), 4)
        self.assertIn(keydir.parent, syncs)  # keydir removal was made durable
        self.assertGreaterEqual(syncs.count(evidence), 3)  # nft, claim, journal
        self.assertIn(self.layout.unit(self.relay).parent, syncs)
        self.assertTrue(self.layout.evidence(self.relay, ".retired.json").is_file())

    def test_power_loss_at_managed_claim_fsync_keeps_journal_recoverable(self):
        self.setup.setup()
        evidence = self.layout.evidence_dir
        claim = self.layout.evidence(self.relay, ".managed.json")
        original = self.retirement._fsync_directory
        def fail_after_claim_unlink(path):
            if path == evidence and not claim.exists():
                raise OSError("simulated power loss at managed-claim fsync")
            return original(path)
        with mock.patch.object(self.retirement, "_fsync_directory", side_effect=fail_after_claim_unlink):
            with self.assertRaisesRegex(OSError, "managed-claim fsync"):
                self.retirement.retire()
        self.assertTrue(self.setup.journal_path.is_file())
        self.assertFalse(self.fake.user_created)
        self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())
        self.assertIn("RETIREMENT VERIFIED", self.retirement.retire())
        self.assertFalse(self.setup.journal_path.exists())

    def test_power_loss_at_journal_fsync_does_not_issue_false_receipt(self):
        self.setup.setup()
        evidence = self.layout.evidence_dir
        journal = self.setup.journal_path
        original = self.retirement._fsync_directory
        def fail_after_journal_unlink(path):
            if path == evidence and not journal.exists():
                raise OSError("simulated interruption at journal fsync")
            return original(path)
        with mock.patch.object(self.retirement, "_fsync_directory", side_effect=fail_after_journal_unlink):
            with self.assertRaisesRegex(OSError, "journal fsync"):
                self.retirement.retire()
        self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())
        self.assertFalse(self.fake.user_created)
        self.assertIn("RETIREMENT VERIFIED", self.retirement.retire())
        self.assertTrue(self.layout.evidence(self.relay, ".retired.json").exists())

    def test_final_namespace_fsync_failure_blocks_cleanup_receipt_and_recovers(self):
        self.setup.setup()
        systemd_parent = self.layout.unit(self.relay).parent
        original = self.retirement._fsync_directory
        seen = 0
        def fail_final_flush(path):
            nonlocal seen
            if path == systemd_parent:
                seen += 1
                if seen == 2:
                    raise OSError("simulated power loss at final namespace barrier")
            return original(path)
        with mock.patch.object(self.retirement, "_fsync_directory", side_effect=fail_final_flush):
            with self.assertRaisesRegex(OSError, "final namespace barrier"):
                self.retirement.retire()
        self.assertEqual(2, seen)
        self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())
        self.assertEqual("provisioning", self.retirement._generation()["state"])
        self.assertIn("RETIREMENT VERIFIED", self.retirement.retire())
        self.assertTrue(self.layout.evidence(self.relay, ".retired.json").exists())

    def test_power_loss_on_credential_fsync_keeps_original_uid_journal(self):
        self.setup.setup()
        keydir = self.layout.key_dir(self.relay)
        original = self.retirement._fsync_directory
        def fail_first_keyfile_fsync(path):
            if path == keydir:
                raise OSError("simulated power loss during credential fsync")
            return original(path)
        with mock.patch.object(self.retirement, "_fsync_directory", side_effect=fail_first_keyfile_fsync):
            with self.assertRaisesRegex(OSError, "credential fsync"):
                self.retirement.retire()
        self.assertFalse(self.fake.user_created)
        self.assertTrue(self.setup.journal_path.exists())
        self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())
        self.assertIn("RETIREMENT VERIFIED", self.retirement.retire())

    def test_managed_claim_cannot_retire_without_ssh_uid_journal(self):
        self.setup.setup()
        self.setup.journal_path.unlink()
        # Even after an unrelated loss of the persistence file, the owner
        # claim alone must never authorize SSH account deletion.
        self.setup.nft_path.unlink()
        self.fake.calls.clear()
        with self.assertRaisesRegex(mod.Refusal, "principal claim survives"):
            self.retirement.retire()
        self.assertTrue(self.fake.user_created)
        self.assertTrue(self.fake.nft)
        self.assertTrue(self.layout.unit(self.relay).exists())

    def test_foreign_acl_in_partial_stage_fails_without_unrelated_mutation(self):
        original = self.setup._write_exact
        def crash_before_claim(path, content, mode):
            if path.name.endswith(".managed.json"):
                raise OSError("simulated interruption")
            return original(path, content, mode)
        with mock.patch.object(self.setup, "_write_exact", side_effect=crash_before_claim):
            with self.assertRaisesRegex(OSError, "interruption"):
                self.setup.setup()
        self.fake.extra_acl = [{"accept": None}]
        self.fake.calls.clear()
        with self.assertRaises(mod.Refusal):
            self.retirement.retire()
        self.assertFalse(any(x[:3] == ["nft", "delete", "table"] for x in self.fake.calls))
        self.assertFalse(any(x[:2] == ["/usr/sbin/userdel", self.relay.ssh_user]
                             for x in self.fake.calls))
        self.assertTrue(self.fake.nft)
        self.assertTrue(self.fake.user_created)
        self.fake.extra_acl = None
        self._assert_partial_rollback()

    def test_cold_boot_recovers_missing_runtime_lock_and_acl_when_already_present(self):
        self.setup.setup()
        directory = self.layout.lock_path(self.relay).parent
        self.layout.lock_path(self.relay).unlink()
        directory.rmdir()
        verifier = mod.GatewayAclRecovery(self.relay, self.layout, self.fake)
        self.assertIn("VERIFIED", verifier.ensure(self.uid))
        lock = self.layout.lock_path(self.relay)
        self.assertTrue(lock.is_file())
        self.assertEqual(self.layout.owner_uid, lock.stat().st_uid)
        self.assertFalse(lock.stat().st_mode & 0o022)
        self.assertEqual(1, self.fake.nft_mutations)
        self.assertIn("RETIREMENT VERIFIED", self.retirement.retire())
        self.assertIn("LIFECYCLE FENCE VERIFIED", self.retirement.seal("delete"))
        with self.assertRaises(mod.Refusal):
            verifier.ensure(self.uid)

    def test_cold_boot_recovers_absent_runtime_lock_and_absent_acl_under_same_lock(self):
        self.setup.setup()
        self.fake.nft = False
        directory = self.layout.lock_path(self.relay).parent
        self.layout.lock_path(self.relay).unlink()
        directory.rmdir()
        verifier = mod.GatewayAclRecovery(self.relay, self.layout, self.fake)
        self.assertIn("RESTORED", verifier.ensure(self.uid))
        self.assertEqual(2, self.fake.nft_mutations)
        with self.assertRaisesRegex(mod.Refusal, "lifecycle maintenance"):
            fd = os.open(self.layout.lock_path(self.relay), os.O_RDONLY)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                verifier.ensure(self.uid)
            finally:
                os.close(fd)
        self.assertIn("RETIREMENT VERIFIED", self.retirement.retire())
        self.assertIn("LIFECYCLE FENCE VERIFIED", self.retirement.seal("delete"))

    def test_cold_boot_symlink_lock_refused_without_modifying_other_file(self):
        self.setup.setup()
        parent = self.layout.lock_path(self.relay).parent
        destination = self.root / "foreign-root-lock"
        destination.write_text("unrelated")
        self.layout.lock_path(self.relay).unlink()
        self.layout.lock_path(self.relay).symlink_to(destination)
        verifier = mod.GatewayAclRecovery(self.relay, self.layout, self.fake)
        with self.assertRaises((OSError, mod.Refusal)):
            verifier.ensure(self.uid)
        self.assertEqual("unrelated", destination.read_text())
        self.assertEqual(1, self.fake.nft_mutations)

    def test_retirement_removes_scoped_service_identity_persistence_and_journal(self):
        self.setup.setup()
        response = self.retirement.retire()
        self.assertIn("RETIREMENT VERIFIED", response)
        self.assertFalse(self.fake.user_created)
        self.assertFalse(self.setup.journal_path.exists())
        self.assertFalse(self.setup.nft_path.exists())
        self.assertFalse(self.layout.key_dir(self.relay).exists())
        self.assertFalse(self.layout.unit(self.relay).exists())
        self.assertFalse(self.layout.evidence(self.relay, ".managed.json").exists())
        self.assertTrue(self.layout.evidence(self.relay, ".retired.json").exists())
        self.assertFalse(self.fake.nft)
        self.assertFalse(self.fake.active)

    def test_retirement_does_not_delete_foreign_setup_acl_file(self):
        self.setup.setup()
        self.setup.nft_path.write_text("flush ruleset\\n")
        with self.assertRaisesRegex(mod.Refusal, "persistence source changed"):
            self.retirement.retire()
        self.assertTrue(self.fake.user_created)
        self.assertTrue(self.layout.unit(self.relay).exists())
        self.assertTrue(self.fake.nft)

    def test_retirement_refuses_unknown_canonical_nss_identity(self):
        self.setup.setup()
        with mock.patch.object(mod.pwd, "getpwuid", side_effect=KeyError(1500)):
            with self.assertRaisesRegex(mod.Refusal, "Cannot prove exclusive Relay SSH identity"):
                self.retirement.retire()
        self.assertTrue(self.fake.user_created)

    def test_setup_refuses_unknown_canonical_nss_identity(self):
        with mock.patch.object(mod.pwd, "getpwuid", side_effect=KeyError(1500)):
            with self.assertRaisesRegex(mod.Refusal, "Cannot prove dedicated Relay SSH UID ownership"):
                self.setup.setup()
        self.assertTrue(self.setup.journal_path.exists())
        self.assertFalse(self.setup.nft_path.exists())

    def test_retirement_refuses_to_delete_account_with_live_process(self):
        self.setup.setup()
        pid = self.root / "proc/4321"
        pid.mkdir()
        (pid / "status").write_text("Name:\tssh\nUid:\t1500\t1500\t1500\t1500\n")
        with self.assertRaisesRegex(mod.Refusal, "still owns a process"):
            self.retirement.retire()
        self.assertTrue(self.fake.user_created)

    def test_acl_guard_serializes_existing_table_verification_with_retirement(self):
        self.setup.setup()
        verifier = mod.GatewayAclRecovery(self.relay, self.layout, self.fake)
        fd = os.open(self.layout.lock_path(self.relay), os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(mod.Refusal, "lifecycle maintenance"):
                verifier.ensure(self.uid)
            self.assertEqual(1, self.fake.nft_mutations)
        finally:
            os.close(fd)
        self.assertIn("VERIFIED", verifier.ensure(self.uid))
        self.assertIn("RETIREMENT VERIFIED", self.retirement.retire())
        with self.assertRaisesRegex(mod.Refusal, "no longer|provisioning|provisioned"):
            verifier.ensure(self.uid)
        self.assertFalse(self.fake.nft)

    def test_drifted_policy_file_fails_closed_without_loading(self):
        self.setup.setup()
        before = self.fake.nft_mutations
        self.setup.nft_path.write_text("flush ruleset\n")
        self.fake.nft = False
        with self.assertRaisesRegex(mod.Refusal, "source is missing or modified"):
            mod.GatewayAclRecovery(self.relay, self.layout, self.fake).ensure(self.uid)
        self.assertEqual(before, self.fake.nft_mutations)
