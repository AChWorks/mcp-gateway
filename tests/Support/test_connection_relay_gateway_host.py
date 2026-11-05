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

sys.dont_write_bytecode = True
source = pathlib.Path(__file__).resolve().parents[2] / "resources/host/connection-relay-gateway.py"
spec = importlib.util.spec_from_file_location("relay_gateway_host", source)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class FakeHost:
    def __init__(self, relay: mod.Relay):
        self.relay = relay
        self.active = False
        self.enabled = False
        self.nft = False
        self.listener = False
        self.fail_stop = False
        self.fail_daemon_reload = False
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(argv)
        if argv[:3] == ["nft", "-j", "list"]:
            entries = ([{"table": {"family": "inet", "name": self.relay.firewall_table}}]
                       if self.nft else [])
            return subprocess.CompletedProcess(argv, 0, json.dumps({"nftables": entries}), "")
        if argv[:3] == ["nft", "delete", "table"]:
            if not self.nft:
                return subprocess.CompletedProcess(argv, 1, "", "not found")
            self.nft = False
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[0] == "systemctl":
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
        (self.root / "proc/sys/kernel/random/boot_id").write_text(
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n"
        )
        (self.root / "proc/uptime").write_text("3601.50 100.00\n")
        self.fake = FakeHost(self.relay)
        self.operator = mod.Retirement(self.relay, self.layout, self.fake)

    def test_fresh_disabled_draft_can_retire_without_remote_host_or_any_network(self):
        self.assertIn("claim=absent", self.operator.preview().replace("resource claim", "claim"))
        self.assertEqual([], [x for x in self.fake.calls if x[0] in ("ssh", "curl")])
        result = self.operator.retire()
        self.assertIn("Iran was not contacted", result)
        output = self.layout.evidence(self.relay, ".retired.json")
        receipt = json.loads(output.read_text())
        self.assertEqual(set(receipt), {
            "relay_record_id", "relay_id", "host_fingerprint",
            "configuration_revision", "verified_boot_id", "verified_at_unix",
            "verified_at_boot_seconds", "expires_at_unix",
            "gateway_cleanup_verified",
        })
        self.assertEqual(self.relay.record_id, receipt["relay_record_id"])
        self.assertTrue(receipt["gateway_cleanup_verified"])
        self.assertEqual(3601, receipt["verified_at_boot_seconds"])
        self.assertLessEqual(receipt["expires_at_unix"]-receipt["verified_at_unix"], 900)
        self.assertEqual([], [x for x in self.fake.calls if x[0] in ("ssh", "curl", "scp")])
        self.assertEqual(0, self.operator.retire().count("Iran was not contacted") - 1)

    def test_owned_managed_relay_is_removed_without_affecting_another(self):
        self.fake.active = self.fake.enabled = self.fake.listener = self.fake.nft = True
        claim = {
            "version": 1,
            "relay_record_id": self.relay.record_id,
            "relay_id": self.relay.relay_id,
            "service_unit": self.relay.unit_name,
            "firewall_table": self.relay.firewall_table,
            "local_socks_port": self.relay.local_port,
        }
        self.layout.evidence(self.relay, ".managed.json").write_text(json.dumps(claim))
        unit = self.layout.unit(self.relay)
        unit.write_text(
            "# MCP-GATEWAY-CONNECTION-RELAY " + self.relay.record_id
            + " " + self.relay.relay_id + "\n[Unit]\nDescription=owned\n"
        )
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
        self.assertIn("resource claim=verified", self.operator.preview())
        self.assertIn("RETIREMENT VERIFIED", self.operator.retire())
        for old in (unit, keys, policy, attestation, self.layout.evidence(self.relay, ".managed.json")):
            self.assertFalse(old.exists(), str(old))
        self.assertEqual("NEVER TOUCH", sibling.read_text())
        self.assertFalse(self.fake.active)
        self.assertFalse(self.fake.nft)
        self.assertEqual(1, sum(1 for x in self.fake.calls if x[:3] == ["nft", "delete", "table"]))
        self.assertEqual(1, sum(1 for x in self.fake.calls if x[:2] == ["systemctl", "disable"]))

    def test_listener_refusal_preserves_firewall_even_after_service_stops(self):
        self.fake.nft = True
        self.fake.listener = True
        managed = {
            "version": 1, "relay_record_id": self.relay.record_id,
            "relay_id": self.relay.relay_id, "service_unit": self.relay.unit_name,
            "firewall_table": self.relay.firewall_table,
            "local_socks_port": self.relay.local_port,
        }
        self.layout.evidence(self.relay, ".managed.json").write_text(json.dumps(managed))
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
        managed = {
            "version": 1, "relay_record_id": self.relay.record_id,
            "relay_id": self.relay.relay_id, "service_unit": self.relay.unit_name,
            "firewall_table": self.relay.firewall_table,
            "local_socks_port": self.relay.local_port,
        }
        self.layout.evidence(self.relay, ".managed.json").write_text(json.dumps(managed))
        with self.assertRaisesRegex(mod.Refusal, "Unsafe ownership/permissions|Unsafe non-file"):
            self.operator.retire()
        self.assertEqual("keep\n", outside.read_text())

    def test_failed_systemd_reload_recovers_when_unit_was_already_removed(self):
        owned = {
            "version": 1, "relay_record_id": self.relay.record_id,
            "relay_id": self.relay.relay_id, "service_unit": self.relay.unit_name,
            "firewall_table": self.relay.firewall_table,
            "local_socks_port": self.relay.local_port,
        }
        self.layout.evidence(self.relay, ".managed.json").write_text(json.dumps(owned))
        unit = self.layout.unit(self.relay)
        unit.write_text("# MCP-GATEWAY-CONNECTION-RELAY " + self.relay.record_id +
                        " " + self.relay.relay_id + "\n[Unit]\nDescription=owned\n")
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
        managed = {
            "version": 1, "relay_record_id": self.relay.record_id,
            "relay_id": self.relay.relay_id, "service_unit": self.relay.unit_name,
            "firewall_table": self.relay.firewall_table,
            "local_socks_port": self.relay.local_port,
        }
        self.layout.evidence(self.relay, ".managed.json").write_text(json.dumps(managed))
        with self.assertRaisesRegex(mod.Refusal, "Could not stop"):
            self.operator.retire()
        self.assertFalse(self.layout.evidence(self.relay, ".retired.json").exists())
        self.fake.fail_stop = False
        self.assertIn("RETIREMENT VERIFIED", self.operator.retire())

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

    def script(self) -> str:
        php = (source.parents[2] / "app/Infrastructure/Connectors/Relay/"
               "ConnectionRelayHostOperatorPlan.php").read_text()
        m = re.search(r"\$bootstrapScript = <<<'BASH'\n(.*?)\nBASH;", php, re.S)
        assert m is not None
        body = m.group(1)
        replacements = {
            "source=__SOURCE__": "source=" + shlex.quote(str(self.source)),
            "expected=__SHA__": "expected=" + shlex.quote(self.hash),
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
        }
        for old, new in replacements.items():
            self.assertIn(old, body)
            body = body.replace(old, new, 1)
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




if __name__ == "__main__":
    unittest.main()
