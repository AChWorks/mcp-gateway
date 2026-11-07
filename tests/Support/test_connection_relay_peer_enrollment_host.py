"""Rootless lifecycle/fault tests. The separate OS fixture proves real kernel policy."""
from __future__ import annotations

import copy
from dataclasses import replace
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import subprocess
import unittest
from unittest import mock

import test_connection_relay_peer_host as offline

mod, source = offline.mod, offline.source


class FakeHost:
    """Only account/service/nft effects are simulated; all claimed files are real."""

    def __init__(self, case):
        self.case = case
        self.peers = {}
        self.accounts = {}
        self.groups = {}
        self.tables = {}
        self.services = {}
        self.calls = []
        self.fail_once = None
        self.real_command = mod.command

    def add(self, peer):
        self.peers[peer.unit_name] = peer
        self.services.setdefault(peer.unit_name, {"loaded": False, "active": False, "enabled": False})

    @staticmethod
    def lookup(items, name):
        if name not in items:
            raise KeyError(name)
        return items[name]

    def info(self, name):
        peer, state = self.peers[name], self.services[name]
        loaded = state["loaded"]
        info = {
            "LoadState": "loaded" if loaded else "not-found",
            "ActiveState": "active" if state["active"] else "inactive",
            "MainPID": "123" if state["active"] else "0",
            "FragmentPath": str(peer.unit) if loaded else "", "DropInPaths": "",
            "NeedDaemonReload": "no", "KillMode": "control-group", "User": "root" if loaded else "",
            "ControlGroup": "/system.slice/" + name if state["active"] else "",
            "UnitFileState": "enabled" if state["enabled"] else ("disabled" if loaded else ""),
            "Transient": "no",
        }
        if loaded:
            info["ExecStart"] = "{ argv[]=/usr/sbin/sshd -D -e -f " + str(peer.public / "sshd_config") + " ; }"
            info["ExecStartPre"] = ("{ argv[]=/usr/bin/python3 -I " + str(peer.helper)
                                    + " ensure-egress --input " + str(peer.record / "input.txt") + " ; }")
        # Match real systemd 257: missing Exec properties for absent units.
        return info

    def command(self, argv, data=None, check=True):
        self.calls.append(tuple(argv))
        if self.fail_once and self.fail_once(argv):
            self.fail_once = None
            raise OSError("simulated interruption")
        binary = Path(argv[0]).name
        output = ""
        if binary in ("ssh-keygen", "sshd"):
            return self.real_command(argv, data, check)
        if binary == "getent":
            account = self.accounts[argv[-1]]
            output = account.pw_name + ":*:20000:0:99999:7:::\n"
        elif binary == "groupadd":
            name, gid = argv[-1], int(argv[argv.index("--gid") + 1])
            if name in self.groups or any(group.gr_gid == gid for group in self.groups.values()):
                raise AssertionError("attempted group collision")
            self.groups[name] = grp.struct_group((name, "x", gid, []))
        elif binary == "useradd":
            name = argv[-1]
            self.accounts[name] = pwd.struct_passwd((
                name, "x", int(argv[argv.index("--uid") + 1]),
                int(argv[argv.index("--gid") + 1]), argv[argv.index("--comment") + 1],
                argv[argv.index("--home-dir") + 1], argv[argv.index("--shell") + 1],
            ))
        elif binary == "userdel":
            del self.accounts[argv[-1]]
        elif binary == "groupdel":
            del self.groups[argv[-1]]
        elif binary == "systemctl":
            action = argv[1]
            if action == "show":
                output = "".join(key + "=" + value + "\n" for key, value in self.info(argv[2]).items())
            elif action == "daemon-reload":
                for name, peer in self.peers.items():
                    self.services[name]["loaded"] = peer.unit.exists()
            elif action == "enable":
                self.services[argv[2]]["enabled"] = True
            elif action == "disable":
                if not self.services[argv[2]]["loaded"]:
                    raise AssertionError("disable called on nonexistent unit")
                self.services[argv[2]]["enabled"] = False
            elif action == "stop":
                if not self.services[argv[2]]["loaded"]:
                    raise AssertionError("stop called on nonexistent unit")
                self.services[argv[2]]["active"] = False
            elif action == "start":
                peer = self.peers[argv[2]]
                # Re-enter the public pre-start path, including its lifecycle
                # lock, so accidentally holding the Setup lock is observable.
                peer.ensure_egress()
                self.services[argv[2]]["active"] = True
            else:
                raise AssertionError(argv)
        elif binary == "nft":
            if argv[1:] == ["-j", "list", "tables"]:
                output = json.dumps({"nftables": [{"table": {"family": "inet", "name": name}} for name in self.tables]})
            elif argv[1:6] == ["-j", "-n", "list", "table", "inet"]:
                output = json.dumps({"nftables": copy.deepcopy(self.tables[argv[-1]])})
            elif argv[1:] == ["-j", "-f", "-"]:
                objects = [item["add"] for item in json.loads(data)["nftables"]]
                name = objects[0]["table"]["name"]
                if name in self.tables:
                    raise AssertionError("replaced an existing nft table")
                self.tables[name] = objects
            elif argv[1:4] == ["delete", "table", "inet"]:
                del self.tables[argv[-1]]
            else:
                raise AssertionError(argv)
        else:
            raise AssertionError("unexpected host mutation: " + repr(argv))
        return subprocess.CompletedProcess(argv, 0, output, "")

    def mutable_calls(self):
        return [call for call in self.calls
                if Path(call[0]).name in ("useradd", "userdel", "groupadd", "groupdel")
                or Path(call[0]).name == "systemctl" and call[1] != "show"
                or Path(call[0]).name == "nft" and ("-f" in call or "delete" in call)]


class RelayPeerEnrollmentTests(unittest.TestCase):
    export = offline.RelayPeerOfflinePublicStageTests.export

    def setUp(self):
        offline.RelayPeerOfflinePublicStageTests.setUp(self)
        self.peer = mod.PeerEnrollment(self.snapshot, self.layout)
        mod.ensure_root_directory(self.peer.helper.parent, self.layout)
        self.peer.helper.write_bytes(source.read_bytes())
        self.peer.helper.chmod(0o500)
        self.host_key = self.root / "temporary-key"
        pin = subprocess.run(
            ["/usr/bin/ssh-keygen", "-l", "-E", "sha256", "-f", str(self.host_key)],
            check=True, text=True, capture_output=True,
        ).stdout.split()[1]
        self.policy = self.peer._validate_spec("127.0.0.1", str(self.host_key), pin, [443, 22])
        self.host = FakeHost(self)
        self.host.add(self.peer)
        patches = [
            mock.patch.object(mod, "command", side_effect=self.host.command),
            mock.patch.object(pwd, "getpwall", side_effect=lambda: list(self.host.accounts.values())),
            mock.patch.object(pwd, "getpwnam", side_effect=lambda name: self.host.lookup(self.host.accounts, name)),
            mock.patch.object(pwd, "getpwuid", side_effect=lambda uid: next(account for account in self.host.accounts.values() if account.pw_uid == uid)),
            mock.patch.object(grp, "getgrgid", side_effect=lambda gid: next(group for group in self.host.groups.values() if group.gr_gid == gid)),
            mock.patch.object(mod.os, "getgrouplist", side_effect=lambda name, gid: [gid] + [
                group.gr_gid for group in self.host.groups.values() if name in group.gr_mem]),
            mock.patch.object(grp, "getgrall", side_effect=lambda: list(self.host.groups.values())),
            mock.patch.object(grp, "getgrnam", side_effect=lambda name: self.host.lookup(self.host.groups, name)),
            # Actual PID/cgroup/listener ownership is exercised in the
            # independently executed privileged OS fixture, never faked as
            # physical-host acceptance by this unit suite.
            mock.patch.object(mod.PeerEnrollment, "_live_process"),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def other_peer(self, suffix="78", user="relay-other", revision=None, generation=None):
        snapshot = replace(self.snapshot, record_id=self.snapshot.record_id[:-2] + suffix, control_user=user)
        if revision is not None:
            snapshot = replace(snapshot, record_id=self.snapshot.record_id, revision=revision,
                               host_generation=generation)
        peer = mod.PeerEnrollment(snapshot, self.layout)
        self.host.add(peer)
        return peer

    def test_setup_and_repeat_preserve_healthy_forwarding_service(self):
        self.assertIn("AUDIT PASS", self.peer.setup(self.policy))
        self.assertIn("NO GATEWAY READINESS", self.peer.audit())
        before = len(self.host.mutable_calls())
        original = {path: path.read_bytes() for path in self.peer._files()}
        self.assertIn("AUDIT PASS", self.peer.setup(self.policy))
        self.assertEqual(before, len(self.host.mutable_calls()))
        self.assertEqual(original, {path: path.read_bytes() for path in original})
        self.assertEqual(1, len(self.host.accounts))

    def test_native_sshd_effective_policy_rejects_weakened_result(self):
        self.peer.setup(self.policy)
        original = self.host.command
        def changed(argv, data=None, check=True):
            result = original(argv, data, check)
            if Path(argv[0]).name == "sshd" and "-T" in argv:
                result.stdout = result.stdout.replace("maxsessions 0", "maxsessions 10")
            return result
        with mock.patch.object(mod, "command", side_effect=changed):
            with self.assertRaisesRegex(mod.Refusal, "maxsessions"):
                self.peer.audit()

    def test_policy_is_immutable_until_retirement_and_new_generation(self):
        self.peer.setup(self.policy)
        changed = {**self.policy, "allowed_ports": [22, 80, 443]}
        before = len(self.host.mutable_calls())
        with self.assertRaisesRegex(mod.Refusal, "immutable"):
            self.peer.setup(changed)
        self.assertEqual(before, len(self.host.mutable_calls()))

    def test_missing_guard_repair_stops_service_before_restoration(self):
        self.peer.setup(self.policy)
        del self.host.tables[self.peer.table]
        self.host.calls.clear()
        self.assertIn("AUDIT PASS", self.peer.setup())
        stop = next(i for i, call in enumerate(self.host.calls) if call[1:2] == ("stop",))
        restore = next(i for i, call in enumerate(self.host.calls) if "-f" in call and Path(call[0]).name == "nft")
        self.assertLess(stop, restore)

    def test_ensure_egress_recovers_cold_lock_and_missing_table(self):
        self.peer.setup(self.policy)
        for path in self.layout.locks.iterdir():
            path.unlink()
        self.layout.locks.rmdir()
        del self.host.tables[self.peer.table]
        self.assertIn("EGRESS VERIFIED", self.peer.ensure_egress())
        self.assertTrue(self.layout.lock(self.snapshot).exists())
        self.assertTrue(self.host.services[self.peer.unit_name]["active"])

    def test_guard_drift_is_not_overwritten_by_repair(self):
        self.peer.setup(self.policy)
        self.host.tables[self.peer.table][-1]["rule"]["expr"] = [{"accept": None}]
        before = copy.deepcopy(self.host.tables)
        mutations = len(self.host.mutable_calls())
        with self.assertRaisesRegex(mod.Refusal, "foreign or has drifted"):
            self.peer.setup()
        self.assertEqual(before, self.host.tables)
        self.assertEqual(mutations, len(self.host.mutable_calls()))

    def test_config_drift_preserved_and_not_repaired(self):
        self.peer.setup(self.policy)
        config = self.peer.public / "sshd_config"
        config.write_bytes(config.read_bytes().replace(b"MaxSessions 0", b"MaxSessions 10"))
        before = config.read_bytes()
        with self.assertRaisesRegex(mod.Refusal, "source differs"):
            self.peer.setup()
        self.assertEqual(before, config.read_bytes())

    def test_pending_claim_reserves_uid_before_account_exists(self):
        self.peer._new_claim(self.policy)
        second = self.other_peer()
        second._new_claim(self.policy)
        self.assertEqual({}, self.host.accounts)
        self.assertEqual(20000, self.peer.owner["uid"])
        self.assertEqual(20001, second.owner["uid"])

    def test_pending_claim_reserves_principal_before_account_exists(self):
        self.peer._new_claim(self.policy)
        second = self.other_peer(user=self.snapshot.control_user)
        with self.assertRaisesRegex(mod.Refusal, "principal is reserved"):
            second._new_claim(self.policy)
        self.assertFalse(second.record.exists())
        self.assertEqual({}, self.host.accounts)

    def test_restrictive_chain_requires_positive_uid_match(self):
        self.peer._new_claim(self.policy)
        objects = self.peer._nft_objects()
        base = [item["rule"] for item in objects if "rule" in item and item["rule"]["chain"] == "output"]
        self.assertEqual(1, len(base))
        self.assertEqual({"match": {"op": "==", "left": {"meta": {"key": "skuid"}},
                                    "right": self.peer.owner["uid"]}}, base[0]["expr"][0])
        self.assertEqual({"jump": {"target": "peer_egress"}}, base[0]["expr"][1])
        self.assertNotIn("reject", json.dumps(base))
        guard = [item["rule"] for item in objects if "rule" in item and item["rule"]["chain"] == "peer_egress"]
        self.assertIn("reject", guard[-1]["expr"][0])
        chain = next(item["chain"] for item in objects if "chain" in item and item["chain"]["name"] == "output")
        self.assertGreaterEqual(chain["prio"], 0)

    def test_native_numeric_nft_enums_are_exactly_normalized(self):
        self.peer.setup(self.policy)
        state = None
        for item in self.host.tables[self.peer.table]:
            for expression in item.get("rule", {}).get("expr", []):
                match = expression.get("match", {})
                right = match.get("right")
                if right == "reply":
                    match["right"] = 1
                elif right == "established":
                    match["right"] = 2
                    state = match
                elif right == "local":
                    match["right"] = 2
                if expression.get("reject") == {"type": "icmpx", "expr": "admin-prohibited"}:
                    expression["reject"]["expr"] = 3
        self.peer._nft_exact()
        self.assertIsNotNone(state)
        state["right"] = 6  # established OR related must not be normalized.
        with self.assertRaisesRegex(mod.Refusal, "drifted"):
            self.peer._nft_exact()

    def test_nft_rule_order_drift_is_refused_even_when_handles_change(self):
        self.peer.setup(self.policy)
        for index, item in enumerate(self.host.tables[self.peer.table]):
            next(iter(item.values()))["handle"] = index + 50
        self.peer._nft_exact()
        rules = self.host.tables[self.peer.table]
        rules[-1], rules[-2] = rules[-2], rules[-1]
        with self.assertRaisesRegex(mod.Refusal, "drifted"):
            self.peer._nft_exact()

    def test_shared_allocator_lock_refuses_parallel_claim_without_mutation(self):
        with mod.live_lock(None, self.layout):
            with self.assertRaisesRegex(mod.Refusal, "maintenance is active"):
                self.peer._new_claim(self.policy)
        self.assertFalse(self.peer.record.exists())
        self.assertEqual([], self.host.mutable_calls())

    def test_setup_interruption_after_group_creation_can_resume(self):
        self.host.fail_once = lambda argv: Path(argv[0]).name == "useradd"
        with self.assertRaisesRegex(OSError, "interruption"):
            self.peer.setup(self.policy)
        self.assertTrue((self.peer.record / "owner.json").exists())
        self.assertEqual(1, len(self.host.groups))
        self.assertEqual({}, self.host.accounts)
        self.assertIn("AUDIT PASS", self.peer.setup(self.policy))
        self.assertEqual(1, len(self.host.groups))

    def test_retirement_interruption_preserves_guard_and_fences_restart(self):
        self.peer.setup(self.policy)
        self.host.fail_once = lambda argv: Path(argv[0]).name == "userdel"
        with self.assertRaisesRegex(OSError, "interruption"):
            self.peer.retire()
        self.assertTrue((self.peer.record / "retiring.json").exists())
        self.assertIn(self.peer.table, self.host.tables)
        self.assertIn(self.snapshot.control_user, self.host.accounts)
        for action in (self.peer.setup, self.peer.ensure_egress, self.peer.audit):
            with self.assertRaisesRegex(mod.Refusal, "retiring or retired"):
                action()
        self.assertIn("RETIRED", self.peer.retire())
        self.assertIn("RETIRED", self.peer.retire())

    def test_two_live_relays_have_distinct_uids_and_scoped_retirement(self):
        self.peer.setup(self.policy)
        second = self.other_peer()
        second.setup(self.policy)
        second_uid = second.owner["uid"]
        self.peer.retire()
        self.assertNotEqual(self.peer.owner["uid"], second_uid)
        self.assertEqual({second.table}, set(self.host.tables))
        self.assertIn(second.snapshot.control_user, self.host.accounts)
        self.assertTrue(self.host.services[second.unit_name]["active"])
        self.assertIn("AUDIT PASS", second.audit())
        self.assertIn("RETIRED", self.peer.retire())

    def test_inert_stage_retire_requires_completed_live_retirement(self):
        mod.operate("stage", self.snapshot, self.layout)
        self.peer.setup(self.policy)
        with self.assertRaisesRegex(mod.Refusal, "Retire the live"):
            mod.operate("retire", self.snapshot, self.layout)
        self.peer.retire()
        self.assertIn("PUBLIC STAGE RETIRED", mod.operate("retire", self.snapshot, self.layout))
        self.assertTrue((self.peer.record / "retiring.json").exists())

    def _foreign_live_record_drift(self):
        """A is active; B is fully retired; only A's trusted input drifts to B."""
        self.peer.setup(self.policy)
        other = self.other_peer()
        other.setup(self.policy)
        other.retire()
        mod.operate("stage", self.snapshot, self.layout)
        mod.operate("stage", other.snapshot, self.layout)
        (self.peer.record / "input.txt").write_bytes(mod.canonical_export(other.snapshot))
        return other

    def _assert_foreign_drift_refused_without_mutation(self, action):
        def files_and_directories():
            return {
                str(path.relative_to(self.root)): (
                    ("dir", path.stat().st_mode & 0o777) if path.is_dir()
                    else ("file", path.read_bytes())
                )
                for path in self.root.rglob("*")
            }

        before_files = files_and_directories()
        before_host = copy.deepcopy((
            self.host.accounts, self.host.groups, self.host.tables, self.host.services
        ))
        self.host.calls.clear()
        with self.assertRaisesRegex(mod.Refusal, "foreign Relay record"):
            action()
        self.assertEqual(before_files, files_and_directories())
        self.assertEqual(before_host, (
            self.host.accounts, self.host.groups, self.host.tables, self.host.services
        ))
        self.assertFalse(self.host.mutable_calls())
        self.assertFalse(any(
            path.name.startswith(self.snapshot.record_id + ".retired-")
            for path in self.peer.record.parent.iterdir()
        ))

    def test_foreign_retired_record_input_cannot_advance_active_setup(self):
        other = self._foreign_live_record_drift()
        self.assertTrue((other.record / "retiring.json").is_file())
        fresh = mod.PeerEnrollment(
            replace(self.snapshot, revision=2, host_generation="c" * 64), self.layout
        )
        self._assert_foreign_drift_refused_without_mutation(
            lambda: fresh.setup(self.policy)
        )

    def test_foreign_retired_record_input_cannot_retire_active_public_stage(self):
        other = self._foreign_live_record_drift()
        self.assertTrue((other.record / "retiring.json").is_file())
        self._assert_foreign_drift_refused_without_mutation(
            lambda: mod.operate("retire", self.snapshot, self.layout)
        )

    def test_monotonic_new_generation_can_reenroll_same_record(self):
        self.peer.setup(self.policy)
        old_uid = self.peer.owner["uid"]
        self.peer.retire()
        next_peer = self.other_peer(user=self.snapshot.control_user, revision=2, generation="c" * 64)
        self.assertIn("AUDIT PASS", next_peer.setup({**self.policy, "allowed_ports": [22, 80, 443]}))
        self.assertNotEqual(old_uid, next_peer.owner["uid"])
        archive = self.peer.record.with_name(self.snapshot.record_id + ".retired-" + self.snapshot.host_generation)
        self.assertTrue((archive / "retiring.json").exists())
        with self.assertRaises(mod.Refusal):
            self.peer.setup(self.policy)

    def test_reenrollment_requires_both_new_generation_and_higher_revision(self):
        self.peer.setup(self.policy)
        self.peer.retire()
        for revision, generation in ((1, "c" * 64), (2, self.snapshot.host_generation)):
            next_peer = self.other_peer(user=self.snapshot.control_user, revision=revision, generation=generation)
            with self.assertRaisesRegex(mod.Refusal, "higher V2 revision"):
                next_peer.setup(self.policy)

    def test_crash_after_archive_preserves_replay_fence_and_resume(self):
        self.peer.setup(self.policy)
        self.peer.retire()
        next_peer = self.other_peer(user=self.snapshot.control_user, revision=2, generation="c" * 64)
        with mock.patch.object(next_peer, "_new_claim", side_effect=OSError("publication interruption")):
            with self.assertRaises(OSError):
                next_peer.setup(self.policy)
        self.assertFalse(self.peer.record.exists())
        with self.assertRaisesRegex(mod.Refusal, "replay refused"):
            self.peer.setup(self.policy)
        self.assertIn("AUDIT PASS", next_peer.setup(self.policy))

    def test_uid_substitution_and_supplementary_group_refuse_audit(self):
        self.peer.setup(self.policy)
        account = self.host.accounts[self.snapshot.control_user]
        changed = list(account)
        changed[2] += 100
        self.host.accounts[account.pw_name] = pwd.struct_passwd(changed)
        with self.assertRaisesRegex(mod.Refusal, "principal has changed"):
            self.peer.audit()
        self.host.accounts[account.pw_name] = account
        self.host.groups["unrelated"] = grp.struct_group(("unrelated", "x", 500, [account.pw_name]))
        with self.assertRaisesRegex(mod.Refusal, "supplementary"):
            self.peer.audit()

    def test_wrong_host_pin_refuses_before_claim_and_preserves_key(self):
        before = self.host_key.read_bytes()
        with self.assertRaisesRegex(mod.Refusal, "independently trusted pin"):
            self.peer.setup({**self.policy, "host_key_fingerprint": "SHA256:" + "A" * 43})
        self.assertFalse(self.peer.record.exists())
        self.assertEqual(before, self.host_key.read_bytes())

    def test_existing_private_public_parent_is_never_widened(self):
        parent = self.root / "etc/mcp-gateway"
        mod.ensure_root_directory(parent, self.layout)
        with self.assertRaisesRegex(mod.Refusal, "not traversable"):
            self.peer.setup(self.policy)
        self.assertEqual(0o700, parent.stat().st_mode & 0o777)
        self.assertFalse(self.peer.public.exists())

    def test_unsafe_setup_spec_inputs_are_refused(self):
        good = self.policy
        for changes in (
            {"bind_address": "0.0.0.0"}, {"bind_address": "::"},
            {"bind_address": "::ffff:127.0.0.1"}, {"bind_address": "fe80::1%lo"},
            {"bind_address": "224.0.0.1"}, {"host_key": "/tmp/a b"},
            {"host_key": "/tmp/../key"}, {"host_key_fingerprint": "untrusted"},
            {"allowed_ports": []}, {"allowed_ports": [22, 22]},
            {"allowed_ports": [True]}, {"allowed_ports": [0]}, {"allowed_ports": [65536]},
        ):
            candidate = {**good, **changes}
            with self.subTest(changes=changes), self.assertRaises(mod.Refusal):
                self.peer._validate_spec(candidate["bind_address"], candidate["host_key"],
                                         candidate["host_key_fingerprint"], candidate["allowed_ports"])

    def test_all_live_actions_require_root_before_mutation(self):
        with mock.patch.object(mod.os, "geteuid", return_value=self.layout.owner_uid + 1):
            for action in (lambda: self.peer.setup(self.policy), self.peer.setup,
                           self.peer.audit, self.peer.ensure_egress, self.peer.retire):
                with self.assertRaisesRegex(mod.Refusal, "explicit root"):
                    action()
        self.assertFalse(self.peer.record.exists())
        self.assertEqual([], self.host.calls)


if __name__ == "__main__":
    unittest.main()
