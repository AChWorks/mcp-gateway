#!/usr/bin/env python3
"""Regression fixtures for the rolling-three direct browser-update contract."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "baseline_parity", Path(__file__).with_name("test-released-baseline-parity.py"))
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


def notes(*versions):
    return "\n".join(f"# MCP Gateway v{version}\n\nFixture notes.\n" for version in versions)


class BaselineTest(unittest.TestCase):
    def fixture(self, root):
        (root / "VERSION").write_text("2.5.5\n", encoding="utf-8")
        (root / "RELEASE_NOTES.md").write_text(
            notes("2.5.5", "2.5.4", "2.5.3", "2.5.2", "2.5.1"), encoding="utf-8")
        p = root / GUARD.MANIFEST
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("2.5.2\n2.5.3\n2.5.4\n", encoding="utf-8")
        for wf in GUARD.WORKFLOWS:
            p = root / wf
            p.parent.mkdir(parents=True, exist_ok=True)
            commands = (
                "gh release download; sha256sum --check --strict",
                "bash bin/test-update-package.sh",
                "bash bin/test-update-backup-integrity.sh",
            )
            p.write_text("".join(
                f"      - name: {step}\n        run: |\n"
                "          mapfile -t versions < <(python3 bin/test-released-baseline-parity.py --list)\n"
                "          [[ ${#versions[@]} -eq 3 ]] || exit 1\n"
                '          for version in "${versions[@]}"; do\n'
                f"            {command}\n          done\n"
                for step, command in zip(GUARD.STEPS, commands)
            ), encoding="utf-8")

    def test_actual_repository_is_valid(self):
        GUARD.main()

    def test_previous_three_stable_releases_ignores_rc_notes(self):
        candidate = "2.5.5-rc.2"
        n = notes(candidate, "2.5.5-rc.1", "2.5.4", "2.5.3", "2.5.2", "2.5.1")
        self.assertEqual(("2.5.2", "2.5.3", "2.5.4"), GUARD.previous_stables(n, candidate))

    def test_invalid_release_notes_are_rejected(self):
        for candidate, prior in [
            ("2.5.5", ["2.5.4", "2.5.3"]),  # Incomplete history.
            ("2.5.5", ["2.5.4", "2.5.4", "2.5.2"]),  # Duplicate.
            ("2.5.5", ["2.5.3", "2.5.4", "2.5.2"]),  # Wrong order.
            ("2.5.5-rc.01", ["2.5.4", "2.5.3", "2.5.2"]),  # Invalid RC.
            ("2.5.5", ["2.5.4", "2.5.3", "2.5.2-rc.1"]),  # No third stable.
        ]:
            with self.subTest(candidate=candidate, prior=prior), self.assertRaises(ValueError):
                GUARD.previous_stables(notes(candidate, *prior), candidate)

    def test_wrong_or_dropped_manifests_fail(self):
        for versions in [
            "", "2.5.4", "2.5.3 2.5.4", "2.5.1 2.5.3 2.5.4",
            "2.5.2 2.5.3 2.5.3", "2.5.4 2.5.3 2.5.2",
            "2.5.2 2.5.3 2.5.5", "2.5.2 2.5.3 2.5.4 2.5.1",
            "2.5.2 2.5.3 2.5.4-rc.1",
        ]:
            with self.subTest(versions=versions), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                self.fixture(root)
                (root / GUARD.MANIFEST).write_text(
                    "\n".join(versions.split()) + "\n", encoding="utf-8")
                with self.assertRaises(ValueError):
                    GUARD.main(root)

    def test_all_three_workflow_phases_must_use_complete_selector(self):
        for wf in GUARD.WORKFLOWS:
            for old, new in [
                ("--list", ""),
                ("-eq 3", "-ge 0"),
                ('for version in "${versions[@]}"', "for version in 2.5.4"),
                ("Download released deployment baselines", "Download partial baselines"),
                ("sha256sum --check --strict", "echo skipped"),
            ]:
                with self.subTest(wf=wf, old=old), tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    self.fixture(root)
                    path = root / wf
                    path.write_text(path.read_text().replace(old, new, 1), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        GUARD.main(root)


if __name__ == "__main__":
    unittest.main()
