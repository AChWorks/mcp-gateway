#!/usr/bin/env python3
"""Regression fixtures for the same-major rolling browser-update contract."""
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
        (root / "VERSION").write_text("3.0.5\n", encoding="utf-8")
        (root / "RELEASE_NOTES.md").write_text(
            notes("3.0.5", "3.0.4", "3.0.3", "3.0.2", "3.0.1"), encoding="utf-8")
        p = root / GUARD.MANIFEST
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("3.0.2\n3.0.3\n3.0.4\n", encoding="utf-8")
        for wf in GUARD.WORKFLOWS:
            p = root / wf
            p.parent.mkdir(parents=True, exist_ok=True)
            commands = (
                "gh release download; sha256sum --check --strict",
                "bash bin/test-update-package.sh",
                "bash bin/test-update-backup-integrity.sh",
            )
            event_owner = (
                "name: Update Package\non:\n"
                "  push:\n    paths:\n      - RELEASE_NOTES.md\n"
                "  pull_request:\n    paths:\n      - RELEASE_NOTES.md\n\n"
                if wf == ".github/workflows/update-package.yml" else ""
            )
            p.write_text(event_owner + "".join(
                f"      - name: {step}\n        run: |\n"
                "          mapfile -t versions < <(python3 bin/test-released-baseline-parity.py --list)\n"
                '          expected_count="$(python3 bin/test-released-baseline-parity.py --count)"\n'
                '          [[ ${#versions[@]} -eq "$expected_count" ]] || exit 1\n'
                '          for version in "${versions[@]}"; do\n'
                f"            {command}\n          done\n"
                for step, command in zip(GUARD.STEPS, commands)
            ), encoding="utf-8")

    def test_actual_repository_is_valid(self):
        GUARD.main()

    def test_active_deployment_instructions_are_v3_only(self):
        guide = (Path(__file__).resolve().parent.parent / "docs/DEPLOYMENT.md").read_text()
        self.assertIn("RELEASE_TAG=v3.0.0", guide)
        self.assertNotIn("RELEASE_TAG=v2.", guide)
        self.assertNotIn("\n-ZIP installations", guide)
        self.assertNotIn("Supported pre-role releases", guide)
        self.assertIn("### Browser update for installed v3 ZIPs", guide)


    def test_first_v3_update_has_one_real_prior_stable(self):
        self.assertEqual(("3.0.0",), GUARD.previous_stables(
            notes("3.0.1", "3.0.0"), "3.0.1",
        ))

    def test_previous_three_stable_releases_ignores_rc_notes(self):
        candidate = "3.0.5-rc.2"
        n = notes(candidate, "3.0.5-rc.1", "3.0.4", "3.0.3", "3.0.2", "3.0.1")
        self.assertEqual(("3.0.2", "3.0.3", "3.0.4"), GUARD.previous_stables(n, candidate))

    def test_invalid_release_notes_are_rejected(self):
        for candidate, prior in [
            ("3.0.1", []),  # No previous v3 stable to update from.
            ("3.0.5", ["3.0.4", "3.0.4", "3.0.2"]),  # Duplicate.
            ("3.0.5", ["3.0.3", "3.0.4", "3.0.2"]),  # Wrong order.
            ("3.0.5-rc.01", ["3.0.4", "3.0.3", "3.0.2"]),  # Invalid RC.
            ("3.0.5", ["3.0.4", "3.0.3", "3.0.2-rc.01"]),  # No third stable.
        ]:
            with self.subTest(candidate=candidate, prior=prior), self.assertRaises(ValueError):
                GUARD.previous_stables(notes(candidate, *prior), candidate)

    def test_wrong_or_dropped_manifests_fail(self):
        for versions in [
            "", "3.0.4", "3.0.3 3.0.4", "3.0.1 3.0.3 3.0.4",
            "3.0.2 3.0.3 3.0.3", "3.0.4 3.0.3 3.0.2",
            "3.0.2 3.0.3 3.0.5", "3.0.2 3.0.3 3.0.4 3.0.1",
            "3.0.2 3.0.3 3.0.4-rc.1",
        ]:
            with self.subTest(versions=versions), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                self.fixture(root)
                (root / GUARD.MANIFEST).write_text(
                    "\n".join(versions.split()) + "\n", encoding="utf-8")
                with self.assertRaises(ValueError):
                    GUARD.main(root)

    def test_release_notes_only_edits_have_an_owner_and_are_validated(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.fixture(root)
            notes_file = root / "RELEASE_NOTES.md"
            original = notes_file.read_text(encoding="utf-8")
            # Only the release-note file changes: the workflow must be routed,
            # and a harmless prose edit must leave the parity gate green.
            notes_file.write_text(original + "\n## Clarification\nNo version change.\n", encoding="utf-8")
            GUARD.main(root)

            # With all other files unchanged, the same parity gate must fail
            # if a preceding stable heading is omitted or incorrectly ordered.
            for changed in (
                original.replace("# MCP Gateway v3.0.3\n", ""),
                original.replace(
                    "# MCP Gateway v3.0.4\n\nFixture notes.\n",
                    "# MCP Gateway v3.0.3\n\nFixture notes.\n",
                ),
                notes("3.0.5", "3.0.3", "3.0.4", "3.0.2", "3.0.1"),
            ):
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    notes_file.write_text(changed, encoding="utf-8")
                    GUARD.main(root)

    def test_release_notes_only_trigger_must_exist_in_both_event_paths(self):
        for event in ("push", "pull_request"):
            with self.subTest(event=event), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                self.fixture(root)
                workflow = root / ".github/workflows/update-package.yml"
                contents = workflow.read_text(encoding="utf-8")
                anchor = f"  {event}:\n    paths:\n      - RELEASE_NOTES.md\n"
                self.assertIn(anchor, contents)
                workflow.write_text(contents.replace(anchor, anchor.replace(
                    "      - RELEASE_NOTES.md\n", "      - VERSION\n",
                ), 1), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, f"{event} omits RELEASE_NOTES.md"):
                    GUARD.main(root)

    def test_all_three_workflow_phases_must_use_complete_selector(self):
        for wf in GUARD.WORKFLOWS:
            for old, new in [
                ("--list", ""),
                ('-eq "$expected_count"', "-ge 0"),
                ('for version in "${versions[@]}"', "for version in 3.0.4"),
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
