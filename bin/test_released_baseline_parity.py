#!/usr/bin/env python3
"""Isolated regression fixtures for the actual release-baseline/identity guard."""
from contextlib import redirect_stdout
import importlib.util
import io
import sys
from pathlib import Path
import tempfile
import unittest

sys.dont_write_bytecode = True

SPEC = importlib.util.spec_from_file_location(
    "baseline_parity", Path(__file__).with_name("test-released-baseline-parity.py")
)
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


def notes(*versions: str) -> str:
    return "\n".join(f"# MCP Gateway v{version}\n\nFixture notes.\n" for version in versions)


class ReleaseBaselineParityTest(unittest.TestCase):
    def test_stable_rc_and_promotion_resolve_the_previous_stable(self):
        for candidate, history, expected in [
            ("2.3.12", ["2.3.11"], "2.3.11"),
            ("2.4.0-rc.1", ["2.3.12", "2.3.11"], "2.3.12"),
            ("2.4.0-rc.10", ["2.4.0-rc.2", "2.4.0-rc.1", "2.3.12"], "2.3.12"),
            ("2.4.0", ["2.4.0-rc.2", "2.4.0-rc.1", "2.3.12"], "2.3.12"),
        ]:
            with self.subTest(candidate=candidate):
                self.assertEqual(expected, GUARD.previous_stable(notes(candidate, *history), candidate))

    def test_malformed_candidate_identity_is_never_skipped_as_a_heading(self):
        for candidate in [
            "2.4.0-rc.0", "2.4.0-rc.01", "2.4.0-rc.alpha", "2.4.0-rc.1+changed",
            "2.4.0-rc.1.0", "2.4.0-rc.-1", "2.4.0-RC.1", "2.4.0-beta.1",
        ]:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                GUARD.previous_stable(notes(candidate, "2.3.12"), candidate)

    def test_version_mismatch_duplicates_and_nonmonotonic_history_fail(self):
        for declared, history in [
            ("2.4.0-rc.1", ["2.4.0-rc.2", "2.3.12"]),
            ("2.4.0-rc.1", ["2.4.0-rc.1", "2.4.0-rc.1", "2.3.12"]),
            ("2.4.0-rc.1", ["2.4.0-rc.1", "2.4.0", "2.3.12"]),
            ("2.4.0-rc.1", ["2.4.0-rc.1", "2.3.12", "2.3.12"]),
            ("2.4.0-rc.1", ["2.4.0-rc.1", "2.3.11", "2.3.12"]),
            ("2.4.0-rc.1", ["2.4.0-rc.1"]),
            ("2.4.0-rc.2", ["2.4.0-rc.2", "2.4.0-rc.1"]),
        ]:
            with self.subTest(history=history), self.assertRaises(ValueError):
                GUARD.previous_stable(notes(*history), declared)

    def test_invalid_historical_rc_is_rejected_too(self):
        with self.assertRaises(ValueError):
            GUARD.previous_stable(notes("2.4.0-rc.2", "2.4.0-rc.01", "2.3.12"), "2.4.0-rc.2")

    def fixture(self, root: Path, versions: str, history: list[str]) -> None:
        (root / "VERSION").write_text(history[0] + "\n", encoding="utf-8")
        (root / "RELEASE_NOTES.md").write_text(notes(*history), encoding="utf-8")
        for workflow in GUARD.WORKFLOWS:
            target = root / workflow
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("".join(
                f"      - name: {step}\n        run: |\n          for version in {versions}; do\n            true\n          done\n"
                for step in GUARD.STEPS
            ), encoding="utf-8")

    def test_current_candidate_matrix_passes_only_with_its_previous_stable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, "1.1.2 2.3.11 2.3.12", ["2.4.0-rc.1", "2.3.12"])
            with redirect_stdout(io.StringIO()):
                GUARD.main(root)
            self.fixture(root, "1.1.2 2.3.11", ["2.4.0-rc.1", "2.3.12"])
            with self.assertRaises(ValueError):
                GUARD.main(root)

    def test_empty_duplicate_disordered_or_prerelease_baselines_fail(self):
        for versions in [" ", "1.1.2 1.1.2 2.3.12", "1.1.2 01.1.2 2.3.12", "2.3.12 1.1.2", "1.1.2 2.4.0-rc.1"]:
            with self.subTest(versions=versions), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.fixture(root, versions, ["2.4.0-rc.1", "2.3.12"])
                with self.assertRaises(ValueError):
                    GUARD.main(root)

    def test_a_single_step_or_workflow_cannot_drop_a_baseline(self):
        for workflow in GUARD.WORKFLOWS:
            with self.subTest(workflow=workflow), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.fixture(root, "1.1.2 2.3.11 2.3.12", ["2.4.0-rc.1", "2.3.12"])
                path = root / workflow
                path.write_text(path.read_text().replace("2.3.11 2.3.12", "2.3.11", 1), encoding="utf-8")
                with self.assertRaises(ValueError):
                    GUARD.main(root)


if __name__ == "__main__":
    unittest.main()
