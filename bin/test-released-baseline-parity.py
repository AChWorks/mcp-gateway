#!/usr/bin/env python3
"""Keep candidate identity and published stable upgrade baselines consistent."""
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
STEPS = (
    "Download released deployment baselines",
    "Verify released-baseline browser updates",
    "Verify released-baseline backup integrity fail-safe",
)
WORKFLOWS = (
    ".github/workflows/update-package.yml",
    ".github/workflows/release-package.yml",
)
STEP_PATTERN = r"(?ms)^      - name: {name}\n(.*?)(?=^      - name: |\Z)"
LOOP_PATTERN = re.compile(r"for version in ([0-9. ]+); do")


def version_key(value: str) -> tuple[int, int, int]:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value):
        raise ValueError(f"invalid baseline version {value}")
    return tuple(map(int, value.split(".")))


def package_version_key(value: str) -> tuple[int, int, int, int, int]:
    # Reuse the package syntax authority, including its strict rc.N policy.
    # The remaining tuple only orders already-validated versions: rc < stable.
    checked = subprocess.run(
        ["bash", str(ROOT / "bin/validate-version.sh"), "package", value],
        capture_output=True, text=True, check=False,
    )
    if checked.returncode != 0:
        raise ValueError(f"invalid release-note package version {value}")
    core, prerelease, number = value.partition("-rc.")
    return (*version_key(core), 0 if prerelease else 1, int(number) if prerelease else 0)


def previous_stable(notes: str, candidate: str) -> str:
    headings = re.findall(r"(?m)^# MCP Gateway v([^\r\n]*)$", notes)
    if len(headings) < 2 or headings[0] != candidate:
        raise ValueError("Release notes must start with the exact VERSION and identify a previous stable release")
    keys = [package_version_key(value) for value in headings]
    if any(current <= older for current, older in zip(keys, keys[1:])):
        raise ValueError("Release-note versions must be unique and strictly descending")
    # Earlier RC notes, when retained, are not published stable upgrade fixtures.
    for value, key in zip(headings[1:], keys[1:]):
        if key[3] == 1:
            return value
    raise ValueError("Release notes must identify a previous stable release")


def baseline_lists(workflow: str, root: Path = ROOT) -> list[tuple[str, ...]]:
    source = (root / workflow).read_text(encoding="utf-8")
    result = []
    for name in STEPS:
        match = re.search(STEP_PATTERN.format(name=re.escape(name)), source)
        if not match:
            raise ValueError(f"{workflow}: missing release acceptance step {name}")
        versions = LOOP_PATTERN.findall(match.group(1))
        if len(versions) != 1:
            raise ValueError(f"{workflow}: {name}: expected exactly one release-baseline loop")
        values = tuple(versions[0].split())
        keys = [version_key(value) for value in values]
        if not values or any(earlier >= later for earlier, later in zip(keys, keys[1:])):
            raise ValueError(f"{workflow}: {name}: empty, duplicated or unordered stable versions")
        result.append(values)
    return result


def main(root: Path = ROOT) -> None:
    lists = [baseline_lists(workflow, root) for workflow in WORKFLOWS]
    expected = lists[0][0]
    for workflow, steps in zip(WORKFLOWS, lists):
        for name, versions in zip(STEPS, steps):
            if versions != expected:
                raise ValueError(
                    f"{workflow}: {name}: release baselines differ from Update Package: "
                    f"{versions!r} vs {expected!r}"
                )

    notes = (root / "RELEASE_NOTES.md").read_text(encoding="utf-8")
    candidate = (root / "VERSION").read_text(encoding="utf-8").strip()
    latest_stable = previous_stable(notes, candidate)
    if expected[-1] != latest_stable:
        raise ValueError(
            f"Last accepted published stable baseline {latest_stable} missing from "
            f"both release workflows (found latest {expected[-1]})"
        )
    print(f"PASS: {len(expected)} published baselines in both workflows and all three steps; "
          f"candidate={candidate}; latest stable={expected[-1]}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        print(f"Release-baseline parity FAILED: {error}", file=sys.stderr)
        raise SystemExit(1) from error
