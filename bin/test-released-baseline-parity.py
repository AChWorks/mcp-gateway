#!/usr/bin/env python3
"""Prevent the public release workflow from omitting tested stable upgrade baselines."""
from pathlib import Path
import re
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
    if not re.fullmatch(r"\d+\.\d+\.\d+", value):
        raise ValueError(f"invalid baseline version {value}")
    return tuple(map(int, value.split(".")))


def baseline_lists(workflow: str) -> list[tuple[str, ...]]:
    source = (ROOT / workflow).read_text(encoding="utf-8")
    result = []
    for name in STEPS:
        match = re.search(STEP_PATTERN.format(name=re.escape(name)), source)
        if not match:
            raise ValueError(f"{workflow}: missing release acceptance step {name}")
        versions = LOOP_PATTERN.findall(match.group(1))
        if len(versions) != 1:
            raise ValueError(f"{workflow}: {name}: expected exactly one release-baseline loop")
        values = tuple(versions[0].split())
        if len(set(values)) != len(values) or tuple(sorted(values, key=version_key)) != values:
            raise ValueError(f"{workflow}: {name}: duplicated or unordered stable versions")
        result.append(values)
    return result


def main() -> None:
    lists = [baseline_lists(workflow) for workflow in WORKFLOWS]
    expected = lists[0][0]
    for workflow, steps in zip(WORKFLOWS, lists):
        for name, versions in zip(STEPS, steps):
            if versions != expected:
                raise ValueError(
                    f"{workflow}: {name}: release baselines differ from Update Package: "
                    f"{versions!r} vs {expected!r}"
                )

    notes = (ROOT / "RELEASE_NOTES.md").read_text(encoding="utf-8")
    headings = re.findall(r"(?m)^# MCP Gateway v(\d+\.\d+\.\d+)\s*$", notes)
    if len(headings) < 2 or not version_key(headings[0]) > version_key(headings[1]):
        raise ValueError("Release notes must identify the candidate and previous stable release")
    if expected[-1] != headings[1]:
        raise ValueError(
            f"Last accepted published stable baseline {headings[1]} missing from "
            f"both release workflows (found latest {expected[-1]})"
        )
    print(f"PASS: {len(expected)} published baselines in both workflows and all three steps; "
          f"latest stable={expected[-1]}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        print(f"Release-baseline parity FAILED: {error}", file=sys.stderr)
        raise SystemExit(1) from error
