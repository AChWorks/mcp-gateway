#!/usr/bin/env python3
"""Fail-closed rolling-three stable baseline, release-notes and workflow parity."""
import argparse
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = "bin/released-baselines.txt"
WORKFLOWS = (".github/workflows/update-package.yml", ".github/workflows/release-package.yml")
STEPS = (
    "Download released deployment baselines",
    "Verify released-baseline browser updates",
    "Verify released-baseline backup integrity fail-safe",
)
STEP_PATTERN = r"(?ms)^      - name: {name}\n(.*?)(?=^      - name: |\Z)"
STABLE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")


def version_key(value: str) -> tuple[int, int, int]:
    if not STABLE.fullmatch(value):
        raise ValueError(f"invalid stable baseline {value!r}")
    return tuple(map(int, value.split(".")))


def package_version_key(value: str) -> tuple[int, int, int, int, int]:
    checked = subprocess.run(
        ["bash", str(ROOT / "bin/validate-version.sh"), "package", value],
        capture_output=True, text=True, check=False,
    )
    if checked.returncode != 0:
        raise ValueError(f"invalid release-note package version {value}")
    core, prerelease, number = value.partition("-rc.")
    return (*version_key(core), 0 if prerelease else 1, int(number) if prerelease else 0)


def previous_stables(notes: str, candidate: str, limit: int = 3) -> tuple[str, ...]:
    headings = re.findall(r"(?m)^# MCP Gateway v([^\r\n]*)$", notes)
    if len(headings) < limit + 1 or headings[0] != candidate:
        raise ValueError(f"Release notes must identify candidate VERSION and {limit} previous stable releases")
    keys = [package_version_key(value) for value in headings]
    if any(current <= older for current, older in zip(keys, keys[1:])):
        raise ValueError("Release-note versions must be unique and strictly descending")
    selected = [v for v, k in zip(headings[1:], keys[1:]) if k[3] == 1][:limit]
    if len(selected) != limit:
        raise ValueError(f"Release notes do not identify {limit} preceding stable releases")
    return tuple(reversed(selected))


def read_manifest(root: Path = ROOT) -> tuple[str, ...]:
    lines = (root / MANIFEST).read_text(encoding="utf-8").splitlines()
    versions = tuple(line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#"))
    if len(versions) != 3:
        raise ValueError(f"{MANIFEST}: exactly three stable baselines required; found {len(versions)}")
    keys = [version_key(version) for version in versions]
    if any(a >= b for a, b in zip(keys, keys[1:])):
        raise ValueError(f"{MANIFEST}: duplicated or nonascending release baselines")
    return versions


def check_release_notes_trigger_owner(content: str) -> None:
    # This file is the source of the rolling supported-version history.
    # A release-notes-only PR must run validation; broad CI ignores *.md.
    for event in ("push", "pull_request"):
        section = re.search(
            rf"(?ms)^  {event}:\n(.*?)(?=^  [a-z_]+:|^[a-z_]+:|\Z)", content,
        )
        if section is None:
            raise ValueError(f"Update Package: missing {event} event for release-note parity")
        paths = re.search(r"(?m)^    paths:\n((?:^      - [^\n]+\n)+)", section.group(1))
        if paths is None:
            raise ValueError(f"Update Package: {event} must own explicit paths")
        included = {line.strip().removeprefix("- ").strip("'\"")
                    for line in paths.group(1).splitlines()}
        if "RELEASE_NOTES.md" not in included:
            raise ValueError(f"Update Package: {event} omits RELEASE_NOTES.md from paths")


def check_workflow(root: Path, path: str) -> None:
    content = (root / path).read_text(encoding="utf-8")
    if path == ".github/workflows/update-package.yml":
        check_release_notes_trigger_owner(content)
    expected_commands = (
        ("gh release download", "sha256sum --check --strict"),
        ("bash bin/test-update-package.sh",),
        ("bash bin/test-update-backup-integrity.sh",),
    )
    for name, expected in zip(STEPS, expected_commands):
        match = re.search(STEP_PATTERN.format(name=re.escape(name)), content)
        if not match:
            raise ValueError(f"{path}: missing baseline verification step {name}")
        block = match.group(1)
        if block.count("python3 bin/test-released-baseline-parity.py --list") != 1:
            raise ValueError(f"{path}: {name} must select exactly the manifest's 3 baselines")
        if not re.search(r'mapfile -t versions < <\(python3 bin/test-released-baseline-parity.py --list\)', block):
            raise ValueError(f"{path}: {name} must capture manifest versions via mapfile")
        if not re.search(r'\[\[ \$\{#versions\[@\]\} -eq 3 \]\]', block):
            raise ValueError(f"{path}: {name} must fail if baseline manifest selection is incomplete")
        if 'for version in "${versions[@]}"; do' not in block:
            raise ValueError(f"{path}: {name} must run for each selected baseline")
        if not all(command in block for command in expected):
            raise ValueError(f"{path}: {name} is missing the required official ZIP or safety check")


def main(root: Path = ROOT) -> None:
    versions = read_manifest(root)
    notes = (root / "RELEASE_NOTES.md").read_text(encoding="utf-8")
    candidate = (root / "VERSION").read_text(encoding="utf-8").strip()
    expected = previous_stables(notes, candidate)
    if versions != expected:
        raise ValueError(f"Rolling supported upgrade window is {expected!r}, manifest has {versions!r}")
    for workflow in WORKFLOWS:
        check_workflow(root, workflow)
    print(f"PASS: exact three-release supported update window {', '.join(versions)}; "
          f"candidate={candidate}; all three release/PR integration stages present", file=sys.stderr)


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--list", action="store_true", help="Print validated three-release baseline list")
        args = parser.parse_args()
        main()
        if args.list:
            # Keep stdout machine-readable for mapfile; validation messages go to stderr.
            print(*read_manifest(), sep="\n")
    except (OSError, ValueError) as error:
        print(f"Release-baseline parity FAILED: {error}", file=sys.stderr)
        raise SystemExit(1) from error
