#!/usr/bin/env python3
"""Check that the operator reference inventories each .env.example key exactly once.

Docs alone cannot validate semantic meaning; this cheap guard prevents silent
omission of new example keys. Run on the source tree, not the deployed ZIP.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
example = (ROOT / ".env.example").read_text()
reference = (ROOT / "docs/CONFIGURATION.md").read_text()
readme = (ROOT / "README.md").read_text()
deployment = (ROOT / "docs/DEPLOYMENT.md").read_text()

keys = re.findall(r"^([A-Z][A-Z0-9_]*)=", example, re.MULTILINE)
assert len(keys) == len(set(keys)), "Duplicate .env.example keys"

begin = "## Complete `.env.example` key reference"
end = "## Additional supported settings intentionally not in the basic template"
assert reference.count(begin) == 1 and reference.count(end) == 1
catalog = reference.split(begin, 1)[1].split(end, 1)[0]
rows = re.findall(r"^\|\s*`([A-Z][A-Z0-9_]*)`\s*\|", catalog, re.MULTILINE)

missing = sorted(set(keys) - set(rows))
extra = sorted(set(rows) - set(keys))
duplicates = sorted({key for key in rows if rows.count(key) > 1})
errors = []
if missing:
    errors.append(f"missing documented .env.example keys: {missing}")
if extra:
    errors.append(f"unexpected keys in complete inventory: {extra}")
if duplicates:
    errors.append(f"duplicated keys in complete inventory: {duplicates}")
if "docs/CONFIGURATION.md" not in readme:
    errors.append("README.md does not link the configuration guide")
if "(CONFIGURATION.md)" not in deployment:
    errors.append("docs/DEPLOYMENT.md does not link the configuration guide")

for expected in ("SESSION_LIFETIME=120", "SESSION_EXPIRE_ON_CLOSE=false"):
    if expected not in example:
        errors.append(f"missing example session setting: {expected}")
    if expected not in readme:
        errors.append(f"missing README session example: {expected}")

if errors:
    for error in errors:
        print("CONFIG DOCS ERROR: " + error, file=sys.stderr)
    raise SystemExit(1)

print(f"Configuration documentation: PASS ({len(keys)} distinct .env.example keys documented)")
