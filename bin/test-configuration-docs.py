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

# Security cookie behavior must be correct for both the local-HTTP template
# and the HTTPS-production web installer. A literal true here would break
# browser login on fresh local HTTP dev setups; a literal false is dangerous
# if a manually copied template is switched to production without review.
if re.search(r"^SESSION_SECURE_COOKIE=", example, re.MULTILINE):
    errors.append("leave SESSION_SECURE_COOKIE unset in the HTTP dev template")
if "# SESSION_SECURE_COOKIE=true" not in example:
    errors.append("explain the HTTPS production SESSION_SECURE_COOKIE override")

for expected in (
    "SESSION_HTTP_ONLY=true",
    "SESSION_SAME_SITE=lax",
    "OAUTH_ACCESS_TOKEN_TTL_SECONDS=3600",
    "SSH_FILE_TRANSFER_ENABLED=true",
    "SSH_FILE_TRANSFER_MAX_BYTES=8388608",
    "SSH_FILE_TRANSFER_MAX_SECONDS=30",
    "SSH_VERIFY_MAX_ATTEMPTS_PER_MINUTE=6",
    "SSH_VERIFY_DECAY_SECONDS=60",
    "SSH_VERIFY_LEASE_SECONDS=30",
):
    if expected not in example:
        errors.append(f"missing supported operator-facing setting: {expected}")

# These are advanced opt-in controls; keep them discoverable without
# enabling an unsafe reverse-proxy/cookie configuration by default.
for expected in ("# GATEWAY_TRUSTED_PROXIES=", "# SESSION_COOKIE="):
    if expected not in example:
        errors.append(f"missing optional configuration hint: {expected}")

if errors:
    for error in errors:
        print("CONFIG DOCS ERROR: " + error, file=sys.stderr)
    raise SystemExit(1)

print(f"Configuration documentation: PASS ({len(keys)} distinct .env.example keys documented)")
