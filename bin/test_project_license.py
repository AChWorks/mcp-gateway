#!/usr/bin/env python3
"""Verify the exact GNU license and the retained first-party copyright notice.

This protects the project's published license identity without rewriting or
claiming ownership of any third-party vendor license.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPDX = "AGPL-3.0-only"
# Verbatim official Free Software Foundation agpl-3.0.txt retrieved over HTTPS.
# AGPLv3 section 0 says copying the full license verbatim is allowed; changing it
# is not. Exact hash avoids a plausible-looking but altered licensing document.
OFFICIAL_GNU_AGPL_V3_SHA256 = (
    "0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0"
)


def assert_license() -> None:
    license_path = ROOT / "LICENSE"
    license_text = license_path.read_bytes()
    digest = hashlib.sha256(license_text).hexdigest()
    assert digest == OFFICIAL_GNU_AGPL_V3_SHA256, (
        "LICENSE differs from the official verbatim GNU Affero GPL v3 text"
    )
    assert license_text.startswith(b"                    GNU AFFERO GENERAL PUBLIC LICENSE\n")
    assert b"13. Remote Network Interaction; Use with the GNU General Public License." in license_text

    metadata = json.loads((ROOT / "composer.json").read_text())
    assert metadata.get("license") == SPDX, "composer.json SPDX project license mismatch"

    notice = (ROOT / "NOTICE").read_text()
    assert "Copyright (c) 2026 ACh" in notice, "Historical project copyright was lost"
    assert SPDX in notice, "NOTICE must identify the project license"
    assert "https://github.com/AChWorks/mcp-gateway" in notice, "Corresponding upstream source link missing"
    assert "section 13" in notice, "Network source-offer guidance missing"
    assert "third-party" in notice.lower(), "Independent dependency license notice missing"

    print(f"PASS: official FSF AGPLv3 intact; SPDX {SPDX}, source/copyright NOTICE coherent.")


if __name__ == "__main__":
    assert_license()
