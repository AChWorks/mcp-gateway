#!/usr/bin/env python3
"""Isolated release-publication security tests; never contact GitHub."""
from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

sys.dont_write_bytecode = True
import release_publication_guard as guard

APPROVED = "a" * 40
OTHER = "b" * 40
VERSION = "2.2.1"
TAG = "v" + VERSION


class PublicationGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory(prefix="release-guard-unit-")
        self.addCleanup(self.dir.cleanup)
        self.root = Path(self.dir.name) / "repo"
        self.root.mkdir()
        (self.root / "VERSION").write_text(VERSION + "\n")
        self.dist = self.root / "dist"
        self.dist.mkdir()
        self.source = {}
        for name in (f"mcp-gateway-v{VERSION}.zip", f"mcp-gateway-update-v{VERSION}.zip"):
            data = (name + ":test-only-binary").encode()
            self.source[name] = data
            self.source[name + ".sha256"] = (
                hashlib.sha256(data).hexdigest() + "  " + name + "\n"
            ).encode()
        for name, data in self.source.items():
            (self.dist / name).write_bytes(data)

        self.main_sha = APPROVED
        self.tag = (None, None)
        self.release = None
        self.tamper = None
        self.download_called = 0
        self.real_api = guard.api_release
        self.env = {
            "GITHUB_REPOSITORY": guard.REPOSITORY,
            "GITHUB_SHA": APPROVED,
            "GITHUB_REF": "refs/heads/main",
            "APPROVED_SHA": APPROVED,
            "APPROVED_VERSION": VERSION,
            "GH_TOKEN": "non-secret-disposable-test-token",
        }
        patcher1 = patch.object(guard, "ROOT", self.root)
        patcher2 = patch.object(guard, "command", side_effect=self.fake_command)
        patcher3 = patch.object(guard, "api_release", side_effect=self.fake_api)
        patcher4 = patch.object(guard, "remote_tag", side_effect=self.fake_tag)
        patcher5 = patch.dict(os.environ, self.env, clear=True)
        for p in (patcher1, patcher2, patcher3, patcher4, patcher5):
            p.start()
            self.addCleanup(p.stop)

    def fake_api(self, tag: str, token: str):
        self.assertEqual(tag, TAG)
        self.assertTrue(token)
        return self.release

    def fake_tag(self, tag: str):
        self.assertEqual(tag, TAG)
        return self.tag

    def fake_command(self, *argv: str):
        if argv == ("git", "rev-parse", "HEAD"):
            return APPROVED
        if argv == ("git", "ls-remote", "--exit-code", "origin", "refs/heads/main"):
            return f"{self.main_sha}\trefs/heads/main"
        if argv[:3] == ("gh", "release", "download"):
            self.assertEqual(argv[3:6], (TAG, "--repo", guard.REPOSITORY))
            self.assertEqual(argv[6], "--dir")
            target = Path(argv[7])
            self.download_called += 1
            for name, source in self.source.items():
                data = b"UNTRUSTED TAMPER" if self.tamper == name else source
                (target / name).write_bytes(data)
            return ""
        self.fail(f"Unexpected external command: {argv!r}")

    def expected_release(self):
        return {
            "tag_name": TAG,
            "name": f"MCP Gateway {TAG}",
            "target_commitish": APPROVED,
            "draft": False,
            "prerelease": False,
            "published_at": "2026-10-14T16:00:00Z",
            "assets": [{
                "name": name, "state": "uploaded", "size": len(data),
                "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
            } for name, data in self.source.items()],
        }

    def test_fresh_publication_preflight_passes(self):
        guard.execute("before")
        self.assertEqual(self.download_called, 0)

    def test_preexisting_mismatched_release_rejected(self):
        self.release = self.expected_release()
        self.release["target_commitish"] = OTHER
        with self.assertRaisesRegex(guard.PublicationStateError, "Release already exists"):
            guard.execute("before")

    def test_preexisting_exact_release_also_rejected_without_silent_success(self):
        self.release = self.expected_release()
        with self.assertRaisesRegex(guard.PublicationStateError, "Release already exists"):
            guard.execute("before")

    def test_preexisting_tag_without_release_rejected(self):
        self.tag = (OTHER, None)
        with self.assertRaisesRegex(guard.PublicationStateError, "tag already exists"):
            guard.execute("before")

    def test_stale_main_rejected(self):
        self.main_sha = OTHER
        with self.assertRaisesRegex(guard.PublicationStateError, "Remote main moved"):
            guard.execute("before")

    def test_unavailable_release_api_fails_closed(self):
        with patch.object(guard, "api_release", side_effect=guard.PublicationStateError("API denied")):
            with self.assertRaisesRegex(guard.PublicationStateError, "API denied"):
                guard.execute("before")

    def test_release_api_404_is_absent_but_403_is_not(self):
        with patch.object(guard, "api_release", self.real_api):
            with patch.object(
                guard.urllib.request, "urlopen",
                side_effect=HTTPError("https://api.github.com", 404, "Not found", {}, None),
            ):
                self.assertIsNone(guard.api_release(TAG, "test-token"))
            with patch.object(
                guard.urllib.request, "urlopen",
                side_effect=HTTPError("https://api.github.com", 403, "Forbidden", {}, None),
            ):
                with self.assertRaisesRegex(guard.PublicationStateError, "authoritative 200/404"):
                    guard.api_release(TAG, "test-token")

    def test_post_publication_main_drift_rejected(self):
        self.main_sha = OTHER
        self.tag = (APPROVED, None)
        self.release = self.expected_release()
        with self.assertRaisesRegex(guard.PublicationStateError, "Remote main moved"):
            guard.execute("after")

    def test_successful_publication_verifies_exact_downloaded_bytes(self):
        self.tag = (APPROVED, None)
        self.release = self.expected_release()
        guard.execute("after")
        self.assertEqual(self.download_called, 1)

    def test_preexisting_tag_points_at_different_approved_commit(self):
        self.tag = (OTHER, None)
        self.release = self.expected_release()
        with self.assertRaisesRegex(guard.PublicationStateError, "Published tag does not resolve"):
            guard.execute("after")

    def test_annotated_tag_peeled_commit_controls_identity(self):
        self.tag = (OTHER, APPROVED)
        self.release = self.expected_release()
        guard.execute("after")

    def test_draft_is_not_a_published_release(self):
        self.tag = (APPROVED, None)
        self.release = self.expected_release()
        self.release["draft"] = True
        with self.assertRaisesRegex(guard.PublicationStateError, "not fully published"):
            guard.execute("after")

    def test_incomplete_asset_set_fails_closed(self):
        self.tag = (APPROVED, None)
        self.release = self.expected_release()
        self.release["assets"].pop()
        with self.assertRaisesRegex(guard.PublicationStateError, "exactly four"):
            guard.execute("after")

    def test_tampered_remote_bytes_fail_even_when_api_claims_correct_digest(self):
        self.tag = (APPROVED, None)
        self.release = self.expected_release()
        self.tamper = f"mcp-gateway-v{VERSION}.zip"
        with self.assertRaisesRegex(guard.PublicationStateError, "Published asset bytes differ"):
            guard.execute("after")

    def test_missing_local_checksum_fails_closed(self):
        self.tag = (APPROVED, None)
        self.release = self.expected_release()
        (self.dist / f"mcp-gateway-v{VERSION}.zip.sha256").write_text("WRONG")
        with self.assertRaisesRegex(guard.PublicationStateError, "checksum companion mismatches"):
            guard.execute("after")

    def test_release_metadata_wrong_target_is_rejected(self):
        self.tag = (APPROVED, None)
        self.release = self.expected_release()
        self.release["target_commitish"] = OTHER
        with self.assertRaisesRegex(guard.PublicationStateError, "identity differs"):
            guard.execute("after")


if __name__ == "__main__":
    unittest.main(verbosity=2)
