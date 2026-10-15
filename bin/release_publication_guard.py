#!/usr/bin/env python3
"""Fail-closed GitHub stable-release identity guard.

"before" refuses any existing tag or Release; no implicit idempotent success.
"reserve" creates the approved Git tag *atomically if absent*, then verifies
its exact target. A competing writer/ambiguous outcome is never auto-retried.
"after" checks exact published tag, metadata, assets and downloaded bytes.
Any partial publication or reserved-only tag requires manual reconciliation.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

REPOSITORY = "AChWorks/mcp-gateway"
ROOT = Path(__file__).resolve().parent.parent
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


class PublicationStateError(RuntimeError):
    pass


def require(ok: bool, why: str) -> None:
    if not ok:
        raise PublicationStateError(why)


def command(*argv: str) -> str:
    try:
        result = subprocess.run(list(argv), check=False, text=True, capture_output=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PublicationStateError(f"Required command unavailable/failed: {argv[0]}") from error
    require(result.returncode == 0, f"Required {argv[0]} operation failed; reconcile external state.")
    return result.stdout.strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def source_envelope() -> tuple[str, str, str, str]:
    env = os.environ
    version = env.get("APPROVED_VERSION", "")
    approved = env.get("APPROVED_SHA", "")
    repo = env.get("GITHUB_REPOSITORY", "")
    require(repo == REPOSITORY, "Publication repository differs from approved scope.")
    require(bool(SHA_PATTERN.fullmatch(approved)), "Invalid approved source SHA.")
    require(bool(VERSION_PATTERN.fullmatch(version)), "Public Release requires a stable version.")
    require(env.get("GITHUB_REF") == "refs/heads/main", "Release workflow did not run on main.")
    require(env.get("GITHUB_SHA") == approved, "Workflow SHA differs from Owner-approved SHA.")
    require((ROOT / "VERSION").read_text().strip() == version, "Tracked VERSION differs from approved stable version.")
    require(command("git", "rev-parse", "HEAD") == approved, "Checked-out Git HEAD differs from approved source.")
    main = command("git", "ls-remote", "--exit-code", "origin", "refs/heads/main").splitlines()
    require(len(main) == 1, "Expected exactly one authoritative remote main ref.")
    parts = main[0].split()
    require(len(parts) == 2 and parts[1] == "refs/heads/main" and parts[0] == approved,
            "Remote main moved or no longer equals Owner-approved source.")
    token = env.get("GH_TOKEN", "")
    require(bool(token), "Missing authenticated GitHub read access.")
    return version, approved, repo, token


def remote_tag(tag: str) -> tuple[str | None, str | None]:
    output = command("git", "ls-remote", "origin", f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}")
    refs: dict[str, str] = {}
    for line in output.splitlines():
        values = line.split()
        require(len(values) == 2 and bool(SHA_PATTERN.fullmatch(values[0])),
                "Malformed tag reference received from remote.")
        require(values[1] in (f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}"),
                "Unexpected tag reference returned.")
        require(values[1] not in refs, "Duplicate remote release tag reference.")
        refs[values[1]] = values[0]
    return refs.get(f"refs/tags/{tag}"), refs.get(f"refs/tags/{tag}^{{}}")


def api_release(tag: str, token: str) -> dict | None:
    url = f"https://api.github.com/repos/{REPOSITORY}/releases/tags/{tag}"
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            require(response.status == 200, "Unexpected release API status.")
            body = response.read(512 * 1024)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise PublicationStateError("Release API did not return an authoritative 200/404 result.") from error
    except (OSError, urllib.error.URLError, TimeoutError) as error:
        raise PublicationStateError("Release API unavailable; do not assume a Release is absent.") from error
    try:
        result = json.loads(body)
    except (ValueError, UnicodeDecodeError) as error:
        raise PublicationStateError("Release API response malformed.") from error
    require(isinstance(result, dict), "Release API returned a non-object.")
    return result


# GitHub must enforce one-time creation but forbid ordinary writers from
# moving/deleting stable release tags. The Owner configures the no-bypass
# policy once; changing that policy later requires an administrator and is
# a separate governance risk, not a per-release attestation ceremony.
RELEASE_TAG_RULESET_INCLUDE = "refs/tags/v*"


def github_ruleset_json(url: str, token: str):
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            require(response.status == 200, "Ruleset API returned an unexpected HTTP status.")
            body = response.read(512 * 1024)
    except (urllib.error.HTTPError, urllib.error.URLError, OSError, TimeoutError) as error:
        raise PublicationStateError(
            "GitHub ruleset policy could not be verified; refuse Release publication."
        ) from error
    try:
        return json.loads(body)
    except (ValueError, UnicodeDecodeError) as error:
        raise PublicationStateError("GitHub ruleset API returned invalid JSON; refuse publication.") from error


def qualifies_as_immutable_release_policy(ruleset: object) -> bool:
    """Require effective GitHub tag-update and deletion protection.

    GitHub withholds bypass_actors from tokens lacking ruleset-write access.
    The Owner must verify an empty bypass list when configuring the rule;
    if a bypass is visible, refuse it. Only administrators can change that
    policy later, and release CI must not hold an admin credential.
    """
    if not isinstance(ruleset, dict):
        return False
    if (ruleset.get("target") != "tag"
            or ruleset.get("source_type") != "Repository"
            or ruleset.get("source") != REPOSITORY
            or ruleset.get("enforcement") != "active"
            or ("bypass_actors" in ruleset and ruleset["bypass_actors"] != [])):
        return False
    conditions = ruleset.get("conditions")
    if not isinstance(conditions, dict):
        return False
    ref_names = conditions.get("ref_name")
    if not isinstance(ref_names, dict):
        return False
    includes = ref_names.get("include")
    if (not isinstance(includes, list)
            or not all(isinstance(item, str) for item in includes)
            or not any(item in (RELEASE_TAG_RULESET_INCLUDE, "~ALL") for item in includes)
            or ref_names.get("exclude") != []):
        return False
    rules = ruleset.get("rules")
    if not isinstance(rules, list) or not all(isinstance(rule, dict) for rule in rules):
        return False
    types = [rule.get("type") for rule in rules]
    return "update" in types and "deletion" in types and "creation" not in types


def require_immutable_release_tag_policy(tag: str, token: str) -> int:
    """Require effective repo-level protection before tag reservation or Release.

    The API includes applicable parent rulesets; only an active repository
    ruleset with no bypass is currently accepted as sufficient evidence.
    Incomplete listings, forbidden reads and malformed data fail closed.
    """
    require(bool(re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag)),
            "Expected an exact stable release tag.")
    base = f"https://api.github.com/repos/{REPOSITORY}/rulesets"
    seen: set[int] = set()
    for page in range(1, 11):
        results = github_ruleset_json(
            f"{base}?includes_parents=true&targets=tag&per_page=100&page={page}",
            token,
        )
        require(isinstance(results, list) and len(results) <= 100,
                "GitHub ruleset listing is incomplete or malformed; refuse publication.")
        for item in results:
            require(isinstance(item, dict) and type(item.get("id")) is int
                    and item["id"] > 0, "GitHub ruleset listing has an invalid ID.")
            ruleset_id = item["id"]
            require(ruleset_id not in seen, "Duplicate GitHub ruleset ID; refuse publication.")
            seen.add(ruleset_id)
            ruleset = github_ruleset_json(f"{base}/{ruleset_id}?includes_parents=true", token)
            if isinstance(ruleset, dict) and ruleset.get("id") == ruleset_id:
                if qualifies_as_immutable_release_policy(ruleset):
                    return ruleset_id
        if len(results) < 100:
            break
    else:
        raise PublicationStateError("GitHub ruleset listing exceeds verified pagination bound.")
    raise PublicationStateError(
        "No active immutable stable-tag ruleset was verified. The Owner must "
        "configure refs/tags/v* with Restrict updates/deletions, allow creations, "
        "and verify an empty bypass list once in GitHub repository settings."
    )


def create_tag_once(tag: str, approved: str, token: str) -> None:
    """Atomically create a lightweight GitHub tag, without overwrite/retry.

    The REST Create a Reference endpoint is create-only: if another writer
    wins the tag name (409/422), no subsequent Release is attempted.
    """
    ref = f"refs/tags/{tag}"
    request = urllib.request.Request(
        f"https://api.github.com/repos/{REPOSITORY}/git/refs",
        data=json.dumps({"ref": ref, "sha": approved}, separators=(",", ":")).encode("utf-8"),
        method="POST",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            require(response.status == 201, "Uncertain tag reservation response; manual reconciliation required.")
            body = response.read(128 * 1024)
    except urllib.error.HTTPError as error:
        if error.code in (409, 422):
            raise PublicationStateError(
                "Atomic tag reservation was rejected or lost a concurrent writer race; "
                "do not publish or retry; reconcile the existing tag/Release."
            ) from error
        raise PublicationStateError(
            "GitHub tag reservation failed; state may be partial; reconcile without retry."
        ) from error
    except (OSError, urllib.error.URLError, TimeoutError) as error:
        raise PublicationStateError(
            "GitHub tag reservation outcome unknown; check remote tag/Release manually, "
            "never auto-retry the create."
        ) from error
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError) as error:
        raise PublicationStateError(
            "Tag reservation response invalid after possible creation; reconcile manually."
        ) from error
    require(
        isinstance(data, dict)
        and data.get("ref") == ref
        and isinstance(data.get("object"), dict)
        and data["object"].get("type") == "commit"
        and data["object"].get("sha") == approved,
        "Tag creation response not proven to bind the approved commit; reconcile manually.",
    )


def local_assets(version: str) -> dict[str, tuple[Path, str, int]]:
    base = f"mcp-gateway-v{version}.zip"
    update = f"mcp-gateway-update-v{version}.zip"
    files: dict[str, tuple[Path, str, int]] = {}
    for name in (base, update):
        archive = ROOT / "dist" / name
        checksum_file = ROOT / "dist" / (name + ".sha256")
        require(archive.is_file() and checksum_file.is_file(), f"Missing verified local Release asset: {name}")
        checksum = sha256(archive)
        require(archive.stat().st_size > 0, f"Empty Release package: {name}")
        require(checksum_file.read_text() == f"{checksum}  {name}\n",
                f"Release checksum companion mismatches its ZIP: {name}")
        files[name] = (archive, checksum, archive.stat().st_size)
        files[name + ".sha256"] = (checksum_file, sha256(checksum_file), checksum_file.stat().st_size)
    return files


def verify_remote_assets(release: dict, tag: str, version: str, repo: str) -> None:
    expected = local_assets(version)
    assets = release.get("assets")
    require(isinstance(assets, list), "Release assets missing.")
    names = [item.get("name") for item in assets if isinstance(item, dict)]
    require(len(names) == 4 and len(set(names)) == 4 and set(names) == set(expected),
            "Published Release must have exactly four expected package/checksum assets.")
    for item in assets:
        name = item["name"]
        _, digest, size = expected[name]
        require(item.get("state") == "uploaded" and item.get("size") == size,
                f"Published asset is missing, incomplete or wrong-sized: {name}")
        digest_value = item.get("digest")
        require(digest_value in (None, f"sha256:{digest}"), f"Published asset digest mismatch: {name}")
    # Metadata may lack digest on older API paths. Independently download and
    # compare exact ZIP and checksum-companion bytes, never trust a name alone.
    with tempfile.TemporaryDirectory(prefix="gateway-published-release-") as destination:
        command("gh", "release", "download", tag, "--repo", repo, "--dir", destination)
        actual = {p.name for p in Path(destination).iterdir() if p.is_file()}
        require(actual == set(expected), "Downloaded assets differ from exactly four approved files.")
        for name, (path, digest, _) in expected.items():
            require(sha256(Path(destination) / name) == digest and sha256(path) == digest,
                    f"Published asset bytes differ from locally checked release output: {name}")


def execute(phase: str) -> None:
    require(phase in ("before", "reserve", "after"), "Expected release guard phase: before | reserve | after.")
    version, approved, repo, token = source_envelope()
    tag = f"v{version}"
    require_immutable_release_tag_policy(tag, token)
    raw, peeled = remote_tag(tag)
    release = api_release(tag, token)
    if phase in ("before", "reserve"):
        require(raw is None and peeled is None, "Release tag already exists; reconcile before publication.")
        require(release is None, "Same-tag Release already exists; never silently treat it as published.")
        if phase == "before":
            print(f"PASS: {tag} has no existing remote tag/Release and main equals approved SHA.")
            return

        # The only tag-creation operation in this workflow. GitHub's POST
        # /git/refs rejects an existing ref atomically (never updates it).
        # Do not retry on ambiguous failure: a tag-only reservation is
        # intentional partial state that requires explicit reconciliation.
        create_tag_once(tag, approved, token)
        raw, peeled = remote_tag(tag)
        require(raw == approved and peeled is None,
                "Reserved Git tag does not resolve directly to approved SHA; do not publish.")
        require(api_release(tag, token) is None,
                "A Release appeared during tag reservation; refuse publication.")
        print(f"PASS: reserved {tag} exclusively at approved SHA; Release still absent.")
        return

    require(raw is not None, "Published release tag is missing.")
    require(raw == approved and peeled is None,
            "Published lightweight tag does not resolve directly to approved SHA.")
    require(release is not None, "Release does not exist after publication.")
    require(release.get("tag_name") == tag and release.get("target_commitish") == approved,
            "Release tag name or target identity differs from approved source.")
    require(release.get("name") == f"MCP Gateway {tag}", "Release title differs from approved identity.")
    require(release.get("draft") is False and release.get("prerelease") is False
            and bool(release.get("published_at")), "Release not fully published as stable.")
    verify_remote_assets(release, tag, version, repo)
    print(f"PASS: published {tag} resolves to approved source with four byte-verified official assets.")


def main() -> None:
    try:
        require(len(sys.argv) == 2, "Usage: release_publication_guard.py before|reserve|after")
        execute(sys.argv[1])
    except (PublicationStateError, OSError) as error:
        print(f"Release publication guard FAILED: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
