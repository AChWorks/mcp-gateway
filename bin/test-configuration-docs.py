#!/usr/bin/env python3
"""Fail if the public first-party environment contract drifts from its consumers.

This scans real Gateway PHP config/runtime and the installed recovery/installer
entrypoints, not vendor packages or fixture/test code. Unsupported Laravel
scaffold adapters are explicit exclusions, not silently skipped entire trees.
Every supported active/commented key needs one canonical docs row.
"""
from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / ".env.example"
DOC = ROOT / "docs" / "CONFIGURATION.md"

# Referenced by Laravel's stock scaffold, but unusable as standalone Gateway
# settings without unsupported adapters, dependencies, alternate models,
# additional user-facing contracts or a separate reviewed deployment profile.
# Do not add these to the operator template merely to satisfy a key counter.
UNSUPPORTED = {
    "authentication-driver-not-configurable": {
        "AUTH_GUARD", "AUTH_MODEL", "AUTH_PASSWORD_BROKER",
        "AUTH_PASSWORD_RESET_TOKEN_TABLE", "AUTH_PASSWORD_TIMEOUT",
    },
    "missing-aws-and-sqs-transport-dependencies": {
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_DEFAULT_REGION",
        "AWS_BUCKET", "AWS_ENDPOINT", "AWS_URL",
        "AWS_USE_PATH_STYLE_ENDPOINT", "SQS_PREFIX", "SQS_QUEUE", "SQS_SUFFIX",
    },
    "missing-beanstalkd-adapter": {
        "BEANSTALKD_QUEUE", "BEANSTALKD_QUEUE_HOST", "BEANSTALKD_QUEUE_RETRY_AFTER",
    },
    "missing-dynamodb-adapter": {"DYNAMODB_CACHE_TABLE", "DYNAMODB_ENDPOINT"},
    "non-baseline-postgres-driver": {"DB_SSLMODE"},
    "missing-mail-provider-transports": {"POSTMARK_API_KEY", "RESEND_API_KEY"},
    "unused-slack-bot-service-scaffold": {
        "SLACK_BOT_USER_DEFAULT_CHANNEL", "SLACK_BOT_USER_OAUTH_TOKEN",
    },
}

KEY_PATTERN = re.compile(r"^(?:#\s*)?([A-Z][A-Z0-9_]*)=", re.MULTILINE)
ACTIVE_PATTERN = re.compile(r"^([A-Z][A-Z0-9_]*)=", re.MULTILINE)
CONSUMER_PATTERN = re.compile(r"\benv\(\s*['\"]([A-Z][A-Z0-9_]*)['\"]")
DOC_ROW_PATTERN = re.compile(r"^\|\s*`([A-Z][A-Z0-9_]*)`\s*\|", re.MULTILINE)


def source_consumers() -> set[str]:
    references: set[str] = set()
    for folder in ("app", "config", "bootstrap", "routes", "database"):
        for path in (ROOT / folder).rglob("*.php"):
            source = path.read_text()
            # Ignore *commented-out* stock example config, not executable
            # Laravel env() expressions; support multiline PHP calls.
            source = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
            source = re.sub(r"^\s*//[^\n]*(?:\n|$)", "", source, flags=re.MULTILINE)
            references.update(CONSUMER_PATTERN.findall(source))

    # The installer writes these overriding settings from its approved
    # literal values array; they remain first-party even if Laravel config
    # stops directly referencing one of them in the future.
    installer = (ROOT / "app/Support/SimpleWebInstaller.php").read_text()
    method = installer.split("function buildEnvironment(", 1)[1]
    values = method.split("$values = [", 1)[1].split("];", 1)[0]
    references.update(re.findall(r"['\"]([A-Z][A-Z0-9_]*)['\"]\s*=>", values))

    # The *installed* emergency recovery CLI also consumes process-level
    # DB identity override names and a disposable-only test loopback knob.
    # The rest of bin/ contains release/CI fixtures, not installed .env API.
    recovery = (ROOT / "bin/mcp-gateway-web-recovery.php").read_text()
    references.update(re.findall(r"\bgetenv\(\s*['\"]([A-Z][A-Z0-9_]*)['\"]", recovery))
    fence = re.search(
        r"foreach\s*\(\s*\[(.*?)\]\s*as\s*\$name\s*\)",
        recovery,
        re.DOTALL,
    )
    if not fence:
        raise ValueError("Recovery DB override identity fence is no longer recognizable")
    references.update(re.findall(r"['\"]([A-Z][A-Z0-9_]*)['\"]", fence.group(1)))
    return references


def main() -> int:
    example = EXAMPLE.read_text()
    reference = DOC.read_text()
    readme = (ROOT / "README.md").read_text()
    deployment = (ROOT / "docs/DEPLOYMENT.md").read_text()
    errors: list[str] = []

    keys = KEY_PATTERN.findall(example)
    count = Counter(keys)
    for k, n in sorted(count.items()):
        if n != 1:
            errors.append(f"duplicate active/commented .env.example key {k}: {n}")
    active = set(ACTIVE_PATTERN.findall(example))
    template_keys = set(keys)
    begin = "## Complete `.env.example` key reference"
    end = "## Operational cautions"
    if reference.count(begin) != 1 or reference.count(end) != 1:
        errors.append("configuration reference inventory section delimiters changed")
        documented = []
    else:
        catalog = reference.split(begin, 1)[1].split(end, 1)[0]
        documented = DOC_ROW_PATTERN.findall(catalog)
    docs_count = Counter(documented)
    for k, n in sorted(docs_count.items()):
        if n != 1:
            errors.append(f"duplicate configuration reference key {k}: {n}")
    for k in sorted(template_keys - set(documented)):
        errors.append(f"template key not documented: {k}")
    for k in sorted(set(documented) - template_keys):
        errors.append(f"documented key absent from template: {k}")

    all_exclusions = [k for group in UNSUPPORTED.values() for k in group]
    excluded = set(all_exclusions)
    if len(all_exclusions) != len(excluded):
        errors.append("duplicate exclusions in unsupported config-key groups")

    try:
        source = source_consumers()
    except (ValueError, IndexError) as e:
        errors.append(f"first-party environment-source scan unavailable: {e}")
        source = set()

    for k in sorted(source - template_keys - excluded):
        errors.append(f"consumed first-party setting missing from template/docs: {k}")
    for k in sorted(template_keys - source):
        errors.append(f"unconsumed/unsupported template key: {k}")
    for k in sorted(excluded & template_keys):
        errors.append(f"unsupported scaffold key was advertised in template: {k}")
    for k in sorted(excluded - source):
        errors.append(f"stale explicit unsupported-key exception: {k}")

    if "docs/CONFIGURATION.md" not in readme:
        errors.append("README does not link canonical configuration guide")
    if "(CONFIGURATION.md)" not in deployment:
        errors.append("deployment does not link canonical configuration guide")

    # The template is safe for *local HTTP*, while fresh production installer
    # forces secure HTTPS cookies. Do not silently enable reverse proxy trust.
    expected_active = {
        "SESSION_LIFETIME": "120",
        "SESSION_EXPIRE_ON_CLOSE": "false",
        "SESSION_HTTP_ONLY": "true",
        "SESSION_SAME_SITE": "lax",
        "OAUTH_ACCESS_TOKEN_TTL_SECONDS": "3600",
        "SSH_FILE_TRANSFER_ENABLED": "true",
        "SSH_FILE_TRANSFER_MAX_BYTES": "8388608",
        "SSH_FILE_TRANSFER_MAX_SECONDS": "30",
        "SSH_VERIFY_MAX_ATTEMPTS_PER_MINUTE": "6",
        "SSH_VERIFY_DECAY_SECONDS": "60",
        "SSH_VERIFY_LEASE_SECONDS": "30",
    }
    for key, value in expected_active.items():
        if f"{key}={value}" not in example.splitlines():
            errors.append(f"unsafe/missing active source template value: {key}")
    for key in ("SESSION_SECURE_COOKIE", "SESSION_COOKIE", "GATEWAY_TRUSTED_PROXIES"):
        if key in active:
            errors.append(f"context-sensitive key must stay commented by default: {key}")
        if key not in template_keys:
            errors.append(f"context-sensitive documented example missing: {key}")
    for key in (
        "APP_PREVIOUS_KEYS",
        "DB_URL",
        "MYSQL_ATTR_SSL_CA",
        "MAIL_PASSWORD",
        "REDIS_PASSWORD",
        "GATEWAY_TARGET_RESET_ACKNOWLEDGED",
        "GATEWAY_TARGET_RESET_DATABASE_BACKUP_VERIFIED",
        "MCP_GATEWAY_RECOVERY_TEST_LOOPBACK",
    ):
        if key in active:
            errors.append(f"sensitive/rare key accidentally active: {key}")

    installer = (ROOT / "app/Support/SimpleWebInstaller.php").read_text()
    if not re.search(r"'SSH_FILE_TRANSFER_ENABLED'\s*=>\s*'true'", installer):
        errors.append("fresh web installer must explicitly enable SSH whole-file flag")
    if not re.search(r"'SESSION_SECURE_COOKIE'\s*=>\s*'true'", installer):
        errors.append("production web installer must force secure session cookie")
    ssh_config = (ROOT / "config/ssh.php").read_text()
    if not re.search(r"env\('SSH_FILE_TRANSFER_ENABLED',\s*false\)", ssh_config):
        errors.append("legacy absent-key SSH whole-file fallback must remain false")

    if errors:
        for error in errors:
            print("CONFIG CONTRACT ERROR: " + error, file=sys.stderr)
        return 1

    print(
        f"Configuration contract: PASS ({len(template_keys)} first-party keys "
        f"= {len(active)} active + {len(template_keys) - len(active)} commented; "
        f"{len(source)} source consumers, {len(excluded)} justified exclusions)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
