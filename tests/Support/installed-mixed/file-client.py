#!/usr/bin/env python3
"""Independent, stdlib-only HTTP/MCP + streaming binary consumer.

Runs against the REAL installed Gateway HTTPS endpoint in disposable netns.
Not a ChatGPT host test. No PHP SDK, Guzzle, or project runtime imported.
"""
import base64
import hashlib
import http.client
import json
import os
import shlex
import ssl
import tempfile
import time
from pathlib import Path

root = Path(os.environ["MIXED_ROOT"])
state = json.loads((root / "secrets/state.json").read_text())
ssh_user = os.environ["MIXED_SSH_USER"]
host = "11.22.33.45"
target = state["ssh_target"]
token = state["owner_token"]
endpoint = f"/mcp/file-transfer/ssh/{target}"
context = ssl.create_default_context(cafile=str(root / "secrets/tls.crt"))
assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname


def connect():
    return http.client.HTTPSConnection(host, 443, context=context, timeout=40)


def mcp(method, params=None):
    body = json.dumps({"jsonrpc": "2.0", "id": 10, "method": method,
                       **({"params": params} if params is not None else {})},
                      separators=(",", ":")).encode()
    conn = connect()
    try:
        conn.request("POST", "/mcp", body=body, headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2025-11-25",
        })
        response = conn.getresponse()
        raw = response.read(1048576)
        assert response.status == 200, (method, response.status, raw[:200])
        content_type = response.getheader("Content-Type", "")
        if "text/event-stream" in content_type:
            events = [
                json.loads(line[5:].strip())
                for line in raw.decode().splitlines() if line.startswith("data:")
            ]
            assert len(events) == 1, (method, "unexpected SSE result count")
            payload = events[0]
        else:
            payload = json.loads(raw)
        assert "error" not in payload, (method, "JSON-RPC error")
        return payload["result"]
    finally:
        conn.close()


def require(test, message):
    if not test:
        raise AssertionError(message)


tools = mcp("tools/list")
names = [tool["name"] for tool in tools["tools"]]
require("ssh-file-stat" in names and "ssh-command-run" in names,
        "independent MCP client did not negotiate Gateway SSH tools")
start = time.monotonic()
remote = f"/home/{ssh_user}/python-whole-file-{os.urandom(6).hex()}.bin"
payload = bytes(range(256)) * 4097 + b"\\x00\\xff"
expected_bytes = len(payload)
expected_sha = hashlib.sha256(payload).hexdigest()

with tempfile.TemporaryDirectory(prefix="whole-file-python-", dir=str(root / "client")) as temporary:
    local = Path(temporary) / "generated.bin"
    local.write_bytes(payload)
    metadata = {
        "path": remote,
        "private_staging_dir": f"/home/{ssh_user}/.gateway-transfer-private",
        "size": expected_bytes,
        "sha256": expected_sha,
        "overwrite": False,
    }
    header = base64.urlsafe_b64encode(
        json.dumps(metadata, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    conn = connect()
    try:
        conn.putrequest("POST", endpoint + "/upload")
        conn.putheader("Authorization", "Bearer " + token)
        conn.putheader("Content-Type", "application/octet-stream")
        conn.putheader("X-Gateway-Metadata", header)
        conn.putheader("Content-Length", str(expected_bytes))
        conn.endheaders()
        with local.open("rb") as source:
            while chunk := source.read(32768):
                conn.send(chunk)
        response = conn.getresponse()
        body = response.read(4096)
        require(response.status == 201, f"Python upload rejected: {response.status} {body[:120]!r}")
        result = json.loads(body)
        require(result["sha256"] == expected_sha, "upload SHA parity")
    finally:
        conn.close()

    try:
        stat = mcp("tools/call", {"name": "ssh-file-stat", "arguments": {
            "target_id": target, "path": remote,
        }})
        details = stat.get("structuredContent", {})
        require(details["result"]["file"]["size"] == expected_bytes,
                "MCP SDK-independent stat parity")

        conn = connect()
        try:
            conn.request("POST", endpoint + "/download", body=json.dumps({
                "path": remote, "expected_sha256": expected_sha,
            }).encode(), headers={
                "Authorization": "Bearer " + token, "Content-Type": "application/json"
            })
            response = conn.getresponse()
            require(response.status == 200, f"Python download rejected: {response.status}")
            require(response.getheader("X-Gateway-File-SHA256") == expected_sha,
                    "returned HTTP digest")
            require(response.getheader("Content-Length") == str(expected_bytes),
                    "returned content length")
            downloaded = Path(temporary) / "received.bin"
            with downloaded.open("wb") as sink:
                while chunk := response.read(32768):
                    sink.write(chunk)
        finally:
            conn.close()

        require(downloaded.stat().st_size == expected_bytes, "actual saved client file size")
        digest = hashlib.sha256()
        with downloaded.open("rb") as source:
            while chunk := source.read(32768):
                digest.update(chunk)
        require(digest.hexdigest() == expected_sha, "actual saved client file integrity")

        conn = connect()
        try:
            conn.request("POST", endpoint + "/download", body=b'{"path":"' +
                         remote.encode() + b'"}', headers={
                             "Authorization": "Bearer invalid", "Content-Type": "application/json"
                         })
            response = conn.getresponse()
            require(response.status == 401, "invalid bearer downloaded file")
            response.read(2048)
        finally:
            conn.close()
    finally:
        outcome = mcp("tools/call", {"name": "ssh-command-run", "arguments": {
            "target_id": target, "command": "rm -f -- " + shlex.quote(remote),
        }})
        require(outcome.get("structuredContent", {}).get("ok") is True,
                "remote disposable cleanup not confirmed")

print(json.dumps({
    "outcome": "PASS",
    "client": "independent Python 3 standard HTTPS + JSON-RPC MCP, no PHP SDK",
    "incoming": "file streaming in 32768-byte blocks over verified HTTPS",
    "outgoing": "binary HTTP stream saved as an actual client-side disk file",
    "bytes": expected_bytes,
    "sha256": expected_sha,
    "roundtrip_ms": round((time.monotonic() - start) * 1000, 2),
    "model_consumed": False,
    "tls_verified": True,
}, indent=2))
