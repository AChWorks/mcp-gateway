#!/usr/bin/python3
"""Real peer enrollment acceptance on an explicitly disposable Linux/systemd VM.

This fixture never contacts an external destination. Its public-looking Target
addresses are routed exclusively to task-owned local network namespaces. Run only
on a disposable CI runner or an isolated task VM, never an operator's host.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import shlex
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import unittest


def command(argv, *, check=True, timeout=20, input=None):
    result = subprocess.run([str(x) for x in argv], capture_output=True, text=True,
                            input=input, timeout=timeout, check=False)
    if check and result.returncode:
        raise RuntimeError("Command failed: " + shlex.join([str(x) for x in argv])
                           + "\n" + result.stdout[-1800:] + result.stderr[-1800:])
    return result


def read_exact(stream, length):
    value = bytearray()
    while len(value) < length:
        part = stream.recv(length - len(value))
        if not part:
            raise OSError("SOCKS connection closed before complete response")
        value.extend(part)
    return bytes(value)


def socks_connect(port, address, target_port, timeout=3):
    stream = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        stream.sendall(b"\x05\x01\x00")
        if read_exact(stream, 2) != b"\x05\x00":
            raise OSError("Unexpected SOCKS authentication response")
        ip = ipaddress.ip_address(address)
        stream.sendall(b"\x05\x01\x00" + bytes([1 if ip.version == 4 else 4])
                       + ip.packed + struct.pack("!H", target_port))
        reply = read_exact(stream, 4)
        if reply[0] != 5 or reply[1] != 0:
            raise OSError("SOCKS CONNECT refused: " + reply.hex())
        if reply[3] == 1:
            read_exact(stream, 6)
        elif reply[3] == 4:
            read_exact(stream, 18)
        else:
            raise OSError("Unexpected SOCKS address response")
        return stream
    except BaseException:
        stream.close()
        raise


def proxy(port, address, target_port):
    import select
    stream = socks_connect(port, address, target_port, 10)
    stream.settimeout(None)
    try:
        stdin_open = True
        while True:
            readers = [stream] + ([sys.stdin.buffer] if stdin_open else [])
            ready, _, _ = select.select(readers, [], [], 20)
            if not ready:
                raise OSError("Bounded fixture proxy idle timeout")
            for source in ready:
                if source is stream:
                    block = stream.recv(65536)
                    if not block:
                        return
                    sys.stdout.buffer.write(block)
                    sys.stdout.buffer.flush()
                else:
                    block = os.read(sys.stdin.fileno(), 65536)
                    if not block:
                        stdin_open = False
                        stream.shutdown(socket.SHUT_WR)
                    else:
                        stream.sendall(block)
    finally:
        stream.close()


def https_server(cert, key, ipv6=False, port=443, bind=None):
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Response(BaseHTTPRequestHandler):
        def do_GET(self):
            payload = b"relay-peer-real-https-target\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_):
            pass

    if ipv6:
        class V6Server(HTTPServer):
            address_family = socket.AF_INET6

            def server_bind(self):
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                super().server_bind()
        server = V6Server((bind or "::", port), Response)
    else:
        server = HTTPServer((bind or "0.0.0.0", port), Response)
    if cert is not None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


class PeerOsAcceptance(unittest.TestCase):
    helper_source: Path
    base: Path
    peers: list
    targets: list
    processes: list
    handles: list

    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0 or os.environ.get("MCP_RELAY_DISPOSABLE_OS_TEST") != "1":
            raise RuntimeError("Requires root and explicit disposable-OS fixture authorization")
        if not Path("/run/systemd/system").is_dir():
            raise RuntimeError("Real systemd is required")
        for tool in ("ip", "nft", "sshd", "ssh", "sftp", "ssh-keygen", "openssl", "systemctl", "nsenter"):
            if not shutil.which(tool):
                raise RuntimeError("Missing fixture prerequisite: " + tool)
        # StrictModes validates every authorized_keys ancestor, so a private
        # child of a world-writable /tmp or /var/tmp is not an SSH-safe root.
        cls.base = Path(tempfile.mkdtemp(prefix="mcp-relay-peer-os-", dir="/var/lib"))
        cls.base.chmod(0o700)
        cls.peers, cls.targets, cls.processes, cls.handles = [], [], [], []
        cls.local_public_added = False
        cls.installed_helper_created = False
        cls.helper_directory_created = False
        cls.addClassCleanup(cls.cleanup)
        cls.shared_sshd = Path("/etc/ssh/sshd_config").read_bytes()
        cls.helper = Path("/usr/local/libexec/mcp-gateway-relay-peer/connection-relay-peer.py")
        source_bytes = cls.helper_source.read_bytes()
        cls.helper_sha256 = hashlib.sha256(source_bytes).hexdigest()
        for directory in (Path("/usr/local/libexec"), cls.helper.parent):
            if not directory.exists():
                directory.mkdir(mode=0o700 if directory == cls.helper.parent else 0o755)
                if directory == cls.helper.parent:
                    cls.helper_directory_created = True
            info = directory.lstat()
            if directory.is_symlink() or not directory.is_dir() or info.st_uid != 0 or info.st_mode & 0o022:
                raise RuntimeError("Unsafe installed helper directory")
        with cls.helper.open("xb") as published:
            published.write(source_bytes)
        cls.installed_helper_created = True
        cls.helper.chmod(0o500)
        cls.script = cls.base / "fixture.py"
        shutil.copyfile(Path(__file__), cls.script)
        cls.script.chmod(0o500)
        cls.keypair(cls.base / "target-client")
        cls.keypair(cls.base / "wrong-key")
        for index in range(2):
            cls.target(index)
        command(["ip", "addr", "add", "8.8.4.240/32", "dev", "lo"])
        cls.local_public_added = True
        directory = cls.targets[0]["directory"]
        for family, address in (("4", "127.0.0.1"), ("6", "::1"), ("4", "8.8.4.240")):
            proc = cls.spawn(["/usr/bin/python3", "-I", cls.script, "https",
                              str(directory / "tls.crt"), str(directory / "tls.key"), family, address], "local-https-" + address.replace(":", "_"))
            cls.wait_port(address, 443, proc)
        for index in range(2):
            cls.peer(index)

    @classmethod
    def keypair(cls, path):
        command(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", path])

    @classmethod
    def spawn(cls, argv, label):
        log = open(cls.base / (label + ".log"), "wb")
        cls.handles.append(log)
        proc = subprocess.Popen([str(x) for x in argv], stdout=log, stderr=log,
                                stdin=subprocess.DEVNULL)
        cls.processes.append(proc)
        return proc

    @staticmethod
    def wait_port(host, port, proc=None):
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if proc is not None and proc.poll() is not None:
                raise RuntimeError("Fixture process exited before socket readiness")
            try:
                with socket.create_connection((host, port), timeout=.3):
                    return
            except OSError:
                time.sleep(.1)
        raise RuntimeError("Fixture listener did not become ready: " + host + ":" + str(port))

    @classmethod
    def target(cls, index):
        tag = "a" if index == 0 else "b"
        ns, outer, inner = "mcp-rp-284-" + tag, "mrp284" + tag, "mrp284" + tag + "p"
        if command(["ip", "netns", "list"], check=False).stdout.find(ns) >= 0:
            raise RuntimeError("Foreign fixture network namespace already exists")
        for interface in (outer, inner):
            if command(["ip", "link", "show", "dev", interface], check=False).returncode == 0:
                raise RuntimeError("Foreign fixture network interface already exists: " + interface)
        directory = cls.base / ("target-" + tag)
        directory.mkdir()
        target = {"ns": ns, "outer": outer, "directory": directory,
                  "ip4": "8.8.8." + str(240 + index),
                  "ip6": "2606:4700:4700::" + str(2840 + index),
                  "private4": "10.28." + str(index + 1) + ".2",
                  "private6": "fd42:284:" + tag + "::22", "tag": tag,
                  "ns_inode": None, "outer_ifindex": None}
        cls.targets.append(target)
        command(["ip", "netns", "add", ns])
        info = Path("/run/netns", ns).stat()
        target["ns_inode"] = (info.st_dev, info.st_ino)
        command(["ip", "link", "add", outer, "type", "veth", "peer", "name", inner])
        target["outer_ifindex"] = json.loads(command(["ip", "-j", "link", "show", "dev", outer]).stdout)[0]["ifindex"]
        command(["ip", "link", "set", inner, "netns", ns])
        command(["ip", "addr", "add", "169.254." + str(240 + index) + ".1/30", "dev", outer])
        command(["ip", "-6", "addr", "add", "fd42:284:" + tag + "::1/64", "dev", outer, "nodad"])
        command(["ip", "link", "set", outer, "up"])
        # Enter only the network namespace. ip -n/netns exec also remounts
        # /sys, which is unnecessary here and unavailable in an unprivileged
        # Incus container; netlink and the real packet path need no remount.
        ip = ["nsenter", "--net=/run/netns/" + ns, "--", "ip"]
        command(ip + ["link", "set", "lo", "up"])
        command(ip + ["link", "set", inner, "up"])
        command(ip + ["addr", "add", "169.254." + str(240 + index) + ".2/30", "dev", inner])
        command(ip + ["-6", "addr", "add", "fd42:284:" + tag + "::2/64", "dev", inner, "nodad"])
        target["negative4"] = [target["private4"]]
        target["negative6"] = [target["private6"]]
        if index == 0:
            target["negative4"] += ["169.254.169.254", "100.64.28.4", "192.0.2.84", "192.168.28.4"]
            target["negative6"] += ["2001:db8::284", "64:ff9b:1::284", "3fff::284"]
        for addr in [target["ip4"]] + target["negative4"]:
            command(ip + ["addr", "add", addr + "/32", "dev", "lo"])
            command(["ip", "route", "add", addr + "/32", "via", "169.254." + str(240 + index) + ".2", "dev", outer])
        for addr in [target["ip6"]] + target["negative6"]:
            command(ip + ["-6", "addr", "add", addr + "/128", "dev", "lo", "nodad"])
            command(["ip", "-6", "route", "add", addr + "/128", "via", "fd42:284:" + tag + "::2", "dev", outer])
        cls.keypair(directory / "host-key")
        (directory / "authorized_keys").write_bytes((cls.base / "target-client.pub").read_bytes())
        (directory / "authorized_keys").chmod(0o600)
        conf = ("Port 22\nListenAddress 0.0.0.0\nListenAddress ::\n"
                + "HostKey " + str(directory / "host-key") + "\n"
                + "PidFile " + str(directory / "sshd.pid") + "\n"
                + "AuthorizedKeysFile " + str(directory / "authorized_keys") + "\n"
                + "AuthenticationMethods publickey\nPasswordAuthentication no\n"
                + "KbdInteractiveAuthentication no\nUsePAM yes\nPermitRootLogin prohibit-password\n"
                + "StrictModes yes\nAllowUsers root\nUseDNS no\nSubsystem sftp internal-sftp\n")
        (directory / "sshd_config").write_text(conf)
        Path("/run/sshd").mkdir(mode=0o755, exist_ok=True)
        proc = cls.spawn(["nsenter", "--net=/run/netns/" + ns, "--", "/usr/sbin/sshd", "-D", "-e", "-f", directory / "sshd_config"], "target-" + tag)
        cls.wait_port(target["ip4"], 22, proc)
        known = "target-" + tag + " " + (directory / "host-key.pub").read_text()
        (directory / "known_hosts").write_text(known)
        (directory / "wrong_known_hosts").write_text("target-" + tag + " " + (cls.base / "wrong-key.pub").read_text())
        command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                 "-keyout", directory / "tls.key", "-out", directory / "tls.crt",
                 "-subj", "/CN=relay-target.test", "-addext", "subjectAltName=DNS:relay-target.test"])
        tls = cls.spawn(["nsenter", "--net=/run/netns/" + ns, "--", "/usr/bin/python3", "-I", cls.script,
                         "https", str(directory / "tls.crt"), str(directory / "tls.key")], "tls-" + tag)
        cls.wait_port(target["ip4"], 443, tls)
        tls6 = cls.spawn(["nsenter", "--net=/run/netns/" + ns, "--", "/usr/bin/python3", "-I", cls.script,
                          "https", str(directory / "tls.crt"), str(directory / "tls.key"), "6"], "tls6-" + tag)
        cls.wait_port(target["ip6"], 443, tls6)
        http = cls.spawn(["nsenter", "--net=/run/netns/" + ns, "--", "/usr/bin/python3", "-I", cls.script, "http"], "http-" + tag)
        cls.wait_port(target["ip4"], 80, http)

    @classmethod
    def peer(cls, index):
        # Action/argument mapping is kept in one place so the fixture exercises
        # the installed public CLI rather than calling helper internals.
        tag = "a" if index == 0 else "b"
        root = cls.base / ("peer-" + tag)
        root.mkdir()
        # Each execution has a fresh canonical record; durable retirement
        # tombstones intentionally survive until this disposable OS is removed.
        record = "01" + os.urandom(12).hex().upper()
        peer = {"tag": tag, "root": root, "record": record, "relay": "os-peer-" + tag,
                "port": 45881 + index, "socks": 46881 + index, "user": "mcp-rp-os-" + tag,
                "bind": "127.0.0.1" if index == 0 else "::1",
                "unit": None, "table": None}
        cls.peers.append(peer)
        cls.keypair(root / "control-key")
        cls.keypair(root / "host-key")
        public = (root / "control-key.pub").read_text().strip()
        host_public = (root / "host-key.pub").read_text().strip()
        peer["host_key"] = host_public
        peer["host_key_fingerprint"] = "SHA256:" + base64.b64encode(
            hashlib.sha256(base64.b64decode(host_public.split()[1])).digest()).decode().rstrip("=")
        peer["input"] = root / "public-export.txt"
        peer["input"].write_text("\n".join([
            "PUBLIC ONLY - OFFLINE RELAY PEER ENROLLMENT INPUT V2",
            "Relay: " + peer["relay"], "Record: " + record,
            "Configuration revision: 1", "Host fingerprint: " + ("a" if index == 0 else "c") * 64,
            "Host generation: " + os.urandom(32).hex(),
            "Control endpoint: " + ("127.0.0.1" if index == 0 else "0:0:0:0:0:0:0:1") + ":" + str(peer["port"]),
            "Control user on Relay peer: " + peer["user"],
            "Ed25519 PUBLIC KEY (never copy the private key):", public,
            "NOT ENROLLED. Restrict Relay peer SSHD forwarding and public egress separately; "
            "verify both hosts and issue independent readiness before enabling.", ""]))
        (root / "known_hosts").write_text("[" + peer["bind"] + "]:" + str(peer["port"]) + " " + host_public + "\n")
        cls.helper_action(peer, "stage")
        units = set(Path("/etc/systemd/system").glob("*.service"))
        tables = cls.nft_tables()
        try:
            cls.helper_action(peer, "setup")
        finally:
            new_units = set(Path("/etc/systemd/system").glob("*.service")) - units
            if len(new_units) == 1:
                unit = new_units.pop()
                if record in unit.read_text() and "/usr/sbin/sshd" in unit.read_text():
                    peer["unit"] = unit.name
            new_tables = cls.nft_tables() - tables
            if len(new_tables) == 1:
                peer["table"] = new_tables.pop()
        if peer["unit"] is None or peer["table"] is None:
            raise RuntimeError("Setup did not create exactly one independently owned peer service and inet table")
        cls.start_client(peer)

    @staticmethod
    def nft_tables():
        document = json.loads(command(["nft", "-j", "list", "tables"]).stdout)
        return {item["table"]["name"] for item in document["nftables"]
                if "table" in item and item["table"].get("family") == "inet"}

    @classmethod
    def helper_action(cls, peer, action, *, check=True):
        argv = ["/usr/bin/python3", "-I", cls.helper, action, "--input", peer["input"]]
        if action == "setup":
            argv += ["--bind-address", peer["bind"], "--host-key", peer["root"] / "host-key",
                     "--host-key-fingerprint", peer["host_key_fingerprint"]]
            for port in peer.get("allowed_ports", (22, 443)):
                argv += ["--allow-port", str(port)]
        return command(argv, check=check, timeout=35)

    @classmethod
    def client_args(cls, peer, key=None):
        return ["ssh", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                "-o", "StrictHostKeyChecking=yes", "-o", "PasswordAuthentication=no",
                "-o", "KbdInteractiveAuthentication=no", "-o", "ConnectTimeout=5",
                "-o", "ExitOnForwardFailure=yes", "-o", "GlobalKnownHostsFile=/dev/null",
                "-o", "UserKnownHostsFile=" + str(peer["root"] / "known_hosts"),
                "-i", key or peer["root"] / "control-key", "-p", str(peer["port"]),
                "-l", peer["user"]]

    @classmethod
    def start_client(cls, peer):
        proc = cls.spawn(cls.client_args(peer) + ["-N", "-T", "-D", "127.0.0.1:" + str(peer["socks"]), peer["bind"]], "control-" + peer["tag"])
        peer["client"] = proc
        cls.wait_port("127.0.0.1", peer["socks"], proc)

    @classmethod
    def target_args(cls, peer, target, *, ipv6=False, wrong=False):
        address = target["ip6" if ipv6 else "ip4"]
        proxy_command = shlex.join(["/usr/bin/python3", "-I", str(cls.script), "proxy", str(peer["socks"]), address, "22"])
        return ["-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                "-o", "StrictHostKeyChecking=yes", "-o", "PasswordAuthentication=no",
                "-o", "ConnectTimeout=8", "-o", "GlobalKnownHostsFile=/dev/null",
                "-o", "UserKnownHostsFile=" + str(target["directory"] / ("wrong_known_hosts" if wrong else "known_hosts")),
                "-o", "HostKeyAlias=target-" + target["tag"], "-o", "ProxyCommand=" + proxy_command,
                "-i", str(cls.base / "target-client")]

    def test_01_actual_effective_audit_and_idempotent_setup(self):
        for peer in self.peers:
            self.assertEqual(0, self.helper_action(peer, "audit").returncode)
            before = pwd.getpwnam(peer["user"]).pw_uid
            self.assertEqual(0, self.helper_action(peer, "setup").returncode)
            self.assertEqual(before, pwd.getpwnam(peer["user"]).pw_uid)
            self.assertNotEqual(0, self.helper_action(peer, "retire", check=False).returncode,
                                "Inert-stage retirement must not discard a live enrollment's identity")
        self.assertNotEqual(pwd.getpwnam(self.peers[0]["user"]).pw_uid,
                            pwd.getpwnam(self.peers[1]["user"]).pw_uid)

    def test_02_two_peers_two_targets_ipv4_ipv6_ssh_and_sftp(self):
        def transfer(combination):
            pi, ti, ipv6 = combination
            peer, target = self.peers[pi], self.targets[ti]
            args = self.target_args(peer, target, ipv6=ipv6)
            result = command(["ssh"] + args + ["root@" + target["ip6" if ipv6 else "ip4"], "printf relay-target-authenticated"], timeout=15)
            self.assertEqual("relay-target-authenticated", result.stdout)
            source = self.base / ("payload-" + str(pi) + str(ti) + str(ipv6))
            destination = target["directory"] / source.name
            returned = self.base / (source.name + ".returned")
            payload = (b"multi-relay-sftp-integrity\x00" * 1024) + os.urandom(31)
            source.write_bytes(payload)
            commands = "put " + str(source) + " " + str(destination) + "\nget " + str(destination) + " " + str(returned) + "\n"
            command(["sftp"] + args + ["-b", "-", "root@" + ("[" + target["ip6"] + "]" if ipv6 else target["ip4"])], input=commands, timeout=20)
            self.assertEqual(hashlib.sha256(payload).digest(), hashlib.sha256(returned.read_bytes()).digest())
        combinations = [(p, t, v) for p in range(2) for t in range(2) for v in (False, True)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            list(executor.map(transfer, combinations))

    def test_03_https_preserves_trusted_certificate_and_hostname(self):
        for peer in self.peers:
            for target in self.targets:
                context = ssl.create_default_context(cafile=str(target["directory"] / "tls.crt"))
                with socks_connect(peer["socks"], target["ip4"], 443) as raw:
                    with context.wrap_socket(raw, server_hostname="relay-target.test") as stream:
                        stream.sendall(b"GET / HTTP/1.0\r\nHost: relay-target.test\r\n\r\n")
                        response = b""
                        while True:
                            chunk = stream.recv(4096)
                            if not chunk:
                                break
                            response += chunk
                        self.assertIn(b"relay-peer-real-https-target", response)
                with socks_connect(peer["socks"], target["ip4"], 443) as raw:
                    with self.assertRaises(ssl.SSLCertVerificationError):
                        context.wrap_socket(raw, server_hostname="wrong-target.test")
                with socks_connect(peer["socks"], target["ip6"], 443) as raw:
                    with context.wrap_socket(raw, server_hostname="relay-target.test") as stream:
                        stream.sendall(b"GET / HTTP/1.0\r\nHost: relay-target.test\r\n\r\n")
                        self.assertIn(b"200", stream.recv(200))
                with socks_connect(peer["socks"], target["ip4"], 443) as raw:
                    with self.assertRaises(ssl.SSLCertVerificationError):
                        ssl.create_default_context().wrap_socket(raw, server_hostname="relay-target.test")

    def test_04_private_local_and_unapproved_port_denied(self):
        for peer in self.peers:
            for target in self.targets:
                for address in target["negative4"] + target["negative6"]:
                    with self.subTest(peer=peer["tag"], address=address):
                        with socket.create_connection((address, 22), timeout=3) as unrelated:
                            self.assertTrue(unrelated.recv(100).startswith(b"SSH-2.0-"))
                        with self.assertRaises(OSError):
                            socks_connect(peer["socks"], address, 22).close()
                with socket.create_connection((target["ip4"], 80), timeout=3) as unrelated:
                    unrelated.sendall(b"GET / HTTP/1.0\r\n\r\n")
                    self.assertIn(b"200", unrelated.recv(200))
                with self.assertRaises(OSError):
                    socks_connect(peer["socks"], target["ip4"], 80).close()
                # The same private target is really reachable for an unrelated
                # UID; a failed route or absent listener cannot prove the ACL.
                with socket.create_connection((target["private4"], 22), timeout=3) as raw:
                    self.assertTrue(raw.recv(100).startswith(b"SSH-2.0-"))
            for address in ("8.8.4.240", "127.0.0.1", "::1", "::ffff:127.0.0.1"):
                with self.subTest(peer=peer["tag"], local=address):
                    with socket.create_connection((address, 443), timeout=3):
                        pass
                    with self.assertRaises(OSError):
                        socks_connect(peer["socks"], address, 443).close()

    def test_05_wrong_control_key_and_target_host_key_are_rejected(self):
        peer = self.peers[1]
        result = command(self.client_args(peer, self.peers[0]["root"] / "control-key")
                         + ["-T", peer["bind"], "true"], check=False)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("Permission denied", result.stderr)
        result = command(["ssh"] + self.target_args(self.peers[0], self.targets[0], wrong=True)
                         + ["root@" + self.targets[0]["ip4"], "true"], check=False)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("HOST IDENTIFICATION HAS CHANGED", result.stderr)

    def test_07_nft_enforces_uid_policy_independently_of_sshd(self):
        source = "import socket,sys; s=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=2); s.close(); print('CONNECTED')"
        target = self.targets[0]
        for peer in self.peers:
            principal = pwd.getpwnam(peer["user"])
            for address, port, allowed in (
                (target["ip4"], 22, True), (target["ip6"], 22, True),
                (target["ip4"], 443, True), (target["ip6"], 443, True),
                (target["private4"], 22, False), (target["private6"], 22, False),
                (target["ip4"], 80, False), ("127.0.0.1", 443, False),
                ("::1", 443, False), ("::ffff:127.0.0.1", 443, False),
                ("8.8.4.240", 443, False),
            ):
                with self.subTest(peer=peer["tag"], address=address, port=port):
                    result = subprocess.run(["/usr/bin/python3", "-I", "-c", source, address, str(port)],
                                            user=principal.pw_uid, group=principal.pw_gid,
                                            extra_groups=[], capture_output=True, text=True, timeout=4)
                    self.assertEqual(allowed, result.returncode == 0, result.stderr)
                    if allowed:
                        self.assertEqual("CONNECTED\n", result.stdout)

    def test_07b_unrelated_socketless_kernel_replies_remain_reachable(self):
        # Echo replies generated by the kernel have no peer-owned socket.
        # A negative skuid early-return alone incorrectly drops these packets.
        source = r'''import socket,struct,sys,time
v6 = sys.argv[1] == "6"
s = socket.socket(socket.AF_INET6 if v6 else socket.AF_INET, socket.SOCK_RAW,
                  socket.IPPROTO_ICMPV6 if v6 else socket.IPPROTO_ICMP)
s.settimeout(3)
payload = b"relay-kernel-output-proof"
packet = struct.pack("!BBHHH", 128 if v6 else 8, 0, 0, 284, 1) + payload
if not v6:
    padded = packet + (b"\0" if len(packet) % 2 else b"")
    words = struct.unpack("!" + "H" * (len(padded)//2), padded)
    checksum = sum(words)
    while checksum >> 16:
        checksum = (checksum & 65535) + (checksum >> 16)
    packet = packet[:2] + struct.pack("!H", (~checksum) & 65535) + packet[4:]
s.sendto(packet, (sys.argv[2], 0))
deadline = time.monotonic() + 3
while time.monotonic() < deadline:
    data, _ = s.recvfrom(2048)
    if not v6:
        data = data[(data[0] & 15) * 4:]
    if data[0] == (129 if v6 else 0) and data[4:] == packet[4:]:
        print("KERNEL-ECHO-REPLY")
        break
else:
    raise RuntimeError("No exact kernel echo reply")
'''
        for index, target in enumerate(self.targets):
            for family, address in (("4", "169.254." + str(240 + index) + ".1"),
                                    ("6", "fd42:284:" + target["tag"] + "::1")):
                with self.subTest(target=target["tag"], family=family):
                    result = command(["nsenter", "--net=/run/netns/" + target["ns"], "--",
                                      "/usr/bin/python3", "-I", "-c", source, family, address], timeout=5)
                    self.assertEqual("KERNEL-ECHO-REPLY\n", result.stdout)

    def authenticate_target(self, peer, target=None):
        target = target or self.targets[0]
        result = command(["ssh"] + self.target_args(peer, target)
                         + ["root@" + target["ip4"], "printf relay-target-authenticated"], timeout=15)
        self.assertEqual("relay-target-authenticated", result.stdout)

    def test_08_effective_firewall_drift_is_refused_without_overwrite(self):
        peer, sibling = self.peers
        self.helper_action(peer, "audit")
        command(["nft", "add", "chain", "inet", peer["table"], "fixture_foreign_chain"])
        try:
            before = command(["nft", "-j", "list", "table", "inet", peer["table"]]).stdout
            self.assertNotEqual(0, self.helper_action(peer, "audit", check=False).returncode)
            self.assertNotEqual(0, self.helper_action(peer, "repair", check=False).returncode)
            self.assertEqual(before, command(["nft", "-j", "list", "table", "inet", peer["table"]]).stdout,
                             "Repair must preserve a present foreign/drifted table")
            self.authenticate_target(sibling)
        finally:
            command(["nft", "delete", "chain", "inet", peer["table"], "fixture_foreign_chain"])
        self.helper_action(peer, "audit")

    def test_09_restart_restores_missing_egress_and_cold_runtime_lock(self):
        peer, sibling = self.peers
        self.helper_action(peer, "audit")
        command(["systemctl", "stop", peer["unit"]])
        peer["client"].wait(timeout=10)
        self.authenticate_target(sibling)
        command(["nft", "delete", "table", "inet", peer["table"]])
        lock = Path("/run/mcp-gateway-relay-peers", peer["record"] + ".lock")
        if lock.exists():
            import fcntl
            info = lock.lstat()
            self.assertFalse(lock.is_symlink())
            self.assertEqual(0, info.st_uid)
            self.assertEqual(0, info.st_mode & 0o022)
            with lock.open("rb") as held:
                fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                lock.unlink()
        command(["systemctl", "start", peer["unit"]])
        self.helper_action(peer, "audit")
        self.assertIn(peer["table"], self.nft_tables())
        self.assertTrue(lock.is_file(), "Cold runtime lock must be recreated before admission")
        self.helper_action(peer, "repair")
        self.start_client(peer)
        self.authenticate_target(peer)
        self.authenticate_target(sibling, self.targets[1])
        with self.assertRaises(OSError):
            socks_connect(peer["socks"], self.targets[0]["private4"], 22).close()

    def test_10_output_dnat_cannot_bypass_private_destination_policy(self):
        target = self.targets[0]
        table = "mcp_relay_os_dnat_probe"
        self.assertNotIn(table, self.nft_tables())
        public4, public6 = "8.8.8.242", "2606:4700:4700::2842"
        route4 = [public4 + "/32", "via", "169.254.240.2", "dev", target["outer"]]
        route6 = [public6 + "/128", "via", "fd42:284:a::2", "dev", target["outer"]]
        added4 = added6 = added_table = False
        try:
            command(["ip", "route", "add"] + route4)
            added4 = True
            command(["ip", "-6", "route", "add"] + route6)
            added6 = True
            source = ("add table inet " + table + "\n"
                      "add chain inet " + table + " output_nat { type nat hook output priority -100; policy accept; }\n"
                      "add rule inet " + table + " output_nat ip daddr " + public4
                      + " tcp dport 22 dnat ip to " + target["private4"] + "\n"
                      "add rule inet " + table + " output_nat ip6 daddr " + public6
                      + " tcp dport 22 dnat ip6 to " + target["private6"] + "\n")
            command(["nft", "-f", "-"], input=source)
            added_table = True
            for address in (public4, public6):
                with socket.create_connection((address, 22), timeout=3) as permitted:
                    self.assertTrue(permitted.recv(100).startswith(b"SSH-2.0-"))
                for peer in self.peers:
                    with self.subTest(peer=peer["tag"], translated=address):
                        with self.assertRaises(OSError):
                            socks_connect(peer["socks"], address, 22).close()
        finally:
            if added_table:
                command(["nft", "delete", "table", "inet", table])
            if added6:
                command(["ip", "-6", "route", "delete"] + route6)
            if added4:
                command(["ip", "route", "delete"] + route4)

    def test_11_retirement_terminates_active_forwarding_and_preserves_other_peer(self):
        peer, sibling = self.peers
        with socks_connect(peer["socks"], self.targets[0]["ip4"], 22) as active:
            self.assertTrue(active.recv(100).startswith(b"SSH-2.0-"))
            self.helper_action(peer, "retire-live")
            active.settimeout(5)
            try:
                self.assertEqual(b"", active.recv(100))
            except ConnectionResetError:
                pass
        peer["client"].wait(timeout=10)
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", peer["socks"]), timeout=2).close()
        with self.assertRaises(KeyError):
            pwd.getpwnam(peer["user"])
        self.assertNotIn(peer["table"], self.nft_tables())
        self.assertFalse(Path("/etc/systemd/system", peer["unit"]).exists())
        self.assertNotEqual(0, command(["systemctl", "is-active", "--quiet", peer["unit"]], check=False).returncode)
        self.helper_action(peer, "retire-live")
        self.assertNotEqual(0, self.helper_action(peer, "setup", check=False).returncode,
                            "Retired generation must never regain SSH admission")
        self.assertNotEqual(0, self.helper_action(peer, "ensure-egress", check=False).returncode,
                            "Retired generation must never recreate an egress guard")
        self.authenticate_target(sibling)
        self.helper_action(sibling, "audit")

    def test_12_new_generation_reenrolls_same_record_without_replay_or_old_policy(self):
        peer, sibling = self.peers
        old_input = peer["root"] / "retired-export.txt"
        old_input.write_bytes(peer["input"].read_bytes())
        old_peer = dict(peer, input=old_input)
        self.helper_action(peer, "retire")
        old_key = peer["root"] / "retired-control-key"
        (peer["root"] / "control-key").rename(old_key)
        (peer["root"] / "control-key.pub").unlink()
        self.keypair(peer["root"] / "control-key")
        lines = peer["input"].read_text().splitlines()
        lines[3] = "Configuration revision: 2"
        lines[4] = "Host fingerprint: " + os.urandom(32).hex()
        lines[5] = "Host generation: " + os.urandom(32).hex()
        lines[9] = (peer["root"] / "control-key.pub").read_text().strip()
        peer["input"].write_text("\n".join(lines) + "\n")
        peer["allowed_ports"] = (443,)
        self.helper_action(peer, "stage")
        self.helper_action(peer, "setup")
        self.start_client(peer)
        self.helper_action(peer, "audit")
        target = self.targets[0]
        with socks_connect(peer["socks"], target["ip4"], 443) as raw:
            context = ssl.create_default_context(cafile=str(target["directory"] / "tls.crt"))
            with context.wrap_socket(raw, server_hostname="relay-target.test") as tls:
                tls.sendall(b"GET / HTTP/1.0\r\n\r\n")
                self.assertIn(b"200", tls.recv(300))
        with self.assertRaises(OSError):
            socks_connect(peer["socks"], target["ip4"], 22).close()
        for action in ("setup", "ensure-egress", "retire-live"):
            self.assertNotEqual(0, self.helper_action(old_peer, action, check=False).returncode)
        result = command(self.client_args(peer, old_key) + ["-T", peer["bind"], "true"], check=False)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("Permission denied", result.stderr)
        self.helper_action(peer, "audit")
        self.authenticate_target(sibling)
        self.helper_action(sibling, "audit")

    def test_06_control_account_has_no_command_subsystem_or_reverse_forward(self):
        for peer in self.peers:
            result = command(self.client_args(peer) + ["-T", peer["bind"], "id"], check=False)
            self.assertNotEqual(0, result.returncode)
            self.assertNotIn("uid=", result.stdout)
            result = command(self.client_args(peer) + ["-T", "-s", peer["bind"], "sftp"], check=False, timeout=10)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("open failed", result.stderr)
            result = command(self.client_args(peer) + ["-N", "-T", "-R", "127.0.0.1:47889:127.0.0.1:22", peer["bind"]], check=False, timeout=10)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("remote port forwarding failed", result.stderr)

    def test_90_shared_sshd_configuration_is_unchanged(self):
        self.assertEqual(self.shared_sshd, Path("/etc/ssh/sshd_config").read_bytes())

    @classmethod
    def cleanup(cls):
        failures = []
        # Preserve only bounded non-secret diagnostics, before stopping units
        # or removing tables. Never collect credential directories/key files.
        for peer in cls.peers:
            try:
                if peer["unit"]:
                    for label, argv in (
                        ("status", ["systemctl", "status", peer["unit"], "--no-pager", "--lines=40"]),
                        ("journal", ["journalctl", "--unit", peer["unit"], "--no-pager", "-n", "100"]),
                    ):
                        result = command(argv, check=False)
                        (cls.base / ("peer-" + peer["tag"] + "-" + label + ".log")).write_text((result.stdout + result.stderr)[-32768:])
                if peer["table"]:
                    result = command(["nft", "-j", "list", "table", "inet", peer["table"]], check=False)
                    (cls.base / ("peer-" + peer["tag"] + "-nft.log")).write_text((result.stdout + result.stderr)[-32768:])
            except BaseException as error:
                failures.append("Peer diagnostic collection failed: " + str(error))
        for proc in reversed(cls.processes):
            try:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=4)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=4)
            except BaseException as error:
                failures.append("Fixture process cleanup failed: " + str(error))
        for peer in reversed(cls.peers):
            for action in ("retire-live", "retire"):
                try:
                    journal = Path("/var/lib/mcp-gateway-relay-peer-services", peer["record"])
                    if action == "retire-live" and not (journal.exists() or journal.is_symlink()):
                        unit = Path("/etc/systemd/system", "mcp-gateway-relay-peer-" + peer["record"].lower() + ".service")
                        table = "mcp_gateway_peer_" + hashlib.sha256(peer["record"].encode()).hexdigest()[:12]
                        if unit.exists() or unit.is_symlink() or table in cls.nft_tables():
                            raise RuntimeError("Peer resources exist without an ownership claim; preserve for inspection")
                        continue
                    cls.helper_action(peer, action)
                except BaseException as error:
                    failures.append(str(error))
        for target in reversed(cls.targets):
            try:
                netns = Path("/run/netns", target["ns"])
                if target["ns_inode"] is not None and netns.exists():
                    info = netns.stat()
                    if (info.st_dev, info.st_ino) == target["ns_inode"]:
                        result = command(["ip", "netns", "delete", target["ns"]], check=False)
                        if result.returncode:
                            failures.append("Could not remove owned fixture namespace: " + target["ns"])
                    else:
                        failures.append("Changed namespace preserved: " + target["ns"])
                if target["outer_ifindex"] is not None:
                    found = command(["ip", "-j", "link", "show", "dev", target["outer"]], check=False)
                    if found.returncode == 0:
                        if json.loads(found.stdout)[0]["ifindex"] == target["outer_ifindex"]:
                            result = command(["ip", "link", "delete", target["outer"]], check=False)
                            if result.returncode:
                                failures.append("Could not remove owned fixture interface: " + target["outer"])
                        else:
                            failures.append("Changed interface preserved: " + target["outer"])
            except BaseException as error:
                failures.append("Fixture network cleanup failed: " + str(error))
        for handle in cls.handles:
            handle.close()
        if cls.local_public_added:
            result = command(["ip", "addr", "delete", "8.8.4.240/32", "dev", "lo"], check=False)
            if result.returncode or "8.8.4.240" in command(["ip", "-j", "addr", "show", "dev", "lo"]).stdout:
                failures.append("Task-local public address remains after cleanup")
        for target in cls.targets:
            if target["ns_inode"] is not None and Path("/run/netns", target["ns"]).exists():
                failures.append("Fixture namespace remains: " + target["ns"])
            if target["outer_ifindex"] is not None and command(["ip", "link", "show", "dev", target["outer"]], check=False).returncode == 0:
                failures.append("Fixture interface remains: " + target["outer"])
        if cls.installed_helper_created and not failures:
            if cls.helper.is_file() and hashlib.sha256(cls.helper.read_bytes()).hexdigest() == cls.helper_sha256:
                cls.helper.unlink()
            else:
                failures.append("Changed installed fixture helper preserved")
        if cls.helper_directory_created and not failures:
            try:
                cls.helper.parent.rmdir()
            except OSError:
                failures.append("Installed fixture helper directory remains")
        if failures:
            print("FIXTURE CLEANUP INCOMPLETE; retain exact evidence at " + str(cls.base), file=sys.stderr)
            raise RuntimeError("\n".join(failures))


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "proxy":
        proxy(int(sys.argv[2]), sys.argv[3], int(sys.argv[4]))
        return 0
    if len(sys.argv) > 1 and sys.argv[1] == "https":
        https_server(sys.argv[2], sys.argv[3], len(sys.argv) > 4 and sys.argv[4] == "6",
                     bind=sys.argv[5] if len(sys.argv) > 5 else None)
        return 0
    if len(sys.argv) > 1 and sys.argv[1] == "http":
        https_server(None, None, port=80)
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path)
    args = parser.parse_args()
    PeerOsAcceptance.helper_source = args.helper.resolve(strict=True)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(PeerOsAcceptance)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if args.artifacts and hasattr(PeerOsAcceptance, "base"):
        args.artifacts.mkdir(parents=True, exist_ok=True, mode=0o755)
        for logfile in PeerOsAcceptance.base.glob("*.log"):
            destination = args.artifacts / logfile.name
            shutil.copyfile(logfile, destination)
            destination.chmod(0o644)
        report = args.artifacts / "result.json"
        report.write_text(json.dumps({"tests_run": result.testsRun,
                                      "errors": len(result.errors), "failures": len(result.failures),
                                      "successful": result.wasSuccessful(),
                                      "scope": "disposable OS; no physical-host, kernel-reboot or WordPress acceptance"}, indent=2) + "\n")
        report.chmod(0o644)
    if result.wasSuccessful():
        shutil.rmtree(PeerOsAcceptance.base)
    elif hasattr(PeerOsAcceptance, "base"):
        print("Failure diagnostics retained in " + str(PeerOsAcceptance.base), file=sys.stderr)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
