#!/usr/bin/env python3
"""Disposable loopback-only OpenSSH external SFTP subsystem for CI fault injection.

No network access or arbitrary shell interaction. 'oversize' advertises an
oversized SFTP frame following an ordinary VERSION handshake. 'delay-write'
proxies the real local OpenSSH sftp-server but holds WRITE STATUS responses
after the remote operation has already been dispatched.
"""
import os
import struct
import subprocess
import sys
import threading
import time


def read_exact(file, count):
    result = bytearray()
    while len(result) < count:
        chunk = file.read(count - len(result))
        if not chunk:
            return None
        result.extend(chunk)
    return bytes(result)


def read_frame(file):
    header = read_exact(file, 4)
    if header is None:
        return None
    (count,) = struct.unpack(">I", header)
    if count < 1 or count > 1024 * 1024:
        return None
    body = read_exact(file, count)
    if body is None:
        return None
    return header + body


def write_frame(file, frame):
    file.write(frame)
    file.flush()


def oversized():
    start = read_frame(sys.stdin.buffer)
    if start is None or start[4] != 1:
        return
    # Valid SFTP v3 VERSION response, before request IDs are switched on.
    write_frame(sys.stdout.buffer, struct.pack(">IBI", 5, 2, 3))
    request = read_frame(sys.stdin.buffer)
    if request is None:
        return
    # Advertise an impossible SFTP response length, then attempt to deliver
    # the claimed payload. The client must reject BEFORE accumulating it.
    try:
        sys.stdout.buffer.write(struct.pack(">I", 8 * 1024 * 1024))
        sys.stdout.buffer.flush()
        data = b"\x65" + b"R" * 32767
        for _ in range(256):
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
    except (BrokenPipeError, ConnectionResetError):
        return


def delayed_status():
    server = subprocess.Popen(
        ["/usr/lib/openssh/sftp-server"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        bufsize=0,
    )
    writes = set()
    lock = threading.Lock()
    marker = os.path.expanduser("~/.mcp-sftp-delay-write-observed")

    def forward_requests():
        try:
            while True:
                packet = read_frame(sys.stdin.buffer)
                if packet is None:
                    break
                if len(packet) >= 9 and packet[4] == 6:  # SSH_FXP_WRITE
                    with lock:
                        writes.add(packet[5:9])
                    with open(marker, "wb") as event:
                        event.write(b"write-received")
                write_frame(server.stdin, packet)
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                server.stdin.close()
            except OSError:
                pass

    worker = threading.Thread(target=forward_requests, daemon=True)
    worker.start()
    try:
        while True:
            packet = read_frame(server.stdout)
            if packet is None:
                break
            if len(packet) >= 9 and packet[4] == 101:  # SSH_FXP_STATUS
                with lock:
                    delayed = packet[5:9] in writes
                if delayed:
                    # Exceeds the per-request deadline, but remains far below
                    # the 90-second lock lease when transport is implemented
                    # correctly. An unbounded STATUS drain violates the test.
                    time.sleep(12)
            write_frame(sys.stdout.buffer, packet)
    except (BrokenPipeError, OSError):
        pass
    finally:
        try:
            server.terminate()
        except OSError:
            pass


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("oversize", "delay-write"):
        sys.exit(2)
    if sys.argv[1] == "oversize":
        oversized()
    else:
        delayed_status()
