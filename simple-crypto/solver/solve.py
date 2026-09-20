#!/usr/bin/env python3
import re
import sys

import requests

FLAG_RE = re.compile(r"flag\{[^}]+\}")


def xor_bytes(left, right):
    return bytes(a ^ b for a, b in zip(left, right))


def solve(host="127.0.0.1", port=8082):
    base = f"http://{host}:{port}"
    flag_ct = bytes.fromhex(requests.get(base + "/api/flag", timeout=5).json()["ciphertext"])
    known = b"A" * len(flag_ct)
    known_ct = bytes.fromhex(
        requests.post(base + "/api/encrypt", json={"message": known.decode()}, timeout=5).json()["ciphertext"]
    )
    keystream = xor_bytes(known_ct, known)
    flag = xor_bytes(flag_ct, keystream).decode()
    return flag if FLAG_RE.fullmatch(flag) else None


if __name__ == "__main__":
    target_host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 8082
    recovered = solve(target_host, target_port)
    if not recovered:
        print("flag not found", file=sys.stderr)
        sys.exit(1)
    print(recovered)
