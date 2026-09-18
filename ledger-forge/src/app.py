#!/usr/bin/env python3
# =============================================================================
# ledger-forge — an intentionally vulnerable Attack & Defense web target.
#
# A small JWT-authenticated EXPENSE LEDGER API: users register, log in, add
# expense entries, list them, and (admins only) render a templated report.
# Tokens are RS256-signed with an RSA keypair generated once at startup; the
# matching PUBLIC key is published at /pubkey (intended — attackers fetch it).
#
# Two deliberately planted, CHAINED bugs lead to the live flag:
#
#   BUG 1 — JWT ALGORITHM CONFUSION (verify_jwt below)
#     The token verifier is HAND-ROLLED (so no library guard fights us). It
#     trusts the `alg` field in the attacker-controlled header: RS256 is
#     verified against the RSA public key, but HS256 is verified as
#     HMAC-SHA256 keyed with the PUBLIC-KEY PEM BYTES. An attacker who GETs
#     /pubkey therefore knows the HMAC secret and can forge ANY token —
#     including {"user":"pwn","role":"admin"}.
#
#   BUG 2 — SERVER-SIDE TEMPLATE INJECTION (/admin/report)
#     The admin-only report endpoint renders a USER-SUPPLIED template with
#     Jinja2 render_template_string(...). Once you hold a forged admin token,
#     that's RCE → read $GZCTF_FLAG_FILE.
#
#   THE CHAIN: GET /pubkey → forge an admin HS256 token (HMAC secret = the
#   public-key PEM bytes) → POST /admin/report with an SSTI payload that
#   reads the flag file.
#
# Flag plumbing (same contract as the other GZCTF A&D harness challenges):
#   * The platform writes the live, per-tick flag to $GZCTF_FLAG_FILE
#     (Docker: /flag bind-mount, K8s: /gzctf-flag/flag). We read it FRESH on
#     demand — never baked into the image, and never referenced by normal
#     code. The flag is ONLY reachable through the SSTI sink.
#
# DEFENDER INTENT (don't ship a patch — keep it patchable): a defender fixes
# this by (a) only accepting RS256 in verify_jwt AND (b) not rendering the
# user template in /admin/report. The register / login / add-entry / list /
# report SLA flow the checker drives must stay green either way.
# =============================================================================

import base64
import hashlib
import hmac
import json
import os
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)

# --------------------------------------------------------------------------- #
# RSA keypair — generated ONCE at startup. Tokens are signed RS256 with the
# private key; the public key PEM is published at /pubkey. The PEM BYTES are
# also (the bug) accepted as an HS256 HMAC secret by the hand-rolled verifier.
# --------------------------------------------------------------------------- #
_PRIV_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUB_KEY = _PRIV_KEY.public_key()
# Serialize once and reuse the SAME bytes everywhere (served at /pubkey AND used
# as the HS256 secret). Do NOT strip/normalize — byte identity is what makes the
# alg-confusion forgery verify.
PUB_PEM = _PUB_KEY.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

# In-memory stores (single Flask process). username -> {"password", "role"} and
# username -> [entries]. Plain dicts are fine for an ephemeral A&D target.
USERS: dict = {}
ENTRIES: dict = {}


# --------------------------------------------------------------------------- #
# base64url helpers (no padding on the wire; re-pad on decode)
# --------------------------------------------------------------------------- #
def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# --------------------------------------------------------------------------- #
# JWT issue + verify
# --------------------------------------------------------------------------- #
def issue_jwt(user: str, role: str) -> str:
    """Issue an RS256-signed token (the legitimate path)."""
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"user": user, "role": role, "iat": int(time.time())}
    h_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = _PRIV_KEY.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{h_b64}.{p_b64}.{b64url_encode(sig)}"


def verify_jwt(token: str):
    """HAND-ROLLED verifier (no library guard).

    Returns the decoded claims dict if the signature checks out, else None.
    The bug lives here: HS256 is accepted, keyed with the PUBLIC PEM bytes.
    """
    try:
        h_b64, p_b64, s_b64 = token.split(".")
    except ValueError:
        return None
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    try:
        header = json.loads(b64url_decode(h_b64))
        claims = json.loads(b64url_decode(p_b64))
        sig = b64url_decode(s_b64)
    except (ValueError, json.JSONDecodeError):
        return None

    alg = header.get("alg")
    if alg == "RS256":
        try:
            _PUB_KEY.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature:
            return None
        return claims
    if alg == "HS256":
        # BUG: HMAC-SHA256 keyed with the public-key PEM bytes — which anyone
        # can fetch from /pubkey. An attacker forges an admin token at will.
        expected = hmac.new(PUB_PEM, signing_input, hashlib.sha256).digest()
        if hmac.compare_digest(sig, expected):
            return claims
        return None
    return None


def current_claims():
    """Pull + verify the bearer token from the Authorization header."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return verify_jwt(auth[len("Bearer "):].strip())


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    user = data.get("username")
    pw = data.get("password")
    if not user or not pw:
        return jsonify(ok=False, error="username and password required"), 400
    if user in USERS:
        return jsonify(ok=False, error="user exists"), 409
    USERS[user] = {"password": pw, "role": "user"}
    ENTRIES.setdefault(user, [])
    return jsonify(ok=True)


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    user = data.get("username")
    pw = data.get("password")
    rec = USERS.get(user)
    if not rec or rec["password"] != pw:
        return jsonify(ok=False, error="invalid credentials"), 401
    return jsonify(ok=True, token=issue_jwt(user, rec["role"]))


@app.get("/pubkey")
def pubkey():
    # Intended exposure: attackers fetch the PEM to mount the alg-confusion
    # forgery. Served as the EXACT bytes used elsewhere (no normalization).
    return app.response_class(PUB_PEM, mimetype="text/plain")


@app.post("/entries")
def add_entry():
    claims = current_claims()
    if not claims:
        return jsonify(ok=False, error="unauthorized"), 401
    data = request.get_json(silent=True) or {}
    amount = data.get("amount")
    memo = data.get("memo", "")
    if amount is None:
        return jsonify(ok=False, error="amount required"), 400
    # Authorization is CLAIM-based: a forged user need not exist in USERS.
    user = claims.get("user", "")
    bucket = ENTRIES.setdefault(user, [])
    entry = {"id": len(bucket) + 1, "amount": amount, "memo": memo}
    bucket.append(entry)
    return jsonify(ok=True, id=entry["id"])


@app.get("/entries")
def list_entries():
    claims = current_claims()
    if not claims:
        return jsonify(ok=False, error="unauthorized"), 401
    user = claims.get("user", "")
    return jsonify(ok=True, entries=ENTRIES.get(user, []))


@app.get("/me")
def me():
    claims = current_claims()
    if not claims:
        return jsonify(ok=False, error="unauthorized"), 401
    # Role comes straight from the verified claims, NOT a store lookup, so a
    # forged admin token reports role "admin" without ever registering.
    return jsonify(ok=True, user=claims.get("user"), role=claims.get("role"))


@app.post("/admin/report")
def admin_report():
    claims = current_claims()
    if not claims:
        return jsonify(ok=False, error="unauthorized"), 401
    if claims.get("role") != "admin":
        return jsonify(ok=False, error="admin only"), 403
    data = request.get_json(silent=True) or {}
    title = data.get("title", "Expense Report")
    template = data.get("template", "")
    user = claims.get("user", "")
    entries = ENTRIES.get(user, [])
    # BUG: the user-supplied template is rendered server-side → SSTI → RCE.
    html = render_template_string(template, title=title, entries=entries)
    return jsonify(ok=True, html=html)


@app.get("/health")
def health():
    return app.response_class("ok", mimetype="text/plain")


if __name__ == "__main__":
    # Bind all interfaces: the platform (and the SLA checker / attack proxy)
    # reach us on the container IP, not localhost.
    app.run(host="0.0.0.0", port=8080)
