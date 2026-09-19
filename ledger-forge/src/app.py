#!/usr/bin/env python3
# =============================================================================
# ledger-forge — an intentionally vulnerable Attack & Defense web target.
#
# A small JWT-authenticated EXPENSE LEDGER API: users register, log in, add
# expense entries, list them, and (admins only) render a templated report.
# Tokens are RS256-signed with a persisted RSA keypair; the
# matching PUBLIC key is published at /pubkey (intended — attackers fetch it).
#
# The challenge retains its original JWT algorithm-confusion and template
# rendering weaknesses. Neither weakness is exercised by the V2 checker.
#
# V2 flag storage: the checker logs in as an ordinary private account and
# stores flags in ledger entries. It retrieves retained entries through the
# same legitimate API, without exploiting either vulnerability. Accounts,
# entries and signing keys live under LEDGER_DATA_DIR (default /app/data).
# Preserve this data when patching/restarting the service.
#
# DEFENDER INTENT (don't ship a patch — keep it patchable): a defender fixes
# this by (a) only accepting RS256 in verify_jwt AND (b) not rendering the
# user template in /admin/report. The register / login / add-entry / list /
# normal-owner SLA flow the checker drives must stay green either way.
# =============================================================================

import base64
import fcntl
import hashlib
import hmac
import json
import os
import sqlite3
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)

# --------------------------------------------------------------------------- #
# RSA keypair — persisted across process restarts. Tokens are signed RS256 with the
# private key; the public key PEM is published at /pubkey. The PEM BYTES are
# also (the bug) accepted as an HS256 HMAC secret by the hand-rolled verifier.
# --------------------------------------------------------------------------- #
DATA_DIR = Path(os.environ.get("LEDGER_DATA_DIR", "/app/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "ledger.sqlite3"

# Preserve accounts, records and signing keys when defenders restart the app.
# The data directory must also survive any deployment/container replacement.
with (DATA_DIR / "key.lock").open("a") as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    key_path = DATA_DIR / "private-key.pem"
    if not key_path.exists():
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with tempfile.NamedTemporaryFile(dir=DATA_DIR, prefix="private-key-", delete=False) as key_file:
            key_file.write(private_key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
            key_file.flush()
            os.fsync(key_file.fileno())
        os.replace(key_file.name, key_path)
    _PRIV_KEY = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
_PUB_KEY = _PRIV_KEY.public_key()
# Serialize once and reuse the SAME bytes everywhere (served at /pubkey AND used
# as the HS256 secret). Do NOT strip/normalize — byte identity is what makes the
# alg-confusion forgery verify.
PUB_PEM = _PUB_KEY.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

@contextmanager
def database():
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    try:
        with db:
            yield db
    finally:
        db.close()


with database() as db:
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY, password TEXT NOT NULL, role TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL,
            amount TEXT NOT NULL, memo TEXT NOT NULL, client_id TEXT);
        CREATE INDEX IF NOT EXISTS entries_owner ON entries(username);
        CREATE UNIQUE INDEX IF NOT EXISTS entries_client ON entries(username, client_id);
        CREATE TABLE IF NOT EXISTS entry_requests (
            username TEXT NOT NULL, client_id TEXT NOT NULL, entry_id INTEGER NOT NULL,
            PRIMARY KEY (username, client_id));
    """)


def entries_for(user):
    with database() as db:
        rows = db.execute("SELECT * FROM entries WHERE username = ? ORDER BY id", (user,)).fetchall()
    return [{"id": row["id"], "amount": json.loads(row["amount"]),
             "memo": row["memo"], "clientId": row["client_id"]} for row in rows]


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
    if not isinstance(user, str) or not user or not isinstance(pw, str) or not pw:
        return jsonify(ok=False, error="username and password required"), 400
    try:
        with database() as db:
            db.execute("INSERT INTO users VALUES (?, ?, 'user')", (user, pw))
    except sqlite3.IntegrityError:
        return jsonify(ok=False, error="user exists"), 409
    return jsonify(ok=True)


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    user = data.get("username")
    pw = data.get("password")
    if not isinstance(user, str) or not isinstance(pw, str):
        return jsonify(ok=False, error="invalid credentials"), 401
    with database() as db:
        rec = db.execute("SELECT * FROM users WHERE username = ?", (user,)).fetchone()
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
    client_id = data.get("clientId")
    if amount is None:
        return jsonify(ok=False, error="amount required"), 400
    if not isinstance(memo, str) or (client_id is not None and
                                    (not isinstance(client_id, str) or not client_id or len(client_id) > 256)):
        return jsonify(ok=False, error="invalid memo or clientId"), 400
    # Authorization is CLAIM-based: a forged user need not exist in USERS.
    user = claims.get("user", "")
    with database() as db:
        db.execute("BEGIN IMMEDIATE")
        if client_id is not None:
            previous = db.execute("SELECT entry_id FROM entry_requests WHERE username = ? AND client_id = ?",
                                  (user, client_id)).fetchone()
            if previous:
                entry = db.execute("SELECT * FROM entries WHERE id = ?", (previous["entry_id"],)).fetchone()
                if entry and json.loads(entry["amount"]) == amount and entry["memo"] == memo:
                    return jsonify(ok=True, id=entry["id"])
                # Retain a tombstone: a repeated write must never repair lost data.
                return jsonify(ok=False, error="clientId already used"), 409
        entry_id = db.execute("INSERT INTO entries(username, amount, memo, client_id) VALUES (?, ?, ?, ?)",
                              (user, json.dumps(amount), memo, client_id)).lastrowid
        if client_id is not None:
            db.execute("INSERT INTO entry_requests VALUES (?, ?, ?)", (user, client_id, entry_id))
    return jsonify(ok=True, id=entry_id)


@app.get("/entries")
def list_entries():
    claims = current_claims()
    if not claims:
        return jsonify(ok=False, error="unauthorized"), 401
    user = claims.get("user", "")
    return jsonify(ok=True, entries=entries_for(user))


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
    entries = entries_for(user)
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
