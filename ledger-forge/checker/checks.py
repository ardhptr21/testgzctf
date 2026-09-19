"""Ledger Forge V2 hooks. No exploit or privileged flag-reading endpoint.

The checker is an ordinary customer: its private memo contains the flag.
Defenders may fix JWT confusion and SSTI without changing this flow. Credentials
are derived from the secret flag, so a replacement worker can log in without
knowing anything stored in an old worker's filesystem. Placement authorization
is separate: the framework must durably claim it before calling put_flag.
"""
import hashlib
import hmac
import secrets

from checker import Infrastructure, Mumble, check


def identity(flag):
    """Domain-separated, unpredictable credentials; never team/tick passwords."""
    def derive(purpose):
        return hmac.new(flag.value.encode(), ("ledger-forge-v2:" + purpose).encode(), hashlib.sha256).hexdigest()

    return {
        "username": "ledger_" + derive("username")[:40],
        "password": derive("password"),
        "clientId": derive("entry"),
    }


def _json(response):
    try:
        body = response.json()
    except ValueError:
        raise Mumble("service returned non-JSON data") from None
    if not isinstance(body, dict):
        raise Mumble("service returned an invalid JSON object")
    return body


def _login(t, credentials, *, retention=False):
    response = t.post("/login", json={key: credentials[key] for key in ("username", "password")})
    if retention and response.status_code in (401, 403, 404):
        return None
    if response.status_code != 200:
        raise Mumble("ordinary login failed")
    token = _json(response).get("token")
    if not isinstance(token, str) or not token:
        raise Mumble("login did not return a token")
    return {"Authorization": "Bearer " + token}


@check
def health(t):
    response = t.get("/health")
    if response.status_code != 200 or response.text.strip() != "ok":
        raise Mumble("health endpoint failed")


@check
def pubkey(t):
    response = t.get("/pubkey")
    if response.status_code != 200 or "-----BEGIN PUBLIC KEY-----" not in response.text:
        raise Mumble("public-key endpoint failed")


@check
def core_flow(t):
    """Independent, harmless ordinary functionality; no historical flag writes."""
    credentials = {"username": "customer_" + secrets.token_hex(16), "password": secrets.token_hex(32)}
    response = t.post("/register", json=credentials)
    if response.status_code != 200:
        raise Mumble("ordinary registration failed")
    auth = _login(t, credentials)
    marker, client_id = "expense-" + secrets.token_hex(16), secrets.token_hex(32)
    response = t.post("/entries", headers=auth, json={"amount": 127, "memo": marker, "clientId": client_id})
    if response.status_code != 200 or not _json(response).get("id"):
        raise Mumble("ordinary entry creation failed")
    response = t.get("/entries", headers=auth)
    if response.status_code != 200:
        raise Mumble("ordinary entry listing failed")
    entries = _json(response).get("entries")
    if not isinstance(entries, list) or not any(
        isinstance(entry, dict) and entry.get("memo") == marker and entry.get("amount") == 127
        and entry.get("clientId") == client_id for entry in entries
    ):
        raise Mumble("ordinary entry was not preserved")
    response = t.get("/me", headers=auth)
    data = _json(response)
    if response.status_code != 200 or data.get("user") != credentials["username"] or data.get("role") != "user":
        raise Mumble("authenticated profile failed")


def put_flag(t, flag):
    """Called once after a durable placement claim, ONLY for a newly issued flag.

    Creation is idempotent by clientId. A collision never permits overwriting
    an existing memo; a missing previously accepted record must stay missing.
    """
    credentials = identity(flag)
    response = t.post("/register", json={key: credentials[key] for key in ("username", "password")})
    if response.status_code not in (200, 409):
        raise Mumble("flag account registration failed")
    auth = _login(t, credentials)
    response = t.post("/entries", headers=auth, json={
        "amount": 1, "memo": flag.value, "clientId": credentials["clientId"],
    })
    if response.status_code >= 500:
        raise Infrastructure("entry write outcome is ambiguous")
    if response.status_code not in (200, 409, 410):
        raise Mumble("flag entry creation failed")
    if response.status_code == 200:
        try:
            entry_id = _json(response).get("id")
        except Mumble:
            raise Infrastructure("entry write acknowledgement is malformed") from None
        if type(entry_id) is not int or entry_id < 1:
            raise Infrastructure("entry write acknowledgement is malformed")
        return "confirmed"
    return "failed"


def get_flag(t, flag):
    """Read-only retrieval through the legitimate owner's session on EVERY tick.

    Do not register, recreate entries, use SSTI, forge JWTs, or read /flag here.
    The framework compares the actual retrieved memo with the expected flag.
    """
    credentials = identity(flag)
    auth = _login(t, credentials, retention=True)
    if auth is None:
        return None
    response = t.get("/entries", headers=auth)
    if response.status_code in (401, 403, 404, 410):
        return None
    if response.status_code != 200:
        raise Mumble("retained entry listing failed")
    entries = _json(response).get("entries")
    if not isinstance(entries, list):
        raise Mumble("retained entry listing malformed")
    matches = [entry for entry in entries if isinstance(entry, dict) and entry.get("clientId") == credentials["clientId"]]
    if len(matches) != 1 or not isinstance(matches[0].get("memo"), str):
        return None
    return matches[0]["memo"]
