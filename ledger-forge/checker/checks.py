"""
SLA test cases for ledger-forge — FUNCTIONALITY ONLY.

These exercise the legitimate behaviour of the team's expense-ledger API so the
platform can tell whether it is still working. They deliberately never trigger
either planted bug (JWT alg-confusion / Jinja2 SSTI) — stealing the flag is the
attackers' job, not the SLA checker's. A team that patches both bugs keeps SLA
green as long as the normal register → login → add-entry → list → report flow
still works; a team that guts core functionality to dodge attacks loses SLA.

Verdicts: return = Ok, raise Mumble = up-but-wrong, t.get/post raise Offline
for you when the service is unreachable.
"""
import requests

from checker import Mumble, Offline, check


def _session(t):
    """A cookie-persisting session bound to the target, mapping transport
    errors to Offline so content checks never see a half-dead connection."""
    s = requests.Session()
    s.request_orig = s.request

    def _req(method, path, **kw):
        kw.setdefault("timeout", 6)
        try:
            return s.request_orig(method, t.url + path, **kw)
        except requests.exceptions.RequestException as e:
            raise Offline(f"{method} {path}: {e}") from e

    s.req = _req
    return s


def _json(r):
    """Parse a JSON body, mapping a non-JSON / malformed response to Mumble.

    A team that breaks a core endpoint so it returns HTML / empty / an error
    page is "up but wrong" = Mumble. Calling r.json() directly would let
    requests raise JSONDecodeError, which bubbles out of the check and the
    harness mis-scores as InternalError (a *checker* bug → no SLA penalty),
    handing that team a free pass for a broken service. Catch it here so the
    verdict is the Mumble it should be. (requests' JSONDecodeError subclasses
    ValueError, so this is version-agnostic.) Returns {} for an empty-but-OK
    body so callers can keep using .get(...)."""
    try:
        return r.json() or {}
    except ValueError:
        raise Mumble(f"non-JSON response ({r.status_code}): {r.text[:80]!r}") from None


@check
def health(t):
    """GET /health must return a plain 'ok'."""
    r = t.get("/health")
    if r.status_code != 200 or r.text.strip() != "ok":
        raise Mumble(f"/health => {r.status_code} {r.text[:60]!r}")


@check
def pubkey(t):
    """GET /pubkey must return something that looks like a PEM public key.

    Fetching the public key is part of the legitimate API surface (clients
    verify tokens with it), so the SLA exercises it — but the checker NEVER
    uses it to forge a token. That's the attacker's path, not ours."""
    r = t.get("/pubkey")
    if r.status_code != 200 or "-----BEGIN PUBLIC KEY-----" not in r.text:
        raise Mumble(f"/pubkey => {r.status_code} {r.text[:80]!r}")


@check
def core_flow(t):
    """Register → login (RS256 token) → add an entry → list contains it →
    /me reports role 'user'. All legitimate; no bug is exercised."""
    s = _session(t)
    # Deterministic-but-unique identity per (team, round) so reruns don't
    # collide on the "user exists" (409) path.
    tag = f"chk_{t.team_id or '0'}_{t.round}"
    user, pw = tag, "P@ss-" + tag

    # register (200 fresh / 409 already exists are both fine)
    r = s.req("POST", "/register", json={"username": user, "password": pw})
    if r.status_code not in (200, 409):
        raise Mumble(f"/register => {r.status_code} {r.text[:80]!r}")

    # login -> RS256 bearer token (the legitimate, library-issued token)
    r = s.req("POST", "/login", json={"username": user, "password": pw})
    if r.status_code != 200:
        raise Mumble(f"/login => {r.status_code} {r.text[:80]!r}")
    token = _json(r).get("token")
    if not token:
        raise Mumble(f"/login body has no token => {r.text[:80]!r}")
    auth = {"Authorization": f"Bearer {token}"}

    # add an expense entry
    marker = "memo-" + tag
    amount = 100 + (t.round or 0)
    r = s.req("POST", "/entries", headers=auth, json={"amount": amount, "memo": marker})
    if r.status_code != 200:
        raise Mumble(f"/entries create => {r.status_code} {r.text[:80]!r}")
    eid = _json(r).get("id")
    if not eid:
        raise Mumble(f"/entries create => {r.status_code} {r.text[:80]!r}")

    # list shows it back
    r = s.req("GET", "/entries", headers=auth)
    if r.status_code != 200:
        raise Mumble(f"/entries list => {r.status_code} {r.text[:80]!r}")
    entries = _json(r).get("entries", [])
    if not any(e.get("memo") == marker for e in entries):
        raise Mumble(f"/entries list missing memo {marker!r}: {r.text[:120]!r}")

    # /me reports the authenticated user with role 'user'
    r = s.req("GET", "/me", headers=auth)
    body = _json(r)
    if r.status_code != 200 or body.get("user") != user or body.get("role") != "user":
        raise Mumble(f"/me => {r.status_code} {r.text[:100]!r}")
