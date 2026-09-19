#!/usr/bin/env python3
"""Persistent GZCTF V2 worker: functionality + real retained-flag retrieval.

Challenge-specific hooks are in checks.py. The platform persists placement
state BEFORE dispatching a new flag. No pod-local database, privileged flag
reader, exploit, or repair of historical data is used. An ambiguous first
write is an infrastructure error, never fabricated missing-flag evidence.
Flags change only at round boundaries; intermediate ticks only validate them.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import sys
import threading
import time
from dataclasses import dataclass, field, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests

OK, MUMBLE, OFFLINE, INTERNAL_ERROR = 0, 1, 2, 3
_NAME = {OK: "Ok", MUMBLE: "Mumble", OFFLINE: "Offline", INTERNAL_ERROR: "InternalError"}
MAX_BODY = 1024 * 1024
MAX_FLAGS = 1000
_CHECKS = []
_NEW_CLAIMS = set()
_CLAIM_LOCK = threading.Lock()


class CheckError(Exception):
    status = INTERNAL_ERROR


class Mumble(CheckError):
    """The service answered but ordinary functionality is incorrect."""
    status = MUMBLE


class Offline(CheckError):
    """The target could not be reached within a bounded request."""
    status = OFFLINE


class Infrastructure(CheckError):
    """A checker/placement ambiguity is not a service-outage verdict."""


def check(fn):
    _CHECKS.append(fn)
    return fn


@dataclass(frozen=True)
class RetainedFlag:
    id: int
    value: str
    planted_at_tick: int
    placement: str


@dataclass
class Target:
    ip: str
    port: int
    round: int
    tick: int
    tick_number: int
    round_start_tick: int
    team_id: str
    challenge_id: int
    flags: tuple[RetainedFlag, ...]
    deadline: float = field(default_factory=lambda: time.monotonic() + 24)
    session: requests.Session = field(default_factory=requests.Session, repr=False)

    def __post_init__(self):
        self.session.trust_env = False

    @property
    def url(self):
        host = "[" + self.ip + "]" if ":" in self.ip else self.ip
        return f"http://{host}:{self.port}"

    def get(self, path="/", **kwargs):
        return self.request("GET", path, **kwargs)

    def post(self, path="/", **kwargs):
        return self.request("POST", path, **kwargs)

    def request(self, method, path="/", **kwargs):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise Offline("target response deadline exceeded")
        kwargs.setdefault("timeout", min(3, remaining))
        kwargs["allow_redirects"] = False
        kwargs["stream"] = True
        try:
            response = self.session.request(method, self.url + path, **kwargs)
            chunks, size = [], 0
            # Small reads enforce a total deadline even if an untrusted target
            # trickles bytes slowly enough to avoid the socket idle timeout.
            for chunk in response.iter_content(1):
                if time.monotonic() >= self.deadline:
                    response.close()
                    raise Offline("target response deadline exceeded")
                size += len(chunk)
                if size > MAX_BODY:
                    response.close()
                    raise Mumble("service response exceeded the maximum size")
                chunks.append(chunk)
            response._content = b"".join(chunks)
            response._content_consumed = True
            response.close()
            return response
        except requests.exceptions.RequestException:
            # Never echo target responses, URLs, passwords, or flags into logs.
            raise Offline("target transport failed") from None


def run_once(target):
    if not _CHECKS:
        raise Infrastructure("no functionality hooks registered")
    for hook in _CHECKS:
        hook(target)


def _integer(value, name, low=1, high=2147483647):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("invalid " + name)
    return value


def _worker_target(payload):
    if not isinstance(payload, dict) or type(payload.get("protocolVersion")) is not int or payload["protocolVersion"] != 2:
        raise ValueError("only checker protocol V2 is supported")
    host = payload.get("targetIp")
    if not isinstance(host, str):
        raise ValueError("invalid targetIp")
    host = str(ipaddress.ip_address(host))
    tick_number = _integer(payload.get("tickNumber"), "tickNumber")
    round_start_tick = _integer(payload.get("roundStartTick"), "roundStartTick", high=tick_number)
    tick = _integer(payload.get("tick"), "tick")
    if tick != tick_number - round_start_tick + 1:
        raise ValueError("tick does not match its flag round")
    team_id = payload.get("teamId")
    if not isinstance(team_id, str) or not team_id.isascii() or not team_id.isdigit() or len(team_id) > 20 or int(team_id) < 1:
        raise ValueError("invalid teamId")
    raw_flags = payload.get("flags")
    if not isinstance(raw_flags, list) or not 1 <= len(raw_flags) <= MAX_FLAGS:
        raise ValueError("invalid retained flags")
    flags, seen_ids, seen_values = [], set(), set()
    for item in raw_flags:
        if not isinstance(item, dict):
            raise ValueError("invalid retained flag")
        flag_id = _integer(item.get("id"), "flag id")
        value = item.get("flag")
        issued = _integer(item.get("plantedAtTick"), "plantedAtTick", high=round_start_tick)
        placement = item.get("placement")
        if not isinstance(value, str) or not 1 <= len(value) <= 4096 or flag_id in seen_ids or value in seen_values:
            raise ValueError("invalid or duplicate retained flag")
        if placement not in ("new", "unknown", "confirmed", "failed"):
            raise ValueError("platform-v1 placement state required")
        if placement == "new" and (issued != round_start_tick or tick_number != round_start_tick):
            raise ValueError("new flags require the first tick of their round")
        flags.append(RetainedFlag(flag_id, value, issued, placement))
        seen_ids.add(flag_id)
        seen_values.add(value)
    if not any(flag.planted_at_tick == round_start_tick for flag in flags):
        raise ValueError("no current-round flag provided")
    return Target(ip=host, port=_integer(payload.get("targetPort"), "targetPort", high=65535),
                  round=_integer(payload.get("round"), "round"), tick=tick,
                  tick_number=tick_number, round_start_tick=round_start_tick,
                  team_id=team_id, challenge_id=_integer(payload.get("challengeId"), "challengeId"),
                  flags=tuple(flags))


def _claim_new_once(target, flag):
    # Duplicate delivery inside the same process must also stay read-only.
    # The platform ledger handles restarts/replacements and concurrent replicas.
    identity = (target.team_id, target.challenge_id, flag.id, hashlib.sha256(flag.value.encode()).digest())
    with _CLAIM_LOCK:
        if identity in _NEW_CLAIMS:
            return False
        _NEW_CLAIMS.add(identity)
        return True


def run_check(target):
    import checks  # by-name import; run.py already registered the same module

    results = [{"id": flag.id, "retrievable": False,
                "placement": "unknown" if flag.placement == "new" else flag.placement}
               for flag in target.flags]
    status = OK
    try:
        run_once(target)
    except CheckError as exc:
        status = exc.status
    except Exception:
        status = INTERNAL_ERROR

    can_place = status == OK
    try:
        for flag, result in zip(target.flags, results):
            if flag.placement == "new":
                if not can_place:
                    # No placement attempt: root can distinguish this response
                    # from a lost response via the explicit failed state.
                    result["placement"] = "failed"
                elif _claim_new_once(target, flag):
                    try:
                        result["placement"] = checks.put_flag(target, flag)
                        # A target acknowledgement proves it accepted this
                        # placement; only actual readback proves retention.
                    except Mumble:
                        result["placement"] = "failed"
                    except Offline:
                        status = max(status, OFFLINE)
                        result["placement"] = "unknown"
                    except Infrastructure:
                        result["placement"] = "unknown"
                else:
                    flag = replace(flag, placement="unknown")
            try:
                actual = checks.get_flag(target, flag)
                found = isinstance(actual, str) and hmac.compare_digest(actual.encode(), flag.value.encode())
            except Mumble:
                found = False
            except Offline:
                status = max(status, OFFLINE)
                found = False
            result["retrievable"] = found
            if found:
                result["placement"] = "confirmed"
            # Keep unresolved placement read-only, but report service health
            # independently. The platform excludes unknown retention evidence
            # and derives Mumble/Recovering from missing current/older flags.
        response = {"status": _NAME[status], "code": status, "flags": results}
        if status != OK:
            response["message"] = {MUMBLE: "ordinary service functionality failed",
                                   OFFLINE: "target service is unreachable",
                                   INTERNAL_ERROR: "checker execution failed"}[status]
        return response
    except Exception:
        # Unknown checker errors never become service failure evidence.
        return {"status": "InternalError", "code": INTERNAL_ERROR, "flags": results}
    finally:
        target.session.close()


class WorkerServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, address, token):
        if not token:
            raise ValueError("GZCTF_CHECKER_TOKEN must be configured")
        self.token = token
        self.check_lock = threading.Lock()
        super().__init__(address, _WorkerHandler)


class _WorkerHandler(BaseHTTPRequestHandler):
    server_version = "GZCTF-Checker-Worker/2"

    def setup(self):
        super().setup()
        self.connection.settimeout(30)

    def _json(self, status, body):
        raw = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        if self.path == "/healthz":
            self._json(200, {"status": "ready", "protocolVersion": 2,
                             "flagPlacement": "platform-v1", "groupedRounds": True})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        if self.path != "/check":
            self._json(404, {"error": "not found"})
            return
        supplied = self.headers.get("X-GZCTF-Checker-Token", "")
        if not hmac.compare_digest(supplied.encode(), self.server.token.encode()):
            self._json(401, {"status": "InternalError", "code": INTERNAL_ERROR})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_BODY or self.headers.get("Transfer-Encoding"):
                raise ValueError("invalid request length")
            if self.headers.get_content_type() != "application/json":
                raise ValueError("application/json required")
            payload = json.loads(self.rfile.read(length))
            target = _worker_target(payload)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            self._json(400, {"status": "InternalError", "code": INTERNAL_ERROR, "error": "invalid V2 request"})
            return
        if not self.server.check_lock.acquire(blocking=False):
            target.session.close()
            self._json(503, {"status": "InternalError", "code": INTERNAL_ERROR, "error": "worker is busy"})
            return
        try:
            result = run_check(target)
        finally:
            self.server.check_lock.release()
        # Release before responding: a client may send its next tick as soon as
        # it receives the response, and must not see a spurious busy verdict.
        self._json(200, result)

    def log_message(self, *_args):
        pass  # Request bodies, flags, credentials and target replies are secret.


def worker():
    host = os.environ.get("GZCTF_CHECKER_BIND", "0.0.0.0")
    port = int(os.environ.get("GZCTF_CHECKER_PORT", "8081"))
    server = WorkerServer((host, port), os.environ.get("GZCTF_CHECKER_TOKEN", ""))
    print(f"V2 checker worker listening on {host}:{port}", file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    print("persistent worker: start with python3 run.py", file=sys.stderr)
    sys.exit(INTERNAL_ERROR)
