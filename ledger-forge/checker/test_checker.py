"""Local V2 contract/retention regression suite; no external targets or Docker.

Run from this directory: python3 -m unittest -v test_checker.py
Requires checker/requirements.txt and src/requirements.txt in the test Python.
"""
import base64
from contextlib import closing
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

import requests
from werkzeug.serving import make_server, WSGIRequestHandler

import checker
import checks


class QuietRequestHandler(WSGIRequestHandler):
    def log(self, *_args, **_kwargs):
        pass


class CheckerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="ledger-forge-v2-")
        self.environment = patch.dict(os.environ, {"LEDGER_DATA_DIR": self.directory.name})
        self.environment.start()
        self.platform_state = {}
        checker._NEW_CLAIMS.clear()
        self.start_service()
        self.worker = checker.WorkerServer(("127.0.0.1", 0), "test-only-worker-token")
        self.worker_thread = threading.Thread(target=self.worker.serve_forever, daemon=True)
        self.worker_thread.start()

    def tearDown(self):
        self.worker.shutdown()
        self.worker.server_close()
        self.worker_thread.join()
        self.stop_service()
        self.environment.stop()
        self.directory.cleanup()

    def start_service(self, patched=False):
        path = Path(__file__).resolve().parent.parent / "src" / "app.py"
        spec = importlib.util.spec_from_file_location("ledger_service_under_test", path)
        self.service = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.service)
        if patched:
            original_verify = self.service.verify_jwt

            def secure_verify(token):
                try:
                    header = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
                    return original_verify(token) if header.get("alg") == "RS256" else None
                except (ValueError, TypeError, KeyError):
                    return None

            self.service.verify_jwt = secure_verify

            def safe_report():
                from flask import jsonify
                # Disabling unsafe template evaluation is a legitimate patch;
                # the checker must not demand that arbitrary templates execute.
                return jsonify(ok=True, html="Expense Report")

            self.service.app.view_functions["admin_report"] = safe_report
        self.paths = []

        @self.service.app.before_request
        def record_path():
            from flask import request
            self.paths.append(request.path)

        self.http = make_server("127.0.0.1", 0, self.service.app, threaded=True, request_handler=QuietRequestHandler)
        self.http_thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.http_thread.start()

    def stop_service(self):
        self.http.shutdown()
        self.http.server_close()
        self.http_thread.join()

    def restart_worker(self):
        self.worker.shutdown()
        self.worker.server_close()
        self.worker_thread.join()
        checker._NEW_CLAIMS.clear()
        self.worker = checker.WorkerServer(("127.0.0.1", 0), "test-only-worker-token")
        self.worker_thread = threading.Thread(target=self.worker.serve_forever, daemon=True)
        self.worker_thread.start()

    def payload(self, tick, retained=None, *, ticks_per_round=1):
        start = (tick - 1) // ticks_per_round * ticks_per_round + 1
        retained = list(range(1, start + 1, ticks_per_round)) if retained is None else retained
        return {
            "protocolVersion": 2, "targetIp": "127.0.0.1", "targetPort": self.http.server_port,
            "round": (tick - 1) // ticks_per_round + 1, "tick": tick - start + 1,
            "tickNumber": tick, "roundStartTick": start, "teamId": "12", "challengeId": 8,
            "flags": [{"id": number, "flag": "flag{ledger-v2-secret-" + str(number) + "}",
                       "plantedAtTick": number, "placement": self.platform_state.get(number, "new")}
                      for number in retained],
        }

    def send(self, payload, token="test-only-worker-token"):
        response = requests.post(f"http://127.0.0.1:{self.worker.server_port}/check", json=payload,
                                 headers={"X-GZCTF-Checker-Token": token}, timeout=30)
        return response.status_code, response.json()

    def check(self, tick, retained=None, *, ticks_per_round=1):
        code, result = self.send(self.payload(tick, retained, ticks_per_round=ticks_per_round))
        self.assertEqual(code, 200)
        for flag in result.get("flags", []):
            self.platform_state[flag["id"]] = flag["placement"]
        return result

    def flag_identity(self, number):
        return checks.identity(checker.RetainedFlag(number, "flag{ledger-v2-secret-" + str(number) + "}", number, "confirmed"))

    def sql(self, statement, values=()):
        with closing(sqlite3.connect(Path(self.directory.name) / "ledger.sqlite3")) as db:
            with db:
                return db.execute(statement, values).fetchall()

    def test_fresh_and_retained_flags_are_retrieved_via_ordinary_routes(self):
        for tick in range(1, 4):
            result = self.check(tick)
            self.assertEqual(result["status"], "Ok")
            self.assertEqual(result["flags"], [
                {"id": number, "retrievable": True, "placement": "confirmed"} for number in range(1, tick + 1)
            ])
        self.assertNotIn("/admin/report", self.paths)
        self.assertNotIn("/flag", self.paths)

    def test_patching_jwt_and_ssti_keeps_functionality_and_all_flags_green(self):
        self.assertEqual(self.check(1, ticks_per_round=5)["status"], "Ok")
        self.stop_service()
        self.start_service(patched=True)
        for tick in range(2, 8):
            result = self.check(tick, ticks_per_round=5)
            self.assertEqual(result["status"], "Ok")
            self.assertTrue(all(flag["retrievable"] for flag in result["flags"]))
        self.assertNotIn("/admin/report", self.paths)
        self.assertNotIn("/flag", self.paths)

    def test_grouped_rounds_check_every_tick_and_place_only_at_round_boundaries(self):
        with patch.object(checker, "run_once", wraps=checker.run_once) as health, \
                patch.object(checks, "put_flag", wraps=checks.put_flag) as put, \
                patch.object(checks, "get_flag", wraps=checks.get_flag) as get:
            for tick in range(1, 27):
                # The platform, not the worker, selects the still-valid flags.
                # Five flag rounds of five ticks keep flag 1 through tick 25.
                retained = [issued for issued in range(1, tick + 1, 5) if tick < issued + 25]
                with self.subTest(tick=tick):
                    result = self.check(tick, retained, ticks_per_round=5)
                    self.assertEqual(result["status"], "Ok")
                    self.assertEqual(result["flags"], [
                        {"id": issued, "retrievable": True, "placement": "confirmed"} for issued in retained
                    ])
            self.assertEqual(health.call_count, 26)
            self.assertEqual([call.args[1].id for call in put.call_args_list], [1, 6, 11, 16, 21, 26])
            self.assertEqual(sum(call.args[1].id == 1 for call in get.call_args_list), 25)
            self.assertEqual([
                (call.args[0].round, call.args[0].tick, call.args[0].round_start_tick)
                for call in health.call_args_list
            ], [((tick - 1) // 5 + 1, (tick - 1) % 5 + 1, (tick - 1) // 5 * 5 + 1)
                for tick in range(1, 27)])

    def test_intermediate_ticks_and_worker_replacement_never_repair_missing_round_flag(self):
        self.check(1, ticks_per_round=5)
        self.sql("DELETE FROM entries WHERE username = ?", (self.flag_identity(1)["username"],))
        self.restart_worker()
        with patch.object(checks, "put_flag", wraps=checks.put_flag) as put:
            for tick in range(2, 6):
                result = self.check(tick, ticks_per_round=5)
                self.assertEqual(result["status"], "Ok")  # Platform derives Mumble.
                self.assertEqual(result["flags"], [{"id": 1, "retrievable": False, "placement": "confirmed"}])
            put.assert_not_called()
            for tick in (6, 7):
                result = self.check(tick, ticks_per_round=5)
                self.assertEqual(result["status"], "Ok")  # Platform derives Recovering.
                self.assertEqual(result["flags"], [
                    {"id": 1, "retrievable": False, "placement": "confirmed"},
                    {"id": 6, "retrievable": True, "placement": "confirmed"},
                ])
            self.assertEqual([call.args[1].id for call in put.call_args_list], [6])
        self.assertEqual(self.sql("SELECT memo FROM entries WHERE username = ?", (self.flag_identity(1)["username"],)), [])

    def test_completed_check_unlocks_before_sending_response(self):
        original_json = checker._WorkerHandler._json
        locked_at_response = []

        def observed(handler, status, body):
            if handler.command == "POST" and status == 200:
                locked_at_response.append(handler.server.check_lock.locked())
            return original_json(handler, status, body)

        with patch.object(checker._WorkerHandler, "_json", observed):
            for tick in range(1, 8):
                self.assertEqual(self.check(tick, ticks_per_round=5)["status"], "Ok")
        self.assertEqual(locked_at_response, [False] * 7)

    def test_deleted_old_flag_is_false_without_repair_and_new_flag_survives(self):
        self.check(1)
        self.sql("DELETE FROM entries WHERE username = ?", (self.flag_identity(1)["username"],))
        result = self.check(2)
        self.assertEqual(result["status"], "Ok")  # platform derives Recovering
        self.assertEqual([flag["retrievable"] for flag in result["flags"]], [False, True])
        self.assertEqual(self.sql("SELECT memo FROM entries WHERE username = ?", (self.flag_identity(1)["username"],)), [])
        self.assertEqual([flag["retrievable"] for flag in self.check(2)["flags"]], [False, True])

    def test_corrupted_newest_flag_is_false_on_retry_without_repair(self):
        original_request = self.payload(1)
        self.check(1)
        self.sql("UPDATE entries SET memo = 'corrupted' WHERE username = ?", (self.flag_identity(1)["username"],))
        result = self.check(1)
        self.assertEqual(result["status"], "Ok")  # platform derives Mumble
        self.assertFalse(result["flags"][0]["retrievable"])
        # Even an accidental exact duplicate of the original `new` dispatch
        # cannot recreate the corrupted record inside a still-running worker.
        _, replay = self.send(original_request)
        self.assertFalse(replay["flags"][0]["retrievable"])
        self.assertEqual(self.sql("SELECT memo FROM entries WHERE username = ?", (self.flag_identity(1)["username"],)), [("corrupted",)])

    def test_replacement_worker_cannot_recreate_deleted_account_or_entries(self):
        self.check(1)
        self.sql("DELETE FROM entries WHERE username = ?", (self.flag_identity(1)["username"],))
        self.sql("DELETE FROM users WHERE username = ?", (self.flag_identity(1)["username"],))
        # Process replacement loses all worker-local information. The durable
        # platform state and full flag reconstruct read-only access correctly.
        checker._NEW_CLAIMS.clear()
        result = self.check(1)
        self.assertFalse(result["flags"][0]["retrievable"])
        self.assertEqual(result["flags"][0]["placement"], "confirmed")
        self.assertEqual(self.sql("SELECT username FROM users WHERE username = ?", (self.flag_identity(1)["username"],)), [])

    def test_target_process_restart_preserves_user_data_and_tokens(self):
        self.check(1)
        old_key = self.service.PUB_PEM
        self.stop_service()
        self.start_service()
        checker._NEW_CLAIMS.clear()
        result = self.check(2)
        self.assertEqual(result["status"], "Ok")
        self.assertTrue(all(flag["retrievable"] for flag in result["flags"]))
        self.assertEqual(old_key, self.service.PUB_PEM)

    def test_ambiguous_write_missing_flag_is_internal_error_never_repaired(self):
        with patch.object(checks, "put_flag", side_effect=checker.Offline("write response lost")):
            result = self.check(1, ticks_per_round=5)
        self.assertEqual(result["status"], "InternalError")
        self.assertEqual(result["flags"][0]["placement"], "unknown")
        self.restart_worker()
        with patch.object(checks, "put_flag", side_effect=AssertionError("must not repair")):
            retry = self.check(2, ticks_per_round=5)
        self.assertEqual(retry["status"], "InternalError")
        self.assertFalse(retry["flags"][0]["retrievable"])

    def test_ambiguous_write_can_resolve_by_readback_after_worker_replacement(self):
        real_put = checks.put_flag

        def accepted_then_lost(target, flag):
            real_put(target, flag)
            raise checker.Offline("write response lost")

        with patch.object(checks, "put_flag", side_effect=accepted_then_lost), \
                patch.object(checks, "get_flag", side_effect=checker.Offline("target restarting")):
            result = self.check(1)
        self.assertEqual(result["status"], "InternalError")
        checker._NEW_CLAIMS.clear()
        with patch.object(checks, "put_flag", side_effect=AssertionError("must only read")):
            retry = self.check(1)
        self.assertEqual(retry["status"], "Ok")
        self.assertEqual(retry["flags"], [{"id": 1, "retrievable": True, "placement": "confirmed"}])

    def test_unknown_old_flag_does_not_prevent_new_flag_placement(self):
        with patch.object(checks, "put_flag", side_effect=checker.Offline("write response lost")):
            self.check(1)
        result = self.check(2)
        self.assertEqual(result["status"], "InternalError")
        self.assertEqual(result["flags"], [
            {"id": 1, "retrievable": False, "placement": "unknown"},
            {"id": 2, "retrievable": True, "placement": "confirmed"},
        ])

    def test_malformed_write_ack_and_server_error_remain_unknown_but_rejection_is_failed(self):
        original_post = checker.Target.post
        for tick, code, body, placement in [(1, 200, b"not-json", "unknown"),
                                             (2, 500, b'{"error":"failed"}', "unknown"),
                                             (3, 400, b'{"error":"rejected"}', "failed")]:
            def intercepted(target, path="/", **kwargs):
                if path == "/entries" and kwargs.get("json", {}).get("memo", "").startswith("flag{"):
                    response = requests.Response()
                    response.status_code = code
                    response._content = body
                    return response
                return original_post(target, path, **kwargs)

            with self.subTest(code=code), patch.object(checker.Target, "post", intercepted):
                result = self.check(tick, retained=[tick])
                self.assertEqual(result["flags"][0]["placement"], placement)
                self.assertFalse(result["flags"][0]["retrievable"])
                self.assertEqual(result["status"], "InternalError" if placement == "unknown" else "Ok")

    def test_contract_is_authenticated_v2_only_and_rejects_malformed_input(self):
        readiness = requests.get(f"http://127.0.0.1:{self.worker.server_port}/healthz", timeout=3).json()
        self.assertEqual(readiness["protocolVersion"], 2)
        self.assertEqual(readiness["flagPlacement"], "platform-v1")
        self.assertIs(readiness["groupedRounds"], True)
        self.assertEqual(self.send(self.payload(1), token="wrong")[0], 401)
        invalid = [
            {**self.payload(1), "protocolVersion": 1},
            {**self.payload(1), "flags": []},
            {**self.payload(1), "targetIp": "127.0.0.1/anything"},
            {**self.payload(1), "targetPort": True},
            {**self.payload(1), "flags": self.payload(1)["flags"] * 2},
            {**self.payload(2), "flags": [{**self.payload(1)["flags"][0], "placement": "new"}, self.payload(2)["flags"][1]]},
            {key: value for key, value in self.payload(1).items() if key != "roundStartTick"},
            {**self.payload(1), "roundStartTick": True},
            {**self.payload(1), "roundStartTick": 0},
            {**self.payload(1), "roundStartTick": 2},
            {**self.payload(1), "tick": 2},
            self.payload(2, ticks_per_round=5),  # Cannot initialize flag 1 on validation tick 2.
            {**self.payload(2, ticks_per_round=5), "flags": [
                {"id": 2, "flag": "flag{invalid-mid-round}", "plantedAtTick": 2, "placement": "confirmed"}
            ]},
            {**self.payload(6, ticks_per_round=5), "flags": [
                {**self.payload(1)["flags"][0], "placement": "confirmed"}
            ]},  # The current round's flag cannot be omitted.
        ]
        for request in invalid:
            with self.subTest(request=request):
                self.assertEqual(self.send(request)[0], 400)

    def test_flag_credentials_are_secret_dependent_and_not_tick_predictable(self):
        first = checker.RetainedFlag(1, "flag{one-secret}", 1, "new")
        other = checker.RetainedFlag(1, "flag{different-secret}", 1, "new")
        self.assertNotEqual(checks.identity(first), checks.identity(other))
        self.assertEqual(checks.identity(first), checks.identity(first))
        with self.assertRaises(ValueError):
            checker.WorkerServer(("127.0.0.1", 0), "")


if __name__ == "__main__":
    unittest.main()
