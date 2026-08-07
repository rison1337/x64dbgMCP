import importlib.util
import json
import threading
import unittest
from pathlib import Path
from unittest import mock

import requests


MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "x64dbg.py"


def _load_bridge():
    spec = importlib.util.spec_from_file_location("x64dbg_transport_contract", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class FakeResponse:
    def __init__(self, status=200, body="", content_type="application/json"):
        self.status_code = int(status)
        self.ok = 200 <= self.status_code < 400
        self.content = body.encode("utf-8")
        self.text = body
        self.headers = {"Content-Type": content_type}


class FakeSession:
    def __init__(self, actions):
        self.actions = list(actions)
        self.calls = []

    def _next(self, method, url, kwargs):
        self.calls.append((method, url, kwargs))
        action = self.actions.pop(0)
        if isinstance(action, BaseException):
            raise action
        return action

    def get(self, url, **kwargs):
        return self._next("GET", url, kwargs)

    def post(self, url, **kwargs):
        return self._next("POST", url, kwargs)


class BridgeTransportContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_bridge()

    def setUp(self):
        self.original_session_getter = self.mod._get_http_session
        self.original_http_local = self.mod._HTTP_LOCAL
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["bridgeIdentity"] = None
            self.mod._RUNTIME_STATE["boundSession"] = None

    def tearDown(self):
        self.mod._get_http_session = self.original_session_getter
        self.mod._HTTP_LOCAL = self.original_http_local

    def _install_fake(self, *actions):
        session = FakeSession(actions)
        self.mod._get_http_session = lambda: session
        return session

    def _install_strong_identity(self):
        identity = {
            "bridgeInstanceId": "bridge-a",
            "sessionId": "session-a",
            "sessionGeneration": 7,
            "debuggeePid": 4242,
            "eventSeq": 19,
        }
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["bridgeIdentity"] = dict(identity)
            self.mod._RUNTIME_STATE["boundSession"] = {
                **identity,
                "pid": identity["debuggeePid"],
                "strict": True,
            }

    def test_success_json_and_text_have_exact_envelopes(self):
        session = self._install_fake(
            FakeResponse(body='{"ok":true,"value":7}'),
            FakeResponse(body="plain-result", content_type="text/plain"),
        )
        first = self.mod._bridge_request("GET", "Status", log=False, idempotent=False)
        second = self.mod._bridge_request("GET", "/Text", log=False, idempotent=False)

        self.assertTrue(first.ok)
        self.assertEqual(first.data["value"], 7)
        self.assertEqual(first.meta["httpStatus"], 200)
        self.assertTrue(second.ok)
        self.assertEqual(second.data, "plain-result")
        self.assertEqual(len(session.calls), 2)

    def test_http_and_application_errors_are_never_success_data(self):
        self._install_fake(
            FakeResponse(
                status=409,
                body='{"ok":false,"error":{"code":"stale_session","message":"old target"}}',
            ),
            FakeResponse(body='{"ok":false,"error":"operation failed"}'),
        )
        http_error = self.mod._bridge_request("GET", "Status", log=False)
        app_error = self.mod._bridge_request("GET", "Status", log=False)

        self.assertFalse(http_error.ok)
        self.assertEqual(http_error.error.code, "STALE_SESSION")
        self.assertEqual(http_error.error.http_status, 409)
        self.assertFalse(app_error.ok)
        self.assertEqual(app_error.error.code, "BRIDGE_ERROR")
        self.assertIn("operation failed", app_error.error.message)

    def test_malformed_json_is_invalid_response(self):
        self._install_fake(FakeResponse(body="{broken-json"))
        result = self.mod._bridge_request("GET", "Status", log=False)
        self.assertFalse(result.ok)
        self.assertEqual(result.error.code, "INVALID_RESPONSE")
        self.assertIn("broken-json", result.error.details["bodyPreview"])

    def test_bridge_hello_failure_points_known_targets_to_init_debuggee(self):
        failure = self.mod.BridgeEnvelope(
            False,
            error=self.mod.BridgeError(
                code="BRIDGE_UNAVAILABLE",
                message="No debugger bridge is listening.",
                retryable=True,
            ),
            meta={"endpoint": "Bridge/Hello"},
        )
        with mock.patch.object(self.mod, "_bridge_request", return_value=failure):
            result = self.mod.BridgeHello(refresh=True)

        self.assertFalse(result["ok"])
        self.assertEqual(result["nextAction"]["tool"], "InitDebuggee")
        self.assertEqual(
            result["nextAction"]["when"], "target_executable_path_is_known"
        )
        self.assertIn("X64DBG_ROOT", result["hint"])
        self.assertIn("do not search", result["hint"].lower())

    def test_idempotent_read_retries_with_same_request_id(self):
        session = self._install_fake(
            requests.exceptions.Timeout("first timeout"),
            FakeResponse(body='{"ok":true}'),
        )
        result = self.mod._bridge_request(
            "GET", "Status", log=False, guard="none", idempotent=True
        )
        self.assertTrue(result.ok)
        self.assertEqual(len(session.calls), 2)
        first_headers = session.calls[0][2]["headers"]
        second_headers = session.calls[1][2]["headers"]
        self.assertEqual(
            first_headers["X-MCP-Request-Id"], second_headers["X-MCP-Request-Id"]
        )
        self.assertEqual(result.meta["attempt"], 2)

    def test_mutation_timeout_is_never_retried(self):
        self._install_strong_identity()
        session = self._install_fake(requests.exceptions.Timeout("mutation timeout"))
        result = self.mod._bridge_request(
            "GET", "Memory/Write", params={"addr": "0x1000", "data": "00"}, log=False
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.error.code, "BRIDGE_TIMEOUT")
        self.assertEqual(len(session.calls), 1)

    def test_guarded_mutation_sends_exact_owner_headers(self):
        self._install_strong_identity()
        session = self._install_fake(FakeResponse(body='{"ok":true}'))
        result = self.mod._bridge_request(
            "GET",
            "Memory/Write",
            params={"addr": "0x1000", "data": "00"},
            expected_event_seq=23,
            log=False,
        )
        self.assertTrue(result.ok)
        headers = session.calls[0][2]["headers"]
        self.assertEqual(headers["X-MCP-Bridge-Id"], "bridge-a")
        self.assertEqual(headers["X-MCP-Session-Id"], "session-a")
        self.assertEqual(headers["X-MCP-Session-Generation"], "7")
        self.assertEqual(headers["X-MCP-Debuggee-Pid"], "4242")
        self.assertEqual(headers["X-MCP-Event-Seq"], "23")

    def test_guard_fails_closed_before_network_when_identity_is_missing(self):
        session = self._install_fake(FakeResponse(body='{"ok":true}'))
        result = self.mod._bridge_request(
            "GET", "Register/Set", params={"register": "rax", "value": "1"}, log=False
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.error.code, "BRIDGE_IDENTITY_UNAVAILABLE")
        self.assertEqual(session.calls, [])

    def test_invalid_unicode_query_fails_before_network(self):
        session = self._install_fake(FakeResponse(body='{"ok":true}'))
        result = self.mod._bridge_request(
            "GET", "Status", params={"bad": "\ud800"}, log=False
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.error.code, "INVALID_ARGUMENT")
        self.assertEqual(session.calls, [])

    def test_sensitive_values_are_redacted_recursively(self):
        redacted = self.mod._redact_sensitive(
            {
                "token": "abc",
                "environment": {"API_KEY": "secret"},
                "nested": {"password": "pw", "visible": "yes"},
            }
        )
        self.assertEqual(redacted["token"], "<redacted>")
        self.assertEqual(redacted["environment"]["API_KEY"], "<redacted>")
        self.assertEqual(redacted["nested"]["password"], "<redacted>")
        self.assertEqual(redacted["nested"]["visible"], "yes")

    def test_legacy_adapter_preserves_error_string_shape(self):
        self._install_fake(FakeResponse(status=500, body="bridge exploded", content_type="text/plain"))
        result = self.mod.safe_get("Status", log=False)
        self.assertIsInstance(result, str)
        self.assertTrue(result.startswith("Error 500:"), result)

    def test_http_sessions_are_thread_local(self):
        self.mod._HTTP_LOCAL = threading.local()
        observed = [self.mod._get_http_session()]

        def worker():
            observed.append(self.mod._get_http_session())
            observed.append(self.mod._get_http_session())

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertIs(observed[1], observed[2])
        self.assertIsNot(observed[0], observed[1])
        for session in {id(item): item for item in observed}.values():
            session.close()


if __name__ == "__main__":
    unittest.main()
