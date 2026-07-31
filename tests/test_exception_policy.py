import importlib.util
import json
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "x64dbg.py"


def _load_bridge():
    spec = importlib.util.spec_from_file_location("x64dbg_exception_policy", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ExceptionPolicyContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_bridge()

    def _session(self, event_seq=417):
        return {
            "debugging": True,
            "paused": True,
            "debuggeePid": 4242,
            "eventSeq": event_seq,
            "session": {"sessionId": "session-policy", "generation": 9},
        }

    def _successful_request(self, calls, payload=None):
        response = payload or {"ok": True}

        def fake_request(method, endpoint, **kwargs):
            calls.append((method, endpoint, kwargs))
            return self.mod.BridgeEnvelope(
                True,
                data=response,
                meta={"requestId": "request-policy", "eventSeq": 417},
            )

        return fake_request

    def test_set_normalizes_selectors_actions_chance_and_priority(self):
        calls = []
        rules = [
            {
                "ruleId": "access-violation",
                "code": "0xC0000005",
                "chance": "first",
                "action": "skip",
                "priority": 25,
            },
            {
                "ruleId": "language-family",
                "code": "0xE1234567",
                "mask": "0xF0000000",
                "chance": "second",
                "action": "pass",
                "priority": 10,
                "enabled": False,
            },
            {
                "ruleId": "fallback",
                "code": "*",
                "chance": "any",
                "action": "stop",
                "priority": -5,
            },
        ]

        with mock.patch.object(
            self.mod, "_get_debug_session_state", return_value=self._session()
        ), mock.patch.object(
            self.mod,
            "_bridge_request",
            side_effect=self._successful_request(calls),
        ):
            result = self.mod.SetExceptionPolicy(
                json.dumps(rules),
                enabled=True,
                first_chance_default="skip",
                second_chance_default="pass",
                replace=True,
            )

        self.assertTrue(result["ok"], result)
        self.assertEqual(len(calls), 1)
        method, endpoint, kwargs = calls[0]
        self.assertEqual((method, endpoint), ("POST", "Debug/ExceptionPolicy/Set"))
        self.assertEqual(kwargs["guard"], "session")
        self.assertEqual(kwargs["expected_event_seq"], 417)
        self.assertFalse(kwargs["idempotent"])

        form = kwargs["form_data"]
        self.assertEqual(form["enabled"], "true")
        self.assertEqual(form["firstChanceDefault"], "handled")
        self.assertEqual(form["secondChanceDefault"], "not_handled")
        self.assertEqual(form["replace"], "true")
        self.assertEqual(form["ruleCount"], "3")

        self.assertEqual(form["rule0Id"], "access-violation")
        self.assertEqual(form["rule0Codes"], "0xc0000005")
        self.assertEqual(form["rule0Chance"], "first")
        self.assertEqual(form["rule0Action"], "handled")
        self.assertEqual(form["rule0Priority"], "25")
        self.assertEqual(form["rule0Enabled"], "true")

        # Masked selectors are canonicalized after applying the mask.  Keeping
        # non-significant bits would make semantically identical rules compare
        # differently and would make policy snapshots non-deterministic.
        self.assertEqual(
            form["rule1Codes"], "0xe0000000/0xf0000000"
        )
        self.assertEqual(form["rule1Chance"], "second")
        self.assertEqual(form["rule1Action"], "not_handled")
        self.assertEqual(form["rule1Priority"], "10")
        self.assertEqual(form["rule1Enabled"], "false")

        self.assertEqual(form["rule2Codes"], "*")
        self.assertEqual(form["rule2Chance"], "any")
        self.assertEqual(form["rule2Action"], "pause")
        self.assertEqual(form["rule2Priority"], "-5")

    def test_missing_rule_ids_are_generated_and_unique(self):
        calls = []
        rules = [
            {"code": 0x80000003, "chance": "first", "action": "stop"},
            {"code": "0x80000004", "chance": "second", "action": "pass"},
        ]
        with mock.patch.object(
            self.mod, "_get_debug_session_state", return_value=self._session()
        ), mock.patch.object(
            self.mod,
            "_bridge_request",
            side_effect=self._successful_request(calls),
        ):
            result = self.mod.SetExceptionPolicy(json.dumps(rules))

        self.assertTrue(result["ok"], result)
        form = calls[0][2]["form_data"]
        generated_ids = [form["rule0Id"], form["rule1Id"]]
        self.assertTrue(all(isinstance(value, str) and value for value in generated_ids))
        self.assertEqual(len(set(generated_ids)), 2)
        self.assertEqual(form["rule0Codes"], "0x80000003")
        self.assertEqual(form["rule1Codes"], "0x80000004")

    def test_duplicate_explicit_rule_ids_fail_before_bridge_mutation(self):
        calls = []
        rules = [
            {"ruleId": "duplicate", "code": "0x1", "action": "stop"},
            {"ruleId": "DUPLICATE", "code": "0x2", "action": "pass"},
        ]
        with mock.patch.object(
            self.mod, "_get_debug_session_state", return_value=self._session()
        ), mock.patch.object(
            self.mod,
            "_bridge_request",
            side_effect=self._successful_request(calls),
        ):
            result = self.mod.SetExceptionPolicy(json.dumps(rules))

        self.assertFalse(result["ok"])
        self.assertIn("RULE_ID", str(result.get("errorCode") or "").upper())
        self.assertEqual(calls, [])

    def test_invalid_selector_action_chance_and_priority_are_rejected_locally(self):
        invalid_rules = [
            {"code": "not-a-code", "action": "stop"},
            {"code": "0xc0000005", "action": "invented"},
            {"code": "0xc0000005", "action": "stop", "chance": "third"},
            {"code": "0xc0000005", "action": "stop", "priority": 1.5},
            {"code": "*", "mask": "0xffff0000", "action": "stop"},
        ]
        for rule in invalid_rules:
            with self.subTest(rule=rule):
                calls = []
                with mock.patch.object(
                    self.mod,
                    "_get_debug_session_state",
                    return_value=self._session(),
                ), mock.patch.object(
                    self.mod,
                    "_bridge_request",
                    side_effect=self._successful_request(calls),
                ):
                    result = self.mod.SetExceptionPolicy(json.dumps([rule]))
                self.assertFalse(result["ok"], result)
                self.assertTrue(result.get("errorCode"), result)
                self.assertEqual(calls, [])

    def test_invalid_defaults_and_json_shape_are_rejected(self):
        cases = [
            ({"rules_json": "42"}, "POLICY"),
            ({"rules_json": "not json"}, "JSON"),
            (
                {
                    "rules_json": "[]",
                    "first_chance_default": "invented",
                },
                "DEFAULT",
            ),
            (
                {
                    "rules_json": "[]",
                    "second_chance_default": "invented",
                },
                "DEFAULT",
            ),
        ]
        for kwargs, category in cases:
            with self.subTest(kwargs=kwargs):
                calls = []
                with mock.patch.object(
                    self.mod,
                    "_get_debug_session_state",
                    return_value=self._session(),
                ), mock.patch.object(
                    self.mod,
                    "_bridge_request",
                    side_effect=self._successful_request(calls),
                ):
                    result = self.mod.SetExceptionPolicy(**kwargs)
                self.assertFalse(result["ok"], result)
                self.assertIn(category, str(result.get("errorCode") or "").upper())
                self.assertEqual(calls, [])

    def test_replace_false_requests_an_atomic_append(self):
        calls = []
        rules = [
            {
                "ruleId": "append-rule",
                "code": "0x406d1388",
                "chance": "any",
                "action": "stop",
                "priority": 3,
            }
        ]
        with mock.patch.object(
            self.mod, "_get_debug_session_state", return_value=self._session()
        ), mock.patch.object(
            self.mod,
            "_bridge_request",
            side_effect=self._successful_request(calls),
        ):
            result = self.mod.SetExceptionPolicy(json.dumps(rules), replace=False)

        self.assertTrue(result["ok"], result)
        self.assertEqual(calls[0][2]["form_data"]["replace"], "false")

    def test_mutation_fails_closed_without_current_event_identity(self):
        calls = []
        with mock.patch.object(
            self.mod,
            "_get_debug_session_state",
            return_value={"debugging": True, "debuggeePid": 4242, "eventSeq": 0},
        ), mock.patch.object(
            self.mod,
            "_bridge_request",
            side_effect=self._successful_request(calls),
        ):
            result = self.mod.SetExceptionPolicy("[]")

        self.assertFalse(result["ok"])
        self.assertIn("EVENT", str(result.get("errorCode") or "").upper())
        self.assertEqual(calls, [])

    def test_get_policy_is_an_idempotent_auth_only_read(self):
        calls = []
        payload = {
            "ok": True,
            "policy": {
                "enabled": True,
                "firstChanceDefault": "pause",
                "secondChanceDefault": "pause",
                "rules": [],
            },
        }
        with mock.patch.object(
            self.mod,
            "_bridge_request",
            side_effect=self._successful_request(calls, payload),
        ):
            result = self.mod.GetExceptionPolicy()

        self.assertTrue(result["ok"], result)
        self.assertEqual(len(calls), 1)
        method, endpoint, kwargs = calls[0]
        self.assertEqual((method, endpoint), ("GET", "Debug/ExceptionPolicy/Get"))
        self.assertEqual(kwargs["guard"], "none")
        self.assertTrue(kwargs["idempotent"])
        self.assertNotIn("expected_event_seq", kwargs)

    def test_canonical_native_success_envelope_is_unwrapped(self):
        calls = []
        payload = {
            "ok": True,
            "data": {
                "policy": {
                    "enabled": True,
                    "firstChanceDefault": "pause",
                    "secondChanceDefault": "pause",
                    "rules": [],
                }
            },
            "error": None,
            "meta": {
                "requestId": "native-request",
                "sessionId": "session-policy",
                "eventSeq": 418,
            },
        }
        with mock.patch.object(
            self.mod,
            "_bridge_request",
            side_effect=self._successful_request(calls, payload),
        ):
            result = self.mod.GetExceptionPolicy()

        self.assertTrue(result["ok"], result)
        self.assertNotIn("data", result)
        self.assertTrue(result["policy"]["enabled"])
        self.assertEqual(result["meta"]["requestId"], "native-request")
        self.assertEqual(result["meta"]["sessionId"], "session-policy")
        self.assertEqual(result["meta"]["eventSeq"], 418)

    def test_canonical_history_records_are_unwrapped_and_aliased(self):
        calls = []
        payload = {
            "ok": True,
            "data": {
                "records": [{"historySeq": 42, "eventSeq": 500}],
                "nextAfterSeq": 42,
            },
            "error": None,
            "meta": {"sessionId": "session-policy"},
        }
        with mock.patch.object(
            self.mod,
            "_bridge_request",
            side_effect=self._successful_request(calls, payload),
        ):
            result = self.mod.GetExceptionHistory(after_seq=41, limit=25)

        self.assertEqual(result["records"], result["history"])
        self.assertEqual(result["history"][0]["historySeq"], 42)
        self.assertEqual(result["meta"]["sessionId"], "session-policy")

    def test_clear_policy_is_guarded_and_can_clear_history_atomically(self):
        calls = []
        with mock.patch.object(
            self.mod, "_get_debug_session_state", return_value=self._session(502)
        ), mock.patch.object(
            self.mod,
            "_bridge_request",
            side_effect=self._successful_request(calls),
        ):
            result = self.mod.ClearExceptionPolicy(clear_history=True)

        self.assertTrue(result["ok"], result)
        method, endpoint, kwargs = calls[0]
        self.assertEqual((method, endpoint), ("POST", "Debug/ExceptionPolicy/Clear"))
        self.assertEqual(kwargs["form_data"]["clearHistory"], "true")
        self.assertEqual(kwargs["guard"], "session")
        self.assertEqual(kwargs["expected_event_seq"], 502)
        self.assertFalse(kwargs["idempotent"])

    def test_get_exception_history_uses_exclusive_cursor_and_limit(self):
        calls = []
        payload = {
            "ok": True,
            "history": [{"historySeq": 42, "eventSeq": 500}],
            "nextAfterSeq": 42,
        }
        with mock.patch.object(
            self.mod,
            "_bridge_request",
            side_effect=self._successful_request(calls, payload),
        ):
            result = self.mod.GetExceptionHistory(after_seq=41, limit=25)

        self.assertTrue(result["ok"], result)
        method, endpoint, kwargs = calls[0]
        self.assertEqual((method, endpoint), ("GET", "Debug/ExceptionHistory/Get"))
        self.assertEqual(kwargs["params"], {"afterSeq": 41, "limit": 25})
        self.assertEqual(kwargs["guard"], "none")
        self.assertTrue(kwargs["idempotent"])
        self.assertNotIn("expected_event_seq", kwargs)

    def test_get_exception_history_rejects_invalid_cursor_and_limit_locally(self):
        for kwargs in (
            {"after_seq": -1, "limit": 100},
            {"after_seq": 0, "limit": 0},
            {"after_seq": 0, "limit": 1001},
        ):
            with self.subTest(kwargs=kwargs):
                calls = []
                with mock.patch.object(
                    self.mod,
                    "_bridge_request",
                    side_effect=self._successful_request(calls),
                ):
                    result = self.mod.GetExceptionHistory(**kwargs)
                self.assertFalse(result["ok"], result)
                self.assertTrue(result.get("errorCode"), result)
                self.assertEqual(calls, [])

    def test_clear_exception_history_is_a_guarded_mutation(self):
        calls = []
        with mock.patch.object(
            self.mod, "_get_debug_session_state", return_value=self._session(613)
        ), mock.patch.object(
            self.mod,
            "_bridge_request",
            side_effect=self._successful_request(calls),
        ):
            result = self.mod.ClearExceptionHistory()

        self.assertTrue(result["ok"], result)
        method, endpoint, kwargs = calls[0]
        self.assertEqual((method, endpoint), ("POST", "Debug/ExceptionHistory/Clear"))
        self.assertEqual(kwargs["form_data"], {})
        self.assertEqual(kwargs["guard"], "session")
        self.assertEqual(kwargs["expected_event_seq"], 613)
        self.assertFalse(kwargs["idempotent"])

    def test_bridge_failures_remain_structured_for_all_public_reads(self):
        def failed_request(method, endpoint, **kwargs):
            return self.mod.BridgeEnvelope(
                False,
                error=self.mod.BridgeError(
                    "BRIDGE_UNAVAILABLE",
                    "bridge is unavailable",
                    retryable=True,
                    endpoint=endpoint,
                ),
                meta={"requestId": "failed-request"},
            )

        with mock.patch.object(
            self.mod, "_bridge_request", side_effect=failed_request
        ):
            policy = self.mod.GetExceptionPolicy()
            history = self.mod.GetExceptionHistory()

        for result in (policy, history):
            self.assertFalse(result["ok"], result)
            self.assertEqual(result["errorCode"], "BRIDGE_UNAVAILABLE")
            self.assertEqual(result["error"], "bridge is unavailable")
            self.assertEqual(result["meta"]["requestId"], "failed-request")

    def test_native_policy_disables_legacy_wait_filter_to_prevent_double_continue(self):
        state = {
            "paused": True,
            "session": {
                "exceptionCode": "0xc0000005",
                "exceptionFirstChance": True,
            },
        }
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["nativeExceptionPolicyActive"] = True
            self.mod._RUNTIME_STATE["exceptionFilters"] = [
                {
                    "codes": ["0xc0000005"],
                    "action": "skip",
                    "firstChanceOnly": True,
                }
            ]
        try:
            self.assertIsNone(self.mod._match_exception_filter(state))
        finally:
            with self.mod._RUNTIME_LOCK:
                self.mod._RUNTIME_STATE["nativeExceptionPolicyActive"] = False
                self.mod._RUNTIME_STATE["exceptionFilters"] = []

    def test_legacy_filter_maps_to_native_policy_adapter(self):
        calls = []

        def fake_set(**kwargs):
            calls.append(kwargs)
            return {"ok": True, "revision": 3}

        with mock.patch.object(self.mod, "SetExceptionPolicy", side_effect=fake_set), mock.patch.object(
            self.mod,
            "GetExceptionPolicy",
            return_value={"ok": True, "policy": {"rules": []}},
        ):
            result = self.mod.SetExceptionFilter(
                '["0xc0000005"]', action="pass", append=True, first_chance_only=False
            )

        self.assertTrue(result["ok"], result)
        self.assertTrue(result["legacyAdapter"])
        self.assertEqual(len(calls), 1)
        submitted = json.loads(calls[0]["rules_json"])[0]
        self.assertEqual(submitted["action"], "not_handled")
        self.assertEqual(submitted["chance"], "any")
        self.assertFalse(calls[0]["replace"])


if __name__ == "__main__":
    unittest.main()
