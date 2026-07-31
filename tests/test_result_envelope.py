import asyncio
import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = ROOT / "src" / "x64dbg.py"


def _load_server():
    name = "x64dbg_result_envelope_test"
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(name, SERVER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class PublicResultEnvelopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_server()

    def test_success_is_canonical_and_preserves_legacy_payload(self):
        result = self.mod._canonicalize_public_result(
            "Example", {"ok": True, "value": 7, "warning": None}
        )
        self.assertEqual(set(result), {"ok", "data", "error", "meta"})
        self.assertTrue(result["ok"])
        self.assertEqual(result["data"]["value"], 7)
        self.assertIsNone(result["error"])
        self.assertEqual(result["meta"]["resultContract"], "envelope-v1")
        self.assertEqual(result["meta"]["tool"], "Example")
        self.assertIn("requestId", result["meta"])

    def test_legacy_error_string_never_escapes_public_contract(self):
        result = self.mod._canonicalize_public_result("Example", "Error 500: broken")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "HTTP_500")
        self.assertEqual(result["error"]["httpStatus"], 500)
        self.assertNotIn("Error 500:", str(result))

    def test_false_and_validation_failures_have_structured_errors(self):
        false_result = self.mod._canonicalize_public_result("Example", False)
        self.assertEqual(false_result["error"]["code"], "TOOL_FALSE_RESULT")
        validation = self.mod._canonicalize_public_result(
            "VerifyPEDump",
            {"ok": False, "verified": False, "errors": ["PE dump file was not found"]},
        )
        self.assertEqual(validation["error"]["code"], "VALIDATION_FAILED")
        self.assertIn("not found", validation["error"]["message"])

    def test_bridge_envelope_maps_transport_meta_and_retryability(self):
        envelope = self.mod.BridgeEnvelope(
            False,
            data={"partial": True},
            error=self.mod.BridgeError(
                "BRIDGE_TIMEOUT", "timed out", retryable=True, http_status=504
            ),
            meta={"requestId": "transport-request", "endpoint": "Debug/Run", "contractVersion": 3},
        )
        result = self.mod._canonicalize_public_result("DebugRun", envelope, request_id="tool-request")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "BRIDGE_TIMEOUT")
        self.assertTrue(result["error"]["retryable"])
        self.assertEqual(result["meta"]["requestId"], "tool-request")
        self.assertEqual(result["meta"]["endpoint"], "Debug/Run")
        self.assertEqual(result["meta"]["transportContractVersion"], 3)
        self.assertEqual(result["data"], {"partial": True})

    def test_identity_fields_are_attached_when_available(self):
        identity = {
            "bridgeInstanceId": "bridge-1",
            "sessionId": "session-1",
            "sessionGeneration": 4,
            "eventSeq": 17,
            "debuggeePid": 1234,
            "debuggerPid": 5678,
        }
        with mock.patch.object(self.mod, "_identity_for_guard", return_value=identity):
            result = self.mod._canonicalize_public_result("MemoryRead", {"bytes": "90"})
        self.assertEqual(result["meta"]["bridgeId"], "bridge-1")
        self.assertEqual(result["meta"]["sessionId"], "session-1")
        self.assertEqual(result["meta"]["generation"], 4)
        self.assertEqual(result["meta"]["eventSeq"], 17)

    def test_fastmcp_registered_tools_are_wrapped_without_legacy_output_models(self):
        manager = self.mod.mcp._tool_manager
        self.assertGreater(len(manager._tools), 200)
        for name, tool in manager._tools.items():
            with self.subTest(tool=name):
                self.assertEqual(getattr(tool, "_x64dbg_result_contract", None), "envelope-v1")
                self.assertIsNone(tool.fn_metadata.output_schema)
                self.assertIsNone(tool.fn_metadata.output_model)

        async def call():
            return await manager.call_tool("GetMiniDumpProfiles", {})

        result = asyncio.run(call())
        self.assertEqual(set(result), {"ok", "data", "error", "meta"})
        self.assertTrue(result["ok"])
        self.assertEqual(result["meta"]["tool"], "GetMiniDumpProfiles")

        async def invalid_call():
            return await manager.call_tool("VerifyPEDump", {})

        invalid = asyncio.run(invalid_call())
        self.assertFalse(invalid["ok"])
        self.assertEqual(invalid["error"]["code"], "INVALID_ARGUMENT")

    def test_direct_helpers_remain_legacy_compatibility_shim(self):
        # Direct Python calls are intentionally not the MCP public boundary.
        result = self.mod.VerifyPEDump(r"C:\does-not-exist.exe")
        self.assertIsInstance(result, dict)
        self.assertFalse(result.get("ok"))
        self.assertIn("errors", result)

    def test_legacy_environment_switch_is_explicit_and_scoped(self):
        with mock.patch.dict(os.environ, {"X64DBG_MCP_LEGACY_RESULTS": "1"}, clear=False):
            legacy = self.mod._invoke_public_callable(
                "Example", lambda: {"ok": True, "value": 1}
            )
        self.assertEqual(legacy, {"ok": True, "value": 1})
        canonical = self.mod._invoke_public_callable(
            "Example", lambda: {"ok": True, "value": 1}
        )
        self.assertEqual(set(canonical), {"ok", "data", "error", "meta"})

    def test_callable_exception_is_not_reported_as_success(self):
        result = self.mod._invoke_public_callable(
            "Example", lambda: (_ for _ in ()).throw(RuntimeError("boom"))
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "TOOL_EXCEPTION")
        self.assertEqual(result["error"]["message"], "boom")


if __name__ == "__main__":
    unittest.main()
