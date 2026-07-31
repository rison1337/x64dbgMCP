import hashlib
import importlib.util
import re
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "x64dbg.py"
CPP_PATH = ROOT / "src" / "MCPx64dbg.cpp"
POLICY_PATH = ROOT / "src" / "route_policy.inc"

POLICY_ROW_RE = re.compile(
    r'^MCP_ROUTE\("(?P<path>/[A-Za-z0-9_/]+)",\s*'
    r'(?P<guard>NONE|BRIDGE|SESSION|EXEC_DYNAMIC)\)$'
)
NATIVE_HANDLER_RE = re.compile(
    r'(?:if|else\s+if)\s*\(path\s*==\s*"(?P<path>/[A-Za-z0-9_/]+)"\)'
)

# This is intentionally explicit. Adding a state-changing native handler must
# update both the manifest and this security review list.
SIDE_EFFECT_PATHS = {
    "/ApiTrace/Clear",
    "/ApiTrace/Configure",
    "/ApiTrace/Entry",
    "/ApiTrace/Finalize",
    "/ApiTrace/ReturnHooks/Release",
    "/Assembler/AssembleMem",
    "/Bookmark/Delete",
    "/Bookmark/Set",
    "/Comment/Delete",
    "/Comment/Set",
    "/Debug/ContinueException",
    "/Debug/ExceptionHistory/Clear",
    "/Debug/ExceptionPolicy/Clear",
    "/Debug/ExceptionPolicy/Set",
    "/Debug/DeleteBreakpoint",
    "/Debug/DeleteHardwareBreakpoint",
    "/Debug/Launch",
    "/Debug/Launch/Resources/Close",
    "/Debug/Launch/Stdin/Close",
    "/Debug/Launch/Stdin/Write",
    "/Debug/Mutation/Acquire",
    "/Debug/Mutation/Release",
    "/Debug/Mutation/Renew",
    "/Debug/Pause",
    "/Debug/Run",
    "/Debug/RunBlocking",
    "/Debug/SetBreakpoint",
    "/Debug/SetHardwareBreakpoint",
    "/Debug/StepIn",
    "/Debug/StepOut",
    "/Debug/StepOver",
    "/Debug/Stop",
    "/Disasm/StepInWithDisasm",
    "/Dump/MiniDump",
    "/ExecCommand",
    "/Flag/Set",
    "/Function/Add",
    "/Function/Delete",
    "/Label/Delete",
    "/Label/Set",
    "/Memory/RemoteAlloc",
    "/Memory/RemoteFree",
    "/Memory/SetPageRights",
    "/Memory/Write",
    "/Register/Set",
    "/Scylla/DumpFix",
    "/Stack/Pop",
    "/Stack/Push",
    "/Trace/Clear",
    "/Trace/Start",
    "/Trace/Stop",
}


def _load_bridge():
    spec = importlib.util.spec_from_file_location("x64dbg_route_policy", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _parse_manifest_independently(path=POLICY_PATH):
    rows = []
    invalid = []
    raw = Path(path).read_text(encoding="utf-8", errors="strict")
    for line_number, raw_line in enumerate(raw.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue
        match = POLICY_ROW_RE.fullmatch(line)
        if match is None:
            invalid.append((line_number, line))
            continue
        rows.append((match.group("path"), match.group("guard")))
    return rows, invalid


class FakeResponse:
    status_code = 200
    ok = True
    content = b'{"ok":true}'
    text = '{"ok":true}'
    headers = {"Content-Type": "application/json"}


class FakeSession:
    def __init__(self):
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return FakeResponse()

    def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return FakeResponse()


class RoutePolicyContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_bridge()

    def setUp(self):
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["bridgeIdentity"] = None
            self.mod._RUNTIME_STATE["boundSession"] = None

    def _install_v3_identity(self, policy_id):
        payload = {
            "ok": True,
            "protocolVersion": 3,
            "bridgeInstanceId": "bridge-a",
            "capabilities": {"routePolicy": {"version": 1, "sourceId": policy_id}},
            "debugger": {"pid": 9001, "architecture": "x64"},
            "session": {
                "sessionId": "session-a",
                "generation": 7,
                "eventSeq": 19,
                "processId": 4242,
            },
        }
        identity = self.mod._normalize_bridge_identity(payload)
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["bridgeIdentity"] = identity
            self.mod._RUNTIME_STATE["boundSession"] = None
        return identity

    def test_manifest_exactly_matches_all_native_handlers(self):
        rows, invalid = _parse_manifest_independently()
        self.assertEqual(invalid, [], f"invalid manifest rows: {invalid}")

        manifest_paths = [path for path, _guard in rows]
        native_paths = NATIVE_HANDLER_RE.findall(
            CPP_PATH.read_text(encoding="utf-8", errors="strict")
        )
        expected_count = len(manifest_paths)
        self.assertEqual(len(native_paths), expected_count)
        self.assertEqual(len(set(native_paths)), expected_count, "duplicate native route handlers")
        self.assertEqual(len(set(manifest_paths)), expected_count, "duplicate manifest routes")
        self.assertEqual(set(manifest_paths), set(native_paths))

    def test_manifest_has_no_duplicate_unknown_or_malformed_rows(self):
        rows, invalid = _parse_manifest_independently()
        self.assertEqual(invalid, [])
        counts = Counter(path for path, _guard in rows)
        self.assertEqual(
            {path: count for path, count in counts.items() if count != 1},
            {},
        )
        self.assertTrue(rows)
        self.assertTrue(
            all(guard in {"NONE", "BRIDGE", "SESSION", "EXEC_DYNAMIC"} for _, guard in rows)
        )

    def test_python_loader_rejects_duplicate_and_unknown_guard(self):
        invalid_manifests = (
            'MCP_ROUTE("/Bridge/Hello", NONE)\nMCP_ROUTE("/Bridge/Hello", NONE)\n',
            'MCP_ROUTE("/Bridge/Hello", ROOT)\n',
            'MCP_ROUTE("not-absolute", NONE)\n',
        )
        for index, content in enumerate(invalid_manifests):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as raw_dir:
                path = Path(raw_dir) / "route_policy.inc"
                path.write_text(content, encoding="utf-8")
                with mock.patch.object(self.mod, "_ROUTE_POLICY_PATH", path):
                    with self.assertRaises(RuntimeError):
                        self.mod._load_route_policy()

    def test_python_default_guard_matches_every_manifest_row(self):
        rows, invalid = _parse_manifest_independently()
        self.assertEqual(invalid, [])
        for path, raw_guard in rows:
            if raw_guard == "EXEC_DYNAMIC":
                continue
            expected = raw_guard.casefold() if raw_guard != "NONE" else "none"
            with self.subTest(path=path):
                self.assertEqual(
                    self.mod._default_request_guard(path.lstrip("/"), {}),
                    expected,
                )
                self.assertEqual(self.mod._ROUTE_POLICY[path], raw_guard.casefold())

    def test_all_reviewed_side_effect_routes_are_guarded_and_only_them(self):
        rows, _invalid = _parse_manifest_independently()
        observed = {path for path, guard in rows if guard != "NONE"}
        self.assertEqual(observed, SIDE_EFFECT_PATHS)
        for path in SIDE_EFFECT_PATHS:
            with self.subTest(path=path):
                self.assertNotEqual(self.mod._ROUTE_POLICY.get(path), "none")

    def test_trace_stop_and_clear_are_bridge_guarded(self):
        for path in ("/Trace/Stop", "/Trace/Clear"):
            with self.subTest(path=path):
                self.assertEqual(self.mod._ROUTE_POLICY[path], "bridge")
                self.assertEqual(self.mod._default_request_guard(path, {}), "bridge")

    def test_exec_session_creation_commands_are_always_bridge_guarded(self):
        commands = (
            "init C:\\sample.exe",
            " INITDBG   C:\\sample.exe ",
            "\tattach 0x1234",
            "AtTaCh\t1234",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(
                    self.mod._default_request_guard("ExecCommand", {"cmd": command}),
                    "bridge",
                )

    def test_every_other_exec_command_is_session_guarded(self):
        commands = (
            "",
            "run",
            "pause",
            "initx C:\\sample.exe",
            '"init" C:\\sample.exe',
            "attachall 1234",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(
                    self.mod._default_request_guard("ExecCommand", {"cmd": command}),
                    "session",
                )

    def test_native_mutation_permit_does_not_deadlock_session_creation(self):
        source = CPP_PATH.read_text(encoding="utf-8")
        start = source.index("static bool routeNeedsNativeMutationPermit")
        end = source.index("static bool beginNativeMutationPermit", start)
        implementation = source[start:end]
        self.assertIn("isRawSessionCreationCommand(params, body)", implementation)
        self.assertIn("return false;", implementation)

    def test_v3_policy_mismatch_blocks_mutation_before_network(self):
        identity = self._install_v3_identity("0" * 16)
        self.assertFalse(identity["routePolicyCompatible"])
        with mock.patch.object(
            self.mod, "_discover_bridge_auth_token", return_value="aa" * 32
        ), mock.patch.object(
            self.mod,
            "_get_http_session",
            side_effect=AssertionError("network reached despite route-policy mismatch"),
        ) as session_getter:
            result = self.mod._bridge_request(
                "POST",
                "Memory/Write",
                form_data={"addr": "0x1000", "data": "00"},
                log=False,
            )
        self.assertFalse(result.ok)
        self.assertEqual(result.error.code, "ROUTE_POLICY_MISMATCH")
        self.assertEqual(result.error.details["expected"], self.mod._ROUTE_POLICY_ID)
        self.assertEqual(result.error.details["observed"], "0" * 16)
        session_getter.assert_not_called()

    def test_v3_policy_match_allows_guarded_network_request(self):
        identity = self._install_v3_identity(self.mod._ROUTE_POLICY_ID)
        self.assertTrue(identity["routePolicyCompatible"])
        session = FakeSession()
        with mock.patch.object(
            self.mod, "_discover_bridge_auth_token", return_value="aa" * 32
        ), mock.patch.object(self.mod, "_get_http_session", return_value=session):
            result = self.mod._bridge_request(
                "POST",
                "Memory/Write",
                form_data={"addr": "0x1000", "data": "00"},
                log=False,
            )
        self.assertTrue(result.ok)
        self.assertEqual(len(session.calls), 1)
        headers = session.calls[0][2]["headers"]
        self.assertEqual(headers["X-MCP-Bridge-Id"], "bridge-a")
        self.assertEqual(headers["X-MCP-Session-Id"], "session-a")
        self.assertEqual(headers["X-MCP-Session-Generation"], "7")
        self.assertEqual(headers["X-MCP-Debuggee-Pid"], "4242")

    def test_policy_source_id_is_first_16_hex_of_manifest_sha256(self):
        expected = hashlib.sha256(POLICY_PATH.read_bytes()).hexdigest()[:16]
        self.assertRegex(expected, r"^[0-9a-f]{16}$")
        self.assertEqual(self.mod._ROUTE_POLICY_ID, expected)
        loaded_rows, loaded_id = self.mod._load_route_policy()
        self.assertEqual(loaded_id, expected)
        self.assertEqual(loaded_rows, self.mod._ROUTE_POLICY)


if __name__ == "__main__":
    unittest.main()
