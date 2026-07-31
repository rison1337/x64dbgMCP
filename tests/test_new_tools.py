import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "x64dbg.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("x64dbg_bridge", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _rebind_closure(fn, name, value):
    """Rebind a free variable captured by a closure (used to stub the bridge
    callbacks that ext_tools captured at register() time)."""
    idx = fn.__code__.co_freevars.index(name)
    fn.__closure__[idx].cell_contents = value


class ScyllaHideDialogSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def test_browser_title_mentioning_scyllahide_is_never_treated_as_dialog(self):
        browser_window = {
            "pid": 1234,
            "hwnd": "0x123",
            "title": "x64dbg MCP with ScyllaHide - Browser",
            "children": [],
        }
        with (
            mock.patch.object(
                self.mod,
                "_find_windows_by_title_substring",
                return_value=[browser_window],
            ),
            mock.patch.object(
                self.mod,
                "_get_process_image_path",
                return_value=r"C:\Program Files\Browser\browser.exe",
            ),
            mock.patch.object(self.mod, "_flatten_window_tree") as flatten,
        ):
            result = self.mod._inspect_scyllahide_dialog()

        self.assertEqual(result, {"found": False})
        flatten.assert_not_called()


class CommandToolTests(unittest.TestCase):
    """The thread/trace/symbol convenience tools wrap raw x64dbg commands through
    safe_get('ExecCommand', ...). These tests pin the exact command strings so the
    syntax cannot silently regress."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def setUp(self):
        self._orig_safe_get = self.mod.safe_get
        self.calls = []

        def fake_safe_get(endpoint, params=None, log=True, timeout_sec=15.0):
            self.calls.append((endpoint, dict(params or {})))
            return {"success": True}

        self.mod.safe_get = fake_safe_get

    def tearDown(self):
        self.mod.safe_get = self._orig_safe_get

    def _last_cmd(self):
        self.assertTrue(self.calls, "expected an ExecCommand call")
        endpoint, params = self.calls[-1]
        self.assertEqual(endpoint, "ExecCommand")
        return params.get("cmd")

    def test_suspend_thread_with_and_without_tid(self):
        # A decimal tid (as GetThreadList reports) is emitted as a 0x-hex literal
        # because x64dbg's expression parser treats bare numbers as hex.
        self.assertTrue(self.mod.SuspendThread("1234")["ok"])
        self.assertEqual(self._last_cmd(), "suspendthread 0x4d2")
        self.mod.ResumeThread()
        self.assertEqual(self._last_cmd(), "resumethread")

    def test_thread_id_normalized_to_hex(self):
        self.mod.SuspendThread("35304")            # decimal -> 0x89e8
        self.assertEqual(self._last_cmd(), "suspendthread 0x89e8")
        self.mod.SuspendThread("0x89e8")           # already hex -> preserved
        self.assertEqual(self._last_cmd(), "suspendthread 0x89e8")

    def test_suspend_resume_all_threads(self):
        self.mod.SuspendAllThreads()
        self.assertEqual(self._last_cmd(), "suspendallthreads")
        self.mod.ResumeAllThreads()
        self.assertEqual(self._last_cmd(), "resumeallthreads")

    def test_switch_thread_requires_tid(self):
        res = self.mod.SwitchThread("")
        self.assertFalse(res["ok"])
        self.assertEqual(self.calls, [])
        self.mod.SwitchThread("7")
        self.assertEqual(self._last_cmd(), "switchthread 0x7")

    def test_set_thread_priority(self):
        res = self.mod.SetThreadPriority("7", "Highest")
        self.assertTrue(res["ok"])
        self.assertEqual(self._last_cmd(), "setthreadpriority 0x7, Highest")
        self.assertFalse(self.mod.SetThreadPriority("", "Highest")["ok"])

    def test_conditional_trace_into_builds_full_sequence(self):
        res = self.mod.TraceIntoConditional(
            condition="eax==0", log_text="{eax}", log_file=r"c:\t.log", max_steps=10
        )
        self.assertTrue(res["ok"])
        self.assertEqual(
            res["commandsRun"],
            [
                'TraceSetLogFile "c:\\t.log"',
                'TraceSetLog "{eax}"',
                'TraceIntoConditional "eax==0", 0xa',  # 10 -> hex (x64dbg default radix)
            ],
        )

    def test_conditional_trace_over_minimal(self):
        res = self.mod.TraceOverConditional(condition="eip==0x401000")
        self.assertEqual(res["commandsRun"], ['TraceOverConditional "eip==0x401000"'])

    def test_conditional_trace_requires_condition(self):
        self.assertFalse(self.mod.TraceIntoConditional(condition="")["ok"])
        self.assertEqual(self.calls, [])

    def test_load_symbols_download_and_load(self):
        self.mod.LoadSymbolsForModule(module="ntdll", download=True)
        cmds = [c[1].get("cmd") for c in self.calls]
        self.assertEqual(cmds, ["symdownload ntdll", "symload ntdll"])

    def test_load_symbols_with_store(self):
        self.mod.LoadSymbolsForModule(module="ntdll", symbol_store="http://store", download=True)
        cmds = [c[1].get("cmd") for c in self.calls]
        self.assertEqual(cmds, ["symdownload ntdll, http://store", "symload ntdll"])

    def test_load_symbols_load_only(self):
        self.mod.LoadSymbolsForModule(download=False)
        cmds = [c[1].get("cmd") for c in self.calls]
        self.assertEqual(cmds, ["symload"])

    def test_save_memory_region_command(self):
        out = os.path.join(tempfile.gettempdir(), "swp_dump.bin")
        r = self.mod.SaveMemoryRegionToFile(out, "0x401000", 256)
        self.assertEqual(self._last_cmd(), f'savedata "{out}", 0x401000, 0x100')  # 256 -> hex
        self.assertFalse(r["ok"])  # the fake bridge does not actually write a file

    def test_save_memory_region_validates(self):
        self.assertFalse(self.mod.SaveMemoryRegionToFile("", "0x1", 16)["ok"])
        self.assertFalse(self.mod.SaveMemoryRegionToFile("x", "0x1", 0)["ok"])
        self.assertEqual(self.calls, [])

    def test_loadlib_command(self):
        self.mod.LoadLibraryInDebuggee(r"C:\h.dll")
        self.assertEqual(self._last_cmd(), 'loadlib "C:\\h.dll"')
        self.assertFalse(self.mod.LoadLibraryInDebuggee("")["ok"])

    def test_runtrace_commands_append_extension(self):
        orig = self.mod._get_active_debugger_info
        self.mod._get_active_debugger_info = lambda: {"arch": "x64"}
        try:
            out = os.path.join(tempfile.gettempdir(), "swp_run")
            r = self.mod.StartRunTraceToFile(out)
            self.assertEqual(self._last_cmd(), f'StartRunTrace "{out}.trace64"')
            self.assertEqual(r["output"], out + ".trace64")
        finally:
            self.mod._get_active_debugger_info = orig
        self.mod.StopRunTrace()
        self.assertEqual(self._last_cmd(), "StopRunTrace")


class ImportAddressNormalizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def test_symbol_fallback_converts_import_rva_to_loaded_va(self):
        fn = self.mod.GetImports
        replacements = {
            "_load_imports_from_disk": lambda target: None,
            "_resolve_module_by_name": lambda target: {
                "name": "sample.exe",
                "base": "0x10000000",
            },
            "safe_get": lambda *args, **kwargs: {
                "symbols": [
                    {"type": "import", "name": "kernel32!ExitProcess", "rva": "0x2000"}
                ]
            },
        }
        originals = {
            name: fn.__closure__[fn.__code__.co_freevars.index(name)].cell_contents
            for name in replacements
        }
        try:
            for name, value in replacements.items():
                _rebind_closure(fn, name, value)
            result = fn(module="sample.exe")
        finally:
            for name, value in originals.items():
                _rebind_closure(fn, name, value)
        self.assertTrue(result["ok"])
        self.assertEqual(result["imports"][0]["rva"], "0x2000")
        self.assertEqual(result["imports"][0]["iatVa"], "0x10002000")


class ExportPatchedFileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def test_export_reports_no_patches(self):
        fn = self.mod.ExportPatchedFile
        # ExportPatchedFile captured GetPatchList as a closure free-var; stub it.
        if "GetPatchList" in fn.__code__.co_freevars:
            _rebind_closure(fn, "GetPatchList", lambda: {"count": 0, "patches": []})
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "patched.exe")
            res = fn(output_path=out)
        # Either "no patches" (pefile present) or "pefile not installed" — both are
        # a clean, non-crashing error envelope.
        self.assertFalse(res["ok"])
        self.assertIn("error", res)
        self.assertFalse(os.path.exists(out))


class ExceptionFilterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def tearDown(self):
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["exceptionFilters"] = []
            self.mod._RUNTIME_STATE["nativeExceptionPolicyActive"] = False

    def test_json_array_codes_are_stored_without_quotes(self):
        with mock.patch.object(
            self.mod, "SetExceptionPolicy", return_value={"ok": True}
        ) as set_policy, mock.patch.object(
            self.mod,
            "GetExceptionPolicy",
            return_value={"ok": True, "policy": {"rules": []}},
        ):
            result = self.mod.SetExceptionFilter(
                codes_json='["0xE0434352","0xe06d7363"]', action="skip"
            )
        self.assertTrue(result["ok"], result)
        submitted = __import__("json").loads(set_policy.call_args.kwargs["rules_json"])[0]
        self.assertEqual(submitted["codes"], ["0xe0434352", "0xe06d7363"])

    def test_csv_and_decimal_codes_normalize(self):
        # decimal 3762504530 == 0xE0434352 (dedup with the hex form)
        with mock.patch.object(
            self.mod, "SetExceptionPolicy", return_value={"ok": True}
        ) as set_policy, mock.patch.object(
            self.mod,
            "GetExceptionPolicy",
            return_value={"ok": True, "policy": {"rules": []}},
        ):
            result = self.mod.SetExceptionFilter(
                codes_json="0xE0434352, 0xe06d7363, 3762504530"
            )
        self.assertTrue(result["ok"], result)
        submitted = __import__("json").loads(set_policy.call_args.kwargs["rules_json"])[0]
        self.assertEqual(submitted["codes"], ["0xe0434352", "0xe06d7363"])

    def test_normalize_strips_quotes(self):
        self.assertEqual(self.mod._normalize_exception_code('"0xe0434352"'), "0xe0434352")

    def test_filter_matches_after_set(self):
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["nativeExceptionPolicyActive"] = False
            self.mod._RUNTIME_STATE["exceptionFilters"] = [
                {
                    "codes": ["0xe0434352"],
                    "action": "skip",
                    "firstChanceOnly": True,
                }
            ]
        state = {"session": {"exceptionCode": 0xE0434352, "exceptionFirstChance": True}}
        matched = self.mod._match_exception_filter(state)
        self.assertIsNotNone(matched)
        self.assertEqual(matched["matchedCode"], "0xe0434352")


class ScanMemoryStringsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def test_scan_single_region_finds_ascii_and_utf16(self):
        # Non-printable separators keep the ASCII run and the UTF-16 run distinct.
        buf = b"\x00\x01" + b"HELLO_WORLD" + b"\x00\x01" + b"W\x00I\x00D\x00E\x00" + b"\x01"
        fake = lambda addr, size, ty="hex": {"hex": buf.hex()}
        fn = self.mod.ScanMemoryStrings
        if "ReadMemory" in fn.__code__.co_freevars:
            _rebind_closure(fn, "ReadMemory", fake)
        r = fn(addr="0x1000", size=len(buf), min_length=4)
        self.assertTrue(r["ok"])
        texts = {(s["encoding"], s["text"]) for s in r["strings"]}
        self.assertIn(("ascii", "HELLO_WORLD"), texts)
        self.assertIn(("utf16", "WIDE"), texts)
        addrs = {s["text"]: s["addr"] for s in r["strings"]}
        self.assertEqual(addrs["HELLO_WORLD"], "0x1002")  # region base + offset 2

    def test_scan_requires_size_when_addr_given(self):
        r = self.mod.ScanMemoryStrings(addr="0x1000", size=0)
        self.assertFalse(r["ok"])


class LaunchDiagnosticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def test_summarize_launch_failure_gives_error_and_hint(self):
        init = {"ok": False, "attempts": 3, "state": {"debugging": False}}
        err, hint = self.mod._summarize_launch_failure(r"C:\nope\missing.exe", init)
        self.assertIn("3 attempt", err)
        self.assertIn("not_debugging", err)
        self.assertTrue(hint and isinstance(hint, str))

    def test_requires_elevation_false_for_missing_file(self):
        self.assertFalse(self.mod._target_requires_elevation(r"C:\nope\missing.exe"))

    def test_arch_detection_handles_missing_file(self):
        self.assertIsNone(self.mod._detect_pe_arch(r"C:\nope\missing.exe"))
        self.assertIsNone(self.mod._dotnet_effective_arch(r"C:\nope\missing.exe"))


class ToolRegistrationTests(unittest.TestCase):
    """Guard against the missing-@mcp.tool() regression: a function can be
    exported into the module namespace (and unit-tested) yet never registered as
    an MCP tool, making it invisible to every MCP client. Assert the registry
    actually contains the tools we ship."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def _registry_names(self):
        mcp = getattr(self.mod, "mcp", None)
        self.assertIsNotNone(mcp, "module exposes no mcp object")
        tm = getattr(mcp, "_tool_manager", None)
        tools = getattr(tm, "_tools", None) if tm is not None else None
        if tools is None:
            tools = getattr(mcp, "_tools", None)
        self.assertIsInstance(tools, dict, "could not locate the MCP tool registry")
        return set(tools.keys())

    def test_ext_tools_are_registered_not_just_exported(self):
        names = self._registry_names()
        # The two that regressed (defined + exported but undecorated), plus a
        # representative already-working ext tool as a sanity anchor.
        for tool in ("ScanMemoryStrings", "ExportPatchedFile", "SearchStrings"):
            self.assertIn(tool, names, f"{tool} is not registered as an MCP tool")

    def test_new_command_tools_are_registered(self):
        names = self._registry_names()
        for tool in (
            "SaveMemoryRegionToFile",
            "LoadLibraryInDebuggee",
            "StartRunTraceToFile",
            "StopRunTrace",
            "SuspendThread",
            "TraceIntoConditional",
            "LoadSymbolsForModule",
        ):
            self.assertIn(tool, names, f"{tool} is not registered as an MCP tool")

    def test_ext_tools_loaded_without_error(self):
        status = getattr(self.mod, "_EXT_TOOLS_STATUS", {})
        self.assertTrue(status.get("loaded"), f"ext_tools failed to load: {status}")


class CapabilityMapParityTests(unittest.TestCase):
    """Pin the generated schema-v2 catalog to the complete live registry."""

    CAPABILITY_MAP = Path(__file__).resolve().parents[1] / "tools" / "capability_map.json"

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def test_capability_map_matches_registry(self):
        import json

        registry = set(self.mod._get_mcp_tools_registry().keys())
        data = json.loads(self.CAPABILITY_MAP.read_text(encoding="utf-8"))
        mapped = set(data.get("tools") or [])
        missing = sorted(registry - mapped)
        stale = sorted(mapped - registry)
        self.assertEqual(
            missing, [], f"tools registered but not in capability_map.json: {missing}"
        )
        self.assertEqual(
            stale, [], f"tools in capability_map.json that are no longer registered: {stale}"
        )
        self.assertEqual(data.get("count"), len(registry), "capability_map count is stale")
        self.assertEqual(data.get("schemaVersion"), 2)
        self.assertEqual(set(data.get("toolMetadata") or {}), registry)
        self.assertEqual(
            set(((data.get("profiles") or {}).get("full") or {}).get("tools") or []),
            registry,
        )
        self.assertEqual(data.get("defaultProfile"), "full")
        self.assertEqual(data.get("recommendedProfile"), "compact")


if __name__ == "__main__":
    unittest.main()
