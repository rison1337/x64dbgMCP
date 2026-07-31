import base64
import importlib.util
import inspect
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "x64dbg.py"


def _load_bridge():
    spec = importlib.util.spec_from_file_location("x64dbg_launch_contract", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class LaunchNormalizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_bridge()

    def test_defaults_are_v2_bounded_console_inheritance(self):
        result = self.mod._build_launch_spec(sys.executable)

        self.assertTrue(result["ok"], result)
        self.assertEqual(result["contractVersion"], 2)
        self.assertFalse(result["streamsExplicit"])
        self.assertEqual(
            result["streams"],
            {
                "stdin": {"mode": "inherit"},
                "stdout": {"mode": "inherit"},
                "stderr": {"mode": "inherit"},
            },
        )
        self.assertEqual(result["childPolicy"], "none")
        self.assertEqual(result["captureLimitBytes"], 1048576)
        self.assertEqual(
            result["fullCommandLineUtf16Units"],
            len(result["fullCommandLine"].encode("utf-16-le")) // 2,
        )

    def test_explicit_streams_are_all_or_none(self):
        partial = self.mod._build_launch_spec(
            sys.executable, stdout={"mode": "pipe"}
        )
        self.assertFalse(partial["ok"])
        self.assertIn("must all be specified", partial["error"])

        explicit = self.mod._build_launch_spec(
            sys.executable,
            stdin={"mode": "null"},
            stdout={"mode": "pipe"},
            stderr={"mode": "inherit"},
        )
        self.assertTrue(explicit["ok"], explicit)
        self.assertTrue(explicit["streamsExplicit"])

    def test_stream_modes_normalize_raw_bytes_files_and_pipe_capacity(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            stdout_path = os.path.join(temp_dir, "stdout.bin")
            result = self.mod._build_launch_spec(
                sys.executable,
                stdin={
                    "mode": "bytes",
                    "data": b"\x00stdin\xff",
                },
                stdout={
                    "mode": "file",
                    "path": stdout_path,
                    "fileMode": "APPEND",
                },
                stderr={"mode": "pipe"},
                child_policy="attach-first",
                capture_limit_bytes=4096,
            )

        self.assertTrue(result["ok"], result)
        self.assertEqual(result["stdin"]["dataBase64"], "AHN0ZGlu/w==")
        self.assertNotIn("data", result["stdin"])
        self.assertTrue(result["stdin"]["closeAfterWrite"])
        self.assertEqual(result["stdout"]["fileMode"], "append")
        self.assertEqual(result["childPolicy"], "attach-first")
        self.assertEqual(result["captureLimitBytes"], 4096)

        pipe = self.mod._build_launch_spec(
            sys.executable,
            stdin={"mode": "pipe", "capacityBytes": 67108864},
            stdout={"mode": "null"},
            stderr={"mode": "null"},
        )
        self.assertTrue(pipe["ok"], pipe)
        self.assertEqual(pipe["stdin"]["capacityBytes"], 67108864)

    def test_stdin_file_and_base64_are_strict(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source_path = os.path.join(temp_dir, "stdin.bin")
            Path(source_path).write_bytes(b"fixture")
            result = self.mod._build_launch_spec(
                sys.executable,
                stdin={"mode": "file", "path": source_path},
                stdout={"mode": "null"},
                stderr={"mode": "null"},
            )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["stdin"]["path"], os.path.abspath(source_path))

        invalid = self.mod._build_launch_spec(
            sys.executable,
            stdin={"mode": "bytes", "dataBase64": "YQ"},
            stdout={"mode": "null"},
            stderr={"mode": "null"},
        )
        self.assertFalse(invalid["ok"])
        self.assertIn("canonical", invalid["error"])

        both = self.mod._build_launch_spec(
            sys.executable,
            stdin={"mode": "bytes", "data": b"a", "dataBase64": "YQ=="},
            stdout={"mode": "null"},
            stderr={"mode": "null"},
        )
        self.assertFalse(both["ok"])
        self.assertIn("exactly one", both["error"])

        non_finite = self.mod._build_launch_spec(
            sys.executable,
            stdin={"mode": "bytes", "data": b"a", "closeAfterWrite": False},
            stdout={"mode": "null"},
            stderr={"mode": "null"},
        )
        self.assertFalse(non_finite["ok"])
        self.assertEqual(non_finite["errorCode"], "INVALID_STREAM_SPEC")
        self.assertIn("mode=pipe", non_finite["error"])

    def test_stream_paths_fields_modes_and_capacities_fail_closed(self):
        cases = [
            {"stdin": {"mode": "null", "ignored": 1}},
            {"stdin": {"mode": "bytes", "data": "not raw bytes"}},
            {"stdin": {"mode": "pipe", "capacityBytes": True}},
            {"stdin": {"mode": "file", "path": "relative.bin"}},
            {"stdout": {"mode": "bytes"}},
            {"stdout": {"mode": "file", "path": "relative.bin"}},
        ]
        for case in cases:
            with self.subTest(case=case):
                stdin = case.get("stdin", {"mode": "null"})
                stdout = case.get("stdout", {"mode": "null"})
                result = self.mod._build_launch_spec(
                    sys.executable,
                    stdin=stdin,
                    stdout=stdout,
                    stderr={"mode": "null"},
                )
                self.assertFalse(result["ok"], result)

        with tempfile.TemporaryDirectory() as temp_dir:
            shared = os.path.join(temp_dir, "shared.log")
            same_file = self.mod._build_launch_spec(
                sys.executable,
                stdin={"mode": "null"},
                stdout={"mode": "file", "path": shared},
                stderr={"mode": "file", "path": shared.upper()},
            )
        self.assertFalse(same_file["ok"], same_file)
        self.assertEqual(same_file["errorCode"], "INVALID_STREAM_SPEC")
        self.assertIn("same file", same_file["error"])

        for value in (4095, 67108865, True, 1.5):
            with self.subTest(capture=value):
                result = self.mod._build_launch_spec(
                    sys.executable, capture_limit_bytes=value
                )
                self.assertFalse(result["ok"], result)

    def test_argv_and_raw_tail_are_mutually_exclusive_and_utf16_bounded(self):
        not_string = self.mod._build_launch_spec(sys.executable, command_line=7)
        self.assertFalse(not_string["ok"])
        self.assertIn("must be a string", not_string["error"])

        both = self.mod._build_launch_spec(
            sys.executable, arguments=["one"], command_line="two"
        )
        self.assertFalse(both["ok"])
        self.assertIn("mutually exclusive", both["error"])

        arguments = ["", "two words", 'quote"tail', "emoji-\U0001f642"]
        vector = self.mod._build_launch_spec(sys.executable, arguments=arguments)
        self.assertTrue(vector["ok"], vector)
        self.assertEqual(vector["arguments"], arguments)
        self.assertEqual(vector["rawCommandLineTail"], "")

        raw = self.mod._build_launch_spec(sys.executable, command_line='--raw "tail"')
        self.assertTrue(raw["ok"], raw)
        self.assertEqual(raw["arguments"], [])
        self.assertEqual(raw["rawCommandLineTail"], '--raw "tail"')

        # Astral code points count as two UTF-16 units, not one Python code point.
        oversized = self.mod._build_launch_spec(
            sys.executable, command_line="\U0001f642" * 17000
        )
        self.assertFalse(oversized["ok"])
        self.assertIn("UTF-16 code units", oversized["error"])

    def test_v2_capability_contract_and_form_payload(self):
        spec = self.mod._build_launch_spec(
            sys.executable,
            arguments=["", "two words", "\U0001f642"],
            environment={"UNICODE_ENV": "значение"},
            stdin={"mode": "null"},
            stdout={"mode": "pipe"},
            stderr={"mode": "pipe"},
            child_policy="attach-first",
        )
        self.assertTrue(spec["ok"], spec)
        good_caps = {
            "version": 2,
            "args": True,
            "cwd": True,
            "environment": True,
            "environmentMode": "unicode_create_process_block",
            "streams": {"supported": True},
            "childPolicies": ["none", "attach-first"],
        }
        calls = []

        def fake_request(method, endpoint, **kwargs):
            calls.append((method, endpoint, kwargs))
            return self.mod.BridgeEnvelope(True, data={"ok": True, "launchId": "L-1"})

        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["bridgeIdentity"] = {
                "bridgeInstanceId": "bridge-launch",
                "capabilities": {"launch": good_caps},
            }
        with mock.patch.object(self.mod, "_bridge_request", side_effect=fake_request):
            result = self.mod._launch_via_bridge(spec, timeout_sec=2.0)

        self.assertTrue(result["ok"], result)
        self.assertEqual(calls[0][0:2], ("POST", "Debug/Launch"))
        form = calls[0][2]["form_data"]
        self.assertEqual(json.loads(form["arguments"]), spec["arguments"])
        self.assertEqual(form["rawCommandLineTail"], "")
        self.assertNotIn("args", form)
        self.assertEqual(json.loads(form["stdin"]), {"mode": "null"})
        self.assertEqual(json.loads(form["stdout"]), {"mode": "pipe"})
        self.assertEqual(form["childPolicy"], "attach-first")
        self.assertEqual(form["captureLimitBytes"], "1048576")

        capability_cases = [
            ({**good_caps, "version": 1}, "launch.version"),
            (
                {**good_caps, "environmentMode": "synchronized_process_overlay"},
                "launch.environmentMode",
            ),
            ({**good_caps, "streams": False}, "launch.streams"),
            ({**good_caps, "childPolicies": ["none"]}, "launch.childPolicies"),
        ]
        for caps, expected in capability_cases:
            with self.subTest(capability=expected):
                failure = self.mod._validate_launch_v2_capabilities(spec, caps)
                self.assertIsNotNone(failure)
                self.assertEqual(failure["capability"], expected)

    def test_default_streams_are_omitted_for_native_console_default(self):
        spec = self.mod._build_launch_spec(sys.executable)
        self.assertTrue(spec["ok"], spec)
        calls = []

        def fake_request(method, endpoint, **kwargs):
            calls.append((method, endpoint, kwargs))
            return self.mod.BridgeEnvelope(
                True, data={"ok": True, "launchId": "L-console"}
            )

        caps = {
            "version": 2,
            "args": True,
            "cwd": True,
            "environment": True,
            "environmentMode": "unicode_create_process_block",
            "streams": {"supported": True},
            "childPolicies": ["none"],
        }
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["bridgeIdentity"] = {
                "bridgeInstanceId": "bridge-console",
                "capabilities": {"launch": caps},
            }
        with mock.patch.object(self.mod, "_bridge_request", side_effect=fake_request):
            result = self.mod._launch_via_bridge(spec, timeout_sec=2.0)

        self.assertTrue(result["ok"], result)
        form = calls[0][2]["form_data"]
        self.assertNotIn("stdin", form)
        self.assertNotIn("stdout", form)
        self.assertNotIn("stderr", form)

    def test_public_entrypoints_expose_and_forward_v2_parameters(self):
        for name in (
            "LaunchFileUnderDebugger",
            "LaunchAndOpenDebuggee",
            "InitDebuggee",
        ):
            parameters = inspect.signature(getattr(self.mod, name)).parameters
            for expected in (
                "stdin",
                "stdout",
                "stderr",
                "child_policy",
                "capture_limit_bytes",
            ):
                self.assertIn(expected, parameters, name)

        calls = []

        def fake_launch(**kwargs):
            calls.append(kwargs)
            return {"ok": True}

        with mock.patch.object(self.mod, "LaunchFileUnderDebugger", side_effect=fake_launch):
            result = self.mod.LaunchAndOpenDebuggee(
                sys.executable,
                stdin={"mode": "null"},
                stdout={"mode": "pipe"},
                stderr={"mode": "pipe"},
                child_policy="break-on-create",
                capture_limit_bytes=8192,
            )
        self.assertTrue(result["ok"], result)
        self.assertEqual(calls[0]["stdin"], {"mode": "null"})
        self.assertEqual(calls[0]["child_policy"], "break-on-create")
        self.assertEqual(calls[0]["capture_limit_bytes"], 8192)


class LaunchLifecycleToolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # unittest orders classes by name, so this class must not depend on
        # LaunchNormalizationTests.setUpClass having run first.
        cls.mod = _load_bridge()

    def test_lifecycle_tools_use_exact_routes_and_fields(self):
        calls = []

        def fake_request(method, endpoint, **kwargs):
            calls.append((method, endpoint, kwargs))
            return self.mod.BridgeEnvelope(True, data={"ok": True}, meta={"requestId": endpoint})

        with mock.patch.object(self.mod, "_bridge_request", side_effect=fake_request):
            self.assertTrue(self.mod.GetLaunchState("launch-1")["ok"])
            self.assertTrue(
                self.mod.ReadLaunchStream(
                    "launch-1", stream="STDERR", cursor=7, max_bytes=8, wait_ms=9
                )["ok"]
            )
            self.assertTrue(
                self.mod.WriteLaunchStdin(
                    "launch-1",
                    base64.b64encode(b"\x00\xff").decode("ascii"),
                    wait_ms=11,
                    close_after_write=True,
                )["ok"]
            )
            self.assertTrue(self.mod.CloseLaunchStdin("launch-1")["ok"])
            self.assertTrue(self.mod.CloseLaunchResources("launch-1")["ok"])

        self.assertEqual(
            [(method, route) for method, route, _ in calls],
            [
                ("GET", "Debug/Launch/State"),
                ("GET", "Debug/Launch/Stream/Read"),
                ("POST", "Debug/Launch/Stdin/Write"),
                ("POST", "Debug/Launch/Stdin/Close"),
                ("POST", "Debug/Launch/Resources/Close"),
            ],
        )
        self.assertEqual(
            calls[1][2]["params"],
            {
                "launchId": "launch-1",
                "stream": "stderr",
                "cursor": 7,
                "maxBytes": 8,
                "waitMs": 9,
            },
        )
        self.assertEqual(calls[2][2]["form_data"]["dataBase64"], "AP8=")
        self.assertEqual(calls[2][2]["form_data"]["closeAfterWrite"], "true")
        self.assertEqual(
            calls[4][2]["form_data"],
            {"launchId": "launch-1", "timeoutMs": "5000"},
        )
        self.assertEqual(
            [call[2]["guard"] for call in calls],
            ["bridge", "bridge", "session", "session", "bridge"],
        )

    def test_lifecycle_validation_never_contacts_bridge(self):
        invalid_calls = [
            lambda: self.mod.GetLaunchState(" bad"),
            lambda: self.mod.GetLaunchState("x" * 129),
            lambda: self.mod.ReadLaunchStream("launch", stream="stdin"),
            lambda: self.mod.ReadLaunchStream("launch", cursor=-1),
            lambda: self.mod.ReadLaunchStream("launch", max_bytes=1048577),
            lambda: self.mod.ReadLaunchStream("launch", wait_ms=60001),
            lambda: self.mod.WriteLaunchStdin("launch", "not-base64"),
            lambda: self.mod.WriteLaunchStdin("launch", ""),
            lambda: self.mod.WriteLaunchStdin("launch", "YQ==", wait_ms=True),
            lambda: self.mod.WriteLaunchStdin(
                "launch", "YQ==", close_after_write="yes"
            ),
            lambda: self.mod.CloseLaunchStdin("\x00"),
            lambda: self.mod.CloseLaunchResources(7),
            lambda: self.mod.CloseLaunchResources("launch", timeout_ms=30001),
        ]
        with mock.patch.object(
            self.mod, "_bridge_request", side_effect=AssertionError("must not contact bridge")
        ):
            for operation in invalid_calls:
                with self.subTest(operation=operation):
                    result = operation()
                    self.assertFalse(result["ok"], result)
                    self.assertEqual(result["errorCode"], "INVALID_ARGUMENT")

    def test_lifecycle_error_envelope_is_not_reported_as_success(self):
        error = self.mod.BridgeError(
            "LAUNCH_NOT_FOUND", "No such launch", retryable=False
        )
        with mock.patch.object(
            self.mod,
            "_bridge_request",
            return_value=self.mod.BridgeEnvelope(False, error=error, meta={"requestId": "r"}),
        ):
            result = self.mod.GetLaunchState("launch-404")
        self.assertFalse(result["ok"])
        self.assertEqual(result["errorCode"], "LAUNCH_NOT_FOUND")
        self.assertEqual(result["meta"]["requestId"], "r")

    def test_read_stream_aggregates_native_750ms_slices_to_requested_wait(self):
        calls = []
        responses = [
            self.mod.BridgeEnvelope(
                True,
                data={
                    "ok": True,
                    "dataBase64": "",
                    "eof": False,
                    "closed": False,
                },
                meta={},
            ),
            self.mod.BridgeEnvelope(
                True,
                data={
                    "ok": True,
                    "dataBase64": "YQ==",
                    "byteCount": 1,
                    "nextCursor": 1,
                    "eof": False,
                },
                meta={},
            ),
        ]

        def fake_request(method, endpoint, **kwargs):
            calls.append((method, endpoint, kwargs))
            return responses.pop(0)

        with mock.patch.object(self.mod, "_bridge_request", side_effect=fake_request):
            result = self.mod.ReadLaunchStream(
                "launch-1", stream="stdout", cursor=0, max_bytes=8, wait_ms=1000
            )

        self.assertTrue(result["ok"], result)
        self.assertEqual(result["clientWaitMs"], 1000)
        self.assertEqual(result["clientWaitSlices"], 2)
        self.assertTrue(result["clientWaitAggregated"])
        self.assertEqual(calls[0][2]["params"]["waitMs"], 750)
        self.assertGreaterEqual(calls[1][2]["params"]["waitMs"], 1)
        self.assertLessEqual(calls[1][2]["params"]["waitMs"], 750)

    def test_stdin_write_retries_only_explicit_backpressure(self):
        calls = []
        responses = [
            self.mod.BridgeEnvelope(
                False,
                error=self.mod.BridgeError(
                    "STDIN_BACKPRESSURE", "queue full", retryable=True
                ),
                meta={},
            ),
            self.mod.BridgeEnvelope(
                True,
                data={"ok": True, "acceptedBytes": 1, "queuedBytes": 1},
                meta={},
            ),
        ]

        def fake_request(method, endpoint, **kwargs):
            calls.append((method, endpoint, kwargs))
            return responses.pop(0)

        with mock.patch.object(self.mod, "_bridge_request", side_effect=fake_request):
            result = self.mod.WriteLaunchStdin(
                "launch-1", "YQ==", wait_ms=1000, close_after_write=True
            )

        self.assertTrue(result["ok"], result)
        self.assertEqual(result["acceptedBytes"], 1)
        self.assertEqual(result["clientWaitSlices"], 2)
        self.assertEqual(
            [item[2]["form_data"]["waitMs"] for item in calls], ["750", calls[1][2]["form_data"]["waitMs"]]
        )
        self.assertEqual(calls[0][2]["form_data"]["dataBase64"], "YQ==")
        self.assertEqual(calls[1][2]["form_data"]["closeAfterWrite"], "true")

    def test_profile_policy_is_read_only_for_reads_and_mutating_for_writes(self):
        catalog = self.mod._TOOL_CATALOG
        metadata = catalog["toolMetadata"]
        for name in ("GetLaunchState", "ReadLaunchStream"):
            self.assertTrue(metadata[name]["annotations"]["readOnlyHint"], name)
            self.assertIn("inspect", metadata[name]["profiles"])
        for name in ("WriteLaunchStdin", "CloseLaunchStdin"):
            self.assertFalse(metadata[name]["annotations"]["readOnlyHint"], name)
            self.assertEqual(metadata[name]["sideEffects"], ["debuggee.input"])
            self.assertEqual(metadata[name]["profiles"], ["automation", "full"])
        close_resources = metadata["CloseLaunchResources"]
        self.assertEqual(close_resources["sideEffects"], ["mcp.state.write"])
        self.assertNotIn("inspect", close_resources["profiles"])


class NativeTeardownContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.runtime_cpp = (root / "src" / "launch_runtime.cpp").read_text(
            encoding="utf-8"
        )
        cls.runtime_hpp = (root / "src" / "launch_runtime.hpp").read_text(
            encoding="utf-8"
        )
        cls.bridge_cpp = (root / "src" / "MCPx64dbg.cpp").read_text(
            encoding="utf-8"
        )

    def test_teardown_is_bounded_and_reports_cancellation_state(self):
        self.assertIn("OperationResult closeResources", self.runtime_hpp)
        self.assertIn("TeardownStatus", self.runtime_hpp)
        self.assertIn("GetHandleInformation", self.runtime_cpp)
        self.assertIn("CancelSynchronousIo", self.runtime_cpp)
        self.assertNotIn("std::thread", self.runtime_cpp)
        shutdown_start = self.runtime_cpp.index("OperationResult shutdown(")
        shutdown_end = self.runtime_cpp.index(
            "    };\n\n    LaunchRuntime::LaunchRuntime", shutdown_start
        )
        shutdown = self.runtime_cpp[shutdown_start:shutdown_end]
        self.assertNotRegex(
            shutdown,
            r"WaitForSingleObject\s*\([^;]*,\s*INFINITE\s*\)",
        )
        self.assertNotIn("std::thread", shutdown)

    def test_registry_close_is_pinned_and_fail_closed(self):
        self.assertIn("activeOperations", self.bridge_cpp)
        self.assertIn("ManagedLaunchOperationPin", self.bridge_cpp)
        self.assertIn("launch_in_use", self.bridge_cpp)
        self.assertIn("eraseManagedLaunchIfSame", self.bridge_cpp)
        self.assertIn("Launch resources did not quiesce", self.bridge_cpp)
        close_start = self.bridge_cpp.index(
            "static LaunchHttpResult closeManagedLaunchResources"
        )
        close_end = self.bridge_cpp.index(
            "\n    }\n}", close_start
        )
        close = self.bridge_cpp[close_start:close_end]
        self.assertIn("closeResources", close)
        self.assertIn(r"released\":false", close)


if __name__ == "__main__":
    unittest.main()
