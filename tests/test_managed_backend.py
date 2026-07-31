import importlib.util
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "x64dbg.py"
BUILD_SCRIPT = ROOT / "tools" / "build_managed_fixture.ps1"


def _load():
    spec = importlib.util.spec_from_file_location("x64dbg_managed_backend_tests", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(os.name == "nt", "managed fixture uses the Windows Framework compiler")
class ManagedBackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.x64 = ROOT / "tools" / "bin" / "e2e" / "x64" / "managed_exception.exe"
        cls.x86 = ROOT / "tools" / "bin" / "e2e" / "x86" / "managed_exception.exe"
        cls.probe_x64 = ROOT / "tools" / "bin" / "e2e" / "x64" / "managed_probe_fixture.exe"
        cls.probe_x86 = ROOT / "tools" / "bin" / "e2e" / "x86" / "managed_probe_fixture.exe"
        # Do not overwrite a fixture that a live debugger may still have mapped.
        # Fresh checkouts still build both binaries before the first assertion.
        if not cls.x64.is_file() or not cls.x86.is_file():
            subprocess.run(
                ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(BUILD_SCRIPT)],
                cwd=str(ROOT),
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        cls.mod = _load()

    def test_metadata_and_il_are_exact_for_both_architectures(self):
        results = {}
        for arch, path in (("x64", self.x64), ("x86", self.x86)):
            result = self.mod.InspectManagedAssembly(path=str(path), include_il=True)
            self.assertTrue(result["ok"], result)
            self.assertTrue(result["isManaged"])
            self.assertEqual(result["runtime"]["executionArchitecture"], arch)
            self.assertEqual(result["assembly"]["name"], "managed_exception")
            self.assertEqual(result["counts"]["methods"], 1)
            method = result["methods"][0]
            self.assertEqual(method["token"], "0x06000001")
            self.assertEqual(method["declaringType"], "ManagedExceptionFixture")
            self.assertEqual(method["name"], "Main")
            self.assertEqual(method["codeSize"], 50)
            self.assertTrue(method["ilSha256"])
            results[arch] = method["ilSha256"]
        self.assertEqual(results["x64"], results["x86"])

    def test_resolve_token_distinguishes_il_from_jit_native_code(self):
        result = self.mod.ResolveManagedToken("0x06000001", path=str(self.x64))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["method"]["name"], "Main")
        self.assertEqual(result["ilRva"], "0x2050")
        self.assertIsNone(result["jitNativeAddress"])
        self.assertFalse(result["jitMappingSupported"])

    def test_managed_evidence_is_atomic_and_hash_bound(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "managed.json"
            result = self.mod.ExportManagedEvidence(
                path=str(self.x64), output_path=str(output), include_il=True
            )
            document = json.loads(output.read_text(encoding="utf-8"))
        self.assertTrue(result["ok"], result)
        self.assertEqual(document["schema"], "managed-evidence-v1")
        self.assertEqual(document["artifactSha256"], result["artifactSha256"])
        self.assertEqual(document["image"]["sha256"], result["document"]["image"]["sha256"])

    def test_managed_exception_history_filters_native_events(self):
        native = {
            "ok": True,
            "nextAfterSeq": 11,
            "exceptionUnwoundPendingCalls": 1,
            "events": [
                {"seq": 10, "kind": "exception", "managedException": False},
                {
                    "seq": 11,
                    "kind": "exception_unwind",
                    "managedException": True,
                    "managedRuntime": "clr",
                    "managedHResult": "0x80131509",
                },
            ],
        }
        with mock.patch.object(self.mod, "GetNativeApiTraceEvidence", return_value=native):
            result = self.mod.GetManagedExceptionHistory("trace")
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["events"][0]["managedRuntime"], "clr")

    def test_runtime_dependency_is_pinned(self):
        requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8").casefold()
        self.assertIn("dnfile>=0.17.0", requirements)

    def test_managed_probe_runtime_discovery_has_no_checkout_specific_paths(self):
        probe_suffix = os.path.normcase(
            os.path.join("tools", "bin", "managed_probe", "x64", "x64dbg.ManagedProbe.exe")
        )
        portable_root = os.path.join("Z:\\Portable SDK", "dotnet")
        portable_host = os.path.join(portable_root, "dotnet.exe")

        def fake_isfile(path):
            normalized = os.path.normcase(os.path.normpath(str(path)))
            return normalized.endswith(probe_suffix) or normalized == os.path.normcase(portable_host)

        environment = {
            "X64DBG_MCP_MANAGED_PROBE_X64": "",
            "X64DBG_MCP_DOTNET_X64": "",
            "DOTNET_ROOT_X64": "",
            "DOTNET_ROOT": "",
            "ProgramFiles": "Z:\\Portable SDK",
        }
        with (
            mock.patch.dict(os.environ, environment, clear=False),
            mock.patch.object(self.mod.shutil, "which", return_value=None),
            mock.patch.object(self.mod.os.path, "isfile", side_effect=fake_isfile),
        ):
            component = self.mod._managed_probe_component("x64")

        self.assertTrue(component["ok"], component)
        self.assertEqual(os.path.normcase(component["runtimeRoot"]), os.path.normcase(portable_root))
        self.assertNotIn("ai_slop", json.dumps(component).casefold())

    def test_guarded_runtime_capture_preserves_exact_session_identity(self):
        binding = {
            "ok": True,
            "binding": {
                "active": True,
                "matches": True,
                "binding": {
                    "pid": 4242,
                    "bridgeInstanceId": "bridge",
                    "sessionId": "session",
                    "sessionGeneration": 7,
                    "imageSha256": "A" * 64,
                    "debuggerArch": "x64",
                },
            },
        }
        state = {"debugging": True, "paused": True, "debuggeePid": 4242}
        sidecar = {
            "ok": True,
            "schema": "x64dbg-mcp-managed-probe-v1",
            "process": {"pid": 4242, "architecture": "X64"},
            "runtimes": [],
            "resolutions": [],
        }
        with (
            mock.patch.object(self.mod, "_build_debug_state", return_value=state),
            mock.patch.object(self.mod, "GetSessionBinding", side_effect=[binding, binding]),
            mock.patch.object(self.mod, "_managed_probe_invoke", return_value=sidecar) as invoke,
        ):
            result = self.mod.CaptureManagedRuntimeState(metadata_token="0x06000001")
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["identityVerified"])
        self.assertEqual(result["session"]["sessionId"], "session")
        self.assertEqual(result["imageSha256"], "A" * 64)
        self.assertEqual(invoke.call_args.args[:2], (4242, "x64"))
        self.assertEqual(invoke.call_args.kwargs["metadata_token"], 0x06000001)

    def test_jit_resolution_and_post_jit_breakpoint_use_native_code_only(self):
        method = {
            "methodDesc": "0x1234",
            "metadataToken": "0x06000001",
            "declaringType": "Fixture",
            "name": "ManagedWork",
            "nativeCode": "0x7FF612340000",
            "compilationType": "Jit",
            "ilToNativeMap": [{"ilOffset": 0, "startAddress": "0x7FF612340000"}],
        }
        capture = {
            "ok": True,
            "resolutions": [{"methods": [method]}],
            "session": {"sessionId": "s"},
            "imageSha256": "B" * 64,
        }
        with mock.patch.object(self.mod, "CaptureManagedRuntimeState", return_value=capture):
            resolved = self.mod.ResolveManagedJitMethod(
                metadata_token="0x06000001", module="fixture.exe"
            )
        self.assertTrue(resolved["found"])
        self.assertEqual(resolved["methods"], [method])
        with (
            mock.patch.object(self.mod, "ResolveManagedJitMethod", return_value=resolved),
            mock.patch.object(
                self.mod, "DebugSetBreakpoint", return_value="Breakpoint set successfully"
            ) as set_breakpoint,
            mock.patch.object(self.mod, "ExecCommand", return_value={"success": True}),
        ):
            breakpoint = self.mod.SetManagedMethodBreakpoint("0x06000001")
        self.assertTrue(breakpoint["ok"], breakpoint)
        self.assertEqual(breakpoint["address"], "0x7FF612340000")
        set_breakpoint.assert_called_once_with("0x7FF612340000")

    def test_runtime_evidence_export_is_atomic_and_session_bound(self):
        capture = {
            "ok": True,
            "schema": "x64dbg-mcp-managed-probe-v1",
            "session": {"sessionId": "managed-session"},
            "imageSha256": "C" * 64,
            "runtimes": [],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "runtime-managed.json"
            with mock.patch.object(
                self.mod, "CaptureManagedRuntimeState", return_value=capture
            ):
                result = self.mod.ExportManagedRuntimeEvidence(str(output))
            document = json.loads(output.read_text(encoding="utf-8"))
        self.assertTrue(result["ok"], result)
        self.assertEqual(document["schema"], "managed-runtime-evidence-v1")
        self.assertEqual(document["imageSha256"], "C" * 64)
        self.assertEqual(document["session"]["sessionId"], "managed-session")
        self.assertEqual(document["artifactSha256"], result["artifactSha256"])

    def test_dynamic_metadata_stream_export_is_exact_and_session_bound(self):
        raw = b"BSJB" + bytes(range(32))
        session = {
            "pid": 4242,
            "bridgeInstanceId": "bridge",
            "sessionId": "session",
            "sessionGeneration": 2,
            "imageSha256": "D" * 64,
            "debuggerArch": "x64",
        }
        capture = {
            "ok": True,
            "session": session,
            "imageSha256": "D" * 64,
            "runtimes": [
                {
                    "appDomains": [
                        {
                            "modules": [
                                {
                                    "name": "dynamic://fixture",
                                    "assemblyName": "DynamicFixture",
                                    "appDomain": "fixture.exe",
                                    "imageBase": "0x0",
                                    "size": 0,
                                    "isDynamic": True,
                                    "isPeFile": False,
                                    "metadataAddress": "0x1234000",
                                    "metadataLength": len(raw),
                                }
                            ]
                        }
                    ]
                }
            ],
        }
        binding = {
            "ok": True,
            "binding": {"active": True, "matches": True, "binding": session},
        }

        def save(path, addr, size):
            Path(path).write_bytes(raw)
            return {"ok": True, "output": path, "addr": addr, "size": size}

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "dynamic-metadata.json"
            with (
                mock.patch.object(self.mod, "CaptureManagedRuntimeState", return_value=capture),
                mock.patch.object(self.mod, "SaveMemoryRegionToFile", side_effect=save),
                mock.patch.object(self.mod, "GetSessionBinding", return_value=binding),
            ):
                result = self.mod.ExportManagedAssemblyMetadata(
                    str(output), module="DynamicFixture"
                )
            document = json.loads(output.read_text(encoding="utf-8"))
        self.assertTrue(result["ok"], result)
        self.assertEqual(document["schema"], "managed-assembly-metadata-v1")
        self.assertEqual(base64.b64decode(document["metadata"]["base64"]), raw)
        self.assertEqual(
            document["metadata"]["sha256"],
            hashlib.sha256(raw).hexdigest().upper(),
        )
        self.assertTrue(document["module"]["isDynamic"])
        self.assertFalse(document["limitations"]["runnablePe"])


if __name__ == "__main__":
    unittest.main()
