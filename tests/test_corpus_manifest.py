import copy
import base64
import hashlib
import importlib.util
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "tools" / "corpus.py"
MANIFEST_PATH = REPO_ROOT / "tools" / "corpus_manifest.json"


def _load_module():
    spec = importlib.util.spec_from_file_location("x64dbg_mcp_corpus", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class CorpusManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()
        cls.manifest = cls.mod.load_manifest(MANIFEST_PATH)

    def test_repository_manifest_is_valid_and_complete(self):
        result = self.mod.validate_manifest(self.manifest, REPO_ROOT)
        self.assertTrue(result["ok"])
        self.assertEqual(result["schemaVersion"], self.manifest["schemaVersion"])
        self.assertEqual(result["fixtureCount"], 18)
        self.assertEqual(result["runtimeCaseCount"], 30)
        self.assertEqual(result["architectures"], ["x64", "x86"])

    def test_required_scenarios_have_dedicated_fixtures(self):
        scenarios = {fixture["scenario"] for fixture in self.manifest["fixtures"]}
        self.assertEqual(scenarios, self.mod.REQUIRED_SCENARIOS)

    def test_every_fixture_builds_x86_and_x64_from_local_sources(self):
        source_root = (REPO_ROOT / "tests" / "fixtures" / "e2e").resolve()
        for fixture in self.manifest["fixtures"]:
            with self.subTest(fixture=fixture["id"]):
                self.assertEqual(set(fixture["build"]["architectures"]), {"x86", "x64"})
                for source_value in fixture["build"]["sources"]:
                    source = (REPO_ROOT / source_value).resolve()
                    self.assertTrue(source.is_file())
                    self.assertTrue(source.is_relative_to(source_root))

    def test_artifacts_are_confined_to_existing_ignored_tree(self):
        gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("tools/bin/", gitignore.splitlines())
        artifact_root = (REPO_ROOT / self.manifest["artifactRoot"]).resolve()
        expected_root = (REPO_ROOT / "tools" / "bin" / "e2e").resolve()
        self.assertEqual(artifact_root, expected_root)
        for fixture in self.manifest["fixtures"]:
            for arch in ("x86", "x64"):
                rendered = fixture["build"]["output"].format(arch=arch)
                self.assertTrue((REPO_ROOT / rendered).resolve().is_relative_to(expected_root))

    def test_cmd_environment_sanitizes_quoted_path_entries(self):
        source = {
            "Path": r'C:\Windows;C:\Program Files\usbipd-win";C:\Program Files (x86)\Arm Toolchain',
            "KEEP": 'quoted "value"',
        }
        sanitized = self.mod._sanitized_command_environment(source)
        self.assertEqual(
            sanitized["Path"],
            r"C:\Windows;C:\Program Files\usbipd-win;C:\Program Files (x86)\Arm Toolchain",
        )
        self.assertEqual(sanitized["KEEP"], source["KEEP"])

    def test_safety_profile_is_fail_closed(self):
        for fixture in self.manifest["fixtures"]:
            safety = fixture["safety"]
            with self.subTest(fixture=fixture["id"]):
                self.assertEqual(safety["classification"], "benign")
                self.assertFalse(safety["requiresAdmin"])
                self.assertFalse(safety["network"])
                self.assertFalse(safety["dangerous"])
                self.assertLessEqual(set(safety["sideEffects"]), self.mod.ALLOWED_SIDE_EFFECTS)

    def test_module_host_is_built_after_dll_provider(self):
        result = self.mod.validate_manifest(self.manifest, REPO_ROOT)
        order = result["buildOrder"]
        self.assertLess(order.index("fixture_module"), order.index("module_imports"))
        host = next(item for item in self.manifest["fixtures"] if item["id"] == "module_imports")
        self.assertEqual(host["build"]["dependencies"], ["fixture_module"])
        self.assertEqual(host["build"]["expectedImports"], ["fixture_module.dll"])

    def test_exception_crash_permission_is_narrow(self):
        crash_cases = [
            (fixture, case)
            for fixture in self.manifest["fixtures"]
            for case in fixture["runtime"]
            if case.get("allowCrash")
        ]
        self.assertEqual(len(crash_cases), 1)
        fixture, case = crash_cases[0]
        self.assertEqual(fixture["scenario"], "exception-disposition")
        self.assertEqual(case["expectedExitCode"], 0xE0424242)
        self.assertEqual(self.mod._normalize_exit_code(-532528574), 0xE0424242)

    def test_exception_policy_precedence_runtime_oracle_is_declared(self):
        fixture = next(
            item for item in self.manifest["fixtures"]
            if item["id"] == "exception_disposition"
        )
        case = next(
            item for item in fixture["runtime"]
            if item["name"] == "policy-precedence-sequence"
        )
        self.assertEqual(case["args"], ["policy-sequence"])
        self.assertEqual(case["expectedExitCode"], 0)
        self.assertFalse(case.get("allowCrash", False))
        self.assertEqual(
            case["stdoutContains"],
            [
                "EXCEPTION_SEQUENCE selector=exact code=0xE0424242 caught=1",
                "EXCEPTION_SEQUENCE selector=masked code=0xE0429999 caught=1",
                "EXCEPTION_SEQUENCE selector=wildcard code=0xA1234567 caught=1",
                "EXCEPTION_POLICY_OK exact=1 masked=1 wildcard=1 caught=3",
            ],
        )

    def test_unicode_launch_contract_is_manifest_driven(self):
        fixture = next(item for item in self.manifest["fixtures"] if item["id"] == "launch_contract")
        case = fixture["runtime"][0]
        self.assertIn("Привет-世界-🙂", case["args"])
        self.assertEqual(case["env"]["X64DBG_MCP_E2E_ENV"], "значение-世界")
        self.assertIn("launch_тест", case["cwd"])
        self.assertEqual(case["expectedExitCode"], 37)

    def test_typed_launch_contract_modes_are_manifest_driven(self):
        fixture = next(
            item for item in self.manifest["fixtures"]
            if item["id"] == "launch_contract"
        )
        cases = {case["name"]: case for case in fixture["runtime"]}
        self.assertEqual(
            set(cases),
            {
                "unicode-args-cwd-env-exit",
                "typed-argv-env-cwd",
                "typed-stream-binary",
                "typed-quick",
            },
        )
        self.assertEqual(cases["typed-argv-env-cwd"]["args"][:2], ["--case", "argv-env-cwd"])
        self.assertEqual(cases["typed-stream-binary"]["args"], ["--case", "stream"])
        self.assertEqual(cases["typed-quick"]["args"], ["--case", "quick"])
        self.assertNotIn("burst", {arg for case in cases.values() for arg in case["args"]})

    def test_typed_argv_case_covers_windows_quoting_and_environment_states(self):
        fixture = next(
            item for item in self.manifest["fixtures"]
            if item["id"] == "launch_contract"
        )
        case = next(item for item in fixture["runtime"] if item["name"] == "typed-argv-env-cwd")
        self.assertEqual(
            case["args"][2:],
            [
                "",
                "plain",
                "two words",
                'quote"inside',
                'slashes\\\\before"quote',
                "trailing\\",
                "punctuation !@#$%^&*()[]{};,.?",
                "Привет 世界 🙂",
            ],
        )
        self.assertEqual(case["env"]["X64DBG_MCP_E2E_ENV_EMPTY"], "")
        self.assertNotIn("X64DBG_MCP_E2E_ENV_DELETE", case["env"])
        self.assertNotIn("X64DBG_MCP_E2E_ENV_ABSENT", case["env"])
        self.assertIn("launch_тест", case["cwd"])

    def test_binary_stream_manifest_oracles_are_exact_and_consistent(self):
        fixture = next(
            item for item in self.manifest["fixtures"]
            if item["id"] == "launch_contract"
        )
        case = next(item for item in fixture["runtime"] if item["name"] == "typed-stream-binary")
        stdin = self.mod._decode_runtime_stdin(case, "stream")
        self.assertIsNotNone(stdin)
        self.assertEqual(len(stdin), 257)
        self.assertEqual(stdin, bytes(range(256)) + b"\x00")

        for stream in ("stdout", "stderr"):
            title = stream.capitalize()
            expected = base64.b64decode(case[f"{stream}Base64"], validate=True)
            self.assertEqual(len(expected), case[f"expected{title}ByteCount"])
            self.assertEqual(
                hashlib.sha256(expected).hexdigest(),
                case[f"expected{title}Sha256"],
            )
            observed = self.mod._observe_runtime_stream(case, stream, expected)
            self.assertEqual(observed["base64"], case[f"{stream}Base64"])
            self.assertEqual(observed["byteCount"], len(expected))
            self.assertEqual(observed["sha256"], case[f"expected{title}Sha256"])
            self.assertEqual(observed["missing"], [])
            self.assertEqual(observed["mismatches"], [])

    def test_runtime_stdin_base64_and_hex_are_strict_and_mutually_exclusive(self):
        self.assertEqual(
            self.mod._decode_runtime_stdin({"stdinBase64": "AP8="}, "case"),
            b"\x00\xff",
        )
        self.assertEqual(
            self.mod._decode_runtime_stdin({"stdinHex": "00fF"}, "case"),
            b"\x00\xff",
        )
        for invalid in ({"stdinBase64": "***"}, {"stdinHex": "0"}, {"stdinHex": "00 ff"}):
            with self.subTest(invalid=invalid):
                with self.assertRaises(self.mod.CorpusValidationError):
                    self.mod._decode_runtime_stdin(invalid, "case")

        invalid = copy.deepcopy(self.manifest)
        stream = next(
            item for item in invalid["fixtures"][0]["runtime"]
            if item["name"] == "typed-stream-binary"
        )
        stream["stdinHex"] = "00ff"
        with self.assertRaisesRegex(self.mod.CorpusValidationError, "mutually exclusive"):
            self.mod.validate_manifest(invalid, REPO_ROOT)

    def test_exact_binary_oracle_digest_and_count_must_match(self):
        for field, value, message in (
            ("expectedStdoutByteCount", 90, "ByteCount does not match"),
            ("expectedStdoutSha256", "0" * 64, "Sha256 does not match"),
        ):
            invalid = copy.deepcopy(self.manifest)
            stream = next(
                item for item in invalid["fixtures"][0]["runtime"]
                if item["name"] == "typed-stream-binary"
            )
            stream[field] = value
            with self.subTest(field=field):
                with self.assertRaisesRegex(self.mod.CorpusValidationError, message):
                    self.mod.validate_manifest(invalid, REPO_ROOT)

    def test_stream_observation_reports_binary_safe_mismatch(self):
        fixture = next(
            item for item in self.manifest["fixtures"]
            if item["id"] == "launch_contract"
        )
        case = next(item for item in fixture["runtime"] if item["name"] == "typed-stream-binary")
        expected = base64.b64decode(case["stdoutBase64"], validate=True)
        observed = self.mod._observe_runtime_stream(case, "stdout", expected + b"\x00")
        self.assertEqual(observed["byteCount"], case["expectedStdoutByteCount"] + 1)
        self.assertIn("stdoutBase64:exact", observed["mismatches"])
        self.assertIn("expectedStdoutSha256", observed["mismatches"])
        self.assertIn("expectedStdoutByteCount", observed["mismatches"])

    def test_source_hash_manifest_covers_sources_headers_docs_and_cwd_marker(self):
        hashes = self.mod._source_hashes(self.manifest, REPO_ROOT)
        self.assertEqual(len(hashes), 21)
        self.assertIn("tests/fixtures/e2e/module_api.h", hashes)
        self.assertIn("tests/fixtures/e2e/README.md", hashes)
        self.assertIn(
            "tests/fixtures/e2e/workdirs/launch_тест/cwd_marker.txt", hashes
        )
        self.assertTrue(all(len(value) == 64 for value in hashes.values()))

    def test_duplicate_id_is_rejected(self):
        invalid = copy.deepcopy(self.manifest)
        invalid["fixtures"][1]["id"] = invalid["fixtures"][0]["id"]
        with self.assertRaisesRegex(self.mod.CorpusValidationError, "duplicate fixture id"):
            self.mod.validate_manifest(invalid, REPO_ROOT)

    def test_source_path_escape_is_rejected(self):
        invalid = copy.deepcopy(self.manifest)
        invalid["fixtures"][0]["build"]["sources"] = ["../outside.c"]
        with self.assertRaisesRegex(self.mod.CorpusValidationError, "escapes repository root"):
            self.mod.validate_manifest(invalid, REPO_ROOT)

    def test_dangerous_or_network_fixture_is_rejected(self):
        for field in ("dangerous", "network", "requiresAdmin"):
            invalid = copy.deepcopy(self.manifest)
            invalid["fixtures"][0]["safety"][field] = True
            with self.subTest(field=field):
                with self.assertRaisesRegex(self.mod.CorpusValidationError, field):
                    self.mod.validate_manifest(invalid, REPO_ROOT)

    def test_artifact_path_escape_is_rejected(self):
        invalid = copy.deepcopy(self.manifest)
        invalid["fixtures"][0]["build"]["output"] = "build/{arch}/escape.exe"
        with self.assertRaisesRegex(self.mod.CorpusValidationError, "invalid output path"):
            self.mod.validate_manifest(invalid, REPO_ROOT)

    def test_dependency_cycle_is_rejected(self):
        invalid = copy.deepcopy(self.manifest)
        provider = next(item for item in invalid["fixtures"] if item["id"] == "fixture_module")
        provider["build"]["dependencies"] = ["module_imports"]
        with self.assertRaisesRegex(self.mod.CorpusValidationError, "dependency cycle"):
            self.mod.validate_manifest(invalid, REPO_ROOT)

    def test_allow_crash_cannot_be_attached_to_other_fixtures(self):
        invalid = copy.deepcopy(self.manifest)
        case = invalid["fixtures"][0]["runtime"][0]
        case["allowCrash"] = True
        case["expectedExitCode"] = 0xC0000005
        with self.assertRaisesRegex(
            self.mod.CorpusValidationError, "allowCrash is restricted"
        ):
            self.mod.validate_manifest(invalid, REPO_ROOT)

    def test_runtime_environment_cannot_override_process_configuration(self):
        invalid = copy.deepcopy(self.manifest)
        invalid["fixtures"][0]["runtime"][0]["env"]["PATH"] = "C:\\untrusted"
        with self.assertRaisesRegex(self.mod.CorpusValidationError, "non-corpus keys"):
            self.mod.validate_manifest(invalid, REPO_ROOT)

    def test_runtime_cwd_is_confined_to_fixture_workdirs(self):
        invalid = copy.deepcopy(self.manifest)
        invalid["fixtures"][0]["runtime"][0]["cwd"] = "tests"
        with self.assertRaisesRegex(self.mod.CorpusValidationError, "runtime cwd"):
            self.mod.validate_manifest(invalid, REPO_ROOT)


if __name__ == "__main__":
    unittest.main()
