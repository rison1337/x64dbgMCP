import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "src" / "tool_profiles.py"
SERVER_PATH = ROOT / "src" / "x64dbg.py"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class ToolProfileCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profiles = _load_module("x64dbg_tool_profiles_test", PROFILE_PATH)
        cls.server = _load_module("x64dbg_tool_profiles_server_test", SERVER_PATH)
        cls.registry = cls.server._get_mcp_tools_registry()
        cls.catalog = cls.profiles.build_tool_catalog(cls.registry)

    def test_current_registry_has_an_explicit_complete_policy(self):
        actual = set(self.registry)
        known = set(self.profiles.known_tool_names())
        self.assertGreater(len(actual), 0)
        self.assertEqual(known, actual)
        self.assertEqual(set(self.catalog["toolMetadata"]), actual)
        self.assertEqual(self.catalog["count"], len(actual))

    def test_schema_and_compatibility_defaults_are_stable(self):
        self.assertEqual(self.catalog["schemaVersion"], 2)
        self.assertEqual(self.catalog["defaultProfile"], "full")
        self.assertEqual(self.catalog["activeProfile"], "full")
        self.assertEqual(self.catalog["recommendedProfile"], "compact")
        self.assertEqual(
            tuple(self.catalog["profiles"]),
            self.profiles.PROFILE_NAMES,
        )
        self.assertEqual(
            self.catalog["profiles"]["full"]["tools"],
            sorted(self.registry),
        )
        self.assertEqual(
            self.catalog["visibleTools"],
            self.catalog["profiles"]["full"]["tools"],
        )
        self.assertEqual(
            {
                profile: self.catalog["profiles"][profile]["count"]
                for profile in self.profiles.PROFILE_NAMES
            },
            {
                "compact": 40,
                "inspect": 137,
                "standard": 257,
                "automation": 274,
                "full": 290,
            },
        )

    def test_compact_profile_is_the_bounded_workflow_facade(self):
        compact = set(self.catalog["profiles"]["compact"]["tools"])
        standard = set(self.catalog["profiles"]["standard"]["tools"])
        self.assertEqual(compact, set(self.profiles.COMPACT_TOOLS))
        self.assertEqual(len(compact), 40)
        self.assertLess(compact, standard)
        for expected in (
            "InitDebuggee",
            "DebugRun",
            "ReadMemory",
            "SetBreakpointWithCapture",
            "RunApiTrace",
            "DumpPeFromMemory",
            "RecoverComparisonSecret",
            "CaptureManagedRuntimeState",
            "ExportRuntimeEvidence",
        ):
            self.assertIn(expected, compact)
        for low_level in (
            "ExecCommand",
            "MemoryRemoteAlloc",
            "ClickActiveWindow",
        ):
            self.assertNotIn(low_level, compact)

    def test_compact_startup_contract_is_target_first(self):
        instructions = " ".join(self.server.MCP_SERVER_INSTRUCTIONS.split())
        init_doc = self.server.InitDebuggee.__doc__ or ""
        bridge_doc = self.server.BridgeHello.__doc__ or ""

        self.assertIn("call InitDebuggee directly", instructions)
        self.assertIn("Do not preflight BridgeHello", instructions)
        self.assertIn("resolves X64DBG_ROOT", init_doc)
        self.assertIn("Do not preflight BridgeHello", init_doc)
        self.assertIn("Diagnostic only", bridge_doc)
        self.assertIn("call InitDebuggee directly", bridge_doc)

    def test_primary_categories_cover_every_tool_exactly_once(self):
        categories = self.catalog["categories"]
        flattened = [name for names in categories.values() for name in names]
        self.assertEqual(len(flattened), len(set(flattened)))
        self.assertEqual(set(flattened), set(self.registry))
        self.assertEqual(len(categories["annotations"]), 25)
        for name, metadata in self.catalog["toolMetadata"].items():
            self.assertIn(name, categories[metadata["category"]])

    def test_policy_vocabulary_is_closed(self):
        for name, metadata in self.catalog["toolMetadata"].items():
            with self.subTest(tool=name):
                self.assertIn(metadata["risk"], self.profiles.RISK_LEVELS)
                self.assertTrue(metadata["profiles"])
                self.assertEqual(metadata["profiles"][-1], "full")
                self.assertLessEqual(
                    set(metadata["sideEffects"]), self.profiles.SIDE_EFFECT_KINDS
                )
                for item in metadata["conditionalSideEffects"]:
                    self.assertIn(item["kind"], self.profiles.SIDE_EFFECT_KINDS)
                    self.assertIsInstance(item.get("when"), dict)
                self.assertLessEqual(
                    set(metadata["requires"]), self.profiles.REQUIREMENT_KINDS
                )
                self.assertLessEqual(
                    set(metadata["touches"]), self.profiles.TOUCH_KINDS
                )
                annotations = metadata["annotations"]
                self.assertEqual(
                    set(annotations),
                    {
                        "readOnlyHint",
                        "destructiveHint",
                        "idempotentHint",
                        "openWorldHint",
                    },
                )

    def test_inspect_profile_is_strictly_read_only(self):
        inspect_names = set(self.catalog["profiles"]["inspect"]["tools"])
        self.assertTrue(inspect_names)
        for name in inspect_names:
            self.assertTrue(
                self.catalog["toolMetadata"][name]["annotations"]["readOnlyHint"],
                name,
            )
        self.assertIn("BridgeHello", inspect_names)
        self.assertIn("MemoryRead", inspect_names)
        self.assertIn("ValidateAnalysisEvidence", inspect_names)
        self.assertNotIn("DebugRun", inspect_names)
        self.assertNotIn("ExportAnalysisEvidence", inspect_names)
        self.assertNotIn("WaitForModuleLoad", inspect_names)

    def test_standard_and_automation_have_safe_discovery_boundaries(self):
        standard = set(self.catalog["profiles"]["standard"]["tools"])
        automation = set(self.catalog["profiles"]["automation"]["tools"])
        full = set(self.catalog["profiles"]["full"]["tools"])

        self.assertLess(standard, automation)
        self.assertLess(automation, full)
        for expected in (
            "BridgeHello",
            "MemoryRead",
            "MemoryWrite",
            "DebugRun",
            "SetBreakpointWithCapture",
            "RunApiTrace",
            "DumpModule",
            "ExportAnalysisEvidence",
            "AttachToProcess",
            "LaunchFileUnderDebugger",
            "BookmarkDelete",
            "CommentDelete",
            "FunctionDelete",
            "LabelDelete",
        ):
            self.assertIn(expected, standard)

        for hidden in (
            "ExecCommand",
            "MemoryRemoteAlloc",
            "MemoryRemoteFree",
            "LoadLibraryInDebuggee",
            "RemoveProcessDebug",
            "ClickActiveWindow",
            "SendForegroundKeys",
        ):
            self.assertNotIn(hidden, standard)

        self.assertNotIn("ClickDebuggeeWindow", standard)
        self.assertIn("ClickDebuggeeWindow", automation)
        self.assertNotIn("ClickActiveWindow", automation)
        self.assertEqual(full, set(self.registry))

    def test_annotation_deletes_are_idempotent_destructive_mutations(self):
        metadata = self.catalog["toolMetadata"]
        inspect_names = set(self.catalog["profiles"]["inspect"]["tools"])
        standard = set(self.catalog["profiles"]["standard"]["tools"])
        automation = set(self.catalog["profiles"]["automation"]["tools"])
        full = set(self.catalog["profiles"]["full"]["tools"])

        for name in (
            "BookmarkDelete",
            "CommentDelete",
            "FunctionDelete",
            "LabelDelete",
        ):
            with self.subTest(tool=name):
                policy = metadata[name]
                self.assertEqual(policy["category"], "annotations")
                self.assertEqual(policy["tags"], ["core"])
                self.assertEqual(policy["profiles"], ["standard", "automation", "full"])
                self.assertEqual(policy["risk"], "reversible")
                self.assertEqual(policy["touches"], ["bridge", "debugger", "filesystem"])
                self.assertEqual(policy["sideEffects"], ["debugger.database.write"])
                self.assertEqual(policy["conditionalSideEffects"], [])
                self.assertEqual(policy["requires"], ["bridge", "debug-session"])
                self.assertEqual(
                    policy["annotations"],
                    {
                        "readOnlyHint": False,
                        "destructiveHint": True,
                        "idempotentHint": True,
                        "openWorldHint": True,
                    },
                )
                self.assertNotIn(name, inspect_names)
                self.assertIn(name, standard)
                self.assertIn(name, automation)
                self.assertIn(name, full)

    def test_mutation_lease_tools_have_explicit_session_state_metadata(self):
        metadata = self.catalog["toolMetadata"]
        for name in (
            "AcquireMutationLease",
            "RenewMutationLease",
            "ReleaseMutationLease",
        ):
            with self.subTest(tool=name):
                policy = metadata[name]
                self.assertEqual(policy["category"], "session")
                self.assertEqual(policy["risk"], "reversible")
                self.assertEqual(policy["sideEffects"], ["mcp.state.write"])
                self.assertEqual(policy["requires"], ["bridge", "debug-session"])
                self.assertFalse(policy["annotations"]["readOnlyHint"])
                self.assertIn(name, self.catalog["profiles"]["standard"]["tools"])

        self.assertFalse(
            metadata["AcquireMutationLease"]["annotations"]["idempotentHint"]
        )
        self.assertFalse(
            metadata["RenewMutationLease"]["annotations"]["idempotentHint"]
        )
        self.assertTrue(
            metadata["ReleaseMutationLease"]["annotations"]["idempotentHint"]
        )

    def test_conditional_effects_cover_parameter_dependent_mutations(self):
        metadata = self.catalog["toolMetadata"]

        def effect(tool, kind, parameter):
            matches = [
                item
                for item in metadata[tool]["conditionalSideEffects"]
                if item["kind"] == kind
                and item.get("when", {}).get("parameter") == parameter
            ]
            self.assertEqual(len(matches), 1, (tool, kind, parameter))
            return matches[0]

        effect("ExportAnalysisEvidence", "host.filesystem.write", "output_path")
        effect("ExportRuntimeEvidence", "host.filesystem.write", "output_path")
        effect("ExportManagedEvidence", "host.filesystem.write", "output_path")
        effect("ExportManagedRuntimeEvidence", "host.filesystem.write", "output_path")
        effect("ExportCapabilityMap", "host.filesystem.write", "output_path")
        effect("CaptureDebuggeeWindow", "host.filesystem.write", "save_path")
        effect("RecoverComparisonSecret", "host.filesystem.write", "evidence_path")
        effect("ImportAnalysisEvidence", "debugger.database.write", "dry_run")
        effect("ImportStaticAnnotations", "debugger.database.write", "dry_run")
        effect("SyncBreakpoints", "debugger.breakpoint.write", "apply")
        effect("LaunchFileUnderDebugger", "debuggee.module.inject", "use_scyllahide")
        effect("WaitForModuleLoad", "debuggee.execution", "auto_run")
        effect("WriteMiniDump", "debuggee.execution", "pause_if_running")
        effect("WriteMiniDump", "debuggee.execution", "resume_after")
        effect("CaptureManagedRuntimeState", "debuggee.execution", "pause_if_running")
        effect("CaptureManagedRuntimeState", "debuggee.execution", "resume_after")

        for name in (
            "ExportAnalysisEvidence",
            "ExportCapabilityMap",
            "ImportAnalysisEvidence",
            "LaunchFileUnderDebugger",
            "WaitForModuleLoad",
            "WriteMiniDump",
        ):
            self.assertFalse(metadata[name]["annotations"]["readOnlyHint"], name)

    def test_unknown_or_stale_registry_policy_fails_closed(self):
        with self.assertRaisesRegex(
            self.profiles.ToolProfileError, "missing policy: FutureDangerousTool"
        ):
            self.profiles.build_tool_catalog(
                dict(self.registry, FutureDangerousTool=lambda: None)
            )

        without_one = dict(self.registry)
        without_one.pop("MemoryRead")
        with self.assertRaisesRegex(
            self.profiles.ToolProfileError, "stale policy: MemoryRead"
        ):
            self.profiles.build_tool_catalog(without_one)

        with self.assertRaisesRegex(self.profiles.ToolProfileError, "Unknown tool profile"):
            self.profiles.build_tool_catalog(self.registry, active_profile="unsafe")


class ToolProfileFastMcpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profiles = _load_module("x64dbg_tool_profiles_apply_test", PROFILE_PATH)
        cls.server = _load_module("x64dbg_tool_profiles_apply_server_test", SERVER_PATH)
        cls.registry = cls.server._get_mcp_tools_registry()

    def test_annotations_and_namespaced_meta_apply_after_ext_tools(self):
        manager = self.server.mcp._tool_manager
        before_names = {tool.name for tool in manager.list_tools()}
        self.assertEqual(before_names, set(self.registry))

        memory_read = manager.get_tool("MemoryRead")
        memory_read.meta = {"preserved": True}
        catalog = self.profiles.apply_tool_metadata(
            self.server.mcp, self.registry, active_profile="standard"
        )

        after_names = {tool.name for tool in manager.list_tools()}
        self.assertEqual(after_names, before_names)
        self.assertEqual(catalog["activeProfile"], "standard")
        self.assertTrue(memory_read.meta["preserved"])

        for name in (
            "MemoryRead",
            "MemoryWrite",
            "ScanMemoryStrings",
            "DumpModule",
            "SetExceptionFilter",
            "BookmarkDelete",
            "CommentDelete",
            "FunctionDelete",
            "LabelDelete",
        ):
            with self.subTest(tool=name):
                tool = manager.get_tool(name)
                self.assertIsNotNone(tool.annotations)
                self.assertIn("x64dbg", tool.meta)
                self.assertEqual(tool.meta["x64dbg"]["schemaVersion"], 2)

        self.assertTrue(manager.get_tool("MemoryRead").annotations.readOnlyHint)
        self.assertFalse(manager.get_tool("MemoryWrite").annotations.readOnlyHint)
        self.assertTrue(manager.get_tool("MemoryWrite").annotations.destructiveHint)
        for name in (
            "BookmarkDelete",
            "CommentDelete",
            "FunctionDelete",
            "LabelDelete",
        ):
            tool = manager.get_tool(name)
            self.assertFalse(tool.annotations.readOnlyHint)
            self.assertTrue(tool.annotations.destructiveHint)
            self.assertTrue(tool.annotations.idempotentHint)
        self.assertEqual(
            manager.get_tool("ExecCommand").meta["x64dbg"]["risk"], "unbounded"
        )

    def test_filtering_does_not_unregister_hidden_tools(self):
        manager = self.server.mcp._tool_manager
        catalog = self.profiles.build_tool_catalog(self.registry)
        all_tools = manager.list_tools()
        before_count = len(all_tools)

        filtered = self.profiles.filter_mcp_tools(all_tools, catalog, "inspect")
        filtered_names = {tool.name for tool in filtered}
        self.assertEqual(
            filtered_names,
            set(catalog["profiles"]["inspect"]["tools"]),
        )
        self.assertNotIn("DebugRun", filtered_names)
        self.assertIsNotNone(manager.get_tool("DebugRun"))
        self.assertEqual(len(manager.list_tools()), before_count)

    def test_manager_registry_mismatch_is_rejected_before_mutation(self):
        partial = dict(self.registry)
        partial.pop("MemoryRead")
        with self.assertRaises(self.profiles.ToolProfileError):
            self.profiles.apply_tool_metadata(self.server.mcp, partial)


if __name__ == "__main__":
    unittest.main()
