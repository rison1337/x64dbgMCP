"""Offline tests for the unpack/OEP workflow.

These lock in the anti-false-success guarantees of the rewritten engine: a dump
is only "verified" (and thus a DumpModule/FindOEP success) when the entry has
moved out of the packer stub, the IAT resolved cleanly, and the import table is
neither corrupt nor trivial. They run without a live x64dbg by monkeypatching
`_parse_pe_layout` and the prologue probe.
"""

import importlib.util
import hashlib
import json
import os
import struct
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "x64dbg.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("x64dbg_bridge", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BASE = 0x140000000
PACKED_ENTRY_RVA = 0x25A80  # in the packer stub section (UPX1)
OEP_RVA = 0x1460            # in the unpacked section (UPX0)


def _pe64_with_invalid_trailing_import():
    data = bytearray(0x1200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<Q", data, optional + 24, BASE)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, optional + 56, 0x2000, 0x200)
    struct.pack_into("<I", data, optional + 108, 16)
    struct.pack_into("<II", data, optional + 112 + 8, 0x1000, 60)
    struct.pack_into("<II", data, optional + 112 + 12 * 8, 0x1100, 16)
    section = optional + 0xF0
    data[section : section + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x1000, 0x1000, 0x1000, 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000040)
    # One valid descriptor followed by the exact Scylla failure shape: an
    # invalid trailing DLL descriptor and then a terminator.
    struct.pack_into("<IIIII", data, 0x200, 0x1080, 0, 0, 0x1060, 0x1100)
    struct.pack_into("<IIIII", data, 0x214, 0x1080, 0, 0, 0x1070, 0x1100)
    data[0x260 : 0x260 + 13] = b"kernel32.dll\0"
    data[0x270 : 0x270 + 10] = b"*invalid*\0"
    struct.pack_into("<QQ", data, 0x280, 0x10A0, 0)
    struct.pack_into("<H", data, 0x2A0, 0)
    data[0x2A2 : 0x2A2 + 12] = b"ExitProcess\0"
    struct.pack_into("<QQ", data, 0x300, 0x10A0, 0)
    return bytes(data)


def _pe_with_tls_callback(is_64):
    data = bytearray(0x1000)
    image_base = 0x140000000 if is_64 else 0x400000
    optional_size = 0xF0 if is_64 else 0xE0
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        data,
        0x84,
        0x8664 if is_64 else 0x14C,
        1,
        0,
        0,
        0,
        optional_size,
        0x22,
    )
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B if is_64 else 0x10B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    if is_64:
        struct.pack_into("<Q", data, optional + 24, image_base)
    else:
        struct.pack_into("<I", data, optional + 24, 0x1000)  # BaseOfData sentinel
        struct.pack_into("<I", data, optional + 28, image_base)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, optional + 56, 0x2000, 0x200)
    directory_base = optional + (112 if is_64 else 96)
    struct.pack_into("<I", data, optional + (108 if is_64 else 92), 16)
    struct.pack_into("<II", data, directory_base + (9 * 8), 0x1100, 40 if is_64 else 24)
    if is_64:
        struct.pack_into("<II", data, directory_base + (3 * 8), 0x1180, 12)
    section = optional + optional_size
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x800, 0x1000, 0x800, 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    tls_offset = 0x300
    callbacks_va = image_base + 0x1140
    if is_64:
        struct.pack_into(
            "<QQQQII",
            data,
            tls_offset,
            image_base + 0x1200,
            image_base + 0x1200,
            image_base + 0x1130,
            callbacks_va,
            0,
            0,
        )
        struct.pack_into("<QQ", data, 0x340, image_base + 0x1010, 0)
        struct.pack_into("<III", data, 0x380, 0x1000, 0x1050, 0x1160)
    else:
        struct.pack_into(
            "<IIIIII",
            data,
            tls_offset,
            image_base + 0x1200,
            image_base + 0x1200,
            image_base + 0x1130,
            callbacks_va,
            0,
            0,
        )
        struct.pack_into("<II", data, 0x340, image_base + 0x1010, 0)
    return bytes(data)


class OepVerifyDumpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def setUp(self):
        handle = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")
        handle.write(b"MZ" + b"\x00" * 512)
        handle.close()
        self.fixed = handle.name
        self._orig_parse = self.mod._parse_pe_layout

    def tearDown(self):
        self.mod._parse_pe_layout = self._orig_parse
        try:
            os.remove(self.fixed)
        except OSError:
            pass

    def _packed_layout(self):
        return {
            "entryPointRva": f"0x{PACKED_ENTRY_RVA:x}",
            "imports": [{"dll": "kernel32.dll", "functions": ["a", "b"]}],
        }

    def _set_dump_layout(self, layout):
        self.mod._parse_pe_layout = lambda path: layout

    def _payload(self, iat_size="0x190"):
        return {"dumpResult": {"iatSize": iat_size, "searchResultName": "SCY_ERROR_SUCCESS"}}

    def _verify(self, oep_rva=OEP_RVA):
        return self.mod._oep_verify_dump(
            f"0x{BASE + oep_rva:x}", BASE, self.fixed, self._packed_layout(), self._payload()
        )

    def test_missing_file_is_not_verified(self):
        result = self.mod._oep_verify_dump(
            f"0x{BASE + OEP_RVA:x}", BASE, self.fixed + ".nope",
            self._packed_layout(), self._payload(),
        )
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], "dump_no_fixed_file")

    def test_unresolved_iat_is_not_verified(self):
        result = self.mod._oep_verify_dump(
            f"0x{BASE + OEP_RVA:x}", BASE, self.fixed,
            self._packed_layout(), {"dumpResult": {"iatSize": "0x0"}},
        )
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], "dump_iat_unresolved")

    def test_dump_entry_mismatch_is_not_verified(self):
        # Scylla wrote a different entry than the OEP the engine chose -> reject.
        self._set_dump_layout(
            {
                "entryPointRva": f"0x{PACKED_ENTRY_RVA:x}",
                "imports": [{"dll": "kernel32.dll", "functions": ["a", "b", "c", "d"]}],
            }
        )
        result = self._verify(oep_rva=OEP_RVA)  # oep=0x1460 but dump entry=0x25a80
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], "dump_entry_mismatch")

    def test_tls_unpacker_oep_equals_entry_is_verified(self):
        # MPRESS-style TLS unpackers legitimately have OEP == the PE entry point.
        # With clean imports and matching entry, that must verify (not be rejected
        # just because the entry didn't move).
        self._set_dump_layout(
            {
                "entryPointRva": f"0x{PACKED_ENTRY_RVA:x}",
                "imports": [
                    {"dll": "kernel32.dll", "functions": ["a", "b"]},
                    {"dll": "ucrtbase.dll", "functions": ["c", "d", "e"]},
                ],
            }
        )
        result = self._verify(oep_rva=PACKED_ENTRY_RVA)  # oep == dump entry -> match
        self.assertTrue(result["verified"])

    def test_corrupt_iat_garbage_dll_name_is_not_verified(self):
        # The "?.DLL" that over-aggressive IAT search invents must be rejected.
        self._set_dump_layout(
            {
                "entryPointRva": f"0x{OEP_RVA:x}",
                "imports": [
                    {"dll": "kernel32.dll", "functions": ["a", "b", "c"]},
                    {"dll": "?", "functions": ["x"]},
                ],
            }
        )
        result = self._verify()
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], "dump_iat_corrupt")

    def test_trivial_imports_are_not_verified(self):
        self._set_dump_layout(
            {
                "entryPointRva": f"0x{OEP_RVA:x}",
                "imports": [{"dll": "kernel32.dll", "functions": ["a"]}],
            }
        )
        result = self._verify()
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], "dump_imports_trivial")

    def test_unresolved_import_function_name_is_not_verified(self):
        self._set_dump_layout(
            {
                "entryPointRva": f"0x{OEP_RVA:x}",
                "imports": [
                    {"dll": "kernel32.dll", "functions": ["a", "b", "?"]},
                ],
            }
        )
        result = self._verify()
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], "dump_iat_unresolved_names")

    def test_import_count_regression_is_not_verified(self):
        packed = {
            "entryPointRva": f"0x{PACKED_ENTRY_RVA:x}",
            "imports": [{"dll": "kernel32.dll", "functions": ["a", "b", "c", "d"]}],
        }
        self._set_dump_layout(
            {
                "entryPointRva": f"0x{OEP_RVA:x}",
                "imports": [{"dll": "kernel32.dll", "functions": ["a", "b", "c"]}],
            }
        )
        result = self.mod._oep_verify_dump(
            f"0x{BASE + OEP_RVA:x}", BASE, self.fixed, packed, self._payload()
        )
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], "dump_imports_regressed")

    def test_clean_unpack_is_verified(self):
        self._set_dump_layout(
            {
                "entryPointRva": f"0x{OEP_RVA:x}",
                "imports": [
                    {"dll": "kernel32.dll", "functions": ["a", "b"]},
                    {"dll": "ucrtbase.dll", "functions": ["c", "d", "e"]},
                ],
            }
        )
        result = self._verify()
        self.assertTrue(result["verified"])
        self.assertEqual(result["reason"], "verified")
        self.assertTrue(result["iatResolved"])
        self.assertTrue(result["entryMatches"])
        self.assertEqual(result["packedImportCount"], 2)
        self.assertEqual(result["dumpImportCount"], 5)


class OepAcceptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def setUp(self):
        self._orig = self.mod._oep_looks_like_prologue
        self.mod._oep_looks_like_prologue = lambda rip_hex: True

    def tearDown(self):
        self.mod._oep_looks_like_prologue = self._orig

    def _plan(self):
        return {
            "baseInt": BASE,
            "entryInt": BASE + PACKED_ENTRY_RVA,
            "entrySection": "upx1",
            "execSections": [
                {"name": "UPX0", "nameLower": "upx0", "start": BASE + 0x1000, "end": BASE + 0x1E000},
                {"name": "UPX1", "nameLower": "upx1", "start": BASE + 0x1E000, "end": BASE + 0x26000},
            ],
            "layout": {"sizeOfImage": 0x40000},
        }

    def test_rejects_rip_in_packer_section(self):
        verdict = self.mod._oep_accept(f"0x{BASE + 0x1E100:x}", self._plan())
        self.assertFalse(verdict["accepted"])

    def test_accepts_section_hop(self):
        verdict = self.mod._oep_accept(f"0x{BASE + OEP_RVA:x}", self._plan())
        self.assertTrue(verdict["accepted"])
        self.assertEqual(verdict["section"], "UPX0")
        self.assertEqual(verdict["confidence"], "high")

    def test_rejects_rip_outside_image(self):
        verdict = self.mod._oep_accept(f"0x{BASE + 0x900000:x}", self._plan())
        self.assertFalse(verdict["accepted"])

    def test_mpress_first_section_hop_requires_same_section_refinement(self):
        plan = self._plan()
        plan["entrySection"] = ".MPRESS2"
        verdict = {"accepted": True, "section": ".MPRESS1", "rip": hex(BASE + 0x17F4C)}
        self.assertTrue(self.mod._oep_candidate_needs_refinement(verdict, plan))
        verdict["section"] = "UPX0"
        plan["entrySection"] = "UPX1"
        self.assertFalse(self.mod._oep_candidate_needs_refinement(verdict, plan))


class GenericSameSectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def test_unchanged_loader_inside_mutated_section_requires_refinement(self):
        decision = self.mod._oep_same_section_refinement_decision(
            known_loader_shape=False,
            candidate_evidence={
                "available": True,
                "similarity": 0.97,
                "changedBytes": 2,
            },
            section_evidence={
                "available": True,
                "changedSampleCount": 3,
                "mutationRatio": 0.25,
            },
        )
        self.assertTrue(decision["refine"])
        self.assertTrue(decision["genericRuntimeMutation"])
        self.assertEqual(
            decision["reason"],
            "unchanged-loader-inside-runtime-mutated-section",
        )

    def test_mutated_candidate_is_not_misclassified_as_loader(self):
        decision = self.mod._oep_same_section_refinement_decision(
            known_loader_shape=False,
            candidate_evidence={
                "available": True,
                "similarity": 0.18,
                "changedBytes": 72,
            },
            section_evidence={
                "available": True,
                "changedSampleCount": 4,
                "mutationRatio": 0.5,
            },
        )
        self.assertFalse(decision["refine"])
        self.assertFalse(decision["candidateUnchanged"])

    def test_x86_relocation_bytes_do_not_hide_unchanged_loader(self):
        decision = self.mod._oep_same_section_refinement_decision(
            known_loader_shape=False,
            candidate_evidence={
                "available": True,
                "similarity": 0.9375,
                "changedBytes": 1,
            },
            section_evidence={
                "available": True,
                "changedSampleCount": 1,
                "mutationRatio": 0.125,
            },
        )
        self.assertTrue(decision["refine"])
        self.assertTrue(decision["candidateUnchanged"])
        self.assertTrue(decision["genericRuntimeMutation"])

    def test_same_section_condition_supports_forward_and_backward_transfers(self):
        condition = self.mod._oep_same_section_condition(
            BASE + 0x1000,
            BASE + 0x9000,
            [BASE + 0x5000],
            0x100,
        )
        self.assertIn(f"cip>=0x{BASE + 0x1000:x}", condition)
        self.assertIn(f"cip<0x{BASE + 0x4F00:x}", condition)
        self.assertIn(f"cip>=0x{BASE + 0x5100:x}", condition)
        self.assertIn(f"cip<0x{BASE + 0x9000:x}", condition)

    def test_compact_section_sampling_has_no_payload_sized_gaps(self):
        section = {
            "name": ".packed",
            "start": BASE + 0x1000,
            "end": BASE + 0x1200,
        }
        observed = []

        def evidence(address, _section, _plan, *, span):
            observed.append((address, span))
            return {
                "available": True,
                "similarity": 1.0,
                "changedBytes": 0,
            }

        with mock.patch.object(
            self.mod, "_oep_runtime_disk_evidence", side_effect=evidence
        ):
            result = self.mod._oep_section_mutation_evidence(
                section, {}, sample_size=64
            )
        addresses = [item[0] for item in observed]
        self.assertEqual(result["sampleCount"], 8)
        self.assertEqual(addresses[0], BASE + 0x1000)
        self.assertEqual(addresses[-1], BASE + 0x11C0)
        self.assertTrue(
            all(right - left <= 64 for left, right in zip(addresses, addresses[1:]))
        )

    def test_trace_accepts_forward_transfer_only_with_runtime_mutation(self):
        section = {
            "name": ".packed",
            "start": BASE + 0x1000,
            "end": BASE + 0x9000,
        }
        plan = {
            "entryInt": BASE + 0x2000,
            "execSections": [section],
        }
        target = BASE + 0x7000
        telemetry = {"notes": []}
        with mock.patch.object(
            self.mod,
            "_oep_trace_to_sections",
            return_value={"state": "paused"},
        ), mock.patch.object(
            self.mod,
            "_oep_read_state",
            return_value=({"cip": hex(target)}, {"state": "paused"}),
        ), mock.patch.object(
            self.mod,
            "_oep_runtime_disk_evidence",
            return_value={
                "available": True,
                "similarity": 0.10,
                "changedBytes": 80,
            },
        ), mock.patch.object(
            self.mod, "_oep_looks_like_prologue", return_value=True
        ):
            result = self.mod._oep_trace_same_section_transfer(
                hex(BASE + 0x5000),
                section,
                plan,
                time.time() + 2.0,
                telemetry,
            )
        self.assertTrue(result["accepted"])
        self.assertEqual(result["rip"], hex(target))
        self.assertEqual(result["confidence"], "high")
        self.assertTrue(result["sameSectionTransitions"][0]["runtimeMutation"])

    def test_trace_clears_first_chance_inline_breakpoint_before_running(self):
        section = {
            "name": ".packed",
            "start": BASE + 0x1000,
            "end": BASE + 0x9000,
        }
        plan = {"entryInt": BASE + 0x2000, "execSections": [section]}
        target = BASE + 0x7000
        pending = {
            "state": "paused",
            "eventSeq": 77,
            "exceptionPending": True,
            "exceptionFirstChance": True,
            "exceptionCode": "0x80000003",
        }
        with mock.patch.object(
            self.mod,
            "_oep_read_state",
            side_effect=[
                ({"cip": hex(BASE + 0x5001)}, pending),
                ({"cip": hex(target)}, {"state": "paused"}),
            ],
        ), mock.patch.object(
            self.mod,
            "ContinueException",
            return_value={"ok": True, "eventSeq": 77},
        ) as continuation, mock.patch.object(
            self.mod,
            "_oep_trace_to_sections",
            return_value={"state": "paused"},
        ), mock.patch.object(
            self.mod,
            "_oep_runtime_disk_evidence",
            return_value={
                "available": True,
                "similarity": 0.10,
                "changedBytes": 80,
            },
        ), mock.patch.object(
            self.mod, "_oep_looks_like_prologue", return_value=True
        ):
            result = self.mod._oep_trace_same_section_transfer(
                hex(BASE + 0x5000),
                section,
                plan,
                time.time() + 2.0,
                {"notes": []},
            )
        self.assertTrue(result["accepted"])
        continuation.assert_called_once_with(
            disposition="handled",
            expected_event_seq=77,
            resume=False,
        )


class OepToolRegistrationTests(unittest.TestCase):
    def test_oep_tools_are_registered(self):
        mod = _load_module()
        try:
            names = set(mod._get_mcp_tools_registry().keys())
        except Exception:
            names = set(getattr(mod.mcp, "_tool_manager")._tools.keys())
        for tool in ("FindOEP", "DumpModule", "RunUntilOEP"):
            self.assertIn(tool, names)


class UnpackWorkflowArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def test_stage_sequence_and_confidence_are_deterministic(self):
        stages = []
        first = self.mod._append_unpack_stage(stages, "layout", "ready", {"sections": 2})
        second = self.mod._append_unpack_stage(stages, "candidate", "accepted")
        self.assertEqual(first["seq"], 1)
        self.assertEqual(second["seq"], 2)
        self.assertEqual(self.mod._unpack_confidence_score("high", None), 0.85)
        self.assertEqual(self.mod._unpack_confidence_score("low", True), 0.95)
        self.assertEqual(self.mod._unpack_confidence_score("high", False), 0.25)

    def test_workflow_artifact_has_recomputable_digest_and_atomic_output(self):
        result = {
            "workflowId": "unpack-test",
            "startedAt": "2026-07-26T00:00:00Z",
            "finishedAt": "2026-07-26T00:00:01Z",
            "status": "unpacked_verified",
            "ok": True,
            "verified": True,
            "confidence": "high",
            "confidenceScore": 0.95,
            "target": {"sha256": "A" * 64, "architecture": "x64"},
            "oepAddr": "0x140001000",
            "candidateSection": ".text",
            "detectedVia": "fixture",
            "distanceFromEntry": "0x1000",
            "reason": "verified",
            "unsupported": None,
            "stages": [
                {"seq": 1, "stage": "complete", "status": "unpacked_verified"}
            ],
            "artifacts": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "workflow.json"
            written = self.mod._write_unpack_workflow_artifact(result, str(path))
            self.assertTrue(written["ok"], written)
            payload = json.loads(path.read_text(encoding="utf-8"))
            digest = payload.pop("workflowSha256")
            canonical = json.dumps(
                payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            self.assertEqual(digest, hashlib.sha256(canonical).hexdigest().upper())
            self.assertEqual(digest, written["workflowSha256"])


class PeTlsSehEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def _parse(self, is_64):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ("tls64.exe" if is_64 else "tls32.exe")
            path.write_bytes(_pe_with_tls_callback(is_64))
            return self.mod._parse_pe_layout(str(path))

    def test_pe32_image_base_and_tls_callback_are_normalized(self):
        layout = self._parse(False)
        self.assertEqual(layout["imageBase"], "0x400000")
        self.assertEqual(layout["tlsDirectory"]["callbackCount"], 1)
        self.assertEqual(layout["tlsDirectory"]["callbacks"][0]["rva"], "0x1010")
        self.assertEqual(layout["tlsDirectory"]["callbacks"][0]["section"], ".text")
        self.assertTrue(layout["tlsDirectory"]["callbacks"][0]["executable"])

    def test_pe32_plus_tls_and_exception_runtime_function_evidence(self):
        layout = self._parse(True)
        self.assertEqual(layout["imageBase"], "0x140000000")
        self.assertEqual(layout["tlsDirectory"]["callbackCount"], 1)
        self.assertEqual(layout["tlsDirectory"]["callbacks"][0]["va"], "0x140001010")
        exception = layout["exceptionDirectory"]
        self.assertEqual(exception["runtimeFunctionCount"], 1)
        self.assertEqual(exception["runtimeFunctions"][0]["beginRva"], "0x1000")

    def test_exception_history_delta_is_bounded_and_canonical(self):
        original = self.mod.GetExceptionHistory
        calls = []

        def fake_history(after_seq=0, limit=100):
            calls.append((after_seq, limit))
            return {
                "ok": True,
                "records": [
                    {
                        "historySeq": 8,
                        "eventSeq": 80,
                        "threadId": 9,
                        "exceptionCode": "0xE0424242",
                        "chance": "first",
                        "firstChance": True,
                        "address": "0x401020",
                        "source": "debug_event",
                        "unboundedInternalField": "must-not-leak",
                    }
                ],
                "nextAfterSeq": 8,
                "hasMore": False,
            }

        self.mod.GetExceptionHistory = fake_history
        try:
            result = self.mod._oep_collect_exception_history(7)
        finally:
            self.mod.GetExceptionHistory = original
        self.assertEqual(calls, [(7, 256)])
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["firstChanceCount"], 1)
        self.assertNotIn("unboundedInternalField", result["records"][0])

    def test_sanitizer_removes_only_invalid_trailing_import_descriptors(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scylla-tail.exe"
            path.write_bytes(_pe64_with_invalid_trailing_import())
            before = self.mod._pe_import_evidence(self.mod._parse_pe_layout(str(path)))
            self.assertEqual(before["badDllNames"], ["*invalid*"])
            repaired = self.mod._sanitize_trailing_import_descriptors(str(path))
            self.assertTrue(repaired["ok"], repaired)
            self.assertTrue(repaired["changed"])
            self.assertEqual(repaired["trimmedDescriptorCount"], 1)
            after_layout = self.mod._parse_pe_layout(str(path))
            after = self.mod._pe_import_evidence(after_layout)
            self.assertEqual(after["badDllNames"], [])
            self.assertEqual(after["dllNames"], ["kernel32.dll"])
            self.assertEqual(after_layout["iatDirectory"]["size"], 16)


class OepPrologueAndRuntimeFunctionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def test_prologue_probe_rejects_arbitrary_instruction_and_accepts_stack_setup(self):
        original = self.mod.DisasmGetInstructionRange
        try:
            self.mod.DisasmGetInstructionRange = lambda *_args, **_kwargs: {
                "instructions": [
                    {"instruction": "mov rax, qword ptr ds:[rbp+8]"},
                    {"instruction": "xor ecx, ecx"},
                ]
            }
            self.assertFalse(self.mod._oep_looks_like_prologue("0x140001000"))
            self.mod.DisasmGetInstructionRange = lambda *_args, **_kwargs: {
                "instructions": [
                    {"instruction": "sub rsp, 28"},
                    {"instruction": "mov qword ptr ss:[rsp+20], rbx"},
                ]
            }
            self.assertTrue(self.mod._oep_looks_like_prologue("0x140001000"))
        finally:
            self.mod.DisasmGetInstructionRange = original

    def test_live_runtime_function_parser_uses_restored_pdata(self):
        original = self.mod._read_live_memory_exact
        blob = struct.pack("<III", 0x1000, 0x1040, 0x1800)
        self.mod._read_live_memory_exact = lambda address, size: blob
        try:
            result = self.mod._oep_live_runtime_functions(
                {
                    "baseInt": BASE,
                    "layout": {"sizeOfImage": 0x3000},
                    "exceptionDirectory": {"rva": "0x2000", "size": 12},
                }
            )
        finally:
            self.mod._read_live_memory_exact = original
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["functionCount"], 1)
        self.assertEqual(result["functions"][0]["beginRva"], 0x1000)
        self.assertEqual(result["functions"][0]["endRva"], 0x1040)


class RuntimeIatRebuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def setUp(self):
        self.original_scanner = self.mod.FindIATCandidates
        self.original_modules = self.mod.GetModuleList
        self.original_read = self.mod._read_live_memory_exact

    def tearDown(self):
        self.mod.FindIATCandidates = self.original_scanner
        self.mod.GetModuleList = self.original_modules
        self.mod._read_live_memory_exact = self.original_read

    @staticmethod
    def _targets(module, count):
        return [
            {"value": f"0x{0x70000000 + index * 16:X}", "module": module}
            for index in range(count)
        ]

    def test_selector_rejects_main_image_runs_and_chooses_dominant_external_iat(self):
        self.mod.GetModuleList = lambda: {
            "modules": [{"name": "sample.exe", "base": hex(BASE), "size": "0x4000"}]
        }
        self.mod.FindIATCandidates = lambda **_kwargs: {
            "ok": True,
            "candidateCount": 3,
            "candidates": [
                {
                    "base": hex(BASE + 0x1000),
                    "count": 44,
                    "pointerSize": 8,
                    "targets": self._targets("sample.exe", 44),
                },
                {
                    "base": hex(BASE + 0x2000),
                    "count": 16,
                    "pointerSize": 8,
                    "targets": self._targets("kernel32.dll", 16),
                },
                {
                    "base": hex(BASE + 0x3000),
                    "count": 4,
                    "pointerSize": 8,
                    "targets": self._targets("ntdll.dll", 4),
                },
            ],
        }
        self.mod._read_live_memory_exact = lambda _address, size: b"\0" * size
        selected = self.mod._oep_select_runtime_iat_candidate(BASE, 0x4000, 8)
        self.assertTrue(selected["ok"], selected)
        self.assertEqual(selected["rva"], "0x2000")
        self.assertEqual(selected["count"], 16)
        self.assertEqual(selected["size"], 17 * 8)
        self.assertEqual(selected["runnerUpCount"], 4)
        self.assertIn(
            "points_into_main_image",
            {item["reason"] for item in selected["rejected"]},
        )

    def test_selector_rejects_ambiguous_external_runs(self):
        self.mod.GetModuleList = lambda: {
            "modules": [{"name": "sample.exe", "base": hex(BASE), "size": "0x4000"}]
        }
        self.mod.FindIATCandidates = lambda **_kwargs: {
            "ok": True,
            "candidateCount": 2,
            "candidates": [
                {
                    "base": hex(BASE + 0x1000),
                    "count": 10,
                    "pointerSize": 8,
                    "targets": self._targets("kernel32.dll", 10),
                },
                {
                    "base": hex(BASE + 0x2000),
                    "count": 9,
                    "pointerSize": 8,
                    "targets": self._targets("ntdll.dll", 9),
                },
            ],
        }
        self.mod._read_live_memory_exact = lambda _address, size: b"\0" * size
        selected = self.mod._oep_select_runtime_iat_candidate(BASE, 0x4000, 8)
        self.assertFalse(selected["ok"])
        self.assertEqual(selected["reason"], "ambiguous_external_runs")

    def test_rebuilder_adds_named_import_section_and_preserves_original_iat(self):
        selection = {
            "ok": True,
            "start": hex(BASE + 0x1100),
            "rva": "0x1100",
            "size": 32,
            "count": 3,
            "pointerSize": 8,
        }
        resolution = {
            "ok": True,
            "entries": [
                {
                    "index": 0,
                    "module": "kernel32.dll",
                    "function": "ExitProcess",
                    "ordinal": 0,
                },
                {
                    "index": 1,
                    "module": "ntdll.dll",
                    "function": "RtlAllocateHeap",
                    "ordinal": 0,
                },
                {
                    "index": 2,
                    "module": "kernel32.dll",
                    "function": "GetProcAddress",
                    "ordinal": 0,
                },
            ],
            "moduleCounts": {"kernel32.dll": 2, "ntdll.dll": 1},
        }
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "raw.exe"
            target = Path(tmp) / "rebuilt.exe"
            source.write_bytes(_pe64_with_invalid_trailing_import())
            result = self.mod._rebuild_dump_imports_from_runtime_iat(
                str(source),
                str(target),
                BASE,
                selection,
                resolution,
                entrypoint=hex(BASE + 0x1000),
            )
            self.assertTrue(result["ok"], result)
            layout = self.mod._parse_pe_layout(str(target))
            evidence = self.mod._pe_import_evidence(layout)
            self.assertEqual(evidence["functionCount"], 3)
            self.assertEqual(layout["iatDirectory"]["rva"], "0x1100")
            self.assertEqual(layout["iatDirectory"]["size"], 32)
            self.assertEqual(layout["sections"][-1]["name"], ".mcpimp")
            self.assertTrue(layout["sections"][0]["writable"])


if __name__ == "__main__":
    unittest.main()
