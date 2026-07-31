import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "x64dbg.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("x64dbg_payload_identity_tests", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _minimal_disk_pe64(entry_rva=0x1000):
    data = bytearray(0x800)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x84, 0x8664)
    struct.pack_into("<H", data, 0x86, 2)
    struct.pack_into("<H", data, 0x94, 0xF0)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, entry_rva)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<I", data, optional + 32, 0x1000)
    struct.pack_into("<I", data, optional + 36, 0x200)
    struct.pack_into("<I", data, optional + 56, 0x3000)
    struct.pack_into("<I", data, optional + 60, 0x400)
    struct.pack_into("<I", data, optional + 108, 16)
    section_table = optional + 0xF0
    data[section_table : section_table + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section_table + 8, 0x180, 0x1000, 0x200, 0x400)
    struct.pack_into("<I", data, section_table + 36, 0x60000020)
    second = section_table + 40
    data[second : second + 8] = b".data\0\0\0"
    struct.pack_into("<IIII", data, second + 8, 0x100, 0x2000, 0x200, 0x600)
    struct.pack_into("<I", data, second + 36, 0xC0000040)
    data[0x400:0x600] = bytes((index * 7 + 3) & 0xFF for index in range(0x200))
    return bytes(data)


class _ClosurePatch:
    def __init__(self, function, **replacements):
        self.function = function
        cells = dict(zip(function.__code__.co_freevars, function.__closure__ or ()))
        self.cells = {name: cells[name] for name in replacements}
        self.replacements = replacements
        self.original = {}

    def __enter__(self):
        for name, cell in self.cells.items():
            self.original[name] = cell.cell_contents
            cell.cell_contents = self.replacements[name]
        return self.function

    def __exit__(self, *_exc):
        for name, cell in self.cells.items():
            cell.cell_contents = self.original[name]


class ProcessPayloadIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def _inspect(self, disk_image, runtime_header, *, private, code_matches):
        base = 0x140000000
        with tempfile.TemporaryDirectory() as tmp:
            disk_path = Path(tmp) / "host.exe"
            disk_path.write_bytes(disk_image)

            def read_exact(address, size, _chunk_size):
                offset = address - base
                source = runtime_header + b"\0" * 0x10000
                return source[offset : offset + size]

            identity = {
                "schema": "memory-pe-template-identity-v1",
                "verified": code_matches,
                "runtimeBase": hex(base),
                "templateSha256": "A" * 64,
                "architecture": "x64",
                "comparedBytes": 960,
                "equalBytes": 960 if code_matches else 12,
                "similarity": 1.0 if code_matches else 0.0125,
                "readFailures": 0,
                "sections": [],
            }
            candidate = {
                "base": hex(base),
                "manualMapCandidate": private,
                "imageKind": "manual-map" if private else "mapped-image",
                "provenance": {"private": private},
            }
            replacements = {
                "GetDebugStateLean": lambda: {
                    "pid": 4242,
                    "debuggeePath": str(disk_path),
                },
                "_resolve_main_module": lambda: {
                    "name": "host.exe",
                    "path": str(disk_path),
                    "base": hex(base),
                    "size": "0x3000",
                },
                "_read_memory_exact": read_exact,
                "_score_template_memory_identity": lambda *_args, **_kwargs: dict(identity),
                "GetMemoryMap": lambda: {
                    "ok": True,
                    "pages": [
                        {
                            "base": hex(base),
                            "size": "0x3000",
                            "protect": "ER",
                            "type": "PRV" if private else "IMG",
                            "info": "payload" if private else str(disk_path),
                        }
                    ],
                },
                "ScanMemoryForPEImages": lambda **_kwargs: {
                    "ok": True,
                    "schema": "memory-pe-scan-v2",
                    "candidateCount": 1,
                    "readFailureCount": 0,
                    "truncated": False,
                    "candidates": [candidate],
                },
            }
            with _ClosurePatch(self.mod.InspectProcessPayload, **replacements):
                return self.mod.InspectProcessPayload()

    def test_normal_main_image_identity_is_not_hollowed(self):
        image = _minimal_disk_pe64()
        result = self._inspect(image, image, private=False, code_matches=True)
        self.assertTrue(result["ok"], result)
        self.assertFalse(result["likelyHollowed"], result)
        self.assertEqual(result["signals"], [])
        self.assertEqual(result["confidence"], "low")
        self.assertEqual(result["selection"]["selected"]["payloadScore"], 100)

    def test_replaced_private_image_is_hollowed_with_pid_bound_evidence(self):
        disk = _minimal_disk_pe64(entry_rva=0x1000)
        payload = _minimal_disk_pe64(entry_rva=0x1800)
        result = self._inspect(disk, payload, private=True, code_matches=False)
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["likelyHollowed"], result)
        self.assertEqual(result["pid"], 4242)
        self.assertEqual(result["confidence"], "high")
        self.assertIn("entry-rva-mismatch", result["signals"])
        self.assertIn("immutable-code-mismatch", result["signals"])
        self.assertIn("main-image-base-is-private", result["signals"])
        self.assertIn("header-identity-mismatch", result["signals"])
        self.assertEqual(result["selection"]["selected"]["payloadScore"], 155)

    def test_follow_child_strict_mode_preserves_attach_evidence_on_rejection(self):
        function = self.mod.FollowChildProcess
        replacements = {
            "WaitForChildProcess": lambda **_kwargs: {
                "ok": True,
                "candidate": {"pid": 7331, "exe": "host.exe"},
            },
            "GetProcessDebugStatus": lambda **_kwargs: {"underDebugger": False},
            "AttachToProcess": lambda **_kwargs: {"ok": True, "pid": 7331},
            "_get_binding_snapshot": lambda: {"matches": True, "pid": 7331},
            "InspectProcessPayload": lambda: {
                "ok": True,
                "pid": 7331,
                "likelyHollowed": False,
                "signals": [],
            },
        }
        with _ClosurePatch(function, **replacements):
            result = function(require_hollowed=True)
        self.assertFalse(result["ok"], result)
        self.assertEqual(result["errorCode"], "HOLLOWING_NOT_CONFIRMED")
        self.assertTrue(result["attach"]["ok"])
        self.assertEqual(result["payloadIdentity"]["pid"], 7331)

    def test_follow_child_accepts_confirmed_payload(self):
        function = self.mod.FollowChildProcess
        replacements = {
            "WaitForChildProcess": lambda **_kwargs: {
                "ok": True,
                "candidate": {"pid": 7332, "exe": "host.exe"},
            },
            "GetProcessDebugStatus": lambda **_kwargs: {"underDebugger": False},
            "AttachToProcess": lambda **_kwargs: {"ok": True, "pid": 7332},
            "_get_binding_snapshot": lambda: {"matches": True, "pid": 7332},
            "InspectProcessPayload": lambda: {
                "ok": True,
                "pid": 7332,
                "likelyHollowed": True,
                "signals": ["immutable-code-mismatch", "main-image-base-is-private"],
            },
        }
        with _ClosurePatch(function, **replacements):
            result = function(require_hollowed=True)
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["hollowingConfirmed"])


if __name__ == "__main__":
    unittest.main()
