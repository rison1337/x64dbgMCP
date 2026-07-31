import hashlib
import importlib.util
import json
import struct
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "x64dbg.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("x64dbg_memory_pe_tests", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _minimal_pe64(size=0x3000):
    data = bytearray(size)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x84, 0x8664)
    struct.pack_into("<H", data, 0x86, 2)
    struct.pack_into("<H", data, 0x94, 0xF0)
    struct.pack_into("<H", data, 0x96, 0x22)
    optional = 0x80 + 24
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 0x1234)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<I", data, optional + 32, 0x1000)
    struct.pack_into("<I", data, optional + 36, 0x200)
    struct.pack_into("<I", data, optional + 56, 0x3000)
    struct.pack_into("<I", data, optional + 60, 0x400)
    struct.pack_into("<I", data, optional + 108, 16)
    struct.pack_into("<II", data, optional + 112 + 5 * 8, 0x2000, 12)
    section_table = optional + 0xF0
    data[section_table : section_table + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section_table + 8, 0x180, 0x1000, 0x200, 0x400)
    struct.pack_into("<I", data, section_table + 36, 0x60000020)
    second = section_table + 40
    data[second : second + 8] = b".data\0\0\0"
    struct.pack_into("<IIII", data, second + 8, 0x100, 0x2000, 0x200, 0x600)
    struct.pack_into("<I", data, second + 36, 0xC0000040)
    for index in range(0x180):
        data[0x1000 + index] = (index * 3 + 1) & 0xFF
    for index in range(0x100):
        data[0x2000 + index] = (index * 5 + 7) & 0xFF
    struct.pack_into("<IIHH", data, 0x2000, 0x1000, 12, (10 << 12) | 0x20, 0)
    struct.pack_into("<Q", data, 0x1020, 0x140002222)
    return bytes(data)


def _minimal_disk_pe64():
    memory = _minimal_pe64()
    disk = bytearray(0x800)
    disk[:0x400] = memory[:0x400]
    disk[0x400:0x600] = memory[0x1000:0x1200]
    disk[0x600:0x800] = memory[0x2000:0x2200]
    return bytes(disk)


class MemoryPeDiscoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def setUp(self):
        self.original_safe_get = self.mod.safe_get
        self.base = 0x140000000
        self.image = _minimal_pe64()

        def fake_safe_get(endpoint, params=None, **_kwargs):
            if endpoint == "MemoryMap":
                return {
                    "ok": True,
                    "pages": [
                        {
                            "base": hex(self.base),
                            "size": hex(len(self.image)),
                            "protect": "ERW",
                            "type": "PRV",
                            "info": "manual-map candidate",
                        }
                    ],
                }
            if endpoint == "Memory/ReadRange":
                params = params or {}
                address = int(str(params.get("addr") or "0"), 0)
                size = int(params.get("size") or 0)
                offset = address - self.base
                if offset < 0 or offset + size > len(self.image):
                    return {"ok": False, "error": "out of range"}
                return {
                    "ok": True,
                    "addr": hex(address),
                    "sizeRead": size,
                    "hex": self.image[offset : offset + size].hex(),
                }
            raise AssertionError(f"unexpected endpoint: {endpoint}")

        self.mod.safe_get = fake_safe_get

    def tearDown(self):
        self.mod.safe_get = self.original_safe_get

    def test_scan_finds_private_memory_pe_with_provenance(self):
        result = self.mod.ScanMemoryForPEImages()
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["candidateCount"], 1)
        candidate = result["candidates"][0]
        self.assertEqual(candidate["base"], hex(self.base).upper().replace("X", "x"))
        self.assertEqual(candidate["architecture"], "x64")
        self.assertEqual(candidate["entryRva"], "0x1234")
        self.assertEqual(candidate["sizeOfImage"], 0x3000)
        self.assertTrue(candidate["provenance"]["private"])
        self.assertEqual(candidate["headerState"], "intact")
        self.assertTrue(candidate["manualMapCandidate"])

    def test_scan_finds_embedded_reflective_pe_header(self):
        offset = 0x600
        self.image = b"\xA5" * offset + self.image
        result = self.mod.ScanMemoryForPEImages(include_embedded=True)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["candidateCount"], 1)
        candidate = result["candidates"][0]
        self.assertEqual(candidate["base"], f"0x{self.base + offset:X}")
        self.assertEqual(candidate["embeddedOffset"], offset)
        self.assertEqual(candidate["imageKind"], "embedded-reflective")
        self.assertEqual(result["schema"], "memory-pe-scan-v2")

    def test_embedded_disk_staging_image_is_extracted_exactly(self):
        offset = 0x600
        staged = _minimal_disk_pe64()
        self.image = b"\xA5" * offset + staged + b"\0" * 0x1000
        scan = self.mod.ScanMemoryForPEImages(include_embedded=True)
        self.assertTrue(scan["ok"], scan)
        candidate = scan["candidates"][0]
        self.assertEqual(candidate["suggestedSourceLayout"], "disk")
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "embedded-extracted.exe"
            result = self.mod.DumpPeFromMemory(
                candidate["base"],
                str(output),
                source_layout="auto",
            )
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["sourceLayout"]["resolved"], "disk")
            self.assertEqual(result["rawExtent"], len(staged))
            self.assertEqual(output.read_bytes(), staged)

    def test_scan_template_finds_destroyed_header_manual_map(self):
        template = self.image
        destroyed = bytearray(self.image)
        destroyed[:0x400] = b"\0" * 0x400
        destroyed[0x2050] = 0xA5
        self.image = bytes(destroyed)
        with tempfile.TemporaryDirectory() as tmp:
            template_path = Path(tmp) / "template.exe"
            template_path.write_bytes(template)
            result = self.mod.ScanMemoryForPEImages(
                header_template_path=str(template_path)
            )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["candidateCount"], 1)
        candidate = result["candidates"][0]
        self.assertEqual(candidate["base"], f"0x{self.base:X}")
        self.assertEqual(candidate["headerState"], "destroyed-or-headerless")
        self.assertEqual(candidate["imageKind"], "template-matched-manual-map")
        self.assertTrue(candidate["templateIdentity"]["verified"])
        self.assertGreaterEqual(candidate["templateIdentity"]["comparedBytes"], 64)

    def test_manifest_hashes_and_writes_atomically(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "memory-map.json"
            result = self.mod.DumpMemoryMapManifest(
                str(path), include_hashes=True, hash_bytes_per_region=512
            )
            self.assertTrue(result["ok"], result)
            self.assertTrue(result["output"]["written"])
            payload = json.loads(path.read_text(encoding="utf-8"))
            region = payload["regions"][0]
            self.assertEqual(
                region["sampleSha256"],
                hashlib.sha256(self.image[:512]).hexdigest().upper(),
            )
            self.assertEqual(payload["manifestSha256"], result["manifestSha256"])

    def test_raw_dump_is_exact_and_rejects_accidental_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "raw.bin"
            result = self.mod.DumpModuleRaw(
                hex(self.base), len(self.image), str(path), chunk_size=0x400
            )
            self.assertTrue(result["ok"], result)
            self.assertEqual(path.read_bytes(), self.image)
            self.assertEqual(
                result["sha256"], hashlib.sha256(self.image).hexdigest().upper()
            )
            second = self.mod.DumpModuleRaw(
                hex(self.base), len(self.image), str(path)
            )
            self.assertEqual(second["errorCode"], "OUTPUT_EXISTS")

    def test_raw_dump_removes_partial_artifact_after_read_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "partial.bin"
            result = self.mod.DumpModuleRaw(
                hex(self.base), len(self.image) + 1, str(path), chunk_size=0x400
            )
            self.assertFalse(result["ok"])
            self.assertEqual(result["errorCode"], "RAW_DUMP_FAILED")
            self.assertFalse(path.exists())
            self.assertTrue(result["partialArtifactRemoved"])

    def test_pe_reconstruction_maps_virtual_sections_to_disk_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "reconstructed.exe"
            result = self.mod.DumpPeFromMemory(hex(self.base), str(path))
            self.assertTrue(result["ok"], result)
            self.assertTrue(result["verification"]["structural"])
            self.assertTrue(result["reloadable"])
            self.assertEqual(result["architecture"], "x64")
            self.assertEqual(len(result["sections"]), 2)
            file_data = path.read_bytes()
            text_section = next(item for item in result["sections"] if item["name"] == ".text")
            raw_pointer = int(text_section["rawPointer"])
            self.assertEqual(
                file_data[raw_pointer : raw_pointer + 0x180],
                self.image[0x1000:0x1180],
            )

    def test_pe_reconstruction_uses_template_for_destroyed_headers(self):
        template = self.image
        destroyed = bytearray(self.image)
        destroyed[:0x400] = b"\0" * 0x400
        self.image = bytes(destroyed)
        with tempfile.TemporaryDirectory() as tmp:
            template_path = Path(tmp) / "template.exe"
            output_path = Path(tmp) / "headerless-reconstructed.exe"
            template_path.write_bytes(template)
            result = self.mod.DumpPeFromMemory(
                hex(self.base),
                str(output_path),
                header_template_path=str(template_path),
            )
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["sourceMode"], "template")
            self.assertTrue(result["templateIdentity"]["verified"])
            self.assertEqual(output_path.read_bytes()[:2], b"MZ")
            data_section = next(
                item for item in result["sections"] if item["name"] == ".data"
            )
            self.assertEqual(data_section["source"], "template-mutable-reset")
            self.assertEqual(
                output_path.read_bytes()[int(data_section["rawPointer"]) + 0x50],
                template[0x2050],
            )

    def test_pe_reconstruction_rejects_wrong_header_template(self):
        destroyed = bytearray(self.image)
        destroyed[:0x400] = b"\0" * 0x400
        self.image = bytes(destroyed)
        wrong_template = bytearray(_minimal_pe64())
        wrong_template[0x1000:0x1180] = b"\xF4" * 0x180
        with tempfile.TemporaryDirectory() as tmp:
            template_path = Path(tmp) / "wrong-template.exe"
            output_path = Path(tmp) / "must-not-exist.exe"
            template_path.write_bytes(wrong_template)
            result = self.mod.DumpPeFromMemory(
                hex(self.base),
                str(output_path),
                header_template_path=str(template_path),
            )
            self.assertFalse(result["ok"], result)
            self.assertEqual(result["errorCode"], "PE_TEMPLATE_MISMATCH")
            self.assertFalse(output_path.exists())
            self.assertFalse(result["templateIdentity"]["verified"])

    def test_pe_reconstruction_applies_bounded_entry_override(self):
        template = self.image
        destroyed = bytearray(self.image)
        destroyed[:0x400] = b"\0" * 0x400
        self.image = bytes(destroyed)
        with tempfile.TemporaryDirectory() as tmp:
            template_path = Path(tmp) / "template.exe"
            output_path = Path(tmp) / "entry-override.exe"
            template_path.write_bytes(template)
            result = self.mod.DumpPeFromMemory(
                hex(self.base),
                str(output_path),
                header_template_path=str(template_path),
                entry_rva_override="0x1100",
            )
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["entryRva"], "0x1100")
            data = output_path.read_bytes()
            self.assertEqual(struct.unpack_from("<I", data, 0x98 + 16)[0], 0x1100)
            rejected = self.mod.DumpPeFromMemory(
                hex(self.base),
                str(Path(tmp) / "bad-entry.exe"),
                header_template_path=str(template_path),
                entry_rva_override="0x2000",
            )
            self.assertEqual(rejected["errorCode"], "INVALID_ENTRY_RVA")

    def test_pe_reconstruction_reverses_dir64_aslr_relocations(self):
        self.base = 0x150000000
        relocated = bytearray(self.image)
        struct.pack_into("<Q", relocated, 0x1020, self.base + 0x2222)
        self.image = bytes(relocated)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "reloc-reconstructed.exe"
            result = self.mod.DumpPeFromMemory(hex(self.base), str(path))
            self.assertTrue(result["ok"], result)
            self.assertTrue(result["relocations"]["required"])
            self.assertTrue(result["relocations"]["complete"])
            self.assertEqual(result["relocations"]["patched"], 1)
            text_section = next(item for item in result["sections"] if item["name"] == ".text")
            raw_pointer = int(text_section["rawPointer"])
            restored = struct.unpack_from("<Q", path.read_bytes(), raw_pointer + 0x20)[0]
            self.assertEqual(restored, 0x140002222)

    def test_iat_candidate_scan_groups_contiguous_module_pointers(self):
        original = self.mod.safe_get
        scan_base = 0x600000
        target_base = 0x70000000
        pointer_data = b"".join(
            value.to_bytes(8, "little")
            for value in (target_base + 0x100, target_base + 0x200, target_base + 0x300)
        ) + b"\0" * 8

        def fake_safe_get(endpoint, params=None, **_kwargs):
            if endpoint == "GetModuleList":
                return {
                    "modules": [
                        {"name": "kernel32.dll", "base": hex(target_base), "size": "0x10000"}
                    ]
                }
            if endpoint == "Memory/ReadRange":
                params = params or {}
                address = int(str(params.get("addr") or "0"), 0)
                size = int(params.get("size") or 0)
                if address != scan_base or size != len(pointer_data):
                    return {"ok": False, "error": "unexpected range"}
                return {"ok": True, "hex": pointer_data.hex()}
            raise AssertionError(endpoint)

        self.mod.safe_get = fake_safe_get
        try:
            result = self.mod.FindIATCandidates(
                hex(scan_base), len(pointer_data), pointer_size=8, min_entries=3
            )
        finally:
            self.mod.safe_get = original
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["candidateCount"], 1)
        self.assertEqual(result["candidates"][0]["count"], 3)
        self.assertEqual(result["candidates"][0]["targets"][1]["rva"], "0x200")

    def test_validate_dump_reports_structural_result_without_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "validate.exe"
            path.write_bytes(self.image)
            result = self.mod.ValidateDump(str(path), run_isolated=False)
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["architecture"], "x64")
            self.assertFalse(result["execution"]["ran"])

    def test_validate_dump_rejects_unknown_network_policy_before_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "validate-policy.exe"
            path.write_bytes(self.image)
            result = self.mod.ValidateDump(
                str(path), run_isolated=True, network_policy="firewall"
            )
            self.assertFalse(result["ok"])
            self.assertEqual(result["errorCode"], "INVALID_ARGUMENT")

    def test_dump_on_event_reports_supported_event_vocabulary(self):
        result = self.mod.DumpOnEvent("not-an-event", "ignored.exe")
        self.assertFalse(result["ok"])
        self.assertEqual(result["errorCode"], "UNSUPPORTED_EVENT")
        self.assertIn("execute_after_write", result["supported"])


if __name__ == "__main__":
    unittest.main()
