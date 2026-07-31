import copy
import unittest

from tools.managed_ida_coordinator import build_managed_sync_plan


SHA = "A" * 64


def _document(native="0x7FFC00001000", base="0x140000000"):
    method = {
        "metadataToken": "0x06000001",
        "name": "ManagedWork",
        "signature": "Fixture.ManagedWork(Int32)",
        "declaringType": "Fixture",
        "compilationType": "Jit",
        "module": r"D:\fixture\managed.exe",
        "nativeCode": native,
        "moduleImageBase": base,
        "hotCold": {"hotStart": native, "hotSize": 32, "coldStart": "0x0", "coldSize": 0},
        "ilToNativeMap": [],
    }
    return {
        "schema": "managed-runtime-evidence-v1",
        "version": 1,
        "artifactSha256": "B" * 64,
        "imageSha256": SHA,
        "session": {
            "sessionId": "session",
            "pid": 1234,
            "debuggerArch": "x64",
            "imageSha256": SHA,
        },
        "capture": {
            "process": {"architecture": "X64", "imagePath": r"D:\fixture\managed.exe", "pid": 1234},
            "runtimes": [
                {
                    "appDomains": [
                        {
                            "modules": [
                                {
                                    "name": r"D:\fixture\managed.exe",
                                    "imageBase": base,
                                    "isDynamic": False,
                                    "isPeFile": True,
                                    "metadataAddress": "0x2000",
                                    "metadataLength": 64,
                                },
                                {
                                    "name": "dynamic://fixture",
                                    "imageBase": "0x0",
                                    "isDynamic": True,
                                    "isPeFile": False,
                                },
                            ]
                        }
                    ],
                    "methods": [method],
                }
            ],
        },
    }


class ManagedIdaCoordinatorTests(unittest.TestCase):
    def test_jit_outside_image_is_preserved_as_unmapped(self):
        plan = build_managed_sync_plan(
            _document(),
            {"sha256": SHA, "arch": "x64", "imageBase": "0x140000000", "imageSize": "0x2000"},
        )
        self.assertEqual(plan["actionCount"], 0)
        self.assertEqual(plan["unmappedMethods"][0]["reason"], "jit_code_outside_image")
        self.assertEqual(len(plan["dynamicModules"]), 1)
        self.assertEqual(len(plan["idempotencyKey"]), 64)

    def test_in_image_mapping_emits_only_bounded_comment_action(self):
        document = _document(native="0x140001234")
        plan = build_managed_sync_plan(
            document,
            {"sha256": SHA, "arch": "x64", "imageBase": "0x140000000", "imageSize": "0x4000"},
        )
        self.assertEqual(plan["actionCount"], 1)
        self.assertEqual(plan["actions"][0]["source"]["rva"], "0x1234")
        self.assertEqual(plan["mappedMethods"][0]["metadataToken"], "0x06000001")

    def test_identity_mismatch_fails_closed(self):
        document = _document()
        with self.assertRaises(ValueError):
            build_managed_sync_plan(
                document,
                {"sha256": "C" * 64, "arch": "x64", "imageBase": "0x140000000", "imageSize": "0x4000"},
            )

    def test_duplicate_stack_and_runtime_methods_are_deterministic(self):
        document = _document(native="0x140001234")
        duplicate = copy.deepcopy(document["capture"]["runtimes"][0]["methods"][0])
        document["capture"]["threads"] = [{"frames": [{"method": duplicate}]}]
        left = build_managed_sync_plan(
            document,
            {"sha256": SHA, "arch": "x64", "imageBase": "0x140000000", "imageSize": "0x4000"},
        )
        right = build_managed_sync_plan(
            document,
            {"sha256": SHA, "arch": "x64", "imageBase": "0x140000000", "imageSize": "0x4000"},
        )
        self.assertEqual(left["idempotencyKey"], right["idempotencyKey"])
        self.assertEqual(len(left["mappedMethods"]), 1)


if __name__ == "__main__":
    unittest.main()
