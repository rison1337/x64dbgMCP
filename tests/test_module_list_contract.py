import importlib.util
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "x64dbg.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("x64dbg_module_list_tests", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ModuleListContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def test_empty_list_without_debuggee_is_valid_not_an_error(self):
        def fake_get(endpoint, *args, **kwargs):
            if endpoint == "GetModuleList":
                return []
            if endpoint == "Is_Debugging":
                return {"isDebugging": False}
            raise AssertionError(endpoint)

        with mock.patch.object(self.mod, "safe_get", side_effect=fake_get):
            result = self.mod.GetModuleList()

        self.assertEqual(result["count"], 0)
        self.assertEqual(result["modules"], [])
        self.assertFalse(result["ready"])
        self.assertNotIn("error", result)

    def test_transient_empty_list_retries_after_attached_launch(self):
        replies = [
            [],
            [],
            [
                {
                    "name": "fixture.exe",
                    "base": "0x140000000",
                    "size": "0x20000",
                    "entry": "0x140001000",
                    "path": r"C:\fixture.exe",
                }
            ],
        ]

        def fake_get(endpoint, *args, **kwargs):
            if endpoint == "GetModuleList":
                return replies.pop(0)
            if endpoint == "Is_Debugging":
                return {"isDebugging": True}
            raise AssertionError(endpoint)

        with mock.patch.object(self.mod, "safe_get", side_effect=fake_get), mock.patch.object(
            self.mod.time, "sleep", return_value=None
        ):
            result = self.mod.GetModuleList()

        self.assertEqual(result["count"], 1)
        self.assertEqual(result["modules"][0]["name"], "fixture.exe")
        self.assertEqual(result["attempts"], 3)

    def test_public_envelope_payload_is_normalized(self):
        payload = {
            "ok": True,
            "data": {
                "modules": [
                    {
                        "name": "fixture.exe",
                        "base": "0x400000",
                        "size": "0x10000",
                    }
                ]
            },
        }
        self.assertEqual(
            self.mod._parse_module_list_payload(payload)[0]["name"], "fixture.exe"
        )


if __name__ == "__main__":
    unittest.main()
