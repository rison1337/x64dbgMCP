import importlib.util
import json
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "tools" / "run_child_broker_matrix.py"


def _load_runner():
    spec = importlib.util.spec_from_file_location("child_broker_runner_contract", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ChildBrokerRunnerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_runner()

    def test_launch_id_and_exit_code_extract_nested_payloads(self):
        payload = {"init": {"initResult": {"launchId": "launch-1"}}}
        self.assertEqual(self.mod._launch_id(payload), "launch-1")
        self.assertEqual(self.mod._exit_code({"state": {"exitCode": -1}}), 0xFFFFFFFF)

    def test_session_summary_is_bounded_and_phase_counts_are_explicit(self):
        inventory = {
            "sessions": [
                {
                    "sessionRef": "ref",
                    "bridgeInstanceId": "bridge",
                    "debugger": {"pid": 10, "processStartTime100ns": 20, "architecture": "x64"},
                    "childBroker": {"policy": "attach-all", "brokerId": "b"},
                    "childBrokerState": {
                        "broker": {"pendingHandoffCount": 0},
                        "children": [
                            {
                                "pid": 11,
                                "phase": "attached_running",
                                "token": "must-not-leak",
                                "identityVerified": True,
                            }
                        ],
                    },
                }
            ],
            "errors": [],
        }
        summary = self.mod._session_summary(inventory)
        self.assertEqual(summary["phaseCounts"], {"attached_running": 1})
        self.assertNotIn("must-not-leak", json.dumps(summary))
        self.assertEqual(summary["sessions"][0]["brokerState"]["children"][0]["pid"], 11)


if __name__ == "__main__":
    unittest.main()
