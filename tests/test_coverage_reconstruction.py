import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "coverage_core.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("coverage_core_tests", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class CoverageReconstructionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    @staticmethod
    def event(
        seq,
        rva,
        *,
        size=1,
        raw="90",
        instruction="nop",
        thread=1,
        branch=False,
        call=False,
        ret=False,
        target=0,
        **extra,
    ):
        return {
            "seq": seq,
            "threadId": thread,
            "ip": hex(0x140000000 + rva),
            "rva": hex(rva),
            "bytes": raw,
            "instruction": instruction,
            "instructionSize": size,
            "branch": branch,
            "call": call,
            "isReturn": ret,
            "branchTarget": hex(0x140000000 + target) if target else "0x0",
            **extra,
        }

    def reconstruct(self, events):
        return self.mod.reconstruct_basic_block_coverage(
            events, 0x140000000, 0x10000, "a" * 64, 5000
        )

    def test_loop_counts_block_executions_not_instructions(self):
        events = [
            self.event(1, 0x1000),
            self.event(
                2,
                0x1001,
                size=2,
                raw="75fd",
                instruction="jne 0x140001000",
                branch=True,
                target=0x1000,
            ),
            self.event(3, 0x1000),
            self.event(
                4,
                0x1001,
                size=2,
                raw="75fd",
                instruction="jne 0x140001000",
                branch=True,
                target=0x1000,
            ),
            self.event(5, 0x1003, raw="c3", instruction="ret", ret=True),
        ]
        result = self.reconstruct(events)
        loop = next(item for item in result["blocks"] if item["startRva"] == "0x1000")
        self.assertEqual(loop["hits"], 2)
        self.assertEqual(loop["instructionCount"], 2)
        self.assertEqual(loop["instructionHits"], 4)
        kinds = {item["kind"]: item["hits"] for item in result["edges"]}
        self.assertEqual(kinds["taken"], 1)
        self.assertEqual(kinds["not-taken"], 1)

    def test_calls_returns_switch_and_exception_edges_are_typed(self):
        events = [
            self.event(
                1,
                0x2000,
                size=2,
                raw="ffd0",
                instruction="call rax",
                branch=True,
                call=True,
                target=0x2100,
            ),
            self.event(2, 0x2100, raw="c3", instruction="ret", ret=True),
            self.event(
                3,
                0x2002,
                size=6,
                raw="ff248578563412",
                instruction="jmp qword ptr [rax*8+0x12345678]",
                branch=True,
                target=0x2200,
            ),
            self.event(4, 0x2200, exceptionTransition=True, exceptionCode="0xE06D7363"),
            self.event(5, 0x2300, raw="c3", instruction="ret", ret=True),
        ]
        result = self.reconstruct(events)
        kinds = [item["kind"] for item in result["edges"]]
        self.assertIn("indirect-call", kinds)
        self.assertIn("return", kinds)
        self.assertIn("exception", kinds)
        self.assertGreaterEqual(result["indirectEdgeCount"], 1)
        self.assertGreaterEqual(result["exceptionEdgeCount"], 1)

    def test_same_rva_changed_bytes_create_distinct_versions(self):
        events = [
            self.event(
                1,
                0x3000,
                size=2,
                raw="eb00",
                instruction="jmp 0x140003002",
                branch=True,
                target=0x3002,
            ),
            self.event(
                2,
                0x3002,
                size=2,
                raw="ebfc",
                instruction="jmp 0x140003000",
                branch=True,
                target=0x3000,
            ),
            self.event(
                3,
                0x3000,
                size=2,
                raw="9090",
                instruction="nop; nop",
                branch=False,
            ),
            self.event(4, 0x3002, raw="c3", instruction="ret", ret=True),
        ]
        result = self.reconstruct(events)
        versions = [
            item for item in result["blocks"] if item["startRva"] == "0x3000"
        ]
        self.assertEqual(len(versions), 2)
        self.assertTrue(all(item["selfModified"] for item in versions))
        self.assertEqual({item["codeVersion"] for item in versions}, {1, 2})
        self.assertEqual(result["selfModifyingRvas"], ["0x3000"])
        self.assertEqual(result["versionedBlockCount"], 2)
        self.assertGreater(result["coveredInstructionVersions"], result["coveredInstructions"])

    def test_interleaved_threads_do_not_create_cross_thread_edges(self):
        events = [
            self.event(1, 0x4000, thread=1),
            self.event(2, 0x5000, thread=2),
            self.event(3, 0x4001, thread=1, raw="c3", instruction="ret", ret=True),
            self.event(4, 0x5001, thread=2, raw="c3", instruction="ret", ret=True),
        ]
        result = self.reconstruct(events)
        self.assertEqual(result["threadCount"], 2)
        self.assertEqual(result["edgeCount"], 0)
        self.assertEqual(result["blockCount"], 2)

    def test_zero_valued_serialized_exception_fields_are_not_transitions(self):
        result = self.reconstruct(
            [
                self.event(1, 0x5100, exceptionCode="0x0", exceptionTransition=False),
                self.event(
                    2,
                    0x5101,
                    raw="c3",
                    instruction="ret",
                    ret=True,
                    exceptionCode="0x0",
                    exceptionTransition=False,
                ),
            ]
        )
        self.assertEqual(result["exceptionEdgeCount"], 0)
        self.assertEqual(result["blockCount"], 1)

    def test_exception_marker_crosses_out_of_module_dispatcher(self):
        dispatcher = self.event(
            2,
            0x9000,
            thread=1,
            instruction="cld",
            raw="fc",
            exceptionTransition=True,
            exceptionCode="0xE0424242",
        )
        dispatcher["ip"] = hex(0x7FFCD99C40B0)
        dispatcher["rva"] = "0x1640b0"
        result = self.reconstruct(
            [
                self.event(
                    1,
                    0x2000,
                    size=5,
                    raw="e800000000",
                    instruction="call 0x140002100",
                    branch=True,
                    call=True,
                    target=0x2100,
                ),
                dispatcher,
                self.event(3, 0x2300, raw="c3", instruction="ret", ret=True),
            ]
        )
        self.assertEqual(result["exceptionEdgeCount"], 1)
        self.assertIn("exception", {item["kind"] for item in result["edges"]})

    def test_limit_never_returns_dangling_edges(self):
        events = [
            self.event(1, 0x6000, raw="eb00", instruction="jmp 0x140006002", branch=True, target=0x6002),
            self.event(2, 0x6002, raw="eb00", instruction="jmp 0x140006004", branch=True, target=0x6004),
            self.event(3, 0x6004, raw="c3", instruction="ret", ret=True),
        ]
        result = self.mod.reconstruct_basic_block_coverage(
            events, 0x140000000, 0x10000, "a" * 64, 1
        )
        keys = {item["stableKey"] for item in result["blocks"]}
        self.assertTrue(result["truncated"])
        self.assertTrue(
            all(item["from"] in keys and item["to"] in keys for item in result["edges"])
        )


if __name__ == "__main__":
    unittest.main()
