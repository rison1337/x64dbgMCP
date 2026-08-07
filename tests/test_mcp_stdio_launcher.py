import importlib.util
import json
import subprocess
import sys
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "src" / "mcp_stdio_launcher.py"
PROFILES = ROOT / "src" / "tool_profiles.py"


def _load_profiles():
    spec = importlib.util.spec_from_file_location(
        "x64dbg_launcher_profile_inventory_test", PROFILES
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class McpStdioLauncherTests(unittest.TestCase):
    def test_broker_initializes_and_lists_the_complete_profile_inventory(self):
        frames = [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "launcher-regression", "version": "1"},
                },
            },
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {},
            },
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        ]
        process = subprocess.Popen(
            [sys.executable, str(LAUNCHER)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert process.stdin is not None
        assert process.stdout is not None
        process.stdin.write(
            (json.dumps(frames[0], separators=(",", ":")) + "\n").encode("utf-8")
        )
        process.stdin.flush()
        initialize_response = process.stdout.readline()
        self.assertTrue(initialize_response, "launcher closed before initialize response")
        process.stdin.write(
            "".join(
                json.dumps(frame, separators=(",", ":")) + "\n"
                for frame in frames[1:]
            ).encode("utf-8")
        )
        process.stdin.flush()
        process.stdin.close()
        process.stdin = None
        stdout, stderr = process.communicate(timeout=20)
        stdout = initialize_response + stdout
        self.assertEqual(process.returncode, 0, stderr.decode("utf-8", "replace"))
        self.assertNotIn(b"Fatal Python error", stderr)
        responses = [
            json.loads(line)
            for line in stdout.decode("utf-8").splitlines()
            if line.strip()
        ]
        by_id = {item.get("id"): item for item in responses if "id" in item}
        self.assertIn("serverInfo", by_id[1]["result"])
        startup_instructions = " ".join(
            by_id[1]["result"].get("instructions", "").split()
        )
        self.assertIn("call InitDebuggee directly", startup_instructions)
        self.assertIn("Do not preflight BridgeHello", startup_instructions)
        tools = by_id[2]["result"]["tools"]
        expected = _load_profiles().known_tool_names()
        self.assertEqual({item["name"] for item in tools}, set(expected))

    def test_parallel_stdio_clients_do_not_replace_or_close_each_other(self):
        processes = []

        def send(process, payload):
            assert process.stdin is not None
            process.stdin.write(
                (json.dumps(payload, separators=(",", ":")) + "\n").encode(
                    "utf-8"
                )
            )
            process.stdin.flush()

        def receive(process, request_id):
            assert process.stdout is not None
            while True:
                line = process.stdout.readline()
                self.assertTrue(
                    line,
                    f"launcher {process.pid} closed before response {request_id}",
                )
                response = json.loads(line)
                if response.get("id") == request_id:
                    return response

        try:
            for index in range(3):
                process = subprocess.Popen(
                    [sys.executable, str(LAUNCHER)],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                processes.append(process)
                send(
                    process,
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-11-25",
                            "capabilities": {},
                            "clientInfo": {
                                "name": f"parallel-regression-{index}",
                                "version": "1",
                            },
                        },
                    },
                )
                self.assertIn("serverInfo", receive(process, 1)["result"])
                send(
                    process,
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/initialized",
                        "params": {},
                    },
                )

            for round_index in range(2):
                request_id = round_index + 10
                for process in processes:
                    self.assertIsNone(
                        process.poll(),
                        f"parallel launcher {process.pid} exited prematurely",
                    )
                    send(
                        process,
                        {
                            "jsonrpc": "2.0",
                            "id": request_id,
                            "method": "tools/list",
                            "params": {},
                        },
                    )
                    response = receive(process, request_id)
                    self.assertTrue(response["result"]["tools"])
        finally:
            for process in processes:
                if process.stdin is not None:
                    try:
                        process.stdin.close()
                    except OSError:
                        pass
                    process.stdin = None
                try:
                    _, stderr = process.communicate(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    _, stderr = process.communicate(timeout=5)
                self.assertEqual(
                    process.returncode,
                    0,
                    stderr.decode("utf-8", errors="replace"),
                )

    def test_early_child_exit_does_not_leave_a_buffered_stdin_daemon(self):
        # Keep the broker's stdin pipe deliberately open while its child exits.
        # The old read1()-based daemon survived into CPython finalization and
        # raised _enter_buffered_busy / a Windows python.exe crash dialog.
        wrapper = r'''
import importlib.util
import pathlib
import subprocess
import sys

path = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("launcher_failure_regression", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

def spawn_failure():
    return subprocess.Popen(
        [sys.executable, "-c", "import sys; print('child-failure-marker', file=sys.stderr); sys.exit(7)"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=None,
        bufsize=0,
    )

module._spawn_isolated_child = spawn_failure
raise SystemExit(module._run_broker())
'''
        started = time.monotonic()
        process = subprocess.Popen(
            [sys.executable, "-c", wrapper, str(LAUNCHER)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            return_code = process.wait(timeout=10)
            stdout = process.stdout.read()
            stderr = process.stderr.read()
        finally:
            if process.stdin is not None:
                process.stdin.close()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()

        self.assertEqual(return_code, 7, stderr.decode("utf-8", "replace"))
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(stdout, b"")
        self.assertIn(b"child-failure-marker", stderr)
        self.assertNotIn(b"Fatal Python error", stderr)
        self.assertNotIn(b"_enter_buffered_busy", stderr)


if __name__ == "__main__":
    unittest.main()
