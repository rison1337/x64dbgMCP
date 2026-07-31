"""Smoke-test independent MCP stdio clients against a packaged launcher."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any


def _write_message(process: subprocess.Popen[str], message: dict[str, Any]) -> None:
    assert process.stdin is not None
    process.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
    process.stdin.flush()


def _read_response(process: subprocess.Popen[str], request_id: int) -> dict[str, Any]:
    assert process.stdout is not None
    while True:
        line = process.stdout.readline()
        if not line:
            stderr = process.stderr.read() if process.stderr is not None else ""
            raise RuntimeError(
                f"MCP transport closed before response {request_id}: {stderr.strip()}"
            )
        response = json.loads(line)
        if response.get("id") == request_id:
            return response


def _exercise_client(launcher: Path, calls: int) -> None:
    process = subprocess.Popen(
        [sys.executable, "-u", str(launcher)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    try:
        _write_message(
            process,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "release-smoke", "version": "1"},
                },
            },
        )
        initialized = _read_response(process, 1)
        if initialized.get("error"):
            raise RuntimeError(f"initialize failed: {initialized['error']}")
        _write_message(
            process,
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {},
            },
        )
        for offset in range(calls):
            request_id = offset + 2
            _write_message(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": "tools/list",
                    "params": {},
                },
            )
            response = _read_response(process, request_id)
            tools = response.get("result", {}).get("tools")
            if response.get("error") or not isinstance(tools, list) or not tools:
                raise RuntimeError(f"tools/list failed: {response}")
    finally:
        if process.stdin is not None:
            process.stdin.close()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=10)
        if process.returncode not in (0, None):
            stderr = process.stderr.read() if process.stderr is not None else ""
            raise RuntimeError(
                f"launcher exited with {process.returncode}: {stderr.strip()}"
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--launcher", type=Path, required=True)
    parser.add_argument("--clients", type=int, default=3)
    parser.add_argument("--calls", type=int, default=3)
    args = parser.parse_args()
    if not args.launcher.is_file():
        parser.error(f"launcher does not exist: {args.launcher}")
    if args.clients < 2 or args.calls < 1:
        parser.error("clients must be >= 2 and calls must be >= 1")

    errors: list[BaseException] = []
    lock = threading.Lock()

    def worker() -> None:
        try:
            _exercise_client(args.launcher, args.calls)
        except BaseException as exc:
            with lock:
                errors.append(exc)

    threads = [
        threading.Thread(target=worker, name=f"mcp-smoke-{index}", daemon=True)
        for index in range(args.clients)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)
    hanging = [thread.name for thread in threads if thread.is_alive()]
    if hanging:
        errors.append(RuntimeError(f"clients timed out: {', '.join(hanging)}"))
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"OK: {args.clients} clients x {args.calls} tools/list calls")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
