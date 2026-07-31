"""Run the reproducible local certification gates and write one report."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def _command(label: str, args: list[str], timeout: int) -> dict[str, Any]:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            args,
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        output = completed.stdout or ""
        return {
            "label": label,
            "command": args,
            "ok": completed.returncode == 0,
            "exitCode": completed.returncode,
            "durationSec": round(time.monotonic() - started, 3),
            "outputTail": output[-12000:],
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "label": label,
            "command": args,
            "ok": False,
            "exitCode": None,
            "durationSec": round(time.monotonic() - started, 3),
            "timeout": True,
            "outputTail": str(exc.stdout or "")[-12000:],
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run x64dbg MCP local certification gates")
    parser.add_argument("--out", default="tools/dump_outputs/final_certification.json")
    parser.add_argument("--skip-live", action="store_true", help="skip debugger-dependent live gates")
    args = parser.parse_args(argv)

    python = sys.executable
    commands: list[tuple[str, list[str], int]] = [
        ("python-unittest", [python, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"], 300),
        ("corpus-all", [python, "tools/corpus.py", "all", "--arch", "all", "--clean"], 300),
        (
            "managed-fixture-build",
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                "tools/build_managed_fixture.ps1",
            ],
            60,
        ),
        (
            "coordinator-tests",
            [
                python,
                "-m",
                "unittest",
                "tests.test_ida_evidence_coordinator",
                "tests.test_managed_ida_coordinator",
            ],
            60,
        ),
        (
            "generated-docs-check",
            [python, "tools/generate_tool_reference.py", "--check"],
            60,
        ),
        ("native-x64", ["ctest", "--test-dir", "build/p0-x64", "-C", "Release", "--output-on-failure"], 120),
        ("native-x86", ["ctest", "--test-dir", "build/p0-x86", "-C", "Release", "--output-on-failure"], 120),
    ]
    if not args.skip_live:
        commands.extend(
            [
                ("key-recovery-live", [python, "tools/run_key_recovery_live_gate.py", "--arch", "all"], 300),
                ("source-crackme-live", [python, "tools/run_source_crackme_live_gate.py", "--arch", "all"], 300),
                ("ida-runtime-sync-live", [python, "tools/run_ida_runtime_sync_live_gate.py"], 300),
                (
                    "managed-dotnet-live",
                    [
                        python,
                        "tools/run_live_release_matrix.py",
                        "--arch",
                        "all",
                        "--case",
                        "api_trace_managed_exception,managed_runtime_probe",
                        "--out",
                        "tools/dump_outputs/stage7_managed_release_final.json",
                        "--run-id",
                        "final-cert-managed",
                        "--take-over-existing-debugger",
                    ],
                    300,
                ),
            ]
        )
    results: list[dict[str, Any]] = []
    for label, command, timeout in commands:
        result = _command(label, command, timeout)
        # Process-hollowing uses a deliberately suspended child and can hit a
        # transient Windows scheduler/security-product delay on x86. Retry the
        # entire corpus transaction once; the second run rebuilds and verifies
        # from a clean artifact tree and remains bounded by the same timeout.
        if label == "corpus-all" and not result.get("ok"):
            retry = _command(label, command, timeout)
            result["retry"] = retry
            result["ok"] = bool(retry.get("ok"))
            result["exitCode"] = retry.get("exitCode")
            result["durationSec"] = round(
                float(result.get("durationSec") or 0.0)
                + float(retry.get("durationSec") or 0.0),
                3,
            )
            result["outputTail"] = (
                str(result.get("outputTail") or "")
                + "\n--- retry ---\n"
                + str(retry.get("outputTail") or "")
            )[-12000:]
        results.append(result)
    report: dict[str, Any] = {
        "schema": "x64dbg-mcp-final-certification-v1",
        "root": str(ROOT),
        "python": sys.version,
        "skipLive": bool(args.skip_live),
        "results": results,
        "ok": all(item["ok"] for item in results),
    }
    canonical = json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    report["reportSha256"] = hashlib.sha256(canonical).hexdigest().upper()
    output = Path(os.path.abspath(args.out))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"ok": report["ok"], "report": str(output), "reportSha256": report["reportSha256"]}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
