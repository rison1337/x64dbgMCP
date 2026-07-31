import argparse
import json
import os
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

from headless_smoke import (
    SCENARIOS,
    _ensure_watch_target_exe,
    load_bridge,
)


def _build_cases(bridge) -> list[dict]:
    watch_x64 = _ensure_watch_target_exe("x64")
    watch_x86 = _ensure_watch_target_exe("x86")
    return [
        {"name": "plugin_status", "scenario": "plugin_status", "exe": r"C:\Windows\System32\notepad.exe"},
        {"name": "console_cmd", "scenario": "console_cmd", "exe": r"C:\Windows\System32\cmd.exe"},
        {"name": "raw_visual_notepad", "scenario": "raw_visual_notepad", "exe": r"C:\Windows\System32\notepad.exe"},
        {"name": "re_context", "scenario": "re_context", "exe": r"C:\Windows\System32\notepad.exe"},
        {"name": "trace_summary_x64", "scenario": "trace_summary", "exe": watch_x64},
        {"name": "memory_watchpoint_x64", "scenario": "memory_watchpoint", "exe": watch_x64},
        {"name": "dump_main_x64", "scenario": "dump_main", "exe": watch_x64},
        {"name": "api_trace_sleep_x64", "scenario": "api_trace_sleep", "exe": watch_x64},
        {"name": "checkpoint_rewind_x64", "scenario": "checkpoint_rewind", "exe": watch_x64},
        {"name": "heap_trace_live_x64", "scenario": "heap_trace_live", "exe": r"C:\Windows\System32\notepad.exe"},
        {"name": "dump_main_x86", "scenario": "dump_main", "exe": watch_x86},
        {"name": "checkpoint_rewind_x86", "scenario": "checkpoint_rewind", "exe": watch_x86},
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run an extended local smoke suite against the live x64dbg bridge.")
    parser.add_argument(
        "--bridge",
        default=str(Path(__file__).resolve().parents[1] / "src" / "x64dbg.py"),
    )
    parser.add_argument(
        "--out",
        default=str(Path(__file__).resolve().parents[1] / "tools" / "local_extended_smoke_results.json"),
    )
    args = parser.parse_args()

    bridge = load_bridge(args.bridge)
    results = []
    cases = _build_cases(bridge)
    for case in cases:
        exe_path = str(case["exe"])
        arch = bridge._detect_pe_arch(exe_path) or "auto"
        ensure = bridge.RestartDebugger(arch=arch, timeout_ms=45000)
        retry = None
        if not ensure.get("ok"):
            time.sleep(0.5)
            retry = bridge.RestartDebugger(arch=arch, timeout_ms=45000)
            if retry.get("ok"):
                ensure = retry
            else:
                ensure = bridge.EnsureDebugger(arch=arch, timeout_ms=30000, restart=False)
                if isinstance(ensure, dict):
                    ensure["restartRetry"] = retry
        scenario = SCENARIOS[str(case["scenario"])]
        if ensure.get("ok"):
            try:
                result = scenario(bridge, exe_path)
            except Exception as exc:
                result = {
                    "ok": False,
                    "error": str(exc),
                    "traceback": traceback.format_exc(),
                }
        else:
            result = {"ok": False, "error": "EnsureDebugger failed", "ensure": ensure}
        results.append(
            {
                "name": case["name"],
                "scenario": case["scenario"],
                "exe": exe_path,
                "arch": arch,
                "ensure": ensure,
                "ensureRetry": retry,
                "result": result,
                "ok": bool(result.get("ok")),
            }
        )

    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "bridge": os.path.abspath(args.bridge),
        "count": len(results),
        "okCount": sum(1 for item in results if item.get("ok")),
        "ok": bool(results) and all(bool(item.get("ok")) for item in results),
        "results": results,
    }
    out_path = Path(args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"out": str(out_path), "count": payload["count"], "okCount": payload["okCount"]}, ensure_ascii=False))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
