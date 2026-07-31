import argparse
import json
import os
import traceback
from datetime import datetime, timezone
from pathlib import Path

from headless_smoke import SCENARIOS, _default_exe_for_scenario, load_bridge


def main() -> int:
    parser = argparse.ArgumentParser(description="Run smoke scenarios sequentially against a single live x64dbg bridge.")
    parser.add_argument(
        "--bridge",
        default=str(Path(__file__).resolve().parents[1] / "src" / "x64dbg.py"),
    )
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--scenarios", nargs="+", required=True, choices=sorted(SCENARIOS.keys()))
    args = parser.parse_args()

    os.makedirs(os.path.abspath(args.out_dir), exist_ok=True)
    bridge = load_bridge(args.bridge)

    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "bridge": os.path.abspath(args.bridge),
        "outDir": os.path.abspath(args.out_dir),
        "results": [],
    }

    overall_ok = True
    for scenario_name in args.scenarios:
        scenario = SCENARIOS[scenario_name]
        exe_path = _default_exe_for_scenario(bridge, scenario_name)
        if not exe_path:
            result = {
                "ok": False,
                "error": (
                    f"No default exe for scenario {scenario_name}. "
                    "Pass it through headless_smoke.py directly."
                ),
            }
        else:
            try:
                result = scenario(bridge, exe_path)
                if not isinstance(result, dict):
                    result = {
                        "ok": False,
                        "error": "Scenario returned a non-object result",
                        "resultType": type(result).__name__,
                        "rawResult": repr(result),
                    }
            except Exception as exc:
                result = {
                    "ok": False,
                    "error": str(exc),
                    "exceptionType": type(exc).__name__,
                    "traceback": traceback.format_exc(),
                }
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "bridge": os.path.abspath(args.bridge),
            "scenario": scenario_name,
            "exePath": exe_path,
            "result": result,
        }
        per_scenario_path = os.path.join(os.path.abspath(args.out_dir), f"{scenario_name}.json")
        with open(per_scenario_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
        ok = bool((payload.get("result") or {}).get("ok"))
        overall_ok = overall_ok and ok
        summary["results"].append(
            {
                "scenario": scenario_name,
                "exePath": exe_path,
                "ok": ok,
                "resultPath": per_scenario_path,
            }
        )

    summary["ok"] = overall_ok
    summary_path = os.path.join(os.path.abspath(args.out_dir), "summary.json")
    with open(summary_path, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, ensure_ascii=False, indent=2)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if overall_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
