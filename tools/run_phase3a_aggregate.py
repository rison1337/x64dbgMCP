"""Build a reproducible phase-3A native-trace evidence aggregate."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _case_summary(testcase: dict[str, Any]) -> dict[str, Any]:
    worker = testcase.get("worker") or {}
    result = worker.get("result") or {}
    overflow = result.get("highRateOverflow") or {}
    evidence = overflow.get("evidence") or {}
    reader = result.get("readerRace") or {}
    return {
        "name": testcase.get("name"),
        "arch": testcase.get("arch"),
        "status": testcase.get("status"),
        "ok": bool(worker.get("ok")),
        "ringOk": bool((result.get("ringTrace") or {}).get("ok")),
        "readerRaceOk": bool(reader.get("ok")),
        "readerSnapshots": int(reader.get("readerCount") or 0),
        "clearDuringWaitRejected": (
            ((reader.get("clearWhileActive") or {}).get("error") or {}).get("code")
            == "trace_active"
        ),
        "enrichmentOk": bool((result.get("ringTrace") or {}).get("enrichmentOk")),
        "overflowOk": bool(overflow.get("ok")),
        "overflowEventCount": int(evidence.get("eventCount") or 0),
        "overflowDroppedEvents": int(evidence.get("droppedEvents") or 0),
        "overflowOldestSeq": int(evidence.get("oldestEventSeq") or 0),
        "overflowLatestSeq": int(evidence.get("latestEventSeq") or 0),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--report",
        type=Path,
        default=ROOT / "tools/bin/live_release/phase3a-native-trace-live-20260726-r9.json",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=ROOT / "tools/bin/live_release/phase3a-native-trace-aggregate-20260726.json",
    )
    args = parser.parse_args()
    report_path = args.report.resolve()
    report = json.loads(report_path.read_text(encoding="utf-8"))
    cases = [_case_summary(item) for item in report.get("testcases") or []]
    source = ROOT / "src/MCPx64dbg.cpp"
    plugins = {
        "x64": Path(r"C:\x64dbg\x64\plugins\MCPx64dbg.dp64"),
        "x86": Path(r"C:\x64dbg\x32\plugins\MCPx64dbg.dp32"),
    }
    aggregate = {
        "schemaVersion": 1,
        "name": "phase3a-native-trace-aggregate",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "report": {
            "path": str(report_path),
            "sha256": _sha256(report_path),
            "ok": bool(report.get("ok")),
            "testCount": len(cases),
            "successCount": sum(1 for case in cases if case["ok"]),
        },
        "source": {
            "path": str(source),
            "sha256": _sha256(source),
        },
        "plugins": {
            arch: {"path": str(path), "sha256": _sha256(path)}
            for arch, path in plugins.items()
        },
        "cases": cases,
    }
    aggregate["ok"] = bool(
        aggregate["report"]["ok"]
        and aggregate["report"]["testCount"] == 2
        and aggregate["report"]["successCount"] == 2
        and all(case["ok"] for case in cases)
        and all(case["readerRaceOk"] for case in cases)
        and all(case["clearDuringWaitRejected"] for case in cases)
        and all(case["enrichmentOk"] for case in cases)
        and all(case["overflowOk"] for case in cases)
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(aggregate, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"ok": aggregate["ok"], "out": str(args.out.resolve())}))
    return 0 if aggregate["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
