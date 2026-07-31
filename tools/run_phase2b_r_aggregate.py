"""Aggregate current 2B-R lifecycle evidence without hiding open gates."""

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


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _matrix_summary(payload: dict[str, Any]) -> dict[str, Any]:
    cases = payload.get("testcases") or []
    return {
        "name": payload.get("name"),
        "path": str(payload.get("_path") or ""),
        "sha256": payload.get("_sha256"),
        "ok": bool(payload.get("ok")),
        "tests": len(cases),
        "successes": sum(1 for case in cases if case.get("status") == "success"),
        "failures": int(payload.get("failures") or 0),
        "errors": int(payload.get("errors") or 0),
        "skipped": int(payload.get("skipped") or 0),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--matrix",
        type=Path,
        default=ROOT / "tools/bin/live_release/phase2b-r-current-slice-20260726-r2.json",
        help="Fresh current-slice matrix report to include in the aggregate.",
    )
    parser.add_argument(
        "--active-child-unload",
        type=Path,
        default=None,
        help="Optional x86/x64 active child-broker self-unload aggregate.",
    )
    parser.add_argument(
        "--thirty-minute",
        type=Path,
        default=None,
        help="Optional sustained lifecycle report with at least 1800 total seconds.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=ROOT / "tools/bin/live_release/phase2b-r-aggregate-20260726.json",
    )
    args = parser.parse_args()
    matrix_path = args.matrix.resolve()
    self_unload_path = ROOT / "tools/bin/live_release/phase2b-r-self-unload-20260726-r3/report.json"
    audit_path = ROOT / "tools/bin/live_release/phase2b-r-lifecycle-audit-20260726.json"
    soak_path = ROOT / "tools/bin/live_release/phase2b-r-lifecycle-soak-20260726.json"
    occupied_path = ROOT / "tools/bin/live_release/phase2b-r-occupied-port-startup-20260726.json"
    entries: list[dict[str, Any]] = []
    for path in (matrix_path, self_unload_path):
        payload = _load(path)
        payload["_path"] = str(path)
        payload["_sha256"] = _sha256(path)
        entries.append(_matrix_summary(payload))
    audit = _load(audit_path)
    soak = _load(soak_path)
    occupied = _load(occupied_path)
    active_child = (
        _load(args.active_child_unload.resolve())
        if args.active_child_unload is not None
        else {"ok": False, "path": "", "sha256": ""}
    )
    thirty_minute = (
        _load(args.thirty_minute.resolve())
        if args.thirty_minute is not None
        else {"ok": False, "reports": []}
    )
    thirty_minute_duration = sum(
        float(item.get("durationSeconds") or 0)
        for item in (thirty_minute.get("reports") or [])
        if isinstance(item, dict)
    )
    aggregate = {
        "schemaVersion": 1,
        "name": "phase2b-r-lifecycle-aggregate",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "currentMatrix": entries,
        "lifecycleAudit": {
            "path": str(audit_path),
            "sha256": _sha256(audit_path),
            "ok": bool(audit.get("ok")),
            "cyclesPerArch": int(audit.get("cyclesPerArch") or 0),
        },
        "lifecycleSoak": {
            "path": str(soak_path),
            "sha256": _sha256(soak_path),
            "ok": bool(soak.get("ok")),
            "cyclesPerArch": int(soak.get("cyclesPerArch") or 0),
        },
        "occupiedPortStartup": {
            "path": str(occupied_path),
            "sha256": _sha256(occupied_path),
            "ok": bool(occupied.get("ok")),
            "cyclesPerArch": int(occupied.get("cyclesPerArch") or 0),
        },
        "activeChildBrokerUnload": {
            "path": str(args.active_child_unload.resolve())
            if args.active_child_unload is not None
            else "",
            "sha256": (
                _sha256(args.active_child_unload.resolve())
                if args.active_child_unload is not None
                else ""
            ),
            "ok": bool(active_child.get("ok")),
        },
        "thirtyMinuteLifecycle": {
            "path": str(args.thirty_minute.resolve())
            if args.thirty_minute is not None
            else "",
            "sha256": (
                _sha256(args.thirty_minute.resolve())
                if args.thirty_minute is not None
                else ""
            ),
            "ok": bool(thirty_minute.get("ok")),
            "durationSeconds": round(thirty_minute_duration, 3),
            "cyclesPerArch": int(thirty_minute.get("cyclesPerArch") or 0),
        },
        "gates": {
            "currentFreshMatrix": all(item["ok"] and item["failures"] == item["errors"] == item["skipped"] == 0 for item in entries),
            "selfUnload": bool(entries[-1]["ok"]),
            "fiveCycleAudit": bool(audit.get("ok")) and int(audit.get("cyclesPerArch") or 0) >= 5,
            "thirtyCycleSoak": bool(soak.get("ok")) and int(soak.get("cyclesPerArch") or 0) >= 30,
            "occupiedPortStartup": bool(occupied.get("ok")) and int(occupied.get("cyclesPerArch") or 0) >= 5,
            "thirtyMinuteGate": bool(thirty_minute.get("ok"))
            and thirty_minute_duration >= 1800.0,
            "activeChildBrokerUnload": bool(active_child.get("ok")),
        },
    }
    aggregate["ok"] = bool(
        aggregate["gates"]["currentFreshMatrix"]
        and aggregate["gates"]["selfUnload"]
        and aggregate["gates"]["fiveCycleAudit"]
        and aggregate["gates"]["thirtyCycleSoak"]
        and aggregate["gates"]["occupiedPortStartup"]
        and aggregate["gates"]["activeChildBrokerUnload"]
        and aggregate["gates"]["thirtyMinuteGate"]
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
