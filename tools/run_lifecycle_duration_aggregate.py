"""Combine successful lifecycle audits into an actual-duration soak proof."""

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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--report",
        action="append",
        type=Path,
        required=True,
        help="Lifecycle aggregate report; repeat to combine consecutive runs.",
    )
    parser.add_argument("--minimum-seconds", type=float, default=1800.0)
    parser.add_argument(
        "--out",
        type=Path,
        default=ROOT / "tools/bin/live_release/phase2b-r-lifecycle-duration-aggregate-20260726.json",
    )
    args = parser.parse_args()
    sources: list[dict[str, Any]] = []
    runs: list[dict[str, Any]] = []
    for raw_path in args.report:
        path = raw_path.resolve()
        payload = json.loads(path.read_text(encoding="utf-8"))
        sources.append(
            {
                "path": str(path),
                "sha256": _sha256(path),
                "ok": bool(payload.get("ok")),
            }
        )
        for item in payload.get("reports") or []:
            if not isinstance(item, dict):
                continue
            runs.append(
                {
                    "arch": str(item.get("arch") or ""),
                    "cyclesRequested": int(item.get("cyclesRequested") or 0),
                    "cyclesCompleted": int(item.get("cyclesCompleted") or 0),
                    "durationSeconds": float(item.get("durationSeconds") or 0),
                    "handleTrendOk": bool(
                        (item.get("handleTrend") or {}).get("ok")
                    ),
                    "orphanAuditOk": bool(
                        (item.get("orphanAudit") or {}).get("ok")
                    ),
                    "ok": bool(item.get("ok")),
                }
            )
    duration = sum(item["durationSeconds"] for item in runs)
    arches = {item["arch"] for item in runs if item["arch"]}
    aggregate = {
        "schemaVersion": 1,
        "name": "phase2b-r-lifecycle-duration-aggregate",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "minimumSeconds": float(args.minimum_seconds),
        "durationSeconds": round(duration, 3),
        "sources": sources,
        "reports": runs,
        "cyclesPerArch": min(
            (
                sum(
                    item["cyclesCompleted"]
                    for item in runs
                    if item["arch"] == arch
                )
                for arch in ("x86", "x64")
            ),
            default=0,
        ),
    }
    aggregate["ok"] = bool(
        sources
        and all(item["ok"] for item in sources)
        and arches == {"x86", "x64"}
        and all(
            item["ok"]
            and item["cyclesCompleted"] == item["cyclesRequested"]
            and item["handleTrendOk"]
            and item["orphanAuditOk"]
            for item in runs
        )
        and duration >= float(args.minimum_seconds)
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(aggregate, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "ok": aggregate["ok"],
                "durationSeconds": aggregate["durationSeconds"],
                "out": str(args.out.resolve()),
            }
        )
    )
    return 0 if aggregate["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
