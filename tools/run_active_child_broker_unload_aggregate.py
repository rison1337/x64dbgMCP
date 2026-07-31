"""Aggregate active child-broker self-unload proofs for x86 and x64."""

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


def _load_case(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    cases = payload.get("cases") or []
    if len(cases) != 1:
        raise ValueError(f"{path} must contain exactly one graph_attach_all case")
    case = cases[0]
    probe = case.get("activeChildBrokerUnload") or {}
    return {
        "arch": case.get("arch"),
        "path": str(path),
        "sha256": _sha256(path),
        "reportOk": bool(payload.get("ok")),
        "caseOk": bool(case.get("ok")),
        "cleanupOk": bool((case.get("cleanup") or {}).get("ok")),
        "probe": {
            "ok": bool(probe.get("ok")),
            "beforeRunning": bool(probe.get("beforeRunning")),
            "afterRunning": bool(probe.get("afterRunning")),
            "beforeChildCount": int(probe.get("beforeChildCount") or 0),
            "afterChildCount": int(probe.get("afterChildCount") or 0),
            "errorCode": str(probe.get("errorCode") or ""),
            "helloOk": bool((probe.get("helloAfter") or {}).get("ok")),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--x64",
        type=Path,
        required=True,
        help="x64 graph_attach_all active-unload report",
    )
    parser.add_argument(
        "--x86",
        type=Path,
        required=True,
        help="x86 graph_attach_all active-unload report",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=ROOT / "tools/bin/live_release/phase2b-r-active-child-broker-unload-aggregate-20260726.json",
    )
    args = parser.parse_args()
    cases = [_load_case(args.x64.resolve()), _load_case(args.x86.resolve())]
    aggregate = {
        "schemaVersion": 1,
        "name": "phase2b-r-active-child-broker-unload-aggregate",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "cases": cases,
    }
    aggregate["ok"] = all(
        item["reportOk"]
        and item["caseOk"]
        and item["cleanupOk"]
        and item["probe"]["ok"]
        and item["probe"]["beforeRunning"]
        and item["probe"]["afterRunning"]
        and item["probe"]["beforeChildCount"] >= 2
        and item["probe"]["afterChildCount"] >= 2
        and item["probe"]["errorCode"] == "bridge_self_unload_forbidden"
        and item["probe"]["helloOk"]
        for item in cases
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(aggregate, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {"ok": aggregate["ok"], "out": str(args.out.resolve())},
            ensure_ascii=False,
        )
    )
    return 0 if aggregate["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
