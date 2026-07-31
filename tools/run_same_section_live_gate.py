"""Live x64dbg gate for generic same-section unpacking and verified PE recovery."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import traceback
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "src" / "x64dbg.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "x64dbg_same_section_live", MODULE_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _smoke(path: Path) -> dict[str, Any]:
    completed = subprocess.run(
        [str(path)],
        cwd=str(path.parent),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
        check=False,
    )
    exit_code = completed.returncode & 0xFFFFFFFF
    # A reconstructed image enters the restored payload function directly.
    # Its deterministic return value is therefore the process exit code.
    return {
        "ok": exit_code == 42,
        "exitCode": exit_code,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _reset_owned_artifacts(artifact_root: Path, *paths: Path) -> None:
    """Remove only deterministic files owned by this gate."""

    root = artifact_root.resolve()
    for candidate in paths:
        resolved = candidate.resolve()
        if resolved.parent != root:
            raise RuntimeError(f"artifact cleanup escaped gate directory: {resolved}")
        resolved.unlink(missing_ok=True)


def _one_arch(module: Any, arch: str, artifact_root: Path) -> dict[str, Any]:
    target = REPO_ROOT / "tools" / "bin" / "e2e" / arch / "same_section_unpack.exe"
    artifact_root.mkdir(parents=True, exist_ok=True)
    dump_path = artifact_root / f"same_section_unpack-{arch}.dump.exe"
    raw_dump_path = artifact_root / f"same_section_unpack-{arch}.dump.raw.exe"
    timeline_path = artifact_root / f"same_section_unpack-{arch}.timeline.json"
    _reset_owned_artifacts(
        artifact_root,
        dump_path,
        raw_dump_path,
        timeline_path,
    )
    launch = module.LaunchFileUnderDebugger(
        exe_path=str(target),
        arch=arch,
        restart_debugger=True,
        timeout_ms=30000,
        stop_first=True,
        use_scyllahide="off",
        use_hidemain="off",
        advance_to_entry=True,
        environment={"X64DBG_MCP_E2E_SAME_SECTION_BREAK": "1"},
    )
    if not isinstance(launch, dict) or not launch.get("ok"):
        raise RuntimeError(f"{arch} launch failed: {launch}")
    try:
        run = module.DebugRun()
        pause = module.WaitForPause(timeout_ms=20000, poll_ms=50)
        if not isinstance(pause, dict) or not pause.get("paused"):
            raise RuntimeError(f"{arch} inline mutation gate was not reached: {pause}")
        state = module.GetDebugState()
        current_rip = str(
            (state.get("registers") or {}).get("rip")
            or (state.get("registers") or {}).get("eip")
            or state.get("rip")
            or ""
        )
        result = module.FindOEP(
            timeout_ms=45000,
            dump_to_path=str(dump_path),
            timeline_to_path=str(timeline_path),
        )
        if not isinstance(result, dict) or not result.get("ok"):
            raise RuntimeError(f"{arch} FindOEP failed: {result}")
        if not result.get("verified"):
            raise RuntimeError(f"{arch} reconstructed dump was not verified: {result}")
        detected_via = str(result.get("detectedVia") or "").lower()
        if "same_section" not in detected_via:
            raise RuntimeError(
                f"{arch} did not use generic same-section refinement: {result}"
            )
        telemetry = (
            result.get("telemetry")
            if isinstance(result.get("telemetry"), dict)
            else {}
        )
        decision = (
            telemetry.get("sameSectionCurrentEvidence")
            or telemetry.get("sameSectionEntryEvidence")
            or telemetry.get("sameSectionAnchorEvidence")
            or {}
        )
        if not (
            isinstance(decision, dict)
            and decision.get("genericRuntimeMutation")
            and decision.get("sectionMutated")
        ):
            raise RuntimeError(
                f"{arch} generic runtime mutation evidence is incomplete: {telemetry}"
            )
        packed_layout = module._parse_pe_layout(str(target))
        dump_layout = module._parse_pe_layout(str(dump_path))
        packed_entry = int(str(packed_layout.get("entryPointRva") or "0"), 16)
        dump_entry = int(str(dump_layout.get("entryPointRva") or "0"), 16)
        if packed_entry == dump_entry:
            raise RuntimeError(
                f"{arch} dump entry did not move away from the loader: "
                f"0x{dump_entry:x}"
            )
        packed_section = packed_layout.get("entrySection") or {}
        dump_entry_section = dump_layout.get("entrySection") or {}
        if str(packed_section.get("name")) != str(dump_entry_section.get("name")):
            raise RuntimeError(
                f"{arch} candidate is not in the original executable section"
            )
        stop = module.DebugStop()
        smoke = _smoke(dump_path)
        if not smoke.get("ok"):
            raise RuntimeError(f"{arch} reconstructed dump smoke failed: {smoke}")
        return {
            "ok": True,
            "arch": arch,
            "target": {
                "path": str(target),
                "sha256": _sha256(target),
                "entryRva": f"0x{packed_entry:x}",
                "entrySection": packed_section.get("name"),
            },
            "launch": launch,
            "run": run,
            "pause": pause,
            "pauseRip": current_rip,
            "findOep": result,
            "dump": {
                "path": str(dump_path),
                "sha256": _sha256(dump_path),
                "entryRva": f"0x{dump_entry:x}",
                "entrySection": dump_entry_section.get("name"),
            },
            "timeline": {
                "path": str(timeline_path),
                "sha256": _sha256(timeline_path),
            },
            "smoke": smoke,
            "stop": stop,
        }
    finally:
        try:
            module.DebugStop()
        except Exception:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", choices=("x64", "x86", "all"), default="all")
    parser.add_argument(
        "--output",
        type=Path,
        default=(
            REPO_ROOT
            / "tools"
            / "dump_outputs"
            / "stage5e_same_section_live_final.json"
        ),
    )
    args = parser.parse_args()
    module = _load_module()
    architectures = ["x64", "x86"] if args.arch == "all" else [args.arch]
    artifact_root = args.output.resolve().parent / "stage5e_same_section_live"
    report: dict[str, Any] = {
        "schema": "stage5e-same-section-live-v1",
        "ok": False,
        "architectures": architectures,
        "results": [],
    }
    try:
        for arch in architectures:
            report["results"].append(_one_arch(module, arch, artifact_root))
        report["ok"] = all(item.get("ok") for item in report["results"])
    except Exception as exc:
        report["error"] = str(exc)
        report["traceback"] = traceback.format_exc()
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    canonical = json.dumps(report, ensure_ascii=False, sort_keys=True).encode("utf-8")
    report["reportSha256"] = hashlib.sha256(canonical).hexdigest().upper()
    args.output.resolve().write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
