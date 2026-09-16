"""Live x64dbg gate for reflective/manual-map and destroyed-header recovery."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
import time
import traceback
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "src" / "x64dbg.py"


def _load_bridge_module():
    spec = importlib.util.spec_from_file_location("x64dbg_manual_map_live", MODULE_PATH)
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


def _launch_evidence(launch: dict[str, Any]) -> dict[str, Any]:
    ensure = launch.get("ensureDebugger") if isinstance(launch.get("ensureDebugger"), dict) else {}
    bridge = ensure.get("bridge") if isinstance(ensure.get("bridge"), dict) else {}
    identity = bridge.get("identity") if isinstance(bridge.get("identity"), dict) else {}
    init = launch.get("init") if isinstance(launch.get("init"), dict) else {}
    init_result = init.get("initResult") if isinstance(init.get("initResult"), dict) else {}
    process = init_result.get("process") if isinstance(init_result.get("process"), dict) else {}
    session = init_result.get("session") if isinstance(init_result.get("session"), dict) else {}
    advance = launch.get("advanceToEntry") if isinstance(launch.get("advanceToEntry"), dict) else {}
    return {
        "ok": bool(launch.get("ok")),
        "exePath": launch.get("exePath"),
        "requestedArch": launch.get("requestedArch"),
        "debuggerPid": identity.get("debuggerPid"),
        "bridgeInstanceId": identity.get("bridgeInstanceId"),
        "sessionId": session.get("sessionId"),
        "sessionGeneration": session.get("generation"),
        "debuggeePid": process.get("pid"),
        "imageSha256": (process.get("actualIdentity") or {}).get("sha256"),
        "entry": {
            "ok": advance.get("ok"),
            "rip": advance.get("rip"),
            "ripRef": advance.get("ripRef"),
        },
    }


def _pause_evidence(state: dict[str, Any]) -> dict[str, Any]:
    binding = state.get("binding") if isinstance(state.get("binding"), dict) else {}
    return {
        "ok": state.get("ok"),
        "pid": state.get("pid"),
        "state": state.get("state"),
        "paused": state.get("paused"),
        "rip": state.get("rip"),
        "ripRef": state.get("ripRef"),
        "stopReason": state.get("stopReason"),
        "exceptionCode": state.get("exceptionCode"),
        "exceptionFirstChance": state.get("exceptionFirstChance"),
        "bindingMatches": binding.get("matches"),
    }


def _run_and_pause(module: Any, arch: str, arguments: list[str]) -> dict[str, Any]:
    directory = REPO_ROOT / "tools" / "bin" / "e2e" / arch
    loader = directory / "manual_map_loader.exe"
    launch = module.LaunchFileUnderDebugger(
        exe_path=str(loader),
        arch=arch,
        restart_debugger=True,
        timeout_ms=30000,
        retries=5,
        stop_first=True,
        use_scyllahide="off",
        advance_to_entry=True,
        arguments=arguments,
        working_directory=str(directory),
        child_policy="none",
    )
    if not isinstance(launch, dict) or not launch.get("ok"):
        raise RuntimeError(f"{arch} launch failed: {launch}")
    module.DebugRun()
    deadline = time.monotonic() + 8.0
    last_state: dict[str, Any] = {}
    while time.monotonic() < deadline:
        time.sleep(0.10)
        last_state = module.GetDebugStateLean()
        if int(last_state.get("pid") or 0) and last_state.get("paused"):
            console = module.ReadDebuggeeConsole(max_chars=4096)
            console_text = str(console.get("text") or "")
            if "MANUAL_MAP_OK" in console_text or "REFLECTIVE_EMBED_OK" in console_text:
                return {
                    "launch": _launch_evidence(launch),
                    "quiescence": {
                        "mode": "fixture-debug-break",
                        "state": _pause_evidence(last_state),
                        "console": console,
                    },
                }
            # Advance past any unrelated loader pause; the deterministic
            # fixture's own DebugBreak occurs only after the mapping is stable.
            module.DebugRun()
        if str(last_state.get("state") or "") in {"terminated", "not_debugging"}:
            break
    raise RuntimeError(f"{arch} target did not reach the hold state: {last_state}")


def _smoke(loader: Path, payload: Path) -> dict[str, Any]:
    completed = subprocess.run(
        [str(loader), "--mode", "smoke", "--payload", str(payload)],
        cwd=str(loader.parent),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
        check=False,
    )
    return {
        "ok": completed.returncode == 0
        and "MANUAL_DUMP_SMOKE_OK result=42" in completed.stdout,
        "exitCode": completed.returncode & 0xFFFFFFFF,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _one_arch(module: Any, arch: str, artifact_root: Path) -> dict[str, Any]:
    directory = REPO_ROOT / "tools" / "bin" / "e2e" / arch
    loader = directory / "manual_map_loader.exe"
    template = directory / "fixture_module.dll"
    artifact_root.mkdir(parents=True, exist_ok=True)
    manual_dump = artifact_root / f"fixture_module-{arch}-manual-map.dump.dll"
    embedded_dump = artifact_root / f"fixture_module-{arch}-embedded.dump.dll"

    manual_session = _run_and_pause(
        module,
        arch,
        ["--destroy-headers", "--debug-break", "--hold-ms", "300000"],
    )
    manual_scan = module.ScanMemoryForPEImages(
        header_template_path=str(template),
        include_embedded=True,
        header_bytes=4096,
        max_regions=8192,
        max_candidates=256,
    )
    manual_candidates = [
        item
        for item in manual_scan.get("candidates", [])
        if item.get("headerState") == "destroyed-or-headerless"
        and item.get("architecture") == arch
        and item.get("templateIdentity", {}).get("verified")
    ]
    if len(manual_candidates) != 1:
        try:
            console = module.ReadDebuggeeConsole(max_chars=4096)
        except Exception as exc:
            console = {"error": str(exc)}
        raise RuntimeError(
            f"{arch} expected one headerless template match, got "
            f"{manual_candidates}; console={console}; "
            f"diagnostics={manual_scan.get('template')}"
        )
    manual_candidate = manual_candidates[0]
    manual_rebuild = module.DumpPeFromMemory(
        base=manual_candidate["base"],
        output_path=str(manual_dump),
        header_template_path=str(template),
        verify_template_identity=True,
        minimum_template_similarity=0.70,
        source_layout="memory",
        reverse_relocations=True,
        verify=True,
        overwrite=True,
    )
    module.DebugStop()
    if not manual_rebuild.get("ok") or not manual_rebuild.get("reloadable"):
        raise RuntimeError(f"{arch} manual-map rebuild failed: {manual_rebuild}")
    manual_smoke = _smoke(loader, manual_dump)
    if not manual_smoke["ok"]:
        raise RuntimeError(f"{arch} manual-map smoke failed: {manual_smoke}")

    embedded_session = _run_and_pause(
        module,
        arch,
        ["--mode", "embedded", "--debug-break", "--hold-ms", "300000"],
    )
    embedded_scan = module.ScanMemoryForPEImages(
        include_embedded=True,
        header_bytes=1024 * 1024,
        max_regions=8192,
        max_candidates=256,
    )
    embedded_candidates = [
        item
        for item in embedded_scan.get("candidates", [])
        if item.get("imageKind") == "embedded-reflective"
        and item.get("architecture") == arch
        and int(item.get("embeddedOffset") or 0) == 0x600
    ]
    if len(embedded_candidates) != 1:
        raise RuntimeError(
            f"{arch} expected one embedded reflective match, got {embedded_candidates}"
        )
    embedded_candidate = embedded_candidates[0]
    embedded_rebuild = module.DumpPeFromMemory(
        base=embedded_candidate["base"],
        output_path=str(embedded_dump),
        source_layout="auto",
        reverse_relocations=True,
        verify=True,
        overwrite=True,
    )
    module.DebugStop()
    if not embedded_rebuild.get("ok") or not embedded_rebuild.get("reloadable"):
        raise RuntimeError(f"{arch} embedded extraction failed: {embedded_rebuild}")
    embedded_smoke = _smoke(loader, embedded_dump)
    if not embedded_smoke["ok"]:
        raise RuntimeError(f"{arch} embedded smoke failed: {embedded_smoke}")

    return {
        "ok": True,
        "arch": arch,
        "loader": {"path": str(loader), "sha256": _sha256(loader)},
        "template": {"path": str(template), "sha256": _sha256(template)},
        "manualMap": {
            "session": manual_session,
            "candidate": manual_candidate,
            "scanSummary": {
                "candidateCount": manual_scan.get("candidateCount"),
                "template": manual_scan.get("template"),
            },
            "rebuild": manual_rebuild,
            "dumpSha256": _sha256(manual_dump),
            "smoke": manual_smoke,
        },
        "embeddedReflective": {
            "session": embedded_session,
            "candidate": embedded_candidate,
            "scanSummary": {
                "candidateCount": embedded_scan.get("candidateCount"),
                "embeddedScan": embedded_scan.get("embeddedScan"),
            },
            "rebuild": embedded_rebuild,
            "dumpSha256": _sha256(embedded_dump),
            "smoke": embedded_smoke,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", choices=("x64", "x86", "all"), default="all")
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "tools" / "dump_outputs" / "stage5e-manual-map-live.json",
    )
    args = parser.parse_args()
    module = _load_bridge_module()
    architectures = ["x64", "x86"] if args.arch == "all" else [args.arch]
    artifact_root = args.output.resolve().parent / "stage5e-manual-map-live"
    report: dict[str, Any] = {
        "schema": "stage5e-manual-map-live-v1",
        "ok": False,
        "architectures": architectures,
        "results": [],
    }
    try:
        for architecture in architectures:
            report["results"].append(_one_arch(module, architecture, artifact_root))
        report["ok"] = all(item.get("ok") for item in report["results"])
    except Exception as exc:
        report["error"] = str(exc)
        report["traceback"] = traceback.format_exc()
        try:
            module.DebugStop()
        except Exception:
            pass
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    canonical = json.dumps(report, ensure_ascii=False, sort_keys=True).encode("utf-8")
    report["reportSha256"] = hashlib.sha256(canonical).hexdigest().upper()
    args.output.resolve().write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
