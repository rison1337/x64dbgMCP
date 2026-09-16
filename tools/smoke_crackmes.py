import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "src" / "x64dbg.py"


def _load_bridge():
    spec = importlib.util.spec_from_file_location("x64dbg_bridge", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _summarize_binding(payload: Dict[str, Any]) -> Dict[str, Any]:
    binding = payload.get("binding", {}) if isinstance(payload, dict) else {}
    if not isinstance(binding, dict):
        return {}
    record = binding.get("binding", {}) if isinstance(binding.get("binding"), dict) else {}
    return {
        "active": bool(binding.get("active")),
        "matches": bool(binding.get("matches")),
        "reason": binding.get("reason"),
        "pid": record.get("pid"),
        "imagePath": record.get("imagePath"),
        "moduleBase": record.get("moduleBase"),
    }


def _summarize_state(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    return {
        "ok": bool(payload.get("ok", True)),
        "pid": payload.get("pid") or payload.get("debuggeePid"),
        "state": payload.get("state"),
        "paused": payload.get("paused"),
        "running": payload.get("running"),
        "rip": payload.get("rip"),
        "ripRef": payload.get("ripRef"),
        "stopReason": payload.get("stopReason"),
        "exceptionCode": payload.get("exceptionCode"),
        "exceptionFirstChance": payload.get("exceptionFirstChance"),
        "module": payload.get("module"),
        "moduleBase": payload.get("moduleBase"),
        "debuggeeImage": payload.get("debuggeeImage"),
        "debuggeePath": payload.get("debuggeePath"),
        "binding": _summarize_binding(payload),
    }


def _discover_exes(root: Path, include_derived: bool) -> List[Path]:
    items: List[Path] = []
    for path in sorted(root.rglob("*.exe")):
        name = path.name.lower()
        if not include_derived and (
            name.endswith("_cracked.exe") or name.endswith(".bak.exe") or name.endswith(".exe.bak")
        ):
            continue
        items.append(path)
    return items


def run_smoke(root: Path, output_path: Path, include_derived: bool) -> int:
    mod = _load_bridge()
    exes = _discover_exes(root, include_derived=include_derived)
    results: List[Dict[str, Any]] = []
    for exe in exes:
        # ``InitDebuggee`` deliberately requires an absolute path because the
        # native launch contract hashes and verifies the exact target file
        # before resuming it.  The corpus root is often supplied relative to
        # the repository, so normalize each discovered sample here instead of
        # making the smoke gate fail before it reaches the debugger.
        target_path = exe.resolve()
        item: Dict[str, Any] = {"exe": str(target_path)}
        try:
            arch = mod._detect_pe_arch(str(target_path))
            item["arch"] = arch
            # Each corpus sample is an independent session. Restarting the
            # matching debugger prevents a stale x32/x64 plugin state from
            # leaking across GUI, mixed-mode and console targets.
            ensure = mod.EnsureDebugger(
                arch=arch or "auto", timeout_ms=20000, restart=True
            )
            if (not ensure.get("ok")) and ensure.get("restartRecommended"):
                ensure = mod.EnsureDebugger(
                    arch=arch or "auto", timeout_ms=20000, restart=True
                )
            item["ensure"] = ensure
            init = mod.InitDebuggee(
                exe_path=str(target_path),
                timeout_ms=20000,
                retries=2,
                stop_first=True,
                use_scyllahide="off",
            )
            dependency_diag = init.get("dependencyDiagnostics") if isinstance(init, dict) else {}
            item["initOk"] = bool(init.get("ok"))
            item["initHint"] = init.get("hint")
            item["dependencyMissing"] = (
                list(dependency_diag.get("missing") or [])
                if isinstance(dependency_diag, dict)
                else []
            )
            item["initBinding"] = init.get("binding")
            # Keep the gate report useful without embedding the full launch
            # and session payload for every sample.
            item["initDiagnostic"] = {
                "error": init.get("error"),
                "errorCode": init.get("errorCode"),
                "attempts": init.get("attempts"),
                "timedOut": bool(init.get("timedOut")),
                "state": _summarize_state(init.get("state") or {}),
            }
            item["binding"] = mod.GetSessionBinding()
            try:
                entry = mod.RunUntil(target="entry", timeout_ms=15000, poll_ms=100)
            except Exception as exc:
                entry = {"ok": False, "error": repr(exc)}
            if (
                isinstance(entry, dict)
                and not entry.get("ok")
                and callable(getattr(mod, "RunToUserCode", None))
            ):
                try:
                    fallback = mod.RunToUserCode(
                        timeout_ms=10000,
                        poll_ms=100,
                        max_runs=16,
                        skip_startup_exceptions=True,
                    )
                except Exception as exc:
                    fallback = {"ok": False, "error": repr(exc)}
                entry["userCodeFallback"] = {
                    "ok": bool(isinstance(fallback, dict) and fallback.get("ok")),
                    "mode": "user_code",
                    "hint": fallback.get("hint") if isinstance(fallback, dict) else None,
                    "error": fallback.get("error") if isinstance(fallback, dict) else None,
                }
                if isinstance(fallback, dict) and fallback.get("ok"):
                    entry["ok"] = True
                    entry["target"] = fallback.get("target") or fallback.get("stoppedAt")
                    entry["targetRef"] = fallback.get("targetRef") or fallback.get("stoppedAtRef")
            item["entry"] = {
                "ok": bool(entry.get("ok")),
                "target": entry.get("target"),
                "targetRef": entry.get("targetRef"),
                "binding": _summarize_binding(entry),
                "state": _summarize_state(entry.get("state") or {}),
                "hint": entry.get("hint"),
                "error": entry.get("error"),
            }
            entry_state = item["entry"].get("state") or {}
            # A managed/mixed-mode image can stop on a real first-chance
            # exception before its native entry breakpoint. That is a useful
            # debugger stop, not an initialization failure; preserve it as a
            # separate observation instead of collapsing it into "entry miss".
            item["stopObserved"] = bool(
                item["entry"]["ok"]
                or (
                    bool(entry_state.get("paused"))
                    and str(entry_state.get("state") or "").lower() == "paused"
                    and str(entry_state.get("stopReason") or "").lower()
                    in {"breakpoint", "exception", "pause"}
                )
            )
            item["stopKind"] = (
                "entry"
                if item["entry"]["ok"]
                else str(entry_state.get("stopReason") or "").lower() or None
            )
            if item["stopObserved"]:
                try:
                    snap = mod.CaptureStopContextStructured(disasm_after=4, callstack_limit=8)
                except Exception as exc:
                    snap = {"ok": False, "error": repr(exc)}
                item["snapshot"] = {
                    "ok": bool(snap.get("ok")),
                    "state": _summarize_state(snap.get("state") or {}),
                    "disasmCount": len(((snap.get("disasm") or {}).get("instructions") or [])),
                    "callstackCount": len(((snap.get("callstack") or {}).get("entries") or [])),
                }
            if target_path.name.lower() == "crackme_packed.exe":
                try:
                    mod.DebugRun()
                    follow = mod.FollowChildProcess(
                        timeout_ms=8000,
                        poll_ms=100,
                        remove_debug_object=True,
                        stop_first=True,
                    )
                except Exception as exc:
                    follow = {"ok": False, "error": repr(exc)}
                item["followChild"] = {
                    "ok": bool(follow.get("ok")),
                    "candidatePid": ((follow.get("candidate") or {}).get("pid") if isinstance(follow, dict) else None),
                    "candidateExe": ((follow.get("candidate") or {}).get("exe") if isinstance(follow, dict) else None),
                    "attachOk": bool(((follow.get("attach") or {}).get("ok")) if isinstance(follow, dict) else False),
                    "debugStatus": (follow.get("debugStatus") if isinstance(follow, dict) else {}),
                    "binding": _summarize_binding(follow if isinstance(follow, dict) else {}),
                    "error": (follow.get("error") if isinstance(follow, dict) else None),
                }
        except Exception as exc:
            item["fatal"] = repr(exc)
        finally:
            try:
                item["stopResult"] = mod.DebugStop()
            except Exception as exc:
                item["stopResult"] = repr(exc)
        results.append(item)

    summary = {
        "root": str(root),
        "count": len(results),
        "results": results,
    }
    ok_count = sum(1 for item in results if item.get("initOk") and item.get("stopObserved"))
    summary["okCount"] = ok_count
    summary["ok"] = bool(results) and ok_count == len(results)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"smoke results saved to {output_path} ({ok_count}/{len(results)} initialized-and-stopped)")
    return 0 if summary["ok"] else 1


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description="Run x64dbg MCP smoke checks against a crackme corpus.")
    parser.add_argument("root", help="Directory containing crackme samples")
    parser.add_argument(
        "--output",
        default=str(REPO_ROOT / "tools" / "smoke_crackmes_results.json"),
        help="Path to the JSON report",
    )
    parser.add_argument(
        "--include-derived",
        action="store_true",
        help="Include cracked/backed-up executables in discovery",
    )
    args = parser.parse_args(argv)
    return run_smoke(
        root=Path(args.root),
        output_path=Path(args.output),
        include_derived=bool(args.include_derived),
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
