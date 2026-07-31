"""Build a deterministic IDA-side plan from managed runtime evidence.

JIT code normally lives outside the managed PE image.  This coordinator never
turns such an absolute JIT address into a fake static RVA.  It emits safe
in-image comment actions when a runtime address is provably inside the IDA
image and retains every other method/module as explicit ``unmapped`` evidence
for an IDA plugin or a later dynamic database import.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable

MANAGED_SCHEMA = "managed-runtime-evidence-v1"
PLAN_SCHEMA = "ida-managed-runtime-sync-plan-v1"
MAX_BYTES = 64 * 1024 * 1024


def _json_load(value: str) -> Any:
    if os.path.isfile(value):
        path = os.path.abspath(value)
        if os.path.getsize(path) > MAX_BYTES:
            raise ValueError("input exceeds 64 MiB")
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    if len(value.encode("utf-8")) > MAX_BYTES:
        raise ValueError("inline JSON exceeds 64 MiB")
    return json.loads(value)


def _int(value: Any, default: int | None = None) -> int | None:
    if isinstance(value, bool):
        return default
    try:
        if isinstance(value, int):
            return value
        text = str(value or "").strip()
        return int(text, 0) if text else default
    except (TypeError, ValueError):
        return default


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest().upper()


def _iter_dicts(value: Any) -> Iterable[dict[str, Any]]:
    if not isinstance(value, list):
        return ()
    return (item for item in value if isinstance(item, dict))


def _sha(value: Any) -> str:
    result = str(value or "").strip().upper()
    if len(result) != 64 or any(ch not in "0123456789ABCDEF" for ch in result):
        raise ValueError("managed evidence image SHA-256 is invalid")
    return result


def _arch(value: Any) -> str:
    text = str(value or "").casefold()
    if text in {"x64", "amd64", "64", "x86_64"}:
        return "x64"
    if text in {"x86", "i386", "32", "i686"}:
        return "x86"
    raise ValueError("managed evidence architecture is invalid")


def _method_key(method: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(method.get("module") or "").casefold(),
        str(method.get("metadataToken") or "").casefold(),
        str(method.get("nativeCode") or "").casefold(),
    )


def _collect_methods(capture: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for runtime in _iter_dicts(capture.get("runtimes")):
        candidates.extend(_iter_dicts(runtime.get("methods")))
    for thread in _iter_dicts(capture.get("threads")):
        for frame in _iter_dicts(thread.get("frames")):
            method = frame.get("method")
            if isinstance(method, dict):
                candidates.append(method)
    unique: dict[tuple[str, str, str], dict[str, Any]] = {}
    for method in candidates:
        copied = dict(method)
        unique[_method_key(copied)] = copied
    return [unique[key] for key in sorted(unique)]


def _collect_modules(capture: dict[str, Any]) -> list[dict[str, Any]]:
    unique: dict[tuple[str, str], dict[str, Any]] = {}
    for runtime in _iter_dicts(capture.get("runtimes")):
        for domain in _iter_dicts(runtime.get("appDomains")):
            for module in _iter_dicts(domain.get("modules")):
                copied = dict(module)
                key = (
                    str(copied.get("name") or copied.get("assemblyName") or "").casefold(),
                    str(copied.get("imageBase") or "").casefold(),
                )
                unique[key] = copied
    return [unique[key] for key in sorted(unique)]


def _module_memory_only(module: dict[str, Any]) -> bool:
    names = (
        str(module.get("name") or "").strip(),
        str(module.get("assemblyName") or "").strip(),
    )
    return not any(
        os.path.isabs(name) or os.path.isfile(name)
        for name in names
        if name
    )


def build_managed_sync_plan(
    managed_document: dict[str, Any],
    ida_image: dict[str, Any],
) -> dict[str, Any]:
    """Validate identities and produce deterministic managed evidence/actions."""

    if managed_document.get("schema") != MANAGED_SCHEMA:
        raise ValueError(f"expected {MANAGED_SCHEMA}")
    if _int(managed_document.get("version")) != 1:
        raise ValueError("unsupported managed evidence version")
    capture = managed_document.get("capture")
    session = managed_document.get("session")
    if not isinstance(capture, dict) or not isinstance(session, dict):
        raise ValueError("managed evidence capture/session is missing")
    evidence_sha = _sha(managed_document.get("imageSha256") or session.get("imageSha256"))
    ida_sha = _sha(ida_image.get("sha256"))
    evidence_arch = _arch(session.get("debuggerArch") or capture.get("process", {}).get("architecture"))
    ida_arch = _arch(ida_image.get("arch"))
    if evidence_sha != ida_sha or evidence_arch != ida_arch:
        raise ValueError("IDA image identity does not match managed evidence")
    ida_base = _int(ida_image.get("imageBase") or ida_image.get("imagebase"))
    ida_size = _int(ida_image.get("imageSize") or ida_image.get("sizeOfImage"))
    if ida_base is None or ida_base < 0 or ida_size is None or ida_size <= 0:
        raise ValueError("IDA image base/size is invalid")

    process_path = str((capture.get("process") or {}).get("imagePath") or "").casefold()
    methods = _collect_methods(capture)
    modules = _collect_modules(capture)
    actions: list[dict[str, Any]] = []
    unmapped: list[dict[str, Any]] = []
    mapped: list[dict[str, Any]] = []
    for method in methods:
        native = _int(method.get("nativeCode"))
        module_base = _int(method.get("moduleImageBase"))
        module_path = str(method.get("module") or "").casefold()
        token = str(method.get("metadataToken") or "")
        display = str(method.get("signature") or method.get("name") or token)
        reason = ""
        rva: int | None = None
        if native is None or native <= 0:
            reason = "no_native_code"
        elif module_base is None or module_base <= 0:
            reason = "missing_module_image_base"
        elif process_path and module_path != process_path:
            reason = "framework_or_other_module"
        elif native < module_base or native - module_base >= ida_size:
            reason = "jit_code_outside_image"
        else:
            rva = native - module_base
        record = {
            "metadataToken": token or None,
            "name": method.get("name"),
            "signature": method.get("signature"),
            "declaringType": method.get("declaringType"),
            "compilationType": method.get("compilationType"),
            "module": method.get("module"),
            "nativeCode": method.get("nativeCode"),
            "moduleImageBase": method.get("moduleImageBase"),
            "hotCold": method.get("hotCold"),
            "ilToNativeMap": method.get("ilToNativeMap"),
        }
        if rva is None:
            record["reason"] = reason
            unmapped.append(record)
            continue
        record["rva"] = f"0x{rva:X}"
        mapped.append(record)
        comment = (
            f"[x64dbg managed] {display} token={token or 'n/a'} "
            f"compilation={method.get('compilationType') or 'unknown'}"
        )
        actions.append(
            {
                "tool": "append_comments",
                "arguments": {
                    "items": {
                        "addr": f"0x{ida_base + rva:X}",
                        "comment": comment,
                        "dedupe": True,
                        "scope": "line",
                    }
                },
                "source": {"kind": "managed-method", "rva": f"0x{rva:X}", "token": token or None},
            }
        )
    dynamic_modules = [
        {
            **module,
            "isMemoryOnly": _module_memory_only(module),
        }
        for module in modules
        if bool(module.get("isDynamic"))
        or not bool(module.get("isPeFile"))
        or _module_memory_only(module)
    ]
    actions.sort(key=lambda item: (str(item["source"].get("rva")), str(item["source"].get("token"))))
    body = {
        "schema": PLAN_SCHEMA,
        "version": 1,
        "identity": {
            "sha256": evidence_sha,
            "arch": evidence_arch,
            "idaImageBase": f"0x{ida_base:X}",
            "idaImageSize": f"0x{ida_size:X}",
        },
        "source": {
            "schema": MANAGED_SCHEMA,
            "artifactSha256": managed_document.get("artifactSha256"),
            "sessionId": session.get("sessionId"),
            "pid": session.get("pid"),
        },
        "actionCount": len(actions),
        "actions": actions,
        "mappedMethods": mapped,
        "unmappedMethods": unmapped,
        "dynamicModules": dynamic_modules,
        "limitations": {
            "jitOutsideImage": "JIT addresses outside the PE image remain evidence only.",
            "dynamicAssembly": "Dynamic/non-PE modules require an IDA plugin or separate runtime database.",
        },
    }
    body["idempotencyKey"] = _digest(body)
    return body


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a managed x64dbg-to-IDA sync plan")
    parser.add_argument("--managed", required=True, help="managed-runtime-evidence-v1 JSON path or inline JSON")
    parser.add_argument("--ida-image", required=True, help="IDA image identity JSON path or inline JSON")
    parser.add_argument("--output", default="")
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args(argv)
    try:
        plan = build_managed_sync_plan(_json_load(args.managed), _json_load(args.ida_image))
        text = json.dumps(plan, ensure_ascii=False, indent=2) + "\n"
        if args.output:
            output = os.path.abspath(args.output)
            if os.path.exists(output) and not args.overwrite:
                raise FileExistsError(output)
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            Path(output).write_text(text, encoding="utf-8")
        print(text, end="")
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
