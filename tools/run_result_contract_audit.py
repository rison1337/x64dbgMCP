"""Exercise the public envelope through the real MCP stdio transport.

The audit is deliberately offline: it starts the repository's stdio launcher,
does initialize/list_tools/call_tool for every discovery profile, and checks
both a successful result and a validation failure.  It never starts x64dbg.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "src" / "mcp_stdio_launcher.py"
PROFILES = ("inspect", "standard", "automation", "full")


def _decode_result(call_result: Any) -> dict[str, Any]:
    content = getattr(call_result, "content", None) or []
    if not content:
        raise AssertionError("call_tool returned no content")
    text = getattr(content[0], "text", "")
    if not isinstance(text, str) or not text.strip():
        raise AssertionError("call_tool returned non-text content")
    payload = json.loads(text)
    if not isinstance(payload, dict) or set(payload) != {"ok", "data", "error", "meta"}:
        raise AssertionError(f"not an envelope-v1 payload: {payload!r}")
    if not isinstance(payload["meta"], dict) or payload["meta"].get("resultContract") != "envelope-v1":
        raise AssertionError(f"missing result contract metadata: {payload!r}")
    return payload


async def _run_profile(profile: str) -> dict[str, Any]:
    env = os.environ.copy()
    env["X64DBG_MCP_TOOL_PROFILE"] = profile
    env["PYTHONUNBUFFERED"] = "1"
    params = StdioServerParameters(
        command=sys.executable,
        args=["-u", str(LAUNCHER)],
        env=env,
    )
    started = time.monotonic()
    async with stdio_client(params, errlog=sys.stderr) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            initialize = await session.initialize()
            listing = await session.list_tools()
            success_call = await session.call_tool("GetMiniDumpProfiles", {})
            success = _decode_result(success_call)
            invalid_call = await session.call_tool("VerifyPEDump", {})
            invalid = _decode_result(invalid_call)
            if not success["ok"]:
                raise AssertionError(f"success call failed for {profile}: {success!r}")
            if invalid["ok"] or invalid["error"].get("code") != "INVALID_ARGUMENT":
                raise AssertionError(f"validation failure was not canonical: {invalid!r}")
            missing_meta = [
                tool.name
                for tool in listing.tools
                if (getattr(tool, "meta", None) or {}).get("x64dbg", {}).get("resultContract")
                != "envelope-v1"
            ]
            if missing_meta:
                raise AssertionError(f"tools without result metadata: {missing_meta[:5]}")
            return {
                "profile": profile,
                "server": getattr(initialize.serverInfo, "name", ""),
                "toolCount": len(listing.tools),
                "successRequestId": success["meta"].get("requestId"),
                "invalidCode": invalid["error"].get("code"),
                "durationSeconds": round(time.monotonic() - started, 3),
            }


async def _run_all() -> list[dict[str, Any]]:
    results = []
    for profile in PROFILES:
        results.append(await _run_profile(profile))
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT / "tools" / "bin" / "release" / "result-contract-audit.json")
    args = parser.parse_args()
    started = time.time()
    try:
        profiles = anyio.run(_run_all)
        payload: dict[str, Any] = {
            "schemaVersion": 1,
            "contract": "envelope-v1",
            "ok": True,
            "profiles": profiles,
            "durationSeconds": round(time.time() - started, 3),
        }
    except Exception as exc:
        payload = {
            "schemaVersion": 1,
            "contract": "envelope-v1",
            "ok": False,
            "error": {"type": type(exc).__name__, "message": str(exc)},
            "durationSeconds": round(time.time() - started, 3),
        }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    digest = hashlib.sha256(args.out.read_bytes()).hexdigest().upper()
    print(json.dumps({"ok": payload["ok"], "report": str(args.out.resolve()), "sha256": digest}, ensure_ascii=False))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
