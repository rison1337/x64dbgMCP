"""Run the optional native injector with a private, explicit configuration."""

from __future__ import annotations

import configparser
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time


def run_injector(
    *, injector: str, hook: str, config: str, profile: str, pid: int,
    work_dir: str, timeout: float = 20.0,
) -> dict:
    """Apply exactly one profile to one PID; never rely on CLI exit code alone.

    Upstream InjectorCLI reads scylla_hide.ini beside its executable, not beside
    the hook DLL or from its working directory. Its exit status can also be zero
    after a failed injection. A private executable/INI pair and PID-bearing
    terminal output are therefore required for a successful result.
    """
    if pid <= 0:
        raise ValueError("A positive target PID is required")
    raw = Path(config).read_bytes()
    encoding = "utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
    parser = configparser.RawConfigParser(strict=False)
    parser.optionxform = str
    parser.read_string(raw.decode(encoding))
    if not parser.has_section(profile) or profile.upper() == "SETTINGS":
        raise ValueError(f"Unknown ScyllaHide profile: {profile}")
    settings_section = next((s for s in parser.sections() if s.upper() == "SETTINGS"), "SETTINGS")
    if not parser.has_section(settings_section):
        parser.add_section("SETTINGS")
    for key in list(parser[settings_section]):
        if key.lower() == "currentprofile":
            parser.remove_option(settings_section, key)
    parser.set(settings_section, "CurrentProfile", profile)
    # FillHookDllData enables NtContinue when either option is true. Incomplete
    # upstream profiles default KillAntiAttach to 1 even with NtContinueHook=0.
    # This combination reproduces an AV on continuation on current Windows.
    compatibility_overrides = {"NtContinueHook": "0", "KillAntiAttach": "0"}
    for option, value in compatibility_overrides.items():
        for key in list(parser[profile]):
            if key.lower() == option.lower():
                parser.remove_option(profile, key)
        parser.set(profile, option, value)

    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="scylla-injector-", dir=work_dir) as temporary:
        stage = Path(temporary)
        executable = Path(injector).resolve()
        staged_executable = stage / executable.name
        shutil.copy2(executable, staged_executable)
        for dependency in executable.parent.iterdir():
            if dependency.is_file() and (
                dependency.suffix.lower() == ".dll"
                or dependency.name.lower() in {"ntapicollection.ini", executable.name.lower() + ".manifest"}
            ):
                shutil.copy2(dependency, stage / dependency.name)
        staged_config = stage / "scylla_hide.ini"
        # The Win32 profile API natively understands UTF-16 with a BOM.
        with staged_config.open("w", encoding="utf-16", newline="\r\n") as stream:
            parser.write(stream, space_around_delimiters=False)
        config_sha256 = hashlib.sha256(staged_config.read_bytes()).hexdigest()
        command = [str(staged_executable), f"pid:{pid}", str(Path(hook).resolve()), "nowait"]
        timed_out = False
        try:
            completed = subprocess.run(
                command, cwd=stage, stdin=subprocess.DEVNULL, capture_output=True,
                text=True, errors="replace", timeout=timeout, check=False,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            stdout, stderr, returncode = completed.stdout, completed.stderr, completed.returncode
        except subprocess.TimeoutExpired as exc:
            def decoded(value):
                return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value or "")
            stdout, stderr, returncode = decoded(exc.stdout), decoded(exc.stderr), None
            timed_out = True
        log_path = stage / "scylla_hide.log"
        native_log = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""

    reported = re.search(r"(?im)^PID\s*:\s*(\d+)\b", stdout)
    pid_matches = bool(reported and int(reported.group(1)) == pid)
    hook_success = bool(re.search(r"(?im)^Hook injection successful\b", stdout))
    peb_success = bool(re.search(r"(?im)^PEB patch successful, hook injection not needed\b", stdout))
    ok = bool(not timed_out and returncode == 0 and pid_matches and (hook_success or peb_success))
    return {
        "ok": ok, "pid": pid, "profile": profile,
        "returncode": returncode, "timedOut": timed_out,
        "stdout": stdout.strip(), "stderr": stderr.strip(),
        "stdoutSuccess": bool(pid_matches and (hook_success or peb_success)),
        "hookInjected": bool(ok and hook_success), "pebPatched": bool(ok and peb_success),
        "protectionApplied": ok, "profileIsolated": True,
        "compatibilityOverrides": compatibility_overrides,
        "configurationSha256": config_sha256, "nativeLog": native_log,
        "elapsedMs": round((time.monotonic() - started) * 1000, 2),
        "error": None if ok else (
            "ScyllaHide injector timed out; success was not verified." if timed_out
            else "ScyllaHide injector did not confirm success for the requested PID."
        ),
    }
