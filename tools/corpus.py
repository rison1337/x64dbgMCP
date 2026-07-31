"""Build and validate the deterministic x64dbg MCP E2E fixture corpus.

The source fixtures are versioned under ``tests/fixtures/e2e``. Compiler
outputs and reports are intentionally confined to the already-ignored
``tools/bin/e2e`` tree.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = Path(__file__).with_name("corpus_manifest.json")
ALLOWED_ARCHITECTURES = {"x86", "x64"}
ALLOWED_KINDS = {"exe", "dll"}
ALLOWED_LANGUAGES = {"c", "cpp"}
ALLOWED_SIDE_EFFECTS = {
    "allocates-process-memory",
    "creates-child-process",
    "creates-kernel-event",
    "loads-local-test-dll",
    "loads-system-dll",
    "may-create-local-crash-report",
    "queries-screen-metrics",
    "raises-process-local-exception",
    "reads-cwd",
    "reads-environment",
    "resolves-system-exports",
    "rewrites-own-process-memory",
    "sleeps-under-5s",
    "writes-child-process-memory",
}
REQUIRED_SCENARIOS = {
    "launch-contract",
    "exception-disposition",
    "tls-seh-multistage",
    "deterministic-heap",
    "deterministic-api-trace",
    "dynamic-api-trace",
    "deterministic-coverage",
    "child-process",
    "hollow-host",
    "hollow-payload",
    "process-hollowing",
    "same-section-unpack",
    "custom-import-resolver",
    "execute-after-write",
    "comparison-key-recovery",
    "dll-module-provider",
    "manual-map-loader",
    "dll-module-imports",
}
MACHINE_BY_ARCH = {"x86": 0x014C, "x64": 0x8664}
MAX_RUNTIME_STDIN_BYTES = 4 * 1024 * 1024
MAX_RUNTIME_ORACLE_BYTES = 64 * 1024 * 1024


class CorpusValidationError(ValueError):
    """Raised when the manifest violates its schema or safety boundary."""


class CorpusBuildError(RuntimeError):
    """Raised when a compiler, linker, artifact, or runtime check fails."""


def load_manifest(path: Path | str = DEFAULT_MANIFEST) -> dict[str, Any]:
    manifest_path = Path(path).resolve()
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CorpusValidationError(f"cannot read manifest {manifest_path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise CorpusValidationError("manifest root must be an object")
    return payload


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _repo_path(value: str, repo_root: Path, field: str) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise CorpusValidationError(f"{field} must be a non-empty repository-relative path")
    resolved = (repo_root / value).resolve()
    if not _inside(resolved, repo_root.resolve()):
        raise CorpusValidationError(f"{field} escapes repository root: {value}")
    return resolved


def _string_list(value: Any, field: str, *, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        qualifier = "non-empty " if not allow_empty else ""
        raise CorpusValidationError(f"{field} must be a {qualifier}list")
    if any(not isinstance(item, str) or not item for item in value):
        raise CorpusValidationError(f"{field} must contain non-empty strings")
    return list(value)


def _decode_base64(value: Any, field: str, *, max_bytes: int) -> bytes:
    if not isinstance(value, str):
        raise CorpusValidationError(f"{field} must be a Base64 string")
    # Reject oversized values before decoding so an untrusted manifest cannot
    # force an avoidable large allocation in the corpus verifier.
    maximum_encoded_size = ((max_bytes + 2) // 3) * 4
    if len(value) > maximum_encoded_size:
        raise CorpusValidationError(f"{field} exceeds the {max_bytes}-byte limit")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CorpusValidationError(f"{field} is not strict Base64") from exc
    if len(decoded) > max_bytes:
        raise CorpusValidationError(f"{field} exceeds the {max_bytes}-byte limit")
    return decoded


def _decode_runtime_stdin(case: dict[str, Any], field: str) -> bytes | None:
    present = [name for name in ("stdinBase64", "stdinHex") if name in case]
    if len(present) > 1:
        raise CorpusValidationError(
            f"{field}.stdinBase64 and {field}.stdinHex are mutually exclusive"
        )
    if not present:
        return None
    if present[0] == "stdinBase64":
        return _decode_base64(
            case["stdinBase64"],
            f"{field}.stdinBase64",
            max_bytes=MAX_RUNTIME_STDIN_BYTES,
        )

    value = case["stdinHex"]
    if not isinstance(value, str):
        raise CorpusValidationError(f"{field}.stdinHex must be a hexadecimal string")
    if len(value) > MAX_RUNTIME_STDIN_BYTES * 2:
        raise CorpusValidationError(
            f"{field}.stdinHex exceeds the {MAX_RUNTIME_STDIN_BYTES}-byte limit"
        )
    if len(value) % 2 or re.fullmatch(r"[0-9A-Fa-f]*", value) is None:
        raise CorpusValidationError(
            f"{field}.stdinHex must contain an even number of hexadecimal digits"
        )
    return bytes.fromhex(value)


def _validate_runtime_stream_oracles(
    case: dict[str, Any], stream: str, field: str
) -> bool:
    title = stream.capitalize()
    contains_key = f"{stream}Contains"
    exact_key = f"{stream}Base64"
    digest_key = f"expected{title}Sha256"
    count_key = f"expected{title}ByteCount"

    contains = _string_list(case.get(contains_key, []), f"{field}.{contains_key}")
    exact = None
    if exact_key in case:
        exact = _decode_base64(
            case[exact_key],
            f"{field}.{exact_key}",
            max_bytes=MAX_RUNTIME_ORACLE_BYTES,
        )

    digest = case.get(digest_key)
    if digest is not None and (
        not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
    ):
        raise CorpusValidationError(f"{field}.{digest_key} must be lowercase SHA-256")

    count = case.get(count_key)
    if count is not None and (
        isinstance(count, bool)
        or not isinstance(count, int)
        or not 0 <= count <= MAX_RUNTIME_ORACLE_BYTES
    ):
        raise CorpusValidationError(
            f"{field}.{count_key} must be an integer in [0, {MAX_RUNTIME_ORACLE_BYTES}]"
        )

    if exact is not None:
        if digest is not None and hashlib.sha256(exact).hexdigest() != digest:
            raise CorpusValidationError(
                f"{field}.{digest_key} does not match {field}.{exact_key}"
            )
        if count is not None and len(exact) != count:
            raise CorpusValidationError(
                f"{field}.{count_key} does not match {field}.{exact_key}"
            )
    return bool(contains) or exact is not None or digest is not None or count is not None


def _observe_runtime_stream(
    case: dict[str, Any], stream: str, raw: bytes
) -> dict[str, Any]:
    title = stream.capitalize()
    text = raw.decode("utf-8", errors="replace")
    contains = case.get(f"{stream}Contains", [])
    missing = [marker for marker in contains if marker not in text]
    mismatches: list[str] = []

    exact_key = f"{stream}Base64"
    if exact_key in case:
        expected = _decode_base64(
            case[exact_key],
            exact_key,
            max_bytes=MAX_RUNTIME_ORACLE_BYTES,
        )
        if raw != expected:
            mismatches.append(f"{exact_key}:exact")

    digest = hashlib.sha256(raw).hexdigest()
    expected_digest = case.get(f"expected{title}Sha256")
    if expected_digest is not None and digest != expected_digest:
        mismatches.append(f"expected{title}Sha256")

    byte_count = len(raw)
    expected_count = case.get(f"expected{title}ByteCount")
    if expected_count is not None and byte_count != expected_count:
        mismatches.append(f"expected{title}ByteCount")

    return {
        "text": text,
        "base64": base64.b64encode(raw).decode("ascii"),
        "byteCount": byte_count,
        "sha256": digest,
        "missing": missing,
        "mismatches": mismatches,
    }


def _render_arch_path(template: str, arch: str, repo_root: Path, field: str) -> Path:
    if template.count("{arch}") != 1:
        raise CorpusValidationError(f"{field} must contain exactly one {{arch}} placeholder")
    try:
        rendered = template.format(arch=arch)
    except (KeyError, ValueError) as exc:
        raise CorpusValidationError(f"invalid template in {field}: {template}") from exc
    if "{" in rendered or "}" in rendered:
        raise CorpusValidationError(f"unsupported placeholder in {field}: {template}")
    return _repo_path(rendered, repo_root, field)


def _topological_ids(fixtures: list[dict[str, Any]]) -> list[str]:
    by_id = {item["id"]: item for item in fixtures}
    state: dict[str, int] = {}
    ordered: list[str] = []

    def visit(fixture_id: str) -> None:
        marker = state.get(fixture_id, 0)
        if marker == 1:
            raise CorpusValidationError(f"dependency cycle includes {fixture_id}")
        if marker == 2:
            return
        state[fixture_id] = 1
        for dependency in by_id[fixture_id]["build"].get("dependencies", []):
            if dependency not in by_id:
                raise CorpusValidationError(
                    f"fixture {fixture_id} references unknown dependency {dependency}"
                )
            visit(dependency)
        state[fixture_id] = 2
        ordered.append(fixture_id)

    for item in fixtures:
        visit(item["id"])
    return ordered


def validate_manifest(
    manifest: dict[str, Any], repo_root: Path | str = REPO_ROOT
) -> dict[str, Any]:
    root = Path(repo_root).resolve()
    if manifest.get("schemaVersion") != 1:
        raise CorpusValidationError("schemaVersion must be 1")
    if not isinstance(manifest.get("name"), str) or not manifest["name"].strip():
        raise CorpusValidationError("name must be a non-empty string")

    artifact_root_value = manifest.get("artifactRoot")
    artifact_root = _repo_path(artifact_root_value, root, "artifactRoot")
    permitted_artifact_root = (root / "tools" / "bin").resolve()
    if not _inside(artifact_root, permitted_artifact_root):
        raise CorpusValidationError("artifactRoot must stay below ignored tools/bin")

    support_files = _string_list(manifest.get("supportFiles", []), "supportFiles")
    for index, value in enumerate(support_files):
        path = _repo_path(value, root, f"supportFiles[{index}]")
        if not _inside(path, (root / "tests" / "fixtures" / "e2e").resolve()):
            raise CorpusValidationError(f"support file is outside tests/fixtures/e2e: {value}")
        if not path.is_file():
            raise CorpusValidationError(f"support file does not exist: {value}")

    fixtures = manifest.get("fixtures")
    if not isinstance(fixtures, list) or not fixtures:
        raise CorpusValidationError("fixtures must be a non-empty list")

    ids: set[str] = set()
    scenarios: set[str] = set()
    for fixture_index, fixture in enumerate(fixtures):
        prefix = f"fixtures[{fixture_index}]"
        if not isinstance(fixture, dict):
            raise CorpusValidationError(f"{prefix} must be an object")
        fixture_id = fixture.get("id")
        if not isinstance(fixture_id, str) or not re.fullmatch(r"[a-z][a-z0-9_]{1,63}", fixture_id):
            raise CorpusValidationError(f"{prefix}.id is invalid")
        if fixture_id in ids:
            raise CorpusValidationError(f"duplicate fixture id: {fixture_id}")
        ids.add(fixture_id)

        scenario = fixture.get("scenario")
        if not isinstance(scenario, str) or not re.fullmatch(r"[a-z][a-z0-9-]{2,63}", scenario):
            raise CorpusValidationError(f"{prefix}.scenario is invalid")
        if scenario in scenarios:
            raise CorpusValidationError(f"duplicate scenario: {scenario}")
        scenarios.add(scenario)
        if not isinstance(fixture.get("description"), str) or not fixture["description"].strip():
            raise CorpusValidationError(f"{prefix}.description must be non-empty")

        safety = fixture.get("safety")
        if not isinstance(safety, dict):
            raise CorpusValidationError(f"{prefix}.safety must be an object")
        if safety.get("classification") != "benign":
            raise CorpusValidationError(f"{fixture_id} must be classified benign")
        for field in ("requiresAdmin", "network", "dangerous"):
            if safety.get(field) is not False:
                raise CorpusValidationError(f"{fixture_id}.safety.{field} must be false")
        side_effects = _string_list(safety.get("sideEffects", []), f"{prefix}.safety.sideEffects")
        unknown_effects = sorted(set(side_effects) - ALLOWED_SIDE_EFFECTS)
        if unknown_effects:
            raise CorpusValidationError(
                f"{fixture_id} declares unsupported side effects: {unknown_effects}"
            )

        build = fixture.get("build")
        if not isinstance(build, dict):
            raise CorpusValidationError(f"{prefix}.build must be an object")
        kind = build.get("kind")
        language = build.get("language")
        if kind not in ALLOWED_KINDS:
            raise CorpusValidationError(f"{fixture_id}.build.kind must be exe or dll")
        if language not in ALLOWED_LANGUAGES:
            raise CorpusValidationError(f"{fixture_id}.build.language must be c or cpp")
        architectures = _string_list(
            build.get("architectures"), f"{prefix}.build.architectures", allow_empty=False
        )
        if len(architectures) != len(set(architectures)) or set(architectures) != ALLOWED_ARCHITECTURES:
            raise CorpusValidationError(f"{fixture_id} must build exactly x86 and x64")

        sources = _string_list(build.get("sources"), f"{prefix}.build.sources", allow_empty=False)
        source_root = (root / "tests" / "fixtures" / "e2e").resolve()
        expected_suffix = ".c" if language == "c" else ".cpp"
        for source_index, value in enumerate(sources):
            source = _repo_path(value, root, f"{prefix}.build.sources[{source_index}]")
            if not _inside(source, source_root):
                raise CorpusValidationError(f"fixture source is outside tests/fixtures/e2e: {value}")
            if source.suffix.lower() != expected_suffix or not source.is_file():
                raise CorpusValidationError(f"invalid or missing {language} source: {value}")

        output_template = build.get("output")
        if not isinstance(output_template, str):
            raise CorpusValidationError(f"{prefix}.build.output must be a string")
        expected_output_suffix = ".exe" if kind == "exe" else ".dll"
        for arch in architectures:
            output = _render_arch_path(output_template, arch, root, f"{prefix}.build.output")
            if not _inside(output, artifact_root) or output.suffix.lower() != expected_output_suffix:
                raise CorpusValidationError(f"invalid output path for {fixture_id}: {output}")

        dependencies = _string_list(
            build.get("dependencies", []), f"{prefix}.build.dependencies"
        )
        if len(dependencies) != len(set(dependencies)) or fixture_id in dependencies:
            raise CorpusValidationError(f"invalid dependencies for {fixture_id}")

        link_inputs = _string_list(build.get("linkInputs", []), f"{prefix}.build.linkInputs")
        for link_index, template in enumerate(link_inputs):
            for arch in architectures:
                link_input = _render_arch_path(
                    template, arch, root, f"{prefix}.build.linkInputs[{link_index}]"
                )
                if not _inside(link_input, artifact_root) or link_input.suffix.lower() != ".lib":
                    raise CorpusValidationError(f"invalid link input for {fixture_id}: {link_input}")

        if kind == "dll":
            import_library_template = build.get("importLibrary")
            if not isinstance(import_library_template, str):
                raise CorpusValidationError(f"{fixture_id} DLL requires importLibrary")
            for arch in architectures:
                import_library = _render_arch_path(
                    import_library_template, arch, root, f"{prefix}.build.importLibrary"
                )
                if not _inside(import_library, artifact_root) or import_library.suffix.lower() != ".lib":
                    raise CorpusValidationError(f"invalid import library for {fixture_id}")

        for metadata_field in ("expectedExports", "expectedImports"):
            _string_list(build.get(metadata_field, []), f"{prefix}.build.{metadata_field}")
        for flags_field in ("compileFlags", "linkFlags"):
            flags = _string_list(build.get(flags_field, []), f"{prefix}.build.{flags_field}")
            if any("\0" in flag or "\r" in flag or "\n" in flag for flag in flags):
                raise CorpusValidationError(
                    f"{prefix}.build.{flags_field} contains a control character"
                )

        runtime = fixture.get("runtime")
        if not isinstance(runtime, list):
            raise CorpusValidationError(f"{prefix}.runtime must be a list")
        if kind == "exe" and not runtime:
            raise CorpusValidationError(f"executable fixture {fixture_id} requires runtime cases")
        if kind == "dll" and runtime:
            raise CorpusValidationError(f"DLL fixture {fixture_id} must be verified through a host")

        runtime_names: set[str] = set()
        for case_index, case in enumerate(runtime):
            case_prefix = f"{prefix}.runtime[{case_index}]"
            if not isinstance(case, dict):
                raise CorpusValidationError(f"{case_prefix} must be an object")
            case_name = case.get("name")
            if not isinstance(case_name, str) or not re.fullmatch(r"[a-z][a-z0-9-]{2,63}", case_name):
                raise CorpusValidationError(f"{case_prefix}.name is invalid")
            if case_name in runtime_names:
                raise CorpusValidationError(f"duplicate runtime case {fixture_id}/{case_name}")
            runtime_names.add(case_name)
            arguments = case.get("args", [])
            if not isinstance(arguments, list) or any(
                not isinstance(argument, str) for argument in arguments
            ):
                raise CorpusValidationError(
                    f"{case_prefix}.args must be a list of strings"
                )
            expected_exit = case.get("expectedExitCode")
            if not isinstance(expected_exit, int) or not 0 <= expected_exit <= 0xFFFFFFFF:
                raise CorpusValidationError(f"{case_prefix}.expectedExitCode must be uint32")
            _decode_runtime_stdin(case, case_prefix)
            has_stdout_oracle = _validate_runtime_stream_oracles(
                case, "stdout", case_prefix
            )
            _validate_runtime_stream_oracles(case, "stderr", case_prefix)
            if not has_stdout_oracle:
                raise CorpusValidationError(
                    f"{case_prefix} requires at least one stdout oracle"
                )
            timeout = case.get("timeoutSeconds")
            if not isinstance(timeout, (int, float)) or not 0 < timeout <= 30:
                raise CorpusValidationError(f"{case_prefix}.timeoutSeconds must be in (0, 30]")
            environment = case.get("env", {})
            if not isinstance(environment, dict) or any(
                not isinstance(key, str) or not key or not isinstance(value, str)
                for key, value in environment.items()
            ):
                raise CorpusValidationError(f"{case_prefix}.env must map strings to strings")
            invalid_environment_keys = [
                key
                for key in environment
                if not re.fullmatch(r"X64DBG_MCP_E2E_[A-Z0-9_]+", key)
            ]
            if invalid_environment_keys:
                raise CorpusValidationError(
                    f"{case_prefix}.env contains non-corpus keys: {invalid_environment_keys}"
                )
            if "cwd" in case:
                cwd = _repo_path(case["cwd"], root, f"{case_prefix}.cwd")
                runtime_cwd_root = (root / "tests" / "fixtures" / "e2e" / "workdirs").resolve()
                if not cwd.is_dir() or not _inside(cwd, runtime_cwd_root):
                    raise CorpusValidationError(f"runtime cwd does not exist: {case['cwd']}")
            allow_crash = case.get("allowCrash", False)
            if not isinstance(allow_crash, bool):
                raise CorpusValidationError(f"{case_prefix}.allowCrash must be boolean")
            if allow_crash and (
                scenario != "exception-disposition" or expected_exit < 0x80000000
            ):
                raise CorpusValidationError("allowCrash is restricted to the exception fixture")

    missing_scenarios = sorted(REQUIRED_SCENARIOS - scenarios)
    if missing_scenarios:
        raise CorpusValidationError(f"required scenarios are missing: {missing_scenarios}")
    ordered_ids = _topological_ids(fixtures)
    return {
        "ok": True,
        "schemaVersion": 1,
        "fixtureCount": len(fixtures),
        "runtimeCaseCount": sum(len(item["runtime"]) for item in fixtures),
        "architectures": sorted(ALLOWED_ARCHITECTURES),
        "artifactRoot": str(artifact_root),
        "buildOrder": ordered_ids,
    }


def find_vsdevcmd() -> Path:
    candidates: list[Path] = []
    vs_install = os.environ.get("VSINSTALLDIR")
    if vs_install:
        candidates.append(Path(vs_install) / "Common7" / "Tools" / "VsDevCmd.bat")
    candidates.extend(
        [
            Path(r"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"),
            Path(r"C:\Program Files\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"),
            Path(r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"),
        ]
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()

    vswhere = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / (
        "Microsoft Visual Studio/Installer/vswhere.exe"
    )
    if vswhere.is_file():
        completed = subprocess.run(
            [
                str(vswhere),
                "-latest",
                "-products",
                "*",
                "-requires",
                "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                "-property",
                "installationPath",
            ],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        installation = completed.stdout.strip()
        candidate = Path(installation) / "Common7" / "Tools" / "VsDevCmd.bat"
        if completed.returncode == 0 and candidate.is_file():
            return candidate.resolve()
    raise CorpusBuildError("Visual Studio 2022 C++ toolchain was not found")


def capture_msvc_environment(vsdevcmd: Path, arch: str) -> dict[str, str]:
    if arch not in ALLOWED_ARCHITECTURES:
        raise CorpusBuildError(f"unsupported architecture: {arch}")
    command_arch = "x86" if arch == "x86" else "x64"
    comspec = os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe")
    script_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".cmd",
            prefix="x64dbg_mcp_corpus_",
            encoding="utf-8",
            newline="",
            delete=False,
        ) as script:
            script.write("@echo off\r\n")
            script.write(
                f'call "{vsdevcmd}" -no_logo -arch={command_arch} -host_arch=x64 >nul\r\n'
            )
            script.write("if errorlevel 1 exit /b %errorlevel%\r\n")
            script.write("set\r\n")
            script_path = Path(script.name)
        completed = subprocess.run(
            [comspec, "/d", "/u", "/c", str(script_path)],
            check=False,
            capture_output=True,
        )
    finally:
        if script_path is not None:
            script_path.unlink(missing_ok=True)
    stdout = completed.stdout.decode("utf-16le", errors="replace")
    stderr = completed.stderr.decode("utf-16le", errors="replace")
    if completed.returncode != 0:
        raise CorpusBuildError(
            f"VsDevCmd failed for {arch} with {completed.returncode}: {stderr.strip()}"
        )
    environment = dict(os.environ)
    for line in stdout.splitlines():
        if "=" in line and not line.startswith("="):
            key, value = line.split("=", 1)
            environment[key] = value
    path_value = environment.get("Path") or environment.get("PATH") or ""
    if shutil.which("cl.exe", path=path_value) is None:
        raise CorpusBuildError(f"cl.exe is missing from the {arch} MSVC environment")
    return environment


def _tool(environment: dict[str, str], name: str) -> str:
    path_value = environment.get("Path") or environment.get("PATH") or ""
    resolved = shutil.which(name, path=path_value)
    if resolved is None:
        raise CorpusBuildError(f"required MSVC tool not found: {name}")
    return resolved


def _run_build_command(
    command: list[str], environment: dict[str, str], cwd: Path, label: str
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=str(cwd),
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode != 0:
        rendered = subprocess.list2cmdline(command)
        raise CorpusBuildError(
            f"{label} failed with {completed.returncode}\n"
            f"command: {rendered}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _manifest_digest(manifest: dict[str, Any], manifest_path: Path | str | None) -> str:
    if manifest_path is not None:
        path = Path(manifest_path).resolve()
        if path.is_file():
            return _sha256(path)
    encoded = json.dumps(
        manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest().upper()


def _source_hashes(manifest: dict[str, Any], repo_root: Path) -> dict[str, str]:
    values = set(manifest.get("supportFiles", []))
    for fixture in manifest["fixtures"]:
        values.update(fixture["build"]["sources"])
    return {
        value: _sha256(_repo_path(value, repo_root, "corpus source"))
        for value in sorted(values)
    }


def inspect_pe(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise CorpusBuildError(f"not a DOS/PE image: {path}")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise CorpusBuildError(f"invalid PE signature: {path}")
    machine, section_count = struct.unpack_from("<HH", data, pe_offset + 4)
    optional_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    characteristics = struct.unpack_from("<H", data, pe_offset + 22)[0]
    optional_header = pe_offset + 24
    if optional_header_size < 72 or optional_header + optional_header_size > len(data):
        raise CorpusBuildError(f"invalid optional header: {path}")
    optional_magic = struct.unpack_from("<H", data, optional_header)[0]
    if optional_magic not in {0x10B, 0x20B}:
        raise CorpusBuildError(f"unsupported optional header magic in {path}")
    dll_characteristics = struct.unpack_from("<H", data, optional_header + 70)[0]
    return {
        "machine": machine,
        "machineHex": f"0x{machine:04X}",
        "sections": section_count,
        "kind": "dll" if characteristics & 0x2000 else "exe",
        "mitigations": {
            "dynamicBase": bool(dll_characteristics & 0x0040),
            "nxCompat": bool(dll_characteristics & 0x0100),
            "guardCf": bool(dll_characteristics & 0x4000),
        },
        "size": len(data),
        "sha256": _sha256(path),
    }


def _dumpbin_text(
    path: Path, option: str, environment: dict[str, str]
) -> str:
    completed = _run_build_command(
        [_tool(environment, "dumpbin.exe"), "/NOLOGO", option, str(path)],
        environment,
        path.parent,
        f"dumpbin {option} {path.name}",
    )
    return completed.stdout


def _verify_declared_metadata(
    fixture: dict[str, Any], path: Path, environment: dict[str, str]
) -> dict[str, list[str]]:
    build = fixture["build"]
    exports = build.get("expectedExports", [])
    imports = build.get("expectedImports", [])
    result = {"exports": list(exports), "imports": list(imports)}
    if exports:
        text = _dumpbin_text(path, "/EXPORTS", environment).lower()
        missing = [name for name in exports if name.lower() not in text]
        if missing:
            raise CorpusBuildError(f"{path.name} is missing declared exports: {missing}")
    if imports:
        text = _dumpbin_text(path, "/IMPORTS", environment).lower()
        missing = [name for name in imports if name.lower() not in text]
        if missing:
            raise CorpusBuildError(f"{path.name} is missing declared imports: {missing}")
    return result


def _fixture_by_id(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {fixture["id"]: fixture for fixture in manifest["fixtures"]}


def _artifact_path(
    fixture: dict[str, Any], arch: str, repo_root: Path
) -> Path:
    return _render_arch_path(
        fixture["build"]["output"], arch, repo_root, f"{fixture['id']}.build.output"
    )


def _build_one(
    fixture: dict[str, Any], arch: str, repo_root: Path, environment: dict[str, str]
) -> dict[str, Any]:
    build = fixture["build"]
    output = _artifact_path(fixture, arch, repo_root)
    output.parent.mkdir(parents=True, exist_ok=True)
    object_root = output.parent / ".obj" / fixture["id"]
    object_root.mkdir(parents=True, exist_ok=True)
    cl = _tool(environment, "cl.exe")
    objects: list[Path] = []
    compile_mode = "/TC" if build["language"] == "c" else "/TP"
    standard = "/std:c11" if build["language"] == "c" else "/std:c++20"

    for index, source_value in enumerate(build["sources"]):
        source = _repo_path(source_value, repo_root, f"{fixture['id']}.source")
        obj = object_root / f"{index:02d}_{source.stem}.obj"
        command = [
            cl,
            "/nologo",
            "/c",
            compile_mode,
            standard,
            "/utf-8",
            "/W4",
            "/WX",
            "/O2",
            "/GS",
            "/guard:cf",
            "/Brepro",
            "/D_CRT_SECURE_NO_WARNINGS",
            f"/Fo{obj}",
            str(source),
        ]
        command.extend(build.get("compileFlags", []))
        _run_build_command(command, environment, repo_root, f"compile {fixture['id']} {arch}")
        objects.append(obj)

    link_inputs = [
        _render_arch_path(value, arch, repo_root, f"{fixture['id']}.linkInputs")
        for value in build.get("linkInputs", [])
    ]
    missing_inputs = [str(path) for path in link_inputs if not path.is_file()]
    if missing_inputs:
        raise CorpusBuildError(f"missing link inputs for {fixture['id']}: {missing_inputs}")

    command = [cl, "/nologo"]
    if build["kind"] == "dll":
        command.append("/LD")
    command.extend(str(path) for path in objects)
    command.extend(str(path) for path in link_inputs)
    command.append(f"/Fe{output}")
    command.extend(
        [
            "/link",
            "/NOLOGO",
            "/INCREMENTAL:NO",
            "/DYNAMICBASE",
            "/NXCOMPAT",
            "/GUARD:CF",
            "/Brepro",
            "/OPT:REF",
            "/OPT:ICF",
        ]
    )
    if build["kind"] == "exe":
        command.append("/SUBSYSTEM:CONSOLE")
    else:
        import_library = _render_arch_path(
            build["importLibrary"], arch, repo_root, f"{fixture['id']}.importLibrary"
        )
        command.append(f"/IMPLIB:{import_library}")
    command.extend(build.get("linkFlags", []))
    _run_build_command(command, environment, output.parent, f"link {fixture['id']} {arch}")

    if not output.is_file():
        raise CorpusBuildError(f"linker did not create {output}")
    pe = inspect_pe(output)
    if pe["machine"] != MACHINE_BY_ARCH[arch] or pe["kind"] != build["kind"]:
        raise CorpusBuildError(
            f"artifact metadata mismatch for {output}: machine={pe['machineHex']} kind={pe['kind']}"
        )
    if not all(pe["mitigations"].values()):
        raise CorpusBuildError(
            f"artifact mitigations are incomplete for {output}: {pe['mitigations']}"
        )
    metadata = _verify_declared_metadata(fixture, output, environment)
    return {
        "fixture": fixture["id"],
        "scenario": fixture["scenario"],
        "arch": arch,
        "path": str(output),
        **pe,
        **metadata,
    }


def _selected_architectures(value: str | Iterable[str]) -> list[str]:
    if isinstance(value, str):
        requested = sorted(ALLOWED_ARCHITECTURES) if value == "all" else [value]
    else:
        requested = list(value)
    if not requested or any(item not in ALLOWED_ARCHITECTURES for item in requested):
        raise CorpusBuildError(f"invalid architecture selection: {requested}")
    return requested


def build_corpus(
    manifest: dict[str, Any],
    architectures: str | Iterable[str] = "all",
    *,
    repo_root: Path | str = REPO_ROOT,
    clean: bool = False,
    manifest_path: Path | str | None = None,
) -> dict[str, Any]:
    root = Path(repo_root).resolve()
    validation = validate_manifest(manifest, root)
    selected = _selected_architectures(architectures)
    artifact_root = Path(validation["artifactRoot"])
    if clean and artifact_root.exists():
        permitted = (root / "tools" / "bin" / "e2e").resolve()
        if artifact_root.resolve() != permitted:
            raise CorpusBuildError(f"refusing to clean unexpected path: {artifact_root}")
        shutil.rmtree(artifact_root)

    vsdevcmd = find_vsdevcmd()
    environments = {
        arch: capture_msvc_environment(vsdevcmd, arch) for arch in selected
    }
    by_id = _fixture_by_id(manifest)
    artifacts: list[dict[str, Any]] = []
    for arch in selected:
        for fixture_id in validation["buildOrder"]:
            fixture = by_id[fixture_id]
            if arch in fixture["build"]["architectures"]:
                artifacts.append(_build_one(fixture, arch, root, environments[arch]))

    report = {
        "ok": True,
        "manifest": str(Path(manifest_path).resolve()) if manifest_path is not None else "<in-memory>",
        "manifestSha256": _manifest_digest(manifest, manifest_path),
        "sourceSha256": _source_hashes(manifest, root),
        "toolchain": str(vsdevcmd),
        "architectures": selected,
        "artifactCount": len(artifacts),
        "artifacts": artifacts,
    }
    artifact_root.mkdir(parents=True, exist_ok=True)
    report_path = artifact_root / "corpus_build.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    report["reportPath"] = str(report_path)
    return report


def _normalize_exit_code(return_code: int) -> int:
    return return_code & 0xFFFFFFFF


def verify_corpus(
    manifest: dict[str, Any],
    architectures: str | Iterable[str] = "all",
    *,
    repo_root: Path | str = REPO_ROOT,
    manifest_path: Path | str | None = None,
) -> dict[str, Any]:
    root = Path(repo_root).resolve()
    validation = validate_manifest(manifest, root)
    selected = _selected_architectures(architectures)
    artifact_root = Path(validation["artifactRoot"])
    build_report_path = artifact_root / "corpus_build.json"
    if not build_report_path.is_file():
        raise CorpusBuildError(f"build report does not exist; build first: {build_report_path}")
    try:
        build_report = json.loads(build_report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CorpusBuildError(f"cannot read build report {build_report_path}: {exc}") from exc
    current_manifest_hash = _manifest_digest(manifest, manifest_path)
    if build_report.get("manifestSha256") != current_manifest_hash:
        raise CorpusBuildError("build report manifest hash does not match the current manifest")
    current_source_hashes = _source_hashes(manifest, root)
    if build_report.get("sourceSha256") != current_source_hashes:
        raise CorpusBuildError("fixture sources changed after the recorded build")
    recorded_hashes = {
        (item.get("fixture"), item.get("arch")): item.get("sha256")
        for item in build_report.get("artifacts", [])
        if isinstance(item, dict)
    }
    vsdevcmd = find_vsdevcmd()
    environments = {
        arch: capture_msvc_environment(vsdevcmd, arch) for arch in selected
    }
    results: list[dict[str, Any]] = []
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    for arch in selected:
        for fixture in manifest["fixtures"]:
            if arch not in fixture["build"]["architectures"]:
                continue
            artifact = _artifact_path(fixture, arch, root)
            if not artifact.is_file():
                raise CorpusBuildError(f"artifact does not exist; build first: {artifact}")
            pe = inspect_pe(artifact)
            if pe["machine"] != MACHINE_BY_ARCH[arch] or pe["kind"] != fixture["build"]["kind"]:
                raise CorpusBuildError(f"artifact metadata mismatch: {artifact}")
            if not all(pe["mitigations"].values()):
                raise CorpusBuildError(
                    f"artifact mitigations are incomplete for {artifact}: {pe['mitigations']}"
                )
            expected_hash = recorded_hashes.get((fixture["id"], arch))
            if expected_hash is None or pe["sha256"] != expected_hash:
                raise CorpusBuildError(
                    f"artifact hash does not match build report: {artifact}"
                )
            _verify_declared_metadata(fixture, artifact, environments[arch])

            for case in fixture["runtime"]:
                # Corpus variables are deliberately isolated from the parent
                # process.  This makes absent/empty environment-value oracles
                # deterministic even when a developer has stale E2E values in
                # their interactive shell.
                environment = {
                    key: value
                    for key, value in os.environ.items()
                    if not key.upper().startswith("X64DBG_MCP_E2E_")
                }
                environment.update(case.get("env", {}))
                cwd = (
                    _repo_path(case["cwd"], root, f"{fixture['id']}.{case['name']}.cwd")
                    if "cwd" in case
                    else artifact.parent
                )
                stdin = _decode_runtime_stdin(
                    case, f"{fixture['id']}.{case['name']}"
                )
                try:
                    completed = subprocess.run(
                        [str(artifact), *case.get("args", [])],
                        cwd=str(cwd),
                        env=environment,
                        input=stdin,
                        check=False,
                        capture_output=True,
                        timeout=float(case["timeoutSeconds"]),
                        creationflags=creation_flags,
                    )
                except subprocess.TimeoutExpired as exc:
                    raise CorpusBuildError(
                        f"runtime case timed out: {fixture['id']}/{case['name']}/{arch}"
                    ) from exc
                actual_exit = _normalize_exit_code(completed.returncode)
                stdout = _observe_runtime_stream(case, "stdout", completed.stdout)
                stderr = _observe_runtime_stream(case, "stderr", completed.stderr)
                output_mismatches = [
                    *(f"stdout:{item}" for item in stdout["mismatches"]),
                    *(f"stderr:{item}" for item in stderr["mismatches"]),
                ]
                ok = (
                    actual_exit == case["expectedExitCode"]
                    and not stdout["missing"]
                    and not stderr["missing"]
                    and not output_mismatches
                )
                result = {
                    "fixture": fixture["id"],
                    "scenario": fixture["scenario"],
                    "case": case["name"],
                    "arch": arch,
                    "ok": ok,
                    "exitCode": actual_exit,
                    "expectedExitCode": case["expectedExitCode"],
                    "stdinByteCount": 0 if stdin is None else len(stdin),
                    "stdinSha256": None if stdin is None else hashlib.sha256(stdin).hexdigest(),
                    "missingStdout": stdout["missing"],
                    "missingStderr": stderr["missing"],
                    "outputMismatches": output_mismatches,
                    "stdout": stdout["text"],
                    "stderr": stderr["text"],
                    "stdoutBase64": stdout["base64"],
                    "stderrBase64": stderr["base64"],
                    "stdoutByteCount": stdout["byteCount"],
                    "stderrByteCount": stderr["byteCount"],
                    "stdoutSha256": stdout["sha256"],
                    "stderrSha256": stderr["sha256"],
                }
                results.append(result)
                if not ok:
                    raise CorpusBuildError(
                        "runtime verification failed: "
                        f"{fixture['id']}/{case['name']}/{arch}: "
                        f"exit={actual_exit} expected={case['expectedExitCode']} "
                        f"missingStdout={stdout['missing']} "
                        f"missingStderr={stderr['missing']} "
                        f"mismatches={output_mismatches} "
                        f"stdoutSha256={stdout['sha256']} "
                        f"stderrSha256={stderr['sha256']}"
                    )

    report = {
        "ok": True,
        "architectures": selected,
        "caseCount": len(results),
        "validation": validation,
        "results": results,
    }
    artifact_root.mkdir(parents=True, exist_ok=True)
    report_path = artifact_root / "corpus_verify.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    report["reportPath"] = str(report_path)
    return report


def _json_summary(payload: dict[str, Any], verbose: bool) -> dict[str, Any]:
    if verbose:
        return payload
    summary = {key: value for key, value in payload.items() if key not in {"artifacts", "results"}}
    if "artifacts" in payload:
        summary["artifacts"] = [
            {
                key: item[key]
                for key in ("fixture", "arch", "path", "size", "sha256")
                if key in item
            }
            for item in payload["artifacts"]
        ]
    if "results" in payload:
        summary["results"] = [
            {
                key: item[key]
                for key in ("fixture", "case", "arch", "ok", "exitCode")
                if key in item
            }
            for item in payload["results"]
        ]
    return summary


def _write_json(payload: dict[str, Any]) -> None:
    rendered = json.dumps(payload, ensure_ascii=False, indent=2)
    binary_stdout = getattr(sys.stdout, "buffer", None)
    if binary_stdout is not None:
        binary_stdout.write(rendered.encode("utf-8") + b"\n")
        binary_stdout.flush()
    else:
        sys.stdout.write(rendered + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--verbose", action="store_true")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("validate", help="validate schema, safety and source paths")
    for name in ("build", "verify", "all"):
        command = subparsers.add_parser(name)
        command.add_argument("--arch", choices=["all", "x86", "x64"], default="all")
        if name in {"build", "all"}:
            command.add_argument("--clean", action="store_true")

    args = parser.parse_args(argv)
    try:
        manifest_path = args.manifest.resolve()
        manifest = load_manifest(manifest_path)
        if args.command == "validate":
            payload = validate_manifest(manifest, REPO_ROOT)
        elif args.command == "build":
            payload = build_corpus(
                manifest,
                args.arch,
                repo_root=REPO_ROOT,
                clean=bool(args.clean),
                manifest_path=manifest_path,
            )
        elif args.command == "verify":
            payload = verify_corpus(
                manifest,
                args.arch,
                repo_root=REPO_ROOT,
                manifest_path=manifest_path,
            )
        else:
            build = build_corpus(
                manifest,
                args.arch,
                repo_root=REPO_ROOT,
                clean=bool(args.clean),
                manifest_path=manifest_path,
            )
            verification = verify_corpus(
                manifest,
                args.arch,
                repo_root=REPO_ROOT,
                manifest_path=manifest_path,
            )
            payload = {"ok": True, "build": build, "verification": verification}
    except (CorpusValidationError, CorpusBuildError) as exc:
        _write_json({"ok": False, "error": str(exc)})
        return 1
    _write_json(_json_summary(payload, bool(args.verbose)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
