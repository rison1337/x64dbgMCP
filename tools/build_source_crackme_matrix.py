"""Build a source-auditable Windows crackme matrix for x64dbg live tests."""

from __future__ import annotations

import hashlib
import json
import importlib.util
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = (
    REPO_ROOT
    / "Files_to_updates"
    / "source_crack_me"
    / "crackmes-master"
)
OUTPUT_ROOT = REPO_ROOT / "tools" / "bin" / "source_crackmes"
SAMPLES = ("crackme01", "crackme06", "crackme07", "crackme08")


def _load_corpus():
    path = REPO_ROOT / "tools" / "corpus.py"
    spec = importlib.util.spec_from_file_location("source_matrix_corpus", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _adapt_source(source: Path, sample: str, directory: Path) -> Path:
    if sample != "crackme08":
        return source
    # crackme08 is intentionally kept untouched in Files_to_updates.  This
    # temporary adapter only replaces GCC's cpuid.h helper with the equivalent
    # MSVC intrinsic so the original runtime algorithm remains identical.
    text = source.read_text(encoding="utf-8")
    text = text.replace("#include <cpuid.h>", "#include <intrin.h>")
    text = text.replace(
        "__get_cpuid(0, &eax, &ebx, &ecx, &edx);",
        (
            "int cpuid_regs[4]; __cpuid(cpuid_regs, 0); "
            "eax = (unsigned int)cpuid_regs[0]; "
            "ebx = (unsigned int)cpuid_regs[1]; "
            "ecx = (unsigned int)cpuid_regs[2]; "
            "edx = (unsigned int)cpuid_regs[3];"
        ),
    )
    adapted = directory / source.name
    adapted.write_text(text, encoding="utf-8")
    return adapted


def _build(
    arch: str,
    sample: str,
    environment: dict[str, str],
    cl: str,
) -> dict[str, object]:
    source = SOURCE_ROOT / f"{sample}.c"
    output = OUTPUT_ROOT / arch / f"{sample}.exe"
    if not source.is_file() or source.parent.resolve() != SOURCE_ROOT.resolve():
        raise RuntimeError(f"missing or escaped source: {source}")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_root = Path(tempfile.mkdtemp(prefix=f"x64dbg_source_{sample}_"))
    adapted = _adapt_source(source, sample, temporary_root)
    if arch == "x64":
        compiler = Path(r"C:\msys64\ucrt64\bin\gcc.exe")
        if not compiler.is_file():
            compiler_path = shutil.which("gcc")
            compiler = Path(compiler_path) if compiler_path else compiler
        if not compiler.is_file():
            raise RuntimeError(f"missing x64 GCC compiler: {compiler}")
        command = [
            str(compiler),
            "-std=gnu11",
            "-O1",
            "-fno-builtin",
            "-fno-stack-protector",
            "-D__USE_MINGW_ANSI_STDIO=1",
            str(source),
            "-o",
            str(output),
            "-Wl,--dynamicbase",
            "-Wl,--nxcompat",
        ]
        compiler_label = str(compiler)
        adapter_path = None
    else:
        command = [
            cl,
            "/nologo",
            "/TC",
            "/O1",
            "/GS-",
            "/D_CRT_SECURE_NO_WARNINGS",
            f"/Fe{output}",
            str(adapted),
            "/link",
            "/INCREMENTAL:NO",
            "/DYNAMICBASE",
            "/NXCOMPAT",
            "/SUBSYSTEM:CONSOLE",
        ]
        compiler_label = str(cl)
        adapter_path = str(adapted) if adapted != source else None
    completed = subprocess.run(
        command,
        cwd=str(output.parent),
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0 or not output.is_file():
        raise RuntimeError(
            f"{arch}/{sample} compile failed ({completed.returncode})\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return {
        "arch": arch,
        "sample": sample,
        "source": str(source),
        "sourceSha256": _sha256(source),
        "output": str(output),
        "outputSha256": _sha256(output),
        "size": output.stat().st_size,
        "compiler": compiler_label,
        "command": command,
        "adapter": adapter_path,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def main() -> int:
    report: dict[str, object] = {
        "schema": "source-crackme-build-v1",
        "ok": False,
        "sourceRoot": str(SOURCE_ROOT),
        "outputRoot": str(OUTPUT_ROOT),
        "artifacts": [],
    }
    try:
        corpus = _load_corpus()
        vsdevcmd = corpus.find_vsdevcmd()
        environments = {
            arch: corpus.capture_msvc_environment(vsdevcmd, arch)
            for arch in ("x64", "x86")
        }
        compilers = {
            arch: corpus._tool(environments[arch], "cl.exe")
            for arch in ("x64", "x86")
        }
        artifacts = [
            _build(arch, sample, environments[arch], compilers[arch])
            for arch in ("x64", "x86")
            for sample in SAMPLES
        ]
        report["artifacts"] = artifacts
        report["artifactCount"] = len(artifacts)
        report["ok"] = True
    except Exception as exc:
        report["error"] = str(exc)
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    output = OUTPUT_ROOT / "build_report.json"
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
