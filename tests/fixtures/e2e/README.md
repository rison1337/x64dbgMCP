# Deterministic E2E fixture corpus

This directory contains benign Windows fixtures used to verify x64dbg MCP
debugging contracts. Source files are versioned; binaries, objects, import
libraries, and build reports are generated below the ignored
`tools/bin/e2e` directory.

The authoritative fixture list, inputs, expected exit codes, stdout markers,
architectures, dependency graph, and safety declarations live in
`tools/corpus_manifest.json`.

## Commands

Run from the repository root with Python 3.10 or newer:

```powershell
python tools/corpus.py validate
python tools/corpus.py build --arch all --clean
python tools/corpus.py verify --arch all
python tools/corpus.py all --arch all --clean
```

`validate` performs no builds or launches. `build` discovers the Visual Studio
2022 x86/x64 C++ toolchain, compiles with warnings-as-errors and modern PE
mitigations, validates machine type, and verifies declared imports/exports.
`verify` runs only manifest-declared local cases with a timeout and checks their
normalized Windows exit code and output markers.

The separate authorized source-crackme matrix is built and exercised with:

```powershell
python tools/build_source_crackme_matrix.py --arch all
python tools/run_source_crackme_live_gate.py --arch all
```

It uses only source-backed samples from
`Files_to_updates/source_crack_me` (crackme01, crackme06, crackme07 and
crackme08). The gate records when a compiler inlines the CRT comparator instead
of claiming a false API-trace result, and every recovered candidate must pass
an independent process oracle.

For an IDA-side dry-run plan, provide the runtime artifact and the matching IDA
image identity (`sha256`, `arch`, `imageBase`):

```powershell
python tools/ida_evidence_coordinator.py `
  --runtime runtime-evidence.json `
  --ida-image ida-image.json
```

## Fixtures

| Fixture | Contract |
| --- | --- |
| `launch_contract` | Unicode argv, cwd, environment, intentional exit code |
| `exception_disposition` | SEH-handled, VEH-continued first chance, unhandled second chance, and exact/masked/wildcard policy precedence |
| `tls_seh_multistage` | Static TLS process-attach callback that raises and handles one deterministic first-chance SEH exception before `main` |
| `deterministic_heap` | Known alloc/realloc/free lifecycle with checkpoint |
| `deterministic_api_trace` | Known Win32 API call order and return values |
| `deterministic_coverage` | Exported branch functions and logical path ground truth |
| `child_process` | Same-architecture child creation, observation, and exit; optional `--graph-root`/`--graph-node` fan-out and nested cross-architecture broker scenarios |
| `hollow_host` | Benign original-image control used by the hollowing fixture |
| `hollow_payload` | CRT-free replacement image with a deterministic marker and exit code 42 |
| `process_hollowing` | Replaces a suspended initialized child image, redirects its main thread, and verifies replacement execution |
| `same_section_unpack` | Rewrites a compiled function in the same executable section and transfers to the restored code |
| `custom_import_resolver` | Resolves seven FNV-1a keyed exports without a static import directory and calls through the populated table |
| `execute_after_write` | Writes four deterministic machine-code bytes into an exported executable buffer and executes the changed entry byte |
| `key_recovery` | Direct ANSI, single-byte-XOR and UTF-16 comparison candidates with independent success oracles |
| `fixture_module` | DLL with three deterministic exports |
| `manual_map_loader` | Relocates/import-fixes/initializes a DLL in private memory, executes an export, optionally destroys headers, and exposes an embedded reflective-image mode |
| `module_imports` | Normal PE imports from `fixture_module.dll` |

No fixture requires elevation or network access. The unhandled exception is
deliberately limited to its own short-lived process and uses a private test
exception code. The corpus does not include or execute the anti-analysis PoCs
under `Files_to_updates`.
