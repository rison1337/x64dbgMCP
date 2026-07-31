# Contributing

Thanks for your interest in improving **x64dbg MCP**!

## Project layout

| Path | What it is |
|------|-----------|
| `src/MCPx64dbg.cpp` | The x64dbg/x32dbg plugin exposing the local HTTP bridge. |
| `src/exception_policy_core.*` | Pure exception rule, continuation, retention, and cursor logic shared with native tests. |
| `src/x64dbg.py` | The MCP server and direct CLI wrapper. |
| `src/ext_tools.py` | Higher-level reverse-engineering workflow tools. |
| `src/mcp_stdio_launcher.py` | Stdio launcher for desktop MCP clients. |
| `tests/` | Unit tests (no debugger or network required). |
| `tools/` | Live smoke harnesses. |

## Development setup

Windows + Python 3.10+.

```powershell
pip install -r requirements.txt
```

## Building the plugin

```powershell
cmake -S . -B build
cmake --build build --target all_plugins --config Release
```

The plugin SDK is fetched automatically (`-DX64DBG_DOWNLOAD_SDK=ON` is the
default). Copy the built `MCPx64dbg.dp64` / `MCPx64dbg.dp32` into the
`x64\plugins` and `x32\plugins` directories of your own x64dbg installation.

## Running tests

```powershell
python -m pytest -q
python tools/corpus.py all --arch all
```

Every registered MCP tool is exposed through the `envelope-v1` result
contract: `{ok, data, error, meta}`. Add or update a contract test for new
failure paths; do not return an `Error NNN: ...` string from a public tool.
Internal `safe_get`/`safe_post` callers may use the documented legacy shim while
they are migrated, but the FastMCP manager and CLI boundary must remain
canonical.

Run the complete stdio/profile audit locally with:

```powershell
python tools\run_result_contract_audit.py
```

Native transport/parser changes additionally require the deterministic parser
unit/property suite in both architectures and the live framing gate:

```powershell
cmake --build build-codex-vs2022\build64 --config Release --target bridge_core_native_tests
cmake --build build-codex-vs2022\build32 --config Release --target bridge_core_native_tests
python tools\run_live_release_matrix.py --arch all --case http_parser_adversarial

# Bounded dispatcher, FIFO admission, responsiveness and overload cleanup
python tools\run_live_release_matrix.py --arch all --case dispatcher_concurrency
```

The typed launch contract has dedicated native and live gates. Build/run both
architectures before changing launch or stream code:

```powershell
& .\build\p0-x64\Release\bridge_core_native_tests.exe
& .\build\p0-x64\Release\launch_runtime_native_tests.exe
& .\build\p0-x86\Release\bridge_core_native_tests.exe
& .\build\p0-x86\Release\launch_runtime_native_tests.exe
python tools\run_live_release_matrix.py --arch all `
  --case launch_argv_env_cwd `
  --case launch_bytes_stdio `
  --case launch_pipe_stdio `
  --case launch_file_stdio `
  --case launch_bounded_burst `
  --case launch_explicit_inherit
```

Unit tests monkeypatch the bridge, so they need neither a debugger nor a network
and are safe to run in CI. Live smoke scenarios (require a running x64dbg + a
target binary):

```powershell
python tools/headless_smoke.py --scenario self_check
```

Changes to exception disposition or history must also build and run
`bridge_core_native_tests` for both architectures, then pass the dedicated live
matrix without skips:

```powershell
cmake --build build\p0-x64 --config Release --target bridge_core_native_tests MCPx64dbg
cmake --build build\p0-x86 --config Release --target bridge_core_native_tests MCPx64dbg
python tools\run_live_release_matrix.py --arch all `
  --case exception_policy_first_chance `
  --case exception_policy_precedence `
  --case exception_policy_second_chance `
  --case exception_policy_lifecycle
```

The debugger lifecycle gate is intentionally separate and must be run on a
quiet desktop (no pre-existing x32dbg/x64dbg instance). It performs 100 fresh
launch/close cycles per architecture, samples `GetProcessHandleCount`, and
audits PID+creation-time identities after every close:

```powershell
python tools\run_debugger_lifecycle_audit.py --arch all --cycles 100
```

Session identity and transactional-write changes must also pass the
adversarial CAS gate on both debugger architectures:

```powershell
python tools\run_live_release_matrix.py --arch all --case session_identity_cas
```

The gate covers missing/stale bridge, session, SHA-256, and event guards,
same-path replacement, session turnover, and an intent-gated forced readback
failure that must restore the original bytes. The fault-injection header is a
test harness contract only; do not expose or enable it in normal clients.

The optional virtualization-research work is currently deferred. Keep
experimental anti-analysis fixtures outside the normal MCP build and test
paths; the repository intentionally ships only the supported runtime backend
and its benign test corpus.

## Coding conventions

- Match the surrounding style.
- New MCP tools should return a structured `dict` with an `ok` field and carry a
  clear docstring (Parameters / Returns). MCP clients surface docstrings to the
  model, so docstring quality directly affects usability.
- For side-effecting tools that wrap a raw x64dbg command, prefer the shared
  `_exec_command_action` helper so behaviour and error shapes stay consistent.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/) — `feat:`, `fix:`,
`docs:`, `chore:`, `test:`, …

## License

By contributing you agree that your contributions are licensed under the
project's **GPL-3.0** license.

## Known future work (good first issues welcome)

- Mutation transactions and breakpoint ownership/leases.
- Native API/heap trace provenance and real basic-block coverage.
- Unify any remaining internal legacy call sites before the documented
  `safe_get`/`safe_post` shim sunset.
