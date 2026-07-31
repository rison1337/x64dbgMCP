# Demo script / storyboard

A ready-to-read walkthrough for a short screencast. Each scene lists what to show
on screen and the **exact prompt** you can type into your MCP client (Claude
Desktop/Code, Cursor, …). The whole thing runs against a CLI crackme; swap in
your own target as you like.

> Tip: keep the x64dbg window and your MCP client side by side so viewers see the
> debugger react to natural-language prompts in real time.

---

## Scene 0 — The hook (10s)

Say: *"I'm going to reverse and crack a small target without touching the x64dbg
UI — just by talking to it."*

Show: the MCP client and an idle x64dbg.

---

## Scene 1 — Health check & auto-start (20s)

Prompt:
> Make sure the x86 debugger is running and tell me whether the bridge is healthy.

Show: `GetDebuggerPluginStatus` / `EnsureDebugger` bringing x32dbg up; the bridge
reporting healthy. Point out there was no manual launch.

---

## Scene 2 — Load the target and get past loader noise (25s)

Prompt:
> Launch `C:\path\to\crackme.exe` under the debugger and advance to the entry point.

Show: the target loaded, paused at its real entry — not buried in loader/TLS code.

---

## Scene 3 — Find the password dynamically (60s)

Prompt:
> Read the debuggee console. If it's waiting for input, find where it compares my
> input to the expected password: set a breakpoint on the comparison, run, and
> capture the registers, stack and nearby memory when it hits.

Show: `ReadDebuggeeConsole` returning the prompt, a breakpoint on the compare, and
`CaptureStopContextStructured` revealing the expected key in memory/registers.

Prompt:
> Based on that captured context, what is the password?

Show: the model reading the key out of the captured buffer.

---

## Scene 4 — Patch the check and export a cracked build (45s)

Prompt:
> Patch the failed-check jump so any input is accepted, then export a patched copy
> to `C:\temp\cracked.exe`.

Show: the patch applied in x64dbg, then `ExportPatchedFile` writing a standalone
patched executable. Run `cracked.exe` outside the debugger to prove it accepts any
input.

> Note: patches come from x64dbg's patch list. Make the edit in the x64dbg patch
> UI (or via a patching tool), then `ExportPatchedFile` maps each patched address
> to its file offset and writes the new binary.

---

## Scene 5 (optional) — Unpack a packed sample (60s)

Prompt:
> This binary looks packed. Analyze it for packing and anti-debug, find the OEP,
> and dump a fixed module to `C:\temp\unpacked.exe`.

Show: `AnalyzeExecutablePacking` + anti-debug triage, `FindOEP`, then `DumpModule`
(Scylla) producing an import-fixed dump.

---

## Scene 6 — Wrap (10s)

Say: *"Everything you just saw — launch, breakpoints, memory inspection, patching,
unpacking — was driven entirely in natural language."*

Show: the finished cracked/unpacked file.
