---
name: Bug report
about: Report a problem with the MCP server, the bridge plugin, or a specific tool
title: "[bug] "
labels: bug
---

**What happened**
A clear description of the bug.

**What you expected**

**Steps to reproduce**
1. …
2. …

**Which tool / endpoint** (if applicable)
e.g. `LaunchFileUnderDebugger`, `/Memory/Read`, `ExportPatchedFile`

**Environment**
- OS / build:
- Python version:
- x64dbg build (date):
- Plugin arch: x64 / x86
- MCP client (Claude Desktop / Code / Cursor / other):

**Logs**
Attach relevant lines from `src/logs/x64dbg-mcp.log` and the x64dbg Log tab.
Output of `python src/x64dbg.py RunBridgeSelfCheck` is very helpful.
