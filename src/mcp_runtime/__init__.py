"""Shared runtime contracts for the x64dbg MCP server.

The public ``x64dbg`` facade intentionally remains backwards compatible, while
small, dependency-light pieces live in this package so they can be tested and
reused without importing the full 40k-line debugger integration.
"""

from .contracts import BridgeEnvelope, BridgeError, json_safe

__all__ = ["BridgeEnvelope", "BridgeError", "json_safe"]
