"""Transport/result contracts shared by the MCP runtime and standalone tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


def _trim_text(value: Any, limit: int = 800) -> Any:
    if not isinstance(value, str):
        return value
    if len(value) <= limit:
        return value
    return value[:limit] + f"... <trimmed {len(value) - limit} chars>"


def json_safe(value: Any, limit: int = 1200) -> Any:
    """Return a bounded JSON-compatible representation.

    This is deliberately dependency-free so contract tests can import it
    without starting FastMCP or touching the debugger bridge.
    """

    if isinstance(value, dict):
        return {str(k): json_safe(v, limit=limit) for k, v in value.items()}
    if isinstance(value, list):
        return [json_safe(v, limit=limit) for v in value[:50]]
    if isinstance(value, tuple):
        return [json_safe(v, limit=limit) for v in value[:50]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return _trim_text(value, limit=limit)
    return _trim_text(str(value), limit=limit)


@dataclass(frozen=True)
class BridgeError:
    """Normalized bridge/transport failure."""

    code: str
    message: str
    retryable: bool = False
    http_status: Optional[int] = None
    endpoint: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "code": self.code,
            "message": self.message,
            "retryable": bool(self.retryable),
        }
        if self.http_status is not None:
            payload["httpStatus"] = int(self.http_status)
        if self.endpoint:
            payload["endpoint"] = self.endpoint
        if self.details:
            payload["details"] = json_safe(self.details)
        return payload


@dataclass(frozen=True)
class BridgeEnvelope:
    """Typed bridge result used internally and by the public result adapter."""

    ok: bool
    data: Any = None
    error: Optional[BridgeError] = None
    meta: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "ok": bool(self.ok),
            "data": json_safe(self.data, limit=20000),
            "error": self.error.as_dict() if self.error else None,
            "meta": json_safe(self.meta),
        }
