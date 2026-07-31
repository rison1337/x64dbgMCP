"""Parser for the shared Python/native route guard manifest."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Dict, Tuple, Union


PathLike = Union[str, Path]
_ROW_PATTERN = re.compile(
    r'^MCP_ROUTE\("(?P<path>/[A-Za-z0-9_/]+)",\s*'
    r'(?P<guard>NONE|BRIDGE|SESSION|EXEC_DYNAMIC)\)$'
)


def load_route_policy(path: PathLike) -> Tuple[Dict[str, str], str]:
    """Load and validate ``route_policy.inc``.

    The returned identifier is the first 16 hexadecimal characters of the
    manifest SHA-256 and is shared with the native bridge at build time.
    """

    policy_path = Path(path)
    raw = policy_path.read_bytes()
    policy_id = hashlib.sha256(raw).hexdigest()[:16]
    rows: Dict[str, str] = {}
    for line_number, raw_line in enumerate(
        raw.decode("utf-8", errors="strict").splitlines(), 1
    ):
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue
        match = _ROW_PATTERN.fullmatch(line)
        if not match:
            raise RuntimeError(
                f"Invalid route_policy.inc row at line {line_number}: {line!r}"
            )
        route = match.group("path")
        if route in rows:
            raise RuntimeError(f"Duplicate route policy for {route}")
        rows[route] = match.group("guard").casefold()
    if not rows:
        raise RuntimeError("route_policy.inc is empty")
    return rows, policy_id
