"""Small PE/CLR helpers used before a debugger session is selected."""

from __future__ import annotations

import os
import struct
from typing import Optional


def dotnet_effective_arch(exe_path: str) -> Optional[str]:
    """Return the architecture a managed PE will actually execute as.

    Mixed-mode C++/CLI images have a PE32 machine field but clear ``ILONLY``;
    their native code requires x32dbg. Pure IL AnyCPU images can run as x64 on
    a 64-bit host, while ``32BITREQUIRED`` and ``32BITPREFERRED`` force x86.
    """

    try:
        import pefile

        pe = pefile.PE(exe_path, fast_load=True)
        try:
            com_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
            if not com_dir.VirtualAddress or not com_dir.Size:
                return None
            raw = pe.get_data(com_dir.VirtualAddress, 20)
            flags = struct.unpack_from("<I", raw, 16)[0]
            il_only = bool(flags & 0x1)
            force_x86 = bool(flags & (0x2 | 0x20000))
            return "x86" if not il_only or force_x86 else "x64"
        finally:
            pe.close()
    except Exception:
        return None


def detect_pe_arch(exe_path: str) -> Optional[str]:
    """Return x86/x64 (or a machine code) without starting a process."""

    if not exe_path or not os.path.exists(exe_path):
        return None
    try:
        with open(exe_path, "rb") as handle:
            handle.seek(0x3C)
            pe_offset = int.from_bytes(handle.read(4), "little", signed=False)
            handle.seek(pe_offset + 4)
            machine = int.from_bytes(handle.read(2), "little", signed=False)
    except Exception:
        return None
    if machine == 0x14C:
        return dotnet_effective_arch(exe_path) or "x86"
    if machine == 0x8664:
        return "x64"
    return f"0x{machine:X}"
