"""VC++ runtime DLLs placed next to the target: every runner, including MCP `run_controlled`, uses the SAME path.

The sandbox is a clean Windows (no vcruntime140_1.dll etc.); the target cannot start (0xC0000135, STATUS_DLL_NOT_FOUND).
These DLLs come from the host's own system folder, their names are FIXED (neither model nor target can choose), they are
placed under `in/bin` as read-only input and their names + SHA-256 are written to the runner journal: this does not
widen what the target can do (scope manifest, isolation).
"""
from __future__ import annotations

import os
from pathlib import Path

VC_RUNTIME_DLLS = ("vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll")
# Required on both architectures (vcruntime140_1.dll does not exist on x86; placed only if present)
_REQUIRED = ("vcruntime140.dll", "msvcp140.dll")


class SupportFilesMissing(RuntimeError):
    """Required VC++ DLL source missing on the host: never run silently without DLLs; fail explicitly."""


def pe_machine(path: Path) -> int | None:
    """Machine field of the PE header (0x14c = x86, 0x8664 = x64); None if unreadable."""
    try:
        with open(path, "rb") as f:
            head = f.read(4096)
        off = int.from_bytes(head[0x3C:0x40], "little")
        if head[off:off + 4] != b"PE\0\0":
            return None
        return int.from_bytes(head[off + 4:off + 6], "little")
    except (OSError, ValueError):
        return None


def vc_runtime_files(binary: Path, *, system_root: str | None = None) -> list[Path]:
    """VC++ runtime DLLs on the host (the sandbox is a clean Windows: no vcruntime140_1.dll etc.). SysWOW64 for a
    32-bit target, System32 for 64-bit; only those that exist (x86 has no vcruntime140_1.dll). SupportFilesMissing
    if any required DLL is absent on the host."""
    root = Path(system_root or os.environ.get("SystemRoot", r"C:\Windows"))
    sub = "SysWOW64" if pe_machine(binary) == 0x14C else "System32"
    found = [p for p in (root / sub / n for n in VC_RUNTIME_DLLS) if p.is_file()]
    missing = [n for n in _REQUIRED if n not in {p.name for p in found}]
    if missing:
        raise SupportFilesMissing(f"VC++ runtime DLL missing on host ({root / sub}): {', '.join(missing)}")
    return found
