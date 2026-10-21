"""x64 structured-exception scope tables -> exception edges for the slicer's CFG.

Source: the PE's own unwind data (exception directory, `RUNTIME_FUNCTION` -> `UNWIND_INFO`), engine-independent and
checked field by field. A function whose unwind info names `__C_specific_handler` (or `__GSHandlerCheck_SEH`, which
starts with the same scope table) as its language handler carries a `C_SCOPE_TABLE`:
`Count` x {BeginAddress, EndAddress, HandlerAddress, JumpTarget} (RVAs). An entry with JumpTarget != 0 is a
`__try/__except`: an exception raised in [BeginAddress, EndAddress) whose filter accepts it continues at JumpTarget,
inside the same function. That is the edge (try range -> JumpTarget). JumpTarget == 0 is a `__finally` (a separate
funclet): no edge in this function.

The handler RVA is resolved to a name only through the import table (a `jmp [IAT slot]` thunk or a direct IAT slot);
anything else (a statically linked handler, C++ EH `__CxxFrameHandler*`, x86 frame-based SEH) gives no edges and the
slicer keeps its conservative taint for blocks without a known predecessor.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ..pe_dirs import PeDirectoryError, read_data_directories, scan_imports_image
from ..imports_view import iat_slot_names
from ..pe_image import PeImage, Reader

SCOPE_HANDLERS = frozenset({"__C_specific_handler", "_C_specific_handler", "__GSHandlerCheck_SEH"})
UNW_FLAG_EHANDLER, UNW_FLAG_UHANDLER, UNW_FLAG_CHAININFO = 0x1, 0x2, 0x4
MAX_FUNCTIONS = 200_000
MAX_SCOPES = 256


@dataclass(frozen=True)
class ExceptEdge:
    try_begin: int      # VA, inclusive
    try_end: int        # VA, exclusive
    target: int         # VA of the __except block
    filter: int         # VA of the filter function, or 1 (EXCEPTION_EXECUTE_HANDLER constant)
    handler: str        # dll!name of the language handler
    unwind_va: int      # VA of the UNWIND_INFO the entry came from


def _read(img: PeImage, read: Reader, rva: int, n: int) -> bytes | None:
    chunks = img.plan(rva, n)
    if any(c.kind != "file" for c in chunks):
        return None
    data = b"".join(read(c.file_offset, c.length) for c in chunks)
    return data if len(data) == n else None


def _handler_name(img: PeImage, read: Reader, rva: int, slots: dict[int, str]) -> str | None:
    va = img.image_base + rva
    if va in slots:
        return slots[va]
    b = _read(img, read, rva, 6)
    if b and b[:2] == b"\xff\x25":   # jmp qword ptr [rip+disp32]
        return slots.get(va + 6 + struct.unpack_from("<i", b, 2)[0])
    return None


def scope_edges(img: PeImage, read: Reader) -> list[ExceptEdge]:
    """All __try/__except edges of an x64 image (empty for other images or when the tables are unreadable)."""
    if img.machine != 0x8664:
        return []
    try:
        dirs = read_data_directories(img, read)
        slots = iat_slot_names(scan_imports_image(img, read))
    except PeDirectoryError:
        return []
    exc = next((d for d in dirs if d.index == 3), None)
    if exc is None or not exc.rva or exc.size < 12:
        return []
    n = min(exc.size // 12, MAX_FUNCTIONS)
    table = _read(img, read, exc.rva, n * 12)
    if table is None:
        return []
    out: list[ExceptEdge] = []
    names: dict[int, str | None] = {}
    base = img.image_base
    for k in range(n):
        begin, end, unwind = struct.unpack_from("<III", table, 12 * k)
        if not begin or end <= begin or unwind & 1:   # unwind & 1: an indirect (shared) entry, no handler data here
            continue
        hdr = _read(img, read, unwind, 4)
        if hdr is None:
            continue
        version, flags, ncodes = hdr[0] & 7, hdr[0] >> 3, hdr[2]
        if version not in (1, 2) or flags & UNW_FLAG_CHAININFO or not flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER):
            continue
        off = unwind + 4 + 2 * (ncodes + (ncodes & 1))
        hd = _read(img, read, off, 8)
        if hd is None:
            continue
        handler_rva, count = struct.unpack_from("<II", hd)
        if handler_rva not in names:
            names[handler_rva] = _handler_name(img, read, handler_rva, slots)
        name = names[handler_rva]
        if not name or name.split("!")[-1] not in SCOPE_HANDLERS or not 0 < count <= MAX_SCOPES:
            continue
        rows = _read(img, read, off + 8, 16 * count)
        if rows is None:
            continue
        for j in range(count):
            b, e, h, t = struct.unpack_from("<IIII", rows, 16 * j)
            if t == 0 or not b < e or not (img.section_at(t) and img.section_at(b)):
                continue   # a __finally (separate funclet) or an inconsistent row: no edge
            out.append(ExceptEdge(base + b, base + e, base + t, h if h == 1 else base + h, name, base + unwind))
    return out
