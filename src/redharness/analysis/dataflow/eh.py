"""Exception-handling data the slicer cannot model (docs/design/dataflow-slice.md section 6.4).

`seh.py` turns the x64 `__C_specific_handler` / `__GSHandlerCheck_SEH` scope tables into CFG edges. Every other exception
handler can run code that writes the function's frame and resume anywhere inside the function (C++ catch continuations,
x86 frame-based SEH, filters and funclets of unknown shape), and none of that is visible in the engine's instruction
stream of the parent. This module finds those functions so that the slicer reports no value as definite in them:

- x64: the function's `RUNTIME_FUNCTION` -> `UNWIND_INFO` (indirect and chained entries followed) names an exception /
  termination handler that is not one of the modelled ones. Handlers that cannot resume in this function are benign and
  keep the function modelled: `__GSHandlerCheck` (stack cookie check only) and C++ frame handlers whose FuncInfo has no
  try block (destructor unwinding only; control never returns into the frame).
- x86: no unwind tables exist; the frame-based registration is recognised in the decoded instructions (`fs:[0]`
  accesses, SEH/EH prolog helpers, `__except_handler`, `__CxxFrameHandler` references).

Everything unknown is treated as "not modelled": unreadable unwind data, a chain that cannot be followed, a handler
that cannot be named.
"""

from __future__ import annotations

import re
import struct
from bisect import bisect_right
from typing import Callable, Iterable

from ..imports_view import iat_slot_names
from ..pe_dirs import PeDirectoryError, read_data_directories, scan_imports_image
from ..pe_image import PeImage, Reader
from .seh import (MAX_FUNCTIONS, MAX_SCOPES, SCOPE_HANDLERS, UNW_FLAG_CHAININFO, UNW_FLAG_EHANDLER, UNW_FLAG_UHANDLER,
                  _handler_name, _read)

MAX_CHAIN = 8
CXX3_MAGIC = (0x19930520, 0x19930521, 0x19930522)   # low 29 bits of _s_FuncInfo.magicNumber
FH4_TRYBLOCKS, FH4_ISCATCH = 0x10, 0x01              # FuncInfoHeader bits (compressed FuncInfo of __CxxFrameHandler4)
_norm = lambda n: n.split("!")[-1].lstrip("_").lower()   # noqa: E731
_SCOPE = {_norm(n) for n in SCOPE_HANDLERS}
_CXX3 = {"cxxframehandler", "cxxframehandler2", "cxxframehandler3", "gshandlercheck_eh"}
_CXX4 = {"cxxframehandler4", "gshandlercheck_eh4"}
_GS_ONLY = {"gshandlercheck"}

Resolver = Callable[[int], "str | None"]   # handler VA -> function name known to the engine (None: unnamed)


class UnwindData:
    """The image's `RUNTIME_FUNCTION` table (x64 only; empty otherwise), sorted by start address."""

    def __init__(self, img: PeImage, read: Reader):
        self.img, self.read = img, read
        self.rows: list[tuple[int, int, int]] = []
        self.begins: list[int] = []
        self.slots: dict[int, str] = {}
        self._memo: dict[int, str | None] = {}
        self.error: str | None = None   # the table itself could not be read: every function counts as not modelled
        self.truncated = False          # rows stop at MAX_FUNCTIONS: functions past the last row are not known
        if img.machine != 0x8664:
            return
        try:
            dirs = read_data_directories(img, read)
            self.slots = iat_slot_names(scan_imports_image(img, read))
        except PeDirectoryError:
            self.error = "PE data directories unreadable"
            return
        exc = next((d for d in dirs if d.index == 3), None)
        if exc is None or not exc.rva or exc.size < 12:
            return
        n = min(exc.size // 12, MAX_FUNCTIONS)
        self.truncated = exc.size // 12 > MAX_FUNCTIONS
        table = _read(img, read, exc.rva, n * 12)
        if table is None:
            self.error = "exception directory unreadable"
            return
        self.rows = sorted(r for r in struct.iter_unpack("<III", table) if r[0] and r[1] > r[0])
        self.begins = [r[0] for r in self.rows]

    # ------------------------------------------------------------ queries
    def unmodelled(self, vas: Iterable[int], resolve: Resolver | None = None) -> list[str]:
        """Reasons (sorted, unique) why the code at these addresses has exception handlers the slicer does not model;
        empty when every runtime function covering them is modelled or cannot resume in the frame."""
        base = self.img.image_base
        seen: set[int] = set()
        out: set[str] = set()
        vas = list(vas)
        if self.error and vas:
            return [f"exception handler data unreadable ({self.error})"]
        for va in vas:
            rva = va - base
            k = bisect_right(self.begins, rva) - 1
            if self.truncated and (k < 0 or self.rows[k][1] <= rva):
                # not covered by a read row; with a truncated table it may be one of the dropped functions
                out.add(f"exception directory truncated at {MAX_FUNCTIONS} entries")
                continue
            if k < 0 or self.rows[k][1] <= rva or k in seen:
                continue
            seen.add(k)
            why = self._classify(self.rows[k][2], resolve)
            if why:
                out.add(why)
        return sorted(out)

    # ------------------------------------------------------------ classification
    def _classify(self, unwind: int, resolve: Resolver | None) -> str | None:
        if unwind not in self._memo:
            self._memo[unwind] = self._classify_uncached(unwind, resolve)
        return self._memo[unwind]

    def _follow(self, unwind: int) -> tuple[str, int, str]:
        """-> (kind, handler-field RVA, why): kind "none" (no language handler), "handler", or "bad"."""
        for _ in range(MAX_CHAIN):
            if unwind & 1:   # indirect: the entry's unwind data is another RUNTIME_FUNCTION
                rf = _read(self.img, self.read, unwind & ~1, 12)
                if rf is None:
                    return "bad", 0, "indirect unwind info unreadable"
                unwind = struct.unpack_from("<I", rf, 8)[0]
                continue
            hdr = _read(self.img, self.read, unwind, 4)
            if hdr is None:
                return "bad", 0, "unwind info unreadable"
            version, flags, ncodes = hdr[0] & 7, hdr[0] >> 3, hdr[2]
            if version not in (1, 2):
                return "bad", 0, f"unwind info version {version} not understood"
            off = unwind + 4 + 2 * (ncodes + (ncodes & 1))
            if flags & UNW_FLAG_CHAININFO:
                rf = _read(self.img, self.read, off, 12)
                if rf is None:
                    return "bad", 0, "chained unwind info unreadable"
                unwind = struct.unpack_from("<I", rf, 8)[0]
                continue
            if not flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER):
                return "none", 0, ""
            return "handler", off, ""
        return "bad", 0, f"unwind info chain deeper than {MAX_CHAIN} not followed"

    def _classify_uncached(self, unwind: int, resolve: Resolver | None) -> str | None:
        kind, off, why = self._follow(unwind)
        if kind == "none":
            return None
        if kind == "bad":
            return why
        hd = _read(self.img, self.read, off, 4)
        if hd is None:
            return "exception handler data unreadable"
        handler_rva = struct.unpack("<I", hd)[0]
        name = _handler_name(self.img, self.read, handler_rva, self.slots)
        imported = name is not None
        if name is None and resolve is not None:
            name = resolve(self.img.image_base + handler_rva)
        if not name:
            return f"language handler at 0x{self.img.image_base + handler_rva:x} not identified"
        shown, key = name.split("!")[-1], _norm(name)
        data = off + 4
        if key in _SCOPE:
            if imported:
                return None if self._scope_table_ok(key, data) else f"C scope table of handler {shown} unreadable"
            return f"statically linked handler {shown} (scope table not parsed)"
        if key in _GS_ONLY:
            return None   # stack-cookie check: never resumes in the frame
        if key in _CXX3:
            n = self._cxx3_try_blocks(data)
            return None if n == 0 else f"C++ EH, handler {shown}"
        if key in _CXX4:
            fi = self._rva_at(data)
            h = _read(self.img, self.read, fi, 1) if fi else None
            if h is not None and not h[0] & (FH4_TRYBLOCKS | FH4_ISCATCH):
                return None
            return f"C++ EH, handler {shown}"
        return f"exception handler {shown}"

    def _rva_at(self, rva: int) -> int | None:
        b = _read(self.img, self.read, rva, 4)
        return struct.unpack("<I", b)[0] if b else None

    def _scope_table_ok(self, key: str, data: int) -> bool:
        b = _read(self.img, self.read, data, 4)
        if b is None:
            return False
        count = struct.unpack("<I", b)[0]
        return 0 < count <= MAX_SCOPES and _read(self.img, self.read, data + 4, 16 * count) is not None

    def _cxx3_try_blocks(self, data: int) -> int | None:
        """nTryBlocks of the FuncInfo the handler data points to; None when it cannot be read or is not a FuncInfo."""
        fi = self._rva_at(data)
        if not fi:
            return None
        b = _read(self.img, self.read, fi, 16)
        if b is None:
            return None
        magic, _max_state, _unwind_map, n_try = struct.unpack("<IiiI", b)
        return n_try if magic & 0x1FFFFFFF in CXX3_MAGIC else None


# ---------------------------------------------------------------- x86 frame-based registration
_FS0 = re.compile(r"\bfs:\s*(?:\[\s*)?(?:0x0+|0+h?)\s*\]?(?![0-9a-z])")
_HELPER = re.compile(r"(?:_SEH_prolog|_SEH_epilog|_EH_prolog|_EH_epilog|_except_handler\d|_CxxFrameHandler\d*|"
                     r"_local_unwind\d?|_global_unwind\d?|__ehhandler|_except_handler4_common)", re.I)


def x86_markers(insns, limit: int = 3) -> list[str]:
    """x86 code registers its exception handler in the frame (`fs:[0]` chain) or through a CRT prolog helper; neither
    is described by any table. Returns up to `limit` descriptions of what in the decoded instructions shows it."""
    out: list[str] = []
    for ins in insns:
        low = ins.text.lower()
        what = None
        if "fs:" in low and _FS0.search(low):
            what = "fs:[0] exception registration"
        else:
            for blob in [ins.text] + [o.sym for o in ins.operands if o.sym]:
                m = _HELPER.search(blob)
                if m:
                    what = f"reference to {m.group(0)}"
                    break
        if what:
            out.append(f"x86 SEH/EH frame handler: {what} at 0x{ins.address:x}")
            if len(out) >= limit:
                break
    return out
