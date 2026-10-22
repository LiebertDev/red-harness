"""Exception-handling data the slicer cannot model (docs/design/dataflow-slice.md section 6.4).

`seh.py` turns the x64 `__C_specific_handler` / `__GSHandlerCheck_SEH` scope tables into CFG edges. Every other exception
handler can run code that writes the function's frame and resume anywhere inside the function (C++ catch continuations,
x86 frame-based SEH, filters and funclets of unknown shape), and none of that is visible in the engine's instruction
stream of the parent. This module finds those functions so that the slicer reports no value as definite in them:

- x64: the function's `RUNTIME_FUNCTION` -> `UNWIND_INFO` (indirect and chained entries followed) names an exception /
  termination handler that is not one of the modelled ones. Handlers that cannot resume in this function are benign and
  keep the function modelled: `__GSHandlerCheck` (stack cookie check only) and C++ frame handlers whose FuncInfo has no
  try block (destructor unwinding only; control never returns into the frame). A `C_SCOPE_TABLE` (the modelled handler of
  `seh.py`) is modelled only when every row is a pure `__except` whose filter is the constant EXCEPTION_EXECUTE_HANDLER
  (HandlerAddress == 1): a row with a filter function (JumpTarget != 0, HandlerAddress != 1) runs that filter funclet
  during dispatch and a row with JumpTarget == 0 runs its termination-handler funclet during unwind, and both are
  separate code that receives the establisher frame pointer and can write the parent's frame.
- x86: no unwind tables exist; the frame-based registration is recognised in the decoded instructions (`fs:[0]`
  accesses, SEH/EH prolog helpers, `__except_handler`, `__CxxFrameHandler` references). A statically linked prolog the
  engine named `sub_...`/`FUN_...` is recognised by the byte signature of its first instructions.

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
                return self._scope_table_why(shown, data)
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

    def _scope_table_why(self, shown: str, data: int) -> str | None:
        """None when every row of the C scope table is a `__except` whose filter is the constant 1 (the modelled case of
        section 6.3); otherwise why a funclet the slicer does not parse can run and write the parent's frame. The first
        offending row is named: the whole function is not modelled either way."""
        b = _read(self.img, self.read, data, 4)
        if b is None:
            return f"C scope table of handler {shown} unreadable"
        count = struct.unpack("<I", b)[0]
        rows = _read(self.img, self.read, data + 4, 16 * count) if 0 < count <= MAX_SCOPES else None
        if rows is None:
            return f"C scope table of handler {shown} unreadable"
        base = self.img.image_base
        for j in range(count):
            b_, e_, h_, t_ = struct.unpack_from("<IIII", rows, 16 * j)
            if not b_ < e_:
                continue      # an inconsistent row contains no instruction, so it never fires (seh.py: no edge either)
            if t_ == 0:       # __finally: HandlerAddress is the termination-handler funclet, run during unwind
                if h_:
                    return f"__finally funclet at 0x{base + h_:x} not modelled"
            elif h_ != 1:     # __except with a filter function, run during dispatch (1 = EXCEPTION_EXECUTE_HANDLER)
                return f"C-specific filter funclet at 0x{base + h_:x} not modelled"
        return None

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
_AUTO_NAME = re.compile(r"^(?:sub_|FUN_|thunk_FUN_|j_sub_)", re.I)

MAX_PROLOG_BYTES = 64      # enough for the longest signature below; the prolog helper is entered at its first byte
MAX_PROLOG_CACHE = 256     # per image: call targets with their first bytes

# Byte signatures of the statically linked MSVC x86 prolog helpers, read from tests/fixtures/eh/build/eh_cases_x86.exe
# (`dumpbin /disasm`: __EH_prolog3_GS at 0x401213, __SEH_prolog4_GS at 0x401250). None is a wildcard: an operand the
# linker relocates (the pushed handler address). Every other byte is fixed executable content.
PROLOG_SIGNATURES: tuple[tuple[str, tuple[int | None, ...]], ...] = (
    # push eax; push fs:[0]; lea eax,[esp+0Ch]; sub esp,[esp+0Ch]; push ebx; push esi; push edi; mov [eax],ebp;
    # mov ebp,eax  -- the handler arrives in eax (`mov eax, offset handler; call ...`). Covers __EH_prolog3,
    # __EH_prolog3_GS and the __EH_prolog3_catch variants (they share this prolog; the cookie check follows).
    ("__EH_prolog3", (0x50, 0x64, 0xFF, 0x35, 0, 0, 0, 0, 0x8D, 0x44, 0x24, 0x0C,
                      0x2B, 0x64, 0x24, 0x0C, 0x53, 0x56, 0x57, 0x89, 0x28, 0x8B, 0xE8)),
    # push <handler>; push fs:[0]; mov eax,[esp+10h]; mov [esp+10h],ebp; lea ebp,[esp+10h]; sub esp,eax;
    # push ebx; push esi; push edi  -- covers __SEH_prolog4 and __SEH_prolog4_GS (the cookie check follows).
    ("__SEH_prolog4", (0x68, None, None, None, None, 0x64, 0xFF, 0x35, 0, 0, 0, 0, 0x8B, 0x44, 0x24, 0x10,
                       0x89, 0x6C, 0x24, 0x10, 0x8D, 0x6C, 0x24, 0x10, 0x2B, 0xE0, 0x53, 0x56, 0x57)),
)


def match_prolog(head: bytes) -> str | None:
    """Name of the MSVC x86 prolog helper whose signature starts `head`, or None."""
    for name, sig in PROLOG_SIGNATURES:
        if len(head) >= len(sig) and all(w is None or head[k] == w for k, w in enumerate(sig)):
            return name
    return None


def _callee_head(image, va: int) -> bytes | None:
    """First MAX_PROLOG_BYTES bytes at `va` through the image view, cached per image and target."""
    if image is None:
        return None
    cache = getattr(image, "_eh_prolog_heads", None)
    if cache is None:
        cache = {}
        try:
            image._eh_prolog_heads = cache
        except Exception:      # a view that does not accept attributes: still answer, just without a cache
            cache = None
    if cache is not None and va in cache:
        return cache[va]
    try:
        ld = image.load(va, MAX_PROLOG_BYTES)
        head = ld.data if ld is not None else None
    except Exception:          # an unreadable target is no evidence for a helper
        head = None
    if cache is not None and len(cache) < MAX_PROLOG_CACHE:
        cache[va] = head
    return head


def prolog_at(image, va: int) -> str | None:
    """Signature name of the prolog helper at `va`, read from the image; None for anything else."""
    head = _callee_head(image, va)
    return match_prolog(head) if head else None


def _unnamed(sym: str) -> bool:
    return not sym or bool(_AUTO_NAME.match(sym))


def _prolog_call(ins, image) -> tuple[str, int] | None:
    """(signature name, target VA) when `ins` is a direct call to an unnamed function that starts with a prolog."""
    if image is None or str(ins.mnemonic).lower() != "call" or not ins.operands:
        return None
    op = ins.operands[0]
    if op.kind != "near" or op.value is None or not _unnamed(op.sym or ""):
        return None
    name = prolog_at(image, op.value)
    return (name, op.value) if name else None


def x86_markers(insns, image=None, limit: int = 3) -> list[str]:
    """x86 code registers its exception handler in the frame (`fs:[0]` chain) or through a CRT prolog helper; neither
    is described by any table. Returns up to `limit` descriptions of what in the decoded instructions shows it.
    `image` (PeImageView-like) lets a direct call to an unnamed target be matched against the prolog byte signatures:
    the helper touches `fs:[0]` itself, so the caller's own instructions may show no marker at all."""
    out: list[str] = []
    for ins in insns:
        low = ins.text.lower()
        desc = None
        if "fs:" in low and _FS0.search(low):
            desc = f"fs:[0] exception registration at 0x{ins.address:x}"
        else:
            for blob in [ins.text] + [o.sym for o in ins.operands if o.sym]:
                m = _HELPER.search(blob)
                if m:
                    desc = f"reference to {m.group(0)} at 0x{ins.address:x}"
                    break
            if desc is None:
                hit = _prolog_call(ins, image)
                if hit:
                    desc = (f"x86 SEH prolog helper (signature {hit[0]}) at 0x{hit[1]:x} "
                            f"called at 0x{ins.address:x}")
        if desc:
            out.append(f"x86 SEH/EH frame handler: {desc}")
            if len(out) >= limit:
                break
    return out
