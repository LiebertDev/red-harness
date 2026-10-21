"""Memory layout of one emulation (pure Python, no emulator): the PE image at its preferred base, the analyst's stack and
buffers in a separate arena, and unmapped sentinel addresses for the return address, imported APIs and (x64) the TEB.

Rules (docs/design/emulation.md):
- The image is mapped at its PREFERRED base: relocations are not needed and not applied. File bytes come from the same
  chunk plan as `read_bytes` (`PeImage.plan`): headers and the raw data of each section; the rest of a section's
  virtual size is zero, as the loader zero-fills it (this is the loader's documented behaviour, not invented content).
- Section permissions are enforced page by page when every section starts on a page boundary; otherwise the whole image
  is read/write/execute and the evidence says so (`perms_enforced=false`).
- Every import-address-table slot (imports and delay imports) is overwritten with a unique sentinel address in an
  UNMAPPED range: a call to any imported API faults there and the emulation stops with the API's name. Nothing is
  stubbed and no return value is invented. If a declared table cannot be read completely, or a slot cannot be
  redirected, there is no layout (LayoutError): no emulation runs with a partly redirected IAT.
- The layout depends only on the image and the request: the same request gives the same addresses (reproducible).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from ..analysis.pe_dirs import PeDirectoryError, scan_imports_image
from ..analysis.pe_image import PeError, PeImage
from .spec import SpecError, check_pe_image

PAGE = 0x1000
ARENA_SIZE = 0x0400_0000
ARENA_CANDIDATES = (0x1000_0000, 0x2000_0000, 0x3000_0000, 0x5000_0000, 0x6000_0000)
STACK_TOP_OFF = 0x0100_0000      # the stack ends here (it grows down from it; at most 16 MiB)
BUFFERS_OFF = 0x0101_0000        # first argument buffer region (one guard gap above the stack)
BUFFER_GAP = 0x1_0000            # unmapped gap after every buffer region
RET_OFF = 0x0300_0000            # return sentinel (unmapped): reaching it means the function returned
THUNK_OFF = 0x0310_0000          # import sentinels, THUNK_STRIDE apart (unmapped)
THUNK_STRIDE = 0x10
THUNK_SPAN = 0x0010_0000
TEB_OFF = 0x0380_0000            # x64 GS base (unmapped): gs:[..] reads stop as "TEB/PEB access"
TEB_SPAN = 0x0010_0000
LOW_ADDRESS = 0x1_0000           # an access below this is a NULL pointer or (x86) an fs:-relative TEB access

SCN_EXECUTE, SCN_READ, SCN_WRITE = 0x2000_0000, 0x4000_0000, 0x8000_0000

Reader = Callable[[int, int], bytes]


class LayoutError(ValueError):
    pass


def align_up(n: int, a: int = PAGE) -> int:
    return (n + a - 1) & ~(a - 1)


@dataclass
class Layout:
    image_base: int
    image_size: int                          # page-aligned
    chunks: list[tuple[int, bytes]]          # (va, file bytes) written into the image
    perms: list[tuple[int, int, str]]        # (va, size, "rwx" subset) page runs; empty if not enforced
    perms_enforced: bool
    arena: int
    stack_lo: int
    stack_top: int
    buffers: list[tuple[int, int, int]]      # (region va, region size, buffer va) per buffer argument, in arg order
    ret_sentinel: int
    thunks: dict[int, str]                   # sentinel va -> "dll!name" / "dll!#ordinal"
    iat_writes: list[tuple[int, int]]        # (IAT slot va, sentinel va)
    teb_base: int
    import_notes: list[str] = field(default_factory=list)
    scratch: list[tuple[int, int, int]] = field(default_factory=list)   # (region, size, va) per scratch buffer

    def stack_ok(self, va: int, n: int) -> bool:
        return self.stack_lo <= va and va + n <= self.stack_top

    def describe(self) -> dict:
        """The layout facts that go into the evidence result (all integers / strings: no floats)."""
        return {"image_base": self.image_base, "image_size": self.image_size, "perms_enforced": self.perms_enforced,
                "arena": self.arena, "stack": [self.stack_lo, self.stack_top],
                "buffers": [b[2] for b in self.buffers], "ret_sentinel": self.ret_sentinel,
                "import_sentinels": len(self.thunks), "teb_sentinel": self.teb_base,
                "import_notes": list(self.import_notes),
                **({"scratch": [b[2] for b in self.scratch]} if self.scratch else {})}

    def import_at(self, va: int) -> str | None:
        if self.arena + THUNK_OFF <= va < self.arena + THUNK_OFF + THUNK_SPAN:
            return self.thunks.get(va - (va - self.arena - THUNK_OFF) % THUNK_STRIDE, "<unknown import sentinel>")
        return None

    def in_teb(self, va: int) -> bool:
        return self.teb_base <= va < self.teb_base + TEB_SPAN


def _perm_of(flags: int) -> str:
    return ("r" if flags & SCN_READ else "") + ("w" if flags & SCN_WRITE else "") + ("x" if flags & SCN_EXECUTE else "")


def _image_perms(img: PeImage) -> tuple[list[tuple[int, int, str]], bool]:
    if any(s.rva % PAGE for s in img.sections):
        return [], False
    pages = align_up(img.size_of_image) // PAGE
    per = [""] * pages
    for p in range(min(pages, align_up(img.size_of_headers) // PAGE)):
        per[p] = "r"
    for s in img.sections:
        perm = _perm_of(s.flags)
        for p in range(s.rva // PAGE, min(pages, align_up(s.rva + s.extent) // PAGE)):
            per[p] = "".join(c for c in "rwx" if c in per[p] + perm)
    runs: list[tuple[int, int, str]] = []
    for p, perm in enumerate(per):
        va = img.image_base + p * PAGE
        if runs and runs[-1][2] == perm and runs[-1][0] + runs[-1][1] == va:
            runs[-1] = (runs[-1][0], runs[-1][1] + PAGE, perm)
        else:
            runs.append((va, PAGE, perm))
    return runs, True


def _arena(img: PeImage, is64: bool) -> int:
    lo, hi = img.image_base, img.image_base + align_up(img.size_of_image)
    if not is64 and hi > 1 << 32:
        raise LayoutError(f"x86 image range 0x{lo:x}..0x{hi:x} does not fit in 32 bits")
    for c in ARENA_CANDIDATES:
        if c + ARENA_SIZE <= lo or c >= hi:
            return c
    raise LayoutError("no free arena for the stack and buffers next to the image")


def plan(img: PeImage, read: Reader, request: dict) -> Layout:
    """Builds the layout for `request` (spec.build_request). LayoutError / PeError if the image cannot be mapped."""
    is64 = request["arch"] == "x64"
    if img.is64 != is64:
        raise LayoutError("request architecture does not match the image")
    try:   # defense: the tool checks this before the worker starts
        check_pe_image(request, img)
    except SpecError as e:
        raise LayoutError(e.message) from e
    size = align_up(img.size_of_image)
    chunks: list[tuple[int, bytes]] = []
    for c in img.plan(0, img.size_of_image):
        if c.kind == "file":
            data = read(c.file_offset, c.length)
            if len(data) != c.length:
                raise PeError("file shorter than its section table claims")
            chunks.append((img.image_base + c.rva, data))
    perms, enforced = _image_perms(img)
    arena = _arena(img, is64)
    stack_top = arena + STACK_TOP_OFF
    buffers: list[tuple[int, int, int]] = []
    scratch: list[tuple[int, int, int]] = []
    cur = arena + BUFFERS_OFF
    # argument buffers first, then scratch buffers (version 2): a version 1 request keeps its addresses
    for dest, specs in ((buffers, [a for a in request["args"] if a["kind"] == "buffer"]),
                        (scratch, request.get("buffers", []))):
        for a in specs:
            region = align_up(a["size"])
            # the buffer ends near the end of its region (16-byte aligned start): an overrun of more than 15 bytes
            # hits the unmapped gap and stops the emulation instead of silently writing into the next buffer
            dest.append((cur, region, (cur + region - a["size"]) & ~0xF))
            cur += region + BUFFER_GAP
    if cur > arena + RET_OFF:
        raise LayoutError("argument buffers do not fit in the arena")
    thunks: dict[int, str] = {}
    iat: list[tuple[int, int]] = []
    notes: list[str] = []
    # Fail closed: an import slot that cannot be redirected would leave a file value (a name RVA, a bound address) in
    # the IAT, and a call through it would run whatever that value points at. So every declared import and
    # delay-import table must be read completely and every slot must be redirected, or there is no emulation.
    try:
        prof = scan_imports_image(img, read)
    except PeDirectoryError as e:
        raise LayoutError(f"import tables cannot be read ({e}); not every import slot could be redirected") from e
    if not prof.complete:
        raise LayoutError("import/delay-import/TLS tables are incomplete (" + "; ".join(prof.unknowns[:4])
                          + "); not every import slot could be redirected")
    funcs = [(t.dll, f) for t in prof.all_tables for f in t.functions]
    if len(funcs) * THUNK_STRIDE > THUNK_SPAN:
        raise LayoutError(f"{len(funcs)} imports exceed the {THUNK_SPAN // THUNK_STRIDE} sentinel slots")
    for i, (dll, f) in enumerate(funcs):
        if not 0 <= f.thunk_rva <= img.size_of_image - img.pointer_size:
            raise LayoutError(f"import slot of {dll} at rva 0x{f.thunk_rva:x} is outside the image")
        va = arena + THUNK_OFF + i * THUNK_STRIDE
        thunks[va] = f"{dll}!{f.name if f.name is not None else '#%d' % f.ordinal}"
        iat.append((img.image_base + f.thunk_rva, va))
    return Layout(img.image_base, size, chunks, perms, enforced, arena, stack_top - request["stack_size"], stack_top,
                  buffers, arena + RET_OFF, thunks, iat, arena + TEB_OFF, notes, scratch)


__all__ = ["Layout", "LayoutError", "plan", "align_up", "PAGE"]
