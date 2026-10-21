"""Synthetic PE builder: import / delay-import / TLS tables (test helper).

No real binary is needed; the layout is the known answer. The file is never loaded/executed.
  headers 0x400 | .text rva 0x1000 (0x200, 0xCC) | .rdata rva 0x2000 (0x1000)
  .rdata file offset 0x600; every structure inside is addressed by its RVA.
"""
from __future__ import annotations

import struct

FILE_ALIGN = 0x200
SIZE_HEADERS = 0x400
E_LFANEW = 0x80
TEXT_RVA = 0x1000
RDATA_RVA = 0x2000
RDATA_SIZE = 0x1000
SIZE_IMAGE = 0x4000
RDATA_FILE_OFFSET = SIZE_HEADERS + FILE_ALIGN      # 0x600


class _Blob:
    """Sequential allocator inside the 0x1000-byte .rdata; RVAs are RDATA_RVA + offset."""

    def __init__(self) -> None:
        self.data = bytearray(RDATA_SIZE)
        self.cur = 0

    def alloc(self, n: int) -> int:
        off = self.cur
        self.cur += n
        if self.cur > RDATA_SIZE:
            raise AssertionError("synthetic .rdata overflowed")
        return off

    def put(self, off: int, raw: bytes) -> None:
        self.data[off:off + len(raw)] = raw

    @staticmethod
    def rva(off: int) -> int:
        return RDATA_RVA + off

    @staticmethod
    def file_offset(off: int) -> int:
        return RDATA_FILE_OFFSET + off


def _write_thunks(blob: _Blob, functions: list[str | int], psize: int,
                  resolved_base: int | None = None, iat_names: bool = False) -> tuple[int, int]:
    """Allocates the INT (name table) and IAT arrays; returns (int_off, iat_off).
    If `resolved_base` is given the IAT is filled with resolved addresses (dump scenario).
    If `iat_names` is given the IAT is a copy of the INT (unbound, name-based IAT)."""
    int_off = blob.alloc(psize * (len(functions) + 1))
    iat_off = blob.alloc(psize * (len(functions) + 1))
    for i, fn in enumerate(functions):
        if isinstance(fn, int):
            value = (1 << (psize * 8 - 1)) | fn
        else:
            name_off = blob.alloc(2 + len(fn) + 1)
            blob.put(name_off, struct.pack("<H", 0) + fn.encode("ascii") + b"\0")
            value = blob.rva(name_off)
        blob.put(int_off + i * psize, value.to_bytes(psize, "little"))
        if resolved_base is not None:
            blob.put(iat_off + i * psize, (resolved_base + 0x1000 * (i + 1)).to_bytes(psize, "little"))
        elif iat_names:
            blob.put(iat_off + i * psize, value.to_bytes(psize, "little"))
    return int_off, iat_off


def build_pe(*, is64: bool = True, base: int | None = None,
             imports: dict[str, list[str | int]] | None = None,
             delay_imports: dict[str, list[str | int]] | None = None,
             tls_callbacks: tuple[int, ...] = (),
             markers: tuple[bytes, ...] = (),
             import_dir: int | None = None,
             zero_oft: bool = False,
             resolved_base: int | None = None,
             iat_names: bool = False) -> bytes:
    """`imports`: {"KERNEL32.dll": ["IsDebuggerPresent", 17]} — int = ordinal.
    `tls_callbacks`: list of RVAs inside .text. `markers`: raw bytes written at the end of .rdata.
    `import_dir`: if given, the import directory points to this RVA (for corrupt scenarios).
    `zero_oft`: OriginalFirstThunk=0 (no name table in a memory dump).
    `resolved_base`: fills the IAT with addresses resolved from this base.
    `iat_names`: fills the IAT with a copy of the INT (names kept, unbound IAT)."""
    base = base if base is not None else (0x140000000 if is64 else 0x400000)
    psize = 8 if is64 else 4
    sizeopt = 0xF0 if is64 else 0xE0
    imports = imports or {}
    delay_imports = delay_imports or {}
    blob = _Blob()

    imp_off = blob.alloc(20 * (len(imports) + 1))
    dly_off = blob.alloc(32 * (len(delay_imports) + 1)) if delay_imports else 0
    tls_off = blob.alloc(4 * psize + 8) if tls_callbacks else 0
    cbs_off = blob.alloc(psize * (len(tls_callbacks) + 1)) if tls_callbacks else 0

    entries: list[tuple[int, int, int]] = []
    for dll, functions in imports.items():
        int_off, iat_off = _write_thunks(blob, functions, psize, resolved_base, iat_names)
        name_off = blob.alloc(len(dll) + 1)
        blob.put(name_off, dll.encode("ascii") + b"\0")
        entries.append((int_off, iat_off, name_off))
    for i, (int_off, iat_off, name_off) in enumerate(entries):
        blob.put(imp_off + 20 * i,
                 struct.pack("<IIIII", 0 if zero_oft else blob.rva(int_off), 0, 0,
                             blob.rva(name_off), blob.rva(iat_off)))

    if delay_imports:
        dentries: list[tuple[int, int, int]] = []
        for dll, functions in delay_imports.items():
            int_off, iat_off = _write_thunks(blob, functions, psize, resolved_base, iat_names)
            name_off = blob.alloc(len(dll) + 1)
            blob.put(name_off, dll.encode("ascii") + b"\0")
            dentries.append((int_off, iat_off, name_off))
        for i, (int_off, iat_off, name_off) in enumerate(dentries):
            blob.put(dly_off + 32 * i, struct.pack("<IIIIIIII", 1, blob.rva(name_off), 0,
                                                   blob.rva(iat_off), blob.rva(int_off), 0, 0, 0))

    if tls_callbacks:
        cb_rva = blob.rva(cbs_off)
        fmt = "<" + ("Q" if is64 else "I") * 4 + "II"
        blob.put(tls_off, struct.pack(fmt, 0, 0, 0, base + cb_rva, 0, 0))
        for i, cb in enumerate(tls_callbacks):
            blob.put(cbs_off + i * psize, (base + cb).to_bytes(psize, "little"))

    for m in markers:
        blob.put(blob.alloc(len(m)), m)

    hdr = bytearray(SIZE_HEADERS)
    hdr[0:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3C, E_LFANEW)
    hdr[E_LFANEW:E_LFANEW + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", hdr, E_LFANEW + 4, 0x8664 if is64 else 0x14C, 2, 0, 0, 0, sizeopt, 0x22)
    opt = E_LFANEW + 24
    struct.pack_into("<H", hdr, opt, 0x20B if is64 else 0x10B)
    if is64:
        struct.pack_into("<Q", hdr, opt + 24, base)
    else:
        struct.pack_into("<I", hdr, opt + 28, base)
    struct.pack_into("<I", hdr, opt + 16, TEXT_RVA)                 # AddressOfEntryPoint
    struct.pack_into("<II", hdr, opt + 32, 0x1000, FILE_ALIGN)      # SectionAlignment, FileAlignment
    struct.pack_into("<II", hdr, opt + 56, SIZE_IMAGE, SIZE_HEADERS)
    count_at, dirs_at = (opt + 108, opt + 112) if is64 else (opt + 92, opt + 96)
    struct.pack_into("<I", hdr, count_at, 16)
    dirs: dict[int, tuple[int, int]] = {}
    if import_dir is not None:
        dirs[1] = (import_dir, 20)
    elif imports:
        dirs[1] = (RDATA_RVA + imp_off, 20 * (len(imports) + 1))
    if delay_imports:
        dirs[13] = (RDATA_RVA + dly_off, 32 * (len(delay_imports) + 1))
    if tls_callbacks:
        dirs[9] = (RDATA_RVA + tls_off, 4 * psize + 8)
    for idx, (rva, size) in dirs.items():
        struct.pack_into("<II", hdr, dirs_at + 8 * idx, rva, size)
    sections = ((b".text", 0x200, TEXT_RVA, 0x200, SIZE_HEADERS, 0x60000020),
                (b".rdata", RDATA_SIZE, RDATA_RVA, RDATA_SIZE, RDATA_FILE_OFFSET, 0x40000040))
    for i, (nm, vs, va, rs, rp, fl) in enumerate(sections):
        struct.pack_into("<8sIIIIIIHHI", hdr, opt + sizeopt + 40 * i, nm, vs, va, rs, rp, 0, 0, 0, 0, fl)
    return bytes(hdr) + bytes([0xCC]) * FILE_ALIGN + bytes(blob.data)


def to_memory_layout(data: bytes, size: int = SIZE_IMAGE) -> bytes:
    """Converts the generated file-layout PE into a memory dump: sections are written at their RVA,
    `PointerToRawData=VirtualAddress`, `SizeOfHeaders=0x1000`, `SizeOfImage=size`.
    `size` cannot be smaller than `SizeOfImage` (the number of bytes the dump covers)."""
    if size < SIZE_IMAGE:
        raise ValueError("size must be >= SizeOfImage (0x%x)" % SIZE_IMAGE)
    if len(data) < SIZE_HEADERS:
        raise ValueError("input is shorter than the PE headers (0x%x bytes)" % SIZE_HEADERS)
    if data[:2] != b"MZ":
        raise ValueError("input does not start with the MZ signature")
    e = struct.unpack_from("<I", data, 0x3C)[0]
    if e + 24 > len(data):
        raise ValueError("e_lfanew 0x%x leaves no room for the PE header in input 0x%x"
                         % (e, len(data)))
    if data[e:e + 4] != b"PE\0\0":
        raise ValueError("missing PE signature at e_lfanew 0x%x" % e)
    opt = e + 24
    nsec = struct.unpack_from("<H", data, e + 6)[0]
    sizeopt = struct.unpack_from("<H", data, e + 20)[0]
    if sizeopt < 64:
        raise ValueError("optional header is too small (0x%x bytes, need at least 0x40)"
                         % sizeopt)
    if opt + sizeopt > len(data):
        raise ValueError("optional header 0x%x+0x%x exceeds input 0x%x"
                         % (opt, sizeopt, len(data)))
    size_of_headers = struct.unpack_from("<I", data, opt + 60)[0]
    table_end = opt + sizeopt + 40 * nsec
    if table_end > len(data):
        raise ValueError("section table ends at 0x%x, beyond input 0x%x"
                         % (table_end, len(data)))
    if table_end > size_of_headers:
        raise ValueError("section table ends at 0x%x, beyond SizeOfHeaders 0x%x"
                         % (table_end, size_of_headers))
    out = bytearray(size)
    out[:SIZE_HEADERS] = data[:SIZE_HEADERS]
    for i in range(nsec):
        rec = opt + sizeopt + 40 * i
        _nm, vs, va, rs, rp = struct.unpack_from("<8sIIIIII", data, rec)[:5]
        if rs and rp + rs > len(data):
            raise ValueError("section %d raw data 0x%x+0x%x exceeds input 0x%x"
                             % (i, rp, rs, len(data)))
        extent = vs or rs
        n = max(0, min(extent, size - va, len(data) - rp))
        out[va:va + n] = data[rp:rp + n]
        struct.pack_into("<II", out, rec + 16, extent, va)      # SizeOfRawData, PointerToRawData
    struct.pack_into("<I", out, opt + 32, 0x1000)               # FileAlignment
    struct.pack_into("<I", out, opt + 56, size)                  # SizeOfImage
    struct.pack_into("<I", out, opt + 60, 0x1000)                # SizeOfHeaders
    return bytes(out)
