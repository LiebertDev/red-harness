"""PE data directories: import, delay-load import and TLS callback tables.

Engine independent (no IDA/Ghidra): reads only the PE headers, the section table and the file bytes;
executes nothing, uses no network, adds no dependencies. `protection_scan` stays at section/packer
level while this module answers "which function is bound from which DLL"; anti-analysis
(anti-debug/anti-VM/anti-dump) and anti-cheat driver interface inference build on top of it.

Rules (fail-closed):
- If the header declares a directory (rva != 0) but its target cannot be read from the file,
  `PeDirectoryError` is raised: "could not measure" is never silently treated as "clean" or "no imports".
- A single table cut short during the walk (bad thunk, unreadable name, limit) is not discarded: the facts
  read so far are kept, the event is written to `unknowns` and `complete=False`. A partial result is not OK.
- Names are bytes from the file (latin-1); ordering is deterministic (file order, then thunk index).
- The IAT slot address (thunk_rva) is computed but the IAT itself is not read: resolved addresses
  belong to run time and are NOT in the file.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Callable

from .pe_image import PeError, PeImage, parse_pe

Reader = Callable[[int, int], bytes]   # (file offset, length) -> bytes

IMPORT_DIR = 1
TLS_DIR = 9
DELAY_IMPORT_DIR = 13
MAX_DIRECTORIES = 16

IMAGE_ORDINAL_FLAG32 = 0x80000000
IMAGE_ORDINAL_FLAG64 = 0x8000000000000000

MAX_DESCRIPTORS = 512          # max DLLs per table
MAX_IMPORTS_PER_DLL = 8192     # max symbols per DLL
MAX_IMPORTS_TOTAL = 65536      # max total symbols per table
MAX_NAME = 512                 # DLL/function name length limit (excluding NUL)
MAX_TLS_CALLBACKS = 64


class PeDirectoryError(PeError):
    """A declared data directory could not be read reliably from the file (fail-closed)."""


@dataclass(frozen=True)
class DataDirectory:
    """A data directory entry in the optional header. `rva == 0` means the directory is absent."""
    index: int
    rva: int
    size: int


@dataclass(frozen=True)
class ImportedFunction:
    """A single imported symbol. Exactly one of `name`/`ordinal` is set.
    `thunk_rva`: RVA of the IAT slot (NOT the bound address); `file_offset`: position of the name
    string in the file (None for ordinal imports)."""
    dll: str
    name: str | None
    ordinal: int | None
    hint: int | None
    thunk_rva: int
    name_rva: int | None
    file_offset: int | None


@dataclass(frozen=True)
class ImportTableFact:
    """The import descriptor of one DLL and its symbols."""
    dll: str
    descriptor_rva: int
    functions: tuple[ImportedFunction, ...]
    delay: bool


@dataclass(frozen=True)
class TlsCallback:
    """TLS callback pointer. `rva` is None if outside the image (the VA is still reported).
    `file_offset` is the file position of the POINTER SLOT (not of the callback code)."""
    index: int
    va: int
    rva: int | None
    file_offset: int | None


@dataclass(frozen=True)
class ImportProfile:
    """Import and TLS callback facts of a PE. If `complete=False` at least one table was cut short;
    `unknowns` gives the reason and the result is not OK."""
    image_base: int
    is64: bool
    imports: tuple[ImportTableFact, ...]
    delay_imports: tuple[ImportTableFact, ...]
    tls_directory_rva: int | None
    tls_callbacks: tuple[TlsCallback, ...]
    complete: bool
    unknowns: tuple[str, ...]
    notes: tuple[str, ...]

    @property
    def all_tables(self) -> tuple[ImportTableFact, ...]:
        return self.imports + self.delay_imports

    @property
    def function_count(self) -> int:
        return sum(len(t.functions) for t in self.all_tables)

    @property
    def dll_names(self) -> tuple[str, ...]:
        return tuple(t.dll for t in self.all_tables)


# ------------------------------------------------------------------------------------ low-level reading

def read_data_directories(img: PeImage, read: Reader) -> tuple[DataDirectory, ...]:
    """Reads the optional header data directories (PE32/PE32+ aware). Raises `PeDirectoryError` if the
    headers are truncated; if `NumberOfRvaAndSizes` exceeds 16 only the first 16 known directories are taken."""
    head = read(0, 0x40)
    if len(head) < 0x40:
        raise PeDirectoryError("file too short for a PE header")
    e = struct.unpack_from("<I", head, 0x3C)[0]
    need = e + 24 + 0x100
    if need > img.file_size:
        raise PeDirectoryError(f"optional header exceeds end of file (0x{need:x} > 0x{img.file_size:x})")
    head = read(0, need)
    if len(head) < need:
        raise PeDirectoryError("optional header unreadable (file returned short)")
    opt = e + 24
    magic = struct.unpack_from("<H", head, opt)[0]
    if magic == 0x20B:
        count_at, dirs_at = opt + 108, opt + 112
    elif magic == 0x10B:
        count_at, dirs_at = opt + 92, opt + 96
    else:
        raise PeDirectoryError(f"unsupported optional header magic 0x{magic:x}")
    count = struct.unpack_from("<I", head, count_at)[0]
    count = min(count, MAX_DIRECTORIES)
    sizeopt = struct.unpack_from("<H", head, e + 20)[0]
    if count and dirs_at + 8 * count > opt + sizeopt:
        raise PeDirectoryError("data directory count exceeds optional header size (corrupt header)")
    if dirs_at + 8 * count > len(head):
        raise PeDirectoryError("data directory table exceeds the header window read")
    return tuple(DataDirectory(i, *struct.unpack_from("<II", head, dirs_at + 8 * i)) for i in range(count))


def _directory(dirs: tuple[DataDirectory, ...], index: int) -> DataDirectory:
    return dirs[index] if index < len(dirs) else DataDirectory(index, 0, 0)


def _chunk_file_offset(img: PeImage, rva: int, length: int) -> int | None:
    """Returns the file offset of the first chunk if [rva, rva+length) is fully file-backed."""
    if length <= 0:
        return 0
    chunks = img.plan(rva, length)
    first = chunks[0] if chunks else None
    if first is None or first.kind != "file" or first.length != length:
        return None
    return first.file_offset


def _read_mapped(img: PeImage, read: Reader, rva: int, length: int) -> bytes | None:
    """Reads a range of the image from the file; None if any chunk is not in the file (zeros are NOT invented)."""
    if length <= 0:
        return b""
    out = bytearray()
    for c in img.plan(rva, length):
        if c.kind != "file" or c.file_offset is None:
            return None
        data = read(c.file_offset, c.length)
        if len(data) != c.length:
            return None
        out += data
    return bytes(out) if len(out) == length else None


def _read_cstr(img: PeImage, read: Reader, rva: int, max_len: int = MAX_NAME) -> str | None:
    """Reads a NUL-terminated latin-1 string. None if no NUL within max_len (truncated -> not measured)."""
    if rva <= 0:
        return None
    out = bytearray()
    cur = rva
    while len(out) < max_len:
        take = min(64, max_len - len(out))
        block = _read_mapped(img, read, cur, take)
        if block is None:
            # the 64-byte window may have crossed the section end; continue reading the name byte by byte
            block = _read_mapped(img, read, cur, 1)
            if block is None:
                return None
        z = block.find(b"\0")
        if z >= 0:
            out += block[:z]
            return out.decode("latin-1")
        out += block
        cur += len(block)
    return None


def _pointer(img: PeImage, raw: bytes) -> int:
    return int.from_bytes(raw[:img.pointer_size], "little")


# ----------------------------------------------------------------------------------------- import

def _as_rva(value: int, img: PeImage, va_based: bool) -> int | None:
    """In the old delay-load format the values are VAs; None if outside the image."""
    if not va_based:
        return value
    if img.image_base <= value < img.image_base + img.size_of_image:
        return value - img.image_base
    return None


def _walk_thunks(img: PeImage, read: Reader, *, dll: str, thunk_rva: int, iat_rva: int, delay: bool,
                 va_based: bool, unknowns: list[str]) -> tuple[list[ImportedFunction], bool]:
    """Walks one DLL's thunk array. Ends at 0. If cut short, writes to `unknowns` and returns False."""
    stride = img.pointer_size
    high = IMAGE_ORDINAL_FLAG64 if stride == 8 else IMAGE_ORDINAL_FLAG32
    out: list[ImportedFunction] = []
    for idx in range(MAX_IMPORTS_PER_DLL):
        trva = _as_rva(thunk_rva + idx * stride, img, va_based)
        irva = _as_rva(iat_rva + idx * stride, img, va_based)
        if trva is None or irva is None:
            unknowns.append(f"{dll}: thunk {idx} address outside the image (delay-load VA format)")
            return out, False
        raw = _read_mapped(img, read, trva, stride)
        if raw is None:
            unknowns.append(f"{dll}: thunk {idx} unreadable in file (rva 0x{trva:x})")
            return out, False
        value = _pointer(img, raw)
        if value == 0:
            return out, True
        if value & high:
            out.append(ImportedFunction(dll, None, value & 0xFFFF, None, irva, None, None))
            continue
        name_rva = _as_rva(value, img, va_based)
        if name_rva is None:
            unknowns.append(f"{dll}: thunk {idx} name VA outside the image (0x{value:x})")
            return out, False
        head = _read_mapped(img, read, name_rva, 2)
        if head is None:
            unknowns.append(f"{dll}: thunk {idx} name record unreadable in file (rva 0x{name_rva:x})")
            return out, False
        hint = struct.unpack_from("<H", head, 0)[0]
        name = _read_cstr(img, read, name_rva + 2)
        if name is None or name == "":
            unknowns.append(f"{dll}: thunk {idx} name empty/truncated (rva 0x{name_rva:x})")
            return out, False
        out.append(ImportedFunction(dll, name, None, hint, irva, name_rva,
                                    _chunk_file_offset(img, name_rva + 2, 1)))
    unknowns.append(f"{dll}: thunk limit {MAX_IMPORTS_PER_DLL} exceeded (table not terminated, scan stopped)")
    return out, False


def _walk_import_table(img: PeImage, read: Reader, directory: DataDirectory, *, delay: bool,
                       unknowns: list[str]) -> tuple[list[ImportTableFact], bool]:
    """Walks the import or delay-import descriptor chain. The total symbol limit is applied separately."""
    tables: list[ImportTableFact] = []
    complete = True
    total = 0
    desc_size = 32 if delay else 20
    kind = "delay-import" if delay else "import"
    # Descriptor reads are bounded to the declared directory range; the zero terminator must be inside it.
    in_range = directory.size // desc_size
    if in_range == 0:
        unknowns.append(f"{kind} directory size ({directory.size}) cannot hold one descriptor; "
                        f"terminator could not be verified")
        return tables, False
    range_ok = directory.rva + directory.size <= img.size_of_image
    if not range_ok:
        unknowns.append(f"{kind} directory range extends beyond the image/file (rva 0x{directory.rva:x}, "
                        f"size 0x{directory.size:x}); table is not treated as complete")
    for i in range(min(MAX_DESCRIPTORS, in_range)):
        rva = directory.rva + i * desc_size
        raw = _read_mapped(img, read, rva, desc_size)
        if raw is None:
            unknowns.append(f"{'delay-import' if delay else 'import'} descriptor {i} not in file "
                            f"(rva 0x{rva:x}); table cut short")
            return tables, False
        if delay:
            attributes, name_field, _mod, iat_field, int_field, _bound, _unload, _ts = struct.unpack_from(
                "<IIIIIIII", raw, 0)
            va_based = (attributes & 1) == 0
            fields = (name_field, int_field, iat_field)
        else:
            oft, _ts, _fwd, name_field, ft = struct.unpack_from("<IIIII", raw, 0)
            va_based = False
            fields = (name_field, oft or ft, ft)
        if all(v == 0 for v in fields):
            return tables, complete and range_ok
        name_rva, thunk_field, iat_field = (_as_rva(v, img, va_based) for v in fields)
        if name_rva is None or thunk_field is None or iat_field is None:
            unknowns.append(f"descriptor {i}: fields outside the image (rva 0x{rva:x})")
            return tables, False
        if not thunk_field:
            unknowns.append(f"descriptor {i}: no thunk table (FirstThunk/OriginalFirstThunk 0); "
                            f"rva 0x{rva:x}")
            return tables, False
        dll = _read_cstr(img, read, name_rva)
        if not dll:
            unknowns.append(f"descriptor {i}: DLL name unreadable/empty (rva 0x{name_rva:x})")
            return tables, False
        funcs, ok = _walk_thunks(img, read, dll=dll, thunk_rva=thunk_field, iat_rva=iat_field,
                                 delay=delay, va_based=va_based, unknowns=unknowns)
        tables.append(ImportTableFact(dll, rva, tuple(funcs), delay))
        total += len(funcs)
        complete = complete and ok
        if not ok:
            return tables, False
        if total > MAX_IMPORTS_TOTAL:
            unknowns.append(f"total import limit {MAX_IMPORTS_TOTAL} exceeded; chain stopped")
            return tables, False
    if in_range <= MAX_DESCRIPTORS:
        unknowns.append(f"{kind}: no terminating descriptor inside the declared directory range (size {directory.size}); "
                        f"table is not treated as complete")
    else:
        unknowns.append(f"descriptor limit {MAX_DESCRIPTORS} exceeded; chain stopped")
    return tables, False


# --------------------------------------------------------------------------------------------- TLS

def _scan_tls(img: PeImage, read: Reader, directory: DataDirectory,
              unknowns: list[str]) -> tuple[tuple[TlsCallback, ...], bool]:
    """Reads the TLS directory and callback array. rva is None if the callback VA is outside the image."""
    size = 4 * img.pointer_size + 8
    raw = _read_mapped(img, read, directory.rva, size)
    if raw is None:
        unknowns.append(f"TLS directory unreadable in file (rva 0x{directory.rva:x})")
        return (), False
    p = img.pointer_size
    callbacks_va = _pointer(img, raw[3 * p:4 * p])
    if callbacks_va == 0:
        return (), True
    if not (img.image_base <= callbacks_va < img.image_base + img.size_of_image):
        unknowns.append(f"TLS callback array outside the image (VA 0x{callbacks_va:x})")
        return (), False
    callbacks_rva = callbacks_va - img.image_base
    out: list[TlsCallback] = []
    for i in range(MAX_TLS_CALLBACKS):
        entry = _read_mapped(img, read, callbacks_rva + i * p, p)
        if entry is None:
            unknowns.append(f"TLS callback {i} unreadable in file (rva 0x{callbacks_rva + i * p:x})")
            return tuple(out), False
        va = _pointer(img, entry)
        if va == 0:
            return tuple(out), True
        rva = va - img.image_base if img.image_base <= va < img.image_base + img.size_of_image else None
        off = _chunk_file_offset(img, rva, p) if rva is not None else None
        out.append(TlsCallback(i, va, rva, off))
    unknowns.append(f"TLS callback limit {MAX_TLS_CALLBACKS} exceeded")
    return tuple(out), False


# ---------------------------------------------------------------------------------------- public API

def scan_imports_image(img: PeImage, read: Reader) -> ImportProfile:
    """Reads the import/delay-import/TLS tables of a parsed PE.
    `PeDirectoryError` if a declared directory is not in the file; if the walk is cut short it returns
    `complete=False` + `unknowns` (a partial result is not OK)."""
    dirs = read_data_directories(img, read)
    unknowns: list[str] = []
    notes: list[str] = []

    imp = _directory(dirs, IMPORT_DIR)
    if imp.rva:
        if imp.rva >= img.size_of_image:
            raise PeDirectoryError(f"import directory outside the image (rva 0x{imp.rva:x}, "
                                   f"SizeOfImage 0x{img.size_of_image:x})")
        imports, ok = _walk_import_table(img, read, imp, delay=False, unknowns=unknowns)
        complete = ok
    else:
        imports, complete = [], True
        notes.append("no import directory (rva 0): the file declares no imported symbols")

    dly = _directory(dirs, DELAY_IMPORT_DIR)
    if dly.rva:
        if dly.rva >= img.size_of_image:
            raise PeDirectoryError(f"delay-import directory outside the image (rva 0x{dly.rva:x})")
        delay_imports, ok = _walk_import_table(img, read, dly, delay=True, unknowns=unknowns)
        complete = complete and ok
    else:
        delay_imports = []

    tls = _directory(dirs, TLS_DIR)
    tls_rva: int | None = None
    callbacks: tuple[TlsCallback, ...] = ()
    if tls.rva:
        if tls.rva >= img.size_of_image:
            raise PeDirectoryError(f"TLS directory outside the image (rva 0x{tls.rva:x})")
        tls_rva = tls.rva
        callbacks, ok = _scan_tls(img, read, tls, unknowns)
        complete = complete and ok

    if not complete:
        notes.append("at least one table was cut short: a partial result is not OK; the missing part must be "
                     "verified by run-time observation or a repaired dump")
    return ImportProfile(img.image_base, img.is64, tuple(imports), tuple(delay_imports), tls_rva,
                         callbacks, complete, tuple(unknowns), tuple(notes))


def scan_imports(data: bytes) -> ImportProfile:
    """Extracts import/delay-import/TLS facts from the bytes of a PE file."""
    img = parse_pe(lambda off, n: data[off:off + n], len(data))
    return scan_imports_image(img, lambda off, n: data[off:off + n])


@dataclass(frozen=True)
class TlsFact:
    """TLS directory facts for the static PE profile. `status`: absent | ok | unreadable.
    `array_rva` is the RVA of the callback pointer array (None if not derivable)."""
    status: str
    directory_rva: int | None
    array_rva: int | None
    callbacks: tuple[TlsCallback, ...]
    unknowns: tuple[str, ...]


def scan_tls_image(img: PeImage, read: Reader) -> TlsFact:
    """TLS directory + callback array, independent of the import tables (a broken import table must not hide TLS).
    Never raises: a directory that cannot be read is reported `unreadable` with the reason."""
    try:
        dirs = read_data_directories(img, read)
    except PeError as e:
        return TlsFact("unreadable", None, None, (), (f"data directories unreadable: {e}",))
    tls = _directory(dirs, TLS_DIR)
    if not tls.rva:
        return TlsFact("absent", None, None, (), ())
    unknowns: list[str] = []
    if tls.rva >= img.size_of_image:
        return TlsFact("unreadable", tls.rva, None, (), (f"TLS directory outside the image (rva 0x{tls.rva:x})",))
    raw = _read_mapped(img, read, tls.rva, 4 * img.pointer_size + 8)
    if raw is None:
        return TlsFact("unreadable", tls.rva, None, (), (f"TLS directory unreadable in file (rva 0x{tls.rva:x})",))
    p = img.pointer_size
    arr_va = _pointer(img, raw[3 * p:4 * p])
    arr_rva = arr_va - img.image_base if img.image_base <= arr_va < img.image_base + img.size_of_image else None
    cbs, ok = _scan_tls(img, read, tls, unknowns)
    return TlsFact("ok" if ok else "unreadable", tls.rva, arr_rva, cbs, tuple(unknowns))
