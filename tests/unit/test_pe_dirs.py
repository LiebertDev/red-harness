"""Import descriptor walkers are bounded to the declared directory range (hand-built minimal PE bytes)."""
import struct

from redharness.analysis.pe_dirs import IMPORT_DIR, scan_imports
from tests.unit._pe_builder import build_pe

RDATA_FILE = 0x600
RDATA_RVA = 0x2000
E = 0x80
OPT = E + 24


def _pe(size: int, *, second_descriptor: bytes = b"\0" * 20, truncate: int | None = None) -> bytes:
    b = bytearray(build_pe(True))
    struct.pack_into("<I", b, OPT + 108, 16)
    struct.pack_into("<II", b, OPT + 112 + 8 * IMPORT_DIR, RDATA_RVA, size)
    r = RDATA_FILE
    b[r:r + 0x80] = b"\0" * 0x80
    b[r:r + 20] = struct.pack("<IIIII", RDATA_RVA + 0x40, 0, 0, RDATA_RVA + 0x30, RDATA_RVA + 0x50)
    b[r + 20:r + 40] = second_descriptor
    b[r + 0x30:r + 0x36] = b"a.dll\0"
    b[r + 0x38:r + 0x3E] = b"\0\0Foo\0"
    struct.pack_into("<QQ", b, r + 0x40, RDATA_RVA + 0x38, 0)
    struct.pack_into("<QQ", b, r + 0x50, RDATA_RVA + 0x38, 0)
    return bytes(b if truncate is None else b[:truncate])


def test_normal_terminated_in_range_is_complete():
    p = scan_imports(_pe(40))
    assert p.complete and not p.unknowns
    assert [f.name for f in p.imports[0].functions] == ["Foo"]


def test_missing_terminator_in_range_is_incomplete():
    # Declared range covers only the first descriptor; the following zero bytes are outside it.
    p = scan_imports(_pe(20))
    assert not p.complete
    assert p.unknowns


def test_garbage_after_range_not_read_as_import():
    garbage = struct.pack("<IIIII", RDATA_RVA + 0x40, 0, 0, RDATA_RVA + 0x30, RDATA_RVA + 0x50)
    p = scan_imports(_pe(20, second_descriptor=garbage))
    assert not p.complete and len(p.imports) == 1


def test_size_beyond_image_is_incomplete():
    assert not scan_imports(_pe(0x10000)).complete


def test_size_larger_than_truncated_file_is_incomplete_without_crash():
    assert not scan_imports(_pe(0x10000, truncate=RDATA_FILE + 0x10)).complete


def test_zero_declared_size_is_incomplete():
    assert not scan_imports(_pe(0)).complete
