"""Synthetic PE generator: header layout, import/delay/TLS tables, markers and memory mapping."""

import struct

import pytest

from redharness.analysis.pe_image import parse_pe
from ._synthpe import (
    E_LFANEW,
    FILE_ALIGN,
    RDATA_FILE_OFFSET,
    RDATA_RVA,
    RDATA_SIZE,
    SIZE_HEADERS,
    SIZE_IMAGE,
    TEXT_RVA,
    build_pe,
    to_memory_layout,
)

PSIZE = {True: 8, False: 4}


def _opt(pe: bytes) -> int:
    return struct.unpack_from("<I", pe, 0x3C)[0] + 24


def _patch(pe: bytes, offset: int, value: int, fmt: str = "<I") -> bytes:
    buf = bytearray(pe)
    struct.pack_into(fmt, buf, offset, value)
    return bytes(buf)


def _dir(pe: bytes, index: int) -> tuple[int, int]:
    dirs_at = _opt(pe) + (112 if _is64(pe) else 96)
    return struct.unpack_from("<II", pe, dirs_at + 8 * index)


def _is64(pe: bytes) -> bool:
    return struct.unpack_from("<H", pe, _opt(pe))[0] == 0x20B


def _off(rva: int) -> int:
    return RDATA_FILE_OFFSET + (rva - RDATA_RVA)


def _cstr(pe: bytes, rva: int) -> str:
    start = _off(rva)
    return pe[start:pe.index(b"\0", start)].decode("ascii")


def _thunks(pe: bytes, rva: int) -> list[int]:
    psize = PSIZE[_is64(pe)]
    out, i = [], 0
    while True:
        value = int.from_bytes(pe[_off(rva) + i * psize:_off(rva) + (i + 1) * psize], "little")
        out.append(value)
        if value == 0:
            return out
        i += 1


def _sections(pe: bytes) -> list[tuple[bytes, int, int, int, int, int]]:
    e = struct.unpack_from("<I", pe, 0x3C)[0]
    nsec = struct.unpack_from("<H", pe, e + 6)[0]
    sizeopt = struct.unpack_from("<H", pe, e + 20)[0]
    rec = e + 24 + sizeopt
    out = []
    for i in range(nsec):
        rec_i = struct.unpack_from("<8sIIIIIIHHI", pe, rec + 40 * i)
        out.append((rec_i[0].rstrip(b"\0"),) + rec_i[1:])
    return out


def test_default_pe64_layout_is_the_documented_one():
    pe = build_pe()
    assert len(pe) == SIZE_HEADERS + FILE_ALIGN + RDATA_SIZE == 0x1600
    assert pe[:2] == b"MZ" and struct.unpack_from("<I", pe, 0x3C)[0] == E_LFANEW
    assert pe[E_LFANEW:E_LFANEW + 4] == b"PE\0\0"
    e = E_LFANEW
    assert struct.unpack_from("<HHIIIHH", pe, e + 4) == (0x8664, 2, 0, 0, 0, 0xF0, 0x22)
    opt = _opt(pe)
    assert struct.unpack_from("<H", pe, opt)[0] == 0x20B
    assert struct.unpack_from("<Q", pe, opt + 24)[0] == 0x140000000
    assert struct.unpack_from("<I", pe, opt + 16)[0] == TEXT_RVA
    assert struct.unpack_from("<II", pe, opt + 32) == (0x1000, FILE_ALIGN)
    assert struct.unpack_from("<II", pe, opt + 56) == (SIZE_IMAGE, SIZE_HEADERS)
    assert _sections(pe) == [
        (b".text", 0x200, TEXT_RVA, 0x200, SIZE_HEADERS, 0, 0, 0, 0, 0x60000020),
        (b".rdata", RDATA_SIZE, RDATA_RVA, RDATA_SIZE, RDATA_FILE_OFFSET, 0, 0, 0, 0, 0x40000040),
    ]
    assert pe[SIZE_HEADERS:SIZE_HEADERS + 0x200] == b"\xCC" * 0x200
    assert pe[RDATA_FILE_OFFSET:] == bytes(RDATA_SIZE)
    assert _dir(pe, 1) == (0, 0) and _dir(pe, 9) == (0, 0) and _dir(pe, 13) == (0, 0)


def test_pe32_variant_changes_magic_machine_and_base_only():
    pe = build_pe(is64=False)
    assert len(pe) == 0x1600
    assert struct.unpack_from("<H", pe, E_LFANEW + 4)[0] == 0x14C
    opt = _opt(pe)
    assert struct.unpack_from("<H", pe, opt)[0] == 0x10B
    assert struct.unpack_from("<I", pe, opt + 28)[0] == 0x400000
    assert struct.unpack_from("<H", pe, E_LFANEW + 20)[0] == 0xE0
    assert struct.unpack_from("<I", pe, opt + 16)[0] == TEXT_RVA
    assert [s[0] for s in _sections(pe)] == [b".text", b".rdata"]


@pytest.mark.parametrize("is64", [True, False])
def test_import_directory_names_and_ordinals(is64):
    pe = build_pe(is64=is64, imports={"KERNEL32.dll": ["IsDebuggerPresent", 17],
                                      "A.dll": ["X"]})
    rva, size = _dir(pe, 1)
    assert (rva, size) == (RDATA_RVA, 20 * 3)
    desc = struct.unpack_from("<IIIII", pe, _off(rva))
    assert desc[1] == 0 and desc[2] == 0
    assert _cstr(pe, desc[3]) == "KERNEL32.dll"
    assert desc[4] != 0
    second = struct.unpack_from("<IIIII", pe, _off(rva) + 20)
    assert _cstr(pe, second[3]) == "A.dll"
    assert struct.unpack_from("<IIIII", pe, _off(rva) + 40) == (0, 0, 0, 0, 0)

    psize = PSIZE[is64]
    ints = _thunks(pe, desc[0])
    assert ints[0] != 0 and ints[0] < (1 << (psize * 8 - 1))
    assert pe[_off(ints[0]):_off(ints[0]) + 2] == b"\0\0"
    assert _cstr(pe, ints[0] + 2) == "IsDebuggerPresent"
    assert ints[1] == (1 << (psize * 8 - 1)) | 17
    assert _thunks(pe, desc[4]) == [0]            # unbound IAT is zero


def test_import_dir_override_and_zero_oft():
    pe = build_pe(imports={"K.dll": ["F"]}, import_dir=0x3000)
    assert _dir(pe, 1)[0] == 0x3000
    desc = struct.unpack_from("<IIIII", pe, RDATA_FILE_OFFSET)
    assert desc[0] != 0 and desc[4] != 0

    pe2 = build_pe(imports={"K.dll": ["F"]}, zero_oft=True)
    assert _dir(pe2, 1)[0] == RDATA_RVA
    desc2 = struct.unpack_from("<IIIII", pe2, RDATA_FILE_OFFSET)
    assert desc2[0] == 0 and desc2[4] != 0


def test_delay_import_descriptor_points_at_name_and_thunks():
    pe = build_pe(delay_imports={"B.dll": ["Y"]})
    rva, size = _dir(pe, 13)
    assert (rva, size) == (RDATA_RVA + 20, 64)
    attrs, name, hmod, iat, int_rva, bound, unload, stamp = struct.unpack_from(
        "<IIIIIIII", pe, _off(rva))
    assert (attrs, hmod, bound, unload, stamp) == (1, 0, 0, 0, 0)
    assert _cstr(pe, name) == "B.dll"
    assert int_rva != 0 and iat != 0
    first = _thunks(pe, int_rva)[0]
    assert first != 0
    assert pe[_off(first):_off(first) + 4] == b"\0\0Y\0"


@pytest.mark.parametrize("is64", [True, False])
def test_tls_directory_lists_base_relative_callbacks(is64):
    pe = build_pe(is64=is64, tls_callbacks=(0x1010, 0x1020))
    psize = PSIZE[is64]
    base = 0x140000000 if is64 else 0x400000
    rva, size = _dir(pe, 9)
    assert size == 4 * psize + 8
    fmt = "<" + ("Q" if is64 else "I") * 4 + "II"
    start, end, index, callbacks, zero_fill, chars = struct.unpack_from(fmt, pe, _off(rva))
    assert (start, end, index, zero_fill, chars) == (0, 0, 0, 0, 0)
    assert callbacks > base
    cbs = _thunks(pe, callbacks - base)
    assert cbs == [base + 0x1010, base + 0x1020, 0]


def test_markers_are_appended_to_rdata_in_order():
    pe = build_pe(markers=(b"MARKER-ONE\0", b"MARKER-TWO\0"))
    # An empty import-directory terminator (20 bytes) is allocated first.
    assert pe.find(b"MARKER-ONE") == RDATA_FILE_OFFSET + 20
    assert pe.find(b"MARKER-TWO") == RDATA_FILE_OFFSET + 31
    assert len(pe) == 0x1600


def test_rdata_capacity_boundary_is_exact():
    room = RDATA_SIZE - 20
    full = build_pe(markers=(b"x" * room,))
    assert len(full) == 0x1600 and full.find(b"x" * room) == RDATA_FILE_OFFSET + 20
    with pytest.raises(AssertionError, match="rdata"):
        build_pe(markers=(b"x" * (room + 1),))


def test_resolved_base_and_iat_names_fill_the_iat():
    def iat(pe: bytes) -> list[int]:
        rva = _dir(pe, 1)[0]
        desc = struct.unpack_from("<IIIII", pe, _off(rva))
        iat_rva = desc[4]
        psize = PSIZE[_is64(pe)]
        return [int.from_bytes(pe[_off(iat_rva) + i * psize:_off(iat_rva) + (i + 1) * psize],
                               "little") for i in range(3)]

    resolved = build_pe(imports={"K.dll": ["F", "G"]}, resolved_base=0x140000000)
    assert iat(resolved) == [0x140001000, 0x140002000, 0]

    named = build_pe(imports={"K.dll": ["F", "G"]}, iat_names=True)
    desc = struct.unpack_from("<IIIII", named, RDATA_FILE_OFFSET)
    assert iat(named) == _thunks(named, desc[0])

    assert iat(build_pe(imports={"K.dll": ["F", "G"]})) == [0, 0, 0]


@pytest.mark.parametrize("is64", [True, False])
def test_to_memory_layout_maps_sections_at_their_rva(is64):
    pe = build_pe(is64=is64, imports={"KERNEL32.dll": ["IsDebuggerPresent"]},
                  markers=(b"MARKER",))
    m = to_memory_layout(pe)
    assert len(m) == SIZE_IMAGE
    img = parse_pe(lambda off, n: m[off:off + n], len(m))
    assert [(s.name, s.rva, s.raw_ptr, s.raw_size) for s in img.sections] == [
        (".text", TEXT_RVA, TEXT_RVA, 0x200),
        (".rdata", RDATA_RVA, RDATA_RVA, RDATA_SIZE),
    ]
    assert img.size_of_headers == 0x1000 and img.size_of_image == SIZE_IMAGE
    assert m[TEXT_RVA:TEXT_RVA + 0x200] == b"\xCC" * 0x200
    assert m[RDATA_RVA:RDATA_RVA + RDATA_SIZE] == pe[RDATA_FILE_OFFSET:]
    assert m.find(b"MARKER") == RDATA_RVA + (pe.find(b"MARKER") - RDATA_FILE_OFFSET)
    assert struct.unpack_from("<I", m, _opt(m) + 16)[0] == TEXT_RVA
    assert _dir(m, 1) == _dir(pe, 1)


def test_to_memory_layout_size_boundaries():
    pe = build_pe()
    with pytest.raises(ValueError, match="SizeOfImage"):
        to_memory_layout(pe, size=SIZE_IMAGE - 1)
    assert len(to_memory_layout(pe, size=SIZE_IMAGE)) == SIZE_IMAGE
    bigger = to_memory_layout(pe, size=SIZE_IMAGE + 0x2000)
    assert len(bigger) == SIZE_IMAGE + 0x2000
    assert struct.unpack_from("<I", bigger, _opt(bigger) + 56)[0] == SIZE_IMAGE + 0x2000


def test_generation_is_deterministic_and_options_change_bytes():
    assert build_pe(imports={"K.dll": ["F"]}) == build_pe(imports={"K.dll": ["F"]})
    assert build_pe() != build_pe(is64=False)
    assert build_pe() != build_pe(markers=(b"x",))
    assert build_pe(base=0x180000000) != build_pe()


def test_to_memory_layout_rejects_truncated_headers():
    with pytest.raises(ValueError, match="headers"):
        to_memory_layout(build_pe()[:0x200])
    # Headers survive but .rdata's raw range (0x600+0x1000) runs past the input.
    with pytest.raises(ValueError, match="exceeds input"):
        to_memory_layout(build_pe()[:0x1000])


def test_to_memory_layout_rejects_e_lfanew_past_eof():
    pe = build_pe()
    with pytest.raises(ValueError, match="e_lfanew"):
        to_memory_layout(_patch(pe, 0x3C, len(pe)))
    with pytest.raises(ValueError, match="e_lfanew"):
        to_memory_layout(_patch(pe, 0x3C, 0x2000))


def test_to_memory_layout_rejects_truncated_optional_header():
    pe = build_pe()
    # SizeOfOptionalHeader claims more bytes than the input holds.
    with pytest.raises(ValueError, match="optional header"):
        to_memory_layout(_patch(pe, E_LFANEW + 20, 0x2000, "<H"))


def test_to_memory_layout_rejects_section_table_beyond_size_of_headers():
    pe = build_pe()
    # SizeOfHeaders (optional header +0x3C) is shrunk below the section table.
    with pytest.raises(ValueError, match="SizeOfHeaders"):
        to_memory_layout(_patch(pe, _opt(pe) + 60, 0x100))


def test_to_memory_layout_allows_zero_size_raw_section_with_far_pointer():
    pe = build_pe()
    sizeopt = struct.unpack_from("<H", pe, E_LFANEW + 20)[0]
    rec = _opt(pe) + sizeopt + 40                     # .rdata section header
    buf = bytearray(pe)
    struct.pack_into("<II", buf, rec + 16, 0, 0xFFFFFFF0)
    m = to_memory_layout(bytes(buf))
    assert len(m) == SIZE_IMAGE
    vs, va, rs, rp = struct.unpack_from("<IIII", m, rec + 8)
    assert (vs, va, rs, rp) == (RDATA_SIZE, RDATA_RVA, RDATA_SIZE, RDATA_RVA)
    assert m[RDATA_RVA:RDATA_RVA + RDATA_SIZE] == bytes(RDATA_SIZE)
