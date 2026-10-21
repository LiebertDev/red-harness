"""Protection profiling on synthetic PEs: markers, entropy boundaries, EP placement, fail-closed cuts."""

import hashlib
import struct

import pytest

from redharness.analysis.protection import (
    HIGH_ENTROPY_MIN_RAW,
    HIGH_ENTROPY_THRESHOLD,
    ProtectionError,
    compute_entropy,
    scan_protection,
    scan_protection_file,
)
from ._synthpe import RDATA_FILE_OFFSET, SIZE_IMAGE, build_pe

TEXT_REC = 0
RDATA_REC = 1


def _opt(pe: bytes) -> int:
    return struct.unpack_from("<I", pe, 0x3C)[0] + 24


def _rec(pe: bytes, index: int) -> int:
    e = struct.unpack_from("<I", pe, 0x3C)[0]
    sizeopt = struct.unpack_from("<H", pe, e + 20)[0]
    return e + 24 + sizeopt + 40 * index


def _patch_u32(pe: bytes, offset: int, value: int) -> bytes:
    out = bytearray(pe)
    struct.pack_into("<I", out, offset, value)
    return bytes(out)


def _set_raw_size(pe: bytes, index: int, value: int) -> bytes:
    return _patch_u32(pe, _rec(pe, index) + 16, value)


def _set_raw_ptr(pe: bytes, index: int, value: int) -> bytes:
    return _patch_u32(pe, _rec(pe, index) + 20, value)


def _set_name(pe: bytes, index: int, name: bytes) -> bytes:
    out = bytearray(pe)
    out[_rec(pe, index):_rec(pe, index) + 8] = name.ljust(8, b"\0")
    return bytes(out)


def _set_ep(pe: bytes, rva: int) -> bytes:
    return _patch_u32(pe, _opt(pe) + 16, rva)


def _set_text_flags(pe: bytes, flags: int) -> bytes:
    return _patch_u32(pe, _rec(pe, TEXT_REC) + 36, flags)


def _high_entropy_rdata() -> bytes:
    body = bytes(range(256)) * 16          # exactly 4096 bytes, entropy 8.0
    pe = build_pe()
    assert len(body) == HIGH_ENTROPY_MIN_RAW
    return pe[:RDATA_FILE_OFFSET] + body


def test_plain_synthetic_pe_has_sections_entropy_and_no_findings():
    pe = build_pe()
    p = scan_protection(pe)
    assert p.sha256 == hashlib.sha256(pe).hexdigest()
    assert p.file_size == len(pe) == 0x1600
    assert [s.name for s in p.sections] == [".text", ".rdata"]
    assert all(s.entropy == 0.0 and s.raw_size > 0 for s in p.sections)
    assert p.entry_point_rva == 0x1000
    assert p.entry_point_section == ".text" and p.entry_point_in_exec is True
    assert p.markers == () and p.anomalies == () and p.notes == ()


def test_pe32_is_profiled_too():
    p = scan_protection(build_pe(is64=False))
    assert [s.name for s in p.sections] == [".text", ".rdata"]
    assert p.entry_point_section == ".text" and p.entry_point_in_exec is True


def test_section_name_marker_has_no_file_offset_but_names_the_rva():
    p = scan_protection(_set_name(build_pe(), RDATA_REC, b".vmp0"))
    marker = next(m for m in p.markers if m.id == "name:.vmp0")
    assert marker.kind == "section-name"
    assert marker.file_offset is None
    assert "0x2000" in marker.detail
    assert p.notes == ()


def test_each_byte_signature_occurrence_is_its_own_marker():
    pe = build_pe(markers=(b"UPX!", b"UPX!"))
    p = scan_protection(pe)
    hits = [m for m in p.markers if m.id == "sig:UPX!"]
    assert [m.file_offset for m in hits] == [pe.find(b"UPX!"), pe.find(b"UPX!") + 4]
    assert hits[0].file_offset < hits[1].file_offset
    assert all(m.kind == "byte-signature" for m in hits)
    assert any("byte signatures" in n for n in p.notes)


def test_zero_raw_section_entropy_is_unmeasured_none_not_zero():
    pe = _set_raw_size(build_pe(), TEXT_REC, 0)
    p = scan_protection(pe)
    text = p.sections[0]
    assert text.entropy is None and text.raw_size == 0 and text.vsize == 0x200
    assert any(".text" in n and "NOT counted as 0" in n for n in p.notes)
    assert p.entry_point_in_exec is True


@pytest.mark.parametrize("raw_size, flagged", [(HIGH_ENTROPY_MIN_RAW, True),
                                               (HIGH_ENTROPY_MIN_RAW - 1, False)])
def test_high_entropy_threshold_boundary(raw_size, flagged):
    pe = _set_raw_size(_high_entropy_rdata(), RDATA_REC, raw_size)
    p = scan_protection(pe)
    assert p.sections[RDATA_REC].entropy >= HIGH_ENTROPY_THRESHOLD
    ids = [a.id for a in p.anomalies]
    assert ("high_entropy_section" in ids) is flagged
    if flagged:
        a = next(a for a in p.anomalies if a.id == "high_entropy_section")
        assert (a.file_offset, a.rva) == (RDATA_FILE_OFFSET, 0x2000)
    else:
        assert "overlay_present" in ids        # shortened raw size leaves the tail behind


def test_raw_pointer_is_rounded_down_like_the_loader():
    pe = _set_raw_ptr(build_pe(), RDATA_REC, RDATA_FILE_OFFSET + 0x1FF)
    p = scan_protection(pe)
    assert p.sections[RDATA_REC].raw_offset == RDATA_FILE_OFFSET


def test_writable_executable_section_is_an_anomaly():
    p = scan_protection(_set_text_flags(build_pe(), 0xE0000020))
    a = next(a for a in p.anomalies if a.id == "wx_section")
    assert (a.rva, a.file_offset) == (0x1000, None)
    assert ".text" in a.detail


def test_overlay_is_reported_at_the_first_byte_after_the_last_section():
    pe = build_pe()
    p = scan_protection(pe + b"OVERLAY!")
    a = next(a for a in p.anomalies if a.id == "overlay_present")
    assert (a.file_offset, a.rva) == (len(pe), None)
    assert "8" in a.detail


def test_entry_point_inside_rdata_is_outside_code():
    p = scan_protection(_set_ep(build_pe(), 0x2010))
    assert p.entry_point_section == ".rdata" and p.entry_point_in_exec is False
    a = next(a for a in p.anomalies if a.id == "entry_point_outside_code")
    assert (a.rva, a.file_offset) == (0x2010, None)
    assert ".rdata" in a.detail


@pytest.mark.parametrize("ep, expected", [(SIZE_IMAGE - 1, False), (SIZE_IMAGE, None)])
def test_entry_point_at_and_beyond_size_of_image(ep, expected):
    p = scan_protection(_set_ep(build_pe(), ep))
    assert p.entry_point_in_exec is expected
    assert p.entry_point_section is None
    assert "entry_point_outside_code" in [a.id for a in p.anomalies]


def test_beyond_image_detail_names_size_of_image():
    p = scan_protection(_set_ep(build_pe(), 0x5000))
    a = next(a for a in p.anomalies if a.id == "entry_point_outside_code")
    assert "SizeOfImage" in a.detail and "0x5000" in a.detail


def test_same_bytes_give_the_same_profile():
    pe = build_pe(markers=(b"UPX!",))
    assert scan_protection(pe) == scan_protection(pe)
    assert scan_protection(pe).sha256 != scan_protection(pe + b"x").sha256


@pytest.mark.parametrize("cut", [0, 1, 63, 64, 0x80, 0x187, 0x188, 0x1D7, 0x1D8,
                                 0x3FF, 0x400, 0x5FF, 0x600, 0x15FF])
def test_truncated_pe_raises_instead_of_returning_a_clean_profile(cut):
    pe = build_pe()
    assert cut < len(pe)
    with pytest.raises(ProtectionError):
        scan_protection(pe[:cut])


def test_pe_error_text_is_preserved_in_protection_error():
    with pytest.raises(ProtectionError, match="bad e_lfanew"):
        scan_protection(b"MZ" + b"\0" * 62)
    with pytest.raises(ProtectionError, match="file too small"):
        scan_protection(b"")
    with pytest.raises(ProtectionError, match="missing MZ"):
        scan_protection(b"XXXX" * 16)


def test_scan_protection_file_matches_bytes_and_missing_file_is_fail_closed(tmp_path):
    pe = build_pe(markers=(b"UPX!",))
    path = tmp_path / "sample.exe"
    path.write_bytes(pe)
    assert scan_protection_file(path) == scan_protection(pe)
    with pytest.raises(ProtectionError):
        scan_protection_file(tmp_path / "missing.exe")


def test_compute_entropy_boundaries():
    assert compute_entropy(b"") == 0.0
    assert compute_entropy(b"\0" * 1024) == 0.0
    assert compute_entropy(b"\0\xff" * 512) == pytest.approx(1.0)
    assert compute_entropy(bytes(range(256))) == pytest.approx(8.0)
