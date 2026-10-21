"""R5 raw file strings: section/overlay offsets, mapped RVA, UTF-16, pattern filter and boundary decoy."""

from redharness.analysis.file_strings import scan_file_strings
from ._synthpe import build_pe

ASCII_MARKER = b"R5-ASCII-MARKER"
UTF16_TEXT = "R5-UTF16-OVERLAY"


def test_ascii_section_and_utf16_overlay_offsets():
    pe = build_pe(markers=(ASCII_MARKER + b"\0", b"ABCD\0EFGH\0"))
    data = pe + UTF16_TEXT.encode("utf-16-le")
    r = scan_file_strings(data, min_length=4)
    ascii_hit = next(s for s in r.entries if s.value == ASCII_MARKER.decode())
    assert ascii_hit.file_offset == pe.find(ASCII_MARKER)
    assert ascii_hit.rva is not None and ascii_hit.section is not None
    assert ascii_hit.encoding == "ascii"

    utf = next(s for s in r.entries if s.value == UTF16_TEXT)
    assert utf.file_offset == len(pe)
    assert utf.rva is None and utf.section is None
    assert utf.encoding == "utf-16le" and utf.byte_length == len(UTF16_TEXT) * 2

    # A NUL-separated pair must not be concatenated into one string.
    assert not any(s.value == "ABCDEFGH" for s in r.entries)


def test_pattern_filter_and_truncation():
    data = build_pe(markers=(b"needle-one\0", b"other-two\0", b"needle-three\0"))
    r = scan_file_strings(data, pattern="needle")
    assert {s.value for s in r.entries} == {"needle-one", "needle-three"}
    assert r.total == 2 and not r.truncated

    r2 = scan_file_strings(data, max_strings=1)
    assert len(r2.entries) == 1 and r2.total == 1 and r2.truncated and r2.reasons == ("max_hits",)


def test_non_pe_offsets_are_file_offsets():
    r = scan_file_strings(b"\x00hello-raw\x00")
    assert any(s.value == "hello-raw" and s.rva is None for s in r.entries)
    assert any("not a parseable PE" in n for n in r.notes)


def test_pe_parse_failure_does_not_block_the_raw_scan(monkeypatch):
    import redharness.analysis.file_strings as fs

    def boom(*_a, **_k):
        raise RuntimeError("corrupt PE")

    monkeypatch.setattr(fs, "parse_pe", boom)
    r = fs.scan_file_strings(b"\x00hello-raw\x00")
    assert any(s.value == "hello-raw" and s.rva is None and s.section is None for s in r.entries)
    assert any("not a parseable PE" in n for n in r.notes)
