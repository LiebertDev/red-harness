"""Identifier-needle matching: both edges of the match must be word boundaries.

An identifier needle (`safedisc`, `securom`, `starforce`, ...) is matched case-insensitively in
ASCII and UTF-16LE. It must not match inside a longer identifier, e.g. `securomx_helper` or
`xsecurom`, but it must still match when the next character is a genuine boundary (`.` in
`securom.dll`, a space, a NUL or the end of the buffer). Non-identifier needles (`\\device\\`)
keep their raw-match behaviour.
"""

import pytest

from redharness.analysis.antianalysis import Hit, _marker_hits, scan_antianalysis
from redharness.analysis.vendors import attribute_vendors
from ._synthpe import build_pe

NEEDLE = "securom"


def _hits(data: bytes) -> dict[str, Hit]:
    return {h.needle: h for h in _marker_hits(data, data.lower())}


def _utf16(text: str) -> bytes:
    return text.encode("utf-16-le")


def _string_needles(pe: bytes) -> set[str]:
    return {h.needle for h in scan_antianalysis(pe).hits if h.source == "string"}


# ------------------------------------------------------------------------------- ASCII, positive

@pytest.mark.parametrize("data", [
    b"securom",              # start AND end of the buffer
    b"\x00securom\x00",      # NUL-delimited string
    b"...securom",           # end of buffer right after the needle
    b"SecuROM ",             # trailing space
    b"securom.dll",          # extension: '.' is not an identifier char, so this is a boundary
    b"v1.0 (securom)",       # trailing ')'
])
def test_ascii_identifier_needle_matches_at_boundaries(data):
    hit = _hits(data).get(NEEDLE)
    assert hit is not None and hit.source == "string"
    assert hit.occurrences == 1
    assert hit.file_offset == data.lower().index(b"securom")
    assert hit.offsets == (data.lower().index(b"securom"),)


# ------------------------------------------------------------------------------- ASCII, negative

@pytest.mark.parametrize("data", [
    b"xsecurom",             # longer token before the needle
    b"securomx",             # longer token after the needle (the reported false positive)
    b"securomx_helper",      # the review's example
    b"securom64",
    b"securom_",
    b"_securom",
])
def test_ascii_identifier_needle_does_not_match_inside_longer_token(data):
    assert NEEDLE not in _hits(data)


def test_ascii_only_bounded_occurrences_are_counted():
    data = b"securomx_helper securom.dll xsecurom securom"
    hit = _hits(data)[NEEDLE]
    assert hit.occurrences == 2
    assert hit.offsets == (data.index(b"securom.dll"), data.rindex(b"securom"))
    assert hit.file_offset == data.index(b"securom.dll")


# ---------------------------------------------------------------------------- UTF-16LE, positive

@pytest.mark.parametrize("text", [
    "securom",               # start and end of the buffer
    "\x00securom\x00",       # NUL-delimited UTF-16 string
    " securom",              # end of buffer after a space code unit
    "SecuROM ",              # trailing space code unit
    "securom.dll",           # '.' is a boundary in the UTF-16 path too
])
def test_utf16le_identifier_needle_matches_at_boundaries(text):
    data = _utf16(text)
    hit = _hits(data).get(NEEDLE)
    assert hit is not None and hit.source == "string"
    assert hit.occurrences == 1
    assert hit.file_offset == data.lower().index(_utf16("securom"))
    assert "utf-16le" in hit.detail


# ---------------------------------------------------------------------------- UTF-16LE, negative

@pytest.mark.parametrize("text", [
    "xsecurom",
    "securomx",
    "securomx_helper",
    "securom64",
    "securom_",
    "_securom",
])
def test_utf16le_identifier_needle_does_not_match_inside_longer_token(text):
    assert NEEDLE not in _hits(_utf16(text))


# ----------------------------------------------------------- non-identifier needles are unchanged

def test_non_identifier_needle_keeps_raw_match_inside_a_longer_path():
    # '\\device\\' contains a backslash, so it is not an identifier needle: no boundary check.
    assert "\\device\\" in _hits(b"\\Device\\LabDevice\\Control")
    assert "\\device\\" in _hits(b"prefix\\Device\\suffix")


def test_dotted_module_needles_still_match_driver_names():
    assert "easyanticheat.sys" in _hits(b"...\\EasyAntiCheat.sys")
    assert "vgk.sys" in _hits(b"System32\\drivers\\vgk.sys")


# ------------------------------------------------------------------------------ end to end (PE)

def test_scan_rejects_prefix_token_and_accepts_dot_boundary():
    assert NEEDLE not in _string_needles(build_pe(markers=(b"securomx_helper\0",)))
    assert NEEDLE in _string_needles(build_pe(markers=(b"securom.dll\0",)))
    assert NEEDLE in _string_needles(build_pe(markers=(b"SecuROM \0",)))


def test_scan_rejects_prefix_token_in_utf16le():
    assert NEEDLE not in _string_needles(build_pe(markers=(_utf16("securomx_helper") + b"\0\0",)))
    assert NEEDLE in _string_needles(build_pe(markers=(_utf16("securom.dll") + b"\0\0",)))


def test_vendor_attribution_ignores_prefix_only_token():
    prefix_only = attribute_vendors(scan_antianalysis(build_pe(markers=(b"securomx_helper\0",))))
    assert [v.vendor_id for v in prefix_only] == []
    real = attribute_vendors(scan_antianalysis(build_pe(markers=(b"securom.dll\0",))))
    assert [v.vendor_id for v in real] == [NEEDLE]
    assert (real[0].score, real[0].confidence) == (3, "moderate")
