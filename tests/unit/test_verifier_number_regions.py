"""Verifier 9: number extraction is format-aware per evidence type/section.

Regression guard for a false-accept: a `read_bytes` hex-dump row whose bytes are all decimal digits (`12`,
`123456`) was extracted from raw output as a DECIMAL number, so a claim of the decimal value 12 was "supported" by the
byte 0x12. The same held for the instruction-byte field of `disassemble` lines (`0x401000: 55 push ebp` -> 55).
A hex region carries no numbers (only its `0x..:` address prefix); multi-byte values come only from the typed views.
"""
from __future__ import annotations

import hashlib

import pytest

from redharness.analysis.pe_image import parse_pe, read_range
from redharness.core.cas import Cas
from redharness.core.journal import Journal
from redharness.core.result import Status
from redharness.evidence import verifier as V
from redharness.evidence.ledger import Ledger
from redharness.evidence.model import ClaimStatus, build_evidence

from ._pe_builder import build_pe

TARGET = hashlib.sha256(b"number-regions.exe").hexdigest()
BASE = 0x140000000
MARK_VA = BASE + 0x3030   # build_pe puts data_marker at .data + 0x30


def _ledger(tmp_path):
    cas, journal = Cas(tmp_path / "cas"), Journal(tmp_path / "events.jsonl")
    return Ledger(journal, cas, TARGET), cas


def _read_bytes_raw(marker: bytes, length: int, views=()) -> bytes:
    data = build_pe(True, data_marker=marker)
    img = parse_pe(lambda o, n: data[o:o + n], len(data))
    out = read_range(img, lambda o, n: data[o:o + n], 0x3030, length, tuple(views))
    return out.raw.encode("utf-8") if isinstance(out.raw, str) else out.raw


def _ev(ledger, cas, raw, operation):
    ev = build_evidence(cas, subject_sha256=TARGET, tool=operation, operation=operation, raw=raw, status=Status.OK,
                        confidence="observed", authority="shipped-artifact", locations=[],
                        coverage={"scope": "range", "relationship": "complete"})
    return ledger.record_evidence(ev)["evidence_id"]


def _claim(ledger, text, ev, values=None):
    return ledger.add_claim(text, "observation", "present", [ev], [], "SUPPORTED", values=values)


# ---------------------------------------------------------------- read_bytes hex dump
@pytest.mark.parametrize("marker,length,value", [
    (b"\x12", 1, 12),                    # one digits-only byte: the whole row is `12`
    (b"\x12\x34\x56", 3, 123456),        # `12 34 56` -> row `123456`
    (b"\x12\x34\x56\x78", 4, 12345678),  # exactly one 4-byte group
    (b"\x99", 1, 99),
])
def test_digits_only_hexdump_group_is_not_a_decimal_number(tmp_path, marker, length, value):
    raw = _read_bytes_raw(marker, length)
    assert f": {marker.hex()}\n".encode() in raw  # the lone group really is printed as bare digits
    ledger, cas = _ledger(tmp_path)
    ev = _ev(ledger, cas, raw, "read_bytes")
    res = _claim(ledger, f"The number is {value}.", ev, values=[value])
    assert res.status is ClaimStatus.UNVERIFIED
    assert "VALUE_NOT_IN_EVIDENCE" in [i["code"] for i in res.claim["verification"]["issues"]]
    assert value not in V._raw_numbers(raw, dump=True)[1]


def test_typed_views_still_support_multibyte_values(tmp_path):
    raw = _read_bytes_raw(b"\x12\x34", 2, views=("u8", "u16"))
    ledger, cas = _ledger(tmp_path)
    ev = _ev(ledger, cas, raw, "read_bytes")
    assert _claim(ledger, "The u16 at the marker is 13330.", ev, values=[13330]).status is ClaimStatus.SUPPORTED
    assert _claim(ledger, "The u16 at the marker is 0x3412.", ev).status is ClaimStatus.SUPPORTED
    assert _claim(ledger, "The first byte is 18.", ev, values=[18]).status is ClaimStatus.SUPPORTED  # u8 view = decimal
    # ... but the hex dump bytes themselves (0x12 0x34 -> "1234") do not make 1234 a number
    assert _claim(ledger, "The value is 1234.", ev, values=[1234]).status is ClaimStatus.UNVERIFIED


def test_dump_address_prefix_and_header_values_still_count(tmp_path):
    raw = _read_bytes_raw(b"\x12\x34\x56", 3)
    ledger, cas = _ledger(tmp_path)
    ev = _ev(ledger, cas, raw, "read_bytes")
    assert _claim(ledger, f"The read starts at 0x{MARK_VA:x}.", ev).status is ClaimStatus.SUPPORTED
    assert _claim(ledger, "The read is 3 bytes long.", ev, values=[3]).status is ClaimStatus.SUPPORTED


def test_boilerplate_numbers_of_read_bytes_are_not_values(tmp_path):
    """`4-byte groups` in the format line and the `segment 1` index are not data."""
    raw = _read_bytes_raw(b"\xaa" * 16, 16)
    hexes, decs = V._raw_numbers(raw, dump=True)
    assert 4 not in decs and 1 not in decs and 16 in decs
    ledger, cas = _ledger(tmp_path)
    ev = _ev(ledger, cas, raw, "read_bytes")
    assert _claim(ledger, "A value of 4 was read.", ev, values=[4]).status is ClaimStatus.UNVERIFIED


def test_non_dump_evidence_is_extracted_as_before():
    raw = b"0x1000: 12\n"
    assert 12 in V._raw_numbers(raw)[1]            # no read_bytes context: plain text rules (unchanged)
    assert 12 not in V._raw_numbers(raw, dump=True)[1]


def test_view_rows_with_explicit_radix_are_never_stripped():
    raw = (b"read_bytes va=0x1000 rva=0x0 length=4 arch=x64 image_base=0x0\n"
           b"hex = file bytes in file order, 4-byte groups joined by '_'; typed views are little-endian\n"
           b"segment 1 FILE 0x1000..0x1004 len=4 section=.data file_offset=0x0\n"
           b"  0x1000: 12345678\n"
           b"  -- u32 --\n"
           b"  0x1000: 0x78563412 2018915346\n"
           b"segment 2 FILE 0x2000..0x2004 len=4 section=.data file_offset=0x4\n"
           b"  0x2000: 99\n")
    hexes, decs = V._raw_numbers(raw, dump=True)
    assert 0x78563412 in hexes and 2018915346 in decs
    assert 12345678 not in decs and 99 not in decs     # the 2nd segment's dump is back in the hex region


# ---------------------------------------------------------------- disassemble instruction bytes
DISASM = (b"0x401000: 55 push ebp\n0x401001: 8bec mov ebp, esp\n0x401003: 6a20 push 20h\n"
          b"0x401005: 90 nop\n0x401006: 83c408 add esp, 8\n0x401009: 9090 nop ; 77h\n")


@pytest.mark.parametrize("value", [55, 90, 9090])
def test_instruction_byte_field_is_not_a_decimal_number(tmp_path, value):
    ledger, cas = _ledger(tmp_path)
    ev = _ev(ledger, cas, DISASM, "disassemble")
    res = _claim(ledger, f"The constant is {value}.", ev, values=[value])
    assert res.status is ClaimStatus.UNVERIFIED


def test_disassembly_operands_and_addresses_still_count(tmp_path):
    ledger, cas = _ledger(tmp_path)
    ev = _ev(ledger, cas, DISASM, "disassemble")
    assert _claim(ledger, "The push operand is 0x20.", ev).status is ClaimStatus.SUPPORTED    # IDA `20h`
    assert _claim(ledger, "esp is adjusted by 8.", ev, values=[8]).status is ClaimStatus.SUPPORTED
    assert _claim(ledger, "A nop sits at 0x401005.", ev).status is ClaimStatus.SUPPORTED
    assert _claim(ledger, "The constant is 0x55.", ev).status is ClaimStatus.REJECTED          # opcode byte != value


def test_instruction_text_that_looks_like_hex_bytes_is_kept():
    """Only the field right after `0x..:` is the byte dump; a mnemonic like `add` (hex letters) is text."""
    raw = b"0x1000: 83c408 add esp, 10h\n"
    assert V._raw_numbers(raw, asm=True)[0] >= {0x10, 0x1000}
