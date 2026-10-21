"""Verifier 8: an evidence location (address/offset range or point) never supports an arbitrary numeric value.

Reproduction of the read_bytes known weakness: a read at a low RVA range (headers, 0x0-0x400) "contained" small
integers, so an invented small number passed because it fell inside the cited address range. A location now backs a
number only through an explicit `address` atom (the claim says the value IS an address), and then only as a hex
literal / hex-form value, never as a decimal result value.
"""
from __future__ import annotations

import hashlib

import pytest

from redharness.core.cas import Cas
from redharness.core.journal import Journal
from redharness.core.result import Status
from redharness.evidence.ledger import Ledger
from redharness.evidence.model import ClaimStatus, build_evidence

TARGET = hashlib.sha256(b"location-values.exe").hexdigest()
# a read_bytes-shaped evidence: header range in both spaces, hex dump without the numbers used below
HEADER_RAW = (b"read_bytes va=0x400000 rva=0x0 length=1024\n"
              b"  0x400000: 4d5a_9000 0300_0000 0400_0000 ffff_0000\n")
HEADER_LOCS = [{"kind": "address-range", "space": "va", "start": 0x400000, "end": 0x400400},
               {"kind": "address-range", "space": "rva", "start": 0x0, "end": 0x400}]


def _ledger(tmp_path):
    cas, journal = Cas(tmp_path / "cas"), Journal(tmp_path / "events.jsonl")
    return Ledger(journal, cas, TARGET), cas


def _ev(ledger, cas, raw=HEADER_RAW, locations=HEADER_LOCS, operation="read_bytes"):
    ev = build_evidence(cas, subject_sha256=TARGET, tool=operation, operation=operation, raw=raw, status=Status.OK,
                        confidence="observed", authority="shipped-artifact", locations=locations,
                        coverage={"scope": "range", "relationship": "complete"})
    return ledger.record_evidence(ev)["evidence_id"]


def _claim(ledger, text, ev, atoms=(), values=None, kind="observation"):
    return ledger.add_claim(text, kind, "present", [ev], list(atoms), "SUPPORTED", values=values)


def test_invented_small_decimal_value_in_low_rva_range_is_not_supported(tmp_path):
    ledger, cas = _ledger(tmp_path)
    ev = _ev(ledger, cas)
    res = _claim(ledger, "The header field holds the number 77.", ev, values=[77])
    assert res.status is ClaimStatus.UNVERIFIED
    assert "VALUE_NOT_IN_EVIDENCE" in [i["code"] for i in res.claim["verification"]["issues"]]


def test_invented_small_hex_literal_in_low_rva_range_is_rejected(tmp_path):
    ledger, cas = _ledger(tmp_path)
    ev = _ev(ledger, cas)
    res = _claim(ledger, "The checksum constant is 0x2c.", ev)
    assert res.status is ClaimStatus.REJECTED
    assert "HEX_LITERAL_UNSUPPORTED" in [i["code"] for i in res.issues]


def test_invented_hex_form_declared_value_is_not_supported(tmp_path):
    ledger, cas = _ledger(tmp_path)
    ev = _ev(ledger, cas)
    res = _claim(ledger, "A header field value was read.", ev, values=["0x2c"])
    assert res.status is ClaimStatus.UNVERIFIED


@pytest.mark.parametrize("loc", [
    {"kind": "file-offset-range", "start": 6720, "end": 6741},   # strings search match
    {"kind": "address", "space": "va", "start": 4198400},         # function entry point
    {"kind": "address-range", "space": "va", "start": 0x10000, "end": 0x20000},  # dynamic memory dump range
])
def test_other_location_kinds_do_not_back_values(tmp_path, loc):
    ledger, cas = _ledger(tmp_path)
    n = loc.get("start") + (5 if loc["kind"].endswith("range") else 0)
    ev = _ev(ledger, cas, raw=b"some output without that number\n", locations=[loc], operation="strings")
    res = _claim(ledger, f"The count is {n}.", ev, values=[n])
    assert res.status is ClaimStatus.UNVERIFIED


def test_decimal_value_equal_to_address_atom_is_not_supported(tmp_path):
    """An address atom declares an ADDRESS: it backs the hex form, not a decimal result value of the same number."""
    ledger, cas = _ledger(tmp_path)
    ev = _ev(ledger, cas)
    res = _claim(ledger, "The key length is 44.", ev, atoms=[{"type": "address", "evidence_id": ev, "space": "rva",
                                                                "value": "0x2c"}], values=[44])
    assert res.status is ClaimStatus.UNVERIFIED


def test_explicit_address_atom_still_supports_the_address_itself(tmp_path):
    ledger, cas = _ledger(tmp_path)
    ev = _ev(ledger, cas)
    atom = {"type": "address", "evidence_id": ev, "space": "rva", "value": "0x2c"}
    assert _claim(ledger, "The field is at RVA 0x2c.", ev, atoms=[atom]).status is ClaimStatus.SUPPORTED
    assert _claim(ledger, "A field was read.", ev, atoms=[atom], values=["0x2c"]).status is ClaimStatus.SUPPORTED


def test_value_present_in_raw_output_is_still_supported(tmp_path):
    ledger, cas = _ledger(tmp_path)
    ev = _ev(ledger, cas, raw=HEADER_RAW + b"  -- u16 --\n  0x400000: 0x5a4d=23117\n")
    assert _claim(ledger, "The u16 view shows 23117.", ev, values=[23117]).status is ClaimStatus.SUPPORTED
    assert _claim(ledger, "The u16 view shows 0x5a4d.", ev).status is ClaimStatus.SUPPORTED


def test_hex_literal_equal_to_a_reported_point_address_is_still_an_address_mention(tmp_path):
    """"main (0x140001070)" names an address the tool itself reported (a point location): not a range sweep."""
    ledger, cas = _ledger(tmp_path)
    locs = [{"kind": "address", "space": "va", "start": 0x140001070}, {"kind": "address", "space": "rva", "start": 0x1070}]
    ev = _ev(ledger, cas, raw=b"int main() { return 0; }\n", locations=locs, operation="decompile")
    assert _claim(ledger, "main (0x140001070) returns zero.", ev).status is ClaimStatus.SUPPORTED
    assert "HEX_LITERAL_UNSUPPORTED" in [i["code"] for i in _claim(ledger, "main (0x140001071) returns zero.", ev).issues]
