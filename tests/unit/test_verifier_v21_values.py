"""Verifier version 21: no numeric collapse of byte strings / digests (docs/design/evidence-schema.md section 4.14).

Bug (found in review): a claim value of 64 zero hex digits (a SHA-256-like digest) was SUPPORTED against an
emulation record because the value checker read it as the decimal number 0 and the record contains a 0 somewhere
(`buf0+0x0`). Version 21 classifies every claimed token before comparing (values.value_class): a number is compared
numerically, a hex string (byte string / digest) as its exact canonical text against whole hex tokens of the cited
evidence, a decimal fraction as an exact token, anything else as a verbatim substring (unchanged).
"""
from __future__ import annotations

import hashlib

import pytest

from redharness.evidence import verifier as V
from redharness.evidence.model import hex_literals, long_hex_literals
from redharness.evidence.terms import extract_terms
from redharness.evidence.values import claim_number, extract_from_text, value_class

from . import _verifier_corpus as corpus

ZERO64 = "0" * 64
DIGEST = hashlib.sha256(b"payload").hexdigest()
DIGIT_DIGEST = "9" + DIGEST[1:]          # starts with a digit (was neither a value nor a term in version 20)
LETTER_DIGEST = "e" + DIGEST[1:]


# ---------------------------------------------------------------- the classification rule (pure)
@pytest.mark.parametrize("token,cls,key", [
    ("0x5A", "number", 0x5A), ("0x0000005A", "number", 0x5A), ("0x000000000000005a", "number", 0x5A),
    ("90", "number", 90), ("0", "number", 0), ("0x0", "number", 0),
    ("0x00000000deadbeef", "number", 0xDEADBEEF),                      # padded to the 64-bit width: still the number
    ("0xFFFFFFFFFFFFFFFF", "number", (1 << 64) - 1),
    ("18446744073709551615", "number", (1 << 64) - 1),                 # 20 decimal digits: a number
    ("0x" + ZERO64, "hexstr", ZERO64), (ZERO64, "hexstr", ZERO64),     # the false accept
    ("0x00000000000000000deadbeef", "hexstr", "00000000000000000deadbeef"),  # 25 digits: a byte string
    ("00", "hexstr", "00"), ("007", "hexstr", "007"),                  # bare decimal form with a leading zero
    ("123456789012345678901", "hexstr", "123456789012345678901"),      # 21 decimal digits
    (DIGEST.upper(), "hexstr", DIGEST), ("0X" + DIGEST, "hexstr", DIGEST),
    ("1.5", "fraction", "1.5"), ("3.14159", "fraction", "3.14159"),
    ("deadbeef", "string", "deadbeef"), ("RHPAYLOAD", "string", "RHPAYLOAD"), ("1.2.3", "string", "1.2.3"),
])
def test_value_class(token, cls, key):
    assert value_class(token) == (cls, key)
    assert claim_number(token) == (key if cls == "number" else None)


def test_text_extraction_finds_digests_and_long_literals():
    text = (f"digest {DIGIT_DIGEST} and {LETTER_DIGEST}, zeros {ZERO64}, literal 0x{ZERO64[:20]}, "
            "small 0x5A, number 90, ratio 1.5")
    vals = {v["value"]: v["source"] for v in extract_from_text(text)}
    assert vals == {DIGIT_DIGEST: "hex_string", LETTER_DIGEST: "hex_string", ZERO64: "decimal",
                    "0x" + ZERO64[:20]: "hex_string", "90": "decimal", "1.5": "decimal"}
    # a long 0x literal is a byte string, not a number: hex_literals lists only <= 16 digits
    assert hex_literals("0x5A 0x" + ZERO64) == ([0x5A], [])
    assert long_hex_literals("0x5A 0x" + ZERO64 + " 0X" + DIGEST.upper()) == [ZERO64, DIGEST]
    # a digest is a value now, not an identifier term
    assert extract_terms(f"the SHA-256 is {LETTER_DIGEST}") == [{"term": "SHA-256", "cls": "compound"}]


# ---------------------------------------------------------------- evidence side
def test_long_evidence_tokens_are_not_numbers():
    hexes, decs = V._raw_numbers(b"x = 0x" + ZERO64.encode() + b"; y = 0x0000000000000000005a; z = "
                                 + b"0" * 25 + b"; w = 0x5a;")
    assert hexes == {0x5A} and decs == set()
    assert V._raw_numbers(b"mov rax, 0FFFFFFFFFFFFFFFFh", asm=True)[0] == {(1 << 64) - 1}


def test_hex_tokens_are_whole_tokens_and_format_aware():
    toks = V._hex_tokens(f"sha256={DIGEST}\nkey 0x{ZERO64}\nid{DIGEST}x\n".encode())
    assert DIGEST in toks and ZERO64 in toks
    assert DIGEST[2:] not in toks                          # never a part of a longer token
    dump = b"segment 1 OUTPUT\n  0x10: 00000000\n  sha256=" + DIGEST.encode() + b"\n"
    assert "00000000" not in V._hex_tokens(dump, dump=True)  # dump bytes are not values (version 9 rule)
    assert DIGEST in V._hex_tokens(dump, dump=True)
    asm = b"0x401000: 00000000000000000000 add [rax], al\n"
    assert "00000000000000000000" not in V._hex_tokens(asm, asm=True)


# ---------------------------------------------------------------- verifier, static evidence
@pytest.fixture
def c(tmp_path):
    return corpus.Corpus(tmp_path)


def _claim(c, text, ev, values=None, atoms=None, kind="observation"):
    return c.ledger.add_claim(text, kind, "present", [ev], atoms or [], values=values)


def test_zero_digest_is_not_backed_by_a_zero(c):
    ev = c.ev(b"int f() {\n  return 0;\n  buf[0x0] = 0;\n}\n")
    q = [{"type": "quote", "evidence_id": ev, "text": "return 0;"}]
    assert _claim(c, f"The digest is {ZERO64}.", ev, atoms=q).status == "UNVERIFIED"
    assert _claim(c, "The digest is x.", ev, values=[ZERO64], atoms=q).status == "UNVERIFIED"
    r = _claim(c, f"The digest is 0x{ZERO64}.", ev, atoms=q)
    assert r.status == "REJECTED" and r.issues[0]["code"] == "HEX_LITERAL_UNSUPPORTED"
    # the number itself is still fine
    assert _claim(c, "f returns 0.", ev, atoms=q).status == "SUPPORTED"


def test_digest_needs_the_exact_whole_token(c):
    ev = c.ev(f"sha256={DIGEST}\nreturn 0x5a;\n".encode())
    q = [{"type": "quote", "evidence_id": ev, "text": "sha256="}]
    assert _claim(c, f"The SHA-256 is {DIGEST}.", ev, atoms=q).status == "SUPPORTED"
    assert _claim(c, f"The SHA-256 is {DIGEST.upper()}.", ev, atoms=q).status == "SUPPORTED"     # case-insensitive
    assert _claim(c, f"The SHA-256 is 0x{DIGEST}.", ev, atoms=q).status == "SUPPORTED"           # optional 0x
    assert _claim(c, "The SHA-256 is x.", ev, values=[DIGEST[2:]], atoms=q).status == "UNVERIFIED"  # a part of it
    assert _claim(c, f"The SHA-256 is {DIGIT_DIGEST}.", ev, atoms=q).status == "UNVERIFIED"      # was unchecked
    assert _claim(c, f"The SHA-256 is 0x00{DIGEST}.", ev, atoms=q).status == "REJECTED"          # leading zeros


def test_padded_numbers_still_work(c):
    ev = c.ev(b"if ( v3 == 0x5A ) v4 = 90;\nk = 0xdeadbeef;\n")
    q = [{"type": "quote", "evidence_id": ev, "text": "v3 == 0x5A"}]
    for text in ("The key is 0x5A.", "The key is 90.", "The key is 0x0000005A.", "The key is 0x000000000000005A.",
                 "k is 0x00000000deadbeef."):
        assert _claim(c, text, ev, atoms=q).status == "SUPPORTED", text
    assert _claim(c, "The key is 0x00000000000000000000005A.", ev, atoms=q).status == "REJECTED"   # 22 digits
    assert _claim(c, "The key is 0090.", ev, atoms=q).status == "UNVERIFIED"   # leading zeros: exact token only


def test_large_decimal_and_fraction_tokens_are_exact(c):
    ev = c.ev(b"x = 123456789012345678901234;\ny = 13.145;\nz = 2.50;\n")
    q = [{"type": "quote", "evidence_id": ev, "text": "x = 1"}]
    assert _claim(c, "x is 123456789012345678901234.", ev, atoms=q).status == "SUPPORTED"
    assert _claim(c, "x is 0123456789012345678901234.", ev, atoms=q).status == "UNVERIFIED"
    assert _claim(c, "y is 3.14 here.", ev, atoms=q).status == "UNVERIFIED"      # was a substring of 13.145
    assert _claim(c, "y is 13.145 here.", ev, atoms=q).status == "SUPPORTED"
    assert _claim(c, "z is 2.5 here.", ev, atoms=q).status == "UNVERIFIED"       # no numeric collapse of fractions
    assert _claim(c, "z is 2.50 here.", ev, atoms=q).status == "SUPPORTED"


def test_quote_constant_address_atoms_follow_the_rule(c):
    ev = c.ev(b"ret = 0;\nmagic = 0x5a;\n")
    long0 = "0x" + ZERO64
    r = _claim(c, "f sets ret.", ev, atoms=[{"type": "quote", "evidence_id": ev, "text": long0}])
    assert r.status == "REJECTED" and "QUOTE_NOT_IN_RAW" in [i["code"] for i in r.issues]
    r = _claim(c, "f sets ret.", ev, atoms=[{"type": "constant", "evidence_id": ev, "value": long0}])
    assert r.status == "REJECTED" and "CONSTANT_NOT_IN_RAW" in [i["code"] for i in r.issues]
    r = _claim(c, "f sets ret.", ev, atoms=[{"type": "address", "evidence_id": ev, "value": "0x" + "0" * 11 + "401000"}])
    assert r.status == "REJECTED" and "ADDRESS_UNRESOLVABLE" in [i["code"] for i in r.issues]
    assert _claim(c, "f sets magic.", ev, atoms=[{"type": "constant", "evidence_id": ev,
                                                   "value": "0x000000000000005a"}]).status == "SUPPORTED"


def test_derivation_value_is_not_collapsed(c):
    ev = c.ev(b"a = 0x10; b = 0x10;\n")
    atom = {"type": "derivation", "value": "0x" + "0" * 30,
            "expr": {"op": "xor", "args": [{"const": "0x10", "evidence_id": ev}, {"const": "0x10", "evidence_id": ev}]}}
    r = _claim(c, "a xor b gives a value.", ev, atoms=[atom])
    assert r.status == "REJECTED" and "DERIVATION_MISMATCH" in [i["code"] for i in r.issues]


def test_version_is_current():
    assert V.VERIFIER_VERSION == "23"
