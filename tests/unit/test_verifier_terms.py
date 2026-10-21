"""Verifier version 16: technical terms of the claim text must be in the cited evidence (edge cases, fakes).

The proof on real data is scripts/reverify_runs.py (docs/design/evidence-schema.md section 4.12); these tests only pin
the extraction/binding edge cases and the `interpretation` field.
"""
from __future__ import annotations

import time

import pytest

from redharness.evidence import verifier as V
from redharness.evidence.model import ClaimStatus
from redharness.evidence.terms import _squash_templates, extract_terms, normalize_hay, term_backed
from redharness.report.render import render_report

from . import _verifier_corpus as corpus


def terms(text: str) -> list[str]:
    return [t["term"] for t in extract_terms(text)]


def section_terms(text: str) -> list[str]:
    return [t["term"] for t in extract_terms(text) if t["cls"] == "section"]


def backed(term: str, cls: str, hay: str, addrs=()) -> bool:
    return term_backed({"term": term, "cls": cls}, normalize_hay(hay), addrs)


# ---------- extraction ----------

@pytest.mark.parametrize("text,expected", [
    ("sub_1400017A8 FNV-1a hashes the username with a PRNG-selected invertible op chain.",
     ["sub_1400017A8", "FNV-1a", "hashes", "PRNG", "invertible"]),
    ("main compares Str1 with Str2 using strcmp.", ["Str1", "Str2"]),          # plain lower-case words are prose
    ("hiddenKey calls VirtualAlloc in kernel32.dll.", ["hiddenKey", "VirtualAlloc", "kernel32.dll"]),
    ("It XORs each byte; then XORed bytes are compared.", ["XOR"]),             # inflection dropped, unique
    ("The 64-bit value, 12-byte blob and 14-char input; date 2000-01-01.", []),  # units and numbers are not terms
    ("It prints `FNV-1a` and \"SHA-256\" at 0x401000.", []),                     # quoted spans and 0x are values
    ("Reads a NUL-terminated ASCII string via the API at VA/RVA.", []),          # notation acronyms
    ("e.g. the input, i.e. the key.", []),
    ("The result is formatted as lowercase hex.", ["lowercase", "hex"]),
    ("applies rot(..., 6) to the tail", ["rot"]),                               # call shape
    ("XOR'lanmış parçalar", ["XOR"]),
    ("The XXXXX-XXXX-XXX form", ["XXXXX", "XXXX", "XXX"]),                    # word-only compound: per part
])
def test_extract_terms(text, expected):
    assert terms(text) == expected


# ---------- binding ----------

@pytest.mark.parametrize("term,cls,hay,ok", [
    ("FNV-1a", "compound", "unsigned int _fnv_1a_32(char *s)", True),       # `-`/`_` are one separator
    ("SHA-256", "compound", '{"sha256":"ab12"}', True),                       # separator-less variant
    ("_main", "identifier", "int __cdecl main(int argc)", True),             # C name decoration
    ("sub_401920", "identifier", "SUB_401920()", True),                      # case-insensitive
    ("sub_40192", "identifier", "sub_401920()", False),                      # token-bounded
    ("valid_key", "identifier", "Enter a valid key:", False),                # prose does not back an identifier
    ("XOR", "acronym", "v3 = a1[i] ^ 0x37;", True),                          # closed alias
    ("XOR", "acronym", "v3 = a1[i] + 0x37;", False),
    ("hex", "lexicon", 'sprintf(buf, "%02x", b);', True),                     # printf hex conversion
    ("hex", "lexicon", 'sprintf(buf, "%d", b);', False),
    ("decrypted", "lexicon", "decrypt_block(v1);", True),                    # stem + separator tail
    ("sha", "lexicon", "shadow copy", False),                                # stem is not a word prefix
    ("lowercase", "lexicon", "tolower(c)", False),
])
def test_term_binding(term, cls, hay, ok):
    assert backed(term, cls, hay) is ok


# ---------- version 18: template arguments, section names, XOR caret (three false negatives) ----------

@pytest.mark.parametrize("text,expected", [
    ("std::vector<int> is used.", ["std::vector<int>"]),                      # full name, argument list included
    ("std::map<int, int> lookup", ["std::map<int, int>"]),
    ("std::vector<std::pair<int, int>> pairs", ["std::vector<std::pair<int, int>>"]),
    ("count<10 is a comparison", []),                                          # prose, not a template
    ("The function is in .pdata.", [".pdata"]),
    (".text and .rdata are sections", [".text", ".rdata"]),
])
def test_extract_terms_v18(text, expected):
    assert terms(text) == expected


def test_section_extraction_ignores_sentence_dots_decimals_and_file_names():
    got = terms("This is the end of sentence. The value is .5 and the file is foo.dll.")
    assert not [t for t in got if t.startswith(".")]   # `foo.dll` stays an ordinary dotted identifier, not a section


# ---------- v18 review fixes: template prose, closed section list, caret prose, printing keywords, linear scan ----------

@pytest.mark.parametrize("text,expected", [
    ("Vector<T> is a placeholder.", []),                                      # bare Name<T> with one capital parameter
    ("<p>Vector<T></p> is markup.", []),                                      # markup, not a template
    ("Vector<T*> pointers", ["Vector<T*>"]),                                  # a pointer argument is a known type context
    ("std::vector<int> values", ["std::vector<int>"]),                        # `::`-qualified base
    ("QList<int> values", ["QList<int>"]),                                    # known type token without `::`
    ("List<char *> values", ["List<char *>"]),                                # known type + pointer
])
def test_template_requires_qualified_name_or_known_type(text, expected):
    assert terms(text) == expected


@pytest.mark.parametrize("text,expected", [
    (".NET is a framework and .exe files run.", []),                           # `.NET`, `.exe` are not PE sections
    (".This is prose, not a section.", []),                                   # `.This` is not a section
    ("The .dll is not a section either.", []),                                # `.dll` is not in the closed list
    ("(see .text)", [".text"]),                                               # a known name after whitespace still counts
    ("- .text", [".text"]),
    (".rsrc$01 and .CRT are sections", [".rsrc$01", ".CRT"]),                 # optional `$` suffix, case-insensitive
    (".textbss .00cfg .gfids .orpc .debug", [".textbss", ".00cfg", ".gfids", ".orpc", ".debug"]),
])
def test_section_names_are_a_closed_list(text, expected):
    assert section_terms(text) == expected


@pytest.mark.parametrize("hay,ok", [
    ("The ^ is a caret.", False),                                             # prose, not a binary operator
    ("The caret ^ is here.", False),
    ("v3 = v1 ^ 0x5A;", True),
    ("*p ^= k;", True),
    ("(a)^(b)", True),
    ("~x ^ y;", True),
    ("return result ^ key;", True),
    ("a ^ b", True),                                                          # existing code form stays genuine
])
def test_caret_requires_code_like_operands(hay, ok):
    assert backed("XOR", "acronym", hay) is ok


@pytest.mark.parametrize("term,hay,ok", [
    ("std::vector<int,std::allocator<int>>", "std::vector<int,class std::allocator<int> > v;", True),
    ("std::vector<int,std::allocator<int>>", "std::vector<int,class std::allocator<double> > v;", False),
    ("std::map<int,std::vector<int>>", "std::map< int, std::vector< int > > m;", True),
])
def test_template_binding_ignores_printing_keywords_and_deep_whitespace(term, hay, ok):
    assert backed(term, "template", hay) is ok


def test_squash_templates_is_nesting_aware_and_stable():
    assert (_squash_templates("std::map<int, std::vector<std::pair<int, int>>>")
            == "std::map<int,std::vector<std::pair<int,int>>>")
    assert (_squash_templates("std::vector<int,class std::allocator<int> >")
            == "std::vector<int,std::allocator<int>>")
    s = "std::vector<int> v;"
    assert _squash_templates(s) == s                                        # idempotent: a stable pass changes nothing


def test_caret_scan_of_a_large_single_line_is_linear():
    """20k carets on one 200 KB line: a per-caret prefix rescan is quadratic (the reviewed bug)."""
    hay = "^abcdefghi" * 20000                                              # 200 000 chars, 20 000 carets
    started = time.perf_counter()
    assert backed("XOR", "acronym", hay) is False
    assert time.perf_counter() - started < 1.0


@pytest.mark.parametrize("term,cls,hay,ok", [
    ("std::vector<int>", "template", "std::vector<int> v;", True),
    ("std::vector<int>", "template", "std::vector<float> v;", False),          # the argument is part of the term
    ("std::vector<int>", "template", "std::vector< int > v;", True),           # whitespace inside <> is not significant
    ("std::map<int,int>", "template", "std::map<int, int> m;", True),
    ("std::map<int,int>", "template", "std::unordered_map<int, int> m;", False),
    ("XOR", "acronym", "v1 ^ 0x5A", True),                                     # binary operator between operands
    ("XOR", "acronym", "x ^= y", True),
    ("XOR", "acronym", "a ^ b", True),
    ("XOR", "acronym", 'pattern = r"[^a-z]"', False),                          # character class / string
    ("XOR", "acronym", "[^a-z]", False),
    ("XOR", "acronym", 're.compile(r"^abc")', False),                          # regex anchor in a string
    ("XOR", "acronym", "xor eax, ecx", True),                                  # the word still backs it
    (".pdata", "section", "Section: .pdata", True),
    (".pdata", "section", ".text", False),
    (".pdata", "section", "foo.pdata", False),                                 # not a token on its own
])
def test_term_binding_v18(term, cls, hay, ok):
    assert backed(term, cls, hay) is ok


@pytest.mark.parametrize("text,raw,ok", [
    ("std::vector<int> is used.", b"std::vector<float> v;", False),
    ("std::vector<int> is used.", b"std::vector<int> v;", True),
    ("This performs XOR.", b'pattern = r"[^a-z]"', False),
    ("This performs XOR.", b"v1 ^ 0x5A", True),
    ("The function is in .pdata.", b"section .text starts here", False),
    ("The function is in .pdata.", b"exception directory .pdata", True),
])
def test_false_negative_claims_are_checked_end_to_end(tmp_path, text, raw, ok):
    """Each fix must reject the mismatching evidence and keep the matching counterpart SUPPORTED."""
    c = corpus.Corpus(tmp_path)
    d = c.ev(raw)
    r = c.ledger.add_claim(text, "observation", "present", [d])
    if ok:
        assert r.status is ClaimStatus.SUPPORTED, r.issues
    else:
        assert r.status is ClaimStatus.UNVERIFIED
        assert [i["code"] for i in r.issues] == ["TERM_NOT_IN_EVIDENCE"]


def test_ida_auto_name_backed_by_cited_address():
    assert backed("sub_140001BD0", "identifier", "0x140001bd0: 55 push rbp", {0x140001BD0})
    assert not backed("sub_140001BD0", "identifier", "0x140001bd0: 55 push rbp", {0x140001BD1})


def test_compute_output_and_inference_do_not_back_a_term():
    recs = {"s": {"authority": "shipped-artifact", "parameters": {}},
            "c": {"authority": "sandboxed-computation", "parameters": {}}}
    raws = {"s": b"v1 = sub_401000(a1);", "c": b"fnv1a = 0x811C9DC5 FNV-1a"}
    assert V.unbacked_terms("sub_401000 computes FNV-1a.", recs, raws, comp={"c"}) == ["FNV-1a"]
    assert V.unbacked_terms("sub_401000 computes FNV-1a.", recs, raws, comp=set()) == []


def test_run_input_backs_a_term():
    recs = {"r": {"authority": "controlled-replay", "parameters": {"stdin": "SAMPLE_PASSPHRASE_VALUE\n",
                                                                    "argv": ["--key", "AB_12"]}}}
    raws = {"r": b"CONGRATULATIONS\n"}
    assert V.unbacked_terms("Input SAMPLE_PASSPHRASE_VALUE with AB_12 prints CONGRATULATIONS.", recs, raws) == []


# ---------- verifier and ledger ----------

FNV = (b"__int64 __fastcall sub_1400017A8(char *a1, __int64 a2)\n{\n  v2 = 0xCBF29CE484222325uLL;\n"
       b"  for ( i = a1; *i; ++i ) v2 = 0x100000001B3LL * (*i ^ v2);\n  for ( j = 0; j < 10000; ++j ) v4 = sub_1400016C0(v4);\n"
       b"  return v4 == v2;\n}\n")


def test_over_claim_is_downgraded_and_names_the_terms(tmp_path):
    """The false-accept shape: quotes/values hold, but the algorithm name and property are not in the evidence."""
    c = corpus.Corpus(tmp_path)
    d = c.ev(FNV)
    r = c.ledger.add_claim("sub_1400017A8 FNV-1a hashes the username and runs a 10000-round invertible op chain.",
                           "observation", "present", [d], [{"type": "quote", "evidence_id": d, "text": "j < 10000"}])
    assert r.status is ClaimStatus.UNVERIFIED
    assert [i["detail"] for i in r.issues if i["code"] == "TERM_NOT_IN_EVIDENCE"] == ["FNV-1a", "hashes", "invertible"]
    assert {"code": "TERMS_IN_EVIDENCE", "ok": False} in r.claim["verification"]["checks"]
    assert r.claim["verification"]["verifier_version"] == "23"


def test_rephrased_claim_with_interpretation_is_supported_and_interpretation_is_not_verified(tmp_path):
    c = corpus.Corpus(tmp_path)
    d = c.ev(FNV)
    r = c.ledger.add_claim("sub_1400017A8 multiplies by 0x100000001B3 in a loop over a1, then runs sub_1400016C0 "
                           "10000 times.", "observation", "present", [d],
                           [{"type": "quote", "evidence_id": d, "text": "0x100000001B3LL * (*i ^ v2)"}],
                           interpretation="Looks like an FNV-1a hash and an invertible PRNG-driven op chain.")
    assert r.status is ClaimStatus.SUPPORTED, r.issues
    assert r.claim["interpretation"].startswith("Looks like an FNV-1a")
    assert not any(ch["code"] == "TERMS_IN_EVIDENCE" for ch in r.claim["verification"]["checks"])
    assert c.ledger.reverify(r.claim_id).status is ClaimStatus.SUPPORTED   # interpretation never reaches the verifier
    md = render_report(target_sha256=corpus.TARGET, job_id="job_x",
                       findings=[{**r.claim, "final_status": "SUPPORTED"}], hypotheses=[],
                       counts={"findings": 1, "hypotheses": 0, "rejected_at_add": 0, "failed_reverify": 0,
                               "unsupported_claims": 0, "claims_without_evidence": 0,
                               "claims_value_not_in_evidence": 0}, evidence=c.ledger.state["evidence"])
    assert "Interpretation (model's reading, NOT verified" in md and "FNV-1a hash" in md


def test_claim_without_interpretation_keeps_its_record_shape(tmp_path):
    c = corpus.Corpus(tmp_path)
    d = c.ev(FNV)
    r = c.ledger.add_claim("sub_1400017A8 loops 10000 times.", "observation", "present", [d])
    assert r.status is ClaimStatus.SUPPORTED and "interpretation" not in r.claim
    assert [ch["code"] for ch in r.claim["verification"]["checks"]] == [
        "EVIDENCE_INTEGRITY", "NOT_INFERRED_ONLY", "ATOMS", "HEX_LITERALS", "VALUES_IN_EVIDENCE"]


def test_absence_claim_is_not_term_checked(tmp_path):
    """An absence claim names what is NOT in the evidence; complete coverage is its gate."""
    c = corpus.Corpus(tmp_path)
    d = c.ev(FNV)
    r = c.ledger.add_claim("sub_1400017A8 does not call VirtualAllocEx.", "observation", "absent", [d])
    assert "TERM_NOT_IN_EVIDENCE" not in [i["code"] for i in r.issues]


def test_term_issue_lands_in_the_hypothesis_reason(tmp_path):
    c = corpus.Corpus(tmp_path)
    d = c.ev(FNV)
    r = c.ledger.add_claim("sub_1400017A8 is an FNV-1a hash.", "observation", "present", [d])
    md = render_report(target_sha256=corpus.TARGET, job_id="job_x", findings=[], hypotheses=[r.claim],
                       counts={"findings": 0, "hypotheses": 1, "rejected_at_add": 0, "failed_reverify": 0,
                               "unsupported_claims": 0, "claims_without_evidence": 0,
                               "claims_value_not_in_evidence": 0}, evidence=c.ledger.state["evidence"])
    assert "TERM_NOT_IN_EVIDENCE: term not in the cited evidence `FNV-1a`, `hash`" in md


def test_interpretation_must_be_a_bounded_string(tmp_path):
    c = corpus.Corpus(tmp_path)
    d = c.ev(FNV)
    with pytest.raises(ValueError):
        c.ledger.add_claim("sub_1400017A8 loops.", "observation", "present", [d], interpretation="x" * 2001)
    with pytest.raises(ValueError):
        c.ledger.add_claim("sub_1400017A8 loops.", "observation", "present", [d], interpretation=["x"])


# ---------- MCP reply ----------

def test_claim_add_reply_names_unsupported_terms_and_keeps_interpretation(tmp_path):
    from .test_mcp_round2 import VA, make_hub
    hub, _ = make_hub(tmp_path)
    try:
        r = hub.disassemble(f"0x{VA:x}", end=f"0x{VA + 0x20:x}")
        ev = r["evidence_id"]
        bad = hub.claim_add("The CRC32 loop at 0x140001260 decrypts the key.", [ev], kind="observation")
        assert bad["status"] == "UNVERIFIED" and bad["terms_unsupported"] == ["CRC32", "decrypts"], bad
        assert "interpretation" in bad["message"] and "TERM_NOT_IN_EVIDENCE" in [i["code"] for i in bad["issues"]]
        ok = hub.claim_add("The instruction at 0x140001260 is xor with 0x5EC2E7A1.", [ev],
                           [{"type": "quote", "evidence_id": ev, "text": "xor eax, 0x5EC2E7A1"}], kind="observation",
                           interpretation="probably a CRC32-style key decryption step")
        assert ok["status"] == "SUPPORTED" and "terms_unsupported" not in ok, ok
        rec = hub._s.ledger.state["claims"][ok["claim_id"]]
        assert rec["interpretation"] == "probably a CRC32-style key decryption step"
        assert "NOT verified" in hub.report_build()["markdown"]
    finally:
        hub.close()
