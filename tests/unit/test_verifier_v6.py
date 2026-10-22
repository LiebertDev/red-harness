"""Verifier version 6: suffixed/IDA number forms, the `derivation` atom, and bit-for-bit identical verification of version 5 records."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from redharness.core.cas import Cas
from redharness.core.journal import Journal
from redharness.core.result import Status
from redharness.evidence import verifier as V
from redharness.evidence.derivation import DerivationError, evaluate, result_matches
from redharness.evidence.ledger import Ledger
from redharness.evidence.model import ClaimStatus, build_evidence, hex_literals

from . import _verifier_corpus as corpus

REPO = Path(__file__).resolve().parents[2]
GOLDEN = REPO / "tests" / "fixtures" / "verifier_v5_golden.json"
TARGET = hashlib.sha256(b"v6-target.exe").hexdigest()
SANDBOX = {"id": "wsb-1", "platform": "windows", "architecture": "x64", "isolation": "windows-sandbox"}


# Turkish `detail`/`hint` text found in tests/fixtures/verifier_v5_golden.json (written by verifier versions 5-9) ->
# the English text version 10 writes. The golden file is history and is not edited; it is mapped before comparing.
# Keys use \u escapes so this file stays free of Turkish text.
LEGACY_TEXT = {
    "yal\u0131t\u0131lm\u0131\u015f \u00e7al\u0131\u015ft\u0131rma kan\u0131t\u0131 yok": "no isolated run evidence",
}


def _legacy_to_english(node, seen):
    """Maps the Turkish detail/hint strings of the golden file to the version 10 English text (in place)."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k in ("detail", "hint") and isinstance(v, str) and v in LEGACY_TEXT:
                seen.add(v)
                node[k] = LEGACY_TEXT[v]
            else:
                _legacy_to_english(v, seen)
    elif isinstance(node, list):
        for x in node:
            _legacy_to_english(x, seen)


# ---------- version and golden tests ----------

def test_verifier_version_is_13():
    assert V.VERIFIER_VERSION == "24"


def test_v5_golden_corpus_verifies_identically(tmp_path):
    """Golden outputs produced by version 5 code (status, checks, issues, values) are bit-for-bit the same in version 6+.
    Only the Turkish detail/hint text of the golden file is mapped to English (LEGACY_TEXT); nothing else is changed."""
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert golden["verifier_version"] == "5" and len(golden["cases"]) >= 20
    expected, seen = copy.deepcopy(golden["cases"]), set()
    _legacy_to_english(expected, seen)
    assert seen == set(LEGACY_TEXT)  # every legacy key is really used; no Turkish text is left unmapped
    _v24_control_pair(expected)
    assert corpus.build(tmp_path) == expected


# Version 24 (control_pair): the corpus declares behavior_class="ordinary" for its behavior claims (_verifier_corpus);
# its three validation-worded ones ("is accepted", "correct password", "Access denied") without a pair still gain the
# check CONTROL_PAIR (ok=False) after ATOMS and the issue CONTROL_PAIR_MISSING at the end through the text backstop. All
# three were already UNVERIFIED in version 5, so no status changes; every other case is untouched.
V24_PAIR_CASES = ("beh_run_no_output_atom", "beh_static_only", "beh_run_wrong_input")


def _v24_control_pair(cases):
    for name in V24_PAIR_CASES:
        c = cases[name]
        assert c["status"] == "UNVERIFIED"
        at = next(i for i, ch in enumerate(c["checks"]) if ch["code"] == "ATOMS") + 1
        c["checks"].insert(at, {"code": "CONTROL_PAIR", "ok": False})
        c["issues"].append({"code": "CONTROL_PAIR_MISSING", "severity": "UNVERIFY", "detail":
                            "a validation claim (accepted/rejected, valid/invalid, correct input) needs a control_pair "
                            "atom: one run_controlled case the program accepts and one it rejects, same build and "
                            "inputs equal except the discriminator"})


def test_v5_labeled_record_reverifies_identically(tmp_path):
    """A version-5-labeled record in the journal is re-verified with the same body in the reloaded ledger."""
    c = corpus.Corpus(tmp_path)
    dec = c.ev(corpus.DECOMPILE)
    res = c.ledger.add_claim("The XOR key is a constant.", "observation", "present", [dec],
                             [{"type": "constant", "evidence_id": dec, "value": "0x1337"}])
    rec = json.loads(json.dumps(res.claim))
    rec["verification"]["verifier_version"] = "5"
    rec["revision"] += 1
    c.ledger._append("CLAIM_ACCEPTED", rec)
    reloaded = Ledger(c.journal, c.cas, corpus.TARGET)
    again = reloaded.reverify(res.claim_id).to_record()
    assert again["verifier_version"] == "24"
    assert {k: again[k] for k in ("checks", "issues", "values")} == \
        {k: res.claim["verification"][k] for k in ("checks", "issues", "values")}


# ---------- number forms (verifier.py _raw_numbers) ----------

@pytest.mark.parametrize("raw,value", [
    (b"f(a2, 0x6D8C5A83E9463C96LL);", 0x6D8C5A83E9463C96),
    (b"v3 = 0xCBF29CE484222325uLL;", 0xCBF29CE484222325),
    (b"strncpy(v5, &DstBuf[20], 0xCu);", 0xC),
    (b"x = 0x10ul + 0x20LLU;", 0x10),
    (b"x = 0x7fffi64;", 0x7FFF),
    (b"x = 0x7fffui64;", 0x7FFF),
    (b"x = 0x1337L;", 0x1337),
])
def test_decompiler_suffixed_hex_is_a_number(raw, value):
    hexes, _ = V._raw_numbers(raw)
    assert value in hexes
    assert V._quote_in_raw(hex(value), raw)


@pytest.mark.parametrize("raw,value", [(b"for (i = 0; i < 10000uLL; ++i)", 10000), (b"x = 12u;", 12),
                                       (b"x = 100000000000LL;", 100000000000)])
def test_decompiler_suffixed_decimal_is_a_number(raw, value):
    assert value in V._raw_numbers(raw)[1]


@pytest.mark.parametrize("raw,value", [
    (b"0x401752: 817c247065b7b9f9 cmp dword ptr [esp+70h], 0F9B9B765h", 0xF9B9B765),
    (b"0x40168e: 83f820 cmp eax, 20h", 0x20),
    (b"mov [ebp+var_10], 811C9DC5h", 0x811C9DC5),
    (b"lea edx, [eax-61h]", 0x61),
    (b"mov eax, 8BH", 0x8B),
])
def test_ida_h_hex_is_a_number_in_disassembly(raw, value):
    assert value in V._raw_numbers(raw, asm=True)[0]
    assert value not in V._raw_numbers(raw, asm=False)[0]  # only in disassembly evidence


@pytest.mark.parametrize("raw", [
    b"push ebp", b"high byte", b"each match", b"mov eax, [ebp+arg_8h]", b"call sub_4012D0h_x", b"hash", b"h",
    b"0x20h", b"var_1Ch", b"mov eax, 1Ch2", b"db '24h',0", b'aMsg db "load 24h"', b"nop ; CODE XREF: _main+2Ch",
])
def test_h_inside_identifiers_words_strings_comments_is_not_hex(raw):
    hexes, decs = V._raw_numbers(raw, asm=True)
    assert not ({0x20, 0x8, 0x24, 0x2C, 0x1C, 0x4012D0} & (hexes | decs)), (raw, hexes, decs)


def test_suffix_does_not_enable_substring_match():
    raw = b"return 0x104620LL;"
    hexes, _ = V._raw_numbers(raw)
    assert hexes == {0x104620} and not V._quote_in_raw("0x10462", raw)
    assert V._raw_numbers(b"x = 0x12LLL;")[0] == set() and V._raw_numbers(b"x = 0x12zu;")[0] == set()


def test_claim_text_hex_with_decompiler_suffix():
    good, bad = hex_literals("constant 0x6D8C5A83E9463C96LL and 0xCu; malformed 0x12LLL 0x12zz")
    assert good == [0x6D8C5A83E9463C96, 0xC] and bad == ["0x12LLL", "0x12zz"]


# ---------- ledger level ----------

class Env:
    def __init__(self, root: Path):
        self.cas = Cas(root / "cas")
        self.journal = Journal(root / "events.jsonl")
        self.ledger = Ledger(self.journal, self.cas, TARGET)

    def ev(self, raw: bytes, operation: str = "decompile", authority: str = "shipped-artifact", **kw) -> str:
        base = dict(subject_sha256=TARGET, tool=operation, operation=operation, raw=raw, status=Status.OK,
                    confidence="observed", authority=authority, locations=(),
                    coverage={"scope": "function", "relationship": "complete"})
        base.update(kw)
        return self.ledger.record_evidence(build_evidence(self.cas, **base))["evidence_id"]

    def replay(self, raw: bytes, stdin: str) -> str:
        return self.ev(raw, operation="run_controlled", authority="controlled-replay", environment=SANDBOX,
                       exit_code=0, parameters={"argv": [], "stdin": stdin})

    def claim(self, text, ev_ids, atoms=(), kind="observation", req="SUPPORTED", values=None, polarity="present"):
        return self.ledger.add_claim(text, kind, polarity, ev_ids, atoms, req, values=values,
                                     behavior_class=("ordinary" if kind in ("behavior", "runtime_behavior") else None))   # verifier 24


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def codes(res):
    return [i["code"] for i in res.issues]


DEC_LL = b"  v7 = sub_401000(a2, 0x6D8C5A83E9463C96LL);\n  v3 = 0xCBF29CE484222325uLL;\n  strncpy(v5, &B[20], 0xCu);\n"
ASM = b"0x40168e: 83f820 cmp eax, 20h\n0x401752: 817c247065b7b9f9 cmp dword ptr [esp+70h], 0F9B9B765h\n"


def test_bug_class_claims_now_supported(env):
    """Bug class: a suffixed/IDA constant now counts as evidence (REJECTED/UNVERIFIED in version 5)."""
    d, a = env.ev(DEC_LL), env.ev(ASM, operation="disassemble")
    r = env.claim("sub_401000 takes the constant 0x6D8C5A83E9463C96.", [d],
                  [{"type": "constant", "evidence_id": d, "value": "0x6D8C5A83E9463C96"}])
    assert r.status is ClaimStatus.SUPPORTED, r.issues
    r = env.claim("The offset basis is a constant.", [d], [{"type": "quote", "evidence_id": d, "text": "0xCBF29CE484222325"}])
    assert r.status is ClaimStatus.SUPPORTED, r.issues
    r = env.claim("strncpy copies 12 bytes.", [d])
    assert r.status is ClaimStatus.SUPPORTED, r.issues
    r = env.claim("The length is compared with 0x20, the sum with 0xF9B9B765.", [a],
                  [{"type": "constant", "evidence_id": a, "value": "0x20"}])
    assert r.status is ClaimStatus.SUPPORTED, r.issues


def test_ida_h_not_accepted_from_decompile_evidence(env):
    d = env.ev(b"  char Str[16]; // [esp+20h] [ebp-60h] BYREF\n")
    r = env.claim("The stack uses offset 0x60.", [d])
    assert r.status is ClaimStatus.REJECTED and "HEX_LITERAL_UNSUPPORTED" in codes(r)


def test_wrong_value_still_rejected(env):
    a = env.ev(ASM, operation="disassemble")
    r = env.claim("The length is compared with 0x21.", [a])
    assert r.status is ClaimStatus.REJECTED and "HEX_LITERAL_UNSUPPORTED" in codes(r)
    r = env.claim("The length must be 33.", [a])
    assert r.status is ClaimStatus.UNVERIFIED and "VALUE_NOT_IN_EVIDENCE" in codes(r)


# ---------- derivation atom ----------

KEY_DEC = (b"  if ( strlen(a1) != 14 || a1[5] != '-' || a1[10] != '-' ) return 0;\n"
           b"  v2 = \"VUTSRsqsw[ZY\";\n  for (i=0;i<5;++i) if ((a1[i] ^ 0x37) != v2[i]) return 0;\n"
           b"  for (i=0;i<4;++i) if ((a1[i+6] ^ 0x41) != v2[i+5]) return 0;\n"
           b"  for (i=0;i<3;++i) if ((a1[i+11] ^ 0x23) != v2[i+9]) return 0;\n  sep = 45;\n")


def _key_expr(e: str) -> dict:
    key = {"quote": "VUTSRsqsw[ZY", "evidence_id": e}
    dash = {"op": "le_bytes", "width": 1, "args": [{"const": 45, "evidence_id": e}]}
    part = lambda s, t, k: {"op": "xor", "args": [{"op": "slice", "start": s, "end": t, "args": [key]},  # noqa: E731
                                                   {"const": k, "evidence_id": e}]}
    return {"op": "concat", "args": [part(0, 5, "0x37"), dash, part(5, 9, "0x41"), dash, part(9, 12, "0x23")]}


def test_derivation_supports_observation_value(env):
    e = env.ev(KEY_DEC)
    atom = {"type": "derivation", "value": "abcde-2026-xyz", "expr": _key_expr(e)}
    r = env.claim("The check XORs the embedded key piece by piece; the decoded string is `abcde-2026-xyz`.",
                  [e], [atom], values=[{"value": "abcde-2026-xyz", "derived": True}])
    assert r.status is ClaimStatus.SUPPORTED, r.issues
    v = r.claim["verification"]
    assert {"code": "DERIVATIONS", "ok": True} in v["checks"] and v["verifier_version"] == "24"
    assert {"value": "abcde-2026-xyz", "derived": True, "source": "declared", "supported": True,
            "support": "derivation"} in v["values"]


def test_derivation_integer_and_byte_order(env):
    e = env.ev(b"if ( v16 == 17 * (v16 / 0x11) && v3 == (v16 ^ 0x1337) + 42 ) puts(\"ok\");\n"
               b"*(DWORD*)buf = 0x41424344;\n")
    ex = {"op": "add", "args": [{"op": "xor", "args": [{"const": 17, "evidence_id": e},
                                                       {"const": "0x1337", "evidence_id": e}]},
                                {"const": 42, "evidence_id": e}]}
    r = env.claim("For the first part 17 the rule gives the second part (17 ^ 0x1337) + 42 = 4944.", [e],
                  [{"type": "derivation", "value": 4944, "expr": ex}],
                  values=[17, {"value": 4944, "derived": True}])
    assert r.status is ClaimStatus.SUPPORTED, r.issues
    le = {"op": "le_bytes", "width": 4, "args": [{"const": "0x41424344", "evidence_id": e}]}
    r = env.claim("buf holds the bytes `DCBA` in memory.", [e], [{"type": "derivation", "value": "DCBA", "expr": le}])
    assert r.status is ClaimStatus.SUPPORTED, r.issues


def test_derivation_mismatch_and_missing_leaf_rejected(env):
    e = env.ev(KEY_DEC)
    r = env.claim("the decoded string is `abcde-2026-xyw`.", [e],
                  [{"type": "derivation", "value": "abcde-2026-xyw", "expr": _key_expr(e)}])
    assert r.status is ClaimStatus.REJECTED and "DERIVATION_MISMATCH" in codes(r)
    bad = json.loads(json.dumps(_key_expr(e)).replace('"0x37"', '"0x38"'))
    r = env.claim("the decoded string is `abcde-2026-xyz`.", [e],
                  [{"type": "derivation", "value": "abcde-2026-xyz", "expr": bad}])
    assert r.status is ClaimStatus.REJECTED and "DERIVATION_LEAF_NOT_IN_RAW" in codes(r)


def test_derivation_leaf_from_run_input_or_output_never_counts(env):
    """An input the model gave to run_controlled (or an execution output) cannot be a derivation leaf."""
    s = env.ev(KEY_DEC)
    run = env.replay(b"Enter password: Wrong\n--- stderr ---\n", "hunter22\n")
    ex = {"op": "concat", "args": [{"quote": "Enter", "evidence_id": run}, {"quote": "YYXV", "evidence_id": s}]}
    r = env.claim("the combined string is `EnterYYXV`.", [s, run], [{"type": "derivation", "value": "EnterYYXV", "expr": ex}])
    assert r.status is ClaimStatus.REJECTED and "DERIVATION_LEAF_NOT_STATIC" in codes(r)
    other = env.ev(b"unrelated VUTSRsqsw[ZY\n")
    ex = {"op": "slice", "start": 0, "end": 4, "args": [{"quote": "VUTSRsqsw[ZY", "evidence_id": other}]}
    r = env.claim("the string starts with `YYXV`.", [s], [{"type": "derivation", "value": "YYXV", "expr": ex}])
    assert r.status is ClaimStatus.REJECTED and "DERIVATION_LEAF_NOT_STATIC" in codes(r)  # evidence not cited


def test_derivation_never_supports_behavior_or_proven(env):
    """'The correct password is X' is behavior: derivation does not replace execution; even with an output quote there is no PROVEN if X was not executed."""
    e = env.ev(KEY_DEC)
    run = env.replay(b"Enter password: Correct!\n--- stderr ---\n", "something-else\n")
    atom = {"type": "derivation", "value": "abcde-2026-xyz", "expr": _key_expr(e)}
    r = env.claim("The correct password is `abcde-2026-xyz`.", [e], [atom], kind="behavior")
    assert r.status is ClaimStatus.UNVERIFIED
    assert {"VALUE_DERIVED_NEEDS_EXECUTION", "BEHAVIOR_NEEDS_EXECUTION"} <= set(codes(r))
    r = env.claim("The password `abcde-2026-xyz` is accepted.", [e, run],
                  [atom, {"type": "quote", "evidence_id": run, "text": "Correct!"}], kind="behavior", req="PROVEN",
                  values=[{"value": "abcde-2026-xyz", "derived": True}])
    assert r.status is ClaimStatus.UNVERIFIED and "VALUE_DERIVED_NEEDS_EXECUTION" in codes(r)
    r = env.claim("the decoded string `abcde-2026-xyz` is produced.", [e], [atom], req="PROVEN")
    assert r.status is ClaimStatus.SUPPORTED and "PROVEN_STATIC_CLAIM" in codes(r)
    r = env.claim("the decoded string `abcde-2026-xyz` is never used.", [e], [atom], polarity="absent")
    assert r.status is ClaimStatus.UNVERIFIED and "VALUE_DERIVED_NEEDS_EXECUTION" in codes(r)


def test_fed_input_never_supports_observation(env):
    """Version 6 tightening: a value the model gave to run_controlled does not support an observation claim (version 5 let it);
    the behavior + output quote path works as before, a wrong input never becomes PROVEN."""
    ok = env.replay(b"Enter password: Access granted!\n--- stderr ---\n", "secret\n")
    bad = env.replay(b"Enter password: Access denied!\n--- stderr ---\n", "qwerty\n")
    r = env.claim("sub_401000 produces the string `secret`.", [ok], values=[{"value": "secret", "derived": True}])
    assert r.status is ClaimStatus.UNVERIFIED and "VALUE_NOT_IN_EVIDENCE" in codes(r)
    r = env.claim("When the password `secret` is entered the program prints Access granted!", [ok],
                  [{"type": "quote", "evidence_id": ok, "text": "Access granted!"}], kind="behavior",
                  values=[{"value": "secret", "derived": True}])
    assert r.status is ClaimStatus.PROVEN, r.issues
    # if the input was given to another case (even if the ok case's output is quoted) the value was not an input to that run
    r = env.claim("When the password `hunter2` is entered the program prints Access granted!", [ok, bad],
                  [{"type": "quote", "evidence_id": ok, "text": "Access granted!"}], kind="behavior",
                  values=[{"value": "hunter2", "derived": True}])
    assert r.status is ClaimStatus.UNVERIFIED and "VALUE_NOT_IN_EVIDENCE" in codes(r)


def test_derivation_does_not_back_text_hex_literals(env):
    e = env.ev(b"v3 == (v16 ^ 0x1337) + 42 && v16 == 17")
    ex = {"op": "add", "args": [{"op": "xor", "args": [{"const": 17, "evidence_id": e},
                                                       {"const": "0x1337", "evidence_id": e}]},
                                {"const": 42, "evidence_id": e}]}
    r = env.claim("Part2 is 0x1350.", [e], [{"type": "derivation", "value": "0x1350", "expr": ex}])
    assert r.status is ClaimStatus.REJECTED and "HEX_LITERAL_UNSUPPORTED" in codes(r)


@pytest.mark.parametrize("atom,code", [
    ({"type": "derivation", "value": "x"}, "DERIVATION_MALFORMED"),
    ({"type": "derivation", "value": True, "expr": {}}, "DERIVATION_MALFORMED"),
    ({"type": "derivation", "value": "x", "expr": {}, "extra": 1}, "DERIVATION_MALFORMED"),
    ({"type": "derivation", "value": "x", "expr": {"op": "mul", "args": []}}, "DERIVATION_MALFORMED"),
    ({"type": "derivation", "value": "YYX", "expr": {"quote": "YYX", "evidence_id": "EV"}}, "DERIVATION_MALFORMED"),
    ({"type": "derivation", "value": 1, "expr": {"const": True, "evidence_id": "EV"}}, "DERIVATION_MALFORMED"),
])
def test_derivation_malformed_rejected(env, atom, code):
    e = env.ev(KEY_DEC)
    atom = json.loads(json.dumps(atom).replace('"EV"', json.dumps(e)))
    r = env.claim("the key string is decoded with XOR.", [e], [atom])
    assert r.status is ClaimStatus.REJECTED and code in codes(r), r.issues


# ---------- derivation.evaluate (pure) ----------

def _leaf(kind, node):
    return node["quote"].encode() if kind == "quote" else int(node["const"])


def L(x):
    return {"quote": x, "evidence_id": "e"} if isinstance(x, str) else {"const": x, "evidence_id": "e"}


@pytest.mark.parametrize("expr,expected", [
    ({"op": "xor", "args": [L(0x10), L(0x01)]}, 0x11),
    ({"op": "xor", "args": [L("abcd"), L(0x20)]}, b"ABCD"),
    ({"op": "xor", "args": [L("abcd"), L("    ")]}, b"ABCD"),
    ({"op": "sub", "args": [L(1), L(2)], "bits": 32}, 0xFFFFFFFF),
    ({"op": "add", "args": [L(0xFF), L(1)], "bits": 8}, 0),
    ({"op": "be_bytes", "width": 2, "args": [L(0x4142)]}, b"AB"),
    ({"op": "concat", "args": [L("abcd"), L("efgh")]}, b"abcdefgh"),
])
def test_evaluate_ops(expr, expected):
    assert evaluate(expr, _leaf) == expected


@pytest.mark.parametrize("expr", [
    {"op": "sub", "args": [L(1), L(2)]},                                   # negative, no bits
    {"op": "add", "args": [L(2 ** 64 - 1), L(1)]},                           # 64-bit overflow, no bits
    {"op": "xor", "args": [L("abcd"), L("abc ")], "bits": 8},                # xor has no bits field
    {"op": "xor", "args": [L("abcd"), L("abcde")]},                          # length mismatch
    {"op": "xor", "args": [L("abcd"), L(256)]},                              # byte key must be 0..255
    {"op": "slice", "start": 2, "end": 9, "args": [L("abcd")]},              # out of range
    {"op": "slice", "start": 2, "end": 2, "args": [L("abcd")]},              # empty slice
    {"op": "le_bytes", "width": 3, "args": [L(1)]},                          # width not in the allowed set
    {"op": "le_bytes", "width": 1, "args": [L(256)]},                        # does not fit
    {"op": "concat", "args": [L("abcd"), L(1)]},                             # type
    {"op": "concat", "args": [L("abcd")] * 9},                               # at most 8 arguments
    {"op": "concat", "args": [L("abcd"), {"op": "concat", "args": [L("abcd"), {"op": "concat", "args": [L("abcd"), {
        "op": "concat", "args": [L("abcd"), {"op": "concat", "args": [L("abcd"), {"op": "concat", "args": [
            L("abcd"), L("abcd")]}]}]}]}]}]},                                # depth > 6
    {"op": "concat", "args": [{"op": "concat", "args": [L("abcd")] * 5}, {"op": "concat", "args": [L("abcd")] * 5}]},
])
def test_evaluate_rejects(expr):
    with pytest.raises(DerivationError):
        evaluate(expr, _leaf)


def test_result_matches_is_exact():
    assert result_matches(b"abc", "abc") and not result_matches(b"abc", "ABC") and not result_matches(b"abc ", "abc")
    assert result_matches(4944, 4944) and result_matches(4944, "4944") and result_matches(0x1350, "0x1350")
    assert not result_matches(4944, "4944.0") and not result_matches(4944, True) and not result_matches(b"1", 1)
