"""Result-value binding rule: a value the claim reaches cannot be SUPPORTED if it is absent from the evidence (or from execution evidence)."""
import asyncio

import pytest

from redharness.evidence.model import ClaimStatus
from redharness.evidence.values import effective_values, extract_from_text, normalize_declared

from .mcp_helpers import call
from .test_evidence import Env, codes
from .test_mcp_server import env as mcp_env, open_args, session  # noqa: F401


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


# The real case from the experiment: the decompile output has NO password (it is computed by a transformation); the model computed the result itself.
DECOMP_RAW = (b"int check(char *s) {\n  static const unsigned char k[] = {0x6e, 0x6f, 0x70};\n"
              b"  for (i = 0; i < 14; i++) buf[i] = k[i] ^ 0x1f;\n  return strcmp(s, buf);\n}\n")


def test_experiment_case_value_not_in_evidence_is_unverified(env):
    e = env.ev(raw=DECOMP_RAW, locations=())
    r = env.claim("When decoded, the password comes out as `abcde-2026-xyz`.", [e], [
        {"type": "quote", "evidence_id": e, "text": "k[i] ^ 0x1f"}])
    assert r.status is ClaimStatus.UNVERIFIED and r.accepted
    assert "VALUE_NOT_IN_EVIDENCE" in codes(r)
    assert r.claim["status"] == "UNVERIFIED" and r.claim["evidence_ids"] == [e]


def test_declared_value_not_in_evidence_is_unverified_even_without_quotes_in_text(env):
    e = env.ev(raw=DECOMP_RAW, locations=())
    r = env.ledger.add_claim("The password was decoded.", "static_fact", "present", [e], values=["abcde-2026-xyz"])
    assert r.status is ClaimStatus.UNVERIFIED and "VALUE_NOT_IN_EVIDENCE" in codes(r)


def test_value_in_evidence_is_supported(env):
    e = env.ev(raw=b"cmp: strcmp(input, \"abcde-2026-xyz\")\n", locations=())
    assert env.claim("The password is compared with `abcde-2026-xyz`.", [e]).status is ClaimStatus.SUPPORTED
    r = env.ledger.add_claim("The password was found.", "static_fact", "present", [e], values=["abcde-2026-xyz"])
    assert r.status is ClaimStatus.SUPPORTED and r.claim["verification"]["values"][0]["supported"] is True


def test_string_value_is_exact_not_fuzzy(env):
    e = env.ev(raw=b"strcmp(input, \"abcde-2026-xyz\")\n", locations=())
    assert "VALUE_NOT_IN_EVIDENCE" in codes(env.claim("The password reportedly reads `abcde-2026-xyZ`.", [e]))
    assert "VALUE_NOT_IN_EVIDENCE" in codes(env.claim("The password reportedly reads `abcde-2026-xyz!`.", [e]))


def test_numeric_substring_trap_in_values(env):
    e = env.ev(raw=b"ioctl 0x104620\n", locations=())
    r = env.ledger.add_claim("The ioctl code.", "static_fact", "present", [e], values=["0x10462"])
    assert r.status is ClaimStatus.UNVERIFIED and "VALUE_NOT_IN_EVIDENCE" in codes(r)
    r = env.ledger.add_claim("The ioctl code.", "static_fact", "present", [e], values=["0x104620"])
    assert r.status is ClaimStatus.SUPPORTED
    r = env.ledger.add_claim("The ioctl code, decimal.", "static_fact", "present", [e], values=[0x104620])
    assert r.status is ClaimStatus.SUPPORTED  # numeric equality: 0x104620 == 1066528
    r = env.ledger.add_claim("The ioctl code, short decimal.", "static_fact", "present", [e], values=[0x10462])
    assert r.status is ClaimStatus.UNVERIFIED
    # reverse: short number in the raw output, long number in the claim
    e2 = env.ev(raw=b"entry 0x10462 here\n", locations=())
    assert env.ledger.add_claim("Entry.", "static_fact", "present", [e2], values=["0x104620"]).status is ClaimStatus.UNVERIFIED
    assert env.ledger.add_claim("Entry.", "static_fact", "present", [e2], values=["0x0010462"]).status is ClaimStatus.SUPPORTED


def test_decimal_in_text_is_numeric_not_substring(env):
    e = env.ev(raw=b"limit 12345 retries\n", locations=())
    assert "VALUE_NOT_IN_EVIDENCE" in codes(env.claim("Limit 1234 retries.", [e]))
    assert "VALUE_NOT_IN_EVIDENCE" in codes(env.claim("Limit 123456 retries.", [e]))
    assert env.claim("Limit 12345 retries.", [e]).status is ClaimStatus.SUPPORTED
    e3 = env.ev(raw=b"mov eax, 0x3039\n", locations=())  # 0x3039 == 12345
    assert env.claim("Constant 12345.", [e3]).status is ClaimStatus.SUPPORTED


def test_value_must_be_in_cited_evidence_not_just_any_evidence(env):
    has = env.ev(raw=b"secret=hunter2-xyz\n", locations=())
    other = env.ev(raw=b"nothing here\n", locations=())
    assert env.claim("The password `hunter2-xyz`.", [has]).status is ClaimStatus.SUPPORTED
    assert "VALUE_NOT_IN_EVIDENCE" in codes(env.claim("The password `hunter2-xyz` again.", [other]))


def test_derived_value_never_supported_by_static_evidence(env):
    e = env.ev(raw=b"strcmp(input, \"abc-123-xyz\")\n", locations=())
    r = env.ledger.add_claim("Result.", "static_fact", "present", [e],
                             values=[{"value": "abc-123-xyz", "derived": True}])
    assert r.status is ClaimStatus.UNVERIFIED and "VALUE_DERIVED_NEEDS_EXECUTION" in codes(r)
    r = env.ledger.add_claim("Result 2.", "static_fact", "present", [e],
                             values=[{"value": "zzz-computed", "derived": True}])
    assert r.status is ClaimStatus.UNVERIFIED and "VALUE_NOT_IN_EVIDENCE" in codes(r)


def test_derived_value_supported_by_isolated_execution_evidence(env):
    static = env.ev(raw=DECOMP_RAW, locations=())
    run = env.replay_ev(raw=b"ACCEPTED password=abcde-2026-xyz\n")
    claim = dict(values=[{"value": "abcde-2026-xyz", "derived": True}])
    r = env.ledger.add_claim("Password.", "runtime_behavior", "present", [static, run], **claim, behavior_class="ordinary")
    assert r.status is ClaimStatus.PROVEN  # behavior claim + execution evidence + a value that appears in the output
    weak = env.replay_ev(raw=b"ACCEPTED password=abcde-2026-xyz\n", environment={
        "id": "p", "platform": "windows", "architecture": "x64", "isolation": "process"})
    r = env.ledger.add_claim("Password 2.", "runtime_behavior", "present", [static, weak], **claim, behavior_class="ordinary")
    assert r.status is ClaimStatus.UNVERIFIED and "VALUE_DERIVED_NEEDS_EXECUTION" in codes(r)


def test_unverified_value_blocks_proven_too(env):
    run = env.replay_ev(raw=b"ACCEPTED\n")
    r = env.claim("Accepted, the password `ghost-value`.", [run], kind="runtime_behavior", req="PROVEN")
    assert r.status is ClaimStatus.UNVERIFIED and "VALUE_NOT_IN_EVIDENCE" in codes(r)


def test_location_range_does_not_back_numeric_value(env):
    e = env.ev(raw=b"nothing\n")  # location range file-offset 6720..6740
    r = env.ledger.add_claim("Offset.", "static_fact", "present", [e], values=[6725])
    assert r.status is ClaimStatus.UNVERIFIED  # version 8: an evidence location is not a value
    assert env.ledger.add_claim("Offset 2.", "static_fact", "present", [e], values=[9999]).status is ClaimStatus.UNVERIFIED


def test_hypothesis_request_skips_value_check(env):
    r = env.ledger.add_claim("Maybe `x-secret`.", "static_fact", "present", [], requested="UNVERIFIED")
    assert r.status is ClaimStatus.UNVERIFIED and r.claim is not None


def test_value_unverified_is_not_duplicated_in_journal(env):
    e = env.ev(raw=DECOMP_RAW, locations=())
    env.claim("The password `abcde-2026-xyz`.", [e])
    n = env.journal.seq
    env.claim("The  password    `abcde-2026-xyz`.", [e])
    assert env.journal.seq == n


@pytest.mark.parametrize("bad", [True, 1.5, None, [], {"value": "x", "extra": 1}, {"derived": True}, "  ", ""])
def test_bad_declared_values_rejected(bad):
    with pytest.raises(ValueError):
        normalize_declared([bad])


def test_declared_values_must_be_list():
    with pytest.raises(ValueError):
        normalize_declared("abc")
    assert normalize_declared(None) == []
    assert normalize_declared([7, "7"]) == [{"value": "7", "derived": False}]


# ---------- automatic extraction ----------

def vals(text):
    return [(v["value"], v["source"]) for v in extract_from_text(text)]


def test_auto_extract_quotes_and_backticks():
    assert vals("The password `abcde-2026-xyz` and \"abc def\" and 'single-quote'.") == [
        ("abcde-2026-xyz", "quoted"), ("abc def", "quoted"), ("single-quote", "quoted")]
    assert vals("Curly “value-1” and ‘value-2’.") == [
        ("value-1", "quoted"), ("value-2", "quoted")]
    assert vals("The program's key isn't here.") == []  # an apostrophe is not a quote


def test_auto_extract_decimals_and_units():
    assert vals("Key 4660 and 3.14 constant.") == [("4660", "decimal"), ("3.14", "decimal")]
    assert vals("16-bit checksum, 32 bytes, SHA-256, x86, sub_140001250, ev_00112233.") == []
    assert vals("Address 0x1250 and `0x1250`.") == []  # 0x literals are handled by the hex check
    assert vals("The string `abc-2026-x` contains a number.") == [("abc-2026-x", "quoted")]  # the 2026 inside is not a separate value


def test_auto_extract_merges_with_declared():
    eff = effective_values("The password `a-b-c`.", [{"value": "a-b-c", "derived": True}, {"value": "42", "derived": False}])
    assert [(v["value"], v["derived"], v["source"]) for v in eff] == [
        ("a-b-c", True, "declared"), ("42", False, "declared")]


def test_model_cannot_dodge_by_leaving_values_empty(env):
    e = env.ev(raw=DECOMP_RAW, locations=())
    for text in ("The password \"abcde-2026-xyz\".", "The password 'abcde-2026-xyz'.", "The password `abcde-2026-xyz`.",
                 "The secret value is 987654321."):
        r = env.claim(text, [e])
        assert r.status is ClaimStatus.UNVERIFIED, text


# ---------- MCP + report counters ----------

def test_report_counters_and_unverified_section(mcp_env):
    async def go():
        async with session(mcp_env) as s:
            await call(s, "target_open", **open_args(mcp_env))
            _, d = await call(s, "decompile", function="0x140001250")
            ev = d["evidence_id"]
            _, good = await call(s, "claim_add", text="validate_license masks with 0x5EC2E7A1.", evidence_ids=[ev], kind="observation")
            assert good["status"] == "SUPPORTED"
            # the case from the experiment: the password is not in the evidence
            _, bad = await call(s, "claim_add", text="When decoded, the password comes out as `abcde-2026-xyz`.", evidence_ids=[ev], kind="behavior")
            assert bad["status"] == "UNVERIFIED" and bad["accepted"]
            assert "VALUE_NOT_IN_EVIDENCE" in [i["code"] for i in bad["issues"]]
            assert bad["values_checked"][0]["supported"] is False
            # the model field can be used too
            _, bd = await call(s, "claim_add", text="The computed key.", evidence_ids=[ev],
                               values=[{"value": "deadbeefcafe-key", "derived": True}], kind="behavior")
            assert bd["status"] == "UNVERIFIED"
            # hypothesis without evidence
            _, hy = await call(s, "claim_add", text="Maybe something else.", requested="UNVERIFIED", kind="observation")
            assert hy["hypothesis"] is True
            _, rep = await call(s, "report_build")
            return rep
    rep = asyncio.run(go())
    c = rep["counts"]
    assert c["findings"] == 1 and c["hypotheses"] == 3
    # unsupported claims that reach the findings: always 0; hypotheses are counted separately
    assert c["unsupported_claims"] == c["claims_without_evidence"] == c["claims_value_not_in_evidence"] == 0
    assert c["hypotheses_without_evidence"] == 1 and c["hypotheses_value_not_in_evidence"] == 2
    assert c["hypotheses_behavior_needs_execution"] == 0 and c["hypotheses_other"] == 0
    assert c["hypotheses"] == sum(c[k] for k in ("hypotheses_without_evidence", "hypotheses_value_not_in_evidence",
                                                 "hypotheses_behavior_needs_execution", "hypotheses_other"))
    md = rep["markdown"]
    findings, hyp = md.split("## Unverified hypotheses")
    assert "abcde" not in findings and "abcde" in hyp and "VALUE_NOT_IN_EVIDENCE" in hyp
    assert "unsupported_claims; must always be 0" in md and "): 0 (without evidence: 0" in md
