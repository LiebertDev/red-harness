"""Evidence id, fail-closed verifier rules and journal integration."""

import hashlib

import pytest

from redharness.core.cas import Cas
from redharness.core.journal import Journal, state_hash, verify_file
from redharness.core.result import Status
from redharness.evidence.ledger import Ledger, replay_state
from redharness.evidence.model import (AddressError, ClaimStatus, build_evidence, compute_evidence_id,
                                       is_hypothesis, make_claim_id, normalize_address, wrap_untrusted)

TARGET = hashlib.sha256(b"target.sys").hexdigest()
OTHER = hashlib.sha256(b"other.sys").hexdigest()
SANDBOX = {"id": "wsb-1", "platform": "windows", "architecture": "x64", "isolation": "windows-sandbox"}

STRINGS_RAW = (b"0x1a40: IRP_MJ_DEVICE_CONTROL\n"
               b"dispatch at 0x104620 ioctl 0x15e000\n")
LOCS = [{"kind": "file-offset-range", "start": 6720, "end": 6741}]


class Env:
    def __init__(self, tmp_path):
        self.cas = Cas(tmp_path / "cas")
        self.jpath = tmp_path / "events.jsonl"
        self.open()

    def open(self):
        self.journal = Journal(self.jpath)
        self.ledger = Ledger(self.journal, self.cas, TARGET)
        return self.ledger

    def ev(self, raw=STRINGS_RAW, status=Status.OK, **kw):
        base = dict(subject_sha256=TARGET, tool="strings_search", operation="strings_search",
                    raw=raw, status=status, confidence="observed", authority="shipped-artifact",
                    locations=LOCS, coverage={"scope": "all", "relationship": "complete"})
        base.update(kw)
        return self.ledger.record_evidence(build_evidence(self.cas, **base))["evidence_id"]

    def replay_ev(self, raw=b"ACCEPTED\n", status=Status.OK, **kw):
        base = dict(tool="run_controlled", operation="run_controlled", authority="controlled-replay",
                    environment=SANDBOX, exit_code=0, locations=(), raw=raw, status=status)
        base.update(kw)
        return self.ev(**base)

    def claim(self, text, ev_ids, atoms=(), kind="static_fact", polarity="present", req="SUPPORTED"):
        return self.ledger.add_claim(text, kind, polarity, ev_ids, atoms, req)


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def codes(res):
    return {i["code"] for i in res.issues}


# ---------- id stability ----------

def test_evidence_id_ignores_elapsed_ms(env):
    a = build_evidence(env.cas, subject_sha256=TARGET, tool="t", operation="o", raw=b"abc",
                       status=Status.OK, confidence="observed", authority="shipped-artifact", elapsed_ms=5)
    b = build_evidence(env.cas, subject_sha256=TARGET, tool="t", operation="o", raw=b"abc",
                       status=Status.OK, confidence="observed", authority="shipped-artifact", elapsed_ms=99999)
    assert a["evidence_id"] == b["evidence_id"] and a["evidence_id"].startswith("ev_")
    assert a["capture"]["elapsed_ms"] != b["capture"]["elapsed_ms"]


def test_evidence_id_changes_with_content(env):
    kw = dict(subject_sha256=TARGET, tool="t", operation="o", status=Status.OK,
              confidence="observed", authority="shipped-artifact")
    a = build_evidence(env.cas, raw=b"abc", **kw)
    assert build_evidence(env.cas, raw=b"abd", **kw)["evidence_id"] != a["evidence_id"]
    assert build_evidence(env.cas, raw=b"abc", **{**kw, "status": Status.PARTIAL})["evidence_id"] != a["evidence_id"]


def test_identity_stable_after_resume_and_no_duplicate_events(env):
    e1 = env.ev(elapsed_ms=10)
    c1 = env.claim("The string IRP_MJ_DEVICE_CONTROL exists.", [e1],
                   [{"type": "quote", "evidence_id": e1, "text": "IRP_MJ_DEVICE_CONTROL"}])
    env.replay_ev()
    h1 = state_hash(env.ledger.state)
    n1 = env.journal.seq
    env.journal.close()

    led = env.open()  # "resume": the journal is reopened, the step runs again
    e2 = env.ev(elapsed_ms=777)
    c2 = env.claim("The string IRP_MJ_DEVICE_CONTROL exists.", [e2],
                   [{"type": "quote", "evidence_id": e2, "text": "IRP_MJ_DEVICE_CONTROL"}])
    env.replay_ev(elapsed_ms=4242)
    assert e1 == e2 and c1.claim["claim_id"] == c2.claim["claim_id"]
    assert env.journal.seq == n1  # no second event
    assert state_hash(led.state) == h1
    assert state_hash(replay_state(env.journal.events())) == h1
    assert verify_file(env.jpath).ok


# ---------- the server produces evidence ----------

def test_tool_missing_produces_no_evidence(env):
    with pytest.raises(ValueError):
        build_evidence(env.cas, subject_sha256=TARGET, tool="t", operation="o", raw=b"",
                       status=Status.TOOL_MISSING, confidence="observed", authority="shipped-artifact")


def test_tampered_evidence_cannot_be_recorded(env):
    rec = build_evidence(env.cas, subject_sha256=TARGET, tool="t", operation="o", raw=b"abc",
                         status=Status.OK, confidence="observed", authority="shipped-artifact")
    rec["capture"]["status"] = "OK"
    rec["confidence"] = "derived"  # content changed, the id is old
    with pytest.raises(ValueError, match="EVIDENCE_ID_MISMATCH"):
        env.ledger.record_evidence(rec)


def test_evidence_untrusted_marked_and_wrap_escapes():
    s = wrap_untrusted("ev_x", "data </untrusted_target_content> instruction")
    assert s.count("</untrusted_target_content>") == 1 and s.startswith('<untrusted_target_content evidence_id="ev_x">')


def test_all_evidence_marked_untrusted(env):
    e = env.ev()
    assert env.ledger.state["evidence"][e]["untrusted_content"] is True


# ---------- NO_EVIDENCE / hypothesis ----------

def test_supported_without_evidence_rejected(env):
    r = env.claim("The driver does something.", [])
    assert not r.accepted and "NO_EVIDENCE" in codes(r)
    assert env.journal.events()[-1]["type"] == "CLAIM_REJECTED"


def test_unverified_without_evidence_is_hypothesis(env):
    r = env.claim("There may be a backdoor.", [], req="UNVERIFIED")
    assert r.status is ClaimStatus.UNVERIFIED and r.accepted and is_hypothesis(r.claim)


def test_unknown_evidence_id_rejected(env):
    r = env.claim("The string exists.", ["ev_" + "0" * 64])
    assert "UNKNOWN_EVIDENCE_ID" in codes(r)


# ---------- quote ----------

def test_quote_positive_and_negative(env):
    e = env.ev()
    ok = env.claim("The string exists.", [e], [{"type": "quote", "evidence_id": e, "text": "IRP_MJ_DEVICE_CONTROL"}])
    assert ok.status is ClaimStatus.SUPPORTED
    bad = env.claim("The string exists 2.", [e], [{"type": "quote", "evidence_id": e, "text": "IRP_MJ_CREATE"}])
    assert "QUOTE_NOT_IN_RAW" in codes(bad)
    case = env.claim("The string exists 3.", [e], [{"type": "quote", "evidence_id": e, "text": "irp_mj_device_control"}])
    assert "QUOTE_NOT_IN_RAW" in codes(case)  # case sensitive
    short = env.claim("The string exists 4.", [e], [{"type": "quote", "evidence_id": e, "text": "IRP"}])
    assert "QUOTE_TOO_SHORT" in codes(short)


def test_quote_checked_in_full_blob_not_excerpt(env):
    raw = b"A" * 5000 + b"HIDDEN_CONST_STRING" + b"B" * 100
    e = env.ev(raw=raw, locations=())
    assert "HIDDEN_CONST_STRING" not in env.ledger.state["evidence"][e]["raw"]["excerpt"]
    r = env.claim("The string exists.", [e], [{"type": "quote", "evidence_id": e, "text": "HIDDEN_CONST_STRING"}])
    assert r.status is ClaimStatus.SUPPORTED


def test_atom_must_reference_listed_evidence(env):
    e1, e2 = env.ev(), env.ev(raw=b"other output IRP_MJ_CREATE\n")
    r = env.claim("The string exists.", [e1], [{"type": "quote", "evidence_id": e2, "text": "IRP_MJ_CREATE"}])
    assert "ATOM_EVIDENCE_NOT_LISTED" in codes(r)


# ---------- address ----------

def test_address_positive_negative_numeric(env):
    e = env.ev()
    ok = env.claim("The string is at the offset.", [e], [{"type": "address", "evidence_id": e, "space": "file_offset", "value": "0x1a40"}])
    assert ok.status is ClaimStatus.SUPPORTED  # 0x1a40 == 6720, decimal/hex makes no difference
    ok2 = env.claim("The string is at the second offset.", [e], [{"type": "address", "evidence_id": e, "space": "file_offset", "value": 6740}])
    assert ok2.status is ClaimStatus.SUPPORTED
    outside = env.claim("The string is at offset 3.", [e], [{"type": "address", "evidence_id": e, "space": "file_offset", "value": "0x1a55"}])
    assert "ADDRESS_NOT_IN_LOCATIONS" in codes(outside)  # 6741 is outside the range (half-open)
    wrong_space = env.claim("The string is at offset 4.", [e], [{"type": "address", "evidence_id": e, "space": "rva", "value": "0x1a40"}])
    assert "ADDRESS_NOT_IN_LOCATIONS" in codes(wrong_space)


def test_address_unresolvable_fails_closed(env):
    e = env.ev()
    for v in ("1a40", "0x", " 0x1a40", "-1", 1.5, None, True):
        r = env.claim(f"Address {v!r}.", [e], [{"type": "address", "evidence_id": e, "space": "file_offset", "value": v}])
        assert "ADDRESS_UNRESOLVABLE" in codes(r), v


def test_normalize_address_strict_only():
    assert normalize_address("0x10", "va") == 16 and normalize_address("16") == 16
    with pytest.raises(AddressError):
        normalize_address("0x10", strict=False)
    with pytest.raises(AddressError):
        normalize_address("0x10", "bogus")


# ---------- hex literal trap ----------

def test_substring_trap_0x10462_vs_0x104620(env):
    e = env.ev(locations=())  # the raw output has only 0x104620
    wrong = env.claim("The dispatch routine is at address 0x10462.", [e])
    assert "HEX_LITERAL_UNSUPPORTED" in codes(wrong)
    right = env.claim("The dispatch routine is at address 0x104620.", [e])
    assert right.status is ClaimStatus.SUPPORTED


def test_substring_trap_reverse_and_leading_zero(env):
    e = env.ev(raw=b"entry 0x10462 here\n", locations=())
    assert "HEX_LITERAL_UNSUPPORTED" in codes(env.claim("Address 0x104620.", [e]))
    assert env.claim("Address 0x0010462.", [e]).status is ClaimStatus.SUPPORTED  # numerically equal


def test_four_digit_address_checked(env):
    e = env.ev(raw=b"entry 0x1a40 here\n", locations=())
    assert env.claim("Entry 0x1a40.", [e]).status is ClaimStatus.SUPPORTED
    assert "HEX_LITERAL_UNSUPPORTED" in codes(env.claim("Entry 0x1a41.", [e]))
    assert "HEX_LITERAL_UNSUPPORTED" in codes(env.claim("Entry 0x1a4.", [e]))  # 3 digits are checked too


def test_hex_literal_quote_is_token_bounded(env):
    e = env.ev(raw=b"ioctl 0x104620\n", locations=())
    r = env.claim("The ioctl exists.", [e], [{"type": "quote", "evidence_id": e, "text": "0x10462"}])
    assert "QUOTE_NOT_IN_RAW" in codes(r)


def test_hex_literal_not_supported_by_location_alone(env):
    e = env.ev(raw=b"none\n")  # not in the raw output, but inside the location range 6720..6740
    assert "HEX_LITERAL_UNSUPPORTED" in codes(env.claim("Offset 0x1a40.", [e]))  # version 8: a range is not a value
    atom = [{"type": "address", "evidence_id": e, "space": "file_offset", "value": "0x1a40"}]
    assert env.claim("Offset 0x1a40.", [e], atoms=atom).status is ClaimStatus.SUPPORTED  # explicit address atom
    assert "HEX_LITERAL_UNSUPPORTED" in codes(env.claim("Offset 0x2000.", [e]))


def test_malformed_hex_literal_rejected(env):
    e = env.ev()
    assert "HEX_LITERAL_MALFORMED" in codes(env.claim("Address 0xZZ12.", [e]))


def test_constant_atom(env):
    e = env.ev()
    assert env.claim("The constant exists.", [e], [{"type": "constant", "evidence_id": e, "value": "0x15e000"}]).status is ClaimStatus.SUPPORTED
    assert "CONSTANT_NOT_IN_RAW" in codes(
        env.claim("The constant exists 2.", [e], [{"type": "constant", "evidence_id": e, "value": "0x15e00"}]))


# ---------- integrity / target SHA ----------

def test_wrong_subject_sha_rejected_and_derived_accepted(env):
    wrong = env.ev(subject_sha256=OTHER)
    assert "SUBJECT_SHA_MISMATCH" in codes(env.claim("The string exists.", [wrong]))
    derived = env.ev(subject_sha256=OTHER, derived_from_sha256=TARGET, raw=b"patched copy IRP_MJ_X\n")
    assert env.claim("The patched copy was examined.", [derived]).status is ClaimStatus.SUPPORTED
    right = env.ev()
    assert env.claim("The string exists.", [right]).status is ClaimStatus.SUPPORTED


def test_raw_blob_tamper_detected(env):
    e = env.ev()
    blob = env.ledger.state["evidence"][e]["raw"]["blob_sha256"]
    env.cas.path_for(blob).write_bytes(b"tampered output")
    assert "RAW_BLOB_HASH_MISMATCH" in codes(env.claim("The string exists.", [e]))


def test_raw_blob_missing_detected(env):
    e = env.ev()
    env.cas.path_for(env.ledger.state["evidence"][e]["raw"]["blob_sha256"]).unlink()
    assert "RAW_BLOB_HASH_MISMATCH" in codes(env.claim("The string exists.", [e]))


def test_in_memory_evidence_tamper_detected(env):
    e = env.ev()
    env.ledger.state["evidence"][e]["raw"]["excerpt"] = "other text"
    assert "EVIDENCE_ID_MISMATCH" in codes(env.claim("The string exists.", [e]))


def test_target_changed_invalidates_claims(env):
    e = env.ev()
    r = env.claim("The string exists.", [e])
    assert r.status is ClaimStatus.SUPPORTED
    assert env.ledger.invalidate_evidence(e, "TARGET_CHANGED") == [r.claim["claim_id"]]
    assert env.ledger.state["claims"][r.claim["claim_id"]]["status"] == "UNVERIFIED"
    assert "EVIDENCE_INVALIDATED" in codes(env.claim("Another claim.", [e]))
    assert "EVIDENCE_INVALIDATED" in {i["code"] for i in env.ledger.reverify(r.claim["claim_id"]).issues}


# ---------- timeout / truncated / error ----------

@pytest.mark.parametrize("status", [Status.TIMEOUT, Status.MEMORY_LIMIT, Status.ERROR])
def test_failed_evidence_supports_nothing(env, status):
    e = env.ev(status=status)
    assert "EVIDENCE_FAILED" in codes(env.claim("The string exists.", [e]))
    assert env.ev() and env.claim("The string exists.", [env.ev()]).status is ClaimStatus.SUPPORTED  # control: full evidence passes


def test_partial_evidence_supports_present_but_not_absence(env):
    e = env.ev(status=Status.PARTIAL, truncated=True)
    assert env.claim("The string exists.", [e]).status is ClaimStatus.SUPPORTED
    r = env.claim("The string is absent.", [e], polarity="absent")
    assert "ABSENCE_WITHOUT_COMPLETE_COVERAGE" in codes(r)


def test_absence_needs_complete_coverage_and_full_strength(env):
    full_complete = env.ev(raw=b"full scan, no match\n", locations=())
    ok = env.claim("The string is absent.", [full_complete], polarity="absent")
    assert ok.status is ClaimStatus.SUPPORTED
    unknown_cov = env.ev(raw=b"coverage unknown\n", locations=(), coverage={"scope": "x", "relationship": "unknown"})
    assert "ABSENCE_WITHOUT_COMPLETE_COVERAGE" in codes(env.claim("Another string is absent.", [unknown_cov], polarity="absent"))


def test_absence_never_proven(env):
    e = env.replay_ev(coverage={"scope": "run", "relationship": "complete"})
    r = env.claim("There is no network access.", [e], [{"type": "quote", "evidence_id": e, "text": "ACCEPTED"}],
                  kind="runtime_behavior", polarity="absent", req="PROVEN")
    assert r.status is ClaimStatus.SUPPORTED and "PROVEN_ABSENCE" in codes(r)


def test_inferred_only_rejected(env):
    e = env.ev(confidence="inferred", authority="analyst-inference")
    assert "INFERRED_ONLY" in codes(env.claim("The string exists.", [e]))
    e2 = env.ev(confidence="inferred", authority="shipped-artifact", raw=b"other\n")
    assert "INFERRED_ONLY" in codes(env.claim("The string exists 2.", [e2]))


# ---------- PROVEN ----------

def test_proven_positive_isolated_replay(env):
    e = env.replay_ev(raw=b"correct key: ACCEPTED\n")
    r = env.claim("The correct input is accepted.", [e], [{"type": "quote", "evidence_id": e, "text": "ACCEPTED"}],
                  kind="runtime_behavior", req="PROVEN")
    assert r.status is ClaimStatus.PROVEN and not r.issues
    assert r.claim["requested"] == "PROVEN" and r.claim["verification"]["verifier_version"]


def test_proven_refused_for_static_evidence(env):
    e = env.ev()
    r = env.claim("The string exists.", [e], kind="runtime_behavior", req="PROVEN")
    # a behavior claim is not supported by static evidence: UNVERIFIED, not SUPPORTED
    assert r.status is ClaimStatus.UNVERIFIED
    assert {"BEHAVIOR_NEEDS_EXECUTION", "PROVEN_NEEDS_CONTROLLED_REPLAY"} <= codes(r)


def test_proven_refused_for_static_fact_kind_even_with_replay(env):
    e = env.replay_ev()
    r = env.claim("The string exists.", [e], kind="static_fact", req="PROVEN")
    assert r.status is ClaimStatus.SUPPORTED and "PROVEN_STATIC_CLAIM" in codes(r)


@pytest.mark.parametrize("kw", [
    dict(status=Status.PARTIAL, truncated=True),
    dict(status=Status.LIMIT_REACHED),
    dict(status=Status.OK, truncated=True),
])
def test_proven_refused_for_truncated_replay(env, kw):
    e = env.replay_ev(**kw)
    r = env.claim("The correct input is accepted.", [e], kind="runtime_behavior", req="PROVEN")
    assert r.status is not ClaimStatus.PROVEN and "PROVEN_EVIDENCE_NOT_COMPLETE" in codes(r)


@pytest.mark.parametrize("status", [Status.TIMEOUT, Status.MEMORY_LIMIT, Status.ERROR])
def test_proven_refused_for_failed_replay(env, status):
    e = env.replay_ev(status=status)
    r = env.claim("The correct input is accepted.", [e], kind="runtime_behavior", req="PROVEN")
    assert r.status is ClaimStatus.REJECTED and "EVIDENCE_FAILED" in codes(r)


def test_proven_refused_without_exit_code(env):
    e = env.replay_ev(exit_code=None)
    r = env.claim("The correct input is accepted.", [e], kind="runtime_behavior", req="PROVEN")
    assert r.status is ClaimStatus.UNVERIFIED and "PROVEN_EVIDENCE_NOT_COMPLETE" in codes(r)


@pytest.mark.parametrize("iso", ["none", "process"])
def test_proven_refused_for_weak_isolation(env, iso):
    e = env.replay_ev(environment={**SANDBOX, "isolation": iso})
    r = env.claim("The correct input is accepted.", [e], kind="runtime_behavior", req="PROVEN")
    assert r.status is ClaimStatus.UNVERIFIED and "ENV_ISOLATION_BELOW_SCOPE" in codes(r)


def test_proven_needs_observed_confidence(env):
    e = env.replay_ev(confidence="derived")
    r = env.claim("The correct input is accepted.", [e], kind="runtime_behavior", req="PROVEN")
    assert r.status is ClaimStatus.UNVERIFIED and "PROVEN_NEEDS_CONTROLLED_REPLAY" in codes(r)


def test_controlled_replay_requires_environment(env):
    with pytest.raises(ValueError):
        build_evidence(env.cas, subject_sha256=TARGET, tool="t", operation="o", raw=b"x",
                       status=Status.OK, confidence="observed", authority="controlled-replay")


def test_proven_with_good_replay_plus_static_support(env):
    s, e = env.ev(), env.replay_ev()
    # PROVEN must be tied to the execution output: a quote atom (or a value/0x literal that appears in the output) is required
    r = env.claim("The dispatch 0x104620 path produces acceptance.", [s, e], kind="runtime_behavior", req="PROVEN")
    assert r.status is ClaimStatus.UNVERIFIED and "PROVEN_NEEDS_OBSERVED_OUTPUT" in codes(r)
    r = env.claim("The dispatch 0x104620 path produces acceptance.", [s, e], [
        {"type": "quote", "evidence_id": e, "text": "ACCEPTED"}], kind="runtime_behavior", req="PROVEN")
    assert r.status is ClaimStatus.PROVEN


# ---------- journal and unknowns ----------

def test_claim_revision_and_idempotence(env):
    e = env.ev()
    r1 = env.claim("The string exists.", [e])
    n = env.journal.seq
    r2 = env.claim("The   string exists.", [e])  # whitespace is normalized
    assert env.journal.seq == n and r2.claim["revision"] == 1
    e2 = env.replay_ev()
    r3 = env.claim("The string exists.", [e, e2])
    assert r3.claim["revision"] == 2 and r3.claim["claim_id"] == r1.claim["claim_id"]
    with pytest.raises(ValueError, match="REVISION_CONFLICT"):
        env.ledger.add_claim("The string exists.", "static_fact", "present", [e], expected_revision=1)


def test_claim_id_depends_on_target():
    assert make_claim_id("a", "static_fact", "present", TARGET) != make_claim_id("a", "static_fact", "present", OTHER)


def test_everything_in_hash_chained_journal(env):
    e = env.ev()
    env.claim("The string exists.", [e])
    env.claim("Wrong 0x10462.", [e])
    env.ledger.record_unknown("static", "Why does the function count differ between engines?", severity="high")
    types = [x["type"] for x in env.journal.events()]
    assert types == ["EVIDENCE_RECORDED", "CLAIM_ACCEPTED", "CLAIM_REJECTED", "UNKNOWN_RECORDED"]
    assert verify_file(env.jpath).ok
    env.journal.close()
    led = env.open()
    assert len(led.state["claims"]) == 1 and len(led.state["rejected"]) == 1 and len(led.state["unknowns"]) == 1


def test_unknown_ledger_dedup_and_validation(env):
    a = env.ledger.record_unknown("static", "Why   is there a difference?", severity="high")
    b = env.ledger.record_unknown("static", "Why is there a difference?", severity="low")
    assert a["unknown_id"] == b["unknown_id"] and a["unknown_id"].startswith("unk_")
    assert env.journal.seq == 1
    with pytest.raises(ValueError):
        env.ledger.record_unknown("static", "x?", severity="urgent")
    with pytest.raises(ValueError):
        env.ledger.record_unknown("static", "   ")


def test_compute_id_rejects_float(env):
    rec = build_evidence(env.cas, subject_sha256=TARGET, tool="t", operation="o", raw=b"x",
                         status=Status.OK, confidence="observed", authority="shipped-artifact")
    rec["parameters"] = {"x": 1.5}
    with pytest.raises(ValueError):
        compute_evidence_id(rec)
