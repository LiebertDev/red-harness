"""Verifier version 24: the `control_pair` atom and the acceptance-validation rule (docs/design/evidence-schema.md 4.17).

Synthetic ledgers only (no Sandbox is started, no target is run); the real license-sample pair is
tests/heavy/test_control_pair_real.py. One test per reason code, the non-validation path, and v23 compatibility.
"""
import hashlib

import pytest

from redharness.core.journal import Journal
from redharness.core.result import Status
from redharness.evidence import verifier
from redharness.evidence.control_pair import is_validation_text
from redharness.evidence.ledger import Ledger
from redharness.evidence.model import ClaimStatus, build_evidence
from redharness.evidence.verifier import VERIFIER_VERSION

from .test_dynamic import SANDBOX, TARGET, Env
from .test_dynamic import env as env  # noqa: F401  (fixture)
from .test_fix_verification import Builds

GOOD, BAD = "SYNTH-KEY-0001", "SYNTH-KEY-0002"   # synthetic inputs (the real sample keys stay in the answer key)
VALID, INVALID = "License valid (exit 0)", "License invalid (exit 1)"
MARK = b"\n--- stderr ---\n"
ACCEPTS = f"The licence key `{GOOD}` is accepted."


def run(env, stdin, out, *, code=None, status=Status.OK, truncated=False, argv=(), subject=TARGET, stderr=b"",
        params=None):
    """A run_controlled record shaped like sandbox/evidence.py builds it."""
    code = (0 if VALID in out else 1) if code is None else code
    stdout = out.encode() + b"\n"
    p = {"case_index": 0, "argv": list(argv), "stdin": stdin,
         "stdin_sha256": hashlib.sha256(stdin.encode()).hexdigest(), "stdin_bytes": len(stdin.encode()),
         **(params or {})}
    rec = build_evidence(env.cas, subject_sha256=subject, tool="run_controlled", operation="run_controlled",
                         raw=stdout + MARK + stderr, status=status, confidence="observed", authority="controlled-replay",
                         environment=SANDBOX, exit_code=code, truncated=truncated, parameters=p,
                         result={"exit_code": code, "stdout_kept_bytes": len(stdout), "stderr_kept_bytes": len(stderr)},
                         coverage={"scope": "case:0", "relationship": "partial"})
    return env.ledger.record_evidence(rec)["evidence_id"]


def quote(q):
    return {"type": "quote", "quote": q}


def exit_(n):
    return {"type": "exit_code", "code": n}


def pair(acc, rej, acc_out=None, rej_out=None, source="stdin", index=0, asserts="accepted"):
    side = (lambda e, o: {"evidence_ids" if isinstance(e, list) else "evidence_id": e, "outcome": o})
    return {"type": "control_pair", "asserts": asserts,
            "discriminator": {"source": source, **({} if index is None else {"index": index})},
            "accepted": side(acc, acc_out or quote("License valid")),
            "rejected": side(rej, rej_out or quote("License invalid"))}


def claim(env, evs, atoms, text=ACCEPTS, kind="behavior", cls="acceptance_validation", key=GOOD, req="PROVEN",
          ledger=None):
    vals = [{"value": key, "derived": True}] if key else None
    return (ledger or env.ledger).add_claim(text, kind, "present", evs, atoms, req, values=vals, behavior_class=cls)


def codes(res):
    return [i["code"] for i in res.issues]


def good_bad(env):
    return run(env, GOOD + "\n", VALID), run(env, BAD + "\n", INVALID)


# ---------------------------------------------------------------- valid pairs
def test_version_24_and_a_quote_pair_is_proven(env):
    a, b = good_bad(env)
    res = claim(env, [a, b], [pair(a, b)], cls="acceptance_validation")
    assert res.status is ClaimStatus.PROVEN, res.issues
    v = res.claim["verification"]
    assert VERIFIER_VERSION == "24" and v["verifier_version"] == "24"
    assert {"code": "CONTROL_PAIR", "ok": True} in v["checks"]
    assert res.claim["behavior_class"] == "acceptance_validation"


def test_an_exit_code_pair_is_proven(env):
    a, b = good_bad(env)
    res = claim(env, [a, b], [pair(a, b, exit_(0), exit_(1))])
    assert res.status is ClaimStatus.PROVEN, res.issues


def test_mixed_outcomes_and_ntstatus_pattern(env):
    a = run(env, GOOD + "\n", VALID)
    b = run(env, BAD + "\n", "", code=-1073741819)
    res = claim(env, [a, b], [pair(a, b, quote("License valid"), exit_(0xC0000005))])
    assert res.status is ClaimStatus.PROVEN, res.issues


def test_argv_discriminator(env):
    a = run(env, "", VALID, argv=("--key", GOOD))
    b = run(env, "", INVALID, argv=("--key", BAD))
    assert claim(env, [a, b], [pair(a, b, source="argv", index=1)]).status is ClaimStatus.PROVEN
    c = run(env, "", INVALID, argv=("-k", BAD))   # differs outside the discriminator
    res = claim(env, [a, c], [pair(a, c, source="argv", index=1)])
    assert res.status is ClaimStatus.REJECTED and "CONTROL_PAIR_INVALID" in codes(res)


def test_stdin_line_discriminator_and_whole_stdin(env):
    a = run(env, f"alice\n{GOOD}\n", VALID)
    b = run(env, f"alice\n{BAD}\n", INVALID)
    assert claim(env, [a, b], [pair(a, b, index=1)]).status is ClaimStatus.PROVEN
    # whole stdin as the discriminator: the claim names the whole (trimmed) stdin, so a one-line stdin here
    g, w = good_bad(env)
    assert claim(env, [g, w], [pair(g, w, index=None)]).status is ClaimStatus.PROVEN
    multi = claim(env, [a, b], [pair(a, b, index=None)])   # "alice\n<key>" cannot be named as one value
    assert multi.status is ClaimStatus.REJECTED and "CONTROL_PAIR_INVALID" in codes(multi)
    c = run(env, f"bob\n{BAD}\n", INVALID)        # the user line differs too
    res = claim(env, [a, c], [pair(a, c, index=1)])
    assert res.status is ClaimStatus.REJECTED and "CONTROL_PAIR_INVALID" in codes(res)


# ---------------------------------------------------------------- CONTROL_PAIR_MISSING
def test_single_run_validation_claim_is_unverified_missing(env):
    a = run(env, GOOD + "\n", VALID)
    res = claim(env, [a], [{"type": "quote", "evidence_id": a, "text": "License valid"}])
    assert res.status is ClaimStatus.UNVERIFIED and "CONTROL_PAIR_MISSING" in codes(res)
    assert {"code": "CONTROL_PAIR", "ok": False} in res.claim["verification"]["checks"]


def test_explicit_class_needs_a_pair_even_with_neutral_text(env):
    a = run(env, GOOD + "\n", VALID)
    text = f"Given `{GOOD}` the program prints \"License valid\"."
    atoms = [{"type": "quote", "evidence_id": a, "text": "License valid"}]
    assert claim(env, [a], atoms, text=text, cls="ordinary").status is ClaimStatus.PROVEN   # ordinary: no pair
    res = claim(env, [a], atoms, text=text + " ", cls="acceptance_validation")
    assert res.status is ClaimStatus.UNVERIFIED and "CONTROL_PAIR_MISSING" in codes(res)


def test_ordinary_class_with_validation_wording_still_needs_a_pair(env):
    a = run(env, GOOD + "\n", VALID)
    atoms = [{"type": "quote", "evidence_id": a, "text": "License valid"}]
    for text in (f"The correct key is `{GOOD}`.", f"`{GOOD}` is a valid licence key.",
                 f"The program authenticated `{GOOD}`.", f"Entering `{GOOD}` unlocks the program."):
        res = claim(env, [a], atoms, text=text, cls="ordinary")
        assert res.status is ClaimStatus.UNVERIFIED and "CONTROL_PAIR_MISSING" in codes(res), text


def test_a_behavior_claim_without_a_class_is_unverified(env):
    """Structural rule: wording the backstop does not know ("admits this token") cannot prove from one run."""
    a = run(env, GOOD + "\n", VALID)
    atoms = [{"type": "quote", "evidence_id": a, "text": "License valid"}]
    res = claim(env, [a], atoms, text=f"The program admits this token `{GOOD}`.", cls=None)
    assert res.status is ClaimStatus.UNVERIFIED and "BEHAVIOR_CLASS_MISSING" in codes(res)
    assert "CONTROL_PAIR_MISSING" not in codes(res)
    assert {"code": "BEHAVIOR_CLASS", "ok": False} in res.claim["verification"]["checks"]
    ok = claim(env, [a], atoms, text=f"The program admits this token `{GOOD}`.", cls="acceptance_validation")
    assert ok.status is ClaimStatus.UNVERIFIED and codes(ok) == ["CONTROL_PAIR_MISSING"]


def test_bypass_poc_always_needs_a_pair(env):
    a = run(env, GOOD + "\n", VALID)
    res = claim(env, [a], [{"type": "quote", "evidence_id": a, "text": "License valid"}],
                text=f"Given `{GOOD}` the program prints \"License valid\".", kind="bypass_poc", cls=None)
    assert res.status is ClaimStatus.UNVERIFIED and "CONTROL_PAIR_MISSING" in codes(res)


def test_static_evidence_alone_stays_unverified_with_missing(env):
    st = env.static(f"strcmp(input, \"{GOOD}\")\n".encode())
    res = claim(env, [st], [], key=None, text=f"The licence key `{GOOD}` is accepted.")
    assert res.status is ClaimStatus.UNVERIFIED
    assert {"BEHAVIOR_NEEDS_EXECUTION", "CONTROL_PAIR_MISSING"} <= set(codes(res))


@pytest.mark.parametrize("text,want", [
    ("The licence key `K` is accepted.", True), ("The password `x` is rejected.", True),
    ("The correct password is `x`.", True), ("`K` is an invalid key.", True), ("The login check passes the validation.", True),
    ("Doğru parola `x`.", True), ("Anahtar kabul edilir.", True),
    ("The program prints its version string.", False), ("The program exits with code 3 when given `t`.", False),
    ("Given `K` the program prints \"License valid\".", False), ("The program writes out.txt.", False),
    ("The program correctly prints its version.", False), ("main validates the header length.", False),
    ("Program doğrudan çıkar.", False), ("The parser handles incorrectly sized input.", False),
])
def test_validation_text_detection(text, want):
    assert is_validation_text(text) is want


# ---------------------------------------------------------------- non-validation path is unchanged
def test_ordinary_behavior_claim_has_no_pair_check(env):
    a = run(env, "token_a\n", "done", code=3)
    res = claim(env, [a], [{"type": "exit_code", "evidence_id": a, "code": 3}],
                text="The program exits with code 3 when given `token_a`.", key="token_a", cls="ordinary")
    assert res.status is ClaimStatus.PROVEN, res.issues
    assert not any(c["code"] == "CONTROL_PAIR" for c in res.claim["verification"]["checks"])


def test_observation_claims_are_untouched(env):
    st = env.static(b"0x1000: CreateFileW, WriteFile\n")
    res = claim(env, [st], [{"type": "quote", "evidence_id": st, "text": "CreateFileW"}], kind="observation",
                text="The string table contains CreateFileW.", key=None, req="SUPPORTED", cls=None)
    assert res.status is ClaimStatus.SUPPORTED, res.issues
    assert not any(c["code"] == "CONTROL_PAIR" for c in res.claim["verification"]["checks"])


# ---------------------------------------------------------------- CONTROL_PAIR_INVALID (REJECTED)
@pytest.mark.parametrize("mutate", [
    lambda p: {**p, "extra": 1},
    lambda p: {k: v for k, v in p.items() if k != "rejected"},
    lambda p: {**p, "discriminator": {"source": "env"}},
    lambda p: {**p, "asserts": "maybe"},
    lambda p: {k: v for k, v in p.items() if k != "asserts"},
    lambda p: {**p, "discriminator": {"source": "argv"}},
    lambda p: {**p, "discriminator": {"source": "stdin", "index": -1}},
    lambda p: {**p, "accepted": {**p["accepted"], "outcome": {"type": "quote", "quote": "Lic"}}},
    lambda p: {**p, "accepted": {**p["accepted"], "outcome": {"type": "side_effect", "name": "x"}}},
    lambda p: {**p, "rejected": {**p["rejected"], "outcome": {"type": "exit_code", "code": True}}},
    lambda p: {**p, "rejected": {"evidence_id": p["rejected"]["evidence_id"], "evidence_ids": [],
                                 "outcome": p["rejected"]["outcome"]}},
])
def test_malformed_pair_is_rejected(env, mutate):
    a, b = good_bad(env)
    res = claim(env, [a, b], [mutate(pair(a, b))])
    assert res.status is ClaimStatus.REJECTED and "CONTROL_PAIR_INVALID" in codes(res), res.issues


def test_case_not_cited_is_rejected(env):
    a, b = good_bad(env)
    res = claim(env, [a], [pair(a, b)])
    assert res.status is ClaimStatus.REJECTED and "CONTROL_PAIR_INVALID" in codes(res)


def test_static_evidence_as_a_side_is_rejected(env):
    a = run(env, GOOD + "\n", VALID)
    st = env.static(b"License invalid\n")
    res = claim(env, [a, st], [pair(a, st)])
    assert res.status is ClaimStatus.REJECTED and "CONTROL_PAIR_INVALID" in codes(res)


def test_outcome_not_in_its_own_case_is_rejected(env):
    a, b = good_bad(env)
    res = claim(env, [a, b], [pair(a, b, quote("Access granted"))])
    assert res.status is ClaimStatus.REJECTED and "CONTROL_PAIR_INVALID" in codes(res)
    res = claim(env, [a, b], [pair(a, b, exit_(0), exit_(2))])
    assert res.status is ClaimStatus.REJECTED and "CONTROL_PAIR_INVALID" in codes(res)


def test_swapped_sides_are_rejected(env):
    a, b = good_bad(env)
    res = claim(env, [a, b], [pair(b, a)])   # the accepted side's case does not print "License valid"
    assert res.status is ClaimStatus.REJECTED and "CONTROL_PAIR_INVALID" in codes(res)


def test_swapped_sides_with_valid_quotes_are_rejected(env):
    """Each quote is in its own case, but the accepted side is bound to the rejection message (labels swapped)."""
    a, b = good_bad(env)
    res = claim(env, [a, b], [pair(b, a, quote("License invalid"), quote("License valid"))],
                text=f"The licence key `{BAD}` is accepted.", key=BAD)
    assert res.status is ClaimStatus.REJECTED and "CONTROL_PAIR_INVALID" in codes(res)
    assert "reads as a rejected verdict" in res.issues[0]["detail"]


# ---------------------------------------------------------------- direction binding (claim <-> asserted side)
def test_claim_about_the_other_sides_input_is_rejected(env):
    a, b = good_bad(env)   # GOOD ran on the accepted side
    res = claim(env, [a, b], [pair(a, b)], text=f"The licence key `{BAD}` is accepted.", key=BAD)
    assert res.status is ClaimStatus.REJECTED and "CONTROL_PAIR_INVALID" in codes(res)
    both = claim(env, [a, b], [pair(a, b)], text=f"The licence key `{GOOD}` is accepted, `{BAD}` too.", key=GOOD)
    assert both.status is ClaimStatus.REJECTED and "CONTROL_PAIR_INVALID" in codes(both)


def test_inputs_that_differ_only_in_surrounding_whitespace_are_rejected(env):
    a = run(env, GOOD + "\n", VALID)
    for stdin, index in ((" " + GOOD + "\n", None), (GOOD + " \n", None), ("\t" + GOOD + "\n", 0)):
        b = run(env, stdin, INVALID)
        res = claim(env, [a, b], [pair(a, b, index=index)])
        assert res.status is ClaimStatus.REJECTED and "CONTROL_PAIR_INVALID" in codes(res), (stdin, res.issues)
        assert "surrounding whitespace" in res.issues[0]["detail"]


def test_trailing_newline_on_stdin_still_binds_to_the_right_side(env):
    a = run(env, GOOD + "\r\n", VALID)    # recorded raw stdin carries the newline; the claim writes the bare key
    b = run(env, BAD + "\n", INVALID)
    for index in (None, 0):
        assert claim(env, [a, b], [pair(a, b, index=index)]).status is ClaimStatus.PROVEN, index
        res = claim(env, [a, b], [pair(a, b, index=index)], text=f"The licence key `{BAD}` is accepted.", key=BAD)
        assert res.status is ClaimStatus.REJECTED and "CONTROL_PAIR_INVALID" in codes(res), index


def test_claim_that_names_no_input_is_rejected(env):
    a, b = good_bad(env)
    res = claim(env, [a, b], [pair(a, b)], text="The licence key is accepted.", key=None)
    assert res.status is ClaimStatus.REJECTED and "CONTROL_PAIR_INVALID" in codes(res)
    assert "must name the input" in res.issues[0]["detail"]


def test_rejected_side_claims_bind_to_the_rejected_input(env):
    a, b = good_bad(env)
    for text in (f"The licence key `{BAD}` is rejected.", f"The licence key `{BAD}` is not accepted."):
        res = claim(env, [a, b], [pair(a, b, asserts="rejected")], text=text, key=BAD)
        assert res.status is ClaimStatus.PROVEN, (text, res.issues)


def test_verdict_words_opposite_to_the_asserted_side_are_rejected(env):
    a, b = good_bad(env)
    res = claim(env, [a, b], [pair(a, b)], text=f"The licence key `{GOOD}` is rejected.")
    assert res.status is ClaimStatus.REJECTED and "CONTROL_PAIR_INVALID" in codes(res)
    res = claim(env, [a, b], [pair(a, b, asserts="rejected")], text=f"The licence key `{BAD}` is accepted.", key=BAD)
    assert res.status is ClaimStatus.REJECTED and "CONTROL_PAIR_INVALID" in codes(res)


# ---------------------------------------------------------------- integrity
def test_tampered_or_invalidated_case_rejects_the_pair(env):
    a, b = good_bad(env)
    env.ledger.state["evidence"][b]["capture"]["exit_code"] = 0   # record edited after it was written
    res = claim(env, [a, b], [pair(a, b)])
    assert res.status is ClaimStatus.REJECTED and "EVIDENCE_ID_MISMATCH" in codes(res)
    c, d = run(env, GOOD + "\n", VALID, stderr=b"2"), run(env, BAD + "\n", INVALID, stderr=b"2")
    env.ledger.invalidate_evidence(d, "target hash changed")
    res = claim(env, [c, d], [pair(c, d)])
    assert res.status is ClaimStatus.REJECTED and "EVIDENCE_INVALIDATED" in codes(res)


def test_other_build_is_rejected(tmp_path):
    fixed = hashlib.sha256(b"fixed-build").hexdigest()
    env = Env(tmp_path)
    env.ledger = Ledger(Journal(tmp_path / "ev2.jsonl"), env.cas, TARGET, fixed_sha256=fixed)
    a = run(env, GOOD + "\n", VALID)
    b = run(env, BAD + "\n", INVALID, subject=fixed, params={"build": "fixed"})
    res = claim(env, [a, b], [pair(a, b)])
    assert res.status is ClaimStatus.REJECTED and "CONTROL_PAIR_INVALID" in codes(res)


def test_pair_on_an_observation_or_fix_claim_is_rejected(env):
    a, b = good_bad(env)
    res = claim(env, [a, b], [pair(a, b)], kind="observation", text="The program output contains a message.", key=None,
                req="SUPPORTED", cls=None)
    assert res.status is ClaimStatus.REJECTED and "CONTROL_PAIR_INVALID" in codes(res)


def test_behavior_class_values_and_kinds(env):
    a, b = good_bad(env)
    with pytest.raises(ValueError):
        claim(env, [a, b], [pair(a, b)], cls="something_else")
    with pytest.raises(ValueError):
        claim(env, [a, b], [], kind="observation", text="The output has a message.", key=None,
              cls="acceptance_validation")
    with pytest.raises(ValueError):
        claim(env, [a, b], [], kind="fix_verification", cls="acceptance_validation")
    with pytest.raises(ValueError):
        claim(env, [a, b], [], kind="observation", text="The output has a message.", key=None, cls="ordinary")


# ---------------------------------------------------------------- CONTROL_PAIR_INCOMPLETE
@pytest.mark.parametrize("kw", [{"truncated": True}, {"status": Status.PARTIAL}])
def test_incomplete_case_is_unverified(env, kw):
    a = run(env, GOOD + "\n", VALID)
    b = run(env, BAD + "\n", INVALID, **kw)
    res = claim(env, [a, b], [pair(a, b)])
    assert res.status is ClaimStatus.UNVERIFIED and "CONTROL_PAIR_INCOMPLETE" in codes(res), res.issues


def test_timed_out_case_never_proves(env):
    a = run(env, GOOD + "\n", VALID)
    b = run(env, BAD + "\n", INVALID, status=Status.TIMEOUT)
    res = claim(env, [a, b], [pair(a, b)])
    assert res.status is ClaimStatus.REJECTED and "EVIDENCE_FAILED" in codes(res)   # failed evidence, as for any claim


# ---------------------------------------------------------------- CONTROL_PAIR_SAME_OUTCOME
def test_same_outcome_is_unverified(env):
    a = run(env, GOOD + "\n", VALID)
    b = run(env, BAD + "\n", VALID)
    res = claim(env, [a, b], [pair(a, b, quote("License valid"), exit_(0))])
    assert res.status is ClaimStatus.UNVERIFIED and "CONTROL_PAIR_SAME_OUTCOME" in codes(res)


def test_quote_common_to_both_outputs_is_same_outcome(env):
    a, b = good_bad(env)
    res = claim(env, [a, b], [pair(a, b, quote("License"), quote("License invalid"))])
    assert res.status is ClaimStatus.UNVERIFIED and "CONTROL_PAIR_SAME_OUTCOME" in codes(res)


# ---------------------------------------------------------------- CONTROL_PAIR_UNSTABLE
def test_disagreeing_repeats_are_unstable(env):
    a1 = run(env, GOOD + "\n", VALID)
    a2 = run(env, GOOD + "\n", INVALID, stderr=b"retry")   # same input, different outcome
    b = run(env, BAD + "\n", INVALID)
    res = claim(env, [a1, a2, b], [pair([a1, a2], b)])
    assert res.status is ClaimStatus.UNVERIFIED and "CONTROL_PAIR_UNSTABLE" in codes(res)


def test_agreeing_repeats_are_proven(env):
    a1 = run(env, GOOD + "\n", VALID)
    a2 = run(env, GOOD + "\n", VALID, stderr=b"second run")
    b = run(env, BAD + "\n", INVALID)
    assert claim(env, [a1, a2, b], [pair([a1, a2], b)]).status is ClaimStatus.PROVEN


def test_cited_run_outside_the_pair_that_disagrees_is_unstable(env):
    a, b = good_bad(env)
    other = run(env, GOOD + "\n", INVALID, stderr=b"other")
    res = claim(env, [a, b, other], [pair(a, b)])
    assert res.status is ClaimStatus.UNVERIFIED and "CONTROL_PAIR_UNSTABLE" in codes(res)


def test_same_input_on_both_sides_with_different_outcomes_is_unstable(env):
    a = run(env, GOOD + "\n", VALID)
    b = run(env, GOOD + "\n", INVALID)
    res = claim(env, [a, b], [pair(a, b)])
    assert res.status is ClaimStatus.UNVERIFIED and "CONTROL_PAIR_UNSTABLE" in codes(res)


# ---------------------------------------------------------------- version 23 compatibility
def test_v23_status_stays_recorded_until_reverified(tmp_path, monkeypatch):
    env = Env(tmp_path)
    a = run(env, GOOD + "\n", VALID)
    atoms = [{"type": "quote", "evidence_id": a, "text": "License valid"}]
    monkeypatch.setattr(verifier, "VERIFIER_VERSION", "23")   # a version 23 verifier had no pair rule
    monkeypatch.setattr(verifier.control_pair_ev, "needs_pair", lambda *a, **k: False)
    monkeypatch.setattr(verifier.control_pair_ev, "class_missing", lambda *a, **k: False)
    old = claim(env, [a], atoms, cls=None)
    assert old.status is ClaimStatus.PROVEN and old.claim["verification"]["verifier_version"] == "23"
    monkeypatch.undo()
    reloaded = Ledger(env.journal, env.cas, TARGET)
    rec = reloaded.state["claims"][old.claim_id]
    assert rec["status"] == "PROVEN" and rec["verification"]["verifier_version"] == "23"   # not silently rewritten
    v = reloaded.reverify(old.claim_id)
    assert v.status is ClaimStatus.UNVERIFIED and {"CONTROL_PAIR_MISSING", "BEHAVIOR_CLASS_MISSING"} <= set(v.codes)
    assert v.to_record()["verifier_version"] == "24"


def test_reverify_keeps_a_valid_pair_proven(env):
    a, b = good_bad(env)
    res = claim(env, [a, b], [pair(a, b)], cls="acceptance_validation")
    v = env.ledger.reverify(res.claim_id)
    assert v.status is ClaimStatus.PROVEN and v.checks == res.claim["verification"]["checks"]


# ---------------------------------------------------------------- through the MCP Hub (fake sandbox)
def test_hub_claim_add_with_a_pair(tmp_path):
    b = Builds(tmp_path)
    b.open(fixed=False)
    try:
        from .test_fix_verification import GOOD_KEY, WRONG_KEY
        ok, _ = b.run(GOOD_KEY, "original")
        no, _ = b.run(WRONG_KEY, "original")
        text = f"The licence key `{GOOD_KEY}` is accepted."
        single = b.hub.claim_add(text, [ok], [{"type": "quote", "evidence_id": ok, "text": "License valid"}],
                                 "behavior", "present", "PROVEN", [{"value": GOOD_KEY, "derived": True}],
                                 behavior_class="acceptance_validation")
        assert single["status"] == "UNVERIFIED"
        hint = next(i for i in single["issues"] if i["code"] == "CONTROL_PAIR_MISSING")
        assert "control_pair" in hint["hint"]
        out = b.hub.claim_add(text, [ok, no], [pair(ok, no)], "behavior", "present", "PROVEN",
                              [{"value": GOOD_KEY, "derived": True}], behavior_class="acceptance_validation")
        assert out["status"] == "PROVEN", out
    finally:
        b.hub.close()
