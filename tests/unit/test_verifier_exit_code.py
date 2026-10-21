"""Verifier version 17: the `exit_code` atom binds a claim to the observed exit code of ONE run_controlled execution.

Fakes only: no Sandbox is started, no target is run (the real exit code of a real run is checked in the heavy tests).
Ledger level (verifier rules, with the Env fixture of test_dynamic.py) and Hub level (fake sandbox, fake engine).
"""
import hashlib

import pytest

from redharness.core.result import Status
from redharness.evidence.model import ClaimStatus, build_evidence
from redharness.evidence.verifier import VERIFIER_VERSION

from .test_dynamic import SANDBOX, TARGET, Env, fake, request  # noqa: F401  (env fixture is re-used below)
from .test_dynamic import env as env  # noqa: F401
from .test_fix_verification import ALT_KEY, GOOD_KEY, WRONG_KEY, Builds

TEXT = "The program exits with code 3 when given `token_a`."


def atom(ev, code):
    return {"type": "exit_code", "evidence_id": ev, "code": code}


def codes(res):
    return {i["code"] for i in res.issues}


def claim(env, evs, atoms, text=TEXT, req="PROVEN", polarity="present", kind="behavior"):
    return env.ledger.add_claim(text, kind, polarity, evs, atoms, req, values=[{"value": "token_a", "derived": True}])


def run_ev(env, *, code, status=Status.OK, truncated=False, raw=b"done\n", stdin="token_a\n"):
    rec = build_evidence(env.cas, subject_sha256=TARGET, tool="run_controlled", operation="run_controlled", raw=raw,
                         status=status, confidence="observed", authority="controlled-replay", environment=SANDBOX,
                         exit_code=code, truncated=truncated, parameters={"argv": [], "stdin": stdin},
                         result={"exit_code": code}, coverage={"scope": "case:0", "relationship": "partial"})
    return env.ledger.record_evidence(rec)["evidence_id"]


def test_version_and_atom_check_is_recorded(env):
    ev = run_ev(env, code=3)
    res = claim(env, [ev], [atom(ev, 3)])
    assert VERIFIER_VERSION == "23" and res.claim["verification"]["verifier_version"] == "23"
    assert {"code": "EXIT_CODE", "ok": True} in res.claim["verification"]["checks"]


# ---------------------------------------------------------------- accept
def test_valid_exit_code_claim_is_proven(env):
    ev = run_ev(env, code=3)
    res = claim(env, [ev], [atom(ev, 3)])
    assert res.status is ClaimStatus.PROVEN, res.issues


def test_exit_code_zero_and_the_number_in_the_text_is_bound_to_the_atom(env):
    ev = run_ev(env, code=0)
    ok = claim(env, [ev], [atom(ev, 0)], text="The program exits with code 0 when given `token_a`.")
    assert ok.status is ClaimStatus.PROVEN, ok.issues


def test_negative_ntstatus_code_matches_its_unsigned_form_and_hex_text(env):
    ev = run_ev(env, code=-1073741819)   # run_controlled records NTSTATUS codes as signed 32-bit
    text = "The program exits with code 0xC0000005 when given `token_a`."
    for code in (-1073741819, 0xC0000005):
        res = claim(env, [ev], [atom(ev, code)], text=text)
        assert res.status is ClaimStatus.PROVEN, res.issues
    assert claim(env, [ev], [atom(ev, 5)], text=text).status is ClaimStatus.REJECTED


# ---------------------------------------------------------------- reject: wrong code
@pytest.mark.parametrize("claimed", [0, 1, 4, -3, 2 ** 32 + 3])
def test_wrong_exit_code_is_rejected(env, claimed):
    ev = run_ev(env, code=3)
    res = claim(env, [ev], [atom(ev, claimed)])
    assert res.status is ClaimStatus.REJECTED
    assert codes(res) & {"EXIT_CODE_MISMATCH", "EXIT_CODE_MALFORMED"}
    if claimed in (0, 1, 4, -3):
        assert "EXIT_CODE_MISMATCH" in codes(res)


def test_number_in_text_that_is_not_the_proven_code_stays_unsupported(env):
    ev = run_ev(env, code=3)
    res = claim(env, [ev], [atom(ev, 3)], text="The program exits with code 7 when given `token_a`.")
    assert res.status is ClaimStatus.UNVERIFIED and "VALUE_NOT_IN_EVIDENCE" in codes(res)


def test_inconsistent_run_record_is_rejected(env):
    rec = build_evidence(env.cas, subject_sha256=TARGET, tool="run_controlled", operation="run_controlled", raw=b"x\n",
                         status=Status.OK, confidence="observed", authority="controlled-replay", environment=SANDBOX,
                         exit_code=3, parameters={"argv": [], "stdin": "token_a\n"}, result={"exit_code": 0},
                         coverage={"scope": "case:0", "relationship": "partial"})
    ev = env.ledger.record_evidence(rec)["evidence_id"]
    res = claim(env, [ev], [atom(ev, 3)])
    assert res.status is ClaimStatus.REJECTED and "EXIT_CODE_MISMATCH" in codes(res)


# ---------------------------------------------------------------- reject: not a run_controlled observation
def test_static_evidence_cannot_prove_an_exit_code(env):
    st = env.static(b"int main() { return 3; }  // exit status 3\n")
    res = claim(env, [st], [atom(st, 3)], req="SUPPORTED")
    assert res.status is ClaimStatus.REJECTED and "EXIT_CODE_NEEDS_RUN_EVIDENCE" in codes(res)


def test_static_evidence_beside_the_run_does_not_help(env):
    ev, st = run_ev(env, code=3), env.static(b"int main() { return 3; }\n")
    res = claim(env, [ev, st], [atom(st, 3)])
    assert res.status is ClaimStatus.REJECTED and "EXIT_CODE_NEEDS_RUN_EVIDENCE" in codes(res)


def test_dynamic_observation_cannot_prove_an_exit_code(env):
    d = env.dyn(fake(exit_code=3))
    res = claim(env, [d], [atom(d, 3)], req="SUPPORTED")
    assert res.status is ClaimStatus.REJECTED and "EXIT_CODE_NEEDS_RUN_EVIDENCE" in codes(res)


def test_controlled_replay_of_another_operation_is_not_a_run(env):
    rec = build_evidence(env.cas, subject_sha256=TARGET, tool="strings", operation="strings", raw=b"x\n",
                         status=Status.OK, confidence="observed", authority="controlled-replay", environment=SANDBOX,
                         exit_code=3, coverage={"scope": "all", "relationship": "complete"})
    ev = env.ledger.record_evidence(rec)["evidence_id"]
    res = claim(env, [ev], [atom(ev, 3)])
    assert res.status is ClaimStatus.REJECTED and "EXIT_CODE_NEEDS_RUN_EVIDENCE" in codes(res)


# ---------------------------------------------------------------- no usable exit code: never accepted
def test_run_without_a_recorded_exit_code_is_unverified(env):
    ev = run_ev(env, code=None, status=Status.PARTIAL)
    res = claim(env, [ev], [atom(ev, 0)], text="The program exits with code 0 when given `token_a`.")
    assert res.status is ClaimStatus.UNVERIFIED and "EXIT_CODE_NOT_RECORDED" in codes(res)
    assert {"code": "EXIT_CODE", "ok": False} in res.claim["verification"]["checks"]


@pytest.mark.parametrize("status", [Status.TIMEOUT, Status.ERROR])
def test_timed_out_or_crashed_run_is_never_accepted(env, status):
    ev = run_ev(env, code=None, status=status)
    for code in (0, 3):
        res = claim(env, [ev], [atom(ev, code)])
        assert res.status in (ClaimStatus.REJECTED, ClaimStatus.UNVERIFIED)
        assert res.status is not ClaimStatus.PROVEN


def test_truncated_or_partial_run_with_the_right_code_is_unverified(env):
    for kw in (dict(truncated=True), dict(status=Status.PARTIAL)):
        ev = run_ev(env, code=3, **kw)
        res = claim(env, [ev], [atom(ev, 3)])
        assert res.status is ClaimStatus.UNVERIFIED and "EXIT_CODE_RUN_NOT_COMPLETE" in codes(res), kw


def test_wrong_code_on_an_incomplete_run_is_still_not_accepted(env):
    ev = run_ev(env, code=3, truncated=True)
    res = claim(env, [ev], [atom(ev, 0)])
    assert res.status is ClaimStatus.REJECTED and "EXIT_CODE_MISMATCH" in codes(res)


# ---------------------------------------------------------------- malformed atoms
@pytest.mark.parametrize("bad", [dict(code="3"), dict(code=True), dict(code=3.0), dict(code=None), dict(code=2 ** 32),
                                 dict(code=-2 ** 31 - 1), dict(code=3, extra=1)])
def test_malformed_atom_is_rejected(env, bad):
    ev = run_ev(env, code=3)
    res = claim(env, [ev], [{"type": "exit_code", "evidence_id": ev, **bad}])
    assert res.status is ClaimStatus.REJECTED and "EXIT_CODE_MALFORMED" in codes(res)


def test_atom_without_code_or_with_unlisted_evidence_is_rejected(env):
    ev, other = run_ev(env, code=3), run_ev(env, code=3, raw=b"another\n")
    assert "EXIT_CODE_MALFORMED" in codes(claim(env, [ev], [{"type": "exit_code", "evidence_id": ev}]))
    assert "ATOM_EVIDENCE_NOT_LISTED" in codes(claim(env, [ev], [atom(other, 3)]))


def test_absence_claim_cannot_carry_the_atom(env):
    ev = run_ev(env, code=3)
    res = claim(env, [ev], [atom(ev, 3)], polarity="absent", req="SUPPORTED")
    assert res.status is ClaimStatus.REJECTED and "EXIT_CODE_MALFORMED" in codes(res)


# ---------------------------------------------------------------- atom does not replace the rest of the rules
def test_exit_code_atom_alone_does_not_make_an_observation_proven(env):
    ev = run_ev(env, code=3)
    res = claim(env, [ev], [atom(ev, 3)], kind="observation", text="main returns 3 when given `token_a`.")
    assert res.status in (ClaimStatus.SUPPORTED, ClaimStatus.UNVERIFIED) and res.status is not ClaimStatus.PROVEN


def test_input_not_given_to_the_run_is_not_proven(env):
    ev = run_ev(env, code=3, stdin="OTHER\n")
    res = claim(env, [ev], [atom(ev, 3)])   # claims `token_a`, the run was fed `OTHER`
    assert res.status is ClaimStatus.UNVERIFIED and "VALUE_NOT_IN_EVIDENCE" in codes(res)


def test_claims_without_the_atom_keep_their_checks(env):
    st = env.static(b"strcmp(Str1, \"qwerty\")\n")
    res = env.ledger.add_claim("main calls strcmp.", "observation", "present", [st],
                               [{"type": "quote", "evidence_id": st, "text": "strcmp(Str1"}], "SUPPORTED")
    assert res.status is ClaimStatus.SUPPORTED
    assert "EXIT_CODE" not in [c["code"] for c in res.claim["verification"]["checks"]]


# ---------------------------------------------------------------- Hub level: real record path, fake sandbox
@pytest.fixture
def b(tmp_path):
    x = Builds(tmp_path)
    x.open(fixed=False)
    yield x
    x.hub.close()


def hub_claim(b, ev, code, text=None):
    return b.hub.claim_add(text or f"The product exits with code {code} when given `{ALT_KEY}`.", [ev],
                           [{"type": "exit_code", "evidence_id": ev, "code": code}], "behavior", "present", "PROVEN",
                           [{"value": ALT_KEY, "derived": True}])


def test_hub_run_exit_code_is_proven_and_wrong_code_rejected(b):
    ev, reply = b.run(ALT_KEY, "original")            # the fake original accepts ALT_KEY: exit code 0
    assert reply["cases"][0]["exit_code"] == 0
    ok = hub_claim(b, ev, 0)
    assert ok["status"] == "PROVEN", ok
    bad = hub_claim(b, ev, 1)
    assert bad["status"] == "REJECTED" and "EXIT_CODE_MISMATCH" in [i["code"] for i in bad["issues"]]
    ev2, _ = b.run(WRONG_KEY, "original")             # rejected key: exit code 1
    atoms = [{"type": "exit_code", "evidence_id": ev2, "code": 1}]
    ok2 = b.hub.claim_add(f"The product exits with code 1 when given `{WRONG_KEY}`.", [ev2], atoms, "behavior",
                          "present", "PROVEN", [{"value": WRONG_KEY, "derived": True}])
    assert ok2["status"] == "PROVEN", ok2
    assert hub_claim(b, ev2, 0)["status"] == "REJECTED"


def test_hub_static_evidence_is_rejected(b):
    d = b.hub.decompile("0x140001250")["evidence_id"]
    out = hub_claim(b, d, 0)
    assert out["status"] == "REJECTED" and "EXIT_CODE_NEEDS_RUN_EVIDENCE" in [i["code"] for i in out["issues"]]


def test_hub_run_with_no_exit_code_is_not_accepted(tmp_path):
    x = Builds(tmp_path, )
    x.sb.behavior = lambda i, c, stdin: {"stdout": b"", "stderr": b"", "exit_code": None, "launch_error": "boom"}
    x.open(fixed=False)
    try:
        ev, reply = x.run(GOOD_KEY, "original")
        assert reply["cases"][0]["exit_code"] is None
        out = hub_claim(x, ev, 0)
        assert out["status"] in ("REJECTED", "UNVERIFIED") and out["status"] != "PROVEN"
    finally:
        x.hub.close()


def test_hub_timed_out_run_is_not_accepted(tmp_path):
    x = Builds(tmp_path)
    x.sb.behavior = lambda i, c, stdin: {"stdout": b"", "stderr": b"", "exit_code": None, "timed_out": True}
    x.open(fixed=False)
    try:
        ev, reply = x.run(GOOD_KEY, "original")
        assert reply["cases"][0]["timed_out"] is True
        for code in (0, 1):
            assert hub_claim(x, ev, code)["status"] in ("REJECTED", "UNVERIFIED")
    finally:
        x.hub.close()
