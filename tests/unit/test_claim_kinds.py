"""Claim kind (observation | behavior), the execution requirement of a behavior claim, retraction (supersedes), the
partial-support message and report counters. Decoy-value regression: a decoy value that appears in static evidence cannot be a finding."""
import pytest

from redharness.evidence.kinds import is_behavior, kind_class, resolve_kind
from redharness.evidence.ledger import replay_state
from redharness.evidence.model import ClaimStatus
from redharness.core.journal import verify_file

from .test_evidence import Env, codes, control_pair
from .test_run_controlled_mcp import GOOD_KEY, make_hub  # noqa: F401


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


# decoy-value: the _main decompile shows strcmp(Str1, "decoy-pw"); decoy-pw is a dead-code decoy, the correct password is another.
DECOY_RAW = (b"int __cdecl main()\n{\n  scanf(\"%s\", Str1);\n  sub_401490();\n"
              b"  if ( !strcmp(Str1, \"decoy-pw\") )\n    puts(\"Congratulations!\");\n  return 0;\n}\n")
DECOY_CLAIM = 'The correct password is "decoy-pw".'


# ---------- heuristic kind detection ----------

@pytest.mark.parametrize("text", [
    "The correct password is decoy-pw.", "valid key AAA-BBB-CCC", "This input is accepted by the program.",
    "The serial `1234-5678` is valid.", "The password is \"decoy-pw\".", "Doğru parola decoy-pw.",
    "Geçerli anahtar AAA-BBB.", "Bu girdi kabul edilir.", "Parola `x1` kabul edilir", "accepted key",
    "The binary accepts the password hunter2.", "Entering X unlocks the app.",
])
def test_behavior_text_is_detected_when_kind_is_omitted(text):
    kind, source, hit = resolve_kind(None, text)
    assert kind == "behavior" and source == "inferred" and hit, text


@pytest.mark.parametrize("text", [
    "main calls scanf and then strcmp.", "sub_401490 fills the buffer at 0x41F050.",
    "The string \"Congratulations!\" is referenced from 0x401500.", "Function validate_license masks with 0x5EC2E7A1.",
    "fonksiyon main strcmp çağırır.", "The table off_41F000 contains six dwords.",
])
def test_observation_text_is_detected_when_kind_is_omitted(text):
    assert resolve_kind(None, text)[:2] == ("observation", "inferred"), text


def test_unclear_text_without_kind_is_behavior_fail_closed():
    assert resolve_kind(None, "Quux frobnicates the zorp.")[:2] == ("behavior", "inferred")


def test_declared_kinds_and_aliases():
    assert resolve_kind("observation", "main calls strcmp.")[:2] == ("observation", "declared")
    assert resolve_kind("behavior", "main calls strcmp.")[:2] == ("behavior", "declared")
    assert resolve_kind("static_fact", "main calls strcmp.")[0] == "observation"
    assert resolve_kind("runtime_behavior", "main calls strcmp.")[0] == "behavior"
    assert resolve_kind("bypass_poc", "x")[0] == "bypass_poc" and is_behavior("bypass_poc")
    assert kind_class("static_fact") == "observation" and kind_class("runtime_behavior") == "behavior"
    with pytest.raises(ValueError):
        resolve_kind("nonsense", "x")


def test_declared_observation_is_overridden_when_text_clearly_asserts_behavior():
    kind, source, hit = resolve_kind("observation", DECOY_CLAIM)
    assert (kind, source) == ("behavior", "overridden") and hit
    # weak phrases (accepts/prints...) do not change an explicit observation
    assert resolve_kind("observation", "validate accepts two arguments.")[:2] == ("observation", "declared")


# ---------- decoy-value regression (verbatim) ----------

@pytest.mark.parametrize("kind", [None, "static_fact", "observation"])
def test_decoy_decoy_value_in_static_evidence_is_unverified_not_supported(env, kind):
    e = env.ev(raw=DECOY_RAW, locations=())
    r = env.ledger.add_claim(DECOY_CLAIM, kind, "present", [e], [{"type": "quote", "evidence_id": e, "text": "decoy-pw"}])
    assert r.status is ClaimStatus.UNVERIFIED and r.accepted  # used to be SUPPORTED
    assert "BEHAVIOR_NEEDS_EXECUTION" in codes(r) and r.kind == "behavior"
    assert r.claim["verification"]["values"][0]["supported"] is True  # the value really is in the evidence: not enough
    assert r.kind_source == ("inferred" if kind is None else "overridden")
    assert ("KIND_OVERRIDDEN_TO_BEHAVIOR" in codes(r)) == (kind is not None)


def test_decoy_not_in_findings_only_in_hypotheses_via_mcp_report(tmp_path):
    h, _, _ = make_hub(tmp_path)
    d = h.decompile("0x140001250")["evidence_id"]
    # behavior claim built on a value (19) that appears in the decompile output: the old gate would have given SUPPORTED
    r = h.claim_add("The correct key has length 19.", [d], [{"type": "quote", "evidence_id": d, "text": "!= 19"}], kind="behavior", behavior_class="ordinary")
    assert r["status"] == "UNVERIFIED" and r["kind"] == "behavior" and r["hypothesis"] is False
    assert "BEHAVIOR_NEEDS_EXECUTION" in [i["code"] for i in r["issues"]]
    assert "run_controlled" in r["message"] and r["issues"][0]["hint"]
    rep = h.report_build()
    findings, hyp = rep["markdown"].split("## Unverified hypotheses")
    assert "correct key has length" not in findings and "correct key has length" in hyp
    assert "BEHAVIOR_NEEDS_EXECUTION" in hyp
    c = rep["counts"]
    assert c["findings"] == 0 and c["hypotheses"] == 1 and c["hypotheses_behavior_needs_execution"] == 1
    assert c["unsupported_claims"] == 0
    h.close()


def test_observation_about_the_same_code_can_be_supported(env):
    e = env.ev(raw=DECOY_RAW, locations=())
    r = env.ledger.add_claim('main compares the input Str1 with the string "decoy-pw" using strcmp.', "observation",
                             "present", [e], [{"type": "quote", "evidence_id": e, "text": "strcmp(Str1"}])
    assert r.status is ClaimStatus.SUPPORTED and r.kind == "observation" and not r.issues
    r = env.ledger.add_claim("main calls sub_401490 before strcmp.", None, "present", [e],
                             [{"type": "quote", "evidence_id": e, "text": "sub_401490()"}])
    assert r.status is ClaimStatus.SUPPORTED and r.kind_source == "inferred"


# ---------- PROVEN with execution evidence ----------

def test_behavior_with_execution_evidence_is_proven(env):
    s = env.ev(raw=DECOY_RAW, locations=())
    run = env.replay_ev(raw=b"Congratulations! The pass is faster\n", parameters={"stdin": "faster\n"})
    wrong = env.replay_ev(raw=b"Incorrect\n", exit_code=1, parameters={"stdin": "slower\n"})
    atoms = [{"type": "quote", "evidence_id": run, "text": "Congratulations!"}]
    r = env.ledger.add_claim('The correct password is "faster".', "behavior", "present", [s, run], atoms,
                             values=[{"value": "faster", "derived": True}], behavior_class="ordinary")
    assert r.status is ClaimStatus.UNVERIFIED and codes(r) == {"CONTROL_PAIR_MISSING"}   # version 24: one run is not a contrast
    r = env.ledger.add_claim('The correct password is "faster".', "behavior", "present", [s, run, wrong],
                             atoms + [control_pair(run, wrong, "Congratulations!", "Incorrect")],
                             values=[{"value": "faster", "derived": True}], behavior_class="ordinary")
    assert r.status is ClaimStatus.PROVEN and not codes(r) - {"KIND_OVERRIDDEN_TO_BEHAVIOR"}


def test_behavior_requested_supported_with_execution_is_still_proven(env):
    run = env.replay_ev(raw=b"License valid\n", parameters={"stdin": "k1\n"})
    wrong = env.replay_ev(raw=b"License invalid\n", exit_code=1, parameters={"stdin": "k2\n"})
    r = env.ledger.add_claim("Key `k1` is accepted.", None, "present", [run, wrong],
                             [{"type": "quote", "evidence_id": run, "text": "License valid"},
                              control_pair(run, wrong, "License valid", "License invalid")],
                             values=[{"value": "k1", "derived": True}], behavior_class="acceptance_validation")
    assert r.status is ClaimStatus.PROVEN


def test_wrong_run_cannot_prove_behavior_without_output_binding(env):
    run = env.replay_ev(raw=b"Incorrect\n", parameters={"stdin": "decoy-pw\n"})
    r = env.ledger.add_claim('The correct password is "decoy-pw".', "behavior", "present", [run], behavior_class="ordinary")
    assert r.status is ClaimStatus.UNVERIFIED and "BEHAVIOR_NEEDS_EXECUTION" in codes(r)


def test_requested_unverified_behavior_stays_hypothesis_not_rejected(env):
    r = env.ledger.add_claim("The correct password might be zzz.", None, "present", [], requested="UNVERIFIED")
    assert r.status is ClaimStatus.UNVERIFIED and r.accepted and r.kind == "behavior"


def test_legacy_kind_names_still_work(env):
    e = env.ev()
    assert env.claim("The string exists.", [e], kind="static_fact").status is ClaimStatus.SUPPORTED
    assert env.claim("The string exists.", [e], kind="static_fact").claim["kind"] == "observation"


# ---------- supersedes ----------

def test_supersedes_hides_old_claim_from_report_but_keeps_it_in_ledger(tmp_path):
    h, _, _ = make_hub(tmp_path)
    d = h.decompile("0x140001250")["evidence_id"]
    old = h.claim_add("The correct key has length 19.", [d], [{"type": "quote", "evidence_id": d, "text": "!= 19"}], kind="behavior", behavior_class="ordinary")
    assert old["status"] == "UNVERIFIED"
    new = h.claim_add("validate_license compares strlen(key) with 19.", [d],
                      [{"type": "quote", "evidence_id": d, "text": "strlen(key) != 19"}],
                      kind="observation", supersedes=[old["claim_id"]])
    assert new["status"] == "SUPPORTED" and new["superseded"] == [old["claim_id"]]
    rep = h.report_build()
    assert "correct key has length" not in rep["markdown"] and "compares strlen" in rep["markdown"]
    c = rep["counts"]
    assert c["findings"] == 1 and c["hypotheses"] == 0 and c["superseded"] == 1
    # stays in the ledger (append-only) and the journal chain is intact
    sess = h._need()
    st = sess.ledger.state
    assert old["claim_id"] in st["claims"] and old["claim_id"] in st["superseded"]
    assert st["superseded"][old["claim_id"]]["superseded_by"] == new["claim_id"]
    jpath = sess.job_dir / "events.jsonl"
    types = [e["type"] for e in sess.journal.events()]
    assert "CLAIM_SUPERSEDED" in types and types.count("CLAIM_ACCEPTED") == 2
    assert verify_file(jpath).ok
    assert old["claim_id"] in replay_state(sess.journal.events())["superseded"]  # on replay too
    h.close()


def test_supersedes_survives_resume(tmp_path):
    h, _, _ = make_hub(tmp_path)
    d = h.decompile("0x140001250")["evidence_id"]
    old = h.claim_add("The correct key has length 19.", [d], [{"type": "quote", "evidence_id": d, "text": "!= 19"}], kind="behavior", behavior_class="ordinary")
    h.claim_add("validate_license compares strlen(key) with 19.", [d],
                [{"type": "quote", "evidence_id": d, "text": "strlen(key) != 19"}],
                kind="observation", supersedes=[old["claim_id"]])
    h.close()
    h2, _, out = make_hub(tmp_path)  # same data root: continue from the journal
    assert out["resumed"] is True
    listed = {c["claim_id"]: c for c in out["previous"]["claims"]}
    assert listed[old["claim_id"]].get("superseded") is True
    assert h2.report_build()["counts"]["hypotheses"] == 0
    h2.close()


def test_supersedes_validation(env):
    e = env.ev()
    a = env.claim("The string exists.", [e])
    with pytest.raises(ValueError, match="unknown claim_id"):
        env.ledger.add_claim("Another string exists.", "observation", "present", [e], supersedes=["cl_" + "0" * 64])
    with pytest.raises(ValueError, match="supersede itself"):
        env.ledger.add_claim("The string exists.", "observation", "present", [e], supersedes=[a.claim["claim_id"]])


def test_rejected_replacement_does_not_retract_the_old_claim(env):
    e = env.ev()
    a = env.claim("The string exists.", [e])
    r = env.ledger.add_claim("Offset 0x999999 exists.", "observation", "present", [e], supersedes=[a.claim["claim_id"]])
    assert r.status is ClaimStatus.REJECTED and r.superseded == ()
    assert a.claim["claim_id"] not in env.ledger.state["superseded"]


def test_retracted_claim_cannot_retract_others(env):
    e = env.ev()
    a = env.claim("The string exists.", [e])
    b = env.ledger.add_claim("The string IRP_MJ_DEVICE_CONTROL exists.", "observation", "present", [e],
                             supersedes=[a.claim["claim_id"]])
    with pytest.raises(ValueError, match="already retracted"):
        env.ledger.add_claim("The string exists.", "observation", "present", [e], supersedes=[b.claim["claim_id"]])


# ---------- partial support ----------

def test_partial_support_reports_which_value_blocks_the_claim(tmp_path):
    h, _, _ = make_hub(tmp_path)
    d = h.decompile("0x140001250")["evidence_id"]  # contains 19 and 0xA5C3
    r = h.claim_add("The key length is 19 and the checksum equals 4944.", [d],
                    [{"type": "quote", "evidence_id": d, "text": "strlen(key) != 19"}], kind="observation",
                    values=[19, {"value": 4944, "derived": True}])
    assert r["status"] == "UNVERIFIED"
    assert r["values_supported"] == ["19"]
    assert [v["value"] for v in r["values_unsupported"]] == ["4944"] and r["values_unsupported"][0]["derived"] is True
    assert "`4944`" in r["message"] and "Supported value(s): `19`" in r["message"]
    assert "its own claim" in r["message"]
    # fix: the supported part becomes a separate claim and enters the findings; the derived part stays a hypothesis
    ok = h.claim_add("The key length is 19.", [d], [{"type": "quote", "evidence_id": d, "text": "strlen(key) != 19"}],
                     kind="observation", supersedes=[r["claim_id"]])
    assert ok["status"] == "SUPPORTED" and "message" not in ok
    h.close()


def test_report_lists_supported_and_unsupported_values_separately(tmp_path):
    h, _, _ = make_hub(tmp_path)
    d = h.decompile("0x140001250")["evidence_id"]
    h.claim_add("The key length is 19 and the checksum equals 4944.", [d],
                [{"type": "quote", "evidence_id": d, "text": "strlen(key) != 19"}], kind="observation",
                values=[19, {"value": 4944, "derived": True}])
    md = h.report_build()["markdown"]
    hyp = md.split("## Unverified hypotheses")[1]
    assert "unsupported value `4944`" in hyp and "supported value `19`" in hyp
    h.close()


# ---------- counters ----------

def test_counters_split_findings_from_hypotheses(tmp_path):
    h, _, _ = make_hub(tmp_path)
    d = h.decompile("0x140001250")["evidence_id"]
    q = [{"type": "quote", "evidence_id": d, "text": "strlen(key) != 19"}]
    h.claim_add("validate_license compares strlen(key) with 19.", [d], q, kind="observation")           # finding
    h.claim_add("The correct key has length 19.", [d], q, kind="behavior", behavior_class="ordinary")                                              # behavior hyp.
    h.claim_add("The key length is 19 and the checksum equals 4944.", [d], q, kind="observation",
                values=[{"value": 4944, "derived": True}])                                             # value hyp.
    h.claim_add("Maybe a hidden path exists.", requested="UNVERIFIED", kind="observation")                                 # no-evidence hyp.
    h.claim_add("Entry at 0x140009999.", [d], kind="observation")                                                          # rejected
    c = h.report_build()["counts"]
    assert c["findings"] == 1 and c["hypotheses"] == 3 and c["rejected_at_add"] == 1
    assert c["unsupported_claims"] == 0 and c["claims_without_evidence"] == 0
    assert c["claims_value_not_in_evidence"] == 0 and c["claims_behavior_without_execution"] == 0
    assert (c["hypotheses_without_evidence"], c["hypotheses_value_not_in_evidence"],
            c["hypotheses_behavior_needs_execution"], c["hypotheses_other"]) == (1, 1, 1, 0)
    h.close()


def test_bad_kind_and_supersedes_arguments_are_short_errors(tmp_path):
    from redharness.mcp.session import ToolFailure
    h, _, _ = make_hub(tmp_path)
    with pytest.raises(ToolFailure) as e:
        h.claim_add("x y z", kind="nonsense")
    assert e.value.code == "BAD_ARGUMENT" and "observation" in e.value.message
    with pytest.raises(ToolFailure) as e:
        h.claim_add("x y z", supersedes="cl_abc", kind="observation")
    assert e.value.code == "BAD_ARGUMENT"
    with pytest.raises(ToolFailure) as e:
        h.claim_add("x y z", requested="UNVERIFIED", supersedes=["cl_" + "1" * 64], kind="observation")
    assert e.value.code == "INVALID_CLAIM" and "unknown claim_id" in e.value.message
    h.close()


# ---------- kind is required, strong/weak pattern split ----------

def test_kind_is_required_and_nothing_is_recorded_without_it(tmp_path):
    from redharness.mcp.session import ToolFailure
    h, _, _ = make_hub(tmp_path)
    before = len(h.claim_add("Maybe x.", requested="UNVERIFIED", kind="observation").get("claim_id", ""))
    for bad in (None, "", "  "):
        with pytest.raises(ToolFailure) as e:
            h.claim_add("The correct password is decoy-pw.", kind=bad)
        assert e.value.code == "KIND_REQUIRED"
        assert e.value.message.startswith("kind is required: observation") and "behavior" in e.value.message
        assert len(e.value.message) < 160
    assert before > 0
    h.close()


def test_tool_description_tells_the_model_kind_is_required():
    import inspect
    from redharness.mcp import server
    src = inspect.getsource(server)
    assert "REQUIRED" in src and "KIND_REQUIRED" in src


@pytest.mark.parametrize("text", [
    "The correct password is \"decoy-pw\".", "Doğru parola decoy-pw.", "Bu girdi kabul edilir.",
    "The serial `1234-5678` is valid.", "Parola `x1` kabul edilir", "This input is accepted by the program.",
    "the key AAA-BBB is accepted", "Geçerli anahtar AAA-BBB.", "The binary accepts the password \"hunter2\".",
])
def test_strong_patterns_override_declared_observation(text):
    kind, source, hit = resolve_kind("observation", text)
    assert (kind, source) == ("behavior", "overridden") and hit, text


@pytest.mark.parametrize("text", [
    "The function prints success on that branch.", "valid_key accepts a key of 11 characters.",
    "All three keys must be valid for givepass to be called.", "main prints the string \"Correct Password!\".",
    "Fonksiyon geçerli bir uzunluk denetler.", "validate accepts two arguments.", "The call succeeds if rc is 0.",
    "_main requires length 32 and a prefix.", "valid code path at 0x401000", "Kod yolu kabul eder.",
])
def test_weak_words_alone_do_not_override_declared_observation(text):
    assert resolve_kind("observation", text)[:2] == ("observation", "declared"), text
