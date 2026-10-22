"""Dynamic observation interface (fake backend), seal/identity binding and the verifier rule.

Fakes only: the target is NOT RUN, Sandbox is not opened. Real API trace/dump observation is covered by real-process tests.
"""

import copy
import hashlib
import json

import pytest

from redharness.core.cas import Cas
from redharness.core.journal import Journal, canonical
from redharness.core.result import Status
from redharness.dynamic.backend import DynamicBackend, ObservationRequest
from redharness.dynamic.fake import FakeDynamicBackend
from redharness.dynamic.ingest import ingest_observation
from redharness.dynamic.match import check_api_sequence, find_dumps
from redharness.dynamic.model import ObservationError, RunIdentity, body_digest, load_observation, parse_body, scope_digest
from redharness.evidence.ledger import Ledger
from redharness.evidence.model import ClaimStatus, build_evidence
from redharness.scope.manifest import ScopeManifest

TARGET = hashlib.sha256(b"fake-target").hexdigest()
OTHER = hashlib.sha256(b"other-target").hexdigest()
EMPTY = hashlib.sha256(b"").hexdigest()
NONCE = "ab" * 32
SANDBOX = {"id": "wsb-1", "platform": "windows", "architecture": "x64", "isolation": "windows-sandbox"}
SCOPE = ScopeManifest(TARGET, "test", "owner", "test", ("static", "run_controlled"), None, "")
ID = RunIdentity.from_scope("run-1", TARGET, SCOPE)
SEQ = ["GetTempPathW", "GetTickCount", "CreateFileW", "WriteFile", "CloseHandle", "GetTickCount", "DeleteFileW",
       "ExitProcess"]
CLAIM = "The target calls `CreateFileW` and then `WriteFile`"
QUOTE = '"api":"CreateFileW"'


def request(identity=ID, **kw):
    kw.setdefault("stdin_sha256", EMPTY)
    return ObservationRequest(identity, "C:\\in\\t.exe", **kw)


def fake(**kw):
    kw.setdefault("api_calls", SEQ)
    return FakeDynamicBackend(kw.pop("nonce", NONCE), **kw)


def obs_of(backend=None, req=None):
    return load_observation((backend or fake()).observe(req or request()))


class Env:
    def __init__(self, tmp_path):
        self.cas = Cas(tmp_path / "cas")
        self.journal = Journal(tmp_path / "events.jsonl")
        self.ledger = Ledger(self.journal, self.cas, TARGET, scope_sha256=ID.scope_sha256)

    def dyn(self, backend=None, req=None, record=True):
        rec = ingest_observation(self.cas, (backend or fake()).observe(req or request()), nonce=NONCE, expected=ID)
        return self.ledger.record_evidence(rec)["evidence_id"] if record else rec

    def static(self, raw=b"0x1000: CreateFileW, WriteFile, `decoy-pw`\n"):
        rec = build_evidence(self.cas, subject_sha256=TARGET, tool="strings_search", operation="strings_search",
                             raw=raw, status=Status.OK, confidence="observed", authority="shipped-artifact",
                             locations=[{"kind": "file-offset-range", "start": 4096, "end": 4140}],
                             coverage={"scope": "all", "relationship": "complete"})
        return self.ledger.record_evidence(rec)["evidence_id"]

    def replay(self, raw=b"done\n", argv=(), stdin_sha=EMPTY, exit_code=0, status=Status.OK):
        rec = build_evidence(self.cas, subject_sha256=TARGET, tool="run_controlled", operation="run_controlled",
                             raw=raw, status=status, confidence="observed", authority="controlled-replay",
                             environment=SANDBOX, exit_code=exit_code, truncated=False,
                             parameters={"argv": list(argv), "stdin_sha256": stdin_sha},
                             coverage={"scope": "case:0", "relationship": "partial"})
        return self.ledger.record_evidence(rec)["evidence_id"]

    def claim(self, ev_ids, text=CLAIM, kind="behavior", polarity="present", req="SUPPORTED", atoms=None):
        atoms = [{"type": "quote", "evidence_id": ev_ids[0], "text": QUOTE}] if atoms is None else atoms
        return self.ledger.add_claim(text, kind, polarity, ev_ids, atoms, req,
                                     behavior_class=("ordinary" if kind in ("behavior", "runtime_behavior") else None))   # verifier 24


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def codes(res):
    return {i["code"] for i in res.issues}


# ------------------------------------------------------------------ interface + fake backend

def test_fake_backend_implements_interface_and_is_deterministic():
    b = fake(dumps=[(0x400000, b"MZpayload", "dump", "RX")])
    assert isinstance(b, DynamicBackend)
    assert b.observe(request()) == b.observe(request())
    assert b.requests[0].identity == ID
    o = obs_of(b)
    assert [e.api for e in o.api_calls()] == SEQ
    assert o.memory_events()[0].sha256 == hashlib.sha256(b"MZpayload").hexdigest()
    assert o.coverage == {"api_trace": "complete", "memory": "complete"} and o.fully_covered


def test_request_rejects_bad_channels_and_identity():
    with pytest.raises(ValueError):
        request(channels=("kernel",))
    with pytest.raises(ValueError):
        RunIdentity("run 1", TARGET, ID.scope_sha256)
    with pytest.raises(ValueError):
        RunIdentity("r", "zz", ID.scope_sha256)


def test_identity_from_scope_requires_run_permission_and_same_target():
    with pytest.raises(ValueError, match="run_controlled"):
        RunIdentity.from_scope("r", TARGET, ScopeManifest(TARGET, "t", "owner", "s", ("static",), None, ""))
    with pytest.raises(ValueError, match="another target"):
        RunIdentity.from_scope("r", OTHER, SCOPE)
    assert ID.scope_sha256 == scope_digest(SCOPE)


def test_unrequested_channel_is_unknown_not_clean():
    o = obs_of(req=request(channels=("api_trace",)))
    assert o.coverage == {"api_trace": "complete", "memory": "unknown"}
    assert o.fully_covered  # the requested channel is complete; the unrequested channel stays unknown


# ------------------------------------------------------------------ API sequence (exact order and repeats)

def test_api_sequence_exact_order_and_repeats():
    names = list(SEQ)
    assert names.count("GetTickCount") == 2
    o = obs_of(fake(api_calls=names))
    r = check_api_sequence(o, names, module="kernel32.dll")
    assert r.verdict == "match" and r.ok and r.observed == tuple(names)


@pytest.mark.parametrize("name,calls", [
    ("missing_repeat", [c for i, c in enumerate(SEQ) if i != 5]),            # second GetTickCount missing
    ("extra_repeat", SEQ + ["GetTickCount"]),
    ("reordered", SEQ[:2] + [SEQ[3], SEQ[2]] + SEQ[4:]),
    ("missing_tail", SEQ[:-1]),
    ("collapsed_repeat", [c for c in SEQ if c != "GetTickCount"] + ["GetTickCount"]),
])
def test_api_sequence_rejects_wrong_traces(name, calls):
    r = check_api_sequence(obs_of(fake(api_calls=calls)), SEQ, module="kernel32.dll")
    assert r.verdict == "mismatch" and not r.ok and r.first_divergence is not None


def test_api_sequence_ignores_non_target_calls_unless_asked():
    calls = SEQ[:3] + [("NtCreateFile", False)] + SEQ[3:]
    o = obs_of(fake(api_calls=calls))
    assert check_api_sequence(o, SEQ, module="kernel32.dll").verdict == "match"
    assert check_api_sequence(o, SEQ, only_target=False).verdict == "mismatch"


@pytest.mark.parametrize("kw", [dict(dropped_events=3), dict(timed_out=True, exit_code=None),
                                dict(coverage={"api_trace": "partial"}), dict(coverage={"api_trace": "unknown"})])
def test_incomplete_coverage_is_unknown_never_match(kw):
    o = obs_of(fake(**kw))  # with dropped events/timeout the fake backend does not report complete
    r = check_api_sequence(o, SEQ)
    assert r.verdict == "unknown" and not r.ok  # even a fully correct sequence is not 'match' under incomplete coverage


def test_contradictory_coverage_documents_are_rejected_at_parse():
    body = fake().observation(request()).to_body()
    body["dropped_events"] = 2  # complete + dropped events: contradiction
    with pytest.raises(ObservationError):
        from redharness.dynamic.model import parse_body
        parse_body(body)
    body = fake().observation(request(channels=("api_trace",))).to_body()
    body["coverage"]["memory"] = "complete"  # coverage claim on an unrequested channel
    with pytest.raises(ObservationError):
        parse_body(body)


def test_bytes_longer_than_the_declared_region_size_are_rejected():
    body = FakeDynamicBackend(NONCE, dumps=[(0x400000, b"MZpayload", "exec_transition", "RX")]).observation(
        request(channels=("memory",), memory_capture_bytes=64)).to_body()
    ev = body["events"][0]
    assert len(bytes.fromhex(ev["bytes_hex"])) == ev["size"] == 9
    forged = {**ev, "bytes_hex": ev["bytes_hex"] + "00"}       # the digest of the first size bytes still matches
    with pytest.raises(ObservationError, match="exceed the declared size"):
        parse_body({**body, "events": [forged]})
    parse_body({**body, "events": [{**ev, "bytes_hex": ev["bytes_hex"][:-2]}]})   # a shorter head stays valid


def test_find_dumps_by_hash():
    payload = b"\x55\x8b" * 30
    o = obs_of(fake(dumps=[(0x1000, b"junk", "dump", "RW"), (0x20000, payload, "exec_transition", "RX")]))
    hit = find_dumps(o, hashlib.sha256(payload).hexdigest(), size=len(payload))
    assert len(hit) == 1 and hit[0].base == 0x20000 and hit[0].kind == "exec_transition"
    assert find_dumps(o, hashlib.sha256(b"zzz").hexdigest()) == []


# ------------------------------------------------------------------ replay / forgery / tampering (ingest)

def count_blobs(env):
    return len([p for p in env.cas.root.rglob("*") if p.is_file()]) if env.cas.root.exists() else 0


def test_ingest_ok_builds_dynamic_evidence(env):
    rec = env.dyn(record=False)
    assert rec["authority"] == "dynamic-observation" and rec["confidence"] == "observed"
    assert rec["environment"]["isolation"] == "windows-sandbox"
    assert rec["parameters"]["run_id"] == "run-1" and rec["parameters"]["scope_sha256"] == ID.scope_sha256
    assert rec["parameters"]["seal"] == "hmac-verified" and rec["capture"]["strength"] == "full"
    assert rec["coverage"]["relationship"] == "partial"  # single run: never complete
    assert rec["result"]["api_sequence"] == SEQ
    # identity is stable: duration does not enter the identity
    b = fake().observe(request())
    assert (ingest_observation(env.cas, b, nonce=NONCE, expected=ID, elapsed_ms=1)["evidence_id"]
            == ingest_observation(env.cas, b, nonce=NONCE, expected=ID, elapsed_ms=999)["evidence_id"])


def test_incomplete_observation_becomes_partial_evidence_with_unknown_coverage(env):
    rec = env.dyn(fake(dropped_events=5), record=False)
    assert rec["capture"]["strength"] == "partial" and rec["coverage"]["relationship"] == "unknown"
    assert rec["coverage"]["channels"]["api_trace"] == "partial"
    t = env.dyn(fake(timed_out=True, exit_code=None), record=False)
    assert t["capture"]["strength"] == "failed"


def test_memory_events_become_address_locations(env):
    rec = env.dyn(fake(dumps=[(0x400000, b"x" * 125, "exec_transition", "RX")]), record=False)
    assert {"kind": "address-range", "space": "va", "start": 0x400000, "end": 0x400000 + 125} in rec["locations"]


@pytest.mark.parametrize("mk,code,needle", [
    (lambda: fake(identity_override=RunIdentity("run-2", TARGET, ID.scope_sha256)), "DYNAMIC_IDENTITY_MISMATCH", "run_id"),
    (lambda: fake(identity_override=RunIdentity("run-1", OTHER, ID.scope_sha256)), "DYNAMIC_IDENTITY_MISMATCH", "target"),
    (lambda: fake(identity_override=RunIdentity("run-1", TARGET, "0" * 64)), "DYNAMIC_IDENTITY_MISMATCH", "scope"),
    (lambda: fake(nonce="cd" * 32), "DYNAMIC_INTEGRITY", "nonce"),          # sealed with the nonce of another run
    (lambda: fake(seal=False), "DYNAMIC_INTEGRITY", "unsealed"),
])
def test_ingest_rejects_replay_and_forgery_and_writes_nothing(env, mk, code, needle):
    doc = mk().observe(request(mk().identity_override or ID))
    with pytest.raises(ObservationError, match=needle) as ei:
        ingest_observation(env.cas, doc, nonce=NONCE, expected=ID)
    assert ei.value.code == code
    assert count_blobs(env) == 0, "rejected observation was written to the CAS"


def test_replay_of_valid_observation_onto_other_target_or_run_is_rejected(env):
    doc = fake().observe(request())  # valid sealed document for TARGET / run-1
    other_scope = ScopeManifest(OTHER, "t", "owner", "s", ("static", "run_controlled"), None, "")
    with pytest.raises(ObservationError) as ei:
        ingest_observation(env.cas, doc, nonce=NONCE, expected=RunIdentity.from_scope("run-1", OTHER, other_scope))
    assert ei.value.code == "DYNAMIC_IDENTITY_MISMATCH"
    with pytest.raises(ObservationError) as ei:
        ingest_observation(env.cas, doc, nonce=NONCE, expected=RunIdentity("run-9", TARGET, ID.scope_sha256))
    assert ei.value.code == "DYNAMIC_IDENTITY_MISMATCH"
    assert count_blobs(env) == 0


def test_edited_observation_file_is_rejected(env):
    good = json.loads(fake().observe(request()))
    mutations = {
        "api_name": lambda d: d["events"][2].__setitem__("api", "OpenProcess"),
        "drop_event": lambda d: d["events"].pop(),
        "exit_code": lambda d: d["outcome"].__setitem__("exit_code", 1),
        "coverage": lambda d: d["coverage"].__setitem__("memory", "partial"),
        "mac": lambda d: d["integrity"].__setitem__("mac", "0" * 64),
        "swap_identity": lambda d: d["identity"].__setitem__("run_id", "run-2"),
    }
    for name, fn in mutations.items():
        d = copy.deepcopy(good)
        fn(d)
        with pytest.raises(ObservationError):
            ingest_observation(env.cas, canonical(d), nonce=NONCE, expected=ID)
    with pytest.raises(ObservationError):  # byte-level corruption
        ingest_observation(env.cas, fake().observe(request()).replace(b"CreateFileW", b"CreateFileX"),
                           nonce=NONCE, expected=ID)
    with pytest.raises(ObservationError):  # not JSON / float
        ingest_observation(env.cas, b"not json", nonce=NONCE, expected=ID)
    assert count_blobs(env) == 0


def test_sandbox_and_dynamic_seals_do_not_cross_verify(env):
    from redharness.sandbox import integrity as itg
    body = fake().observation(request()).to_body()
    doc = dict(body)
    doc["integrity"] = {"version": 1, "nonce_commit": itg.nonce_commit(NONCE),
                        "mac": itg.sign_session(NONCE, "run-1", TARGET)["mac"]}
    with pytest.raises(ObservationError):
        ingest_observation(env.cas, canonical(doc), nonce=NONCE, expected=ID)


# ------------------------------------------------------------------ verifier: dynamic alone can never be PROVEN

def test_dynamic_alone_can_never_be_proven_but_can_be_supported(env):
    d = env.dyn()
    r = env.claim([d], req="PROVEN")
    assert r.status is ClaimStatus.SUPPORTED, r.issues
    assert "PROVEN_DYNAMIC_NEEDS_RUN_OUTCOME" in codes(r) and "PROVEN_NEEDS_CONTROLLED_REPLAY" in codes(r)
    r2 = env.claim([d], req="SUPPORTED")
    assert r2.status is ClaimStatus.SUPPORTED and "PROVEN_DYNAMIC_NEEDS_RUN_OUTCOME" in codes(r2)
    # even if kind=observation + PROVEN is requested it is not PROVEN
    r3 = env.claim([d], kind="observation", req="PROVEN", text="The trace lists `CreateFileW` and `WriteFile`")
    assert r3.status is ClaimStatus.SUPPORTED


def test_dynamic_plus_static_is_still_not_proven(env):
    d, s = env.dyn(), env.static()
    r = env.claim([d, s], req="PROVEN", atoms=[{"type": "quote", "evidence_id": d, "text": QUOTE},
                                                {"type": "address", "evidence_id": s, "value": "0x1000",
                                                 "space": "file_offset"}])
    assert r.status is ClaimStatus.SUPPORTED and "PROVEN_DYNAMIC_NEEDS_RUN_OUTCOME" in codes(r)


def test_dynamic_plus_matching_run_outcome_is_proven(env):
    d, r_ = env.dyn(), env.replay()
    res = env.claim([d, r_], req="PROVEN")
    assert res.status is ClaimStatus.PROVEN, res.issues
    assert res.claim["verification"]["verifier_version"] == "24"
    # the same combination also becomes PROVEN as a behavior claim when SUPPORTED is requested (like the existing execution rule)
    assert env.claim([d, r_], req="SUPPORTED").status is ClaimStatus.PROVEN


@pytest.mark.parametrize("kw", [dict(argv=("--x",)), dict(stdin_sha=hashlib.sha256(b"a\n").hexdigest()),
                                dict(exit_code=1)])
def test_run_outcome_must_be_the_same_case(env, kw):
    d, r_ = env.dyn(), env.replay(**kw)
    res = env.claim([d, r_], req="PROVEN")
    assert res.status is ClaimStatus.SUPPORTED and "PROVEN_DYNAMIC_NEEDS_RUN_OUTCOME" in codes(res)


def test_incomplete_observation_cannot_be_proven_even_with_run_outcome(env):
    d = env.dyn(fake(dropped_events=1))
    res = env.claim([d, env.replay()], req="PROVEN")
    assert res.status is ClaimStatus.SUPPORTED and "PROVEN_DYNAMIC_NEEDS_RUN_OUTCOME" in codes(res)


def test_run_outcome_cannot_launder_an_unpaired_dynamic_observation(env):
    d = env.dyn(fake(exit_code=7))        # different exit code: unpaired observation
    r_ = env.replay(raw=b"License valid\n")
    res = env.claim([d, r_], req="PROVEN", atoms=[{"type": "quote", "evidence_id": r_, "text": "License valid"}],
                    text="The target prints License valid and calls `CreateFileW`")
    assert res.status is not ClaimStatus.PROVEN


def test_static_value_with_unrelated_dynamic_trace_stays_unverified(env):
    """decoy-value pattern: the behavior claim's value is only in static evidence; an unrelated dynamic trace does not make it executed."""
    s, d = env.static(), env.dyn()
    res = env.claim([s, d], text="The correct password is `decoy-pw`", atoms=[
        {"type": "quote", "evidence_id": s, "text": "`decoy-pw`"}])
    assert res.status is ClaimStatus.UNVERIFIED and "BEHAVIOR_NEEDS_EXECUTION" in codes(res)


def test_absence_claim_from_dynamic_observation_is_rejected(env):
    d = env.dyn()
    res = env.claim([d], text="The target never calls `OpenProcess`", polarity="absent",
                    atoms=[{"type": "quote", "evidence_id": d, "text": "kernel32.dll"}])
    assert res.status is ClaimStatus.REJECTED and "ABSENCE_WITHOUT_COMPLETE_COVERAGE" in codes(res)


def test_partial_observation_supports_present_claims_only(env):
    d = env.dyn(fake(dropped_events=1))
    assert env.claim([d]).status is ClaimStatus.SUPPORTED
    assert env.claim([d], text="The target never calls `OpenProcess`", polarity="absent",
                     atoms=[{"type": "quote", "evidence_id": d, "text": "kernel32.dll"}]).status is ClaimStatus.REJECTED


def test_timed_out_observation_supports_nothing(env):
    d = env.dyn(fake(timed_out=True, exit_code=None))
    res = env.claim([d])
    assert res.status is ClaimStatus.REJECTED and "EVIDENCE_FAILED" in codes(res)


# ------------------------------------------------------------------ verifier: record/document inconsistency and tampering

def test_cas_blob_edit_is_rejected(env):
    d = env.dyn()
    rec = env.ledger.state["evidence"][d]
    p = env.cas.path_for(rec["raw"]["blob_sha256"])
    p.write_bytes(p.read_bytes().replace(b"CreateFileW", b"CreateFileX"))
    res = env.claim([d])
    assert res.status is ClaimStatus.REJECTED and "RAW_BLOB_HASH_MISMATCH" in codes(res)


def test_ledger_record_edit_is_rejected(env):
    d = env.dyn()
    c = env.claim([d])
    assert c.status is ClaimStatus.SUPPORTED
    env.ledger.state["evidence"][d]["parameters"]["run_id"] = "run-2"
    v = env.ledger.reverify(c.claim_id)
    assert v.status is ClaimStatus.REJECTED and "EVIDENCE_ID_MISMATCH" in v.codes


def _forged(env, raw, *, subject=TARGET, params=None, status=Status.OK, exit_code=0, coverage=None):
    """Evidence record produced BY HAND by an attacker with access to the server code (consistent id, contradicts the raw document)."""
    good = json.loads(fake().observe(request()))
    base = {"run_id": "run-1", "scope_sha256": ID.scope_sha256, "argv": [], "stdin_sha256": EMPTY,
            "observation_sha256": body_digest({k: v for k, v in json.loads(raw).items() if k != "integrity"}), "seal": "hmac-verified",
            "channels_requested": ["api_trace", "memory"]}
    base.update(params or {})
    rec = build_evidence(env.cas, subject_sha256=subject, tool="dynamic_observe", operation="dynamic_observe",
                         raw=raw, status=status, confidence="observed", authority="dynamic-observation",
                         parameters=base, exit_code=exit_code, environment=SANDBOX,
                         coverage=coverage or {"scope": "run:run-1", "relationship": "partial",
                                               "channels": good["coverage"]})
    return env.ledger.record_evidence(rec)["evidence_id"]


def test_forged_record_with_unsealed_raw_is_rejected(env):
    body = fake().observation(request()).to_body()
    d = _forged(env, canonical(body))
    res = env.claim([d])
    assert res.status is ClaimStatus.REJECTED and "DYNAMIC_INTEGRITY" in codes(res)


def test_forged_record_without_seal_marker_is_rejected(env):
    d = _forged(env, fake().observe(request()), params={"seal": "none"})
    assert "DYNAMIC_INTEGRITY" in codes(env.claim([d]))


def test_forged_record_edited_body_is_rejected(env):
    doc = json.loads(fake().observe(request()))
    good_digest = body_digest({k: v for k, v in doc.items() if k != "integrity"})
    doc["events"][0]["api"] = "OpenProcess"
    d = _forged(env, canonical(doc), params={"observation_sha256": good_digest})
    res = env.claim([d], text="The target calls `OpenProcess`", atoms=[
        {"type": "quote", "evidence_id": d, "text": '"api":"OpenProcess"'}])
    assert res.status is ClaimStatus.REJECTED and "DYNAMIC_OBSERVATION_INVALID" in codes(res)


def test_forged_record_with_foreign_run_or_target_is_rejected(env):
    raw = fake().observe(request())
    assert "DYNAMIC_IDENTITY_MISMATCH" in codes(env.claim([_forged(env, raw, params={"run_id": "run-2"})]))
    other_raw = fake().observe(request(RunIdentity("run-1", OTHER, ID.scope_sha256)))
    # the raw document belongs to another target; the record subject is this target
    d = _forged(env, other_raw, params={"run_id": "run-1"})
    r = env.claim([d])
    assert r.status is ClaimStatus.REJECTED and "DYNAMIC_IDENTITY_MISMATCH" in codes(r)
    # the record subject is another target: does not match the job's target
    d2 = _forged(env, raw, subject=OTHER)
    assert "SUBJECT_SHA_MISMATCH" in codes(env.claim([d2]))


def test_forged_record_with_status_or_coverage_not_matching_document_is_rejected(env):
    raw = fake(dropped_events=2).observe(request())  # document is partial/unknown
    d = _forged(env, raw, status=Status.OK, coverage={"scope": "run:run-1", "relationship": "partial",
                                                      "channels": {"api_trace": "complete", "memory": "complete"}})
    r = env.claim([d])
    assert r.status is ClaimStatus.REJECTED and "DYNAMIC_OBSERVATION_INVALID" in codes(r)


def test_scope_mismatch_with_ledger_scope_is_rejected(tmp_path):
    e = Env(tmp_path)
    d = e.dyn()
    e.ledger.scope_sha256 = "1" * 64
    r = e.claim([d])
    assert r.status is ClaimStatus.REJECTED and "DYNAMIC_IDENTITY_MISMATCH" in codes(r)


def test_dynamic_evidence_requires_isolated_environment(env):
    with pytest.raises(ValueError, match="isolated"):
        build_evidence(env.cas, subject_sha256=TARGET, tool="dynamic_observe", operation="dynamic_observe",
                       raw=b"x", status=Status.OK, confidence="observed", authority="dynamic-observation",
                       environment={"id": "host", "platform": "windows", "architecture": "x64", "isolation": "none"})
    with pytest.raises(ValueError):
        build_evidence(env.cas, subject_sha256=TARGET, tool="dynamic_observe", operation="dynamic_observe",
                       raw=b"x", status=Status.OK, confidence="observed", authority="dynamic-observation")


def test_below_scope_isolation_is_rejected_by_verifier(tmp_path):
    e = Env(tmp_path)
    e.ledger.allowed_isolations = frozenset({"virtual-machine"})  # the scope wants stronger isolation
    d = e.dyn()
    r = e.claim([d])
    assert r.status is ClaimStatus.REJECTED and "DYNAMIC_NOT_ISOLATED" in codes(r)


# ------------------------------------------------------------------ api_sequence atom (verifier version 5)

def _seq_atom(ev, calls=None, **kw):
    return {"type": "api_sequence", "evidence_id": ev, "calls": list(SEQ if calls is None else calls), **kw}


SEQ_TEXT = "The target calls the listed kernel32 functions in this order"


def seq_claim(env, ev_ids, calls=None, req="SUPPORTED", text=SEQ_TEXT, **kw):
    return env.claim(ev_ids, text=text, req=req, atoms=[_seq_atom(ev_ids[0], calls, **kw)])


def test_verifier_version_is_9():
    from redharness.evidence.verifier import VERIFIER_VERSION
    assert VERIFIER_VERSION == "24"


def test_api_sequence_exact_match_with_repeats_is_supported(env):
    names = list(SEQ)
    assert names.count("GetTickCount") == 2          # the sequence has a repeat
    d = env.dyn(fake(api_calls=names))
    r = seq_claim(env, [d], names, module="kernel32.dll")
    assert r.status is ClaimStatus.SUPPORTED, r.issues
    assert {"code": "API_SEQUENCE", "ok": True} in r.claim["verification"]["checks"]
    assert r.claim["verification"]["verifier_version"] == "24"


def test_api_sequence_dynamic_alone_is_capped_at_supported(env):
    d = env.dyn()
    r = seq_claim(env, [d], req="PROVEN")
    assert r.status is ClaimStatus.SUPPORTED and "PROVEN_DYNAMIC_NEEDS_RUN_OUTCOME" in codes(r)


def test_api_sequence_with_matching_run_outcome_is_proven_only_on_full_coverage(env):
    d, r_ = env.dyn(), env.replay()
    assert seq_claim(env, [d, r_], req="PROVEN").status is ClaimStatus.PROVEN
    d2 = env.dyn(fake(dropped_events=1))   # coverage incomplete: no match, no PROVEN
    r2 = seq_claim(env, [d2, r_], calls=SEQ[:2], mode="subsequence", req="PROVEN")
    assert r2.status is ClaimStatus.SUPPORTED and "PROVEN_DYNAMIC_NEEDS_RUN_OUTCOME" in codes(r2)


@pytest.mark.parametrize("name,calls", [
    ("wrong_order", SEQ[:2] + [SEQ[3], SEQ[2]] + SEQ[4:]),
    ("missing_call", [c for i, c in enumerate(SEQ) if i != 3]),                  # WriteFile missing
    ("extra_call", SEQ[:4] + ["Sleep"] + SEQ[4:]),
    ("extra_tail_call", SEQ + ["ExitProcess"]),
    ("collapsed_repeat", [c for c in SEQ if c != "GetTickCount"] + ["GetTickCount"]),
    ("single_tick", [c for i, c in enumerate(SEQ) if i != 5]),                   # second GetTickCount missing
    ("extra_repeat", SEQ[:2] + ["GetTickCount"] + SEQ[2:]),                      # extra GetTickCount
])
def test_api_sequence_exact_rejects_wrong_claims_on_complete_coverage(env, name, calls):
    d = env.dyn()
    r = seq_claim(env, [d], calls)
    assert r.status is ClaimStatus.REJECTED and "API_SEQUENCE_MISMATCH" in codes(r), name


def test_api_sequence_exact_rejects_when_observed_trace_has_other_order(env):
    d = env.dyn(fake(api_calls=SEQ[:2] + [SEQ[3], SEQ[2]] + SEQ[4:]))
    assert seq_claim(env, [d]).status is ClaimStatus.REJECTED


def test_api_sequence_ignores_calls_not_from_target(env):
    d = env.dyn(fake(api_calls=SEQ[:3] + [("NtCreateFile", False)] + SEQ[3:]))
    assert seq_claim(env, [d]).status is ClaimStatus.SUPPORTED


@pytest.mark.parametrize("kw", [dict(dropped_events=1), dict(coverage={"api_trace": "partial"}),
                                dict(coverage={"api_trace": "unknown"})])
def test_api_sequence_exact_is_unverified_on_partial_or_unknown_coverage(env, kw):
    d = env.dyn(fake(**kw))                     # even if the observed sequence is correct
    r = seq_claim(env, [d])
    assert r.status is ClaimStatus.UNVERIFIED and "API_SEQUENCE_COVERAGE_INCOMPLETE" in codes(r)
    assert "API_SEQUENCE_MISMATCH" not in codes(r)
    # a missing event does not count as "absent": even with a short observed trace it is not a rejection, just unverifiable
    d2 = env.dyn(fake(api_calls=SEQ[:3], **kw))
    r2 = seq_claim(env, [d2])
    assert r2.status is ClaimStatus.UNVERIFIED and "API_SEQUENCE_COVERAGE_INCOMPLETE" in codes(r2)


def test_api_sequence_unrequested_api_channel_is_unknown_not_rejected(env):
    d = env.dyn(req=request(channels=("memory",)))
    r = seq_claim(env, [d])
    assert r.status is ClaimStatus.UNVERIFIED and "API_SEQUENCE_COVERAGE_INCOMPLETE" in codes(r)


def test_api_sequence_subsequence_is_explicit_and_keeps_order_and_repeats(env):
    d = env.dyn()
    ok = seq_claim(env, [d], ["GetTempPathW", "WriteFile", "GetTickCount", "ExitProcess"], mode="subsequence")
    assert ok.status is ClaimStatus.SUPPORTED, ok.issues
    # the same list without mode counts as exact and does not hold
    assert seq_claim(env, [d], ["GetTempPathW", "WriteFile"]).status is ClaimStatus.REJECTED
    # order and repeat count are preserved in a subsequence too
    assert seq_claim(env, [d], ["WriteFile", "CreateFileW"], mode="subsequence").status is ClaimStatus.REJECTED
    three = ["GetTickCount"] * 3
    assert seq_claim(env, [d], three, mode="subsequence").status is ClaimStatus.REJECTED
    assert seq_claim(env, [d], three[:2], mode="subsequence").status is ClaimStatus.SUPPORTED


def test_api_sequence_subsequence_partial_coverage_found_supported_missing_unverified(env):
    d = env.dyn(fake(dropped_events=2))
    found = seq_claim(env, [d], ["CreateFileW", "WriteFile"], mode="subsequence")
    assert found.status is ClaimStatus.SUPPORTED          # observed events are real; only absence cannot be known
    miss = seq_claim(env, [d], ["WriteFile", "CreateFileW"], mode="subsequence")
    assert miss.status is ClaimStatus.UNVERIFIED and "API_SEQUENCE_COVERAGE_INCOMPLETE" in codes(miss)


@pytest.mark.parametrize("atom_kw", [
    dict(mode="loose"), dict(calls=[]), dict(calls=["A", ""]), dict(calls="GetTickCount"), dict(calls=["A", 5]),
    dict(module=5), dict(extra="x"),
])
def test_api_sequence_malformed_atom_is_rejected(env, atom_kw):
    d = env.dyn()
    r = env.claim([d], text=SEQ_TEXT, atoms=[{**_seq_atom(d), **atom_kw}])
    assert r.status is ClaimStatus.REJECTED and "API_SEQUENCE_MALFORMED" in codes(r)


def test_api_sequence_on_static_evidence_is_rejected(env):
    s = env.static()
    r = env.claim([s], text=SEQ_TEXT, kind="observation", atoms=[_seq_atom(s)])
    assert r.status is ClaimStatus.REJECTED and "API_SEQUENCE_NEEDS_DYNAMIC_EVIDENCE" in codes(r)


def test_api_sequence_cannot_back_an_absence_claim(env):
    d = env.dyn()
    r = env.claim([d], text="The target never calls the listed functions", polarity="absent",
                  atoms=[_seq_atom(d)])
    assert r.status is ClaimStatus.REJECTED
    assert {"API_SEQUENCE_MALFORMED", "ABSENCE_WITHOUT_COMPLETE_COVERAGE"} <= codes(r)


def test_api_sequence_atom_must_cite_listed_evidence(env):
    d, other = env.dyn(), env.dyn(fake(api_calls=SEQ[:2]))
    r = env.claim([d], text=SEQ_TEXT, atoms=[_seq_atom(other)])
    assert r.status is ClaimStatus.REJECTED and "ATOM_EVIDENCE_NOT_LISTED" in codes(r)


def test_api_sequence_is_checked_against_the_cited_observation_not_another(env):
    good, short = env.dyn(), env.dyn(fake(api_calls=SEQ[:2]))
    r = env.claim([good, short], text=SEQ_TEXT, atoms=[_seq_atom(short)])
    assert r.status is ClaimStatus.REJECTED and "API_SEQUENCE_MISMATCH" in codes(r)


# ------------------------------------------------------------------ version 4 backward compatibility

# The version 4 verifier (before api_sequence) produced EXACTLY this record for these two scenarios
# (captured from that version's code).
V4_SUPPORTED = {'checks': [{'code': 'EVIDENCE_INTEGRITY', 'ok': True},
            {'code': 'NOT_INFERRED_ONLY', 'ok': True},
            {'code': 'ATOMS', 'ok': True},
            {'code': 'HEX_LITERALS', 'ok': True},
            {'code': 'VALUES_IN_EVIDENCE', 'ok': True},
            {'code': 'BEHAVIOR_NEEDS_EXECUTION', 'ok': True},
            {'code': 'PROVEN_CONDITIONS', 'ok': False}],
 'issues': [{'code': 'PROVEN_DYNAMIC_NEEDS_RUN_OUTCOME',
             'severity': 'CAP',
             'detail': 'a dynamic observation alone never proves a claim: cite a complete run_controlled outcome of '
                       'the same case (argv, stdin, exit code) and a full-coverage observation'},
            {'code': 'PROVEN_NEEDS_CONTROLLED_REPLAY',
             'severity': 'CAP',
             'detail': 'no isolated run evidence'}],
 'values': [{'value': 'CreateFileW', 'derived': False, 'source': 'quoted', 'supported': True},
            {'value': 'WriteFile', 'derived': False, 'source': 'quoted', 'supported': True}]}

V4_PROVEN = {'checks': [{'code': 'EVIDENCE_INTEGRITY', 'ok': True},
            {'code': 'NOT_INFERRED_ONLY', 'ok': True},
            {'code': 'ATOMS', 'ok': True},
            {'code': 'HEX_LITERALS', 'ok': True},
            {'code': 'VALUES_IN_EVIDENCE', 'ok': True},
            {'code': 'BEHAVIOR_NEEDS_EXECUTION', 'ok': True},
            {'code': 'PROVEN_CONDITIONS', 'ok': True}],
 'issues': [],
 'values': [{'value': 'CreateFileW', 'derived': False, 'source': 'quoted', 'supported': True},
            {'value': 'WriteFile', 'derived': False, 'source': 'quoted', 'supported': True}]}


def _as_v4(env, res):
    """Drops a record into the journal as if produced by version 4 and re-verifies it in a ledger reloaded from the journal."""
    rec = copy.deepcopy(res.claim)
    rec["verification"]["verifier_version"] = "4"
    rec["revision"] += 1
    env.ledger._append("CLAIM_ACCEPTED", rec)
    reloaded = Ledger(env.journal, env.cas, TARGET, scope_sha256=ID.scope_sha256)
    assert reloaded.state["claims"][res.claim_id]["verification"]["verifier_version"] == "4"
    return reloaded.reverify(res.claim_id)


def _body(v):
    r = v if isinstance(v, dict) else v.to_record()
    return {k: r[k] for k in ("checks", "issues", "values")}


def test_v4_records_without_api_sequence_atoms_verify_identically(env):
    d, r_ = env.dyn(), env.replay()
    for ev, req, golden, status in (([d], "SUPPORTED", V4_SUPPORTED, ClaimStatus.SUPPORTED),
                                    ([d, r_], "PROVEN", V4_PROVEN, ClaimStatus.PROVEN)):
        res = env.claim(ev, req=req)
        assert res.status is status
        assert _body(res.claim["verification"]) == golden           # version 5 gives the same output as version 4
        old = _as_v4(env, res)                                      # record labeled version 4
        assert old.status is status and _body(old) == golden
        assert "API_SEQUENCE" not in [c["code"] for c in old.checks]
    assert res.claim["verification"]["verifier_version"] == "24"


def test_unknown_atom_types_still_fail_and_quote_atoms_unchanged(env):
    d = env.dyn()
    r = env.claim([d], atoms=[{"type": "api_sequences", "evidence_id": d, "calls": ["A"]}])
    assert r.status is ClaimStatus.REJECTED and "ATOM_TYPE_UNKNOWN" in codes(r)
    assert env.claim([d]).status is ClaimStatus.SUPPORTED
