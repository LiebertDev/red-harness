"""Sandbox output integrity: nonce/HMAC records, tampering, missing records. Fake sandbox (no real sandbox/target).

That the target is really blocked in a real Sandbox and that guest.ps1 and the host use the same canonical form
is tested in tests/heavy/test_sandbox_integrity_real.py.
"""
import hashlib
import json
import re

import pytest

from redharness.config import Config
from redharness.core.cas import Cas
from redharness.core.journal import Journal
from redharness.core.result import Status
from redharness.sandbox import (CaseResult, Code, RunCase, build_run_evidence, build_run_evidence_all,
                                integrity as itg, run_controlled)
from redharness.sandbox.runner import _ack, _done_valid, _fatal_valid, sandbox_dir
from redharness.scope.manifest import ScopeManifest

from ._fake_sandbox import FakeSandbox

FAST = dict(poll_interval_s=0.01, proc_check_interval_s=0.05)
TARGET = b"MZ-fake-target-bytes"
SHA = hashlib.sha256(TARGET).hexdigest()
LEVEL = "windows-sandbox+separate-user+low-il"


@pytest.fixture(autouse=True)
def _short_overheads(monkeypatch):
    from redharness.sandbox import runner
    monkeypatch.setattr(runner, "PER_CASE_OVERHEAD_S", 0.0)
    monkeypatch.setattr(runner, "FINISH_SLACK_S", 0.0)


@pytest.fixture
def cfg(tmp_path):
    return Config.load(tmp_path / "data")


@pytest.fixture
def target(tmp_path):
    p = tmp_path / "sample.exe"
    p.write_bytes(TARGET)
    return p


def run(cfg, target, fake, inputs=None, timeout_s=0.5, **kw):
    sc = ScopeManifest(SHA, "test", "owner", "test", ("static", "run_controlled"), None, "")
    return run_controlled(SHA, sc, inputs if inputs is not None else [RunCase(stdin="a\n")], timeout_s, cfg=cfg,
                          backend=fake, target_path=target, **{**FAST, "boot_allowance_s": 1.0, **kw})


def assert_integrity_failure(cfg, r, *needles, prior_blobs=frozenset()):
    """On mismatch: result never OK, explicit INTEGRITY, no cases/content, no raw output written to CAS, no evidence produced."""
    assert r.code == Code.INTEGRITY and r.status is Status.ERROR and not r.ok
    assert r.cases == [] and r.integrity_verified is False and r.integrity_problems
    assert r.detail.startswith("INTEGRITY:")
    for n in needles:
        assert n in r.detail, (n, r.detail)
    assert r.sandbox_closed is True
    assert {p for p in cfg.cas_dir.rglob("*") if p.is_file()} <= set(prior_blobs), "untrusted output was written to CAS"
    cas = Cas(cfg.cas_dir)
    assert build_run_evidence_all(cas, r) == []
    with pytest.raises(ValueError, match="INTEGRITY"):
        build_run_evidence(cas, r, CaseResult(0, (), None, "", Status.OK, stdout=b"x"))
    types = []
    with Journal(sandbox_dir(cfg) / "journal.jsonl") as j:
        for e in j.events():
            types.append((e["type"], e["payload"]))
    fin = [p for t, p in types if t == "SANDBOX_FINISHED"][-1]
    assert fin["code"] == Code.INTEGRITY and fin["integrity_verified"] is False and fin["integrity_problems"]


# ------------------------------------------------------------------ happy path + nonce handshake

def test_ok_run_is_verified_and_records_isolation_level(cfg, target):
    fake = FakeSandbox()
    r = run(cfg, target, fake, inputs=[RunCase(stdin="a\n"), RunCase(stdin="b\n")])
    assert r.status is Status.OK and r.code is None and r.integrity_verified is True
    assert r.isolation_level == LEVEL and all(c.isolation_level == LEVEL and c.integrity_verified for c in r.cases)
    cas = Cas(cfg.cas_dir)
    for ev in build_run_evidence_all(cas, r):
        assert f"isolation level: {LEVEL}" in ev["limitations"]
        assert any("one-time host nonce" in x for x in ev["limitations"])
        assert ev["capture"]["status"] == "OK"
    assert r.summary()["isolation_level"] == LEVEL and r.summary()["integrity_verified"] is True


def test_nonce_is_secret_one_time_and_removed_before_target_runs(cfg, target):
    fake1, fake2 = FakeSandbox(), FakeSandbox()
    r1 = run(cfg, target, fake1, inputs=[RunCase(stdin="a\n"), RunCase(stdin="b\n")])
    r2 = run(cfg, target, fake2)
    n1, n2 = fake1.seen_nonce, fake2.seen_nonce
    assert re.fullmatch(r"[0-9a-f]{64}", n1) and re.fullmatch(r"[0-9a-f]{64}", n2) and n1 != n2  # one-time
    assert fake1.nonce_present_at_target == [False, False]  # nonce.txt is ABSENT while the target runs (the host deleted it)
    # the nonce is never written in clear text anywhere: cases.json, journal, evidence, CAS
    assert n1 not in json.dumps(fake1.seen_specs)
    with Journal(sandbox_dir(cfg) / "journal.jsonl") as j:
        assert n1 not in json.dumps(list(j.events())) and n2 not in json.dumps(list(j.events()))
    cas = Cas(cfg.cas_dir)
    for ev in build_run_evidence_all(cas, r1):
        assert n1 not in json.dumps(ev) and n1.encode() not in cas.get(ev["raw"]["blob_sha256"])
    assert r1.ok and r2.ok


def test_replaying_previous_run_records_fails(cfg, target):
    """Valid records of an old session (different nonce, different run_id) cannot be carried into a new session."""
    old = {}

    def grab(out):
        old.update({p.name: p.read_bytes() for p in out.iterdir() if p.name.startswith("c000")})

    r1 = run(cfg, target, FakeSandbox(post_start=grab))
    assert r1.ok and old

    def replay(out):
        for name, data in old.items():
            (out / name).write_bytes(data)

    prior = {p for p in cfg.cas_dir.rglob("*") if p.is_file()}
    r2 = run(cfg, target, FakeSandbox(post_start=replay))
    assert_integrity_failure(cfg, r2, prior_blobs=prior)


# ------------------------------------------------------------------ mismatches

def test_nonce_mismatch_is_integrity_error(cfg, target):
    r = run(cfg, target, FakeSandbox(integrity="wrong_nonce"))  # records signed with a different key
    assert_integrity_failure(cfg, r, "MAC mismatch")


def test_nonce_commit_mismatch_is_integrity_error():
    meta = {"index": 0, "exit_code": 0, "timed_out": False, "truncated": False, "launch_error": None,
            "elapsed_ms": 1, "stdout_total": 1, "stderr_total": 0}
    other = itg.new_nonce()
    meta["integrity"] = itg.sign_case(other, "r1", 0, b"x", b"", meta)  # the commit is also from the other nonce
    with pytest.raises(itg.IntegrityError, match="nonce mismatch"):
        itg.verify_case(meta, b"x", b"", itg.new_nonce(), "r1", 0)


@pytest.mark.parametrize("which", ["stdout", "stderr"])
def test_stream_hash_mismatch_is_integrity_error(cfg, target, which):
    def tamper(out):
        (out / f"c000.{which}").write_bytes(b"FORGED RESULT")
    r = run(cfg, target, FakeSandbox(post_start=tamper))
    assert_integrity_failure(cfg, r, f"{which} SHA-256 mismatch")


def test_exit_code_mismatch_is_integrity_error(cfg, target):
    def tamper(out):
        meta = json.loads((out / "c000.json").read_text())
        meta["exit_code"] = 0 if meta["exit_code"] else 1  # the exit code in the file differs from the one in the record
        (out / "c000.json").write_text(json.dumps(meta))
    r = run(cfg, target, FakeSandbox(behavior=lambda *a: {"stdout": b"o", "exit_code": 1}, post_start=tamper))
    assert_integrity_failure(cfg, r, "exit code mismatch")


def test_flag_tampering_under_valid_record_is_integrity_error(cfg, target):
    def tamper(out):  # the record stays the same, but a file field (the timeout flag) is altered
        meta = json.loads((out / "c000.json").read_text())
        meta["timed_out"] = True
        (out / "c000.json").write_text(json.dumps(meta))
    r = run(cfg, target, FakeSandbox(post_start=tamper))
    assert_integrity_failure(cfg, r, "MAC mismatch")


def test_missing_integrity_record_is_integrity_error(cfg, target):
    r = run(cfg, target, FakeSandbox(integrity="no_record"))
    assert_integrity_failure(cfg, r, "integrity record missing")


def test_missing_session_record_is_integrity_error(cfg, target):
    r = run(cfg, target, FakeSandbox(integrity="no_session_record"))
    assert_integrity_failure(cfg, r, "session.json: integrity record missing")


def test_bad_mac_is_integrity_error(cfg, target):
    r = run(cfg, target, FakeSandbox(integrity="bad_mac"))
    assert_integrity_failure(cfg, r, "MAC mismatch")


def test_case_record_from_other_case_is_integrity_error(cfg, target):
    def swap(out):  # c001's (valid) record is moved to c000
        (out / "c000.json").write_bytes((out / "c001.json").read_bytes())
    r = run(cfg, target, FakeSandbox(post_start=swap), inputs=[RunCase(stdin="a\n"), RunCase(stdin="b\n")])
    assert_integrity_failure(cfg, r, "index mismatch")


def test_deleted_case_file_is_integrity_error(cfg, target):
    def rm(out):
        (out / "c001.stdout").unlink()
    r = run(cfg, target, FakeSandbox(post_start=rm), inputs=[RunCase(stdin="a\n"), RunCase(stdin="b\n")])
    assert_integrity_failure(cfg, r, "output files missing")


def test_one_bad_case_poisons_whole_session(cfg, target):
    def tamper(out):
        (out / "c001.stdout").write_bytes(b"x")
    r = run(cfg, target, FakeSandbox(post_start=tamper), inputs=[RunCase(stdin="a\n"), RunCase(stdin="b\n")])
    assert_integrity_failure(cfg, r, "c001")  # even if c000 is intact the session is untrusted


# ------------------------------------------------------------------ the target's fake-result attempts

def _forge_all(out, idx=None):
    meta = {"index": 0, "exit_code": 0, "timed_out": False, "truncated": False, "launch_error": None,
            "elapsed_ms": 1, "stdout_total": 6, "stderr_total": 0}
    (out / "c000.stdout").write_bytes(b"FORGED")
    (out / "c000.stderr").write_bytes(b"")
    forged_rec = {"version": 1, "case_id": "x:0", "stdout_sha256": hashlib.sha256(b"FORGED").hexdigest(),
                  "stderr_sha256": hashlib.sha256(b"").hexdigest(), "exit_code": 0, "nonce_commit": "0" * 64,
                  "target_integrity": "low", "separate_user": True, "mac": "0" * 64}
    (out / "c000.json").write_text(json.dumps({**meta, "integrity": forged_rec}))
    (out / "session.json").write_text(json.dumps({"run_id": "x", "target_sha256": SHA}))
    (out / "done.json").write_text(json.dumps({"run_id": "x", "cases": 1, "mac": "0" * 64}))
    (out / "fatal.json").write_text(json.dumps({"error": "fake"}))


def test_forged_files_overwritten_by_runner_do_not_change_result(cfg, target, monkeypatch):
    """The target writes a fake result while running; the runner writes its own files afterwards (overwrites): the real result stays OK.

    Determinism: the moment the host verifies the GENUINE session.json that the runner wrote before the target started is observed
    (event); the fake write happens only after that. Otherwise, if the host's poll saw the fake session.json in between (race), the
    session would rightly close with INTEGRITY: that branch is tested separately and deterministically in the test below."""
    import threading
    validated = threading.Event()
    real_verify = itg.verify_session

    def spy(*a, **kw):
        r = real_verify(*a, **kw)
        validated.set()
        return r
    monkeypatch.setattr(itg, "verify_session", spy)

    def forge_after_host_validated(out, idx):
        assert validated.wait(10), "host did not verify the genuine session.json"
        _forge_all(out, idx)

    fake = FakeSandbox(behavior=lambda *a: {"stdout": b"GENUINE", "exit_code": 0}, target_writes=forge_after_host_validated)
    r = run(cfg, target, fake)
    assert r.status is Status.OK and r.cases[0].stdout == b"GENUINE" and r.integrity_verified is True


def test_forged_session_seen_by_host_fails_closed_before_runner_overwrites(cfg, target):
    """If the host sees the target's fake session.json before the runner's seal (overwrite) arrives, the session closes at once and
    deterministically with INTEGRITY; a fake record is never accepted under any condition."""
    fake = None

    def forge_session_and_hold(out, idx):
        (out / "session.json").write_text(json.dumps({"run_id": "x", "target_sha256": SHA}))
        fake._stop.wait(10)  # the runner cannot place the seal until the host sees the fake and closes the sandbox (kill_all)

    fake = FakeSandbox(behavior=lambda *a: {"stdout": b"GENUINE", "exit_code": 0}, target_writes=forge_session_and_hold)
    r = run(cfg, target, fake)
    assert_integrity_failure(cfg, r, "session.json: integrity record missing")


def test_forged_files_that_survive_are_integrity_error(cfg, target):
    """The runner could not write its own files (the target held them): the target's fake files remain -> the fake record is rejected."""
    fake = FakeSandbox(integrity="skip_case_write", target_writes=_forge_all)
    r = run(cfg, target, fake)
    assert_integrity_failure(cfg, r)
    assert "FORGED" not in json.dumps(r.summary())


def test_forged_record_with_correct_hashes_but_no_nonce_is_rejected():
    """The target can write hashes consistent with the file contents but cannot produce the MAC since it does not know the nonce."""
    nonce = itg.new_nonce()
    meta = {"index": 0, "exit_code": 0, "timed_out": False, "truncated": False, "launch_error": None,
            "elapsed_ms": 1, "stdout_total": 6, "stderr_total": 0}
    meta["integrity"] = itg.sign_case(itg.new_nonce(), "r1", 0, b"FORGED", b"", meta, commit=itg.nonce_commit(nonce))
    with pytest.raises(itg.IntegrityError, match="MAC mismatch"):
        itg.verify_case(meta, b"FORGED", b"", nonce, "r1", 0)


def test_trust_root_is_nonce_secrecy_documented_limit():
    """Documented limit: if the nonce LEAKS to the target a fake record becomes valid. The trust root is secrecy; hence the target is
    a separate user from the runner and the nonce is not on disk while it runs (checked in the heavy test)."""
    nonce = itg.new_nonce()
    meta = {"index": 0, "exit_code": 0, "timed_out": False, "truncated": False, "launch_error": None,
            "elapsed_ms": 1, "stdout_total": 6, "stderr_total": 0}
    meta["integrity"] = itg.sign_case(nonce, "r1", 0, b"FORGED", b"", meta)
    assert itg.verify_case(meta, b"FORGED", b"", nonce, "r1", 0).mac


def test_forged_done_and_fatal_do_not_finish_session(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    nonce = itg.new_nonce()
    (out / "done.json").write_text(json.dumps({"run_id": "r1", "cases": 1, "mac": "0" * 64}))
    meta = {"index": 0, "integrity": itg.sign_case(nonce, "r1", 0, b"", b"", {"exit_code": 0})}
    (out / "c000.json").write_text(json.dumps(meta))
    assert _done_valid(out, nonce, "r1", 1) is False  # fake done: the session is not counted as finished
    (out / "done.json").write_text(json.dumps({"run_id": "r1", "cases": 1,
                                               "mac": itg.sign_done(nonce, "r1", [meta["integrity"]["mac"]])}))
    assert _done_valid(out, nonce, "r1", 1) is True
    (out / "fatal.json").write_text(json.dumps({"error": "fake"}))
    assert _fatal_valid(out, nonce, acked=True) is False   # after the nonce is read, a MAC-less fatal is ignored
    assert _fatal_valid(out, nonce, acked=False) is True   # a fatal before the target runs is trusted
    (out / "fatal.json").write_text(json.dumps({"error": "x", "mac": itg.sign_fatal(nonce, "x")}))
    assert _fatal_valid(out, nonce, acked=True) is True


def test_ack_rejects_wrong_commit_and_deletes_nonce_only_after_valid_ack(tmp_path):
    in_dir, out_dir = tmp_path / "in", tmp_path / "out"
    in_dir.mkdir()
    out_dir.mkdir()
    nonce = itg.new_nonce()
    (in_dir / itg.NONCE_FILE).write_text(nonce)
    (out_dir / "ready.json").write_text(json.dumps({"run_id": "r1", "nonce_commit": itg.nonce_commit(itg.new_nonce())}))
    assert "nonce mismatch" in _ack(in_dir, out_dir, nonce, "r1")
    assert (in_dir / itg.NONCE_FILE).exists()  # not deleted on an invalid acknowledgement
    (out_dir / "ready.json").write_text(json.dumps({"run_id": "r1", "nonce_commit": itg.nonce_commit(nonce)}))
    assert _ack(in_dir, out_dir, nonce, "r1") is None
    assert not (in_dir / itg.NONCE_FILE).exists()


def test_guest_that_never_acks_never_starts_target(cfg, target):
    """If the guest does not do the nonce handshake (no ready.json) the target does not run and the session becomes RESOURCE_UNAVAILABLE."""
    class NoAck(FakeSandbox):
        def _save(self, out, name, data):
            if name != "ready.json":
                super()._save(out, name, data)
    fake = NoAck()
    r = run(cfg, target, fake, timeout_s=0.3, boot_allowance_s=0.3)
    assert r.code == Code.RESOURCE_UNAVAILABLE and not r.ok  # the ready marker never arrived: counted as a resource problem
    assert fake.nonce_present_at_target == []


# ------------------------------------------------------------------ format (must match guest.ps1)

def test_canonical_formats_and_hmac_vectors_are_pinned():
    """Canonical strings and HMAC values are pinned; if guest.ps1 changes the heavy test catches it."""
    nonce = "ab" * 32
    assert itg.nonce_commit(nonce) == hashlib.sha256(b"rh-nonce-commit/1:" + nonce.encode()).hexdigest()
    assert itg.session_canon("r1", "c" * 64, True, True) == "rh-integrity/1|session|r1|" + "c" * 64 + "|1|1"
    assert itg.case_canon("r1", 2, "a" * 64, "b" * 64, None, True, False, 10, 0, None, 5, "low", True) == (
        "rh-integrity/1|case|r1|2|" + "a" * 64 + "|" + "b" * 64 + "|-|1|0|10|0|-|5|low|1")
    assert itg.case_canon("r1", 0, "a" * 64, "b" * 64, -5, False, True, 1, 2, "x", 7, "medium", False).split("|")[6] == "-5"
    assert itg.done_canon("r1", 2, ["m1", "m2"]) == (
        "rh-integrity/1|done|r1|2|" + hashlib.sha256(b"m1,m2").hexdigest())


def test_isolation_level_from_verified_facts():
    f = itg.CaseFacts
    assert itg.isolation_level([]) == "windows-sandbox"
    assert itg.isolation_level([f("low", True, "m")]) == "windows-sandbox+separate-user+low-il"
    assert itg.isolation_level([f("low", True, "m"), f("medium", True, "m")]) == "windows-sandbox+separate-user"
    assert itg.isolation_level([f("low", False, "m")]) == "windows-sandbox+low-il"
    assert itg.isolation_level([f("unknown", False, "m")]) == "windows-sandbox"
