"""run_controlled unit tests: fake sandbox (no real sandbox/target is run)."""
import hashlib
import json
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from redharness.config import Config
from redharness.core.cas import Cas
from redharness.core.journal import Journal
from redharness.core.lock import JobLock
from redharness.core.result import Status
from redharness.evidence.model import evidence_id_ok
from redharness.sandbox import (Code, RunCase, build_run_evidence, build_run_evidence_all, recover_interrupted,
                                run_controlled, run_status)
from redharness.sandbox.backend import parse_tasklist, render_wsb
from redharness.sandbox.runner import sandbox_dir, workdir_root
from redharness.scope.manifest import ScopeManifest

from ._fake_sandbox import FakeSandbox

FAST = dict(poll_interval_s=0.01, proc_check_interval_s=0.05)
TARGET = b"MZ-fake-target-bytes"
SHA = hashlib.sha256(TARGET).hexdigest()


def scope(ops=("static", "run_controlled"), sha=SHA, expires=None):
    return ScopeManifest(sha, "test", "owner", "test", tuple(ops), expires, "")


@pytest.fixture
def cfg(tmp_path):
    return Config.load(tmp_path / "data")


@pytest.fixture
def target(tmp_path):
    p = tmp_path / "sample.exe"
    p.write_bytes(TARGET)
    return p


_DEFAULT = object()


def run(cfg, target, fake, inputs=None, timeout_s=5, sc=_DEFAULT, **kw):
    kw = {**FAST, **kw}
    return run_controlled(SHA, scope() if sc is _DEFAULT else sc, inputs if inputs is not None else [RunCase(stdin="a\n")], timeout_s,
                          cfg=cfg, backend=fake, target_path=target, **kw)


def journal_types(cfg):
    with Journal(sandbox_dir(cfg) / "journal.jsonl") as j:
        return [(e["type"], e["payload"]) for e in j.events()]


def no_workdirs(cfg):
    root = workdir_root(cfg)
    return not root.exists() or not any(root.iterdir())


# ------------------------------------------------------------------ rejections

def test_scope_without_run_permission_is_denied(cfg, target):
    fake = FakeSandbox()
    r = run(cfg, target, fake, sc=scope(ops=("static",)))
    assert r.status is Status.ERROR and r.code == Code.SCOPE_DENIED and r.cases == []
    assert fake.started == [] and fake.kill_calls == 0
    assert not (sandbox_dir(cfg) / "journal.jsonl").exists()  # no trace: the sandbox never started


@pytest.mark.parametrize("bad", ["none", "other_sha", "expired", "not_manifest"])
def test_scope_other_denials(cfg, target, bad):
    sc = {"none": None, "other_sha": scope(sha="b" * 64), "expired": scope(expires="2020-01-01"),
          "not_manifest": {"allowed_operations": ["run_controlled"]}}[bad]
    fake = FakeSandbox()
    r = run(cfg, target, fake, sc=sc)
    assert r.code == Code.SCOPE_DENIED and r.status is Status.ERROR and fake.started == []


def test_sha_mismatch_is_rejected(cfg, tmp_path):
    other = tmp_path / "other.exe"
    other.write_bytes(b"MZ-changed")
    fake = FakeSandbox()
    r = run(cfg, other, fake)
    assert r.code == Code.SHA_MISMATCH and r.status is Status.ERROR and fake.started == []
    assert no_workdirs(cfg)


def test_target_missing_and_cas_lookup(cfg, tmp_path):
    fake = FakeSandbox()
    r = run_controlled(SHA, scope(), [RunCase(stdin="x")], 5, cfg=cfg, backend=fake, **FAST)
    assert r.code == Code.TARGET_MISSING
    Cas(cfg.cas_dir).put(TARGET)  # the CAS copy that target_open wrote
    r = run_controlled(SHA, scope(), [RunCase(stdin="x")], 5, cfg=cfg, backend=fake, **FAST)
    assert r.status is Status.OK and fake.seen_specs[0]["exe"] == "target.exe"


@pytest.mark.parametrize("inputs,timeout", [([], 5), ("x", 5), ([RunCase()], 0), ([RunCase()], -1),
                                            ([RunCase()], 10_000), ([RunCase()], True), (["str"], 5),
                                            ([RunCase(argv=("a\0b",))], 5), ([RunCase()] * 33, 5)])
def test_invalid_inputs(cfg, target, inputs, timeout):
    fake = FakeSandbox()
    r = run(cfg, target, fake, inputs=inputs, timeout_s=timeout)
    assert r.code == Code.INVALID_INPUT and fake.started == []


def test_sandbox_unavailable_is_tool_missing(cfg, target):
    r = run(cfg, target, FakeSandbox(available=False))
    assert r.status is Status.TOOL_MISSING and r.code == Code.SANDBOX_UNAVAILABLE


# ------------------------------------------------------------------ BUSY

def test_busy_when_lock_held_returns_immediately(cfg, target):
    fake = FakeSandbox()
    with JobLock(sandbox_dir(cfg) / "sandbox.lock"):
        t = time.monotonic()
        r = run(cfg, target, fake)
        assert time.monotonic() - t < 2
    assert r.status is Status.ERROR and r.code == Code.BUSY
    assert fake.started == [] and fake.kill_calls == 0
    assert not r.ok


def test_busy_when_foreign_sandbox_running_and_it_is_not_killed(cfg, target):
    fake = FakeSandbox(preexisting=[4242])
    r = run(cfg, target, fake)
    assert r.code == Code.BUSY and fake.started == [] and fake.kill_calls == 0
    assert fake.pids == [4242]  # someone else's sandbox was not closed


def test_busy_from_another_process(cfg, target):
    code = textwrap.dedent(f"""
        import sys, time
        from redharness.core.lock import JobLock
        l = JobLock(sys.argv[1]); l.acquire(); print("held", flush=True); time.sleep(30)
    """)
    lockp = sandbox_dir(cfg) / "sandbox.lock"
    p = subprocess.Popen([sys.executable, "-I", "-c", code, str(lockp)], stdout=subprocess.PIPE)
    try:
        assert p.stdout.readline().strip() == b"held"
        fake = FakeSandbox()
        r = run(cfg, target, fake)
        assert r.code == Code.BUSY and fake.started == []
    finally:
        p.kill()
        p.wait()


# ------------------------------------------------------------------ success path

def test_ok_two_cases_in_one_session(cfg, target):
    def beh(idx, c, stdin):
        return {"stdout": b"License valid\r\n" if b"good" in stdin else b"License invalid\r\n",
                "stderr": b"", "exit_code": 0 if b"good" in stdin else 1, "elapsed_ms": 30}
    fake = FakeSandbox(behavior=beh)
    cases = [RunCase(stdin="good\n"), RunCase(stdin="bad\n", argv=("--k", "a b"))]
    r = run(cfg, target, fake, inputs=cases)
    assert r.status is Status.OK and r.code is None and r.ok
    assert len(fake.started) == 1 and len(r.cases) == 2  # single session
    a, b = r.cases
    assert a.status is Status.OK and a.exit_code == 0 and a.stdout == b"License valid\r\n"
    assert b.status is Status.OK and b.exit_code == 1 and b.stdout == b"License invalid\r\n"  # exit 1 is not an error
    assert a.isolation == b.isolation == "windows-sandbox" and not a.truncated
    assert fake.seen_specs[0]["cases"][1]["argv_line"] == '--k "a b"'
    cas = Cas(cfg.cas_dir)
    assert cas.get(a.stdout_blob) == a.stdout and cas.get(b.stdout_blob) == b.stdout  # raw output is in CAS
    assert r.sandbox_closed is True and r.workdir_removed is True and no_workdirs(cfg)
    assert fake.pids == [] and fake.kill_calls >= 1
    types = [t for t, _ in journal_types(cfg)]
    assert [t for t in types if t != "SANDBOX_PROCS"] == ["SANDBOX_STARTED", "SANDBOX_FINISHED"]
    assert run_status(cfg, r.run_id) == "FINISHED"
    assert not (sandbox_dir(cfg) / "sandbox.lock").exists()  # lock released


def test_wsb_isolation_flags(cfg, target):
    fake = FakeSandbox()
    run(cfg, target, fake)
    wsb = fake.seen_wsb[0]
    assert "<Networking>Disable</Networking>" in wsb
    assert wsb.count("<ReadOnly>true</ReadOnly>") == 1 and wsb.count("<ReadOnly>false</ReadOnly>") == 1
    assert wsb.index("C:\\in</SandboxFolder><ReadOnly>true") > 0 and wsb.index("C:\\out</SandboxFolder><ReadOnly>false") > 0
    assert str(workdir_root(cfg)) in wsb  # the work folder is under RH_DATA_ROOT (data_root)


def test_render_wsb_escapes_paths(tmp_path):
    wsb = render_wsb(tmp_path / "a&b", tmp_path / "c<d")
    assert "a&amp;b" in wsb and "c&lt;d" in wsb


def test_parse_tasklist():
    csv_text = ('"System","4","Services","0","10 K"\r\n"WindowsSandbox.exe","2780","Console","1","5 K"\r\n'
                '"WindowsSandboxClient.exe","18820","Console","1","5 K"\r\n"vmmem","5508","Services","0","1 K"\r\n'
                '"python.exe","99","Console","1","1 K"\r\n')
    assert parse_tasklist(csv_text) == [2780, 18820]


# ------------------------------------------------------------------ timeout / crash / truncation

def test_session_timeout_kills_and_is_never_ok(cfg, target):
    fake = FakeSandbox(mode="hang")
    r = run(cfg, target, fake, timeout_s=0.3, boot_allowance_s=0.2)
    assert r.status is Status.TIMEOUT and r.code == Code.SESSION_TIMEOUT and not r.ok
    assert fake.pids == [] and fake.kill_calls >= 1 and r.sandbox_closed is True
    assert all(c.status in (Status.TIMEOUT, Status.ERROR) and not c.ok for c in r.cases)
    assert no_workdirs(cfg) and run_status(cfg, r.run_id) == "FINISHED"


@pytest.fixture(autouse=True)
def _short_overheads(monkeypatch):
    from redharness.sandbox import runner
    monkeypatch.setattr(runner, "PER_CASE_OVERHEAD_S", 0.0)
    monkeypatch.setattr(runner, "FINISH_SLACK_S", 0.0)


def test_per_case_timeout_is_not_ok(cfg, target):
    def beh(idx, c, stdin):
        if idx == 1:
            return {"stdout": b"", "exit_code": None, "timed_out": True}
        return {"stdout": b"ok", "exit_code": 0}
    r = run(cfg, target, FakeSandbox(behavior=beh), inputs=[RunCase(), RunCase(), RunCase()])
    assert [c.status for c in r.cases] == [Status.OK, Status.TIMEOUT, Status.OK]
    assert r.status is Status.TIMEOUT and not r.ok and r.code is None
    assert r.cases[1].exit_code is None and r.cases[1].timed_out


def test_truncated_output_is_partial(cfg, target):
    def beh(idx, c, stdin):
        return {"stdout": b"x" * 100, "exit_code": 0, "truncated": True, "stdout_total": 5000}
    r = run(cfg, target, FakeSandbox(behavior=beh), max_stream_bytes=100)
    c = r.cases[0]
    assert c.status is Status.PARTIAL and c.truncated and c.stdout_total == 5000 and len(c.stdout) == 100
    assert r.status is Status.PARTIAL and not r.ok


def test_host_never_accepts_file_larger_than_guest_record(cfg, target):
    # the guest says "not truncated" but the file is over the limit / does not match the record: the host hashes its own bytes -> INTEGRITY
    class Fat(FakeSandbox):
        def _save(self, out, name, data):
            super()._save(out, name, data + b"y" * 50 if name.endswith(".stdout") else data)
    r = run(cfg, target, Fat(behavior=lambda *a: {"stdout": b"x" * 100, "exit_code": 0}), max_stream_bytes=100)
    assert r.code == Code.INTEGRITY and r.status is Status.ERROR and r.cases == [] and not r.ok


def test_sandbox_crash_midway(cfg, target):
    fake = FakeSandbox(mode="crash", crash_after=1)
    r = run(cfg, target, fake, inputs=[RunCase(stdin="a"), RunCase(stdin="b")])
    assert r.status is Status.ERROR and r.code == Code.SANDBOX_CRASHED and not r.ok
    assert r.cases[0].status is Status.PARTIAL  # even the finished case is at most PARTIAL since the session was not clean
    assert r.cases[1].status is Status.ERROR
    assert fake.pids == [] and no_workdirs(cfg)


def test_failed_start_leaves_no_lingering_sandbox_process(cfg, target):
    class DiesOnStart(FakeSandbox):
        def start(self, wsb_path):
            with self._mu:
                self.pids = [777]  # launcher/error-dialog process stays alive; guest never writes ready.json
            raise OSError("start failed")
    fake = DiesOnStart()
    r = run(cfg, target, fake)
    assert r.code == Code.RESOURCE_UNAVAILABLE and r.status is Status.ERROR and not r.ok
    assert fake.pids == [] and fake.kill_calls >= 1 and r.sandbox_closed is True


def test_guest_fatal_error(cfg, target):
    r = run(cfg, target, FakeSandbox(mode="fatal"))
    assert r.code == Code.SANDBOX_CRASHED and "boom" in r.detail and r.status is Status.ERROR


def test_untrusted_session_rejects_all_cases(cfg, target):
    r = run(cfg, target, FakeSandbox(mode="bad_hash"))
    assert r.code == Code.GUEST_HASH_MISMATCH and r.status is Status.ERROR
    assert all(c.status is Status.ERROR for c in r.cases)


def test_done_with_wrong_run_id_is_never_accepted(cfg, target):
    # done.json has the wrong run_id (the MAC does not fit it): not counted as completion, the session times out, the result is never OK
    r = run(cfg, target, FakeSandbox(mode="bad_done"), timeout_s=0.3, boot_allowance_s=0.3)
    assert r.code == Code.INTEGRITY and r.status is Status.ERROR and not r.ok and r.cases == []


def test_symlink_or_junction_output_is_refused_and_target_untouched(cfg, target, tmp_path):
    secret = tmp_path / "secret_dir"
    secret.mkdir()
    (secret / "file.txt").write_text("host data")

    def tamper(out):
        os.remove(out / "c000.stdout")
        subprocess.run(["cmd", "/c", "mklink", "/J", str(out / "c000.stdout"), str(secret)], check=True,
                       capture_output=True)
    r = run(cfg, target, FakeSandbox(post_start=tamper))
    assert r.code == Code.INTEGRITY and "not a plain file" in r.detail and r.cases == []
    assert not r.ok
    assert (secret / "file.txt").read_text() == "host data"  # cleanup did not enter the junction's target
    assert no_workdirs(cfg)


def test_sandbox_not_closed_is_explicit_error_and_outputs_unread(cfg, target):
    fake = FakeSandbox(kill_fails=True)
    r = run(cfg, target, fake)
    assert r.status is Status.ERROR and r.code == Code.SANDBOX_NOT_CLOSED and r.sandbox_closed is False
    assert not r.ok and all(c.status is Status.ERROR and c.stdout == b"" for c in r.cases)
    assert no_workdirs(cfg)
    # the session stays open in the journal; the next call closes and cleans it up
    fake.kill_fails = False
    r2 = run(cfg, target, fake)
    assert r2.status is Status.OK and r2.recovered_runs == [r.run_id]
    assert run_status(cfg, r.run_id) == "FAILED"


def test_transient_read_errors_while_guest_replaces_files_are_not_start_failures(cfg, target, monkeypatch):
    """Race regression: if the guest replaces a file via os.replace while the host polls (Windows sharing violation) the read
    raises PermissionError. This is NOT a launch error: polling continues, OK if the session ends cleanly. (It used to return
    START_FAILED + case PARTIAL/ERROR; the tests failed randomly.)"""
    from redharness.sandbox import runner
    real, real_wait = runner._read_plain, runner._wait_done
    left = {"session.json": 3, "done.json": 3, "c000.json": 3, "ready.json": 3}
    polling = []

    def flaky(p, limit):
        if polling and left.get(Path(p).name, 0) > 0:   # only during polling (files are static after shutdown)
            left[Path(p).name] -= 1
            raise PermissionError(13, "Permission denied (fake sharing violation)")
        return real(p, limit)

    def wait(*a, **kw):
        polling.append(1)
        try:
            return real_wait(*a, **kw)
        finally:
            polling.clear()
    monkeypatch.setattr(runner, "_read_plain", flaky)
    monkeypatch.setattr(runner, "_wait_done", wait)
    r = run(cfg, target, FakeSandbox(), timeout_s=5, boot_allowance_s=5.0)
    assert r.status is Status.OK and r.code is None and r.cases[0].status is Status.OK and r.integrity_verified is True
    # the fake error was really triggered (the session.json poll can be skipped once done is valid: so it is not counted)
    assert left["ready.json"] == left["done.json"] == left["c000.json"] == 0, left


def test_not_closed_blocks_new_run_until_closed(cfg, target):
    fake = FakeSandbox(kill_fails=True)
    r = run(cfg, target, fake)
    assert r.code == Code.SANDBOX_NOT_CLOSED
    n = len(fake.started)
    r2 = run(cfg, target, fake)  # still cannot be closed
    assert r2.code == Code.RECOVERY_FAILED and r2.status is Status.ERROR and len(fake.started) == n


# ------------------------------------------------------------------ power loss / half-finished session

def _fake_interrupted(cfg, run_id="sbx_half", owned=()):
    """A session whose host died. `owned`: PIDs the dead host had journaled as ITS sandbox processes (FakeSandbox start time 1000+pid)."""
    wd = workdir_root(cfg) / run_id
    (wd / "out").mkdir(parents=True)
    (wd / "out" / "c000.stdout").write_bytes(b"half output")
    with Journal(sandbox_dir(cfg) / "journal.jsonl") as j:
        j.append("SANDBOX_STARTED", {"run_id": run_id, "target_sha256": SHA, "cases": 1})
        if owned:
            j.append("SANDBOX_PROCS", {"run_id": run_id, "procs": [{"pid": p, "start": 1000 + p} for p in owned]})
    return run_id, wd


def test_interrupted_session_is_cleaned_and_marked_failed(cfg, target):
    rid, wd = _fake_interrupted(cfg, owned=[7, 8])
    fake = FakeSandbox(preexisting=[7, 8])  # orphaned sandbox processes (journaled as ours)
    assert run_status(cfg, rid) == "STARTED"
    r = run(cfg, target, fake)
    assert r.status is Status.OK and r.recovered_runs == [rid]
    assert fake.owned_kill_calls >= 1 and not wd.exists()
    ev = [(t, p) for t, p in journal_types(cfg) if t == "SANDBOX_RUN_FAILED"]
    assert ev and ev[0][1]["run_id"] == rid and ev[0][1]["reason"] == Code.INTERRUPTED and ev[0][1]["killed_pids"] == [7, 8]
    assert run_status(cfg, rid) == "FAILED"
    assert journal_types(cfg)[0][0] == "SANDBOX_STARTED"  # the chain continues, no silent deletion


def test_recover_interrupted_standalone_and_idempotent(cfg):
    rid, wd = _fake_interrupted(cfg, owned=[9])
    fake = FakeSandbox(preexisting=[9])
    r = recover_interrupted(cfg, fake)
    assert r.recovered_runs == [rid] and not wd.exists() and fake.pids == []
    assert recover_interrupted(cfg, fake).recovered_runs == []  # second time: nothing to do
    assert run_status(cfg, rid) == "FAILED"


def test_recovery_failure_refuses_to_run(cfg, target):
    rid, wd = _fake_interrupted(cfg, owned=[9])
    fake = FakeSandbox(preexisting=[9], kill_fails=True)
    r = run(cfg, target, fake)
    assert r.code == Code.RECOVERY_FAILED and r.status is Status.ERROR and fake.started == []
    assert run_status(cfg, rid) == "STARTED"  # FAILED is not written before closure


def test_host_process_killed_mid_run_is_recovered(cfg, target, tmp_path):
    """Real process death: run_controlled is killed midway (the process-level equivalent of a power loss)."""
    script = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {str(Path(__file__).parent.parent.parent)!r})
        from pathlib import Path
        from redharness.config import Config
        from redharness.sandbox import RunCase, run_controlled
        from redharness.scope.manifest import ScopeManifest
        from tests.unit._fake_sandbox import FakeSandbox
        sc = ScopeManifest({SHA!r}, "t", "owner", "t", ("run_controlled",), None, "")
        run_controlled({SHA!r}, sc, [RunCase(stdin="a")], 5, cfg=Config.load({str(cfg.data_root)!r}),
                       backend=FakeSandbox(mode="hang"), target_path={str(target)!r}, boot_allowance_s=60)
    """)
    p = subprocess.Popen([sys.executable, "-c", script], stderr=subprocess.PIPE)
    try:
        jp = sandbox_dir(cfg) / "journal.jsonl"
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not (jp.exists() and b"SANDBOX_STARTED" in jp.read_bytes()):
            assert p.poll() is None, p.stderr.read().decode()
            time.sleep(0.05)
        assert b"SANDBOX_STARTED" in jp.read_bytes()
    finally:
        p.kill()
        p.wait()
    assert (workdir_root(cfg)).exists() and any(workdir_root(cfg).iterdir())  # the kill left a half-finished job
    fake = FakeSandbox(preexisting=[101, 102])  # the sandbox whose owner died is still running (the dead host journaled 101/102)
    r = run(cfg, target, fake)
    assert r.status is Status.OK and len(r.recovered_runs) == 1
    assert fake.owned_kill_calls >= 1
    assert run_status(cfg, r.recovered_runs[0]) == "FAILED"


# ------------------------------------------------------------------ evidence record

def test_evidence_record_for_ok_case(cfg, target):
    def beh(idx, c, stdin):
        return {"stdout": b"License valid\n", "stderr": b"warning", "exit_code": 0, "elapsed_ms": 11 + idx}
    r = run(cfg, target, FakeSandbox(behavior=beh), inputs=[RunCase(stdin="KEY\n", argv=("-v",))])
    cas = Cas(cfg.cas_dir)
    ev = build_run_evidence(cas, r, r.cases[0])
    assert evidence_id_ok(ev) and ev["schema"] == "rh.evidence/1" and ev["untrusted_content"] is True
    assert ev["authority"] == "controlled-replay" and ev["confidence"] == "observed"
    assert ev["environment"]["isolation"] == "windows-sandbox" and ev["environment"]["networking"] == "disabled"
    assert ev["capture"]["status"] == "OK" and ev["capture"]["strength"] == "full"
    assert ev["capture"]["exit_code"] == 0 and ev["capture"]["truncated"] is False and ev["capture"]["timed_out"] is False
    assert ev["subject"]["sha256"] == SHA and ev["operation"] == "run_controlled"
    assert ev["parameters"]["argv"] == ["-v"] and ev["parameters"]["stdin"] == "KEY\n"
    assert ev["parameters"]["stdin_sha256"] == hashlib.sha256(b"KEY\n").hexdigest()
    raw = cas.get(ev["raw"]["blob_sha256"])
    assert raw == b"License valid\n\n--- stderr ---\nwarning" and b"License valid" in raw
    assert ev["result"]["exit_code"] == 0 and ev["result"]["stdout_bytes"] == 14
    assert cas.get(ev["result"]["stdout_blob_sha256"]) == b"License valid\n"
    assert ev["coverage"]["relationship"] == "partial"


def test_evidence_id_is_stable_across_reruns_and_elapsed(cfg, target):
    ids = []
    for ms in (10, 999):
        r = run(cfg, target, FakeSandbox(behavior=lambda *a, ms=ms: {"stdout": b"o", "exit_code": 0, "elapsed_ms": ms}))
        ids.append(build_run_evidence(Cas(cfg.cas_dir), r, r.cases[0])["evidence_id"])
    assert ids[0] == ids[1]


def test_evidence_degraded_states_never_prove(cfg, target):
    cas = Cas(cfg.cas_dir)
    # truncated
    r = run(cfg, target, FakeSandbox(behavior=lambda *a: {"stdout": b"x", "exit_code": 0, "truncated": True}))
    ev = build_run_evidence(cas, r, r.cases[0])
    assert ev["capture"]["truncated"] is True and ev["capture"]["strength"] == "partial"
    # case timeout
    r = run(cfg, target, FakeSandbox(behavior=lambda *a: {"exit_code": None, "timed_out": True}))
    ev = build_run_evidence(cas, r, r.cases[0])
    assert ev["capture"]["status"] == "TIMEOUT" and ev["capture"]["strength"] == "failed" and ev["capture"]["exit_code"] is None
    # crash: the finished case is PARTIAL
    r = run(cfg, target, FakeSandbox(mode="crash"))
    evs = build_run_evidence_all(cas, r)
    assert [e["capture"]["strength"] for e in evs] != ["full"] and all(e["capture"]["strength"] != "full" for e in evs)
    # sandbox did not close
    r = run(cfg, target, FakeSandbox(kill_fails=True))
    assert all(e["capture"]["strength"] == "failed" for e in build_run_evidence_all(cas, r))


def test_evidence_defense_downgrades_ok_case_of_unclean_run(cfg, target):
    r = run(cfg, target, FakeSandbox())
    r.code = Code.SANDBOX_CRASHED  # a faulty caller that bypasses the runner: still cannot be higher than PARTIAL
    ev = build_run_evidence(Cas(cfg.cas_dir), r, r.cases[0])
    assert ev["capture"]["status"] == "PARTIAL" and ev["capture"]["strength"] == "partial"


def test_no_evidence_when_sandbox_never_opened(cfg, target):
    r = run(cfg, target, FakeSandbox(), sc=scope(ops=("static",)))
    assert build_run_evidence_all(Cas(cfg.cas_dir), r) == []
    ok_run = run(cfg, target, FakeSandbox())
    with pytest.raises(ValueError):
        build_run_evidence(Cas(cfg.cas_dir), r, ok_run.cases[0])
    with pytest.raises(ValueError):
        build_run_evidence(Cas(cfg.cas_dir), ok_run, ok_run.cases[0], target_sha256="c" * 64)


# ------------------------------------------------------------------ support_files (VC++ runtime DLLs)

class _ListingSandbox(FakeSandbox):
    """Records the in/bin contents at start() time (the folder the guest will see)."""
    listings: list

    def start(self, wsb_path):
        import re as _re
        text = Path(wsb_path).read_text(encoding="utf-8")
        in_dir = Path(_re.findall(r"<HostFolder>(.*?)</HostFolder>", text)[0])
        self.listings = getattr(self, "listings", [])
        self.listings.append(sorted(p.name for p in (in_dir / "bin").iterdir()))
        super().start(wsb_path)


def test_support_files_are_copied_next_to_target_and_journaled(cfg, target, tmp_path):
    d = tmp_path / "sys"
    d.mkdir()
    (d / "vcruntime140.dll").write_bytes(b"dll-1")
    (d / "msvcp140.dll").write_bytes(b"dll-2")
    fake = _ListingSandbox()
    r = run(cfg, target, fake, support_files=[d / "vcruntime140.dll", d / "msvcp140.dll"])
    assert r.status is Status.OK, r.detail
    assert fake.listings == [["msvcp140.dll", "sample.exe", "vcruntime140.dll"]]
    started = [p for t, p in journal_types(cfg) if t == "SANDBOX_STARTED"][0]
    assert [f["name"] for f in started["support_files"]] == ["vcruntime140.dll", "msvcp140.dll"]
    assert all(len(f["sha256"]) == 64 for f in started["support_files"])


@pytest.mark.parametrize("name", ["evil.exe", "a b.dll", "ok.txt"])
def test_support_files_invalid_names_rejected(cfg, target, tmp_path, name):
    p = tmp_path / name
    p.write_bytes(b"x")
    r = run(cfg, target, FakeSandbox(), support_files=[p])
    assert r.code == Code.INVALID_INPUT


def test_support_files_missing_file_rejected(cfg, target, tmp_path):
    r = run(cfg, target, FakeSandbox(), support_files=[tmp_path / "missing.dll"])
    assert r.code == Code.INVALID_INPUT
