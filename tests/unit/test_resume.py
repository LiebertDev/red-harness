"""Crash / power-loss resume ("kill mid-analysis and resume", "resume after an interruption in the Sandbox").

Fake engine and fake Windows Sandbox; the process-death cases use a real child process that is killed hard
(TerminateProcess, no cleanup code runs: the same thing a power loss does to the process state).
The real-process kill of the MCP server and of a real Windows Sandbox host is covered by real-process tests.
"""
import json
import os
import socket
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from redharness.config import Config
from redharness.core.journal import Journal, verify_file
from redharness.core.lock import JobLock, LockInfo
from redharness.mcp.server import MAX_TOOLS, TOOL_NAMES
from redharness.mcp.session import Hub, ToolFailure, open_interrupted, orphan_calls
from redharness.sandbox import run_status
from redharness.sandbox.runner import pending_recovery, sandbox_dir, workdir_root

from ._fake_engine import BASE, FakeEngine
from ._fake_sandbox import FakeSandbox
from .mcp_helpers import make_manifest
from .test_run_controlled_mcp import fake_system_root, oracle

VA = hex(BASE + 0x1250)


@pytest.fixture(autouse=True)
def _short_sandbox_waits(monkeypatch):
    from redharness.sandbox import runner
    for name, v in (("BOOT_ALLOWANCE_S", 1.0), ("PER_CASE_OVERHEAD_S", 0.0), ("FINISH_SLACK_S", 0.0),
                    ("RETRY_BACKOFF_S", 0.0)):
        monkeypatch.setattr(runner, name, v)


class CrashEngine(FakeEngine):
    """Counts calls; `crash_on_decompile` simulates the process dying inside the engine (BaseException: no TOOL_CALL
    line is written, like a kill)."""

    def __init__(self):
        self.calls: list[str] = []
        self.crash_on_decompile = False

    def functions(self, sha256, *, offset=0, limit=100):
        self.calls.append("functions")
        return super().functions(sha256, offset=offset, limit=limit)

    def decompile(self, sha256, function, *, max_chars=200_000):
        self.calls.append("decompile")
        if self.crash_on_decompile:
            raise KeyboardInterrupt("simulated power loss")
        return super().decompile(sha256, function, max_chars=max_chars)


def setup(tmp_path, ops=("static",)):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"MZ" + bytes(range(256)) * 8)
    manifest = make_manifest(tmp_path / "scope.json", target, allowed_operations=list(ops))
    return str(target), str(manifest), Config.load(tmp_path / "data")


def new_hub(cfg, engine=None, sandbox=None, root=None):
    return Hub(cfg, engine or CrashEngine(), sandbox, system_root=root)


def simulate_death(hub):
    """The process is gone: the journal fd is closed and the lock is left as it is (a dead owner's lock is stale).
    For the in-process variant we release the lock so a new Hub in THIS process can reopen (the stale-lock path has
    its own test)."""
    hub.close()


# ------------------------------------------------------------------ the summary tool does not need an extra tool
def test_resume_summary_lives_in_target_open_not_a_new_tool():
    assert len(TOOL_NAMES) <= MAX_TOOLS and "job_status" not in TOOL_NAMES


# ------------------------------------------------------------------ torn ledger tail
def test_torn_ledger_tail_is_dropped_reported_and_evidence_ids_stay_stable(tmp_path):
    t, m, cfg = setup(tmp_path)
    h = new_hub(cfg)
    h.target_open(t, m)
    f1 = h.call("functions_list", {"offset": 0, "limit": 5}, lambda: h.functions_list(0, 5))
    jp = h._s.job_dir / "events.jsonl"
    h.close()
    clean = jp.read_bytes()
    torn = b'{"seq":999,"ts":"2000-01-01T00:00:00","type":"TOOL_CA'   # the write that power loss cut in half
    jp.write_bytes(clean + torn)
    assert not verify_file(jp).ok   # detected (read-only verifier flags the torn tail)

    eng = CrashEngine()
    h2 = new_hub(cfg, eng)
    out = h2.target_open(t, m)
    assert out["resumed"] is True and out["resume"]["torn_bytes_dropped"] == len(torn)
    assert verify_file(jp).ok                                           # repaired: chain intact again
    assert jp.read_bytes().startswith(clean)                            # nothing before the torn line was touched
    types = [e["type"] for e in h2._s.journal.events()]
    assert "JOURNAL_TORN_TAIL_DROPPED" in types                         # the repair itself is in the hash chain
    f2 = h2.call("functions_list", {"offset": 0, "limit": 5}, lambda: h2.functions_list(0, 5))
    assert f2["evidence_id"] == f1["evidence_id"] and f2["step_cached"] is True and eng.calls == []  # no engine rerun
    h2.close()


def test_corrupt_complete_line_is_not_repaired_silently(tmp_path):
    t, m, cfg = setup(tmp_path)
    h = new_hub(cfg)
    h.target_open(t, m)
    jp = h._s.job_dir / "events.jsonl"
    h.close()
    jp.write_bytes(jp.read_bytes() + b'{"seq":99,"garbage":true}\n')   # newline-terminated but bad: not a torn write
    h2 = new_hub(cfg)
    with pytest.raises(ToolFailure) as e:
        h2.target_open(t, m)
    assert e.value.code == "JOURNAL_CORRUPT"


# ------------------------------------------------------------------ INTERRUPTED call status + idempotent re-run
def test_call_cut_off_mid_engine_step_is_interrupted_never_ok_and_rerun_is_idempotent(tmp_path):
    t, m, cfg = setup(tmp_path)
    eng = CrashEngine()
    h = new_hub(cfg, eng)
    h.target_open(t, m)
    f1 = h.call("functions_list", {"offset": 0, "limit": 5}, lambda: h.functions_list(0, 5))
    eng.crash_on_decompile = True
    with pytest.raises(KeyboardInterrupt):
        h.call("decompile", {"function": VA}, lambda: h.decompile(VA))
    ev = h._s.journal.events()
    assert [e["type"] for e in ev][-3:] == ["TOOL_STARTED", "STEP_STARTED", "STEP_FAILED"]       # started, never finished, no TOOL_CALL
    assert len(orphan_calls(ev)) == 1
    simulate_death(h)

    eng2 = CrashEngine()
    h2 = new_hub(cfg, eng2)
    out = h2.target_open(t, m)
    res = out["resume"]
    assert [(c["tool"], c["status"]) for c in res["interrupted"]] == [("decompile", "INTERRUPTED")]
    assert res["interrupted"][0]["args"] == {"function": VA}      # exactly what to re-issue
    # +2 each: the open-time protection_scan and check_inventory steps and their evidence
    assert res["steps_finished"] == 3 and res["evidence"] == 3 and "re-issue" in res["next"]
    assert len(json.dumps(res)) < 2500                              # short summary
    # the interrupted call produced no evidence and is not counted as ok anywhere
    st = h2._s.ledger.state
    assert [e["operation"] for e in st["evidence"].values()] == ["protection_scan", "check_inventory", "functions_list"]
    assert f1["evidence_id"] in st["evidence"]
    cov = h2.coverage()
    assert cov["tools_run"].get("decompile") is None

    d = h2.call("decompile", {"function": VA}, lambda: h2.decompile(VA))         # re-issue: runs once
    assert d["status"] == "OK" and d["step_cached"] is False and eng2.calls == ["decompile"]
    d2 = h2.call("decompile", {"function": VA}, lambda: h2.decompile(VA))
    assert d2["step_cached"] is True and d2["evidence_id"] == d["evidence_id"] and eng2.calls == ["decompile"]
    assert open_interrupted(h2._s.journal.events()) == []                        # redone: no longer pending
    h2.close()

    h3 = new_hub(cfg)
    out3 = h3.target_open(t, m)
    assert out3["resume"]["interrupted"] == [] and "newly_interrupted" not in out3["resume"]
    types = [e["type"] for e in h3._s.journal.events()]
    assert types.count("TOOL_INTERRUPTED") == 1                                  # recorded once, not again at every open
    h3.close()

    # evidence id of the re-run equals the id of a run that was never interrupted (nothing in it depends on time/pid)
    (tmp_path / "control").mkdir()
    t2, m2, cfg2 = setup(tmp_path / "control")
    hc = new_hub(cfg2)
    hc.target_open(t2, m2)
    dc = hc.call("decompile", {"function": VA}, lambda: hc.decompile(VA))
    hc.close()
    # the target bytes are identical, so the subject SHA and the evidence id match
    assert dc["evidence_id"] == d["evidence_id"]


def test_failed_tool_calls_are_not_reported_as_interrupted(tmp_path):
    t, m, cfg = setup(tmp_path)
    h = new_hub(cfg)
    h.target_open(t, m)
    with pytest.raises(ToolFailure):
        h.call("decompile", {"function": "0x1"}, lambda: h.decompile("0x1"))   # engine says no such function
    h.close()
    h2 = new_hub(cfg)
    assert h2.target_open(t, m)["resume"]["interrupted"] == []
    h2.close()


# ------------------------------------------------------------------ stale job lock
def test_stale_job_lock_from_dead_server_is_reclaimed_and_recorded(tmp_path):
    t, m, cfg = setup(tmp_path)
    h = new_hub(cfg)
    h.target_open(t, m)
    jd = h._s.job_dir
    h.close()
    # a server that died while holding the lock: its PID is gone
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    from redharness.core.procinfo import process_start_time
    (jd / "lock").write_bytes(LockInfo(p.pid, 123456789, socket.gethostname(), "dead").to_bytes())
    assert process_start_time(p.pid) is None
    h2 = new_hub(cfg)
    out = h2.target_open(t, m)
    assert out["resume"]["lock_reclaimed"] is True
    assert any(e["type"] == "LOCK_RECLAIMED" and e["payload"]["pid"] == p.pid for e in h2._s.journal.events())
    h2.close()
    assert not (jd / "lock").exists()      # released again on close


def test_live_job_lock_is_not_stolen(tmp_path):
    t, m, cfg = setup(tmp_path)
    h = new_hub(cfg)
    h.target_open(t, m)
    h2 = new_hub(cfg)
    with pytest.raises(ToolFailure) as e:
        h2.target_open(t, m)
    assert e.value.code == "JOB_LOCKED"
    h.close()


# ------------------------------------------------------------------ sandbox: host dies during run_controlled
def _run_host_that_dies(tmp_path, t, m, cfg, root, tool="run_controlled"):
    """Runs a Hub in a child process whose fake sandbox hangs, waits until the sandbox is up, then kills the child hard."""
    script = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {str(Path(__file__).parent.parent.parent)!r})
        from redharness.config import Config
        from redharness.mcp.session import Hub
        from tests.unit._fake_engine import FakeEngine
        from tests.unit._fake_sandbox import FakeSandbox
        import redharness.sandbox.runner as r
        r.BOOT_ALLOWANCE_S = 120.0
        hub = Hub(Config.load({str(cfg.data_root)!r}), FakeEngine(), FakeSandbox(mode="hang"), system_root={root!r})
        hub.target_open({t!r}, {m!r})
        args = {{"cases": [{{"stdin": "k1"}}], "timeout_s": 5}}
        hub.call("run_controlled", args, lambda: hub.run_controlled([{{"stdin": "k1"}}], 5))
    """)
    p = subprocess.Popen([sys.executable, "-c", script], stderr=subprocess.PIPE)
    try:
        jp = sandbox_dir(cfg) / "journal.jsonl"
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline and not (jp.exists() and b"SANDBOX_PROCS" in jp.read_bytes()):
            assert p.poll() is None, p.stderr.read().decode()
            time.sleep(0.05)
        assert b"SANDBOX_PROCS" in jp.read_bytes()
    finally:
        p.kill()   # TerminateProcess: no finally/atexit code runs
        p.wait()
    return p


def test_host_death_during_run_controlled_is_interrupted_cleaned_and_rerunnable(tmp_path):
    root = fake_system_root(tmp_path / "sysroot")
    t, m, cfg = setup(tmp_path, ops=("static", "run_controlled"))
    _run_host_that_dies(tmp_path, t, m, cfg, root)
    assert pending_recovery(cfg)                                    # stale sandbox state is detectable without a lock
    jid = next((cfg.data_root / "jobs").iterdir())
    jev = Journal(jid / "events.jsonl").events()
    assert len(orphan_calls(jev)) == 1 and orphan_calls(jev)[0]["tool"] == "run_controlled"
    rid = next(e["payload"]["run_id"] for e in Journal(sandbox_dir(cfg) / "journal.jsonl").events()
               if e["type"] == "SANDBOX_STARTED")
    assert run_status(cfg, rid) == "STARTED"
    assert (sandbox_dir(cfg) / "sandbox.lock").exists()             # locks of the dead host are left behind

    # the sandbox VM outlived its host (as in a host-process crash); a foreign instance (PID 777) runs as well
    fake = FakeSandbox(preexisting=[101, 102, 777], behavior=oracle)
    h = new_hub(cfg, None, fake, root)
    out = h.target_open(t, m)
    rec = out["resume"]["sandbox_recovery"]
    assert rec["recovered_runs"] == [rid] and rec["code"] is None
    assert [(c["tool"], c["status"]) for c in out["resume"]["interrupted"]] == [("run_controlled", "INTERRUPTED")]
    assert fake.pids == [777]                                       # ours (101/102) killed, the foreign one untouched
    assert run_status(cfg, rid) == "FAILED" and not (workdir_root(cfg) / rid).exists()
    failed = next(e["payload"] for e in Journal(sandbox_dir(cfg) / "journal.jsonl").events()
                  if e["type"] == "SANDBOX_RUN_FAILED")
    assert failed["reason"] == "INTERRUPTED" and failed["killed_pids"] == [101, 102] and failed["foreign_pids_left"] == [777]
    # never ok, never silently dropped: no run evidence exists for the cut-off call
    assert not [e for e in h._s.ledger.state["evidence"].values() if e["authority"] == "controlled-replay"]
    # locks: the dead host's stale locks are reclaimable, nothing is held
    for name in ("sandbox.lock",):
        jl = JobLock(sandbox_dir(cfg) / name)
        jl.acquire()
        jl.release()

    # re-issue while the foreign sandbox runs: refused as BUSY (we never open a second instance and never kill it)
    with pytest.raises(ToolFailure) as e:
        h.call("run_controlled", {"cases": [{"stdin": "k1"}], "timeout_s": 5},
               lambda: h.run_controlled([{"stdin": "k1"}], 5))
    assert e.value.code == "BUSY" and fake.pids == [777]
    fake.pids = []                                                  # the foreign instance finished
    r = h.call("run_controlled", {"cases": [{"stdin": "k1"}], "timeout_s": 5},
               lambda: h.run_controlled([{"stdin": "k1"}], 5))
    assert r["status"] == "OK" and r["evidence_ids"]                # the clean re-run
    assert open_interrupted(h._s.journal.events()) == []
    h.close()


def test_run_without_recorded_processes_leaves_every_sandbox_alone(tmp_path):
    """The host died before it noted its sandbox processes: we cannot prove ownership, so nothing is killed."""
    from .test_sandbox import _fake_interrupted
    cfg = Config.load(tmp_path / "data")
    rid, wd = _fake_interrupted(cfg)             # SANDBOX_STARTED only, no SANDBOX_PROCS
    fake = FakeSandbox(preexisting=[555])
    from redharness.sandbox import recover_interrupted
    r = recover_interrupted(cfg, fake)
    assert r.recovered_runs == [rid] and fake.pids == [555] and not wd.exists()
    failed = next(e["payload"] for e in Journal(sandbox_dir(cfg) / "journal.jsonl").events()
                  if e["type"] == "SANDBOX_RUN_FAILED")
    assert failed["killed_pids"] == [] and failed["foreign_pids_left"] == [555]


def test_recorded_process_with_reused_pid_is_not_killed(tmp_path):
    """After a reboot the PID may belong to someone else: creation time must match."""
    from .test_sandbox import _fake_interrupted
    cfg = Config.load(tmp_path / "data")
    rid, wd = _fake_interrupted(cfg, owned=[9])
    fake = FakeSandbox(preexisting=[9])
    fake.alive_owned_orig = fake.alive_owned
    # same PID, different creation time: the journaled record says start 1009 but the live process has another one
    fake.alive_owned = lambda procs: [r["pid"] for r in procs if r["pid"] in fake.pids and r.get("start") == 5]
    from redharness.sandbox import recover_interrupted
    r = recover_interrupted(cfg, fake)
    assert r.recovered_runs == [rid] and fake.pids == [9]
