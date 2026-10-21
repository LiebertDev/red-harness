import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from redharness.core import journal as jmod
from redharness.core.journal import (GENESIS_HASH, Journal, JournalCorrupt, load_snapshot,
                                     state_hash, verify_file)
from redharness.jobs.stepcache import StepCache
from tests.unit import _job_worker as worker

WORKER = Path(__file__).with_name("_job_worker.py")


def make(path, n=5):
    j = Journal(path)
    for i in range(n):
        j.append("E", {"i": i})
    j.close()


def test_chain_links_and_verifies(tmp_path):
    p = tmp_path / "e.jsonl"
    make(p, 5)
    rep = verify_file(p)
    assert rep.ok and rep.count == 5
    evs = Journal(p).events()
    assert evs[0]["prev_hash"] == GENESIS_HASH
    assert all(evs[i]["prev_hash"] == evs[i - 1]["hash"] for i in range(1, 5))
    assert [e["seq"] for e in evs] == [1, 2, 3, 4, 5]


def test_reopen_continues_chain(tmp_path):
    p = tmp_path / "e.jsonl"
    make(p, 3)
    j = Journal(p)
    j.append("E", {"i": 3})
    j.close()
    assert verify_file(p).ok and verify_file(p).count == 4


def test_tampered_payload_detected(tmp_path):
    p = tmp_path / "e.jsonl"
    make(p, 4)
    lines = p.read_bytes().split(b"\n")
    ev = json.loads(lines[1])
    ev["payload"]["i"] = 999
    lines[1] = jmod.canonical(ev)
    p.write_bytes(b"\n".join(lines))
    assert not verify_file(p).ok
    with pytest.raises(JournalCorrupt):
        Journal(p)


def test_deleted_middle_line_detected(tmp_path):
    p = tmp_path / "e.jsonl"
    make(p, 4)
    lines = p.read_bytes().split(b"\n")
    del lines[1]
    p.write_bytes(b"\n".join(lines))
    with pytest.raises(JournalCorrupt):
        Journal(p)


def test_reordered_lines_detected(tmp_path):
    p = tmp_path / "e.jsonl"
    make(p, 4)
    lines = p.read_bytes().split(b"\n")
    lines[1], lines[2] = lines[2], lines[1]
    p.write_bytes(b"\n".join(lines))
    with pytest.raises(JournalCorrupt):
        Journal(p)


def test_torn_tail_is_dropped_and_chain_continues(tmp_path):
    p = tmp_path / "e.jsonl"
    make(p, 3)
    good = p.read_bytes()
    with open(p, "ab") as f:
        f.write(b'{"seq":4,"ts":"x","ty')  # torn write
    j = Journal(p)
    assert j.torn_bytes_dropped > 0
    assert p.read_bytes() == good
    j.append("E", {"i": 3})
    j.close()
    assert verify_file(p).ok and verify_file(p).count == 4


def test_fsync_called_per_append(tmp_path, monkeypatch):
    calls = []
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (calls.append(fd), real(fd))[1])
    j = Journal(tmp_path / "e.jsonl")
    base = len(calls)
    for i in range(3):
        j.append("E", {"i": i})
    j.close()
    assert len(calls) - base == 3


def test_failed_write_fails_closed(tmp_path, monkeypatch):
    j = Journal(tmp_path / "e.jsonl")
    j.append("E", {})
    monkeypatch.setattr(os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("disk")))
    with pytest.raises(OSError):
        j.append("E", {})
    monkeypatch.undo()
    with pytest.raises(JournalCorrupt):
        j.append("E", {})


def test_snapshot_uses_matching_and_replays_stale(tmp_path):
    j = Journal(tmp_path / "e.jsonl")
    snap = tmp_path / "state.json"
    s1 = load_snapshot(snap, j, worker.reducer, {"done": {}})
    assert s1 == {"done": {}}
    j.append("STEP_FINISHED", {"key": "k", "digest": "d"})
    s2 = load_snapshot(snap, j, worker.reducer, {"done": {}})  # snapshot stale -> replay
    assert s2 == {"done": {"k": "d"}}
    snap.write_text("{corrupt")
    assert load_snapshot(snap, j, worker.reducer, {"done": {}}) == s2


def test_step_cache_skips_finished_and_reruns_unfinished(tmp_path):
    j = Journal(tmp_path / "e.jsonl")
    sc = StepCache(j, tmp_path / "steps")
    calls = []
    out1 = sc.run("t", {"a": 1}, "aa", lambda: calls.append(1) or {"r": 1})
    out2 = sc.run("t", {"a": 1}, "aa", lambda: calls.append(2) or {"r": 2})
    assert (out1.cached, out2.cached, out2.result, len(calls)) == (False, True, {"r": 1}, 1)
    # different parameter / target SHA -> different key
    assert not sc.run("t", {"a": 2}, "aa", lambda: {"r": 3}).cached
    assert not sc.run("t", {"a": 1}, "bb", lambda: {"r": 4}).cached
    # a new session (reopen) gets a hit
    j.close()
    sc2 = StepCache(Journal(tmp_path / "e.jsonl"), tmp_path / "steps")
    assert sc2.run("t", {"a": 1}, "aa", lambda: {"r": 9}).cached


def test_step_cache_rejects_tampered_result_file(tmp_path):
    j = Journal(tmp_path / "e.jsonl")
    sc = StepCache(j, tmp_path / "steps")
    o = sc.run("t", {}, "aa", lambda: {"r": 1})
    (tmp_path / "steps" / f"{o.key}.json").write_text(json.dumps({"key": o.key, "result": {"r": 666}}))
    o2 = sc.run("t", {}, "aa", lambda: {"r": 1})
    assert not o2.cached and o2.result == {"r": 1}


def test_failed_step_is_not_cached(tmp_path):
    j = Journal(tmp_path / "e.jsonl")
    sc = StepCache(j, tmp_path / "steps")
    with pytest.raises(RuntimeError):
        sc.run("t", {}, "aa", lambda: (_ for _ in ()).throw(RuntimeError("x")))
    assert not sc.run("t", {}, "aa", lambda: {"ok": 1}).cached
    assert "STEP_FAILED" in [e["type"] for e in j.events()]


# ---- interruption test: a real process is killed 20 times with taskkill /F ----

N_STEPS, STEP_SLEEP, KILLS = 12, 0.0, 20


def _spawn(job_dir, kill_at=0, marker=None):
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).parents[2])}
    if kill_at:
        env["RH_KILL_AT"], env["RH_MARKER"] = str(kill_at), str(marker)
    return subprocess.Popen([sys.executable, str(WORKER), str(job_dir), str(N_STEPS), str(STEP_SLEEP)],
                            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def _final_state(job_dir):
    return json.loads((job_dir / "state.json").read_text())


def _kill_at_marker(job_dir, kill_at, tmp_path):
    """Waits until the marker file appears (an event, not time), then taskkill /F."""
    marker = tmp_path / "kill.marker"
    marker.unlink(missing_ok=True)
    p = _spawn(job_dir, kill_at, marker)
    deadline = time.monotonic() + 60
    while not marker.exists():
        assert p.poll() is None, f"worker finished before the marker: {p.stderr.read().decode()}"
        assert time.monotonic() < deadline, "marker file did not appear"
        time.sleep(0.01)
    subprocess.run(["taskkill", "/F", "/PID", str(p.pid)], capture_output=True, check=True)
    p.wait(30)
    marker.unlink()


def test_resume_after_20_taskkill_matches_uninterrupted(tmp_path):
    ref = tmp_path / "ref"
    p = _spawn(ref)
    assert p.wait(120) == 0, p.stderr.read().decode()
    ref_state = _final_state(ref)
    assert len(ref_state["state"]["done"]) == N_STEPS

    # The kill point is tied to the step boundary: on an odd-numbered attempt INSIDE the 1st step in the process (no progress),
    # on an even-numbered one inside the 2nd step (1 step progresses). 20 kills DEFINITELY happen; 10 steps finish, 2 remain.
    job = tmp_path / "killed"
    kills = 0
    for n in range(KILLS):
        _kill_at_marker(job, 1 if n % 2 == 0 else 2, tmp_path)
        kills += 1
    p = _spawn(job)  # final, uninterrupted run
    assert p.wait(120) == 0, p.stderr.read().decode()

    assert kills == KILLS
    assert verify_file(job / "events.jsonl").ok
    st = _final_state(job)
    assert st["state_hash"] == ref_state["state_hash"]
    assert st["state"] == ref_state["state"]
    assert state_hash(st["state"]) == st["state_hash"]

    # a finished step did not run again: no STEP_STARTED for the same key after STEP_FINISHED, exactly 1 finish
    finished, bad = {}, []
    for ev in Journal(job / "events.jsonl").events():
        k = ev["payload"].get("key")
        if ev["type"] == "STEP_FINISHED":
            finished[k] = finished.get(k, 0) + 1
        elif ev["type"] == "STEP_STARTED" and k in finished:
            bad.append(k)
    assert not bad
    assert set(finished.values()) == {1} and len(finished) == N_STEPS
    print(f"\n[interruption] kills={kills}, events={Journal(job / 'events.jsonl').seq}")


# ---- corrupt last line / partial write ----

def _last_line_variants(good: bytes):
    lines = good.split(b"\n")[:-1]
    last = json.loads(lines[-1])
    tampered = dict(last, payload={"i": 777})  # the hash no longer matches
    return {
        "bad_json": lines[:-1] + [b'{"seq":3,"ts":"x",oops'],
        "hash_mismatch": lines[:-1] + [jmod.canonical(tampered)],
        "not_json": lines[:-1] + [bytes([0xff, 0xfe]) + b" not json"],
    }


@pytest.mark.parametrize("kind", ["bad_json", "hash_mismatch", "not_json"])
def test_newline_terminated_corrupt_last_line_is_explicit_error_not_trimmed(tmp_path, kind):
    p = tmp_path / "e.jsonl"
    make(p, 3)
    data = b"\n".join(_last_line_variants(p.read_bytes())[kind]) + b"\n"
    p.write_bytes(data)
    with pytest.raises(JournalCorrupt):
        Journal(p)
    assert p.read_bytes() == data  # not silently truncated, the file was not touched
    assert not verify_file(p).ok


def test_corrupt_complete_line_plus_torn_tail_leaves_file_untouched(tmp_path):
    p = tmp_path / "e.jsonl"
    make(p, 3)
    lines = p.read_bytes().split(b"\n")[:-1]
    data = b"\n".join(lines[:-1] + [b"{corrupt"]) + b"\n" + b'{"seq":4,"ts'
    p.write_bytes(data)
    with pytest.raises(JournalCorrupt):
        Journal(p)
    assert p.read_bytes() == data  # even a torn tail is not truncated when verification fails


def _short_write(monkeypatch, n_bytes):
    real = os.write
    state = {"armed": True}

    def fake(fd, data):
        if state["armed"] and len(data) > n_bytes:
            state["armed"] = False
            return real(fd, data[:n_bytes])  # partial write: returns a short byte count
        return real(fd, data)
    monkeypatch.setattr(os, "write", fake)


@pytest.mark.parametrize("n_bytes", [1, 40, "len-1"])
def test_partial_write_fails_closed_and_reopen_recovers(tmp_path, monkeypatch, n_bytes):
    p = tmp_path / "e.jsonl"
    j = Journal(p)
    j.append("E", {"i": 0})
    good = p.read_bytes()
    seq_before, hash_before = j.seq, j.last_hash
    if n_bytes == "len-1":
        n_bytes = len(jmod.canonical({"seq": 2, "ts": "2000-01-01T00:00:00.000000+00:00", "type": "E",
                                      "payload": {"i": 1}, "prev_hash": "0" * 64, "hash": "0" * 64}))
    _short_write(monkeypatch, n_bytes)
    with pytest.raises(OSError):
        j.append("E", {"i": 1})
    monkeypatch.undo()
    assert (j.seq, j.last_hash) == (seq_before, hash_before)  # the in-memory chain did not advance
    assert len(p.read_bytes()) > len(good) and not p.read_bytes().endswith(b"\n")
    with pytest.raises(JournalCorrupt):  # the same object no longer writes
        j.append("E", {"i": 2})
    j.close()
    j2 = Journal(p)  # reopening cuts the torn tail
    assert j2.torn_bytes_dropped > 0 and p.read_bytes() == good
    j2.append("E", {"i": 1})
    j2.close()
    rep = verify_file(p)
    assert rep.ok and rep.count == 2
