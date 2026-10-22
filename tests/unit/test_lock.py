import os
import socket
import subprocess
import sys

import pytest

from redharness.core.procinfo import pid_alive, process_start_time
from redharness.core.lock import JobLock, LockError, LockHeldError, LockInfo


def test_acquire_release_and_reacquire(tmp_path):
    p = tmp_path / "lock"
    a = JobLock(p)
    assert a.acquire() is None
    assert p.exists()
    a.release()
    assert not p.exists()
    with JobLock(p):
        assert p.exists()


def test_second_holder_is_rejected_while_alive(tmp_path):
    p = tmp_path / "lock"
    with JobLock(p):
        with pytest.raises(LockHeldError):
            JobLock(p).acquire()
        assert p.exists()  # the rejected one did not delete the lock


def test_dead_pid_lock_is_reclaimed(tmp_path):
    child = subprocess.Popen([sys.executable, "-c", "pass"])
    child.wait()
    start_dead = process_start_time(os.getpid())  # placeholder; the real point: the dead pid
    p = tmp_path / "lock"
    p.write_bytes(LockInfo(child.pid, 123456789, socket.gethostname(), "dead").to_bytes())
    assert start_dead is not None and not pid_alive(child.pid)
    lk = JobLock(p)
    stale = lk.acquire()
    assert stale is not None and stale.pid == child.pid
    assert LockInfo.parse(p.read_bytes()).pid == os.getpid()
    lk.release()


def test_pid_reuse_start_time_mismatch_is_reclaimed(tmp_path):
    """PID alive but start time differs = PID reuse -> stale."""
    p = tmp_path / "lock"
    me = os.getpid()
    p.write_bytes(LockInfo(me, process_start_time(me) + 10_000_000, socket.gethostname(), "old").to_bytes())
    assert pid_alive(me)
    stale = JobLock(p).acquire()
    assert stale is not None and stale.token == "old"


def test_live_holder_with_matching_start_time_is_held(tmp_path):
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        p = tmp_path / "lock"
        p.write_bytes(LockInfo(child.pid, process_start_time(child.pid), socket.gethostname(), "c").to_bytes())
        with pytest.raises(LockHeldError):
            JobLock(p).acquire()
    finally:
        child.kill()
        child.wait()


def test_foreign_host_lock_is_not_stolen(tmp_path):
    p = tmp_path / "lock"
    p.write_bytes(LockInfo(1, 1, "other-machine-xyz", "f").to_bytes())
    with pytest.raises(LockHeldError):
        JobLock(p).acquire()


def test_corrupt_lock_fails_closed(tmp_path):
    p = tmp_path / "lock"
    p.write_bytes(b"not json")
    with pytest.raises(LockError):
        JobLock(p).acquire()
    assert p.exists()


def test_release_does_not_remove_someone_elses_lock(tmp_path):
    p = tmp_path / "lock"
    a = JobLock(p)
    a.acquire()
    p.write_bytes(LockInfo(os.getpid(), process_start_time(os.getpid()), socket.gethostname(), "other").to_bytes())
    a.release()
    assert p.exists()


# ---- concurrent stale lock reclaim ----

N_PROCS, ROUNDS = 6, 8


def _dead_lock(path):
    child = subprocess.Popen([sys.executable, "-c", "pass"])
    child.wait()
    path.write_bytes(LockInfo(child.pid, 123456789, socket.gethostname(), "dead").to_bytes())


def test_concurrent_stale_reclaim_exactly_one_winner(tmp_path):
    from pathlib import Path
    import time
    worker = Path(__file__).with_name("_lock_worker.py")
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).parents[2] / "src")}
    for rnd in range(ROUNDS):
        p = tmp_path / f"lock{rnd}"
        _dead_lock(p)
        start_at = time.time() + 2.0  # all processes start and wait until this moment
        procs = [subprocess.Popen([sys.executable, str(worker), str(p), str(start_at), "1.5"],
                                  env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                 for _ in range(N_PROCS)]
        outs = []
        for pr in procs:
            o, e = pr.communicate(timeout=60)
            assert pr.returncode == 0, e
            outs.append(o.strip())
        winners = [o for o in outs if o.startswith("WON")]
        assert len(winners) == 1, f"round {rnd}: {outs}"
        assert outs.count("HELD") == N_PROCS - 1, f"round {rnd}: {outs}"
        assert not p.exists()  # deleted when the winner released it


def test_reclaim_returns_stale_info_and_leaves_live_lock_intact(tmp_path):
    p = tmp_path / "lock"
    _dead_lock(p)
    a = JobLock(p)
    stale = a.acquire()
    assert stale is not None and stale.token == "dead"
    with pytest.raises(LockHeldError):
        JobLock(p).acquire()  # the new (live) lock was not disturbed
    assert LockInfo.parse(p.read_bytes()).token == a.info.token
    a.release()
