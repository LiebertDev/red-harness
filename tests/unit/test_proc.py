import sys
import time

import pytest

from redharness.core.procinfo import pid_alive
from redharness.core.proc import run_bounded
from redharness.core.result import Status

PY = sys.executable
MB = 1024 * 1024


def py(code, **kw):
    return run_bounded([PY, "-c", code], **kw)


def test_success_is_ok():
    r = py("print('hello')", timeout_s=30)
    assert r.status is Status.OK and r.ok and r.exit_code == 0
    assert b"hello" in r.stdout and not r.truncated


def test_nonzero_exit_is_error_not_ok():
    r = py("import sys; sys.exit(3)", timeout_s=30)
    assert r.status is Status.ERROR and not r.ok and r.exit_code == 3


def test_missing_tool():
    r = run_bounded([r"C:\missing\nonexistent\tool.exe"], timeout_s=5)
    assert r.status is Status.TOOL_MISSING and not r.ok


def test_timeout_kills_and_never_ok():
    t0 = time.monotonic()
    r = py("import time; time.sleep(60)", timeout_s=1.0)
    assert r.status is Status.TIMEOUT and not r.ok
    assert time.monotonic() - t0 < 15


def test_timeout_kills_whole_process_tree(tmp_path):
    pidfile = tmp_path / "grandchild.pid"
    code = (
        "import subprocess, sys, time\n"
        "g = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
        f"open(r'{pidfile}', 'w').write(str(g.pid))\n"
        "time.sleep(120)\n"
    )
    r = py(code, timeout_s=3.0)
    assert r.status is Status.TIMEOUT
    gpid = int(pidfile.read_text())
    deadline = time.monotonic() + 5
    while pid_alive(gpid) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not pid_alive(gpid), "grandchild process is still alive"


def test_orphan_grandchild_killed_after_main_exits(tmp_path):
    pidfile = tmp_path / "orphan.pid"
    code = (
        "import subprocess, sys\n"
        "g = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
        f"open(r'{pidfile}', 'w').write(str(g.pid))\n"
    )
    r = py(code, timeout_s=30)
    gpid = int(pidfile.read_text())
    deadline = time.monotonic() + 5
    while pid_alive(gpid) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not pid_alive(gpid)
    assert r.orphans_killed >= 1


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job Object semantics")
def test_memory_limit_job_object():
    limit = 200 * MB
    # below the limit: OK (the limit does not trigger by itself)
    ok = py("x = bytearray(20*1024*1024); print(len(x))", timeout_s=30, memory_limit_bytes=limit)
    assert ok.status is Status.OK, (ok.status, ok.detail, ok.stderr)
    # above the limit: MEMORY_LIMIT, never OK
    r = py("x = bytearray(1024*1024*1024); print('PASSED')", timeout_s=30, memory_limit_bytes=limit)
    assert r.status is Status.MEMORY_LIMIT and not r.ok, (r.status, r.detail, r.stderr)
    assert b"PASSED" not in r.stdout


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job Object semantics")
def test_memory_hog_swallowing_error_still_flagged():
    code = (
        "try:\n    x = bytearray(1024*1024*1024)\nexcept MemoryError:\n    pass\nprint('swallowed')\n"
    )
    r = py(code, timeout_s=30, memory_limit_bytes=200 * MB)
    assert r.status is Status.MEMORY_LIMIT and not r.ok


def test_large_output_truncated_head_and_tail_never_ok():
    code = (
        "import sys\n"
        "sys.stdout.write('START' + 'a'*500000 + 'b'*500000 + 'END')\n"
    )
    r = py(code, timeout_s=30, head_bytes=1000, tail_bytes=1000)
    assert r.status is Status.PARTIAL and not r.ok and r.truncated
    assert r.stdout.startswith(b"START") and r.stdout.endswith(b"END")
    assert r.stdout_total == 1_000_008
    assert len(r.stdout) < 3000
    assert b"truncated" in r.stdout


def test_stderr_truncation_also_partial():
    r = py("import sys; sys.stderr.write('e'*300000)", timeout_s=30, head_bytes=100, tail_bytes=100)
    assert r.status is Status.PARTIAL and r.truncated


def test_stdin_input_passthrough():
    r = py("import sys; print(sys.stdin.read().upper())", timeout_s=30, input_bytes=b"abc")
    assert r.ok and b"ABC" in r.stdout


def test_invalid_timeout_rejected():
    assert run_bounded([PY, "-c", "pass"], timeout_s=0).status is Status.ERROR


# ---- Job Object error paths (mock) ----

@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job Object semantics")
def test_assign_failure_is_error_and_process_never_runs(tmp_path, monkeypatch):
    from redharness.core import proc as pmod
    marker = tmp_path / "ran.txt"

    def boom(self, handle):
        raise OSError("AssignProcessToJobObject failed: 5")
    monkeypatch.setattr(pmod._Job, "assign", boom)
    r = py(f"open(r'{marker}', 'w').write('x')", timeout_s=10)
    assert r.status is Status.ERROR and not r.ok
    assert "could not be assigned" in r.detail
    time.sleep(0.3)
    assert not marker.exists(), "process ran outside the job"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job Object semantics")
def test_job_limit_setup_failure_is_error(monkeypatch):
    from redharness.core import proc as pmod

    class FailSet:
        def __init__(self, real):
            self._real = real

        def __getattr__(self, name):
            return getattr(self._real, name)

        def SetInformationJobObject(self, *a):
            return 0
    monkeypatch.setattr(pmod.w, "k32", FailSet(pmod.w.k32))
    r = py("print('x')", timeout_s=10, memory_limit_bytes=100 * MB)
    assert r.status is Status.ERROR and not r.ok and "could not set up job" in r.detail


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job Object semantics")
def test_terminate_failure_after_success_is_never_ok(monkeypatch):
    from redharness.core import proc as pmod
    monkeypatch.setattr(pmod._Job, "terminate", lambda self: False)
    r = py("print('done')", timeout_s=10)
    assert r.status is Status.ERROR and not r.ok
    assert "TerminateJobObject" in r.detail


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job Object semantics")
def test_terminate_failure_on_timeout_falls_back_to_kill_and_stays_timeout(monkeypatch):
    from redharness.core import proc as pmod
    monkeypatch.setattr(pmod._Job, "terminate", lambda self: False)
    t0 = time.monotonic()
    r = py("import time; time.sleep(60)", timeout_s=1.0)
    assert r.status is Status.TIMEOUT and not r.ok
    assert "FAILED" in r.detail
    assert time.monotonic() - t0 < 15  # the fallback proc.kill() killed the main process


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job Object semantics")
def test_real_terminate_returns_false_on_bad_handle():
    from redharness.core import proc as pmod
    job = pmod._Job(None)
    try:
        assert job.terminate() is True
        real = job.h
        job.h = 0xDEAD
        assert job.terminate() is False
        job.h = real
    finally:
        job.close()


def test_reader_thread_exceeding_join_never_ok(monkeypatch):
    from redharness.core import proc as pmod
    monkeypatch.setattr(pmod, "READER_JOIN_S", 0.2)
    monkeypatch.setattr(pmod._Capture, "run", lambda self: time.sleep(3))  # the reader never finishes
    t0 = time.monotonic()
    r = py("print('hello')", timeout_s=10)
    assert r.status is Status.ERROR and not r.ok and r.exit_code == 0
    assert "readers did not finish" in r.detail
    assert time.monotonic() - t0 < 5


def test_posix_runner_refuses_active_process_limit(monkeypatch):
    """No per-process cap outside Windows: the request is refused and nothing is run (not silently unbounded)."""
    monkeypatch.setattr("redharness.core.proc.sys.platform", "linux")
    r = run_bounded([PY, "-c", "print('ran')"], timeout_s=5, active_process_limit=1)
    assert r.status is Status.ERROR and not r.ok and b"ran" not in r.stdout
    assert "active_process_limit" in r.detail


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX runner")
def test_posix_memory_cap_and_tree_kill():
    r = py("x = bytearray(1024*1024*1024); print('PASSED')", timeout_s=30, memory_limit_bytes=200 * MB)
    assert not r.ok and b"PASSED" not in r.stdout
    r = py("import time; time.sleep(60)", timeout_s=1.0)
    assert r.status is Status.TIMEOUT and not r.ok and "tree killed" in r.detail
