"""Sandbox resource management: .wsb memory/isolation, launch-failure diagnosis, single retry, machine-wide lock,
heavy-engine conflict (BUSY), real-sandbox marker. Real Windows Sandbox is NOT STARTED (fake backend)."""
import hashlib
import threading
import time
from pathlib import Path

import pytest

from redharness.config import Config, sandbox_memory_mb
from redharness.core.heavy import HeavyGate, heavy_lock, sandbox_global_lock
from redharness.core.result import Status
from redharness.sandbox import Code, RunCase, run_controlled
from redharness.sandbox.backend import render_wsb
from redharness.scope.manifest import ScopeManifest

from .. import conftest as tconf
from ._fake_sandbox import FakeSandbox

FAST = dict(poll_interval_s=0.01, proc_check_interval_s=0.05, retry_backoff_s=0.05)
TARGET = b"MZ-fake-target-bytes"
SHA = hashlib.sha256(TARGET).hexdigest()


@pytest.fixture
def cfg(tmp_path):
    return Config.load(tmp_path / "data")


@pytest.fixture
def target(tmp_path):
    p = tmp_path / "sample.exe"
    p.write_bytes(TARGET)
    return p


def go(cfg, target, backend, **kw):
    scope = ScopeManifest(SHA, "t", "o", "t", ("static", "run_controlled"), None, "")
    return run_controlled(SHA, scope, [RunCase(stdin="x\n")], 5, cfg=cfg, backend=backend, target_path=target,
                          boot_allowance_s=kw.pop("boot_allowance_s", 3), **{**FAST, **kw})


class ScriptedSandbox(FakeSandbox):
    """Counts start calls; `plan[i]`: 'raise' (OSError) | 'die' (process appears, then vanishes without ready)
    | 'ok' (fake guest)."""

    def __init__(self, plan, **kw):
        super().__init__(**kw)
        self.plan = list(plan)
        self.start_calls = 0

    def start(self, wsb_path):
        step = self.plan[min(self.start_calls, len(self.plan) - 1)]
        self.start_calls += 1
        if step == "raise":
            raise OSError("0x800705AA")
        if step == "die":
            with self._mu:
                self.pids = [7]
            threading.Timer(0.15, lambda: self._clear()).start()
            return
        super().start(wsb_path)

    def _clear(self):
        with self._mu:
            self.pids = []


# ---- .wsb
def test_wsb_defaults_memory_2048_and_disables_features(tmp_path, monkeypatch):
    monkeypatch.delenv("RH_SANDBOX_MEMORY_MB", raising=False)
    w = render_wsb(tmp_path / "in", tmp_path / "out")
    assert "<MemoryInMB>2048</MemoryInMB>" in w
    for tag in ("VGpu", "Networking", "AudioInput", "VideoInput", "PrinterRedirection", "ClipboardRedirection"):
        assert f"<{tag}>Disable</{tag}>" in w


def test_wsb_memory_from_env_and_invalid_falls_back(tmp_path, monkeypatch):
    monkeypatch.setenv("RH_SANDBOX_MEMORY_MB", "3072")
    assert "<MemoryInMB>3072</MemoryInMB>" in render_wsb(tmp_path, tmp_path)
    for bad in ("abc", "10", "999999"):
        monkeypatch.setenv("RH_SANDBOX_MEMORY_MB", bad)
        assert sandbox_memory_mb() == 2048
    assert "<MemoryInMB>1024</MemoryInMB>" in render_wsb(tmp_path, tmp_path, memory_mb=1024)


# ---- launch failure + single retry
def test_start_failure_retries_exactly_once_then_resource_unavailable(cfg, target):
    sb = ScriptedSandbox(["raise"])
    run = go(cfg, target, sb)
    assert sb.start_calls == 2 and run.attempts == 2
    assert run.status is Status.ERROR and run.code == Code.RESOURCE_UNAVAILABLE
    assert "restarted" in run.detail and "VMs/WSL" in run.detail


def test_silent_crash_without_ready_is_resource_unavailable(cfg, target):
    sb = ScriptedSandbox(["die"])
    run = go(cfg, target, sb)
    assert sb.start_calls == 2
    assert run.code == Code.RESOURCE_UNAVAILABLE and not run.ok


def test_retry_succeeds_on_second_attempt(cfg, target):
    sb = ScriptedSandbox(["raise", "ok"])
    run = go(cfg, target, sb)
    assert sb.start_calls == 2 and run.attempts == 2
    assert run.ok, (run.code, run.detail)


def test_retry_waits_before_second_start(cfg, target):
    sb = ScriptedSandbox(["raise"])
    t = time.monotonic()
    go(cfg, target, sb, retry_backoff_s=0.6)
    assert time.monotonic() - t >= 0.6


def test_never_more_than_two_starts_even_with_many_failures(cfg, target):
    sb = ScriptedSandbox(["raise"] * 10)
    go(cfg, target, sb)
    assert sb.start_calls == 2


def test_no_retry_when_sandbox_not_closed(cfg, target):
    class Stuck(ScriptedSandbox):
        def kill_all(self, wait_s=20.0):
            return [9]   # the process does not close
    sb = Stuck(["raise"])
    run = go(cfg, target, sb)
    assert sb.start_calls == 1 and run.code == Code.SANDBOX_NOT_CLOSED


# ---- locks
def test_global_machine_lock_conflict_returns_busy_without_start(cfg, target):
    g = sandbox_global_lock()
    g.acquire()
    try:
        sb = ScriptedSandbox(["ok"])
        run = go(cfg, target, sb)
    finally:
        g.release()
    assert run.code == Code.BUSY and sb.start_calls == 0
    run2 = go(cfg, target, ScriptedSandbox(["ok"]))   # lock released: free
    assert run2.ok


def test_busy_while_heavy_engine_runs_and_locks_released_after(cfg, target):
    gate = HeavyGate(wait_s=0.1)
    sb = ScriptedSandbox(["ok"])
    with gate:   # an IDA/Ghidra job is in progress
        run = go(cfg, target, sb)
    assert run.code == Code.BUSY and "heavy" in run.detail and sb.start_calls == 0
    assert go(cfg, target, ScriptedSandbox(["ok"])).ok
    # a failed BUSY does not leak the global lock
    g = sandbox_global_lock()
    g.acquire()
    g.release()


def test_heavy_engine_gate_waits_for_running_sandbox_then_proceeds():
    h = heavy_lock()
    h.acquire()   # as if a sandbox is running
    gate = HeavyGate(wait_s=5)
    entered = threading.Event()

    def worker():
        with gate:
            entered.set()
    t = threading.Thread(target=worker)
    t.start()
    assert not entered.wait(0.7)
    h.release()
    assert entered.wait(5)
    t.join()


def test_engines_use_heavy_gate():
    from redharness.engines import _common
    assert isinstance(_common.HEAVY, HeavyGate)


# ---- real-sandbox marker
class _Item:
    def __init__(self, real):
        self.keywords = {"real_sandbox": True} if real else {}
        self.markers = []

    def add_marker(self, m):
        self.markers.append(m)


def test_real_sandbox_tests_skipped_without_env(monkeypatch):
    monkeypatch.delenv("RH_ALLOW_REAL_SANDBOX", raising=False)
    real, fake = _Item(True), _Item(False)
    tconf.pytest_collection_modifyitems(None, [real, fake])
    assert len(real.markers) == 1 and real.markers[0].name == "skip" and not fake.markers
    monkeypatch.setenv("RH_ALLOW_REAL_SANDBOX", "0")
    r2 = _Item(True)
    tconf.pytest_collection_modifyitems(None, [r2])
    assert r2.markers
    monkeypatch.setenv("RH_ALLOW_REAL_SANDBOX", "1")
    r3 = _Item(True)
    tconf.pytest_collection_modifyitems(None, [r3])
    assert not r3.markers


def test_real_sandbox_modules_carry_marker():
    root = Path(__file__).resolve().parents[1] / "heavy"
    for n in ("test_sandbox_real.py", "test_sandbox_integrity_real.py"):
        if (root / n).is_file():  # some real-sandbox modules exist only in the development tree
            assert "pytest.mark.real_sandbox" in (root / n).read_text(encoding="utf-8")
