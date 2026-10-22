"""Host guards around the sandbox start: memory headroom pre-check, persisted backoff, error dialog of OUR launch.
No real Windows Sandbox, no real window: fakes only."""
import hashlib
import json
import threading
import time

import pytest

from redharness.config import Config
from redharness.core.result import Status
from redharness.sandbox import Code, RunCase, hostres, run_controlled
from redharness.sandbox.backend import WindowsSandboxBackend
from redharness.scope.manifest import ScopeManifest

from ._fake_sandbox import FakeSandbox

TARGET = b"MZ-fake-target-bytes"
SHA = hashlib.sha256(TARGET).hexdigest()
FAST = dict(poll_interval_s=0.01, proc_check_interval_s=0.02, retry_backoff_s=0.05)
ERR = ("Windows Sandbox failed to start.\n\nError 0x800705aa. Not enough system resources to complete the requested "
       "service.\n\nSend feedback?")


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


# ---------------------------------------------------------------- memory headroom (pure)
def test_headroom_problem_blocks_only_on_measured_shortfall():
    ok = {"avail_phys_mb": 8000, "avail_commit_mb": 9000}
    assert hostres.headroom_problem(ok, 2048, 1024) is None
    low_ram = hostres.headroom_problem({"avail_phys_mb": 2500, "avail_commit_mb": 9000}, 2048, 1024)
    assert low_ram and "available RAM 2500 MB" in low_ram and "3072" in low_ram
    low_commit = hostres.headroom_problem({"avail_phys_mb": 8000, "avail_commit_mb": 3000}, 2048, 1024)
    assert low_commit and "commit" in low_commit
    assert hostres.headroom_problem(None, 2048, 1024) is None            # unknown never blocks
    assert hostres.headroom_problem({}, 2048, 1024) is None
    assert hostres.headroom_problem({"avail_phys_mb": 3072, "avail_commit_mb": 3072}, 2048, 1024) is None  # boundary


def test_min_headroom_env(monkeypatch):
    monkeypatch.delenv(hostres.ENV_MIN_HEADROOM_MB, raising=False)
    assert hostres.min_headroom_mb() == hostres.DEFAULT_MIN_HEADROOM_MB
    monkeypatch.setenv(hostres.ENV_MIN_HEADROOM_MB, "512")
    assert hostres.min_headroom_mb() == 512
    for bad in ("x", "-1", "999999"):
        monkeypatch.setenv(hostres.ENV_MIN_HEADROOM_MB, bad)
        assert hostres.min_headroom_mb() == hostres.DEFAULT_MIN_HEADROOM_MB


# ---------------------------------------------------------------- persisted backoff (fake clock)
def test_backoff_doubles_caps_persists_and_resets(tmp_path):
    now = [1000.0]
    path = tmp_path / "sub" / "b.json"
    b = hostres.Backoff(path, 20.0, 6.0, cooldown_after=99, clock=lambda: now[0])
    assert b.remaining() == 0.0 and b.failures() == 0
    assert [b.record_failure() for _ in range(5)] == [20.0, 40.0, 80.0, 120.0, 120.0]   # capped at base*6
    assert hostres.Backoff(path, 20.0, 6.0, clock=lambda: now[0]).failures() == 5       # persisted across instances
    assert b.remaining() == pytest.approx(120.0)
    now[0] += 100
    assert b.remaining() == pytest.approx(20.0)
    now[0] += 100
    assert b.remaining() == 0.0
    b.record_success()
    assert b.failures() == 0 and b.record_failure() == 20.0


def test_backoff_cooldown_after_n_failures_then_expires(tmp_path):
    now = [1000.0]
    b = hostres.Backoff(tmp_path / "b.json", 20.0, cooldown_after=3, cooldown_s=600.0, clock=lambda: now[0])
    assert [b.record_failure() for _ in range(3)] == [20.0, 40.0, 600.0]
    assert b.cooling_down() and b.remaining() == pytest.approx(600.0)
    now[0] += 601
    assert not b.cooling_down()
    assert b.record_failure() == 600.0       # the single probe after the cool-down failed: straight back to cool-down
    b.record_success()
    assert not b.cooling_down() and b.failures() == 0


def test_state_dir_is_machine_wide_not_per_data_root(tmp_path, monkeypatch):
    monkeypatch.delenv(hostres.ENV_STATE_DIR, raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "lad"))
    monkeypatch.setenv("RH_DATA_ROOT", str(tmp_path / "root_a"))
    a = hostres.state_dir()
    monkeypatch.setenv("RH_DATA_ROOT", str(tmp_path / "root_b"))
    assert a == hostres.state_dir() == tmp_path / "lad" / "RedHarness"


def test_backoff_survives_corrupt_file(tmp_path):
    p = tmp_path / "b.json"
    p.write_text("not json", encoding="ascii")
    b = hostres.Backoff(p, 1.0)
    assert b.remaining() == 0.0 and b.failures() == 0
    b.record_failure()
    assert json.loads(p.read_text(encoding="ascii"))["failures"] == 1


# ---------------------------------------------------------------- error dialog discovery (owned PIDs only)
def _win(hwnd, pid, cls="#32770", title="Windows Sandbox", body=ERR):
    return (hwnd, pid, cls, title, body)


def test_find_error_dialogs_only_owned_pids_and_hex_error():
    wins = [_win(1, 111), _win(2, 222),                                   # 222 is foreign
            _win(3, 111, cls="ATL:0000"), _win(4, 111, body="Starting..."),  # not a dialog / no error code
            _win(5, 111, body="Hata 0x800705aa kaynak yok")]                # other locale, still matched
    got = hostres.find_error_dialogs({111}, windows=lambda: wins)
    assert [d.hwnd for d in got] == [1, 5] and all(d.pid == 111 for d in got)
    assert hostres.find_error_dialogs(set(), windows=lambda: wins) == []
    assert hostres.find_error_dialogs({999}, windows=lambda: wins) == []


def test_find_error_dialogs_enumeration_failure_is_unknown():
    def boom():
        raise OSError("no desktop")
    assert hostres.find_error_dialogs({1}, windows=boom) == []


# ---------------------------------------------------------------- backend: dialog of OUR launch only
class FakeWinBackend(WindowsSandboxBackend):
    def __init__(self, listed, launched, before=(), windows=()):
        super().__init__()
        self.listed, self._launched, self._pids_before = list(listed), launched, set(before)
        self.windows, self.pressed, self.killed = list(windows), [], []

    def running_processes(self):
        return list(self.listed)

    def kill_owned(self, procs, wait_s=20.0):
        self.killed += [r["pid"] for r in procs]
        return []


@pytest.fixture
def patched(monkeypatch):
    monkeypatch.setattr("redharness.sandbox.backend.process_start_time", lambda pid: 5000 + pid)
    monkeypatch.setattr(hostres, "_real_windows", lambda: [])
    monkeypatch.setattr("redharness.sandbox.backend.time.sleep", lambda s: None)


def _backend(monkeypatch, **kw):
    b = FakeWinBackend(**kw)
    monkeypatch.setattr(hostres, "_real_windows", lambda: b.windows)
    monkeypatch.setattr(hostres, "press_no", lambda h: b.pressed.append(h) or True)
    return b


def test_start_error_sees_our_dialog_not_a_foreign_one(patched, monkeypatch):
    b = _backend(monkeypatch, listed=[50, 60], launched=60, before=[50], windows=[_win(10, 50), _win(11, 60)])
    assert "0x800705aa" in b.start_error()
    b.windows = [_win(10, 50)]   # only the pre-existing foreign sandbox shows an error
    assert b.start_error() is None


def test_dismiss_closes_only_our_dialog_and_processes(patched, monkeypatch):
    b = _backend(monkeypatch, listed=[50, 60, 61], launched=60, before=[50],
                 windows=[_win(10, 50), _win(11, 60)])
    assert b.dismiss_start_error() == [60]
    assert b.pressed == [11]                 # the foreign dialog (hwnd 10) is never answered
    assert 50 not in b.killed and set(b.killed) <= {60, 61}


def test_dismiss_without_our_dialog_touches_nothing(patched, monkeypatch):
    b = _backend(monkeypatch, listed=[50, 60], launched=60, before=[50], windows=[_win(10, 50)])
    assert b.dismiss_start_error() == [] and b.pressed == [] and b.killed == []


# ---------------------------------------------------------------- runner integration (fake backend)
class Probe(FakeSandbox):
    """FakeSandbox + memory status + (optional) a start-error dialog that keeps the process alive."""

    def __init__(self, memory=None, dialog=False, **kw):
        super().__init__(**kw)
        self.memory, self.dialog = memory, dialog
        self.start_calls, self.dismissed = 0, 0

    def memory_status(self):
        return self.memory

    def start(self, wsb_path):
        self.start_calls += 1
        if self.dialog:
            with self._mu:
                self.pids_before = set(self.pids)
                self.pids = [7]         # WindowsSandbox.exe stays alive, showing the dialog
            return
        super().start(wsb_path)

    def start_error(self):
        return ERR if self.dialog and self.pids else None

    def dismiss_start_error(self):
        self.dismissed += 1
        return [7]


def test_low_memory_returns_resource_unavailable_without_starting(cfg, target):
    sb = Probe(memory={"avail_phys_mb": 1500, "avail_commit_mb": 20000})
    run = go(cfg, target, sb)
    assert run.status is Status.ERROR and run.code == Code.RESOURCE_UNAVAILABLE
    assert sb.start_calls == 0 and run.attempts == 0
    assert "available RAM 1500 MB" in run.detail
    assert not _state_file().exists()   # a refusal is not a failed start


def test_enough_memory_starts_normally(cfg, target):
    sb = Probe(memory={"avail_phys_mb": 9000, "avail_commit_mb": 20000})
    run = go(cfg, target, sb)
    assert run.ok, (run.code, run.detail)
    assert sb.start_calls == 1


def test_error_dialog_ends_the_attempt_fast_dismisses_and_retries_once(cfg, target):
    sb = Probe(dialog=True)
    t = time.monotonic()
    run = go(cfg, target, sb, boot_allowance_s=60)       # without dialog detection this would wait ~60 s per attempt
    assert time.monotonic() - t < 10
    assert sb.start_calls == 2 and sb.dismissed == 2 and sb.kill_calls >= 2
    assert run.code == Code.RESOURCE_UNAVAILABLE and "0x800705aa" in run.detail


def test_memory_collapse_after_first_failure_skips_the_retry(cfg, target):
    class Shrinking(Probe):
        def memory_status(self):
            # fine for the pre-check, short once the first attempt failed
            return {"avail_phys_mb": 9000 if self.start_calls == 0 else 900, "avail_commit_mb": 20000}
    sb = Shrinking(dialog=True)
    run = go(cfg, target, sb)
    assert sb.start_calls == 1 and run.code == Code.RESOURCE_UNAVAILABLE


def _state_file():
    return hostres.state_dir() / hostres.BACKOFF_FILE


def test_failed_attempts_move_the_machine_wide_counter_across_data_roots(cfg, target, tmp_path):
    go(cfg, target, Probe(dialog=True))   # 2 launches, both fail
    assert json.loads(_state_file().read_text(encoding="ascii"))["failures"] == 2
    assert not (cfg.data_root / "sandbox" / "resource_backoff.json").exists()
    _state_file().write_text(json.dumps({"failures": 2, "until": time.time() - 1}), encoding="ascii")  # backoff elapsed
    other = Config.load(tmp_path / "another_root")   # another run, another data root: same counter
    sb = Probe(dialog=True)
    run = go(other, target, sb, retry_backoff_s=0.01)
    assert run.code == Code.RESOURCE_UNAVAILABLE
    assert sb.start_calls == 1                       # 3rd consecutive failure engages the cool-down: no retry
    assert hostres.Backoff(_state_file(), 1.0).cooling_down()


def test_cooldown_refuses_instantly_without_any_launch(cfg, target, tmp_path):
    _state_file().parent.mkdir(parents=True, exist_ok=True)
    _state_file().write_text(json.dumps({"failures": 3, "until": time.time() + 500}), encoding="ascii")
    for root in (cfg, Config.load(tmp_path / "x")):
        sb = Probe(memory={"avail_phys_mb": 9000, "avail_commit_mb": 20000})
        t = time.monotonic()
        run = go(root, target, sb)
        assert time.monotonic() - t < 2
        assert sb.start_calls == 0 and run.attempts == 0 and run.code == Code.RESOURCE_UNAVAILABLE
        assert "retry_after_s=" in run.detail


def test_compute_path_shares_the_cooldown(cfg, tmp_path):
    from redharness.compute import runner as compute
    src = open(compute.__file__, encoding="utf-8").read()
    assert "_run_locked" in src            # compute calls sandbox._run_locked, where the pre-check and counter live
    _state_file().parent.mkdir(parents=True, exist_ok=True)
    _state_file().write_text(json.dumps({"failures": 3, "until": time.time() + 500}), encoding="ascii")
    sb = Probe()
    from redharness.sandbox import runner as sbx
    import redharness.core.journal as j
    journal = j.Journal(tmp_path / "j.jsonl")
    try:
        run = sbx._run_locked(cfg, sb, journal, "cmp_x", SHA, tmp_path, "t.exe", [RunCase(stdin="x")], 5.0, [],
                              time.monotonic(), 3, 0.01, 0.02, 1024, 0.05, ())
    finally:
        journal.close()
    assert run.code == Code.RESOURCE_UNAVAILABLE and sb.start_calls == 0


def test_failure_detail_reports_measured_memory(cfg, target):
    sb = Probe(dialog=True, memory={"avail_phys_mb": 9000, "avail_commit_mb": 20000, "free_zero_mb": 1500,
                                    "standby_mb": 4000})
    run = go(cfg, target, sb)
    assert "free+zeroed 1500 MB" in run.detail and "standby 4000 MB" in run.detail


def test_short_cooldown_is_waited_out_then_success_resets_backoff(cfg, target):
    path = _state_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"failures": 1, "until": time.time() + 0.3}), encoding="ascii")
    sb = Probe()
    t = time.monotonic()
    run = go(cfg, target, sb, retry_backoff_s=1.0)        # base 1 s: a 0.3 s cooldown is below base*3, so it is waited
    assert run.ok, (run.code, run.detail)
    assert time.monotonic() - t >= 0.25
    assert json.loads(path.read_text(encoding="ascii"))["failures"] == 0


def test_backend_without_new_hooks_is_unaffected(cfg, target):
    sb = FakeSandbox()          # no memory_status / start_error: behavior exactly as before
    assert go(cfg, target, sb).ok


def test_windows_sandbox_backend_refuses_off_windows(monkeypatch, tmp_path):
    """Off Windows the backend reports itself unavailable with the platform as the reason (never a bogus path)."""
    from redharness.sandbox import backend as backend_mod
    exe = tmp_path / "WindowsSandbox.exe"
    exe.write_bytes(b"MZ")                       # even a present file does not make it available
    monkeypatch.setattr(backend_mod.sys, "platform", "linux")
    ok, why = WindowsSandboxBackend(exe).available()
    assert not ok and "only on Windows" in why
