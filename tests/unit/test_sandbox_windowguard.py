"""Window guard: ctypes calls are mocked; nothing touches real windows."""

from __future__ import annotations

import threading

import pytest

from redharness.sandbox import windowguard as wg


class FakeApi:
    def __init__(self, windows, fg=100):
        self.windows, self.fg = windows, fg
        self.minimized, self.restored = [], []

    def top_windows(self):
        return list(self.windows)

    def foreground(self):
        return self.fg

    def minimize(self, h):
        self.minimized.append(h)

    def set_foreground(self, h):
        self.restored.append(h)
        self.fg = h


class Clock:
    def __init__(self):
        self.t = 0.0

    def now(self):
        return self.t

    def sleep(self, s):
        self.t += s


def run(api, pids=lambda: {7}, duration=1.0, poll=0.2):
    c = Clock()
    wg.watch(pids, api=api, duration_s=duration, poll_s=poll, clock=c.now, sleep=c.sleep)
    return c


def test_minimizes_new_window_once():
    api = FakeApi([(100, 1), (200, 7)])
    run(api)
    assert api.minimized == [200]


def test_new_window_appearing_later_is_minimized_separately():
    api = FakeApi([(200, 7)])
    c = Clock()
    orig = api.top_windows

    def tw():
        if c.t > 0.5:
            api.windows = [(200, 7), (300, 7)]
        return orig()
    api.top_windows = tw
    wg.watch(lambda: {7}, api=api, duration_s=1.0, poll_s=0.2, clock=c.now, sleep=c.sleep)
    assert api.minimized == [200, 300]


def test_stops_after_time_bound():
    api = FakeApi([])
    polls = []
    api.top_windows = lambda: polls.append(1) or []
    c = run(api, duration=1.0, poll=0.2)
    assert len(polls) == 5 and c.t == pytest.approx(1.0)


def test_restores_previous_foreground():
    api = FakeApi([(200, 7)], fg=100)

    calls = []

    def tw():
        if not calls:
            api.fg = 200        # sandbox window grabs focus on first poll only
        calls.append(1)
        return list(api.windows)
    api.top_windows = tw
    run(api)
    assert api.restored == [100]


def test_other_process_windows_untouched():
    api = FakeApi([(100, 1), (101, 2)])
    run(api)
    assert api.minimized == [] and api.restored == []


def test_never_raises():
    class Boom(FakeApi):
        def top_windows(self):
            raise OSError("x")

        def foreground(self):
            raise RuntimeError("y")
    run(Boom([]))
    c = Clock()
    wg.watch(lambda: {7}, api=FakeApi([(200, 7)]), duration_s=1, poll_s=0.2, clock=c.now, sleep=c.sleep)

    def bad_pids():
        raise ValueError("z")
    run(FakeApi([]), pids=bad_pids)
    wg.watch(lambda: {1}, api=None, duration_s=0.0)   # real api construction/failure must not raise either


def test_disabled_is_noop(monkeypatch):
    monkeypatch.setenv(wg.ENV_WINDOW, "normal")
    assert wg.mode() == "normal" and not wg.enabled()
    assert wg.startupinfo() is None
    api = FakeApi([(200, 7)])
    assert wg.start_watcher(lambda: {7}, api=api) is None
    assert api.minimized == []


def test_non_windows_is_noop(monkeypatch):
    monkeypatch.delenv(wg.ENV_WINDOW, raising=False)
    monkeypatch.setattr(wg.sys, "platform", "linux")
    assert not wg.enabled() and wg.startupinfo() is None
    assert wg.start_watcher(lambda: {7}) is None


def test_default_is_minimized_and_unknown_value_falls_back(monkeypatch):
    monkeypatch.delenv(wg.ENV_WINDOW, raising=False)
    assert wg.mode() == "minimized"
    monkeypatch.setenv(wg.ENV_WINDOW, "bogus")
    assert wg.mode() == "minimized"


def test_start_watcher_runs_thread_with_injected_api(monkeypatch):
    monkeypatch.delenv(wg.ENV_WINDOW, raising=False)
    api = FakeApi([(200, 7)])
    t = wg.start_watcher(lambda: {7}, api=api, duration_s=0.3, poll_s=0.05)
    assert isinstance(t, threading.Thread)
    t.join(5)
    assert api.minimized == [200]


@pytest.mark.skipif(wg.sys.platform != "win32", reason="STARTUPINFO is Windows only")
def test_startupinfo_flags(monkeypatch):
    monkeypatch.delenv(wg.ENV_WINDOW, raising=False)
    import subprocess
    si = wg.startupinfo()
    assert si.dwFlags & subprocess.STARTF_USESHOWWINDOW and si.wShowWindow == 7


def test_expand_pids_walks_children_and_name_prefix():
    table = [(1, 0, "a.exe"), (7, 1, "WindowsSandbox.exe"), (8, 7, "x.exe"), (9, 8, "y.exe"),
             (20, 0, "WindowsSandboxClient.exe"), (21, 0, "WindowsSandboxOld.exe"), (30, 1, "other.exe")]
    assert wg.expand_pids({7}, table) == {7, 8, 9}
    assert wg.expand_pids({7}, table, "windowssandbox", exclude={21}) == {7, 8, 9, 20}


def test_watch_expands_with_process_table_and_spawns_no_subprocess(monkeypatch):
    import subprocess
    spawned = []
    for name in ("Popen", "run", "check_output", "call"):
        monkeypatch.setattr(subprocess, name, lambda *a, **k: spawned.append(1))
    api = FakeApi([(100, 1), (200, 9)])
    api.process_table = lambda: [(7, 1, "WindowsSandbox.exe"), (9, 7, "client.exe")]
    run(api, pids=lambda: {7})
    assert api.minimized == [200] and spawned == []


@pytest.mark.skipif(wg.sys.platform != "win32", reason="Windows only")
def test_win32_ctypes_wrapper_real_calls():
    import os
    api = wg._Win32()
    assert any(p == os.getpid() for p, _pp, _n in api.process_table())
    assert all(isinstance(h, int) for h, _ in api.top_windows())


def test_prev0_is_the_restore_target_even_if_a_sandbox_window_already_owns_focus():
    api = FakeApi([(200, 7)], fg=200)        # the sandbox window grabbed focus before the first poll
    api.window_pid = lambda h: {100: 1, 200: 7}[h]
    c = Clock()
    wg.watch(lambda: {7}, api=api, duration_s=1.0, poll_s=0.2, clock=c.now, sleep=c.sleep, prev0=100)
    assert api.restored and set(api.restored) == {100}


def test_window_of_an_exited_process_is_not_a_restore_target():
    api = FakeApi([(200, 7)], fg=100)
    api.process_table = lambda: [(7, 1, "WindowsSandbox.exe"), (1, 0, "explorer.exe")]   # pid 9 (launcher stub) is gone
    pids_of = {100: 1, 150: 9, 200: 7}
    api.window_pid = lambda h: pids_of[h]
    seq = iter([150, 200, 200])
    c = Clock()
    api.foreground = lambda: next(seq, api.fg) if not api.restored else api.fg
    wg.watch(lambda: {7}, api=api, duration_s=0.6, poll_s=0.2, clock=c.now, sleep=c.sleep, prev0=100)
    assert api.restored and set(api.restored) == {100}
