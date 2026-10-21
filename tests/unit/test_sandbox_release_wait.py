"""Bounded waiting, after shutdown, for the sandbox VM to leave HCS (partition memory released).
Real hcsdiag/Sandbox is NOT used: the backend's `compute_systems`/`running_processes` are replaced by fakes.
Real measurement: after the sandbox processes die the VM stays 'Running' ~1.3-1.6 s more (then 'Unknown', then gone)."""
import time

from redharness.sandbox import backend as be
from redharness.sandbox.backend import WindowsSandboxBackend, parse_hcsdiag

TEMPLATE = "VM,                       \tSavedAsTemplate, 951A2193-E508-40CC-A9D3-F1A7B109A474, CmService"
RUNNING = "VM,                       \tRunning, 56FCEFB7-0003-4916-9444-3A2E33721EC3, Madrid"


def test_parse_hcsdiag_skips_template_and_keys_by_guid():
    text = "951a2193-e508-40cc-a9d3-f1a7b109a474\r\n" + TEMPLATE + "\r\n56fcefb7-0003-4916-9444-3a2e33721ec3\r\n" + RUNNING + "\r\n"
    assert parse_hcsdiag(text) == ["56fcefb7-0003-4916-9444-3a2e33721ec3"]
    assert parse_hcsdiag("VM,                       \tUnknown\r\n") == ["Unknown"]   # transient row without a GUID: state name
    assert parse_hcsdiag("") == [] and parse_hcsdiag(TEMPLATE) == []


class FakeHcs(WindowsSandboxBackend):
    """Process list empty; the HCS list is returned in `script` order (the last element repeats forever)."""

    def __init__(self, script, procs=()):
        super().__init__()
        self.script, self.procs, self.polls = list(script), list(procs), 0

    def running_processes(self):
        return list(self.procs)

    def compute_systems(self):
        i = min(self.polls, len(self.script) - 1)
        self.polls += 1
        return self.script[i]


def test_kill_all_waits_until_our_vm_leaves_hcs(monkeypatch):
    monkeypatch.setattr(be, "HCS_POLL_S", 0.01)
    b = FakeHcs([["g-ours"], ["g-ours"], ["Unknown"], []])
    b._vms_before = set()
    assert b.kill_all(5.0) == []
    assert b.polls == 4                                  # polled until the VM left (did not give up on the first return)


def test_other_vms_present_before_start_do_not_delay_close(monkeypatch):
    monkeypatch.setattr(be, "HCS_POLL_S", 0.01)
    b = FakeHcs([["wsl-vm"]])                            # a VM that is not ours, like WSL, is always there
    b._vms_before = {"wsl-vm"}
    t = time.monotonic()
    assert b.kill_all(5.0) == [] and b.polls == 1 and time.monotonic() - t < 1.0


def test_vm_release_wait_is_bounded_and_does_not_fail_the_close(monkeypatch):
    monkeypatch.setattr(be, "HCS_POLL_S", 0.01)
    monkeypatch.setattr(be, "HCS_RELEASE_WAIT_S", 0.15)
    b = FakeHcs([["g-stuck"]])                           # the VM never leaves
    b._vms_before = set()
    t = time.monotonic()
    assert b.kill_all(5.0) == []                         # the close result does NOT change (processes gone); only a bounded wait
    assert 0.1 <= time.monotonic() - t < 2.0 and not b.wait_vm_released(0.05)


def test_hcsdiag_unavailable_or_no_start_means_no_wait():
    b = FakeHcs([None])
    b._vms_before = set()
    assert b.wait_vm_released(1.0) is True and b.polls == 1     # unknown: no wait
    c = FakeHcs([["g-x"]])                                       # start() never called (recovery path): no wait
    assert c._vms_before is None and c.kill_all(1.0) == [] and c.polls == 0


def test_kill_all_still_reports_surviving_sandbox_processes(monkeypatch):
    monkeypatch.setattr(be.subprocess, "run", lambda *a, **k: None)   # taskkill is not called
    monkeypatch.setattr(be.time, "sleep", lambda s: None)
    b = FakeHcs([[]], procs=[4242])
    b._vms_before = set()
    assert b.kill_all(0.0) == [4242] and b.polls == 0
