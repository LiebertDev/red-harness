"""General test harness: tests must not touch the REAL RH_DATA_ROOT (including machine-wide locks); real Sandbox
tests are skipped without RH_ALLOW_REAL_SANDBOX=1 (so agents cannot start Windows Sandbox by accident)."""
import os
import sys

import pytest

ENV_ALLOW_REAL_SANDBOX = "RH_ALLOW_REAL_SANDBOX"
ENV_ALLOW_HYPERV = "RH_ALLOW_HYPERV"


def real_sandbox_allowed() -> bool:
    return os.environ.get(ENV_ALLOW_REAL_SANDBOX) == "1"


@pytest.fixture(autouse=True)
def _isolated_data_root(request, tmp_path, monkeypatch):
    """In unit tests RH_DATA_ROOT is a temp directory. Real sandbox tests (when allowed) use the real root so that
    they go through the machine-wide lock."""
    if "real_sandbox" in request.keywords:
        return
    monkeypatch.setenv("RH_DATA_ROOT", str(tmp_path / "rh_root"))


@pytest.fixture
def emulate_host_windows(monkeypatch):
    """Tests of what emulate does (stops, arguments, evidence) run it in-process through `hub.emulate_runner`; they must
    not depend on the host operating system, so the availability layer sees a Windows host. The off-Windows refusal
    itself is tested with an explicit platform (tests/unit/test_availability.py, test_emulate.py)."""
    from redharness.mcp import availability
    monkeypatch.setattr(availability, "host_platform", lambda: availability.EMULATE_PLATFORM)


@pytest.fixture(autouse=True)
def _fake_windows_system_root(tmp_path_factory, monkeypatch):
    """Hub tests with a fake sandbox run `run_controlled` through the real handler, which copies the host's VC++ runtime
    DLLs next to the target. Off Windows there are none, so the same tests would stop with SANDBOX_UNAVAILABLE; give them
    a fake SystemRoot there (on Windows the real one is used, as before). Tests that pass `system_root=` or patch
    `vc_runtime_files` themselves are unaffected."""
    if sys.platform == "win32":
        return
    root = tmp_path_factory.mktemp("fake_systemroot")
    (root / "System32").mkdir()
    for n in ("vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll"):
        (root / "System32" / n).write_bytes(b"dll-" + n.encode())
    monkeypatch.setenv("SystemRoot", str(root))


@pytest.fixture(autouse=True)
def _isolated_state_dir(request, tmp_path, monkeypatch):
    """The machine-wide sandbox failure counter must not be read or poisoned by unit tests (fake failures)."""
    if "real_sandbox" in request.keywords:
        return
    monkeypatch.setenv("RH_STATE_DIR", str(tmp_path / "rh_state"))


def pytest_collection_modifyitems(config, items):
    skip_hv = pytest.mark.skip(reason=f"real Hyper-V test: {ENV_ALLOW_HYPERV}=1 is not set")
    skip_sb = pytest.mark.skip(reason=f"real Windows Sandbox test: {ENV_ALLOW_REAL_SANDBOX}=1 is not set")
    for it in items:
        if "hyperv" in it.keywords and os.environ.get(ENV_ALLOW_HYPERV) != "1":
            it.add_marker(skip_hv)
        if "real_sandbox" in it.keywords and not real_sandbox_allowed():
            it.add_marker(skip_sb)
