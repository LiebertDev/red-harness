"""General test harness: tests must not touch the REAL RH_DATA_ROOT (including machine-wide locks); real Sandbox
tests are skipped without RH_ALLOW_REAL_SANDBOX=1 (so agents cannot start Windows Sandbox by accident)."""
import os

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
