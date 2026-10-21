"""Session-level shared fixtures for heavy (real engine) tests.

The first Ghidra analysis takes ~3 min; data_root is shared for the whole session so that several test files use
the same cache. If `RH_HEAVY_DATA_ROOT` is given that directory is used (the cache is reused during development);
otherwise a temp directory.
"""
import os
import shutil
from pathlib import Path

import pytest

NOTEPAD = Path(r"C:\Windows\System32\notepad.exe")


@pytest.fixture(scope="session")
def heavy_data_root(tmp_path_factory):
    env = os.environ.get("RH_HEAVY_DATA_ROOT")
    if env:
        p = Path(env)
        p.mkdir(parents=True, exist_ok=True)
        return p
    return tmp_path_factory.mktemp("rh_heavy_data")


@pytest.fixture(scope="session")
def notepad_copy(tmp_path_factory):
    if not NOTEPAD.is_file():
        pytest.skip("notepad.exe not found")
    p = tmp_path_factory.mktemp("target") / "notepad_copy.exe"
    shutil.copyfile(NOTEPAD, p)
    return p
