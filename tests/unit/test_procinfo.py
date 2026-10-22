"""Process identity helpers (core/procinfo.py): the POSIX branch reads /proc (or `ps`); the Windows branch is the
Win32 API and is covered by test_lock.py and test_proc.py."""
import os
import subprocess
import sys

import pytest

from redharness.core.procinfo import pid_alive, process_start_time


def test_own_process_has_a_stable_start_time_and_is_alive():
    a = process_start_time(os.getpid())
    assert isinstance(a, int) and a == process_start_time(os.getpid())
    assert pid_alive(os.getpid())


def test_exited_process_has_no_start_time():
    child = subprocess.Popen([sys.executable, "-c", "pass"])
    child.wait()
    assert process_start_time(child.pid) is None and not pid_alive(child.pid)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX /proc parsing")
def test_start_time_survives_spaces_and_parentheses_in_the_command_name(tmp_path, monkeypatch):
    import builtins
    real_open = builtins.open
    fake = b"4242 (we ird) name) S 1 4242 4242 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 987654 0 0\n"

    def fake_open(path, *a, **k):
        if path == "/proc/4242/stat":
            import io
            return io.BytesIO(fake)
        return real_open(path, *a, **k)
    monkeypatch.setattr(builtins, "open", fake_open)
    assert process_start_time(4242) == 987654
