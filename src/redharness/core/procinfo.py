"""Process identity helpers that work on Windows and POSIX: the start time (to tell a reused PID from the original
process) and liveness. Windows uses the Win32 API (core/_win.py); Linux reads /proc; other POSIX systems use `ps`."""

from __future__ import annotations

import os
import subprocess
import sys
import zlib

if sys.platform == "win32":
    from ._win import pid_alive, process_start_time  # noqa: F401  (re-exported)
else:
    def process_start_time(pid: int) -> int | None:
        """A number that is stable for the life of the process and differs for a reused PID. None if it is gone."""
        try:
            with open(f"/proc/{pid}/stat", "rb") as f:
                raw = f.read().decode("ascii", "replace")
            # the command name is in parentheses and may contain spaces: split after the LAST ")"
            fields = raw[raw.rindex(")") + 2:].split()
            if fields[0] == "Z":     # zombie: it has exited
                return None
            return int(fields[19])   # field 22 (starttime, clock ticks since boot)
        except (OSError, ValueError, IndexError):
            pass
        if os.path.isdir("/proc/self"):
            return None              # /proc exists, so the process does not
        try:
            out = subprocess.run(["ps", "-p", str(pid), "-o", "lstart="], capture_output=True, text=True,
                                 timeout=5).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return None
        return zlib.crc32(out.encode()) if out else None

    def pid_alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return process_start_time(pid) is not None
