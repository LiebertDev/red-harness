"""Machine-wide resource locks: a single Windows Sandbox + mutual exclusion of sandbox and heavy engine (IDA, Ghidra).

The two lock files live under `locks/` in `RH_DATA_ROOT` (default data_root if unset):
- `sandbox-global.lock`: at most ONE sandbox session at a time (all sandbox users share it).
- `heavy.lock`: held while heavy engine work (IDA/Ghidra) or the sandbox runs. The sandbox tries to take it WITHOUT
  waiting; if it cannot, it returns BUSY. The engine side (`HeavyGate`) waits until the sandbox finishes.
Why: Hyper-V partition resource (0x800705AA) and memory budget; the sandbox and a 6 GB engine must not run at once.
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path

from ..config import default_data_root
from .lock import JobLock, LockError

ENV_HEAVY_WAIT = "RH_HEAVY_WAIT_S"
DEFAULT_HEAVY_WAIT_S = 600.0


def locks_dir() -> Path:
    return default_data_root() / "locks"


def sandbox_global_lock() -> JobLock:
    return JobLock(locks_dir() / "sandbox-global.lock")


def heavy_lock() -> JobLock:
    return JobLock(locks_dir() / "heavy.lock")


class HeavyGate:
    """Replaces `engines._common.HEAVY` (`with HEAVY:`): one heavy operation per process + machine-wide `heavy.lock`.
    If the file lock cannot be taken within the wait time (the sandbox is running long), the work proceeds anyway and
    no marker is set: silently dropping the engine job is worse than erroring because of the lock."""

    def __init__(self, wait_s: float | None = None):
        self._mu = threading.Lock()
        self._wait_s = wait_s
        self._file: JobLock | None = None

    def _wait(self) -> float:
        if self._wait_s is not None:
            return self._wait_s
        try:
            return float(os.environ.get(ENV_HEAVY_WAIT, DEFAULT_HEAVY_WAIT_S))
        except ValueError:
            return DEFAULT_HEAVY_WAIT_S

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        if not self._mu.acquire(blocking, timeout):
            return False
        lock = heavy_lock()
        deadline = time.monotonic() + self._wait()
        while True:
            try:
                lock.acquire()
                self._file = lock
                break
            except (LockError, OSError):
                if time.monotonic() >= deadline:
                    self._file = None
                    break
                time.sleep(0.5)
        return True

    def release(self) -> None:
        f, self._file = self._file, None
        try:
            if f is not None:
                f.release()
        finally:
            self._mu.release()

    def locked(self) -> bool:
        return self._mu.locked()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc) -> None:
        self.release()
