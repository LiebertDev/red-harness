"""Job lock: PID + process start time + host. A lock whose holder is dead or whose start time does not match
(PID reuse) is reclaimed. The lock file is created atomically with full content (tmp + os.link).

Stale-lock reclaim is SERIALIZED by an operating-system lock (msvcrt.locking on Windows, fcntl.flock on POSIX) on the `<lock>.reclaim` file; if the
process dies the OS lock drops by itself, so there is no stale-guard-file problem. The old "move aside with
os.replace, then verify" approach briefly detached a LIVE lock freshly taken by another process from the lock
path (a third process could slip in and create double ownership). Now: under the guard the lock is re-read; if
it is still stale it is removed with unlink and recreated with os.link. The lock path is never replaced with
someone else's live lock; the loser gets LockHeldError.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

from .procinfo import process_start_time

if sys.platform == "win32":
    import msvcrt
else:
    import fcntl


def _os_lock(fd: int) -> None:
    """Non-blocking exclusive OS lock on the fd; OSError if another process holds it."""
    if sys.platform == "win32":
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    else:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _os_unlock(fd: int) -> None:
    if sys.platform == "win32":
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)


class LockError(Exception):
    pass


class LockHeldError(LockError):
    pass


@dataclass(frozen=True)
class LockInfo:
    pid: int
    start_time: int
    host: str
    token: str

    def to_bytes(self) -> bytes:
        return json.dumps(asdict(self), sort_keys=True).encode()

    @classmethod
    def parse(cls, raw: bytes) -> "LockInfo":
        try:
            d = json.loads(raw.decode())
            return cls(int(d["pid"]), int(d["start_time"]), str(d["host"]), str(d["token"]))
        except (ValueError, KeyError, TypeError) as e:
            raise LockError(f"lock file corrupt (delete it by hand): {e!r}") from e


def holder_alive(info: LockInfo) -> bool:
    """Is the holder alive? Another host cannot be verified -> treat as held. PID reuse is filtered out by the start time."""
    if info.host != socket.gethostname():
        return True
    start = process_start_time(info.pid)
    return start is not None and start == info.start_time


class JobLock:
    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self.info: LockInfo | None = None
        self.reclaimed_from: LockInfo | None = None

    def acquire(self) -> LockInfo | None:
        """Acquires the lock. If a stale lock was reclaimed, returns the old holder's LockInfo (otherwise None)."""
        pid = os.getpid()
        start = process_start_time(pid)
        if start is None:
            raise LockError("could not read own process start time")
        mine = LockInfo(pid, start, socket.gethostname(), uuid.uuid4().hex)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self._create(mine):
            self.info, self.reclaimed_from = mine, None
            return None
        with self._reclaim_guard():
            # Under the guard: only this process can remove/change the lock (fresh acquirers only do os.link,
            # which fails while the file exists).
            for _ in range(3):
                try:
                    raw = self.path.read_bytes()
                except FileNotFoundError:
                    raw = None
                if raw is None:
                    stale = None
                else:
                    holder = LockInfo.parse(raw)
                    if holder_alive(holder):
                        raise LockHeldError(f"lock held: pid={holder.pid} host={holder.host}")
                    stale = holder
                    try:
                        os.unlink(self.path)  # holder is dead: only that lock is removed (content cannot change under the guard)
                    except FileNotFoundError:
                        pass
                if self._create(mine):
                    self.info, self.reclaimed_from = mine, stale
                    return stale
                # os.link failed: an unguarded fresh acquirer slipped in; the loop sees it is alive and refuses.
        raise LockHeldError("could not acquire lock (race)")

    @contextlib.contextmanager
    def _reclaim_guard(self, wait_s: float = 10.0):
        guard = self.path.with_name(self.path.name + ".reclaim")
        fd = os.open(guard, os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0))
        deadline = time.monotonic() + wait_s
        try:
            while True:
                try:
                    os.lseek(fd, 0, os.SEEK_SET)
                    _os_lock(fd)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise LockHeldError("could not acquire reclaim guard (timeout)")
                    time.sleep(0.005)
            try:
                yield
            finally:
                os.lseek(fd, 0, os.SEEK_SET)
                _os_unlock(fd)
        finally:
            os.close(fd)

    def _create(self, info: LockInfo) -> bool:
        tmp = self.path.with_name(f".{self.path.name}.{info.token}.tmp")
        with open(tmp, "wb") as f:
            f.write(info.to_bytes())
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(tmp, self.path)
            return True
        except FileExistsError:
            return False
        finally:
            os.unlink(tmp)

    def release(self) -> None:
        if self.info is None:
            return
        try:
            if LockInfo.parse(self.path.read_bytes()).token == self.info.token:
                os.unlink(self.path)
        except FileNotFoundError:
            pass
        self.info = None

    def __enter__(self) -> "JobLock":
        self.acquire()
        return self

    def __exit__(self, *exc) -> None:
        self.release()
