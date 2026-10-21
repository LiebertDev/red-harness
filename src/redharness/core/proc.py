"""Bounded process runner (Windows Job Object: memory, time, process tree).

Fail-closed: timeout, memory overrun, truncated output, missing tool, nonzero exit and failure to set up the
Job Object never return OK. The process is started suspended (CREATE_SUSPENDED) and resumed after being assigned
to the job, so child processes cannot be born outside the job.

A Job Object is not isolation (for untrusted code use: Windows Sandbox).
"""

from __future__ import annotations

import ctypes
import subprocess
import threading
import time
from dataclasses import dataclass, field
from ctypes import wintypes
from typing import Mapping, Sequence

from . import _win as w
from .result import Status

DEFAULT_HEAD = 64 * 1024
DEFAULT_TAIL = 64 * 1024
READER_JOIN_S = 5.0  # reader thread join time; if exceeded the result is never OK


@dataclass
class RunResult:
    status: Status
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    truncated: bool
    duration_s: float
    detail: str = ""
    stdout_total: int = 0
    stderr_total: int = 0
    orphans_killed: int = 0
    peak_job_memory: int | None = None
    extra: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status.is_success


class _Capture(threading.Thread):
    """Pipe reader: keeps the first `head` bytes + last `tail` bytes, counts and discards the rest; drains the pipe to the end."""

    def __init__(self, stream, head: int, tail: int):
        super().__init__(daemon=True)
        self.stream, self.head_cap, self.tail_cap = stream, head, tail
        self.head = bytearray()
        self.tail = bytearray()
        self.total = 0

    def run(self) -> None:
        try:
            while True:
                chunk = self.stream.read(65536)
                if not chunk:
                    break
                self.total += len(chunk)
                room = self.head_cap - len(self.head)
                if room > 0:
                    self.head += chunk[:room]
                    chunk = chunk[room:]
                if chunk:
                    self.tail += chunk
                    if len(self.tail) > self.tail_cap:
                        del self.tail[: len(self.tail) - self.tail_cap]
        except (OSError, ValueError):
            pass

    @property
    def truncated(self) -> bool:
        return self.total > len(self.head) + len(self.tail)

    def render(self) -> bytes:
        if not self.truncated:
            return bytes(self.head + self.tail)
        dropped = self.total - len(self.head) - len(self.tail)
        return bytes(self.head) + f"\n...[{dropped} bytes truncated]...\n".encode() + bytes(self.tail)


class _Job:
    def __init__(self, memory_limit: int | None, active_process_limit: int | None = None):
        self.h = w.k32.CreateJobObjectW(None, None)
        if not self.h:
            raise OSError(f"CreateJobObject failed: {ctypes.get_last_error()}")
        self.port = None
        self.limit = memory_limit
        info = w.EXTENDED_LIMIT()
        flags = w.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if memory_limit:
            flags |= w.JOB_OBJECT_LIMIT_JOB_MEMORY | w.JOB_OBJECT_LIMIT_PROCESS_MEMORY
            info.JobMemoryLimit = memory_limit
            info.ProcessMemoryLimit = memory_limit
        if active_process_limit:   # e.g. 1: the process in the job cannot create child processes
            flags |= w.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            info.BasicLimitInformation.ActiveProcessLimit = active_process_limit
        info.BasicLimitInformation.LimitFlags = flags
        if not w.k32.SetInformationJobObject(self.h, w.JobObjectExtendedLimitInformation,
                                             ctypes.byref(info), ctypes.sizeof(info)):
            err = ctypes.get_last_error()
            self.close()
            raise OSError(f"SetInformationJobObject(limit) failed: {err}")
        port = w.k32.CreateIoCompletionPort(wintypes.HANDLE(w.INVALID_HANDLE), None, 0, 1)
        if not port:
            err = ctypes.get_last_error()
            self.close()
            raise OSError(f"CreateIoCompletionPort failed: {err}")
        self.port = port
        assoc = w.ASSOC_PORT(None, port)
        if not w.k32.SetInformationJobObject(self.h, w.JobObjectAssociateCompletionPortInformation,
                                             ctypes.byref(assoc), ctypes.sizeof(assoc)):
            err = ctypes.get_last_error()
            self.close()
            raise OSError(f"SetInformationJobObject(port) failed: {err}")

    def assign(self, process_handle: int) -> None:
        if not w.k32.AssignProcessToJobObject(self.h, wintypes.HANDLE(process_handle)):
            raise OSError(f"AssignProcessToJobObject failed: {ctypes.get_last_error()}")

    def memory_exceeded(self) -> bool:
        """Drains the completion port; True if a memory-limit message was seen."""
        hit = False
        n, key, ov = wintypes.DWORD(), w.ULONG_PTR(), wintypes.LPVOID()
        while w.k32.GetQueuedCompletionStatus(self.port, ctypes.byref(n), ctypes.byref(key),
                                              ctypes.byref(ov), 0):
            if n.value in (w.JOB_OBJECT_MSG_JOB_MEMORY_LIMIT, w.JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT):
                hit = True
        return hit

    def active_processes(self) -> int:
        acc = w.BASIC_ACCOUNTING()
        if w.k32.QueryInformationJobObject(self.h, w.JobObjectBasicAccountingInformation,
                                           ctypes.byref(acc), ctypes.sizeof(acc), None):
            return int(acc.ActiveProcesses)
        return 0

    def peak_memory(self) -> int | None:
        info = w.EXTENDED_LIMIT()
        if w.k32.QueryInformationJobObject(self.h, w.JobObjectExtendedLimitInformation,
                                           ctypes.byref(info), ctypes.sizeof(info), None):
            return int(info.PeakJobMemoryUsed)
        return None

    def terminate(self) -> bool:
        """TerminateJobObject; False on failure (the caller kills the process by a fallback and does not return OK)."""
        return bool(self.h) and bool(w.k32.TerminateJobObject(self.h, 1))

    def close(self) -> None:
        for h in (self.h, self.port):
            if h:
                w.k32.CloseHandle(h)
        self.h = self.port = None


def run_bounded(argv: Sequence[str], *, timeout_s: float, memory_limit_bytes: int | None = None,
                input_bytes: bytes | None = None, cwd: str | None = None,
                env: Mapping[str, str] | None = None, head_bytes: int = DEFAULT_HEAD,
                tail_bytes: int = DEFAULT_TAIL, active_process_limit: int | None = None) -> RunResult:
    """Runs the command inside a job. Only Status.OK is success. `active_process_limit=1`: no child processes."""
    t0 = time.monotonic()

    def fail(status: Status, detail: str, **kw) -> RunResult:
        return RunResult(status, None, b"", b"", False, time.monotonic() - t0, detail, **kw)

    if timeout_s is None or timeout_s <= 0:
        return fail(Status.ERROR, "timeout_s must be positive")
    try:
        job = _Job(memory_limit_bytes, active_process_limit)
    except OSError as e:
        return fail(Status.ERROR, f"could not set up job: {e}")
    proc = None
    try:
        try:
            proc = subprocess.Popen(
                list(argv), stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd,
                env=dict(env) if env is not None else None,
                creationflags=w.CREATE_SUSPENDED | subprocess.CREATE_NO_WINDOW)
        except (FileNotFoundError, NotADirectoryError) as e:
            return fail(Status.TOOL_MISSING, f"could not execute: {e}")
        except OSError as e:
            return fail(Status.ERROR, f"could not start: {e}")
        try:
            job.assign(int(proc._handle))
        except OSError as e:
            proc.kill()
            proc.wait()
            return fail(Status.ERROR, f"process could not be assigned to the job (it did not run unbounded): {e}")
        if w.ntdll.NtResumeProcess(wintypes.HANDLE(int(proc._handle))) != 0:
            if not job.terminate():
                proc.kill()
            proc.wait()
            return fail(Status.ERROR, "could not resume process")

        out = _Capture(proc.stdout, head_bytes, tail_bytes)
        err = _Capture(proc.stderr, head_bytes, tail_bytes)
        out.start()
        err.start()
        if input_bytes is not None:
            def feed():
                try:
                    proc.stdin.write(input_bytes)
                    proc.stdin.close()
                except (OSError, ValueError):
                    pass
            threading.Thread(target=feed, daemon=True).start()

        deadline = t0 + timeout_s
        timed_out = mem_hit = False
        while proc.poll() is None:
            if job.memory_exceeded():
                mem_hit = True
                break
            if time.monotonic() >= deadline:
                timed_out = True
                break
            time.sleep(0.01)
        if not (timed_out or mem_hit):
            mem_hit = job.memory_exceeded()
        orphans = job.active_processes() - (0 if proc.poll() is not None else 1)
        peak = job.peak_memory()
        term_ok = job.terminate()  # tree: kill leftovers even if the main process has finished
        if not term_ok:
            proc.kill()  # fallback: at least kill the main process; for descendants KILL_ON_JOB_CLOSE takes effect on close
        rc = proc.wait()
        out.join(READER_JOIN_S)
        err.join(READER_JOIN_S)
        truncated = out.truncated or err.truncated
        duration = time.monotonic() - t0

        if timed_out:
            status, detail = Status.TIMEOUT, f"{timeout_s}s exceeded; " + (
                "process tree killed" if term_ok else "TerminateJobObject FAILED, only the main process was killed")
        elif mem_hit:
            status, detail = Status.MEMORY_LIMIT, f"memory limit exceeded ({memory_limit_bytes} bytes)"
        elif rc != 0:
            status, detail = Status.ERROR, f"exit code {rc}"
        elif not term_ok:
            status, detail = Status.ERROR, "TerminateJobObject failed; process tree could not be cleaned up"
        elif truncated:
            status, detail = Status.PARTIAL, "output truncated (head+tail kept)"
        elif out.is_alive() or err.is_alive():
            status, detail = Status.ERROR, "output readers did not finish"
        else:
            status, detail = Status.OK, ""
        return RunResult(status, None if timed_out else rc, out.render(), err.render(), truncated,
                         duration, detail, out.total, err.total, max(orphans, 0), peak)
    finally:
        if proc is not None and proc.poll() is None:
            if not job.terminate():
                proc.kill()
            proc.wait()
        job.close()
