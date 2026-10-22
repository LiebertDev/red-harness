"""Starts the emulation worker as a bounded child process (Job Object: memory cap, wall-clock cap, process tree).

The child is the same interpreter in isolated mode (`-I`); the package root of THIS harness is put on its path so it
runs the same code as the server. The emulator's own instruction and time limits stop the emulation first; the
wall-clock cap here is the backstop (emulation time x runs + start-up margin).
"""

from __future__ import annotations

import json
import site
import sys
from pathlib import Path

from ..core.proc import run_bounded
from ..core.result import Status
from .engine import RUNS

MEMORY_LIMIT = 1 << 30
STARTUP_MARGIN_S = 20.0
RESULT_MAX = 4 << 20


class WorkerError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message


def _argv() -> list[str]:
    """The REAL interpreter, not a venv launcher: on Windows a venv's python.exe starts the base interpreter as a child
    process, which the one-process job limit forbids. The package root of this harness goes first on the path, then
    this environment's site-packages directories (for the emulator package; their .pth files are not processed)."""
    root = str(Path(__file__).resolve().parents[2])
    exe = getattr(sys, "_base_executable", None) or sys.executable
    boot = ("import sys; sys.path[0:0] = sys.argv[1:2]; sys.path += sys.argv[2:]; "
            "from redharness.emulate.worker import main; raise SystemExit(main())")
    return [exe, "-I", "-c", boot, root, *site.getsitepackages()]


def run_in_worker(target_path: str, target_sha256: str, request: dict) -> dict:
    job = {"target_path": target_path, "target_sha256": target_sha256, "request": request}
    return _run(job, RUNS * request["timeout_ms"] / 1000 + STARTUP_MARGIN_S)


def probe_worker(write_dir: str) -> dict:
    """Starts a hardened worker that only reports what it can do (Low integrity? file created in `write_dir`? child
    process started?). Used by tests and as an operator diagnostic."""
    return _run({"probe": {"write_dir": write_dir}}, STARTUP_MARGIN_S + 20)


def _run(job_obj: dict, timeout: float) -> dict:
    if sys.platform != "win32":
        # The worker's hardening (Low integrity, one-process Job Object) exists only on Windows. Refuse rather than
        # run emulation unhardened.
        raise WorkerError("EMULATE_PLATFORM_UNSUPPORTED",
                          "emulate needs the Windows worker hardening (Low integrity level, one-process Job Object), "
                          "which is not available on this platform. No code was run.")
    job = json.dumps(job_obj).encode()
    # one active process: the worker cannot start children; the worker lowers itself to Low integrity (worker.py)
    r = run_bounded(_argv(), timeout_s=timeout, memory_limit_bytes=MEMORY_LIMIT, input_bytes=job,
                    head_bytes=RESULT_MAX, tail_bytes=0, active_process_limit=1)
    if r.status is Status.TIMEOUT:
        raise WorkerError("EMU_LIMIT", f"the emulation worker exceeded its wall-clock cap ({timeout:g} s)")
    if r.status is Status.MEMORY_LIMIT:
        raise WorkerError("EMU_LIMIT", f"the emulation worker exceeded its memory cap ({MEMORY_LIMIT >> 20} MiB)")
    if r.status is not Status.OK:
        tail = r.stderr[-800:].decode("utf-8", "replace")
        raise WorkerError("EMU_WORKER_FAILED", f"emulation worker failed ({r.detail}); stderr tail: {tail}")
    try:
        res = json.loads(r.stdout.decode("utf-8"))
    except ValueError as e:
        raise WorkerError("EMU_WORKER_FAILED", f"emulation worker returned no valid result ({e})") from e
    if not isinstance(res, dict):
        raise WorkerError("EMU_WORKER_FAILED", "emulation worker returned no result object")
    return res
