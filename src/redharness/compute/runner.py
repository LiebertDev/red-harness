"""`compute`: runs model-written Python code TWICE inside Windows Sandbox with a pinned interpreter.

The execution path is THE SAME as `run_controlled` (sandbox/runner.py `_run_locked`): same machine-wide lock, same half-finished
session recovery, same .wsb (network off, input read-only), same guest.ps1 (separate non-admin user + Low IL, runner
pipe, nonce + HMAC output integrity). The only difference is the "target": instead of a target binary, a pinned-digest `python.exe` and
its sibling files (`runtime.py`) are staged; the model's code and inputs are the stdin JSON. Both cases get the same stdin:
if the outputs (stdout, stderr, exit code) are not byte-for-byte identical the result is NONDETERMINISTIC and no evidence is produced.

Scope: the target manifest's `compute` permission (mcp/effects.py) is checked by the caller; here `scope.allows("compute")` is
additionally re-checked as a cheap rejection (defense). Sandbox-specific limits (timeout per case,
per-stream output cap) are enforced by the guest; a timeout is never success.

UNVERIFIED: launching the embeddable CPython with a separate user + Low IL inside a real Windows Sandbox
(tests/heavy/test_compute_real.py, marked real_sandbox, not run).
"""

from __future__ import annotations

import json
import subprocess
import time
import uuid
from dataclasses import dataclass
from typing import Any

from ..config import Config
from ..core.journal import Journal, JournalCorrupt
from ..core.heavy import heavy_lock, sandbox_global_lock
from ..core.lock import JobLock, LockError
from ..core.result import Status
from ..sandbox import runner as sbx
from ..sandbox.backend import SandboxBackend, WindowsSandboxBackend
from ..sandbox.model import Code, RunCase, SandboxRun
from ..scope.manifest import ScopeManifest, sha256_file
from .runtime import BOOT_NAME, Runtime

RUNS = 2                        # determinism: two independent processes with the same input
MAX_CODE_BYTES = 64 * 1024
MAX_INPUTS = 8
MAX_INPUT_BYTES = 1 << 20       # total of all inputs (stdin JSON up to ~1.4 MB with base64)
MAX_OUTPUT_BYTES = 64 * 1024    # per stream (stdout and stderr separately); excess is truncated = not success
DEFAULT_TIMEOUT_S = 30.0
MAX_TIMEOUT_S = 300.0           # wall clock per run; CPU time is bounded by it too (the single process tree is killed)
ARGV = ("-I", "-B", "-X", "utf8", BOOT_NAME)


@dataclass
class ComputeRun:
    run: SandboxRun
    deterministic: bool | None = None   # None: comparison never reached (error/timeout/truncation)


def envelope(code: str, inputs: dict[str, bytes | int]) -> str:
    """rh_boot.py stdin contract (ASCII JSON; fixed key order)."""
    import base64
    enc = {k: ({"b64": base64.b64encode(v).decode("ascii")} if isinstance(v, bytes) else {"int": v})
           for k, v in sorted(inputs.items())}
    return json.dumps({"code": code, "inputs": enc}, ensure_ascii=True, sort_keys=True)


def _scope_problem(scope: Any, target_sha: str) -> str | None:
    if not isinstance(scope, ScopeManifest):
        return "scope manifest is required"
    if not scope.allows("compute"):
        return "scope manifest does not allow 'compute'"
    if scope.target_sha256 != target_sha:
        return "scope manifest target SHA-256 does not match the job's target"
    return None


def run_compute(job_sha: str, scope: ScopeManifest, runtime: Runtime, stdin_text: str, timeout_s: float, *,
                cfg: Config | None = None, backend: SandboxBackend | None = None,
                max_output_bytes: int = MAX_OUTPUT_BYTES, boot_allowance_s: float | None = None,
                poll_interval_s: float = 0.25, proc_check_interval_s: float | None = None,
                retry_backoff_s: float | None = None) -> ComputeRun:
    """Expected situations (rejection, BUSY, timeout...) are not exceptions; they are returned as `ComputeRun.run.status/code`."""
    t0 = time.monotonic()
    run_id = f"cmp_{sbx._now()}_{uuid.uuid4().hex[:8]}"
    cfg = cfg or Config.load()
    backend = backend or WindowsSandboxBackend()

    def fail(status, code, detail, **kw) -> ComputeRun:
        return ComputeRun(sbx._fail(run_id, runtime.exe_sha256, status, code, detail, t0, **kw))

    prob = _scope_problem(scope, job_sha)
    if prob:
        return fail(Status.ERROR, Code.SCOPE_DENIED, prob)
    if (isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float))
            or not 0 < timeout_s <= MAX_TIMEOUT_S):
        return fail(Status.ERROR, Code.INVALID_INPUT, f"timeout_s must be between 0 and {MAX_TIMEOUT_S:g}")
    if len(stdin_text.encode("utf-8")) > 2 * MAX_INPUT_BYTES:
        return fail(Status.ERROR, Code.INVALID_INPUT, "code + inputs too large")
    ok, why = backend.available()
    if not ok:
        return fail(Status.TOOL_MISSING, Code.SANDBOX_UNAVAILABLE, why)
    if sha256_file(runtime.exe_path) != runtime.exe_sha256:   # changed since load_runtime?
        return fail(Status.ERROR, Code.SHA_MISMATCH, "interpreter changed after verification")

    glock, hlock = sandbox_global_lock(), heavy_lock()
    lock = JobLock(sbx.sandbox_dir(cfg) / "sandbox.lock")
    try:
        glock.acquire()
    except LockError as e:
        return fail(Status.ERROR, Code.BUSY, f"another sandbox session is in progress (machine-wide lock): {e}")
    try:
        hlock.acquire()
    except LockError as e:
        glock.release()
        return fail(Status.ERROR, Code.BUSY, f"a heavy engine job is in progress (heavy lock): {e}")
    try:
        lock.acquire()
    except LockError as e:
        hlock.release()
        glock.release()
        return fail(Status.ERROR, Code.BUSY, f"another controlled run is in progress (sandbox lock): {e}")
    journal = None
    try:
        try:
            journal = Journal(sbx.sandbox_dir(cfg) / "journal.jsonl")
        except JournalCorrupt as e:
            return fail(Status.ERROR, Code.JOURNAL_CORRUPT, f"sandbox journal corrupt: {e}")
        recovered, err = sbx._recover(cfg, journal, backend)
        if err:
            return fail(Status.ERROR, Code.RECOVERY_FAILED, err, recovered_runs=recovered)
        try:
            foreign = backend.running_processes()
        except (OSError, subprocess.SubprocessError) as e:
            return fail(Status.ERROR, Code.SANDBOX_UNAVAILABLE, f"could not list sandbox processes: {e}",
                        recovered_runs=recovered)
        if foreign:
            return fail(Status.ERROR, Code.BUSY, f"another Windows Sandbox instance is running (PID {foreign})",
                        recovered_runs=recovered)
        cases = [RunCase(stdin=stdin_text, argv=ARGV) for _ in range(RUNS)]
        support = [p for p in runtime.files if p != runtime.exe_path]
        run = sbx._run_locked(
            cfg, backend, journal, run_id, runtime.exe_sha256, runtime.exe_path, runtime.spec.exe, cases,
            float(timeout_s), recovered, t0,
            sbx.BOOT_ALLOWANCE_S if boot_allowance_s is None else boot_allowance_s, poll_interval_s,
            sbx.PROC_CHECK_INTERVAL_S if proc_check_interval_s is None else proc_check_interval_s,
            max_output_bytes, sbx.RETRY_BACKOFF_S if retry_backoff_s is None else retry_backoff_s, support)
    finally:
        if journal is not None:
            journal.close()
        lock.release()
        hlock.release()
        glock.release()
    return ComputeRun(run, _deterministic(run))


def _deterministic(run: SandboxRun) -> bool | None:
    """Is the observation of the two complete (OK) runs byte-for-byte identical? If not complete, no comparison is made (None)."""
    if run.code is not None or len(run.cases) != RUNS or not all(
            c.status is Status.OK and c.integrity_verified for c in run.cases):
        return None
    a, b = run.cases
    return (a.stdout, a.stderr, a.exit_code, a.stdout_total, a.stderr_total) == \
           (b.stdout, b.stderr, b.exit_code, b.stdout_total, b.stderr_total)
