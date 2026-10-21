"""run_controlled data model: input (RunCase), case result (CaseResult), session result (SandboxRun)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core.result import Status

ISOLATION = "windows-sandbox"
MAX_STREAM_BYTES = 1 << 20  # per-case stdout/stderr cap; excess is truncated and flagged
MAX_CASES = 32
MAX_STDIN_BYTES = 1 << 20
MAX_ARGV = 64
MAX_TIMEOUT_S = 300.0


class Code:
    """Error codes (SandboxRun.code). None = clean session. The result status (Status) is always given separately."""
    BUSY = "BUSY"                          # lock is held or another Windows Sandbox is running
    SCOPE_DENIED = "SCOPE_DENIED"
    SHA_MISMATCH = "SHA_MISMATCH"
    TARGET_MISSING = "TARGET_MISSING"
    INVALID_INPUT = "INVALID_INPUT"
    SANDBOX_UNAVAILABLE = "SANDBOX_UNAVAILABLE"
    JOURNAL_CORRUPT = "JOURNAL_CORRUPT"
    SESSION_TIMEOUT = "SESSION_TIMEOUT"    # done marker did not arrive in time
    SANDBOX_CRASHED = "SANDBOX_CRASHED"    # sandbox closed before finishing / guest errored
    SANDBOX_NOT_CLOSED = "SANDBOX_NOT_CLOSED"  # shutdown unverified: processes still running
    GUEST_HASH_MISMATCH = "GUEST_HASH_MISMATCH"  # target SHA-256 inside the sandbox differs from the expected one
    BAD_OUTPUT = "BAD_OUTPUT"              # output folder not in the expected form (symlink, corrupt JSON...)
    START_FAILED = "START_FAILED"
    RESOURCE_UNAVAILABLE = "RESOURCE_UNAVAILABLE"  # Sandbox/Hyper-V could not start or closed before the ready marker
    INTERRUPTED = "INTERRUPTED"            # half-finished session (recover): job FAILED
    RECOVERY_FAILED = "RECOVERY_FAILED"    # half-finished session could not be cleaned up
    INTEGRITY = "INTEGRITY"                # guest result record failed host verification: no evidence produced
    KERNEL_TARGET_NO_USERMODE_RUN = "KERNEL_TARGET_NO_USERMODE_RUN"  # kernel-mode image (driver / NATIVE): never run in Win32 mode


@dataclass(frozen=True)
class GuestTool:
    """A pinned host file staged into the guest (`in/tools/<name>`), e.g. the dynamic-observation tracer."""
    name: str            # [A-Za-z0-9._-]{1,64}.exe
    path: Path
    sha256: str


@dataclass(frozen=True)
class ObservePlan:
    """Observed executions in the SAME session (dynamic observation): after the plain cases, every case runs once
    more under `tool`. `args[i]` is the tool's argument prefix for case i (the guest appends the target path and the
    case argv line). The tool's stdout (the trace) comes back like any case output, MAC'd by the guest."""
    tool: GuestTool
    args: tuple[str, ...]
    timeout_s: float     # per observed execution (guest kill limit; the tool enforces its own, shorter deadline)


@dataclass(frozen=True)
class RunCase:
    """One run case: argv and/or stdin text. There is NO expected observation; the result is only observed."""
    stdin: str | None = None
    argv: tuple[str, ...] = ()

    def __post_init__(self):
        object.__setattr__(self, "argv", tuple(self.argv))

    def stdin_bytes(self) -> bytes:
        return (self.stdin or "").encode("utf-8")


@dataclass
class CaseResult:
    index: int
    argv: tuple[str, ...]
    stdin: str | None
    stdin_sha256: str
    status: Status
    detail: str = ""
    exit_code: int | None = None
    stdout: bytes = b""
    stderr: bytes = b""
    stdout_total: int = 0
    stderr_total: int = 0
    truncated: bool = False
    timed_out: bool = False
    elapsed_ms: int = 0
    stdout_blob: str | None = None   # CAS
    stderr_blob: str | None = None
    isolation: str = ISOLATION
    isolation_level: str = ""        # verified isolation level, e.g. "windows-sandbox+separate-user+low-il"
    integrity_verified: bool = False  # guest record verified on the host (nonce+HMAC+SHA-256)
    meta: dict | None = field(default=None, repr=False)  # verified guest case record (cNNN.json)

    @property
    def ok(self) -> bool:
        return self.status.is_success

    def summary(self) -> dict[str, Any]:
        return {"index": self.index, "status": self.status.value, "detail": self.detail,
                "exit_code": self.exit_code, "elapsed_ms": self.elapsed_ms, "truncated": self.truncated,
                "timed_out": self.timed_out, "stdout_bytes": self.stdout_total, "stderr_bytes": self.stderr_total,
                "stdout_blob_sha256": self.stdout_blob, "stderr_blob_sha256": self.stderr_blob,
                "isolation": self.isolation, "isolation_level": self.isolation_level,
                "integrity_verified": self.integrity_verified}


@dataclass
class SandboxRun:
    run_id: str
    target_sha256: str
    status: Status
    code: str | None = None
    detail: str = ""
    cases: list[CaseResult] = field(default_factory=list)
    sandbox_closed: bool | None = None   # None: sandbox never opened
    workdir_removed: bool | None = None  # None: work folder never created
    recovered_runs: list[str] = field(default_factory=list)  # half-finished sessions marked FAILED in this call
    duration_s: float = 0.0
    isolation: str = ISOLATION
    isolation_level: str = ""             # verified isolation level (from integrity records)
    integrity_verified: bool | None = None  # None: integrity check never reached
    attempts: int = 0                     # number of sandbox launch attempts (max 2: first + one retry)
    integrity_problems: list[str] = field(default_factory=list)  # on INTEGRITY: which record was rejected and why
    support_files: list[dict[str, str]] = field(default_factory=list)  # DLLs placed next to the target: {name, sha256}
    observed: list[CaseResult] = field(default_factory=list)  # observed executions (ObservePlan), index n+i observes case i
    observe_tool: dict[str, str] | None = None                 # {name, sha256} of the staged tool
    side_effects: list[str] = field(default_factory=list)      # files left in the mapped work folder by the target (host-side, before deletion)

    @property
    def ok(self) -> bool:
        return self.status.is_success

    def summary(self) -> dict[str, Any]:
        return {"run_id": self.run_id, "status": self.status.value, "code": self.code, "detail": self.detail,
                "sandbox_closed": self.sandbox_closed, "workdir_removed": self.workdir_removed,
                "recovered_runs": list(self.recovered_runs), "attempts": self.attempts, "duration_s": round(self.duration_s, 1),
                "isolation": self.isolation, "isolation_level": self.isolation_level,
                "integrity_verified": self.integrity_verified, "integrity_problems": list(self.integrity_problems),
                "support_files": [dict(f) for f in self.support_files],
                "cases": [c.summary() for c in self.cases],
                **({"observed": [c.summary() for c in self.observed], "observe_tool": dict(self.observe_tool)}
                   if self.observe_tool else {}),
                **({"side_effects": list(self.side_effects)} if self.side_effects else {})}


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()
