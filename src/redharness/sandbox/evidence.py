"""Converts a run_controlled result into execution evidence (rh.evidence/1, authority=controlled-replay).

Only builds the record; writing it to the ledger is the MCP integration's job (Ledger.record_evidence).

Format decisions:
- `raw` = stdout + "\\n--- stderr ---\\n" + stderr (the verifier searches quotes in this blob; both streams in one blob).
  The per-stream CAS blobs and byte lengths live in `result`, so the split point is never ambiguous.
- Only observations enter the identity (ev_): argv/stdin, exit code, stream sizes/digests, status. Duration
  (elapsed_ms), run_id and time do not; same input + same observation = same evidence id (resume/idempotency).
- `capture.status` is the case status: OK only for a case in a clean session that was not interrupted, finished
  in time and yielded an exit code. A non-zero exit code does not spoil OK (exit 1 for a rejected key is a valid observation).
- If the session did not end cleanly (run.code set) the case status is downgraded to PARTIAL even if it was OK (defense: the runner does this too).
- `coverage.relationship=partial`: a single run does not cover the input space; it cannot support an absence claim.
"""

from __future__ import annotations

from typing import Any

from ..core.cas import Cas
from ..core.result import Status
from ..evidence.model import build_evidence
from .model import ISOLATION, MAX_STREAM_BYTES, CaseResult, Code, SandboxRun

TOOL = "run_controlled"
TOOL_VERSION = "0.1.0"
STDERR_MARK = b"\n--- stderr ---\n"
STDIN_INLINE_MAX = 1024

ENVIRONMENT = {"id": "windows-sandbox", "platform": "windows", "architecture": "x64", "isolation": ISOLATION,
               "networking": "disabled", "input_mount": "read-only", "output_mount": "separate-writable"}

LIMITATIONS = (
    "isolation=windows-sandbox is the runner's declaration; actual sandbox use was not independently verified",
    "output integrity: the target's stdout/stderr come from a runner-owned pipe and every result record is "
    "HMAC-bound to a one-time host nonce the target cannot read; the host verified it (nonce, SHA-256 of the "
    "streams, exit code) before this evidence was built. Residual risk: a forged result is still possible "
    "through a guest-kernel or sandbox escape (not covered, not measured)",
    "single-run observation: does not cover the whole input space",
)


def build_run_evidence(cas: Cas, run: SandboxRun, case: CaseResult, *, target_sha256: str | None = None,
                       build: str | None = None) -> dict:
    """Evidence record for one case. If the sandbox was never opened (run.sandbox_closed None) there is NO evidence (ValueError)."""
    if run.sandbox_closed is None:
        raise ValueError("sandbox never opened: execution evidence cannot be produced")
    if case.isolation != ISOLATION or run.isolation != ISOLATION:
        raise ValueError("only a windows-sandbox execution counts as evidence")
    sha = target_sha256 or run.target_sha256
    if sha != run.target_sha256:
        raise ValueError("target_sha256 does not match the run's target")
    if run.code == Code.INTEGRITY:
        raise ValueError("INTEGRITY: guest result record could not be verified; no evidence produced")
    has_content = bool(case.stdout or case.stderr or case.exit_code is not None or case.stdout_total
                       or case.stderr_total or case.status in (Status.OK, Status.PARTIAL))
    if has_content and not case.integrity_verified:
        raise ValueError("INTEGRITY: case output was not verified on the host; no evidence produced")
    status = case.status
    limitations = list(LIMITATIONS)
    level = case.isolation_level or run.isolation_level
    if case.integrity_verified and level:  # isolation level used, from the verified record
        limitations.append(f"isolation level: {level}")
    if status is Status.OK and (run.code is not None or run.sandbox_closed is not True):
        status = Status.PARTIAL
    if status is not case.status or run.code is not None:
        limitations.append(f"session did not end cleanly: {run.code or 'sandbox closure unverified'}")
    if status is Status.TOOL_MISSING:
        raise ValueError("TOOL_MISSING produces no evidence")

    raw = case.stdout + STDERR_MARK + case.stderr
    params: dict[str, Any] = {
        "case_index": case.index, "argv": list(case.argv), "stdin_sha256": case.stdin_sha256,
        "stdin_bytes": len((case.stdin or "").encode("utf-8")), "max_stream_bytes": MAX_STREAM_BYTES}
    if case.stdin is not None and len(case.stdin) <= STDIN_INLINE_MAX:
        params["stdin"] = case.stdin
    if build:   # fix verification: the run of the vendor's fixed build says so (original runs carry no such field)
        params["build"] = build
    if run.support_files:  # DLLs placed next to the target must be visible (not silent)
        params["support_files"] = [dict(f) for f in run.support_files]
    if run.side_effects:   # files the target left in the mapped work folder (names are target-controlled, clipped)
        names = [str(x) for x in run.side_effects[:50]]
        params["side_effects"] = [x if len(x) <= 200 else x[:200] + "…[clipped]" for x in names]
        clipped = sum(1 for x in names if len(x) > 200)
        if clipped:
            params["side_effects_names_clipped"] = clipped
        if len(run.side_effects) > 50:
            params["side_effects_total"] = len(run.side_effects)
    result = {"exit_code": case.exit_code, "stdout_bytes": case.stdout_total, "stderr_bytes": case.stderr_total,
              "stdout_blob_sha256": case.stdout_blob, "stderr_blob_sha256": case.stderr_blob,
              "stdout_kept_bytes": len(case.stdout), "stderr_kept_bytes": len(case.stderr)}
    return build_evidence(
        cas, subject_sha256=sha, tool=TOOL, operation="run_controlled", raw=raw, status=status,
        confidence="observed", authority="controlled-replay", parameters=params, tool_version=TOOL_VERSION,
        engine="windows-sandbox", truncated=case.truncated, exit_code=case.exit_code,
        elapsed_ms=case.elapsed_ms, result=result, environment=ENVIRONMENT,
        coverage={"scope": f"case:{case.index}", "relationship": "partial"}, limitations=limitations)


def build_run_evidence_all(cas: Cas, run: SandboxRun) -> list[dict]:
    """One evidence record per case (including failed-status cases: weak, cannot support PROVEN).
    Empty list if the sandbox was never opened."""
    if run.sandbox_closed is None:
        return []
    return [build_run_evidence(cas, run, c) for c in run.cases]
