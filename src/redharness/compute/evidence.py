"""Converts a deterministic, complete `compute` result into evidence (authority=`sandboxed-computation`, confidence=`derived`).

Enters the identity (ev_): code digest, input bindings (evidence id + kind + SHA-256), interpreter identity (zip/exe/bootstrap
SHA-256), limits, output. Does not: duration, run_id, time. Same code + same inputs + same interpreter = same output = same
`ev_` (rerun equality is checked by a test). The code is stored in CAS (`code_sha256`): the evidence can be re-run.
"""

from __future__ import annotations

import hashlib
from typing import Any

from ..core.cas import Cas
from ..core.result import Status
from ..evidence.compute import input_links
from ..evidence.model import COMPUTE_AUTHORITY, build_evidence
from ..sandbox.evidence import ENVIRONMENT
from ..sandbox.model import ISOLATION
from .runner import ARGV, RUNS, ComputeRun
from .runtime import Runtime

TOOL = "compute"
TOOL_VERSION = "0.1.0"
LANGUAGE = "python"

LIMITATIONS = (
    "computation by model-written code: it shows what THIS code outputs on THESE inputs, not what the target does; "
    "whether the code models the target correctly is not verified",
    "deterministic: two independent runs in one Windows Sandbox session produced byte-identical stdout, stderr and "
    "exit code (string hash randomization was on in both)",
    "inputs are bound to evidence of this job by evidence id and SHA-256; constants written inside the code are not",
    "isolation=windows-sandbox is the runner's declaration; actual sandbox use was not independently verified",
)


def build_compute_evidence(cas: Cas, *, job_sha: str, runtime: Runtime, code: str, bindings: list[dict],
                           crun: ComputeRun, timeout_s: float, max_output_bytes: int) -> dict:
    """Only a clean result becomes evidence: session clean, both cases OK + integrity verified, not truncated, no timeout,
    exit 0, outputs identical. Otherwise ValueError (the caller returns an explicit error, no evidence is written)."""
    run = crun.run
    if crun.deterministic is not True:
        raise ValueError("not a deterministic and complete result: no evidence produced")
    a = run.cases[0]
    if a.exit_code != 0 or a.truncated or a.timed_out or run.isolation != ISOLATION:
        raise ValueError("not exit 0 / untruncated / no timeout / windows-sandbox: no evidence produced")
    code_b = code.encode("utf-8")
    code_sha = cas.put(code_b)
    limitations = list(LIMITATIONS)
    if a.isolation_level:
        limitations.append(f"isolation level: {a.isolation_level}")
    params: dict[str, Any] = {
        "language": LANGUAGE, "code_sha256": code_sha, "code_bytes": len(code_b),
        "inputs": [dict(b) for b in bindings], "runtime": runtime.describe(), "argv": list(ARGV),
        "runs": RUNS, "timeout_ms": int(round(timeout_s * 1000)), "max_output_bytes": int(max_output_bytes)}
    result = {"exit_code": 0, "deterministic": True, "runs": RUNS,
              "output_sha256": hashlib.sha256(a.stdout).hexdigest(), "stdout_bytes": a.stdout_total,
              "stderr_sha256": hashlib.sha256(a.stderr).hexdigest(), "stderr_bytes": a.stderr_total,
              "stderr_blob_sha256": cas.put(a.stderr) if a.stderr else None}
    return build_evidence(
        cas, subject_sha256=job_sha, tool=TOOL, operation="compute", raw=a.stdout, status=Status.OK,
        confidence="derived", authority=COMPUTE_AUTHORITY, parameters=params, tool_version=TOOL_VERSION,
        engine=runtime.spec.runtime_id, engine_version=runtime.exe_sha256[:16], exit_code=0,
        elapsed_ms=max(c.elapsed_ms for c in run.cases), result=result,
        environment={**ENVIRONMENT, "interpreter": runtime.spec.runtime_id},
        coverage={"scope": "computation", "relationship": "unknown"}, limitations=limitations,
        evidence_links=input_links(bindings))
