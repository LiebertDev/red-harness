"""Turns a sealed observation document into evidence (rh.evidence/1, authority=dynamic-observation).

The host side works with untrusted bytes: first the seal (nonce+HMAC), then the identity (run_id, target SHA-256, scope
digest) must match the expected one. If either fails an exception is raised and NOTHING is written to the CAS/ledger (same as
the sandbox INTEGRITY behavior).

Evidence decisions:
- `raw` = canonical JSON bytes of the sealed document (quote atoms are searched inside it).
- The observation goes into the identity; the duration does not (identity stability rule).
- `authority=dynamic-observation`: the verifier does not count this as `controlled-replay`; it is not PROVEN grounds on its own
  (docs/design/evidence-schema.md §4.6).
- Coverage: `coverage.relationship` is NEVER `complete` (a single run does not cover the input/path space; it cannot back
  an absence claim). `partial` if all requested channels are complete, otherwise `unknown`. Channel coverage is in `coverage.channels`.
- Memory events become `address-range` (va) locations; claim addresses are matched against them numerically.
"""

from __future__ import annotations

from typing import Any

from ..core.cas import Cas
from ..core.result import Status
from ..evidence.model import DYNAMIC_AUTHORITY, build_evidence
from .model import CHANNELS, Observation, ObservationError, RunIdentity, parse_body
from .seal import verify_seal

TOOL = "dynamic_observe"
TOOL_VERSION = "0.1.0"
ENVIRONMENT = {"id": "windows-sandbox", "platform": "windows", "architecture": "x64", "isolation": "windows-sandbox",
               "networking": "disabled"}

LIMITATIONS = (
    "single-run observation: an event that was not seen is NOT evidence that it does not happen; missing or partial "
    "channel coverage is unknown, never clean",
    "the instrumentation runs inside the observed process' environment and can be detected or evaded by the target; "
    "a dynamic observation alone never proves a behavior claim (it needs a matching run_controlled outcome)",
    "seal: the document is HMAC-bound to a one-time run nonce the target cannot read and the host verified run id, "
    "target SHA-256 and scope digest before this evidence was built. Residual risk: a forged document is still "
    "possible through a guest-kernel or sandbox escape or a nonce leak (not covered, not measured)",
)


class IdentityMismatch(ObservationError):
    def __init__(self, message: str):
        super().__init__(message, "DYNAMIC_IDENTITY_MISMATCH")


def derive_status(obs: Observation) -> Status:
    """Status derived from the document (the verifier re-applies the same rule)."""
    if obs.timed_out:
        return Status.TIMEOUT
    return Status.OK if obs.fully_covered else Status.PARTIAL


def derive_relationship(obs: Observation) -> str:
    return "partial" if obs.fully_covered else "unknown"


def channel_coverage(obs: Observation) -> dict[str, str]:
    return {c: obs.coverage.get(c, "unknown") for c in CHANNELS}


def check_identity(got: RunIdentity, expected: RunIdentity) -> None:
    if got.run_id != expected.run_id:
        raise IdentityMismatch("run_id mismatch (observation of another run)")
    if got.target_sha256 != expected.target_sha256:
        raise IdentityMismatch("target SHA-256 mismatch (observation of another target)")
    if got.scope_sha256 != expected.scope_sha256:
        raise IdentityMismatch("scope manifest digest mismatch")


def ingest_observation(cas: Cas, doc_bytes: bytes, *, nonce: str, expected: RunIdentity,
                       elapsed_ms: int = 0) -> dict:
    """Verifies untrusted observation bytes and returns an evidence record (writing it to the ledger is the caller's job).

    Errors are `ObservationError` subtypes; `.code`: DYNAMIC_INTEGRITY (seal/nonce/MAC missing or not matching),
    DYNAMIC_IDENTITY_MISMATCH (run/target/scope), DYNAMIC_OBSERVATION_INVALID (schema/contradiction).
    """
    body, digest = verify_seal(doc_bytes, nonce)
    obs = parse_body(body)
    check_identity(obs.identity, expected)
    status = derive_status(obs)
    locations = [{"kind": "address-range", "space": "va", "start": e.base, "end": e.base + e.size}
                 for e in obs.memory_events()]
    result: dict[str, Any] = {
        "exit_code": obs.exit_code, "timed_out": obs.timed_out,
        "event_counts": {"api_call": len(obs.api_calls(only_target=False)), "memory": len(obs.memory_events())},
        "coverage": channel_coverage(obs), "dropped_events": obs.dropped_events,
        "api_sequence": [e.api for e in obs.api_calls()],
    }
    params = {"run_id": obs.identity.run_id, "scope_sha256": obs.identity.scope_sha256, "argv": list(obs.argv),
              "stdin_sha256": obs.stdin_sha256, "observation_sha256": digest, "seal": "hmac-verified",
              "channels_requested": list(obs.channels_requested)}
    return build_evidence(
        cas, subject_sha256=obs.identity.target_sha256, tool=TOOL, operation=TOOL, raw=bytes(doc_bytes),
        status=status, confidence="observed", authority=DYNAMIC_AUTHORITY, parameters=params,
        tool_version=TOOL_VERSION, engine=obs.backend_name, engine_version=obs.backend_version,
        truncated=obs.dropped_events > 0, exit_code=obs.exit_code, elapsed_ms=elapsed_ms, result=result,
        locations=locations, environment=ENVIRONMENT,
        coverage={"scope": f"run:{obs.identity.run_id}", "relationship": derive_relationship(obs),
                  "channels": channel_coverage(obs)},
        limitations=list(LIMITATIONS))
