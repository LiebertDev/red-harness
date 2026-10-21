"""Verifier side: internal consistency of a recorded `dynamic-observation` evidence record.

The nonce is no longer on the host once the run ends, so the verifier cannot re-check the HMAC. Integrity chain:
- ingest (nonce present): seal + identity were verified and the evidence was built only after that (`parameters.seal`);
- record: the raw blob is protected by its CAS digest, the record by its `ev_` id (verifier.py: RAW_BLOB_HASH_MISMATCH,
  EVIDENCE_ID_MISMATCH); `parameters.observation_sha256` binds to the raw body;
- here: the raw document is re-parsed and checked for contradictions with the record fields (target, run_id, scope, status,
  coverage channels, exit code, input). A hand-made/adapted record that does not match the raw document is REJECTED.
Every result is a (code, detail) pair and is a rejection reason in the verifier (fail-closed).
"""

from __future__ import annotations

from typing import Any, Mapping

from ..evidence.model import DYNAMIC_AUTHORITY
from .ingest import TOOL, channel_coverage, derive_relationship, derive_status
from .model import ObservationError, body_digest, parse_body, split_document


def validate_record(rec: Mapping[str, Any], raw: bytes, *, scope_sha256: str | None = None) -> list[tuple[str, str]]:
    if rec.get("authority") != DYNAMIC_AUTHORITY:
        return [("DYNAMIC_OBSERVATION_INVALID", "authority is not dynamic-observation")]
    bad: list[tuple[str, str]] = []
    if rec.get("confidence") != "observed" or rec.get("operation") != TOOL:
        bad.append(("DYNAMIC_OBSERVATION_INVALID", "confidence/operation differ from expected"))
    try:
        body, integ = split_document(raw)
        obs = parse_body(body)
    except ObservationError as e:
        code = "DYNAMIC_INTEGRITY" if e.code == "DYNAMIC_INTEGRITY" else "DYNAMIC_OBSERVATION_INVALID"
        return bad + [(code, str(e))]
    p = rec.get("parameters") or {}
    if p.get("seal") != "hmac-verified":
        bad.append(("DYNAMIC_INTEGRITY", "record does not carry the seal-verified marker"))
    mac = integ.get("mac")
    if not isinstance(mac, str) or len(mac) != 64:
        bad.append(("DYNAMIC_INTEGRITY", "MAC malformed in the raw document"))
    if p.get("observation_sha256") != body_digest(body):
        bad.append(("DYNAMIC_OBSERVATION_INVALID", "body digest does not match the record (document was edited)"))
    ident = obs.identity
    if (rec.get("subject") or {}).get("sha256") != ident.target_sha256:
        bad.append(("DYNAMIC_IDENTITY_MISMATCH", "observation target SHA-256 does not match the evidence subject"))
    if p.get("run_id") != ident.run_id:
        bad.append(("DYNAMIC_IDENTITY_MISMATCH", "observation run_id does not match the record"))
    if p.get("scope_sha256") != ident.scope_sha256:
        bad.append(("DYNAMIC_IDENTITY_MISMATCH", "observation scope digest does not match the record"))
    if scope_sha256 is not None and ident.scope_sha256 != scope_sha256:
        bad.append(("DYNAMIC_IDENTITY_MISMATCH", "observation does not belong to this job's scope manifest"))
    cap, cov = rec.get("capture") or {}, rec.get("coverage") or {}
    if cap.get("status") != derive_status(obs).value or cap.get("exit_code") != obs.exit_code:
        bad.append(("DYNAMIC_OBSERVATION_INVALID", "capture status/exit code does not match the raw document"))
    if cov.get("relationship") != derive_relationship(obs) or cov.get("channels") != channel_coverage(obs):
        bad.append(("DYNAMIC_OBSERVATION_INVALID", "coverage record does not match the raw document"))
    if p.get("argv") != list(obs.argv) or p.get("stdin_sha256") != obs.stdin_sha256:
        bad.append(("DYNAMIC_OBSERVATION_INVALID", "input (argv/stdin) record does not match the raw document"))
    return bad
