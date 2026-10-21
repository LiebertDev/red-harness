"""`captured_region` evidence (authority=`dynamic-region-view`, confidence=`derived`): record checks for the verifier.

A region view is a bounded, read-only rendering (hex window, strings, linear disassembly) of bytes that the tracer
captured from an executable region of ONE dynamic observation. It is not itself an observation and it never executes
anything. What the verifier lets it do (evidence-schema section 4.15, verifier version 22):

- It is tied to its observation: `evidence_links` is exactly that observation, which must be a (not invalidated)
  `dynamic-observation` record of the same target, with the same stored document and body digest. A claim that cites a
  view must also cite its observation (`REGION_VIEW_PARENT_NOT_CITED`), so the observation's own coverage and
  incompleteness stay in front of the claim.
- It never claims more than its observation: the view's capture strength may not exceed the observation's (a view of an
  incomplete or failed observation is partial or failed), and its coverage is never `complete`, so it can back no
  absence claim.
- It can back an `observation` + `present` claim (SUPPORTED at most). It never backs PROVEN (`PROVEN_REGION_VIEW`, a cap).
"""

from __future__ import annotations

from typing import Any, Mapping

from .model import DYNAMIC_AUTHORITY, REGION_VIEW_AUTHORITY, derive_strength, evidence_id_ok

OPERATION = "captured_region"
DYNAMIC_OPERATION = "dynamic_observe"
CODE = "REGION_VIEW_INVALID"
PARENT_NOT_CITED = "REGION_VIEW_PARENT_NOT_CITED"
PROVEN_CAP = "PROVEN_REGION_VIEW"
_RANK = {"failed": 0, "partial": 1, "full": 2}


def is_region_view(rec: Mapping[str, Any] | None) -> bool:
    return bool(rec) and rec.get("authority") == REGION_VIEW_AUTHORITY


def parent_id(rec: Mapping[str, Any]) -> str | None:
    """The observation evidence id a view was derived from (its only evidence link)."""
    links = rec.get("evidence_links")
    return links[0] if isinstance(links, list) and len(links) == 1 and isinstance(links[0], str) else None


def validate_record(rec: Mapping[str, Any], evidence: Mapping[str, Mapping[str, Any]],
                    invalidated: Mapping[str, Any] | None = None) -> list[tuple[str, str]]:
    """Problems that make a cited region-view record unusable (code, detail); empty list = consistent."""
    bad: list[tuple[str, str]] = []
    p = rec.get("parameters") or {}
    if rec.get("operation") != OPERATION or (rec.get("source") or {}).get("tool") != OPERATION:
        bad.append((CODE, "not a captured_region record"))
    if rec.get("confidence") != "derived":
        bad.append((CODE, "a region view is derived, never observed"))
    if (rec.get("coverage") or {}).get("relationship") == "complete":
        bad.append((CODE, "a region view covers one capture of one run; it can never be complete"))
    pid = parent_id(rec)
    if pid is None or p.get("observation_evidence_id") != pid:
        bad.append((CODE, "evidence_links must be exactly the observation named in parameters.observation_evidence_id"))
        return bad
    parent = evidence.get(pid)
    if parent is None or (invalidated and pid in invalidated):
        bad.append((CODE, f"the observation {pid} is not (or no longer) a valid evidence of this job"))
        return bad
    if (not evidence_id_ok(parent) or parent.get("authority") != DYNAMIC_AUTHORITY
            or parent.get("operation") != DYNAMIC_OPERATION):
        bad.append((CODE, f"{pid} is not an intact dynamic-observation record"))
        return bad
    if (parent.get("subject") or {}).get("sha256") != (rec.get("subject") or {}).get("sha256"):
        bad.append((CODE, "the view and its observation are about different targets"))
    if p.get("observation_blob_sha256") != (parent.get("raw") or {}).get("blob_sha256"):
        bad.append((CODE, "the view was taken from another stored copy of the observation document"))
    if p.get("observation_sha256") != (parent.get("parameters") or {}).get("observation_sha256"):
        bad.append((CODE, "the view names another body digest than its observation"))
    vs, ps = derive_strength(rec.get("capture") or {}), derive_strength(parent.get("capture") or {})
    if _RANK[vs] > _RANK[ps]:
        bad.append((CODE, f"capture strength {vs} exceeds the observation's ({ps}): an incomplete observation "
                          "cannot yield a complete view"))
    return bad
