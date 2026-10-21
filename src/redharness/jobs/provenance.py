"""Provenance of imported jobs (open core): the per-claim status cap of a job that came from an unauthenticated bundle.

The MCP session and the verifier only READ this record; the code that creates bundles (export / import) is a separate
premium module (`jobs.bundle`) that imports these names. A bundle is not authenticated: the cap protects against
untrusted bundles, not against the local operator."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping

from ..core.journal import JournalCorrupt, canonical, verify_file

_AUTH_NOTE = "imported bundle: authenticity not established"
_PROVENANCE_FILE = "provenance.json"
_IMPORT_EVENT = "BUNDLE_IMPORTED"
_PROVENANCE_ISSUE = "imported bundle: provenance file missing or altered"
_STATUS_RANK = {"REJECTED": 0, "UNVERIFIED": 1, "SUPPORTED": 2, "PROVEN": 3}


def _status_map(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {str(k): v for k, v in value.items() if isinstance(v, str)}


def _journal_import_record(job_dir: Path | None) -> Mapping[str, Any] | None:
    """The last BUNDLE_IMPORTED event payload, or None if the job has no readable journal/import record."""
    if job_dir is None:
        return None
    path = job_dir / "events.jsonl"
    if not path.is_file():
        return None
    try:
        if not verify_file(path).ok:   # read-only: a corrupt/torn journal is never repaired by this query
            return None
        events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except (JournalCorrupt, OSError, ValueError):
        return None
    for ev in reversed(events):
        if isinstance(ev, dict) and ev.get("type") == _IMPORT_EVENT and isinstance(ev.get("payload"), Mapping):
            return ev["payload"]
    return None


def _imported_result(source_sha: Any, imported_at: Any, statuses: Mapping[str, str], *,
                     strict: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {
        "imported": True,
        "source_bundle_sha256": source_sha,
        "imported_at": imported_at,
        "authenticity": "not established",
        "note": _AUTH_NOTE,
        "claim_statuses": dict(statuses),
    }
    if strict:   # the journal says imported but provenance.json is missing/altered: trust nothing it recorded
        out["strict_cap"] = True
        out["provenance_issue"] = _PROVENANCE_ISSUE
    return out


def imported_status_cap(job: str | os.PathLike | Mapping[str, Any]) -> dict[str, Any]:
    """Provenance and per-claim status cap of an imported job.

    ``job`` may be a job directory, its ``provenance.json``, or a mapping carrying either the provenance
    record or a ``provenance`` field. Returns ``{}`` for a job that was not imported. For an imported job:
    ``{"imported": True, "source_bundle_sha256": ..., "imported_at": ..., "authenticity":
    "not established", "note": "imported bundle: authenticity not established",
    "claim_statuses": {claim_id: status_in_bundle}}``.

    The hash-chained journal is authoritative: if it carries a BUNDLE_IMPORTED record the job is imported even
    when provenance.json was deleted. When provenance.json is missing or disagrees with that record, the cap is
    strict (every claim at most SUPPORTED, recorded bundle statuses ignored) and ``provenance_issue`` says why.

    Callers must cap each claim at its bundle status (see ``_STATUS_RANK``) and state the note in every
    claim/report generated from the job."""
    prov: Mapping[str, Any] | None = None
    job_dir: Path | None = None
    if isinstance(job, Mapping):
        nested = job.get("provenance")
        prov = nested if isinstance(nested, Mapping) else job
    else:
        path = Path(job)
        if path.is_dir():
            job_dir = path
            path = path / _PROVENANCE_FILE
        elif path.name == _PROVENANCE_FILE:
            job_dir = path.parent
        if path.is_file():
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                doc = None
            if isinstance(doc, dict):
                prov = doc

    journal_rec = _journal_import_record(job_dir)
    if journal_rec is not None:
        source_sha, imported_at = journal_rec.get("source_bundle_sha256"), journal_rec.get("imported_at")
        strict = not prov or prov.get("imported") is not True
        if not strict and str(prov.get("source_bundle_sha256") or "") != str(source_sha or ""):
            strict = True
        if not strict and str(prov.get("imported_at") or "") != str(imported_at or ""):
            strict = True
        if "claim_statuses" in journal_rec:
            recorded = _status_map(journal_rec.get("claim_statuses"))
            if not strict and _status_map(prov.get("claim_statuses")) != recorded:
                strict = True
        elif "claim_statuses_sha256" in journal_rec:
            prov_statuses = _status_map(prov.get("claim_statuses"))
            recorded = prov_statuses
            if not strict and hashlib.sha256(canonical(prov_statuses)).hexdigest() != journal_rec.get(
                    "claim_statuses_sha256"):
                strict = True
        else:
            recorded = {}
            if not strict and _status_map(prov.get("claim_statuses")):
                strict = True
        if strict:
            return _imported_result(source_sha, imported_at, {}, strict=True)
        return _imported_result(source_sha, imported_at, recorded)

    if not prov or prov.get("imported") is not True:
        return {}
    return _imported_result(prov.get("source_bundle_sha256"), prov.get("imported_at"),
                            _status_map(prov.get("claim_statuses")))
