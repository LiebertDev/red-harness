"""Writing evidence/claim/unknown records to the hash-chained journal and rebuilding state from the journal.

State is rebuilt by replaying the journal (no side store). Rewriting the same ev_/cl_/unk_ is a no-op:
after resume the same step produces the same id and no second event is appended to the journal.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, replace
from typing import Any, Iterable, Mapping

from ..core.cas import Cas
from ..core.journal import Journal
from .control_pair import BEHAVIOR_CLASSES
from .kinds import CLAIM_KINDS, is_behavior, resolve_kind
from .model import (CLAIM_SCHEMA, ISOLATED, POLARITIES, ClaimStatus, build_unknown, evidence_id_ok,
                    make_claim_id, normalize_text)
from .values import normalize_declared
from .verifier import Verdict, verify_claim

MAX_INTERPRETATION = 2000  # characters of the unverified `interpretation` beside a claim

# Claim status ordering (low -> high). REJECTED is not on the ladder: it is never capped.
STATUS_ORDER = {ClaimStatus.UNVERIFIED: 0, ClaimStatus.SUPPORTED: 1, ClaimStatus.PROVEN: 2}
IMPORTED_ISSUE_CODE = "IMPORTED_BUNDLE_UNAUTHENTICATED"
IMPORTED_ISSUE_TEXT = "imported bundle: authenticity not established"
IMPORTED_PROVENANCE_ISSUE_CODE = "IMPORTED_BUNDLE_PROVENANCE"
IMPORTED_PROVENANCE_ISSUE_TEXT = "imported bundle: provenance file missing or altered"
IMPORTED_NEW_CLAIM_CAP = ClaimStatus.SUPPORTED   # a claim the bundle did not record never reaches PROVEN on its own


def empty_state() -> dict:
    return {"evidence": {}, "invalidated": {}, "claims": {}, "rejected": {}, "unknowns": {}, "superseded": {}}


def reduce_event(state: dict, ev: dict) -> dict:
    t, p = ev["type"], ev["payload"]
    if t == "EVIDENCE_RECORDED":
        state["evidence"].setdefault(p["evidence_id"], p)
    elif t == "EVIDENCE_INVALIDATED":
        state["invalidated"][p["evidence_id"]] = p["reason"]
    elif t == "CLAIM_ACCEPTED":
        state["claims"][p["claim_id"]] = p
        state["rejected"].pop(p["claim_id"], None)
    elif t == "CLAIM_REJECTED":
        state["rejected"][p["claim_id"]] = p
    elif t == "CLAIM_STATUS_CHANGED":
        c = state["claims"].get(p["claim_id"])
        if c is not None:
            c["status"] = p["to"]
    elif t == "CLAIM_SUPERSEDED":  # retraction: the record stays in the ledger (append-only), invisible in the report
        state["superseded"].setdefault(p["claim_id"], p)
    elif t == "UNKNOWN_RECORDED":
        state["unknowns"].setdefault(p["unknown_id"], p)
    elif t == "UNKNOWN_UPDATED":  # closing an unknown: the record stays (append-only), only its status/resolution move
        u = state["unknowns"].get(p["unknown_id"])
        if u is not None and u.get("revision") == p.get("expected_revision"):
            state["unknowns"][p["unknown_id"]] = {**u, "status": p["status"], "resolution": copy.deepcopy(p["resolution"]),
                                                  "revision": u["revision"] + 1}
    return state


def replay_state(events: Iterable[dict]) -> dict:
    st = empty_state()
    for ev in events:
        reduce_event(st, ev)
    return st


@dataclass(frozen=True)
class ClaimResult:
    status: ClaimStatus
    claim: dict | None  # the record if accepted; None if REJECTED
    issues: list[dict]
    claim_id: str = ""
    kind: str = ""            # resolved kind (observation | behavior | bypass_poc)
    kind_source: str = ""     # declared | inferred | overridden
    superseded: tuple[str, ...] = ()  # ids of claims retracted by this call

    @property
    def accepted(self) -> bool:
        return self.status is not ClaimStatus.REJECTED


class Ledger:
    def __init__(self, journal: Journal, cas: Cas, target_sha256: str, *,
                 allowed_isolations: frozenset[str] = ISOLATED, scope_sha256: str | None = None,
                 fixed_sha256: str | None = None, imported: Mapping[str, Any] | None = None):
        # imported: the job came from an unauthenticated bundle (jobs.bundle.imported_status_cap). No claim may ever
        # hold a status above the one recorded in the bundle; claims the bundle did not record stay <= SUPPORTED.
        self.imported = dict(imported) if imported and imported.get("imported") else None
        self.journal, self.cas, self.target_sha256 = journal, cas, target_sha256
        self.fixed_sha256 = fixed_sha256   # SHA-256 of the vendor's fixed build (scope manifest), if bound
        self.allowed_isolations = allowed_isolations
        self.scope_sha256 = scope_sha256  # if given, the scope digest of dynamic observations must equal it
        self.state = replay_state(journal.events())

    def _cap_verdict(self, claim_id: str, verdict: Verdict) -> Verdict:
        """Imported jobs: lowers the verdict to the bundle's status for this claim and states why (never raises it)."""
        if self.imported is None or verdict.status is ClaimStatus.REJECTED:
            return verdict
        recorded = (self.imported.get("claim_statuses") or {}).get(claim_id)
        try:
            cap = ClaimStatus(recorded) if recorded is not None else IMPORTED_NEW_CLAIM_CAP
        except ValueError:
            cap = ClaimStatus.UNVERIFIED   # unreadable recorded status: assume nothing
        if cap is ClaimStatus.REJECTED:
            cap = ClaimStatus.UNVERIFIED
        status = verdict.status
        if STATUS_ORDER[status] > STATUS_ORDER[cap]:
            status = cap
        note = {"code": IMPORTED_ISSUE_CODE, "severity": "INFO", "detail": IMPORTED_ISSUE_TEXT}
        issues = [*verdict.issues, note]
        if self.imported.get("strict_cap"):   # journal says imported, provenance.json missing/altered
            issues.append({"code": IMPORTED_PROVENANCE_ISSUE_CODE, "severity": "INFO",
                           "detail": self.imported.get("provenance_issue") or IMPORTED_PROVENANCE_ISSUE_TEXT})
        return replace(verdict, status=status, issues=issues)

    def _append(self, type_: str, payload: Any) -> None:
        ev = self.journal.append(type_, payload)
        reduce_event(self.state, ev)

    # ---- evidence ----
    def record_evidence(self, record: Mapping[str, Any]) -> dict:
        """Writes evidence produced by server code. Id and raw blob are verified; rewriting is a no-op."""
        eid = record.get("evidence_id")
        if not evidence_id_ok(record):
            raise ValueError("EVIDENCE_ID_MISMATCH")
        if record.get("untrusted_content") is not True:
            raise ValueError("evidence must be marked untrusted_content")
        self.cas.get(record["raw"]["blob_sha256"])  # CasError if missing/corrupt; blob first, then the event
        if eid in self.state["evidence"]:
            return self.state["evidence"][eid]
        self._append("EVIDENCE_RECORDED", dict(record))
        return self.state["evidence"][eid]

    def invalidate_evidence(self, evidence_id: str, reason: str) -> list[str]:
        """Invalidates evidence; SUPPORTED/PROVEN claims resting on it become UNVERIFIED. Returns the affected claim ids."""
        if evidence_id not in self.state["evidence"]:
            raise KeyError(evidence_id)
        if evidence_id in self.state["invalidated"]:
            return []
        self._append("EVIDENCE_INVALIDATED", {"evidence_id": evidence_id, "reason": reason})
        hit = []
        for cid, c in list(self.state["claims"].items()):
            if evidence_id in c["evidence_ids"] and c["status"] in ("SUPPORTED", "PROVEN"):
                self._append("CLAIM_STATUS_CHANGED", {
                    "claim_id": cid, "from": c["status"], "to": "UNVERIFIED",
                    "reason": f"EVIDENCE_INVALIDATED:{reason}", "trigger_evidence_id": evidence_id})
                hit.append(cid)
        return hit

    # ---- claim ----
    def add_claim(self, text: str, kind: str | None, polarity: str, evidence_ids: Iterable[str] = (),
                  atoms: Iterable[Mapping[str, Any]] = (), requested: str = "SUPPORTED", *,
                  expected_revision: int | None = None, values: Iterable[Any] | None = None,
                  supersedes: Iterable[str] = (), interpretation: str | None = None,
                  behavior_class: str | None = None) -> ClaimResult:
        """kind: observation | behavior | bypass_poc (legacy: static_fact, runtime_behavior) or None; if None the kind is
        decided heuristically from the text, behavior if unclear (kinds.resolve_kind). A behavior claim is supported only
        by execution evidence (BEHAVIOR_NEEDS_EXECUTION).
        values: concrete values the claim asserts (string/integer or {value, derived}); the server additionally
        extracts them from the text automatically. A value absent from the evidence makes the claim UNVERIFIED (VALUE_NOT_IN_EVIDENCE).
        supersedes: ids of earlier claims being retracted; if the new claim is NOT REJECTED they vanish from the report
        (they stay in the ledger).
        interpretation: the model's reading of the code (algorithm names, purpose, format) that the evidence does not
        show; stored beside the claim and printed as NOT verified. It is never passed to the verifier, so the status
        never covers it (verifier version 16, docs/design/evidence-schema.md section 4.12).
        behavior_class: required for a behavior claim (verifier version 24, section 4.17; missing -> UNVERIFIED
        BEHAVIOR_CLASS_MISSING): "acceptance_validation" (accepted/rejected, correct input, valid licence; needs a
        control_pair atom) or "ordinary". Validation wording in the text makes an "ordinary" claim need a pair too."""
        interp = None
        if interpretation is not None:
            if not isinstance(interpretation, str) or len(interpretation) > MAX_INTERPRETATION:
                raise ValueError(f"interpretation must be a string of <= {MAX_INTERPRETATION} characters")
            interp = normalize_text(interpretation) or None
        if (kind is not None and kind not in CLAIM_KINDS) or polarity not in POLARITIES:
            raise ValueError("invalid kind/polarity")
        text = normalize_text(text)
        if not text:
            raise ValueError("empty claim text")
        req = ClaimStatus(requested)
        kind, kind_source, kind_hit = resolve_kind(kind, text)
        if behavior_class is not None:
            if behavior_class not in BEHAVIOR_CLASSES:
                raise ValueError(f"behavior_class must be one of {list(BEHAVIOR_CLASSES)} or omitted")
            if not is_behavior(kind) or kind == "fix_verification":
                raise ValueError("behavior_class applies to a behavior claim (kind 'behavior' or 'bypass_poc'); a fix "
                                 "claim uses kind='fix_verification' with a fix_pair atom")
        cid = make_claim_id(text, kind, polarity, self.target_sha256)
        sup_ids = list(dict.fromkeys(supersedes or ()))
        for sid in sup_ids:
            if not isinstance(sid, str) or sid not in self.state["claims"]:
                raise ValueError(f"supersedes: unknown claim_id {str(sid)[:24]!r} (use claim_id values returned by claim_add)")
            if sid == cid:
                raise ValueError("supersedes: a claim cannot supersede itself (change the text or kind)")
        if sup_ids and cid in self.state["superseded"]:
            raise ValueError("this claim was already retracted (superseded) and cannot retract others; "
                             "change its text to make a new claim")
        prev = self.state["claims"].get(cid)
        if expected_revision is not None and (prev["revision"] if prev else 0) != expected_revision:
            raise ValueError("REVISION_CONFLICT")
        ev_ids = list(dict.fromkeys(evidence_ids))
        atoms = [dict(a) for a in atoms]
        values = normalize_declared(list(values) if values is not None else None)
        verdict: Verdict = verify_claim(
            {"text": text, "kind": kind, "polarity": polarity, "requested": req.value,
             "evidence_ids": ev_ids, "atoms": atoms, "values": values, "behavior_class": behavior_class},
            self.state["evidence"], self.state["invalidated"], self.cas, self.target_sha256,
            self.allowed_isolations, self.scope_sha256, self.fixed_sha256)
        verdict = self._cap_verdict(cid, verdict)
        issues = list(verdict.issues)
        if kind_source == "overridden":  # not silent: the model explicitly said observation but the text is a behavior claim
            issues.append({"code": "KIND_OVERRIDDEN_TO_BEHAVIOR", "severity": "INFO",
                           "detail": f"text asserts program behavior ({kind_hit!r})"})
        if verdict.status is ClaimStatus.REJECTED:
            self._append("CLAIM_REJECTED", {"claim_id": cid, "text": text, "requested": req.value,
                                            "issues": issues})
            return ClaimResult(ClaimStatus.REJECTED, None, issues, cid, kind, kind_source)
        rec = {"schema": CLAIM_SCHEMA, "claim_id": cid, "revision": (prev["revision"] + 1) if prev else 1,
               "text": text, "kind": kind, "kind_source": kind_source, "polarity": polarity,
               "target_sha256": self.target_sha256,
               "requested": req.value, "status": verdict.status.value, "evidence_ids": ev_ids,
               "atoms": atoms, "values": values, "verification": verdict.to_record()}
        if sup_ids:
            rec["supersedes"] = sup_ids
        if interp:  # written only when given: records without it keep their version 15 shape
            rec["interpretation"] = interp
        if behavior_class:  # written only when given: records without it keep their version 23 shape
            rec["behavior_class"] = behavior_class
        if prev is not None and _same_claim(prev, rec):
            out = prev
        else:
            self._append("CLAIM_ACCEPTED", rec)
            out = copy.deepcopy(rec)
        done = []
        for sid in sup_ids:  # retraction: only if the new claim was accepted; append-only event
            if sid not in self.state["superseded"]:
                self._append("CLAIM_SUPERSEDED", {"claim_id": sid, "superseded_by": cid})
                done.append(sid)
        return ClaimResult(verdict.status, out, issues, cid, kind, kind_source, tuple(done))

    def reverify(self, claim_id: str) -> Verdict:
        """Re-verifies a recorded claim against the current evidence state (writes nothing)."""
        c = self.state["claims"][claim_id]
        return self._cap_verdict(claim_id, verify_claim(
            {**c, "requested": c["requested"]}, self.state["evidence"], self.state["invalidated"], self.cas,
            self.target_sha256, self.allowed_isolations, self.scope_sha256, self.fixed_sha256))

    # ---- unknown ----
    def record_unknown(self, domain: str, question: str, **kw: Any) -> dict:
        rec = build_unknown(domain, question, self.target_sha256, **kw)
        if rec["unknown_id"] in self.state["unknowns"]:
            return self.state["unknowns"][rec["unknown_id"]]
        self._append("UNKNOWN_RECORDED", rec)
        return rec

    def close_unknown(self, unknown_id: str, status: str, *, evidence_ids: Iterable[str] = (), reason: str = "") -> dict:
        """Closes an open unknown as `resolved` (needs evidence ids that exist and are not invalidated) or `withdrawn`
        (needs a reason). The unknown and its history stay in the journal; closing again with the same status and
        evidence is a no-op. ValueError(code) otherwise: UNKNOWN_NOT_FOUND, UNKNOWN_ALREADY_CLOSED, BAD_RESOLUTION,
        UNKNOWN_EVIDENCE_ID."""
        u = self.state["unknowns"].get(unknown_id)
        if u is None:
            raise ValueError("UNKNOWN_NOT_FOUND")
        if status not in ("resolved", "withdrawn"):
            raise ValueError("BAD_RESOLUTION")
        ids = sorted(set(evidence_ids))
        note = normalize_text(reason)
        res = {"status": status, "evidence_ids": ids, **({"reason": note} if note else {})}
        if u["status"] in ("resolved", "withdrawn"):
            if u.get("resolution") == res:
                return u
            raise ValueError("UNKNOWN_ALREADY_CLOSED")
        if status == "resolved" and not ids:
            raise ValueError("BAD_RESOLUTION")
        if status == "withdrawn" and not note:
            raise ValueError("BAD_RESOLUTION")
        if any(e not in self.state["evidence"] or e in self.state["invalidated"] for e in ids):
            raise ValueError("UNKNOWN_EVIDENCE_ID")
        self._append("UNKNOWN_UPDATED", {"unknown_id": unknown_id, "expected_revision": u["revision"],
                                         "status": status, "resolution": res})
        return self.state["unknowns"][unknown_id]


def _same_claim(prev: Mapping[str, Any], new: Mapping[str, Any]) -> bool:
    keys = ("status", "requested", "evidence_ids", "atoms", "values", "verification", "interpretation",
            "behavior_class")
    return all(prev.get(k) == new.get(k) for k in keys)
