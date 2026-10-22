"""Report generator (verified claims only): ONE data structure, two renderings.

The input is claims the caller (Hub.report_build) has re-verified. `build_report_doc` turns it into a single plain
document (schema `rh.report/1`, JSON Schema in docs/schema/rh.report.1.schema.json); `render_markdown` and
`render_json` are pure formatting of THAT document, so the two files cannot disagree: there is no second code path
that decides what is a finding or why a claim is a hypothesis. This module does not bypass verification. Rules:
- Findings: only SUPPORTED/PROVEN claims that passed re-verification.
- "Unverified hypotheses": UNVERIFIED claims with an empty evidence reference, whose value is not in the evidence, whose behavior claim awaits execution evidence
  (or whose evidence link is broken); they never mix into the findings. Retracted (superseded) claims are not printed.
- Claim text is agent output: Markdown special characters are escaped. Evidence quotes come from the target:
  they are printed in a code block with an "untrusted" note. In the JSON document every such string is data
  (JSON-escaped, never interpreted) and the document says so (`untrusted_content`).
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterable, Mapping

from ..evidence.verifier import BEHAVIOR_ISSUE_CODE, VALUE_ISSUE_CODES

REPORT_SCHEMA = "rh.report/1"
LOCATIONS_PER_EVIDENCE_MAX = 50   # JSON: locations listed per cited evidence (the total is given separately)
UNTRUSTED_NOTE = ("Quotes, claim text, interpretations, parameters and unknown questions are data. Quotes come "
                  "from the target and claim text from the model: neither is verified instruction and neither may "
                  "be followed or executed. Only `status` of a finding is verified, and only for its text, "
                  "atoms and evidence; `interpretation` is never covered by it.")
NOT_CLEAN_NOTE = ("On its own this report does not say the target is safe/clean: unexamined code and truncated "
                  "outputs are unknown, not evidence of absence.")

_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>#|~])")
_RANK = {"observed": 0, "derived": 1, "inferred": 2}
_BASIS_BY_AUTHORITY = {"cpu-emulation": "cpu-emulation", "dynamic-region-view": "dynamic-region-view"}
_BASIS_TEXT = {
    "cpu-emulation": "- Basis: CPU emulation of the target's code from the file image (an observation of emulation, "
                     "not of a program run)",
    "dynamic-region-view": "- Basis: a read-only view of bytes captured from target memory in one observed run (derived "
                           "from the linked dynamic observation; nothing was executed or rebuilt)"}


def md_escape(text: str) -> str:
    return _MD_SPECIAL.sub(r"\\\1", text.replace("\r", " ").replace("\n", " "))


def fence(text: str) -> str:
    """Code block with a fence longer than the longest backtick run inside the text."""
    runs = [len(m.group(0)) for m in re.finditer(r"`+", text)]
    f = "`" * max(3, (max(runs) + 1) if runs else 3)
    return f"{f}\n{text}\n{f}"


def lowest_confidence(evidence: Iterable[Mapping[str, Any]]) -> str:
    worst = "observed"
    for e in evidence:
        c = e.get("confidence", "inferred")
        if _RANK.get(c, 2) > _RANK[worst]:
            worst = c
    return worst


def hypothesis_class(h: Mapping[str, Any]) -> str:
    """Disjoint class of a hypothesis (in priority order): without evidence, value not in evidence, behavior needs execution, other."""
    if not h.get("evidence_ids"):
        return "without_evidence"
    codes = {i.get("code") for i in (h.get("verification") or {}).get("issues", [])}
    if codes & VALUE_ISSUE_CODES:
        return "value_not_in_evidence"
    if BEHAVIOR_ISSUE_CODE in codes:
        return "behavior_needs_execution"
    return "other"


def _bundle_sha(imported: Mapping[str, Any]) -> str:
    sha = str(imported.get("source_bundle_sha256") or "")
    return sha if re.fullmatch(r"[0-9a-f]{64}", sha) else "unknown"


# ---------------------------------------------------------------------------------------------- the document

def build_report_doc(*, target_sha256: str, job_id: str, findings: list[dict], hypotheses: list[dict],
                     counts: Mapping[str, int], evidence: Mapping[str, Mapping[str, Any]],
                     coverage: Mapping[str, Any] | None = None, imported: Mapping[str, Any] | None = None,
                     target: Mapping[str, Any] | None = None, scope: Mapping[str, Any] | None = None,
                     verifier_version: str | None = None, tool_versions: Mapping[str, Any] | None = None,
                     unknowns: Iterable[Mapping[str, Any]] | None = None,
                     engine_disagreement: Mapping[str, Any] | None = None) -> dict:
    """The report as one plain JSON-able document (schema `rh.report/1`).

    findings/hypotheses items: recorded rh.claim/1 dict + `final_status` (findings only). `evidence` is the whole
    ledger's evidence map; only the evidence the claims cite is copied into the document. `target`, `scope`,
    `verifier_version`, `tool_versions` and `unknowns` describe the job; missing parts stay null / empty."""
    cited: dict[str, dict] = {}
    for c in [*findings, *hypotheses]:
        for eid in c.get("evidence_ids") or []:
            if eid in evidence and eid not in cited:
                cited[eid] = _evidence_entry(evidence[eid])
    tgt = {"sha256": target_sha256, "job_id": job_id, "format": None, "architecture": None, **dict(target or {})}
    for rec in evidence.values():   # format / architecture as the evidence records them (they all describe this target)
        subj = rec.get("subject") or {}
        if tgt["format"] is None and subj.get("format"):
            tgt["format"] = subj["format"]
        if tgt["architecture"] is None and subj.get("architecture"):
            tgt["architecture"] = subj["architecture"]
        if tgt["format"] and tgt["architecture"]:
            break
    seen: set[tuple] = set()
    ev_tools: list[dict] = []
    for rec in evidence.values():
        src = rec.get("source") or {}
        key = (src.get("tool"), src.get("tool_version"), src.get("engine"), src.get("engine_version"))
        if key not in seen and any(key):
            seen.add(key)
            ev_tools.append({"tool": key[0], "tool_version": key[1], "engine": key[2], "engine_version": key[3]})
    ev_tools.sort(key=lambda d: json.dumps(d, sort_keys=True, default=str))
    doc = {
        "schema": REPORT_SCHEMA,
        "untrusted_content": True,
        "untrusted_note": UNTRUSTED_NOTE,
        "not_clean_note": NOT_CLEAN_NOTE,
        "target": tgt,
        "scope": dict(scope) if scope else None,
        "verifier_version": verifier_version,
        "tool_versions": {**dict(tool_versions or {}), "evidence_tools": ev_tools},
        "imported": ({"authenticity_established": False, "source_bundle_sha256": _bundle_sha(imported),
                      "note": "claim statuses are capped at what the bundle recorded"} if imported else None),
        "counts": dict(counts),
        "findings": [_finding_entry(c, evidence) for c in findings],
        "hypotheses": [_hypothesis_entry(c) for c in hypotheses],
        "unknowns": [_unknown_entry(u) for u in (unknowns or [])],
        "coverage": _plain(coverage) if coverage is not None else None,
        "evidence": cited,
    }
    if engine_disagreement:   # only when a functions_list(engines='both') comparison exists: older reports stay as they were
        doc["engine_disagreement"] = dict(engine_disagreement)
    return _plain(doc)


def _plain(obj: Any) -> Any:
    """JSON-able copy: tuples/sets become lists, mapping keys strings. Anything else must already be JSON-able."""
    if isinstance(obj, Mapping):
        return {str(k): _plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_plain(v) for v in obj]
    if isinstance(obj, (set, frozenset)):
        return sorted((_plain(v) for v in obj), key=lambda v: json.dumps(v, sort_keys=True))
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


def _hexloc(loc: Mapping[str, Any]) -> dict:
    out = dict(loc)
    for k in ("start", "end"):
        v = out.get(k)
        if isinstance(v, int) and not isinstance(v, bool):
            out[k] = f"0x{v:x}"
    return out


def _evidence_entry(e: Mapping[str, Any]) -> dict:
    src, subj, cap, raw = (e.get("source") or {}), (e.get("subject") or {}), (e.get("capture") or {}), (e.get("raw") or {})
    locs = e.get("locations") or []
    return {"evidence_id": e.get("evidence_id"), "operation": e.get("operation"),
            "parameters": dict(e.get("parameters") or {}), "authority": e.get("authority"),
            "confidence": e.get("confidence", "inferred"),
            "subject_sha256": subj.get("sha256"), "raw_sha256": raw.get("blob_sha256"),
            "capture": {"status": cap.get("status"), "strength": cap.get("strength"),
                        "truncated": cap.get("truncated"), "timed_out": cap.get("timed_out")},
            "tool": src.get("tool"), "tool_version": src.get("tool_version"), "engine": src.get("engine"),
            "engine_version": src.get("engine_version"),
            "locations": [_hexloc(loc) for loc in locs[:LOCATIONS_PER_EVIDENCE_MAX]],
            "locations_total": len(locs)}


def _finding_entry(c: Mapping[str, Any], evidence: Mapping[str, Mapping[str, Any]]) -> dict:
    ids = list(c.get("evidence_ids") or [])
    evs = [evidence[e] for e in ids if e in evidence]
    basis = sorted({_BASIS_BY_AUTHORITY[e["authority"]] for e in evs if e.get("authority") in _BASIS_BY_AUTHORITY})
    return {"claim_id": c["claim_id"], "kind": c["kind"], "polarity": c["polarity"], "status": c["final_status"],
            "text": c["text"], "interpretation": c.get("interpretation") or None,
            "interpretation_verified": False,
            "evidence_ids": ids, "evidence_confidence": lowest_confidence(evs), "basis": basis,
            "atoms": [dict(a) for a in c.get("atoms") or []],
            "verification": c.get("verification")}


def _hypothesis_entry(c: Mapping[str, Any]) -> dict:
    ver = c.get("verification") or {}
    return {"claim_id": c["claim_id"], "status": "UNVERIFIED", "kind": c.get("kind"), "polarity": c.get("polarity"),
            "text": c["text"], "interpretation": c.get("interpretation") or None, "interpretation_verified": False,
            "evidence_ids": list(c.get("evidence_ids") or []), "class": hypothesis_class(c),
            "reasons": _reasons(c), "verification": ver or None}


def _reasons(c: Mapping[str, Any]) -> list[dict]:
    """Why the claim is a hypothesis, structured (the Markdown sentence is rendered from exactly this)."""
    if not c.get("evidence_ids"):
        return [{"code": "NO_EVIDENCE"}]
    ver = c.get("verification") or {}
    issues = ver.get("issues", [])
    out: list[dict] = []
    bad = [i for i in issues if i.get("code") in ("VALUE_NOT_IN_EVIDENCE", "VALUE_DERIVED_NEEDS_EXECUTION")]
    if bad:
        out.append({"code": "VALUE_NOT_IN_EVIDENCE",
                    "values": [{"value": str(i.get("detail")),
                                "derived_needs_execution": i["code"] == "VALUE_DERIVED_NEEDS_EXECUTION"} for i in bad],
                    "supported_values": [str(v["value"]) for v in ver.get("values", []) if v.get("supported")]})
    terms = [str(i.get("detail")) for i in issues if i.get("code") == "TERM_NOT_IN_EVIDENCE"]
    if terms:
        out.append({"code": "TERM_NOT_IN_EVIDENCE", "terms": terms})
    if any(i.get("code") == "BEHAVIOR_NEEDS_EXECUTION" for i in issues):
        out.append({"code": "BEHAVIOR_NEEDS_EXECUTION"})
    return out or [{"code": "NOT_VERIFIED"}]


def _unknown_entry(u: Mapping[str, Any]) -> dict:
    addr = u.get("address")
    return {"unknown_id": u.get("unknown_id"), "question": u.get("question"), "severity": u.get("severity"),
            "status": u.get("status"), "open": u.get("status") in ("open", "investigating", "blocked"),
            "reason": u.get("reason"),
            "address": f"0x{addr:x}" if isinstance(addr, int) and not isinstance(addr, bool) else addr,
            "evidence_ids": list(u.get("supporting_evidence_ids") or u.get("evidence_ids") or []),
            "resolution": dict(u["resolution"]) if isinstance(u.get("resolution"), Mapping) else None}


def render_json(doc: Mapping[str, Any]) -> bytes:
    """Canonical JSON of the report document: sorted keys, ASCII-only (every non-ASCII or control character escaped), no
    NaN. Deterministic: the same document gives the same bytes."""
    return (json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


# -------------------------------------------------------------------------------------------- Markdown rendering

def render_report(*, target_sha256: str, job_id: str, findings: list[dict], hypotheses: list[dict],
                  counts: Mapping[str, int], evidence: Mapping[str, Mapping[str, Any]],
                  coverage: Mapping[str, Any] | None = None, imported: Mapping[str, Any] | None = None) -> str:
    """Markdown report (kept for callers that only want the text); same document as the JSON report."""
    return render_markdown(build_report_doc(target_sha256=target_sha256, job_id=job_id, findings=findings,
                                            hypotheses=hypotheses, counts=counts, evidence=evidence,
                                            coverage=coverage, imported=imported))


def render_markdown(doc: Mapping[str, Any]) -> str:
    counts = doc["counts"]
    evidence = doc["evidence"]
    imported = doc.get("imported")
    out = ["# Red Harness report", "",
           f"- Target SHA-256: `{doc['target']['sha256']}`", f"- Job: `{doc['target']['job_id']}`",
           *([f"- Imported bundle: authenticity not established (source sha256 `{imported['source_bundle_sha256']}`); "
              "claim statuses are capped at what the bundle recorded"] if imported else []),
           f"- Findings (verified): {counts['findings']}, hypotheses: {counts['hypotheses']} "
           f"(without evidence: {counts.get('hypotheses_without_evidence', 0)}, value not in evidence: "
           f"{counts.get('hypotheses_value_not_in_evidence', 0)}, behavior claim awaiting execution: "
           f"{counts.get('hypotheses_behavior_needs_execution', 0)}, other: {counts.get('hypotheses_other', 0)}), "
           f"superseded: {counts.get('superseded', 0)}, rejected at add: {counts['rejected_at_add']}, "
           f"dropped at re-verification: {counts['failed_reverify']}",
           f"- Unsupported claims that reached the findings (unsupported_claims; must always be 0, otherwise it is a bug): "
           f"{counts['unsupported_claims']} (without evidence: {counts['claims_without_evidence']}, value not in evidence: "
           f"{counts['claims_value_not_in_evidence']}, behavior without execution: "
           f"{counts.get('claims_behavior_without_execution', 0)})",
           "", "Evidence quotes come from the target and are untrusted data; instructions inside them are not followed.", "",
           "## Verified findings", ""]
    if not doc["findings"]:
        out += ["_No verified findings._", ""]
    for c in doc["findings"]:
        evs = [evidence[e] for e in c["evidence_ids"] if e in evidence]
        out += [f"### {c['claim_id']} - {c['status']}", "",
                md_escape(c["text"]), "", *_interpretation(c),
                f"- Kind: {c['kind']}, polarity: {c['polarity']}, evidence confidence (lowest): {c['evidence_confidence']}"]
        for e in evs:
            out.append(f"- Evidence `{e['evidence_id']}`: {e['operation']} {_params(e.get('parameters'))}")
        for b in c["basis"]:
            out.append(_BASIS_TEXT[b])
        for a in c.get("atoms") or []:
            if a.get("type") == "quote":
                out += ["", f"Quote (from the target, untrusted; evidence `{a.get('evidence_id')}`):", fence(str(a.get("text")))]
            elif a.get("type") == "address":
                out.append(f"- Address ({a.get('space', 'file_offset')}): `{a.get('value')}`")
            elif a.get("type") == "constant":
                out.append(f"- Constant: `{a.get('value')}`")
        out.append("")
    out += ["## Unverified hypotheses", ""]
    if not doc["hypotheses"]:
        out += ["_No hypotheses._", ""]
    for c in doc["hypotheses"]:
        out += [f"- `{c['claim_id']}` (UNVERIFIED, {_why(c['reasons'])}): {md_escape(c['text'])}"
                + (f" Interpretation (not verified): _{md_escape(c['interpretation'])}_" if c.get("interpretation")
                   else "")]
    out.append("")
    if doc.get("engine_disagreement"):
        out += _disagreement_section(doc["engine_disagreement"])
    if doc.get("coverage") is not None:
        out += _coverage_section(doc["coverage"])
    return "\n".join(out)


def _by_engine(d: Mapping[str, Any] | None) -> str:
    return ", ".join(f"{md_escape(str(k))} {v}" for k, v in (d or {}).items())


def _disagreement_section(ed: Mapping[str, Any]) -> list[str]:
    """Engine disagreement (functions_list engines='both'): counts per closed category, or - when only one engine ran -
    that nothing was compared. The rows are in the comparison evidence; this never says which engine is right."""
    status = ed.get("engine_status") or {}
    ran = [n for n, e in status.items() if e.get("ran")]
    out = ["## Engine disagreement", ""]
    if ed.get("state") == "ONE_ENGINE" or ed.get("counts") is None:
        miss = [f"{md_escape(str(n))}: {md_escape(str(e.get('reason') or 'not run'))}" for n, e in status.items()
                if not e.get("ran")]
        out += [f"- Only {md_escape(', '.join(ran) or 'one engine')} ran ({'; '.join(miss) or 'the other engine did not run'}). "
                "Nothing was compared: this engine's function boundaries are unchecked (unknown, not agreement).",
                f"- Comparison evidence `{ed.get('evidence_id')}`.", ""]
        return out
    c = ed["counts"]
    only = ed.get("only_in") or {}
    cats = []
    for name in ("END_DIFFERS", "ONLY_IN_ONE", "SPLIT_MERGED", "NAME_DIFFERS"):
        extra = (f" (the function is defined by: {_by_engine({k: v for k, v in only[name].items() if v})})"
                 if name in only and c.get(name) else "")
        cats.append(f"{name} {c.get(name, 0)}{extra}")
    inv = ", ".join(f"{md_escape(str(n))} `{e['evidence_id']}`" for n, e in status.items() if e.get("ran"))
    out += [f"- Engines: {md_escape(', '.join(ed.get('engines') or []))} (coverage state {ed.get('state')}); "
            f"functions listed: {_by_engine(ed.get('functions'))}; starts both define: {ed.get('common')}, of which "
            f"no difference found: {ed.get('agreed')}",
            f"- Disagreements by category: {'; '.join(cats)}",
            f"- Real names only one engine gives (not counted as disagreements): {_by_engine(ed.get('named_only_by'))}",
            f"- Evidence: comparison `{ed.get('evidence_id')}` (one row per disagreement, each naming both inventories); "
            f"inventories {inv}",
            "- A disagreement is a place to resolve with the code, not a verdict: neither engine is trusted over the "
            "other.", ""]
    unm = {n: e["unmeasured"] for n, e in status.items() if e.get("unmeasured")}
    if unm:
        out += [f"- Functions without instructions or without a complete disassembly have no end and are compared by "
                f"start and name only: {_by_engine(unm)}.", ""]
    if ed.get("state") != "BOTH_ENGINES":
        out += ["- Function ends were not compared (an engine had no extents): END_DIFFERS and SPLIT_MERGED are not "
                "computed.", ""]
    return out


def _interpretation(c: Mapping[str, Any]) -> list[str]:
    """The model's own reading beside a finding: printed apart from the verified text, never covered by its status."""
    if not c.get("interpretation"):
        return []
    return [f"- Interpretation (model's reading, NOT verified; the status above does not cover it): "
            f"_{md_escape(c['interpretation'])}_", ""]


def _why(reasons: list[dict]) -> str:
    """Reason for the hypothesis: no evidence / unsupported value (supported and unsupported values are separate) / behavior awaiting execution."""
    parts: list[str] = []
    for r in reasons:
        code = r["code"]
        if code == "NO_EVIDENCE":
            return "no evidence reference"
        if code == "VALUE_NOT_IN_EVIDENCE":
            parts.append("VALUE_NOT_IN_EVIDENCE: unsupported value " + ", ".join(
                f"`{md_escape(v['value'])}`" + (" (derived, needs execution)" if v["derived_needs_execution"] else "")
                for v in r["values"]))
            if r["supported_values"]:
                parts.append("supported value " + ", ".join(f"`{md_escape(v)}`" for v in r["supported_values"]))
        elif code == "TERM_NOT_IN_EVIDENCE":
            parts.append("TERM_NOT_IN_EVIDENCE: term not in the cited evidence " + ", ".join(
                f"`{md_escape(t)}`" for t in r["terms"]))
        elif code == "BEHAVIOR_NEEDS_EXECUTION":
            parts.append("BEHAVIOR_NEEDS_EXECUTION: a behavior claim (what happens when the program runs) is supported only by "
                         "execution (run_controlled) evidence")
    return "; ".join(parts) or "not verified (evidence link broken or verification not requested)"


_ASSESS_TR = {"INCOMPLETE": "INCOMPLETE COVERAGE: truncated/failed calls or open unknowns exist",
              "NOT_EXAMINED": "NOT EXAMINED: no evidence was produced",
              "NO_RECORDED_GAPS": "no recorded gaps (this does NOT mean 'clean')"}


def _coverage_section(cov: Mapping[str, Any]) -> list[str]:
    """Coverage and unknowns: missing coverage is unknown, not absence; this section never makes the report 'clean'."""
    a = cov.get("assessment", "INCOMPLETE")
    tools = ", ".join(f"{md_escape(k)} ({v['calls']})" for k, v in sorted((cov.get("tools_run") or {}).items()))
    out = ["## Coverage and unknowns", "",
           f"- Coverage assessment: **{a}** - {_ASSESS_TR.get(a, 'unknown')}",
           "- On its own this report does not say the target is safe/clean: unexamined code and truncated outputs "
           "are unknown, not evidence of absence.",
           f"- Functions examined: {cov.get('functions_examined_total', 0)}, disassembly regions: "
           f"{cov.get('regions_examined_total', 0)}, tools run: {tools or 'none'}",
           f"- Truncated/timed-out/partial calls: {cov.get('incomplete_calls_total', 0)}, failed calls: "
           f"{cov.get('failed_calls_total', 0)}, denied calls: {cov.get('denied_calls', 0)}, open unknowns: "
           f"{cov.get('open_unknowns_total', 0)}, resolved: {cov.get('resolved_unknowns_total', 0)}, withdrawn: "
           f"{cov.get('withdrawn_unknowns_total', 0)}", ""]
    for c in cov.get("incomplete_calls") or []:
        out.append(f"- Truncated/partial: `{c['evidence_id']}` {md_escape(str(c['operation']))} "
                   f"{_params(c.get('parameters'))} status={c['status']} strength={c['strength']}"
                   + (" TIMED OUT" if c.get("timed_out") else "") + (" TRUNCATED" if c.get("truncated") else ""))
    for c in cov.get("failed_calls") or []:
        out.append(f"- Failed call: {md_escape(str(c['tool']))} code={md_escape(str(c.get('code')))} "
                   f"{_params(c.get('args'))}")
    for li in cov.get("listings") or []:
        if not li.get("exhausted"):
            out.append(f"- Listing not exhausted: {md_escape(str(li['tool']))} {li['reached']}/{li['total']}")
    out += ["", "### Open unknowns", ""]
    unk = cov.get("open_unknowns") or []
    if not unk:
        out += ["_No recorded open unknowns (questions the model did not record may still be unknown)._", ""]
    for u in unk:
        extra = (f", address {u['address']}" if u.get("address") else "") + (
            f", evidence {', '.join(u['evidence_ids'])}" if u.get("evidence_ids") else "")
        out.append(f"- `{u['unknown_id']}` ({u['severity']}, {u['status']}{extra}): {md_escape(u['question'])}"
                   + (f" - reason: {md_escape(str(u['reason']))}" if u.get("reason") else ""))
    out.append("")
    closed = cov.get("closed_unknowns") or []
    if closed:
        out += ["### Resolved and withdrawn unknowns", "",
                "_Closed unknowns stay in the ledger; a resolution is only as good as the evidence it cites._", ""]
        for u in closed:
            r = u.get("resolution") or {}
            ev = f", evidence {', '.join(r['evidence_ids'])}" if r.get("evidence_ids") else ""
            out.append(f"- `{u['unknown_id']}` ({u['severity']}, **{u['status']}**{ev}): {md_escape(u['question'])}"
                       + (f" - {md_escape(str(r['reason']))}" if r.get("reason") else ""))
        out.append("")
    return out


def _params(p: Any) -> str:
    if not p:
        return ""
    s = ", ".join(f"{k}={v!r}" for k, v in sorted(dict(p).items()))
    return "(" + md_escape(s[:200]) + ")"
