"""Simple Markdown report generator (verified claims only).

The input is claims the caller (Hub.report_build) has re-verified; this module is pure formatting and
does not bypass verification. Rules:
- Findings: only SUPPORTED/PROVEN claims that passed re-verification.
- "Unverified hypotheses": UNVERIFIED claims with an empty evidence reference, whose value is not in the evidence, whose behavior claim awaits execution evidence
  (or whose evidence link is broken); they never mix into the findings. Retracted (superseded) claims are not printed.
- Claim text is agent output: Markdown special characters are escaped. Evidence quotes come from the target:
  they are printed in a code block with an "untrusted" note.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>#|~])")
_RANK = {"observed": 0, "derived": 1, "inferred": 2}


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


def _bundle_sha(imported: Mapping[str, Any]) -> str:
    sha = str(imported.get("source_bundle_sha256") or "")
    return sha if re.fullmatch(r"[0-9a-f]{64}", sha) else "unknown"


def render_report(*, target_sha256: str, job_id: str, findings: list[dict], hypotheses: list[dict],
                  counts: Mapping[str, int], evidence: Mapping[str, Mapping[str, Any]],
                  coverage: Mapping[str, Any] | None = None, imported: Mapping[str, Any] | None = None) -> str:
    """findings/hypotheses items: recorded rh.claim/1 dict + `final_status` (findings only)."""
    out = ["# Red Harness report", "",
           f"- Target SHA-256: `{target_sha256}`", f"- Job: `{job_id}`",
           *([f"- Imported bundle: authenticity not established (source sha256 `{_bundle_sha(imported)}`); "
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
    if not findings:
        out += ["_No verified findings._", ""]
    for c in findings:
        evs = [evidence[e] for e in c["evidence_ids"] if e in evidence]
        out += [f"### {c['claim_id']} - {c['final_status']}", "",
                md_escape(c["text"]), "", *_interpretation(c),
                f"- Kind: {c['kind']}, polarity: {c['polarity']}, evidence confidence (lowest): {lowest_confidence(evs)}"]
        for e in evs:
            out.append(f"- Evidence `{e['evidence_id']}`: {e['operation']} {_params(e.get('parameters'))}")
        if any(e.get("authority") == "cpu-emulation" for e in evs):
            out.append("- Basis: CPU emulation of the target's code from the file image (an observation of emulation, "
                       "not of a program run)")
        if any(e.get("authority") == "dynamic-region-view" for e in evs):
            out.append("- Basis: a read-only view of bytes captured from target memory in one observed run (derived "
                       "from the linked dynamic observation; nothing was executed or rebuilt)")
        for a in c.get("atoms") or []:
            if a.get("type") == "quote":
                out += ["", f"Quote (from the target, untrusted; evidence `{a.get('evidence_id')}`):", fence(str(a.get("text")))]
            elif a.get("type") == "address":
                out.append(f"- Address ({a.get('space', 'file_offset')}): `{a.get('value')}`")
            elif a.get("type") == "constant":
                out.append(f"- Constant: `{a.get('value')}`")
        out.append("")
    out += ["## Unverified hypotheses", ""]
    if not hypotheses:
        out += ["_No hypotheses._", ""]
    for c in hypotheses:
        out += [f"- `{c['claim_id']}` (UNVERIFIED, {_why(c)}): {md_escape(c['text'])}"
                + (f" Interpretation (not verified): _{md_escape(c['interpretation'])}_" if c.get("interpretation")
                   else "")]
    out.append("")
    if coverage is not None:
        out += _coverage_section(coverage)
    return "\n".join(out)


def _interpretation(c: Mapping[str, Any]) -> list[str]:
    """The model's own reading beside a finding: printed apart from the verified text, never covered by its status."""
    if not c.get("interpretation"):
        return []
    return [f"- Interpretation (model's reading, NOT verified; the status above does not cover it): "
            f"_{md_escape(c['interpretation'])}_", ""]


def _why(c: Mapping[str, Any]) -> str:
    """Reason for the hypothesis: no evidence / unsupported value (supported and unsupported values are separate) / behavior awaiting execution."""
    if not c["evidence_ids"]:
        return "no evidence reference"
    ver = c.get("verification") or {}
    issues = ver.get("issues", [])
    parts: list[str] = []
    bad = [i for i in issues if i.get("code") in ("VALUE_NOT_IN_EVIDENCE", "VALUE_DERIVED_NEEDS_EXECUTION")]
    if bad:
        parts.append("VALUE_NOT_IN_EVIDENCE: unsupported value " + ", ".join(
            f"`{md_escape(str(i.get('detail')))}`" + (" (derived, needs execution)"
                                                    if i["code"] == "VALUE_DERIVED_NEEDS_EXECUTION" else "")
            for i in bad))
        ok = [v for v in ver.get("values", []) if v.get("supported")]
        if ok:
            parts.append("supported value " + ", ".join(f"`{md_escape(str(v['value']))}`" for v in ok))
    terms = [str(i.get("detail")) for i in issues if i.get("code") == "TERM_NOT_IN_EVIDENCE"]
    if terms:
        parts.append("TERM_NOT_IN_EVIDENCE: term not in the cited evidence " + ", ".join(
            f"`{md_escape(t)}`" for t in terms))
    if any(i.get("code") == "BEHAVIOR_NEEDS_EXECUTION" for i in issues):
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
           f"{cov.get('open_unknowns_total', 0)}", ""]
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
    return out


def _params(p: Any) -> str:
    if not p:
        return ""
    s = ", ".join(f"{k}={v!r}" for k, v in sorted(dict(p).items()))
    return "(" + md_escape(s[:200]) + ")"
