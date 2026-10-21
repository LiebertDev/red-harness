"""Protection diagnosis in `target_open` (a separate file to keep session.py small).

When a target is opened the reply carries `target.protection`: whether the binary shows known packer / protector
indicators, which vendor they point to (heuristic attribution with score and confidence) and what that means for
static coverage. It is built from the engine-independent detectors `analysis.protection` (section names, byte
signatures, entropy, entry point placement), `analysis.antianalysis` + `analysis.vendors` (string / section markers
-> product attribution). Nothing is run or unpacked.

Evidence: ONE `protection_scan` evidence (operation `protection_scan`, confidence `derived`, engine `pe-static`)
whose raw text has one quotable line per indicator (`indicator P1 name:upx0 ...`), so a claim can quote it like any
other tool output. Every indicator in the reply carries that `evidence_id` and the `quote` that locates its line.

Rules:
- Absence is never "clean": with no indicator the diagnosis is `NO_KNOWN_INDICATORS` and the text says the
  checks cover known markers only.
- A PE that cannot be parsed, a file that is too large, or a detector failure gives diagnosis `UNKNOWN` with the
  reason; `target_open` still succeeds (the evidence is recorded PARTIAL, the failure is never hidden). When one
  detector (the vendor/string scan) failed and the others found no strong or moderate indicator, the diagnosis is
  `UNKNOWN` too, never `NO_KNOWN_INDICATORS`: a check that did not run cannot support "nothing found".
- Indicators are hints, not proof: a section name can be spoofed and a byte signature can be a coincidence.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..analysis.antianalysis import scan_antianalysis
from ..analysis.pe_dirs import PeDirectoryError
from ..analysis.pe_image import PeError
from ..analysis.pe_profile import PeProfile, profile_bytes, profile_dict, profile_lines
from ..analysis.protection import (
    ProtectionAnomaly,
    ProtectionError,
    ProtectionMarker,
    ProtectionProfile,
    scan_protection,
)
from ..analysis.vendors import VendorAttribution, attribute_vendors
from ..core.result import Status
from ..evidence.model import wrap_untrusted

if TYPE_CHECKING:
    from .session import Hub, _Session

OPERATION = "protection_scan"
MAX_FILE_BYTES = 32 * 1024 * 1024   # the entropy pass is pure Python: larger files are reported UNKNOWN, not guessed
SUMMARY_INDICATORS = 10             # indicators in the detail='summary' reply (the evidence holds all of them)
FULL_INDICATORS = 40                # indicators in the detail='full' reply
MAX_OFFSETS = 3                     # file offsets listed per grouped byte-signature / vendor string
MAX_SECTIONS = 24
PROFILE_LINES_SUMMARY = 40          # pe_profile lines in the detail='summary' reply (the evidence holds all of them)
PROFILE_LINES_FULL = 120

DIAGNOSES = ("INDICATORS_FOUND", "NO_KNOWN_INDICATORS", "UNKNOWN")
STRENGTH_ORDER = {"strong": 0, "moderate": 1, "weak": 2}

# Byte signatures specific enough to be "moderate"; the other signatures are ordinary words ("Themida", "Enigma")
# that can sit in any security tool's string table, so they stay "weak" (the vendor attribution scores them).
_MODERATE_SIGNATURES = frozenset({"sig:UPX!", "sig:MPRESS1", "sig:MPRESS2"})

_COVERAGE_TEXT = {
    "likely_partial": (
        "Strong packer/protector indicators found. Static coverage of the program's real code is likely partial: "
        "functions_list / decompile / disassemble may show only the unpacking or virtualization stub or encrypted "
        "bytes, and strings and imports may not reflect the real program. Treat missing functions, strings and "
        "imports as unknown, not as absent."),
    "possibly_partial": (
        "Protector indicators found (moderate evidence). Static coverage of code may be partial; check the listed "
        "indicators against decompile output before drawing conclusions from something being absent."),
    "no_known_indicators": (
        "No known protector indicators found by these checks (section names, byte signatures, entropy, entry "
        "point placement, vendor markers). This does not establish that the binary is unprotected: unknown or "
        "custom protectors, virtualization and obfuscation are not detected by them."),
    "unassessed": "Protection could not be assessed ({reason}). Static coverage caveats are UNKNOWN.",
    "incomplete_checks": (
        "Protection could not be fully assessed: {reason}. No strong or moderate indicator was found by the checks "
        "that did run (section names, byte signatures, entropy, entry point placement), but the check that did not "
        "run could have found one, so the absence of indicators is UNKNOWN, not 'no known indicators'. Static "
        "coverage caveats are UNKNOWN."),
}

_ANOMALY_TEXT = {
    "entry_point_outside_code": "entry point is not inside an executable section (typical of a packer stub)",
    "wx_section": "section is both executable and writable (self-modifying or unpacking code is possible)",
    "high_entropy_section": "section has very high entropy (compressed or encrypted bytes)",
    "overlay_present": "bytes after the last section are not part of the mapped image (may be an Authenticode "
                       "signature, an installer payload or appended data); engine analysis does not cover them",
}


def _ev_safe(s: str) -> str:
    """Target-controlled text (section names) on one raw line: no control characters."""
    return "".join(c if 32 <= ord(c) < 127 else f"\\x{ord(c) & 0xff:02x}" for c in s)


def _hx(v: int | None) -> str:
    return "none" if v is None else f"0x{v:x}"


# ----------------------------------------------------------------------------------------- indicators


def _marker_indicators(markers: tuple[ProtectionMarker, ...], profile: ProtectionProfile) -> list[dict]:
    out: list[dict] = []
    by_name = {s.name.strip().lower(): s for s in profile.sections}
    sig_groups: dict[str, list[ProtectionMarker]] = {}
    for m in markers:
        if m.kind == "section-name":
            sec = by_name.get(m.id.split(":", 1)[1])
            out.append({"name": m.id, "source": "section-name", "strength": "strong",
                        "section": _ev_safe(sec.name.strip()) if sec else None,
                        "rva": sec.va if sec else None,
                        "file_offset": sec.raw_offset if sec and sec.raw_size else None,
                        "why": "section name is a known packer/protector section name (names can be spoofed)"})
        else:
            sig_groups.setdefault(m.id, []).append(m)
    for mid, ms in sorted(sig_groups.items()):
        offs = sorted(m.file_offset for m in ms if m.file_offset is not None)
        total = max(m.total_matches for m in ms)     # records are capped in the detector; this is the true count
        out.append({"name": mid, "source": "byte-signature",
                    "strength": "moderate" if mid in _MODERATE_SIGNATURES else "weak",
                    "file_offset": offs[0] if offs else None, "offsets": offs[:MAX_OFFSETS],
                    "occurrences": total,
                    "why": f"byte signature {mid.split(':', 1)[1]!r} found in the file (a coincidence is possible)"})
    return out


def _anomaly_indicators(anomalies: tuple[ProtectionAnomaly, ...], profile: ProtectionProfile) -> list[dict]:
    out: list[dict] = []
    by_va = {s.va: s for s in profile.sections}
    for a in anomalies:
        sec = by_va.get(a.rva) if a.id in ("wx_section", "high_entropy_section") else None
        strength = "weak"
        why = _ANOMALY_TEXT.get(a.id, "static anomaly")
        if a.id == "entry_point_outside_code":
            if a.rva == 0:
                why = "image declares no entry point (RVA 0), e.g. a resource-only DLL; not a packer sign by itself"
            else:
                strength = "strong"
                if profile.entry_point_section:
                    why += f" (entry point is in {_ev_safe(profile.entry_point_section)})"
        elif a.id == "high_entropy_section":
            if sec is not None and sec.is_executable:
                strength = "strong"
            else:
                why += " but it is not executable: may be compressed data or resources"
        out.append({"name": f"anomaly:{a.id}", "source": "anomaly", "strength": strength,
                    "section": _ev_safe(sec.name.strip()) if sec else (
                        _ev_safe(profile.entry_point_section) if a.id == "entry_point_outside_code"
                        and profile.entry_point_section else None),
                    "rva": a.rva, "file_offset": a.file_offset, "why": why,
                    **({"entropy": f"{sec.entropy:.2f}"} if sec and sec.entropy is not None
                       and a.id == "high_entropy_section" else {})})
    return out


def _vendor_indicators(vendors: tuple[VendorAttribution, ...]) -> list[dict]:
    out: list[dict] = []
    for v in vendors:
        offs = sorted({m.file_offset for m in v.matches if m.file_offset is not None})
        strength = "strong" if v.kind == "protector" and v.confidence == "strong" else "moderate"
        out.append({"name": f"vendor:{v.vendor_id}", "source": "vendor", "strength": strength,
                    "vendor": {"id": v.vendor_id, "name": v.name, "kind": v.kind, "score": v.score,
                               "confidence": v.confidence, "groups": list(v.groups)},
                    "file_offset": offs[0] if offs else None, "offsets": offs[:MAX_OFFSETS],
                    "matched": [f"{m.kind}:{m.value}" for m in v.matches][:8],
                    "why": f"markers point to {v.name} ({v.kind}); heuristic attribution, not proof that the "
                           f"product is active" + (f"; {v.note}" if v.note else "")})
    return out


def _line(p: dict) -> str:
    """The quotable evidence line of one indicator (the reply's `quote` is the prefix up to the first `|`)."""
    bits = [f"indicator {p['id']} {p['name']}", f"strength={p['strength']}"]
    if p.get("section"):
        bits.append(f"section={p['section']}")
    if p.get("rva") is not None:
        bits.append(f"rva={_hx(p['rva'])}")
    if p.get("file_offset") is not None:
        bits.append(f"file_offset={_hx(p['file_offset'])}")
    if p.get("offsets") and len(p["offsets"]) > 1:
        bits.append("offsets=" + ",".join(_hx(o) for o in p["offsets"]))
    if p.get("occurrences", 1) > 1:
        bits.append(f"occurrences={p['occurrences']}")
    if p.get("vendor"):
        v = p["vendor"]
        bits.append(f"vendor={v['name']!r} kind={v['kind']} confidence={v['confidence']} score={v['score']}")
        bits.append("matched=" + ",".join(p["matched"]))
    if p.get("entropy") is not None:
        bits.append(f"entropy={p['entropy']}")
    return " ".join(bits) + " | " + p["why"]


def _flags(s) -> str:
    return ("R" + ("W" if s.is_writable else "-") + ("X" if s.is_executable else "-"))


def diagnose(data: bytes | None) -> dict:
    """Pure function: file bytes -> the full step output (`result` plus evidence `raw`). Never raises.
    `data=None` means the file is over the size limit (reported UNKNOWN)."""
    reason: str | None = None
    profile: ProtectionProfile | None = None
    vendors: tuple[VendorAttribution, ...] = ()
    notes: list[str] = []
    vendor_note: str | None = None
    if data is None:
        reason = f"file is larger than the {MAX_FILE_BYTES // (1024 * 1024)} MiB protection-scan limit"
    else:
        try:
            profile = scan_protection(data)
        except ProtectionError as e:
            reason = _ev_safe(f"not a readable PE: {e}")
        except Exception as e:  # noqa: BLE001 - target_open must succeed; the failure is reported
            reason = _ev_safe(f"protection scan failed: {e!r}"[:200])
    if profile is not None:
        try:
            vendors = attribute_vendors(scan_antianalysis(data))
        except (PeError, PeDirectoryError, ProtectionError) as e:
            vendor_note = _ev_safe(f"vendor attribution unavailable (import/string scan failed: {e})"[:240])
        except Exception as e:  # noqa: BLE001
            vendor_note = _ev_safe(f"vendor attribution unavailable ({e!r})"[:240])
    pe_prof: PeProfile | None = None
    pe_prof_err: str | None = None
    if data is None:
        pe_prof_err = "file over the size limit"
    else:
        try:
            pe_prof = profile_bytes(data)
        except Exception as e:  # noqa: BLE001 - the profile is additive; its failure is reported, never hidden
            pe_prof_err = _ev_safe(f"{e}"[:160])
    return _assemble(profile, vendors, reason, vendor_note, notes, pe_prof, pe_prof_err)


def _profile_conflicts(profile: ProtectionProfile, pp: PeProfile) -> list[str]:
    """The protection diagnosis and the PE profile share rules (entry point, overlay, W+X); a disagreement is a bug
    and is shown as a note instead of being left for the reader to discover."""
    out: list[str] = []
    ids = {a.id for a in profile.anomalies}
    if (pp.entry_in_exec is not True) != ("entry_point_outside_code" in ids):
        out.append("entry point")
    if (pp.overlay_size > 0) != ("overlay_present" in ids):
        out.append("overlay")
    if any("writable+executable" in s.notes for s in pp.sections) != ("wx_section" in ids):
        out.append("writable+executable sections")
    return out


def _assemble(profile: ProtectionProfile | None, vendors: tuple[VendorAttribution, ...], reason: str | None,
              vendor_note: str | None, notes: list[str], pe_prof: PeProfile | None = None,
              pe_prof_err: str | None = None) -> dict:
    indicators: list[dict] = []
    sections: list[dict] = []
    if profile is not None:
        indicators = (_marker_indicators(profile.markers, profile) + _anomaly_indicators(profile.anomalies, profile)
                      + _vendor_indicators(vendors))
        indicators.sort(key=lambda p: (STRENGTH_ORDER[p["strength"]], p["name"],
                                       p["file_offset"] if p["file_offset"] is not None else -1))
        for i, p in enumerate(indicators, 1):
            p["id"] = f"P{i}"
        for s in profile.sections:
            sections.append({"name": _ev_safe(s.name.strip()), "rva": s.va, "vsize": s.vsize,
                             "file_offset": s.raw_offset, "raw_size": s.raw_size,
                             "entropy": None if s.entropy is None else f"{s.entropy:.2f}",   # string: evidence results hold no floats
                             "flags": _flags(s)})
        if any(i["source"] == "byte-signature" for i in indicators):
            notes.append("byte signatures are matched anywhere in the file (headers, overlay, data); a match can "
                         "be a coincidence and is not proof of a packer")
        for s in profile.sections:
            if s.entropy is None:
                notes.append(f"section {_ev_safe(s.name.strip())} has no raw data: entropy not measured "
                             "(not treated as 0)")
    strengths = {p["strength"] for p in indicators}
    if profile is None:
        diagnosis, coverage = "UNKNOWN", "unassessed"
    elif "strong" in strengths:
        diagnosis, coverage = "INDICATORS_FOUND", "likely_partial"
    elif "moderate" in strengths:
        diagnosis, coverage = "INDICATORS_FOUND", "possibly_partial"
    elif vendor_note:
        # a detector did not run: missing coverage is unknown, never clean
        diagnosis, coverage = "UNKNOWN", "unassessed"
        reason = vendor_note
    else:
        diagnosis, coverage = "NO_KNOWN_INDICATORS", "no_known_indicators"
    statement = _COVERAGE_TEXT["incomplete_checks" if (profile is not None and diagnosis == "UNKNOWN")
                               else coverage].format(reason=reason or "")
    if vendor_note and diagnosis == "INDICATORS_FOUND":
        statement += f" Note: {vendor_note}; the vendor-marker check did not run, so there may be more indicators."
    weak = [p for p in indicators if p["strength"] == "weak"]
    if diagnosis == "NO_KNOWN_INDICATORS" and weak:
        statement += f" {len(weak)} weak signal(s) are listed below; they are hints, not protector indicators."
    if vendor_note:
        notes.append(vendor_note)

    for p in indicators:
        p["text"] = _line(p)
    lines = [f"protection_scan diagnosis={diagnosis} static_coverage={coverage} indicators={len(indicators)}"
             + (f" sha256={profile.sha256} file_size={profile.file_size}" if profile else "")]
    if profile is not None:
        for s in sections:
            ent = "not-measured" if s["entropy"] is None else f"{s['entropy']}"
            lines.append(f"section {s['name']} rva={_hx(s['rva'])} vsize={_hx(s['vsize'])} "
                         f"file_offset={_hx(s['file_offset'])} raw_size={_hx(s['raw_size'])} entropy={ent} "
                         f"flags={s['flags']}")
        ep_exec = {True: "true", False: "false", None: "unknown"}[profile.entry_point_in_exec]
        lines.append(f"entry_point rva={_hx(profile.entry_point_rva)} "
                     f"section={_ev_safe(profile.entry_point_section) if profile.entry_point_section else 'none'} "
                     f"in_executable_section={ep_exec}")
    lines += [p["text"] for p in indicators]
    if pe_prof is not None:
        if profile is not None:
            bad = _profile_conflicts(profile, pe_prof)
            if bad:
                notes.append("INCONSISTENT: pe_profile and the protection scan disagree on " + ", ".join(bad)
                             + "; treat both as unverified")
        lines += profile_lines(pe_prof)
    elif pe_prof_err:
        lines.append(f"pe_profile unavailable({pe_prof_err})")
    if reason:
        lines.append(f"unknown protection not assessed: {reason}")
    lines += [f"note {n}" for n in notes]
    lines.append("statement " + statement)
    result = {"diagnosis": diagnosis, "static_coverage": coverage, "statement": statement,
              "indicators": indicators, "sections": sections,
              "entry_point": ({"rva": profile.entry_point_rva,
                               "section": (_ev_safe(profile.entry_point_section)
                                           if profile.entry_point_section is not None else None),
                               "in_executable_section": profile.entry_point_in_exec} if profile else None),
              "vendors": [i["vendor"] | {"matched": i["matched"]} for i in indicators if i.get("vendor")],
              "notes": notes, "reason": reason,
              "pe_profile": profile_dict(pe_prof) if pe_prof is not None else None,
              "pe_profile_lines": profile_lines(pe_prof) if pe_prof is not None else [],
              "pe_profile_unavailable": pe_prof_err}
    return {"result": result, "raw": "\n".join(lines) + "\n"}


# ------------------------------------------------------------------------------------------- reply


def _locations(result: dict, image_base: int | None) -> list[dict]:
    locs: list[dict] = []
    seen: set[tuple[int, int]] = set()
    for s in result["sections"]:
        rng = (s["rva"], s["rva"] + max(s["vsize"], 1))
        flagged = any(p.get("section") == s["name"] or p.get("rva") == s["rva"] for p in result["indicators"])
        if not flagged or rng in seen:
            continue
        seen.add(rng)
        locs.append({"kind": "address-range", "space": "rva", "start": rng[0], "end": rng[1]})
        if image_base:
            locs.append({"kind": "address-range", "space": "va", "start": image_base + rng[0],
                         "end": image_base + rng[1]})
    return locs


def _public_indicator(p: dict, ev_id: str, detail: str) -> dict:
    keys = ("id", "name", "strength", "section", "rva", "file_offset")
    out = {k: p[k] for k in keys if p.get(k) is not None}
    out["evidence_id"] = ev_id
    out["quote"] = f"indicator {p['id']} {p['name']}"
    if p.get("vendor"):
        out["vendor"] = p["vendor"]["name"]
    if detail == "full":
        if p.get("offsets"):
            out["offsets"] = [_hx(o) for o in p["offsets"]]
        if p.get("occurrences", 1) > 1:
            out["occurrences"] = p["occurrences"]
        if p.get("matched"):
            out["matched"] = p["matched"]
        if p.get("entropy") is not None:
            out["entropy"] = p["entropy"]
        out["why"] = p["why"]
    return out


def protection_summary(hub: "Hub", s: "_Session", detail: str = "summary") -> dict:
    """Runs (step-cached) the protection diagnosis and returns the `protection` block of the target_open reply. It never
    fails target_open: a problem is reported as diagnosis UNKNOWN / status ERROR, and static tools remain."""
    from .session import ToolFailure, hexify

    def run(sess: "_Session") -> dict:
        out = diagnose(None if sess.cas.size(sess.sha) > MAX_FILE_BYTES else sess.cas.get(sess.sha))
        res = out["result"]
        partial = res["diagnosis"] == "UNKNOWN" or any("unavailable" in n for n in res["notes"])
        limits = ["heuristic scan of section names, byte signatures, entropy, entry point placement and vendor "
                  "markers; it detects KNOWN markers only (custom packers, virtualization and obfuscation are not "
                  "detected); a hit is a hint, not proof, and nothing was unpacked or run"]
        if res["reason"]:
            limits.append(res["reason"])
        return {"status": (Status.PARTIAL if partial else Status.OK).value, "raw": out["raw"], "truncated": partial,
                "result": res, "addresses": [], "locations": _locations(res, sess.image_base),
                "coverage": "partial" if partial else "complete", "coverage_scope": "protection_scan:file",
                "limitations": limits, "engine": "pe-static", "engine_version": "1"}

    try:
        ev, out, cached = hub._engine_tool(OPERATION, {}, run, confidence="derived")
    except ToolFailure as e:
        return {"diagnosis": "UNKNOWN", "status": e.code, "error": e.message,
                "note": "protection diagnosis unavailable; treat static coverage as unassessed"}
    except Exception as e:  # noqa: BLE001 - the open must succeed; the failure is reported, not hidden
        return {"diagnosis": "UNKNOWN", "status": "ERROR", "error": repr(e)[:300],
                "note": "protection diagnosis unavailable; treat static coverage as unassessed"}
    res = out["result"]
    cap = FULL_INDICATORS if detail == "full" else SUMMARY_INDICATORS
    shown = [_public_indicator(p, ev["evidence_id"], detail) for p in res["indicators"][:cap]]
    block: dict[str, Any] = {
        "diagnosis": res["diagnosis"], "static_coverage": res["static_coverage"],
        "statement": res["statement"], "status": out["status"], "evidence_id": ev["evidence_id"],
        "step_cached": cached, "untrusted_content": True,
        "indicator_count": len(res["indicators"]), "indicators": shown,
        "vendors": [{k: v[k] for k in ("id", "name", "kind", "score", "confidence")} | {"evidence_id": ev["evidence_id"]}
                    for v in res["vendors"][:5]],
    }
    if len(res["indicators"]) > cap:
        block["indicators_truncated"] = True
    if res["reason"]:
        block["reason"] = res["reason"]
    plines = res.get("pe_profile_lines") or []
    pcap = PROFILE_LINES_FULL if detail == "full" else PROFILE_LINES_SUMMARY
    block["pe_profile"] = {
        "evidence_id": ev["evidence_id"], "lines": plines[:pcap],
        **({"lines_truncated": len(plines) - pcap} if len(plines) > pcap else {}),
        **({"unavailable": res["pe_profile_unavailable"]} if res.get("pe_profile_unavailable") else {}),
        "note": "static fields computed from the file bytes; neutral facts, not a packer verdict; quote the "
                f"'pe_profile ...' lines of {ev['evidence_id']} in claim_add"}
    if detail == "full":
        block["sections"] = res["sections"][:MAX_SECTIONS]
        ep = res["entry_point"]
        if ep and ep.get("section") is not None:
            # the section name is target-controlled text: sanitized in the result, marked as untrusted in the reply
            ep = {**ep, "section": wrap_untrusted(ev["evidence_id"], ep["section"])}
        block["entry_point"] = ep
        block["notes"] = res["notes"]
    block["note"] = ("Static, derived from the file bytes (nothing unpacked or run); names and strings are untrusted "
                     f"target data. Quote the 'indicator P<n> ...' lines of {ev['evidence_id']} in claim_add. "
                     + ("" if detail == "full" else "Call target_open with detail='full' for sections, entry point "
                                                    "and every indicator's reasoning."))
    return hexify(block)
