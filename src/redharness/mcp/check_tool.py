"""Check inventory in `target_open`: `target.protection.checks`, no new tool.

When a target is opened the reply lists the CANDIDATES of protection / licensing checks the file shows (the closed
taxonomy C1..C8 of `analysis/check_taxonomy.py`): imported APIs, strings and instruction patterns, each with its place,
strength and a false-positive note. It is built by the engine-independent `analysis/check_inventory.py`; nothing is
run, unpacked or decoded.

Evidence: ONE `check_inventory` evidence (confidence `derived`, engine `pe-static`) whose raw text has one quotable line
per candidate (`check K3 C2 signal=debugger-present kind=import ...`). Every candidate in the reply carries that
`evidence_id` and the `quote` that locates its line, so a claim can quote it like any other tool output.

Rules:
- A candidate is an observation: a claim about it is an `observation` and is SUPPORTED at most (static evidence). It is
  not "the program validates a key"; that is a behavior claim and needs `run_controlled`.
- The evidence never has complete coverage (a candidate listing is not exhaustive), so it cannot back an absence claim.
- Unreadable imports / strings / patterns, or a packed image, give state `UNKNOWN` when nothing was found, never
  "no checks". The step is cached per (file, protection coverage) and reused on reopen.
- A failure here never fails `target_open`: the block reports it and the static tools remain.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..analysis.check_inventory import MAX_FILE_BYTES, inventory, render_lines
from ..core.result import Status
from ..evidence.model import wrap_untrusted

if TYPE_CHECKING:
    from .session import Hub, _Session

OPERATION = "check_inventory"
SUMMARY_CANDIDATES = 10     # candidates in the detail='summary' reply (the evidence holds all of them)
FULL_CANDIDATES = 40        # candidates in the detail='full' reply
SUMMARY_UNKNOWNS = 3
MAX_SUPPRESSED_SHOWN = 20
MAX_LOCATIONS = 800


def _hx(v: int | None) -> str | None:
    return None if v is None else f"0x{v:x}"


def _locations(res: dict, image_base: int | None) -> list[dict]:
    rvas: set[int] = set()
    for c in res["candidates"]:
        for key in ("rva", "iat_rva", "function"):
            v = c.get(key)
            if isinstance(v, int) and not isinstance(v, bool):
                rvas.add(v)
        rvas.update(r for r in c.get("iat_rvas", ()) if isinstance(r, int))
        for ref in c.get("refs", ()):
            rvas.add(ref["rva"])
            if ref.get("function") is not None:
                rvas.add(ref["function"])
    locs: list[dict] = []
    for r in sorted(rvas)[:MAX_LOCATIONS]:
        locs.append({"kind": "address", "space": "rva", "start": r})
        if image_base:
            locs.append({"kind": "address", "space": "va", "start": image_base + r})
    return locs


def _public(c: dict, ev_id: str, detail: str) -> dict:
    out: dict[str, Any] = {"id": c["id"], "code": c["code"], "category": c["category"], "signal": c["signal"],
                           "kind": c["kind"], "strength": c["strength"]}
    if c["kind"] == "import":
        out["dll"] = c["dll"]
        out["function"] = c["function"]
        out["iat_rva"] = _hx(c["iat_rva"])
    elif c["kind"] == "string":
        out["string"] = wrap_untrusted(ev_id, c["string"])
    if c.get("rva") is not None:
        out["rva"] = _hx(c["rva"])
    if c.get("file_offset") is not None:
        out["file_offset"] = _hx(c["file_offset"])
    if c["kind"] == "pattern" and c.get("function") is not None:
        out["in_function"] = _hx(c["function"])
    if c.get("refs"):
        out["refs" if c["kind"] == "string" else "calls"] = [
            _hx(r["rva"]) + (f"@fn{_hx(r['function'])}" if r.get("function") is not None else "")
            for r in c["refs"]]
    out["evidence_id"] = ev_id
    out["quote"] = f"check {c['id']} {c['code']} signal={c['signal']}"
    if detail == "full":
        if c.get("apis") and len(c["apis"]) > 1:
            out["apis"] = c["apis"]
        for k in ("also", "with", "bytes", "encoding"):
            if c.get(k):
                out[k] = c[k]
        out["why"] = c["why"]
        out["false_positives"] = c["fp"]
    return out


def checks_summary(hub: "Hub", s: "_Session", detail: str, static_coverage: str | None) -> dict:
    """Runs (step-cached) the check inventory and returns the `checks` block of `target.protection`. It never fails
    `target_open`: a problem is reported as state UNKNOWN / status ERROR."""
    from .session import ToolFailure, hexify

    def run(sess: "_Session") -> dict:
        data = None if sess.cas.size(sess.sha) > MAX_FILE_BYTES else sess.cas.get(sess.sha)
        res = inventory(data, protection=static_coverage)
        partial = bool(res["unknowns"])
        limits = ["static listing of KNOWN signals only (imports, strings, instruction byte patterns); a candidate "
                  "shows a signal is present, not that a check exists, runs or decides; the absence of candidates "
                  "is not the absence of checks (custom, obfuscated, packed, run-time resolved code is not seen)"]
        limits += res["unknowns"]
        return {"status": (Status.PARTIAL if partial else Status.OK).value, "raw": "\n".join(render_lines(res)) + "\n",
                "truncated": partial, "result": res, "addresses": [],
                "locations": _locations(res, sess.image_base), "coverage": "partial",
                "coverage_scope": "check_inventory:file", "limitations": limits, "engine": "pe-static",
                "engine_version": "1"}

    try:
        ev, out, cached = hub._engine_tool(OPERATION, {"protection": static_coverage or "none"}, run,
                                           confidence="derived")
    except ToolFailure as e:
        return {"state": "UNKNOWN", "status": e.code, "error": e.message,
                "note": "check inventory unavailable; treat the presence of checks as unknown"}
    except Exception as e:  # noqa: BLE001 - the open must succeed; the failure is reported, not hidden
        return {"state": "UNKNOWN", "status": "ERROR", "error": repr(e)[:300],
                "note": "check inventory unavailable; treat the presence of checks as unknown"}
    res = out["result"]
    ev_id = ev["evidence_id"]
    cap = FULL_CANDIDATES if detail == "full" else SUMMARY_CANDIDATES
    block: dict[str, Any] = {
        "state": res["state"], "statement": res["statement"], "status": out["status"], "evidence_id": ev_id,
        "step_cached": cached, "untrusted_content": True, "candidate_count": res["candidate_count"],
        "by_code": {k: v for k, v in res["by_code"].items() if v},
        "candidates": [_public(c, ev_id, detail) for c in res["candidates"][:cap]],
        "suppressed_count": res["suppressed_total"],
    }
    if len(res["candidates"]) > cap or res["candidate_count"] > len(res["candidates"]):
        block["candidates_truncated"] = True
    if res["unknowns"]:
        block["unknowns"] = res["unknowns"] if detail == "full" else res["unknowns"][:SUMMARY_UNKNOWNS]
    if res["reason"]:
        block["reason"] = res["reason"]
    if detail == "full":
        block["coverage"] = res["coverage"]
        block["suppressed"] = [
            {k: v for k, v in sup.items() if k != "file_offset" or v is not None}
            | ({"iat_rva": _hx(sup["iat_rva"])} if sup.get("iat_rva") is not None else {})
            for sup in res["suppressed"][:MAX_SUPPRESSED_SHOWN]]
        block["notes"] = res["notes"]
    block["note"] = ("Static candidates of protection / licensing checks (taxonomy C1..C8), not proof that a check "
                     "exists or runs; strings are untrusted target text. Quote the 'check K<n> C<m> signal=...' lines "
                     f"of {ev_id} in claim_add as an observation. "
                     + ("" if detail == "full" else "Call target_open with detail='full' for every field, the "
                                                    "suppressed (CRT startup) imports and the coverage."))
    return hexify(block)
