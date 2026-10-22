"""`functions_list(engines="both")`: the function inventory of the open target from BOTH engines (IDA and Ghidra), and where
they disagree. No new tool: an option of `functions_list`, so a single engine's function boundaries are never silently
trusted when the second engine is installed.

Evidence (all `functions_list`, all bound to the job's target SHA-256):
- one INVENTORY evidence per engine (`engines=both, engine=<name>`): one quotable line per function that engine defines
  (`0x140001000 name end=0x140001040 insns=12 chunks=1`), built from the engine's whole-function disassembly (so the end
  is the end of the last instruction, chunks included; see analysis/engine_disagreement.py);
- one COMPARISON evidence (`engines=both`, paged): the closed classification of the differences
  (analysis/engine_disagreement.py), one row per disagreeing function, each row naming BOTH inventory evidence ids.

Coverage states (closed set): BOTH_ENGINES, BOTH_ENGINES_STARTS_AND_NAMES_ONLY (an engine's extents were unavailable) and
ONE_ENGINE (the other engine is not installed, could not open the target or failed): then nothing was compared; the
comparison evidence is PARTIAL and says why. That is unknown, never agreement.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..analysis import engine_disagreement as ed
from ..core.result import Status
from ..engines.base import Engine

if TYPE_CHECKING:
    from .session import Hub, _Session

OTHER_ENGINE = {"ida": "ghidra", "ghidra": "ida"}
VIEW = "both"
BULK_INSNS = 60_000            # instructions per bulk whole-function disassembly run (the same chunking as compare=fixed)
MAX_FUNCTIONS = 20_000         # more functions or instructions than this: extents are not computed (starts and names only)
MAX_INSNS = 2_000_000
SUMMARY_ROWS = 5
REASON_MAX = 300


def second_engine(hub: "Hub") -> tuple[Engine | None, str]:
    """(the engine that is not the job's engine, "") or (None, why it cannot be used). A built engine is kept."""
    if hub._second is not None:
        return hub._second, ""
    other = OTHER_ENGINE.get(hub.engine.name)
    if other is None:
        return None, f"no second engine is defined for engine {hub.engine.name!r} (supported pair: ida and ghidra)"
    from .server import make_engine
    try:
        eng = make_engine(other, hub.config)
    except Exception as e:  # noqa: BLE001 - not installed / probe failed: the call reports one engine, it does not fail
        return None, str(e)[:REASON_MAX] or type(e).__name__
    hub._second = eng
    return eng, ""


def _inventory(hub: "Hub", eng: Engine, sha: str) -> ed.Inventory:
    """Every function the engine defines, with the extent of its body when the bulk whole-function disassembly runs to the
    end; otherwise starts and names only (extents=False, with the reason)."""
    from .session import ToolFailure, _EngineFailure
    funcs: list[ed.EngineFunc] = []
    note = ""
    try:
        first, n_insns = 0, 0
        while True:
            r = eng.disassemble_functions(sha, first=first, max_insns=BULK_INSNS)
            hub._ok_or_raise(r)
            for b in r.data.items:
                funcs.append(ed.func_from_body(b))
                n_insns += len(b.disassembly.items)
            if r.data.next_index is None:
                if len(funcs) != r.data.total:
                    raise _EngineFailure(Status.ERROR, f"the engine listed {r.data.total} functions but returned {len(funcs)}")
                break
            if r.data.next_index <= first or not r.data.items:
                raise _EngineFailure(Status.ERROR, "the engine made no progress in the bulk disassembly")
            if len(funcs) > MAX_FUNCTIONS or n_insns > MAX_INSNS:
                raise ToolFailure("BUILD_TOO_LARGE", f"more than {MAX_FUNCTIONS} functions or {MAX_INSNS} instructions")
            first = r.data.next_index
    except (_EngineFailure, ToolFailure) as e:
        funcs, note = [], (getattr(e, "detail", None) or getattr(e, "message", None) or str(e))[:REASON_MAX]
    if funcs or not note:   # the bulk run finished; a function without instructions simply has no extent (counted apart)
        return ed.Inventory(eng.name, tuple(funcs), True)
    off = 0   # no extents: the plain function list (starts and names)
    plain: list[ed.EngineFunc] = []
    while True:
        r = eng.functions(sha, offset=off, limit=200)
        hub._ok_or_raise(r)
        plain += [ed.func_from_info(f) for f in r.data.items]
        if not r.data.has_more or not r.data.items:
            break
        off += len(r.data.items)
    return ed.Inventory(eng.name, tuple(plain), False, note or "no whole-function disassembly")


def _inventory_step(hub: "Hub", s: "_Session", eng: Engine, version: str) -> tuple[dict, ed.Inventory, bool]:
    """(inventory evidence, the inventory, step_cached) of one engine; step-cached per (target, engine, engine version)."""
    from .session import ToolFailure

    def run(sess: "_Session") -> dict:
        r = eng.open_target(sess.path)   # analysed once per SHA-256 (cached like any target); static, nothing runs
        hub._ok_or_raise(r)
        if r.data.sha256 != sess.sha:
            raise ToolFailure("ARTIFACT_CHANGED", f"{eng.name}: the target file changed after the manifest check; use "
                                                  "the original file")
        inv = _inventory(hub, eng, sess.sha)
        raw = "".join(ed.inventory_line(f) for f in inv.funcs)
        with_extent = len(inv.funcs) - inv.unmeasured if inv.extents else 0
        lim = [f"function ends come from the whole-function disassembly of {eng.name}; a function without instructions "
               "(for example a forwarded-export record) or without a complete disassembly has no end"]
        if not inv.extents:
            lim.append(f"extents unavailable: {inv.extent_note}")
        return {"status": (Status.OK if inv.extents else Status.PARTIAL).value, "raw": raw, "truncated": False,
                "result": {"engine": eng.name, "function_count": len(inv.funcs), "with_extent": with_extent,
                           "extents": inv.extents},
                "addresses": [], "coverage": "complete" if inv.extents else "partial",
                "coverage_scope": f"functions-engine:{eng.name}", "limitations": lim,
                "engine": eng.name, "engine_version": version.split(":", 1)[1], "inventory": inv.to_dict()}

    args = {"engines": VIEW, "engine": eng.name}
    ev, out, cached = hub._engine_tool("functions_list", args, run, engine_version=version)
    return ev, ed.Inventory.from_dict(out["inventory"]), cached


def report_block(evidence: Any) -> dict | None:
    """The `engine_disagreement` block of the report: the summary of the LATEST engines='both' comparison evidence in the
    ledger (None when there is none). It is read from the evidence record, so the report and the tool cannot disagree."""
    last = None
    for e in evidence.values():
        res = e.get("result") or {}
        if e.get("operation") == "functions_list" and (e.get("parameters") or {}).get("engines") == VIEW \
                and "state" in res:
            last = e
    if last is None:
        return None
    r = last["result"]
    keys = ("state", "engines", "engine_status", "functions", "common", "agreed", "counts", "only_in",
            "named_only_by", "explained_end_differs")
    return {"evidence_id": last["evidence_id"], **{k: r.get(k) for k in keys}}


def functions_both(hub: "Hub", offset: int, limit: int, detail: str) -> dict:
    from .session import RESPONSE_BUDGET, ToolFailure, _locations, hexify
    s = hub._need()
    ev_p, inv_p, _ = _inventory_step(hub, s, hub.engine, s.engine_version)
    other, why = second_engine(hub)
    ev_s = inv_s = None
    ver_s = ""
    if other is not None:
        try:
            ver_s = f"{other.name}:{other.probe().version}"
            ev_s, inv_s, _ = _inventory_step(hub, s, other, ver_s)
        except ToolFailure as e:   # the other engine could not open or list the target: reported, never hidden
            why = f"{e.code}: {e.message}"[:REASON_MAX]
    ran = {hub.engine.name: (ev_p, inv_p)}
    if inv_s is not None:
        ran[other.name] = (ev_s, inv_s)
    engines = {n: {"ran": True, "evidence_id": e["evidence_id"], "functions": len(i.funcs), "extents": i.extents,
                   **({"unmeasured": i.unmeasured} if i.extents else {"extent_note": i.extent_note})}
               for n, (e, i) in ran.items()}
    if inv_s is None:
        engines[other.name if other is not None else OTHER_ENGINE.get(hub.engine.name, "second")] = {
            "ran": False, "reason": why or "not run"}
    args = {"offset": offset, "limit": limit, "engines": VIEW}
    versions = "+".join(s.engine_version.split(":", 1)[1:] + ver_s.split(":", 1)[1:])
    key_version = f"{s.engine_version}+{ver_s}" if ver_s else s.engine_version

    def run(sess: "_Session") -> dict:
        names = sorted(engines)
        if inv_s is None:
            only = hub.engine.name
            header = (f"# engine disagreement: sha256={sess.sha} engines={','.join(names)} state={ed.ONE_ENGINE}\n"
                      f"# only {only} ran ({why or 'the other engine did not run'}); nothing was compared. This is "
                      "unknown, not agreement: this engine's function boundaries are unchecked.\n")
            result = {"state": ed.ONE_ENGINE, "engines": names, "engine_status": engines,
                      "functions": {only: len(inv_p.funcs)}, "counts": None, "agreed": None, "common": None,
                      "total": 0, "offset": offset, "returned": 0, "next_offset": None}
            return {"status": Status.PARTIAL.value, "raw": header, "truncated": False, "result": result,
                    "addresses": [], "coverage": "partial", "coverage_scope": f"functions-engines:one:offset={offset}",
                    "limitations": [f"the second engine did not run: {why or 'unknown reason'}"],
                    "engine": only, "engine_version": s.engine_version.split(":", 1)[1]}
        d = ed.classify(inv_p, inv_s)
        ev_of = {n: e["evidence_id"] for n, (e, _) in ran.items()}
        header = (f"# engine disagreement: sha256={sess.sha} engines={d.a},{d.b} state={d.state}\n"
                  f"# functions: {d.a}={d.functions[d.a]} {d.b}={d.functions[d.b]} common={d.common} agreed={d.agreed} "
                  + " ".join(f"{c}={d.counts[c]}" for c in ed.CATEGORIES) + "\n"
                  "# named_only_by (a real name where the other engine has only a generated one; not a disagreement): "
                  + " ".join(f"{n}={d.named_only_by[n]}" for n in (d.a, d.b)) + "\n"
                  "# a row says what each engine reports at that start, not which one is right; every row names both "
                  f"inventory evidence ids. end_delta = {d.b} end minus {d.a} end in bytes. Rows: END_DIFFERS, "
                  "ONLY_IN_ONE, SPLIT_MERGED, NAME_DIFFERS.\n")
        kept: list[tuple[ed.Row, str]] = []
        used = len(header)
        for r in d.rows[offset:offset + limit]:
            ln = ed.row_line(r, d.a, d.b, ev_of[d.a], ev_of[d.b])
            if used + len(ln) > RESPONSE_BUDGET and kept:
                break
            kept.append((r, ln))
            used += len(ln)
        reached = offset + len(kept)
        has_more = reached < len(d.rows)
        addrs = list(dict.fromkeys(a for r, _ in kept for a in (r.start, *( (r.container.start,) if r.container else ()))))
        result = {**ed.to_result(d), "engine_status": engines, "total": len(d.rows), "offset": offset,
                  "returned": len(kept), "next_offset": reached if has_more else None}
        lim = list(d.limitations) + [
            "an engine's function list is its own analysis, not ground truth: a row is a disagreement to resolve with "
            "disassemble / xrefs, never a verdict on either engine"]
        return {"status": Status.OK.value if d.state == ed.BOTH_ENGINES else Status.PARTIAL.value,
                "raw": header + "".join(ln for _, ln in kept), "truncated": False, "result": result,
                "addresses": addrs,
                "coverage": "complete" if offset == 0 and not has_more and d.state == ed.BOTH_ENGINES else "partial",
                "coverage_scope": f"functions-engines:both:offset={offset}", "limitations": lim,
                "engine": f"{d.a}+{d.b}", "engine_version": versions}

    ev, out, cached = hub._engine_tool("functions_list", args, run, engine_version=key_version)
    res = out["result"]
    summary: dict[str, Any] = {k: res.get(k) for k in ("state", "counts", "agreed", "common", "functions", "total",
                                                       "offset", "returned", "next_offset")}
    summary["inventory_evidence"] = {n: e.get("evidence_id") for n, e in res["engine_status"].items() if e.get("ran")}
    return hub._reply(ev, out, cached, out["raw"], detail, hexify(summary))
