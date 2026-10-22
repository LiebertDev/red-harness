"""Where two engines disagree about the function boundaries of ONE target (`functions_list(engines="both")`).

Engine-independent and pure: the inputs are two inventories (every function an engine defines: start, name and the
instruction ranges of its body, as the engine's whole-function disassembly reports them), the output is a closed
classification. Nothing is decided by an engine's own matching, and no engine is trusted over the other: a row says
what each side reports, never which side is right.

Extent. The engines' own `size` fields do not measure the same thing (IDA: the entry chunk's extent; Ghidra: the number
of addresses over all chunks), so the end of a function is taken from its instructions: the end of the last instruction
of the whole-function disassembly (chunks included). A function whose disassembly is missing or incomplete has no extent;
a row never claims an end it did not see.

Categories (closed set `CATEGORIES`; every disagreeing function is exactly one row):
- `END_DIFFERS`    both engines define a function at the same start and the extents end at different addresses;
- `ONLY_IN_ONE`    one engine defines a function at a start where the other has no function and no instruction of any of its
                   functions (data, undefined bytes, or code the other engine never reached);
- `SPLIT_MERGED`   one engine defines a function at a start that lies INSIDE a function of the other (the first engine
                   split what the second merged, or the second merged what the first split); the row names the container;
- `NAME_DIFFERS`   same start (and the same end, or no extent to compare), two REAL names that differ. An engine-generated
                   name (`sub_140001000`, `FUN_140001000`: it embeds an address) is no name: a start one engine names and
                   the other does not is counted in `named_only_by`, not as a disagreement. Real names can also differ
                   only in representation (mangled / demangled, namespace); the row shows both, it does not judge.

An `END_DIFFERS` row whose function contains a `SPLIT_MERGED` start is marked `explained_by` (the same disagreement seen
from the container); it stays counted in `END_DIFFERS`.

Limits (stated, not hidden): a name comparison cannot tell which engine is right; an `ONLY_IN_ONE` row does not say the
function exists (it can be a false positive of the engine that lists it); with no extents on a side only starts and names
are compared, and `END_DIFFERS` / `SPLIT_MERGED` are not computed (`ONLY_IN_ONE` then cannot rule out a split).
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from ..engines.base import FunctionBody, FunctionInfo
from .build_diff import stable_name

END_DIFFERS = "END_DIFFERS"
ONLY_IN_ONE = "ONLY_IN_ONE"
SPLIT_MERGED = "SPLIT_MERGED"
NAME_DIFFERS = "NAME_DIFFERS"
CATEGORIES = (END_DIFFERS, ONLY_IN_ONE, SPLIT_MERGED, NAME_DIFFERS)   # listing order of the rows

# Coverage states of a both-engines inventory (closed set)
BOTH_ENGINES = "BOTH_ENGINES"                           # both engines ran, both have function extents
BOTH_STARTS_ONLY = "BOTH_ENGINES_STARTS_AND_NAMES_ONLY"  # both ran, but at least one has no extents: ends not compared
ONE_ENGINE = "ONE_ENGINE"                               # only one engine ran: nothing was compared (unknown, never "agree")
STATES = (BOTH_ENGINES, BOTH_STARTS_ONLY, ONE_ENGINE)

NAME_MAX = 120   # chars of a function name shown in a row (names come from the target)


@dataclass(frozen=True)
class EngineFunc:
    start: int
    name: str
    ranges: tuple[tuple[int, int], ...] = ()   # merged instruction byte ranges [start, end), address order; () = no extent
    insns: int = 0

    @property
    def end(self) -> int | None:
        return self.ranges[-1][1] if self.ranges else None


@dataclass(frozen=True)
class Inventory:
    engine: str
    funcs: tuple[EngineFunc, ...]
    extents: bool            # the whole-function disassembly ran to the end (False: only starts and names are known)
    extent_note: str = ""    # why there are no extents, when there are none

    @property
    def unmeasured(self) -> int:
        """Functions without an extent although the disassembly ran: no instructions (a forwarded-export record, data)
        or an incomplete body. Their ends are not compared."""
        return sum(1 for f in self.funcs if f.end is None) if self.extents else len(self.funcs)

    def to_dict(self) -> dict:
        return {"engine": self.engine, "extents": self.extents, "extent_note": self.extent_note,
                "funcs": [[f.start, f.name, [list(r) for r in f.ranges], f.insns] for f in self.funcs]}

    @staticmethod
    def from_dict(d: dict) -> "Inventory":
        return Inventory(d["engine"], tuple(EngineFunc(int(s), str(n), tuple((int(a), int(b)) for a, b in rg), int(k))
                                            for s, n, rg, k in d["funcs"]), bool(d["extents"]), d.get("extent_note", ""))


def merge_ranges(spans: Iterable[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    """Instruction (address, size) spans -> merged contiguous byte ranges in address order."""
    out: list[list[int]] = []
    for a, n in sorted(spans):
        if out and a <= out[-1][1]:
            out[-1][1] = max(out[-1][1], a + n)
        else:
            out.append([a, a + n])
    return tuple((a, b) for a, b in out)


def func_from_body(b: FunctionBody) -> EngineFunc:
    """A function from the engine's whole-function disassembly. An incomplete body (the engine returned a prefix) has no
    extent: its end would be a guess."""
    d = b.disassembly
    if not d.complete or not d.items:
        return EngineFunc(b.address, b.name)
    return EngineFunc(b.address, b.name, merge_ranges((i.address, i.size) for i in d.items), len(d.items))


def func_from_info(f: FunctionInfo) -> EngineFunc:
    return EngineFunc(f.address, f.name)


def is_auto_name(name: str) -> bool:
    """An engine-generated name embeds an address (sub_140001000, FUN_140001000, ...); an empty name counts as generated."""
    return not stable_name(name)


ENGINE_NAME_PREFIXES = ("FID_conflict:",)   # an engine's own annotation in front of a name (Ghidra function-ID conflict)


def _plain_name(name: str) -> str:
    for p in ENGINE_NAME_PREFIXES:
        if name.startswith(p):
            return name[len(p):]
    return name


def names_differ(a: str, b: str) -> bool:
    """Two real names that differ. A generated name on either side is never a difference (one engine simply gave no
    name there; that is counted as `named_only_by`, not as a disagreement)."""
    if is_auto_name(a) or is_auto_name(b):
        return False
    return _plain_name(a) != _plain_name(b)


@dataclass(frozen=True)
class Row:
    category: str
    start: int
    a: EngineFunc | None            # the function engine A defines at `start` (None: A has none)
    b: EngineFunc | None
    container: EngineFunc | None = None   # SPLIT_MERGED: the function of the OTHER engine that contains `start`
    explained_by: tuple[int, ...] = ()    # END_DIFFERS: starts of SPLIT_MERGED rows inside this function

    @property
    def has(self) -> str:
        """`a` / `b` for a row where only one side defines a function at `start`, else ''."""
        return "a" if self.a and not self.b else "b" if self.b and not self.a else ""


@dataclass
class Disagreement:
    a: str
    b: str                          # engine names (A sorts before B)
    state: str
    rows: list[Row] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)       # category -> rows
    only_in: dict[str, dict[str, int]] = field(default_factory=dict)   # ONLY_IN_ONE / SPLIT_MERGED -> engine -> rows
    agreed: int = 0                 # same start and no difference found in what was compared
    common: int = 0                 # starts both engines define
    functions: dict[str, int] = field(default_factory=dict)    # engine -> functions listed
    explained_end_differs: int = 0
    named_only_by: dict[str, int] = field(default_factory=dict)   # engine -> common starts only it gives a real name
    limitations: list[str] = field(default_factory=list)


def _locator(funcs: Sequence[EngineFunc]):
    """addr -> the function whose instruction ranges hold it (the lowest function start when ranges overlap), or None."""
    spans = sorted((lo, hi, f.start) for f in funcs for lo, hi in f.ranges)
    starts = [s[0] for s in spans]
    reach: list[int] = []   # reach[k] = the highest range end among spans[0..k]: stops the backward scan exactly
    top = 0
    for _, hi, _ in spans:
        top = max(top, hi)
        reach.append(top)
    by_start = {f.start: f for f in funcs}

    def find(addr: int) -> EngineFunc | None:
        k = bisect.bisect_right(starts, addr) - 1
        best: int | None = None
        while k >= 0 and reach[k] > addr:
            lo, hi, fs = spans[k]
            if addr < hi and (best is None or fs < best):
                best = fs
            k -= 1
        return by_start[best] if best is not None else None
    return find


def classify(inv_a: Inventory, inv_b: Inventory) -> Disagreement:
    """The closed classification of the differences between two inventories of the same target."""
    if inv_a.engine > inv_b.engine:
        inv_a, inv_b = inv_b, inv_a
    A, B = {f.start: f for f in inv_a.funcs}, {f.start: f for f in inv_b.funcs}
    full = inv_a.extents and inv_b.extents
    d = Disagreement(inv_a.engine, inv_b.engine, BOTH_ENGINES if full else BOTH_STARTS_ONLY,
                     functions={inv_a.engine: len(A), inv_b.engine: len(B)},
                     named_only_by={inv_a.engine: 0, inv_b.engine: 0})
    if not full:
        missing = [i for i in (inv_a, inv_b) if not i.extents]
        d.limitations.append("function ends were not compared (no extents from " + ", ".join(
            f"{i.engine}: {i.extent_note or 'whole-function disassembly unavailable'}" for i in missing)
            + "): END_DIFFERS and SPLIT_MERGED are not computed and ONLY_IN_ONE cannot rule out a split")
    elif inv_a.unmeasured or inv_b.unmeasured:
        d.limitations.append("functions without an extent (no instructions, e.g. a forwarded-export record, or an "
                             "incomplete disassembly) are compared by start and name only: "
                             + ", ".join(f"{i.engine} {i.unmeasured}" for i in (inv_a, inv_b)))
    in_a, in_b = _locator(inv_a.funcs), _locator(inv_b.funcs)
    rows: list[Row] = []
    split_in: dict[int, list[int]] = {}   # container start -> starts of SPLIT_MERGED rows inside it
    for start in sorted(A.keys() | B.keys()):
        fa, fb = A.get(start), B.get(start)
        if fa is not None and fb is not None:
            d.common += 1
            if is_auto_name(fa.name) != is_auto_name(fb.name):
                who = inv_b.engine if is_auto_name(fa.name) else inv_a.engine
                d.named_only_by[who] = d.named_only_by.get(who, 0) + 1
            if fa.end is not None and fb.end is not None and fa.end != fb.end:
                rows.append(Row(END_DIFFERS, start, fa, fb))
            elif names_differ(fa.name, fb.name):
                rows.append(Row(NAME_DIFFERS, start, fa, fb))
            else:
                d.agreed += 1
            continue
        lone, other_find = (fa, in_b) if fb is None else (fb, in_a)
        box = other_find(start) if full else None
        if box is not None:
            rows.append(Row(SPLIT_MERGED, start, fa, fb, container=box))
            split_in.setdefault(box.start, []).append(start)
        else:
            rows.append(Row(ONLY_IN_ONE, start, fa, fb))
    fixed: list[Row] = []
    for r in rows:
        if r.category == END_DIFFERS and r.start in split_in:
            r = Row(r.category, r.start, r.a, r.b, explained_by=tuple(split_in[r.start]))
            d.explained_end_differs += 1
        fixed.append(r)
    order = {c: i for i, c in enumerate(CATEGORIES)}
    d.rows = sorted(fixed, key=lambda r: (order[r.category], r.start))
    d.counts = {c: sum(1 for r in d.rows if r.category == c) for c in CATEGORIES}
    for cat in (ONLY_IN_ONE, SPLIT_MERGED):
        d.only_in[cat] = {inv_a.engine: sum(1 for r in d.rows if r.category == cat and r.has == "a"),
                          inv_b.engine: sum(1 for r in d.rows if r.category == cat and r.has == "b")}
    return d


def _nm(name: str) -> str:
    s = name.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    return s if len(s) <= NAME_MAX else s[:NAME_MAX] + "..."


def _side(label: str, f: EngineFunc | None) -> str:
    if f is None:
        return f"{label}=-"
    end = f"0x{f.end:x}" if f.end is not None else "?"
    return f"{label}:name={_nm(f.name)} end={end} insns={f.insns}"


def inventory_line(f: EngineFunc) -> str:
    """One line of a per-engine inventory evidence: what a claim quotes to say what that engine defines."""
    end = f"0x{f.end:x}" if f.end is not None else "?"
    return f"0x{f.start:x} {_nm(f.name)} end={end} insns={f.insns} chunks={len(f.ranges)}\n"


def row_line(r: Row, a: str, b: str, ev_a: str, ev_b: str) -> str:
    """`<CATEGORY> start=0x.. <a>:... <b>:... [container=...] [explained_by=...] ev_<a>=.. ev_<b>=..`: both engines'
    evidence ids are on every row (the inventory evidence holds each engine's own line for that start)."""
    parts = [r.category, f"start=0x{r.start:x}", _side(a, r.a), _side(b, r.b)]
    if r.category == END_DIFFERS:
        parts.append(f"end_delta={r.b.end - r.a.end:+d}")   # second engine's end minus the first's, in bytes
    if r.container is not None:
        side = b if r.has == "a" else a   # the container belongs to the engine that does NOT define the function
        c = r.container
        parts.append(f"container={side}:0x{c.start:x}..0x{c.end:x} name={_nm(c.name)}")
    if r.explained_by:
        parts.append("explained_by=" + ",".join(f"0x{x:x}" for x in r.explained_by))
    parts.append(f"{a}_ev={ev_a} {b}_ev={ev_b}")
    return " ".join(parts) + "\n"


def to_result(d: Disagreement) -> dict:
    """The JSON-able summary kept in the evidence `result` (and read back by the report)."""
    return {"state": d.state, "engines": [d.a, d.b], "functions": dict(d.functions), "common": d.common,
            "agreed": d.agreed, "named_only_by": dict(d.named_only_by), "counts": dict(d.counts), "only_in": {k: dict(v) for k, v in d.only_in.items()},
            "explained_end_differs": d.explained_end_differs, "rows": len(d.rows)}
