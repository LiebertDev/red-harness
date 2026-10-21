"""Abstract values and the per-program-point state of the data-flow slicer (docs/design/dataflow-slice.md section 3.2).

A value is one of
- CONST: a known bit pattern (the same on every path of the engine's CFG that reaches the point),
- STACK: an address inside the function's own frame, as a signed offset from `sp0` (the stack pointer at entry),
- UNKNOWN: not known; `why` says where it comes from (call result, argument, join of different values, ...),
- RANGE: an address inside the frame at an offset >= `v` that is not constant (a pointer advanced in a loop or by an
  unknown index; under assumption A1 it never goes below `v`),
- UNINIT: a stack byte that no write reaches (only for stack bytes),
- PTRB / RPTRB: one byte of a STACK / RANGE address spilled into a frame slot (`v` = offset * 16 + byte index), so
  that `lea eax, [ebp-0x64]; mov [ebp-0x1cc], eax; ...; mov eax, [ebp-0x1cc]` gives the frame address back.
Every value carries `sites` (the instruction addresses that produced it, transitively: its provenance) and `srcs`
(its other dependencies: image ranges `(va, size)` it was loaded from, and the assumption tags "A1"/"A2" it relies on,
see x86.py; a value carrying a tag is printed with `assumes=` and is never unconditional). Joins never guess: different values become UNKNOWN, equal values keep
the union of their provenance (the same value written by different instructions is still definite).
"""

from __future__ import annotations

from dataclasses import dataclass, field

CONST, STACK, UNKNOWN, UNINIT, RANGE, PTRB, RPTRB = "c", "s", "u", "n", "r", "p", "q"
FRAME = (STACK, RANGE)
PTR_BYTES = (PTRB, RPTRB)
NEG_INF = -(1 << 62)
EMPTY: frozenset = frozenset()


@dataclass(frozen=True)
class Val:
    kind: str
    v: int = 0
    sites: frozenset = EMPTY
    why: frozenset = EMPTY
    srcs: frozenset = EMPTY
    parts: tuple | None = None   # register only: per-byte values when some bytes are known and others not
    last: int | None = None      # frame byte only: the definite value it held before a possible overwrite made it
    #                              UNKNOWN (a call or store through an escaped address); shown, never used as a value

    def with_site(self, site: int) -> "Val":
        parts = None if self.parts is None else tuple(p.with_site(site) for p in self.parts)
        return Val(self.kind, self.v, self.sites | {site}, self.why, self.srcs, parts, self.last)


def split(v: Val, n: int) -> list[Val]:
    """A register value as `n` byte values (little endian)."""
    if v.parts is not None:
        return list(v.parts)
    if v.kind == CONST:
        return [Val(CONST, (v.v >> (8 * k)) & 0xFF, v.sites, EMPTY, v.srcs) for k in range(n)]
    if v.kind in FRAME:
        b = Val(UNKNOWN, 0, v.sites, frozenset(["byte of a frame address"]), v.srcs)
        return [b] * n
    b = Val(UNKNOWN, 0, v.sites, v.why, v.srcs)
    return [b] * n


def from_bytes(bs: list[Val]) -> Val:
    """Per-byte values -> one register value: CONST if every byte is CONST, else UNKNOWN keeping the bytes."""
    sites, why, srcs = set(), set(), set()
    for b in bs:
        sites |= b.sites
        why |= b.why
        srcs |= b.srcs
    if all(b.kind == CONST for b in bs):
        return Val(CONST, sum((b.v & 0xFF) << (8 * k) for k, b in enumerate(bs)), frozenset(sites), EMPTY,
                   frozenset(srcs))
    if all(b == bs[0] for b in bs):
        return Val(UNKNOWN, 0, bs[0].sites, bs[0].why, bs[0].srcs)
    return Val(UNKNOWN, 0, frozenset(sites), frozenset(why), frozenset(srcs), tuple(bs))


def const(v: int, sites=EMPTY, srcs=EMPTY) -> Val:
    return Val(CONST, v, frozenset(sites), EMPTY, frozenset(srcs))


def unknown(why: str | frozenset | set, sites=EMPTY, srcs=EMPTY) -> Val:
    w = frozenset([why]) if isinstance(why, str) else frozenset(why)
    return Val(UNKNOWN, 0, frozenset(sites), w, frozenset(srcs))


def taint(vals: list[Val], why: str | None, sites=EMPTY) -> Val:
    """UNKNOWN that keeps the provenance and the reasons of its inputs (plus `why`)."""
    w, s, r = set(), set(sites), set()
    for x in vals:
        w |= x.why
        s |= x.sites
        r |= x.srcs
        if x.kind == UNINIT:
            w.add("uninitialised stack bytes")
    if why:
        w.add(why)
    return Val(UNKNOWN, 0, frozenset(s), frozenset(w), frozenset(r))


UNINIT_BYTE = Val(UNINIT)


def fmt_off(o: int) -> str:
    return f"sp0{o:+#x}"


def join_val(a: Val, b: Val, at: int) -> Val:
    if a == b:
        return a
    if a.parts is not None or b.parts is not None:
        n = len(a.parts if a.parts is not None else b.parts)
        return from_bytes([join_val(x, y, at) for x, y in zip(split(a, n), split(b, n))])
    if a.kind == b.kind and a.v == b.v and a.kind in (CONST, STACK, RANGE, PTRB, RPTRB):
        return Val(a.kind, a.v, a.sites | b.sites, EMPTY, a.srcs | b.srcs)
    if a.kind in FRAME and b.kind in FRAME:      # the same frame base at different offsets: offset not constant
        return Val(RANGE, min(a.v, b.v), a.sites | b.sites, EMPTY, a.srcs | b.srcs)
    if a.kind in PTR_BYTES and b.kind in PTR_BYTES and (a.v & 15) == (b.v & 15):
        return Val(RPTRB, (min(a.v >> 4, b.v >> 4) << 4) | (a.v & 15), a.sites | b.sites, EMPTY, a.srcs | b.srcs)
    if a.kind == UNINIT and b.kind == UNINIT:
        return a
    if a.kind == UNKNOWN and b.kind == UNKNOWN:
        return Val(UNKNOWN, 0, a.sites | b.sites, a.why | b.why, a.srcs | b.srcs, None,
                   a.last if a.last is not None and a.last == b.last else None)
    if UNINIT in (a.kind, b.kind):
        why = f"not written on every path (join at 0x{at:x})"
    else:
        why = f"different values on different paths or loop iterations (join at 0x{at:x})"
    w = (a.why | b.why) | {why}
    # a definite byte joined with the same byte made non-definite (its last value equal) keeps that last value
    la = a.v & 0xFF if a.kind == CONST else a.last
    lb = b.v & 0xFF if b.kind == CONST else b.last
    last = la if la is not None and la == lb and a.parts is None and b.parts is None else None
    return Val(UNKNOWN, 0, a.sites | b.sites, frozenset(w), a.srcs | b.srcs, None, last)


@dataclass
class State:
    regs: dict                      # register family -> Val
    stack: dict = field(default_factory=dict)   # sp0 offset -> byte Val
    floor: int | None = None        # absent bytes at offsets >= floor are UNKNOWN(floor_why)
    floor_why: frozenset = EMPTY
    floor_sites: frozenset = EMPTY
    esc: frozenset = EMPTY          # stack offsets whose address escaped (stored, passed, lost)
    fresh: set = field(default_factory=set)   # offsets written since the last tag_all (the only ones it must visit)

    def copy(self) -> "State":
        return State(dict(self.regs), dict(self.stack), self.floor, self.floor_why, self.floor_sites, self.esc,
                     set(self.fresh))

    def put(self, o: int, v: Val) -> None:
        self.stack[o] = v
        self.fresh.add(o)

    def byte_at(self, o: int) -> Val:
        b = self.stack.get(o)
        if b is not None:
            return b
        if self.floor is not None and o >= self.floor:
            return Val(UNKNOWN, 0, self.floor_sites, self.floor_why)
        if o >= 0:
            return unknown(f"caller frame {fmt_off(o)} (argument or return address)")
        return UNINIT_BYTE

    def escape(self, off: int) -> None:
        if off not in self.esc:
            self.esc = self.esc | {off}

    def havoc_range(self, lo: int, hi: int, why: str, site: int) -> None:
        """Frame bytes [lo, hi) become UNKNOWN (an ABI-owned area the callee may write); a definite byte keeps its last
        value, an unwritten byte becomes UNKNOWN too (it is no longer "uninitialised": the callee may have written)."""
        for o in range(lo, hi):
            b = self.byte_at(o)
            last = b.v & 0xFF if b.kind == CONST else (b.last if b.kind == UNKNOWN else None)
            self.stack[o] = Val(UNKNOWN, 0, b.sites | {site}, (b.why if b.kind == UNKNOWN else EMPTY) | {why},
                                b.srcs, None, last)

    def havoc_from(self, off: int, why: str, site: int) -> None:
        """Every frame byte at offset >= `off` becomes UNKNOWN (the writes that were there stay as provenance)."""
        for o, b in list(self.stack.items()):
            if o >= off:
                last = b.v & 0xFF if b.kind == CONST else (b.last if b.kind == UNKNOWN else None)
                self.stack[o] = Val(UNKNOWN, 0, b.sites | {site}, (b.why if b.kind == UNKNOWN else EMPTY) | {why},
                                    b.srcs, None, last)
            else:   # kept only because of assumption A1 (nothing is written below the address the havoc starts at)
                self.stack[o] = tag(b, "A1")
        if self.floor is None or off < self.floor:
            self.floor = off
        self.floor_why = self.floor_why | {why}
        self.floor_sites = self.floor_sites | {site}

    def tag_from(self, off: int, t: str) -> None:
        """Every tracked frame byte at offset >= `off` now relies on assumption `t`."""
        for o, b in list(self.stack.items()):
            if o >= off and o < 0:
                self.stack[o] = tag(b, t)

    def tag_all(self, t: str) -> None:
        """Every tracked frame byte now relies on assumption `t` (a store that could have hit it was ignored)."""
        for o in self.fresh:   # every other byte was tagged by an earlier call already
            b = self.stack.get(o)
            if b is not None:
                self.stack[o] = tag(b, t)
        self.fresh = set()


def tag(v: Val, t: str) -> Val:
    if v.kind == UNINIT or t in v.srcs:
        return v
    parts = None if v.parts is None else tuple(tag(p, t) for p in v.parts)
    return Val(v.kind, v.v, v.sites, v.why, v.srcs | {t}, parts, v.last)


def tags_of(srcs) -> frozenset:
    return frozenset(x for x in srcs if isinstance(x, str))


def ranges_of(srcs) -> list:
    return sorted(x for x in srcs if isinstance(x, tuple))


def join_state(a: State, b: State, at: int) -> State:
    regs = {}
    for k in set(a.regs) | set(b.regs):
        x, y = a.regs.get(k), b.regs.get(k)
        if x is None or y is None:
            regs[k] = x or y
            continue
        regs[k] = join_val(x, y, at)
    esc = a.esc | b.esc
    for k, v in regs.items():  # a frame address that does not survive the join is lost: treat it as escaped
        if k != "rsp" and v.kind == UNKNOWN:
            for src in (a.regs.get(k), b.regs.get(k)):
                if src is not None and src.kind in FRAME:
                    esc = esc | {src.v}
    stack = {}
    for o in set(a.stack) | set(b.stack):
        x, y = a.byte_at(o), b.byte_at(o)
        j = join_val(x, y, at)
        if j.kind == UNKNOWN:
            for src in (x, y):
                if src.kind in PTR_BYTES:
                    esc = esc | {src.v >> 4}
        stack[o] = j
    if a.floor is None and b.floor is None:
        floor = None
    else:
        floor = min(x for x in (a.floor, b.floor) if x is not None)
    return State(regs, stack, floor, a.floor_why | b.floor_why, a.floor_sites | b.floor_sites, esc,
                 a.fresh | b.fresh)


def taint_state(st: State, why: str) -> State:
    """Every definite value becomes non-definite (a definite stack byte keeps its last value); frame addresses in
    registers and spilled frame pointers are kept (assumption: a path entered by exception dispatch restores the frame
    pointer). Used at blocks that a not-analysed block (no known predecessor) also flows into."""
    w = frozenset([why])
    regs = {k: (Val(UNKNOWN, 0, v.sites, v.why | w, v.srcs) if v.kind == CONST or v.parts is not None else v)
            for k, v in st.regs.items()}
    stack = {o: (Val(UNKNOWN, 0, b.sites, w, b.srcs, None, b.v & 0xFF) if b.kind == CONST else b)
             for o, b in st.stack.items()}
    return State(regs, stack, st.floor, st.floor_why, st.floor_sites, st.esc, set(st.fresh))


def top_state(families, why: str) -> State:
    """Nothing known (a block without a known predecessor, or a fixpoint cap)."""
    u = unknown(why)
    return State({f: u for f in families}, {}, NEG_INF, frozenset([why]), EMPTY, EMPTY)
