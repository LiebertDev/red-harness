"""Bounded data-flow slice inside one function (docs/design/dataflow-slice.md).

Input: the engine's whole-function instruction list (common contract, `Disassembly`), the address of an instruction, and
optionally a PE image view for constant loads. Output: text lines that are verifiable evidence (instruction VA + the
engine's own text + `key=value` annotations), plus the addresses and image ranges they mention.

Guarantee ("definite"): a CONST value or byte is the same on every path of the CFG built from the engine's instructions
(harness-derived edges; an indirect jump is given edges to every block). Unresolved edges, a truncated disassembly or the
fixpoint cap make the affected values UNKNOWN, never a guess. Bounded by counts only, so the same input gives the same
output.
"""

from __future__ import annotations

import re
from collections import OrderedDict
from dataclasses import dataclass, field

from ...engines.base import Disassembly, InsnInfo, OperandInfo
from . import eh as ehmod
from . import x86
from .state import (CONST, EMPTY, FRAME, NEG_INF, PTR_BYTES, PTRB, RANGE, STACK, UNINIT, UNKNOWN, State, Val, fmt_off,
                    join_state, ranges_of, tags_of, taint_state, top_state, unknown)

SLICER_REV = 6   # 5: no definite value in functions with unmodelled exception handlers (C++ EH, x86 SEH, ...); 6: also when the exception directory is unreadable or truncated
# 2: spilled frame pointers, RANGE pointers, last-write candidates, cstr; 3: assumes= on writes
# 4: exception edges from x64 scope tables, callee-writable stack arguments (A3)
CACHE_FUNCTIONS = 2
_CACHE: "OrderedDict[tuple, tuple]" = OrderedDict()
MAX_FUNCTION_INSNS = 20_000
MAX_BUFFER = 4096
MAX_STEPS_DEFAULT = 200
MAX_STEPS_MAX = 1000
BLOCK_VISIT_CAP = 64
MAX_UNKNOWN_LINES = 64
MIN_HEX_RUN = 9          # > 16 hex digits: a whole byte-string token for the verifier (version 21)
_LOC_MEM = re.compile(r"^\[\s*([a-z][a-z0-9]*)\s*(?:([+-])\s*(0x[0-9a-f]+|\d+))?\s*\]$", re.I)
_LOC_SP0 = re.compile(r"^sp0\s*([+-])\s*(0x[0-9a-f]+|\d+)$", re.I)


class SliceError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message


@dataclass
class SliceResult:
    text: str
    complete: bool
    reasons: list[str]
    addresses: list[int]                 # every instruction VA printed
    image_ranges: list[tuple[int, int]]  # (va, size) of every image range printed
    summary: dict = field(default_factory=dict)


# ---------------------------------------------------------------- CFG
@dataclass
class Cfg:
    blocks: dict[int, list[InsnInfo]]
    succs: dict[int, list[int]]
    preds: dict[int, list[int]]
    entry: int
    block_of: dict[int, int]
    notes: list[str]
    exc: dict = field(default_factory=dict)   # block -> [(handler target, try begin, try end)]
    exc_edges: int = 0


def _is_branch(m: str) -> bool:
    return m == "jmp" or m in x86.CONDITIONAL


def build_cfg(insns: list[InsnInfo], entry: int, complete: bool, exc_edges=()) -> Cfg:
    """`exc_edges`: verified exception edges (objects with try_begin / try_end / target VAs, seh.ExceptEdge); an edge
    is used only when its target is a decoded instruction of this function and its try range covers some of them."""
    by_addr = {i.address: i for i in insns}
    order = sorted(by_addr)
    leaders = {entry, order[0]}
    usable = [e for e in exc_edges if e.target in by_addr
              and any(e.try_begin <= a < e.try_end for a in by_addr)]
    for e in usable:
        leaders.add(e.target)
    notes: list[str] = []
    indirect: list[int] = []
    for k, a in enumerate(order):
        ins = by_addr[a]
        m = x86.base_mnemonic(ins.mnemonic)
        nxt = a + ins.size
        if k + 1 < len(order) and order[k + 1] != nxt:
            leaders.add(order[k + 1])
        if _is_branch(m) or m in x86.RETURNS:
            if nxt in by_addr:
                leaders.add(nxt)
            if ins.operands and ins.operands[0].kind == "near" and ins.operands[0].value in by_addr:
                leaders.add(ins.operands[0].value)
    blocks: dict[int, list[InsnInfo]] = {}
    block_of: dict[int, int] = {}
    cur = None
    for a in order:
        if a in leaders or cur is None:
            cur = a
            blocks[cur] = []
        blocks[cur].append(by_addr[a])
        block_of[a] = cur
    succs: dict[int, list[int]] = {}
    for b, body in blocks.items():
        last = body[-1]
        m = x86.base_mnemonic(last.mnemonic)
        nxt = last.address + last.size
        out: list[int] = []
        op = last.operands[0] if last.operands else None
        if m in x86.RETURNS:
            pass
        elif m == "jmp":
            if op is not None and op.kind == "near" and op.value is not None:
                if op.value in by_addr:
                    out.append(op.value)
                elif not complete:
                    notes.append(f"jump target 0x{op.value:x} at 0x{last.address:x} is not in the decoded "
                                 "instructions (disassembly incomplete)")
            elif op is not None and op.kind == "mem" and not op.base and not op.index:
                pass   # jmp [abs]: tail jump through a pointer/import slot, leaves the function
            else:
                indirect.append(b)
        elif m in x86.CONDITIONAL:
            if op is not None and op.kind == "near" and op.value in by_addr:
                out.append(op.value)
            elif op is not None and op.kind == "near" and op.value is not None and not complete:
                notes.append(f"branch target 0x{op.value:x} at 0x{last.address:x} not decoded")
            if nxt in by_addr:
                out.append(nxt)
        elif nxt in by_addr:
            out.append(nxt)
        succs[b] = out
    for b in indirect:
        succs[b] = sorted(blocks)
        notes.append(f"indirect jump at 0x{blocks[b][-1].address:x}: edges to every block assumed")
    preds: dict[int, list[int]] = {b: [] for b in blocks}
    for b, out in succs.items():
        for s in out:
            preds[s].append(b)
    exc: dict[int, list[tuple[int, int, int]]] = {}
    for e in usable:
        for b, body in blocks.items():
            if any(e.try_begin <= i.address < e.try_end for i in body):
                exc.setdefault(b, []).append((e.target, e.try_begin, e.try_end))
                if b not in preds[e.target]:
                    preds[e.target].append(b)
    return Cfg(blocks, succs, preds, block_of[entry], block_of, notes, exc, len(usable))


# ---------------------------------------------------------------- fixpoint
def entry_state(ctx: x86.Ctx) -> State:
    regs = {f: unknown(f"value of {ctx.rname(f)} at function entry (argument or caller state)")
            for f in ctx.families}
    regs["rsp"] = Val(STACK, 0)
    return State(regs)


def _step(st: State, ins: InsnInfo, ctx: x86.Ctx) -> None:
    """One instruction. In a function with an unmodelled exception handler the handler may have run and rewritten any
    frame slot or register before any later instruction, so no value survives an instruction as definite: stack bytes
    are made non-definite when written (State.put), registers here. Frame addresses in rsp/rbp stay (the unwinder
    restores them; same assumption as the not-analysed-block taint); any other frame address register is dropped and
    its target counted as escaped."""
    x86.step(st, ins, ctx)
    if not ctx.eh:
        return
    for f, v in st.regs.items():
        if f == "rsp" and v.kind != CONST:
            continue
        if v.kind in FRAME and f == "rbp":
            continue
        if v.kind == CONST or v.parts is not None or v.kind in FRAME:
            if v.kind in FRAME:
                st.escape(v.v)
            st.regs[f] = Val(UNKNOWN, 0, v.sites, v.why | ctx.eh, v.srcs)


def run_block(st: State, body: list[InsnInfo], ctx: x86.Ctx, stop: int | None = None) -> State:
    st.eh = ctx.eh
    for ins in body:
        if stop is not None and ins.address == stop:
            break
        _step(st, ins, ctx)
    return st


def analyze(cfg: Cfg, ctx: x86.Ctx) -> dict[int, State]:
    rpo = _rpo(cfg)
    rank = {b: k for k, b in enumerate(rpo)}
    for b in cfg.blocks:
        rank.setdefault(b, len(rank))
    ins: dict[int, State] = {cfg.entry: entry_state(ctx)}
    # A block without any edge into it (no indirect jump in the function: those get edges to every block) is not
    # entered: it is dead in the engine's CFG (junk after an unconditional jump) or reached only by exception dispatch.
    # Paths through it are not covered, and the coverage says so.
    for b in cfg.blocks:
        if b != cfg.entry and not cfg.preds[b]:
            ctx.partial.setdefault("block without a known predecessor not analysed (unreachable in this CFG unless "
                                   "entered by exception dispatch)", b)
    # A not-analysed block (and what only it reaches) may still run (exception dispatch has no CFG edge yet). Where
    # such a path flows into an analysed block, nothing that arrives there is definite any more.
    reach = _reachable(cfg, [cfg.entry])   # exception edges included
    dead = [b for b in cfg.blocks if b not in reach]
    tainted: dict[int, int] = {}
    for d in dead:
        for s in cfg.succs[d]:
            if s in reach:
                tainted.setdefault(s, d)
    for j, d in tainted.items():
        ctx.partial.setdefault(f"not-analysed block 0x{d:x} flows into 0x{j:x}: values arriving there are not "
                               "definite (frame addresses kept)", j)
    visits: dict[int, int] = {}
    capped: set[int] = set()
    work = set(ins)
    while work:
        b = min(work, key=lambda x: rank[x])
        work.discard(b)
        visits[b] = visits.get(b, 0) + 1
        if visits[b] > BLOCK_VISIT_CAP and b not in capped:
            capped.add(b)
            ins[b] = top_state(ctx.families, f"fixpoint cap reached at block 0x{b:x}")
            ctx.partial.setdefault("fixpoint cap", b)
        if b in cfg.exc:
            out, dispatch = _run_block_with_dispatch(ins[b].copy(), cfg.blocks[b], cfg.exc[b], ctx)
            for t, st in dispatch.items():
                old = ins.get(t)
                new = st if old is None else join_state(old, st, t)
                if old is None or new != old:
                    ins[t] = new
                    work.add(t)
        else:
            out = run_block(ins[b].copy(), cfg.blocks[b], ctx)
        for s in cfg.succs[b]:
            old = ins.get(s)
            new = out.copy() if old is None else join_state(old, out, s)
            if s in tainted:
                new = taint_state(new, f"a path from not-analysed block 0x{tainted[s]:x} (possible exception "
                                       f"handler) also reaches 0x{s:x}")
            if s in capped:
                new = join_state(new, top_state(ctx.families, f"fixpoint cap reached at block 0x{s:x}"), s)
            if old is None or new != old:
                ins[s] = new
                work.add(s)
    return ins


def _run_block_with_dispatch(st: State, body: list[InsnInfo], edges, ctx: x86.Ctx):
    """Runs a block that lies in a __try range. Before every instruction inside a range, the state an exception
    raised there would carry into the __except block is joined into that handler's entry state: the frame as it is,
    the volatile registers unknown (x64 dispatch restores only the non-volatile ones)."""
    dispatch: dict[int, State] = {}
    st.eh = ctx.eh
    for ins in body:
        for t, lo, hi in edges:
            if lo <= ins.address < hi:
                d = st.copy()
                for f in x86.VOLATILE64:
                    if f in d.regs:
                        d.regs[f] = unknown(f"{ctx.rname(f)} at exception dispatch into 0x{t:x}", {ins.address})
                dispatch[t] = d if t not in dispatch else join_state(dispatch[t], d, t)
        _step(st, ins, ctx)
    return st, dispatch


def _succs_all(cfg: Cfg, b: int) -> list[int]:
    return cfg.succs[b] + [t for t, _lo, _hi in cfg.exc.get(b, ())]


def _reachable(cfg: Cfg, starts: list[int]) -> set[int]:
    seen, todo = set(starts), list(starts)
    while todo:
        for s in _succs_all(cfg, todo.pop()):
            if s not in seen:
                seen.add(s)
                todo.append(s)
    return seen


def _rpo(cfg: Cfg) -> list[int]:
    seen, post = set(), []
    stack = [(cfg.entry, iter(_succs_all(cfg, cfg.entry)))]
    seen.add(cfg.entry)
    while stack:
        b, it = stack[-1]
        nxt = next(it, None)
        if nxt is None:
            post.append(b)
            stack.pop()
        elif nxt not in seen:
            seen.add(nxt)
            stack.append((nxt, iter(_succs_all(cfg, nxt))))
    return list(reversed(post))


# ---------------------------------------------------------------- query
@dataclass
class Read:
    label: str
    value: Val | None = None             # register / scalar memory value
    buffer: tuple[int, list[Val]] | None = None   # (frame offset, bytes)
    note: str = ""


def _parse_int(sign: str, s: str) -> int:
    v = int(s, 16) if s.lower().startswith("0x") else int(s)
    return -v if sign == "-" else v


def _query_reads(st: State, ins: InsnInfo, ctx: x86.Ctx, operand: int | None, location: str | None,
                 size: int | None) -> list[Read]:
    if location is not None:
        return [_location_read(st, ins, ctx, location.strip(), size)]
    ops = list(ins.operands)
    m = x86.base_mnemonic(ins.mnemonic)
    if operand is not None:
        if not 0 <= operand < len(ops):
            raise SliceError("BAD_ARGUMENT", f"operand must be 0..{len(ops) - 1} for this instruction")
        idx = [operand]
    elif m in ("mov", "movzx", "movsx", "movsxd", "lea", "movabs"):
        idx = list(range(1, len(ops)))
        if ops and ops[0].kind == "mem":
            idx.append(0)  # the address registers of the destination are read too
    else:
        idx = list(range(len(ops)))
    out = []
    for k in idx:
        op = ops[k]
        other = ops[1 - k] if len(ops) == 2 else None
        dest_only = m in ("mov", "movzx", "movsx", "movsxd", "movabs") and k == 0
        out.append(_operand_read(st, ins, ctx, op, other, k, size, dest_only))
    return out


def _operand_read(st: State, ins: InsnInfo, ctx: x86.Ctx, op: OperandInfo, other, k: int, size: int | None,
                  dest_only: bool) -> Read:
    label = f"operand {k}: {op.text}"
    if op.kind == "reg":
        return Read(label, x86.read_reg(st, op.reg, ctx))
    if op.kind == "imm":
        w = x86.width_of(op, ctx) or ctx.fw
        return Read(label, x86.get(st, op, w, ins, ctx), note="immediate")
    if op.kind == "near":
        return Read(label, note=f"branch/call target 0x{op.value:x}" if op.value is not None else "branch target")
    if op.kind != "mem":
        return Read(label, note="operand not modelled")
    st2 = st.copy()
    a = x86.address(st2, op, ins, ctx)
    w = x86.width_of(op, ctx, other)
    if dest_only:
        return Read(label, note=f"destination address {_addr_text(a)}",
                    value=None if a.kind in ("stack", "abs") else unknown(a.why, a.sites))
    if a.kind in ("stack", "stackidx"):
        if a.kind == "stackidx" or size:
            n = size or _auto_extent(st, a.off)
            return Read(label + f" -> frame buffer from {fmt_off(a.off)}"
                        + (" (index not constant)" if a.kind == "stackidx" else ""),
                        buffer=(a.off, [st.byte_at(a.off + j) for j in range(n)]))
        if w is None:
            return Read(label, unknown(f"access width unknown ({op.text})"))
        return Read(label + f" -> {fmt_off(a.off)} size={w}", buffer=(a.off, [st.byte_at(a.off + j) for j in range(w)]))
    if a.kind == "abs":
        if w is None:
            return Read(label, unknown(f"access width unknown ({op.text})"))
        return Read(label + f" -> memory 0x{a.off:x} size={w}", x86.image_load(a.off, w, a.sites, ins.address, ctx))
    return Read(label, unknown(a.why | {f"address of {op.text} not known"}, a.sites))


def _auto_extent(st: State, off: int) -> int:
    n = 0
    while n < MAX_BUFFER and off + n < 0 and (off + n) in st.stack and st.stack[off + n].kind != UNINIT:
        n += 1
    return max(n, 1)


def _location_read(st: State, ins: InsnInfo, ctx: x86.Ctx, loc: str, size: int | None) -> Read:
    low = loc.lower()
    if low in x86.REG:
        if not x86.tracked(low, ctx):
            raise SliceError("BAD_ARGUMENT", f"register {loc} does not exist in {ctx.bits}-bit code")
        return Read(f"location {low}", x86.read_reg(st, low, ctx))
    m = _LOC_SP0.match(low)
    if m:
        off = _parse_int(m.group(1), m.group(2))
    else:
        m = _LOC_MEM.match(low)
        if not m or m.group(1) not in x86.REG:
            raise SliceError("BAD_ARGUMENT", "location: a register name (eax), a frame slot like [ebp-0x20] / "
                                             "[rsp+0x40], or sp0-0x24")
        base = x86.read_reg(st.copy(), m.group(1), ctx)
        disp = _parse_int(m.group(2), m.group(3)) if m.group(2) else 0
        if base.kind == CONST:
            n = size or ctx.fw
            va = (base.v + disp) & x86.mask(ctx.fw)
            if n > 8:
                raise SliceError("BAD_ARGUMENT", f"0x{va:x} is image memory: read more than 8 bytes with read_bytes")
            return Read(f"location {loc} -> memory 0x{va:x} size={n}",
                        x86.image_load(va, n, base.sites, ins.address, ctx))
        if base.kind != STACK:
            return Read(f"location {loc}", unknown(base.why | {f"{m.group(1)} is not a known frame address here"},
                                                   base.sites))
        off = base.v + disp
    n = size or _auto_extent(st, off)
    return Read(f"location {loc} -> frame buffer from {fmt_off(off)}",
                buffer=(off, [st.byte_at(off + j) for j in range(n)]))


def _addr_text(a: x86.Addr) -> str:
    if a.kind == "stack":
        return fmt_off(a.off)
    if a.kind == "abs":
        return f"0x{a.off:x}"
    if a.kind == "stackidx":
        return f"{fmt_off(a.off)}+index"
    return "unknown"


# ---------------------------------------------------------------- render
def _safe(s: str) -> str:
    return re.sub(r"[\x00-\x1f\x7f]", "?", s)[:200]


def _qstr(bs: bytes) -> tuple[str, bool]:
    s = bs.decode("latin-1")
    esc = '"' in s or "\\" in s
    return s.replace("\\", "\\\\").replace('"', '\\"'), esc


def _runs(bytes_: list[Val]) -> list[tuple[int, int]]:
    out, start = [], None
    for k, b in enumerate(bytes_ + [Val(UNINIT)]):
        if b.kind == CONST and start is None:
            start = k
        elif b.kind != CONST and start is not None:
            out.append((start, k))
            start = None
    return out


def _text_forms(raw: bytes) -> list[str]:
    """`hex=` (9+ bytes only: a whole byte-string token) and `ascii=`/`utf16=` when every byte is printable."""
    parts = []
    if len(raw) >= MIN_HEX_RUN:
        parts.append(f"hex={raw.hex()}")
    body = raw[:-1] if raw.endswith(b"\x00") and len(raw) > 1 else raw
    if body and all(0x20 <= c < 0x7F for c in body):
        s, esc = _qstr(body)
        parts.append(f'ascii="{s}"')
        if len(body) < len(raw):
            parts.append("nul_terminated=yes")
        if esc:
            parts.append("escaped=yes")
    elif len(body) >= 2 and len(body) % 2 == 0 and all(body[i + 1] == 0 and 0x20 <= body[i] < 0x7F
                                                        for i in range(0, len(body), 2)):
        s, esc = _qstr(body[::2])
        parts.append(f'utf16="{s}"')
        if esc:
            parts.append("escaped=yes")
    elif 0 in raw and raw.index(0) > 0 and all(0x20 <= c < 0x7F for c in raw[:raw.index(0)]):
        s, esc = _qstr(raw[:raw.index(0)])   # printable bytes up to the first NUL: the C string the bytes hold
        parts.append(f'cstr="{s}"')
        if esc:
            parts.append("escaped=yes")
    return parts


def _site_list(sites, limit: int = 8) -> str:
    xs = sorted(sites)
    more = f",+{len(xs) - limit} more" if len(xs) > limit else ""
    return ",".join(f"0x{s:x}" for s in xs[:limit]) + more


def _candidate_runs(bs: list[Val]) -> list[tuple[int, int]]:
    """Ranges where every byte is definite or UNKNOWN with a known last definite write, with at least one such
    UNKNOWN byte (an all-definite range is a `run`)."""
    out, start = [], None
    ok = lambda b: b.kind == CONST or (b.kind == UNKNOWN and b.last is not None)
    for k, b in enumerate(bs + [Val(UNINIT)]):
        if ok(b) and start is None:
            start = k
        elif not ok(b) and start is not None:
            if k - start >= 2 and any(x.kind != CONST for x in bs[start:k]):
                out.append((start, k))
            start = None
    return out


def _render_buffer(off: int, bs: list[Val], target: int, sites: set, whys: set, srcs: set) -> list[str]:
    lines = [f"  bytes: {len(bs)} from {fmt_off(off)}, definite={sum(b.kind == CONST for b in bs)}"]

    for a, e in _runs(bs):
        raw = bytes(b.v & 0xFF for b in bs[a:e])
        run_tags = frozenset().union(*(tags_of(b.srcs) for b in bs[a:e]))
        parts = [f"  run +0x{a:x}..+0x{e - 1:x} len={e - a}"] + _text_forms(raw)
        if run_tags:
            parts.append("assumes=" + ",".join(sorted(run_tags)))
        lines.append(" ".join(parts))
    for a, e in _candidate_runs(bs):
        raw = bytes((b.v if b.kind == CONST else b.last) & 0xFF for b in bs[a:e])
        n_unk = sum(b.kind != CONST for b in bs[a:e])
        lines.append(" ".join([f"  candidate +0x{a:x}..+0x{e - 1:x} len={e - a}"] + _text_forms(raw)
                              + [f"NOT definite: last write of each byte; {n_unk} byte(s) may have been overwritten "
                                 "later (see their unknown reasons); only run_controlled can show the value is used"]))
    def key(b: Val):
        return (CONST, b.sites, tags_of(b.srcs)) if b.kind == CONST else (b.kind, b.sites, b.why, b.last)
    k = 0
    while k < len(bs):
        b = bs[k]
        j = k
        while j + 1 < len(bs) and key(bs[j + 1]) == key(b):
            j += 1
        span = f"+0x{k:x}" if j == k else f"+0x{k:x}..+0x{j:x}"
        if b.kind == CONST:
            lines.append(f"  {span} definite src={','.join(f'0x{s:x}' for s in sorted(b.sites))}{_assumes(b.srcs)}")
        elif b.kind == UNINIT:
            lines.append(f"  {span} unknown: no write reaches 0x{target:x} on any path (uninitialised)")
        elif b.kind in PTR_BYTES:
            what = fmt_off(b.v >> 4) + ("" if b.kind == PTRB else "+index")
            lines.append(f"  {span} frame address &{what} (spilled pointer) src={_site_list(b.sites)}")
        else:
            src = f" writes={_site_list(b.sites)}" if b.sites else ""
            last = f" last=0x{b.last:02x}" if b.last is not None else ""
            lines.append(f"  {span} unknown{last}{src}: {'; '.join(sorted(b.why)[:3])}")
        sites |= b.sites
        whys |= b.why
        srcs |= b.srcs
        k = j + 1
    return lines


def _assumes(srcs) -> str:
    t = tags_of(srcs)
    return (" assumes=" + ",".join(sorted(t))) if t else ""


def _eh_reasons(insns: list[InsnInfo], bits: int, given) -> tuple[str, ...]:
    found = list(given) + (ehmod.x86_markers(insns) if bits == 32 else [])
    return tuple(sorted(dict.fromkeys(found)))


def _eh_why(reasons: tuple[str, ...]) -> str:
    more = f"; +{len(reasons) - 3} more" if len(reasons) > 3 else ""
    return "exception handler not modelled (" + "; ".join(reasons[:3]) + more + ")"


def slice_function(dis: Disassembly, *, bits: int, target: int, image=None, operand: int | None = None,
                   location: str | None = None, size: int | None = None, max_steps: int = MAX_STEPS_DEFAULT,
                   engine: str = "", cache_key: tuple | None = None, exc_edges=(),
                   call_args: dict | None = None, eh_unmodelled=()) -> SliceResult:
    """`cache_key`: identifies (target, function, engine version, slicer revision); the function's analysis is then
    reused by later queries into the same function (in-process, at most CACHE_FUNCTIONS functions).
    `eh_unmodelled`: reasons (from eh.UnwindData.unmodelled) why the function has exception handlers the slicer does
    not model; x86 frame-based SEH is added here from the instructions. Non-empty: nothing is reported definite."""
    if bits not in (32, 64):
        raise SliceError("ARCH_UNSUPPORTED", f"only x86 (32-bit) and x64 are supported (bits={bits})")
    if size is not None and not 1 <= size <= MAX_BUFFER:
        raise SliceError("BAD_ARGUMENT", f"size must be 1..{MAX_BUFFER}")
    max_steps = max(1, min(int(max_steps), MAX_STEPS_MAX))
    insns = list(dis.items)
    by_addr = {i.address: i for i in insns}
    if target not in by_addr:
        raise SliceError("NO_INSTRUCTION", f"0x{target:x} is not the start of an instruction of this function")
    reasons: list[str] = []
    if not dis.complete:
        reasons.append("function disassembly incomplete" + (f" ({dis.stop_reason})" if dis.stop_reason else ""))
    entry = dis.function_address if dis.function_address in by_addr else min(by_addr)
    hit = _CACHE.get(cache_key) if cache_key is not None else None
    if hit is not None:
        cfg, ins_states, ctx = hit
        _CACHE.move_to_end(cache_key)
    else:
        ctx = x86.Ctx(bits, image)
        ctx.call_args = dict(call_args or {})
        ctx.eh_reasons = _eh_reasons(insns, bits, eh_unmodelled)
        if ctx.eh_reasons:
            ctx.eh = frozenset([_eh_why(ctx.eh_reasons)])
        cfg = build_cfg(insns, entry, dis.complete, exc_edges)
        ins_states = analyze(cfg, ctx)
        # final replay with effect recording (each instruction once, from the converged block-entry states)
        ctx.record = True
        for b, body in cfg.blocks.items():
            if b in ins_states:
                run_block(ins_states[b].copy(), body, ctx)
        ctx.record = False
        if cache_key is not None:
            _CACHE[cache_key] = (cfg, ins_states, ctx)
            while len(_CACHE) > CACHE_FUNCTIONS:
                _CACHE.popitem(last=False)
    tb = cfg.block_of[target]
    if tb in ins_states:
        st = run_block(ins_states[tb].copy(), cfg.blocks[tb], ctx, stop=target)
    else:   # the target itself is unreachable in this CFG: nothing is known about its inputs
        why = f"0x{target:x} is not reachable from the function entry in this CFG"
        reasons.append(why)
        st = run_block(top_state(ctx.families, why), cfg.blocks[tb], ctx, stop=target)
    reads = _query_reads(st, by_addr[target], ctx, operand, location, size)
    if ctx.eh:
        reasons.append(next(iter(ctx.eh)))
    reasons += [f"{r} at 0x{a:x}" for r, a in ctx.partial.items()]
    reasons += cfg.notes

    tins = by_addr[target]
    lines = [f"slice target=0x{target:x} function=0x{entry:x} name={_safe(dis.function_name)} bits={bits}",
             f"insn: 0x{target:x} | {_safe(tins.text)}",
             f"flow: cfg=harness from {engine or 'engine'} instructions, blocks={len(cfg.blocks)} "
             f"insns={len(insns)} exception_edges={cfg.exc_edges} (x64 scope tables) "
             + ("eh=unmodelled " if ctx.eh else "") +
             f"callee_parameter_lists={sum(v is not None for v in ctx.call_args.values())}/"
             f"{sum(1 for i in insns if x86.base_mnemonic(i.mnemonic) == 'call')} calls; "
             "sp=harness (sp0 = stack pointer at function entry)",
             "guarantee: 'definite' = the same value on every path of the CFG built from the engine's decoded "
             "instructions (the engine disassembly is taken as correct); anything else is printed as unknown"]
    sites: set[int] = set()
    whys: set[str] = set()
    srcs: set = set()   # image ranges and assumption tags of every reported value
    n_def = n_unk = n_buf_def = 0
    buffers = []
    for r in reads:
        lines.append(f"read {r.label}" + (f" ({r.note})" if r.note else ""))
        if r.value is not None:
            v = r.value
            if v.kind == CONST:
                lines.append(f"  value=0x{v.v:x} definite{_assumes(v.srcs)}")
                n_def += 1
            elif v.kind == STACK:
                lines.append(f"  value=&{fmt_off(v.v)} definite (frame address){_assumes(v.srcs)}")
                n_def += 1
            elif v.kind == RANGE:
                lines.append(f"  value=&{fmt_off(v.v)}+index (frame address, offset not constant; not below "
                             f"{fmt_off(v.v)} under A1)")
                n_unk += 1
                srcs.add("A1")
            else:
                lines.append("  value=unknown: " + "; ".join(sorted(v.why)[:4]))
                n_unk += 1
            sites |= v.sites
            whys |= v.why
            srcs |= v.srcs
        if r.buffer is not None:
            off, bs = r.buffer
            lines += _render_buffer(off, bs, target, sites, whys, srcs)
            nd = sum(b.kind == CONST for b in bs)
            n_buf_def += nd
            buffers.append({"offset": fmt_off(off), "size": len(bs), "definite": nd,
                            "runs": [[a, e - a] for a, e in _runs(bs)],
                            "candidate_runs": [[a, e - a] for a, e in _candidate_runs(bs)],
                            "assumes": sorted(frozenset().union(*(tags_of(b.srcs) for b in bs if b.kind == CONST)))})
    if ctx.eh:
        whys |= ctx.eh   # the rule is named even when the value is unknown for another reason as well
    def_sites = sorted(s for s in sites if s in by_addr)
    lines.append(f"defs: {len(def_sites)} (address order)")
    cut = max(0, len(def_sites) - max_steps)
    shown = def_sites[:max_steps]
    for s in shown:
        fx = "; ".join(ctx.effects.get(s, [])) or "no tracked write"
        lines.append(f"  0x{s:x} | {_safe(by_addr[s].text)} | {fx}")
    if cut:
        lines.append(f"cut: {cut} more definitions not shown (max_steps={max_steps})")
        reasons.append(f"max_steps={max_steps} reached")
    img_ranges = ranges_of(srcs)
    tags = tags_of(srcs)
    for va, n in img_ranges:
        ld = ctx.image_refs.get((va, n))
        if ld is None:
            continue
        head = f"image 0x{va:x} size={n} section={ld.section} {ld.flags}"
        if ld.data is None:
            lines.append(f"{head} unknown: {ld.reason}")
            continue
        val = f"hex={ld.data.hex()}" if n >= MIN_HEX_RUN else f"value=0x{int.from_bytes(ld.data, 'little'):x}"
        lines.append(f"{head} {val}" + (" note=initial file value only, section is writable" if ld.writable else ""))
    unk = sorted(whys)
    for w in unk[:MAX_UNKNOWN_LINES]:
        lines.append(f"unknown: {w}")
    if len(unk) > MAX_UNKNOWN_LINES:
        lines.append(f"unknown: ({len(unk) - MAX_UNKNOWN_LINES} more reasons not shown)")
    complete = not reasons
    lines.append("coverage: complete" if complete else "coverage: partial reasons=" + "; ".join(reasons))
    lim = ["callees are not entered (Windows x86/x64 ABI volatile registers become unknown after a call)",
           "image values are the file's bytes at the preferred image base (a relocated pointer differs at run time by "
           "the load delta); writable sections and import address slots give unknown"]
    if "A1" in tags:
        lim.append("A1: indexed stores and callees writing through an escaped frame address do not write below it")
    if "A3" in tags:
        lim.append("A3: a callee whose parameter list is unknown takes at most 16 stack arguments (x64: the home "
                   "space and 0x80 bytes above it; x86: 0x40 bytes); bytes above that window survive its call only "
                   "under this assumption")
    if "A2" in tags:
        lim.append("A2: stores through the stack pointer while its frame offset is unknown do not overlap "
                   "frame-pointer-relative slots")
    if ctx.eh:
        lim.append("this function has exception handlers the slicer does not model (see the unknown: lines): a handler "
                   "may rewrite any frame slot and resume at any instruction, so only immediates, read-only image "
                   "bytes and the frame pointer are reported definite; written bytes appear as candidates")
    if tags:
        lim.append("values marked assumes=A1/A2 hold only under that assumption (not unconditional)")
    lines += [f"assumption: {x}" for x in lim]
    addresses = sorted({target} | set(shown))
    summary = {"reads": len(reads), "definite_values": n_def, "unknown_values": n_unk, "defs": len(def_sites),
               "defs_shown": len(shown), "buffers": buffers, "unknown_reasons": len(unk),
               "image_ranges": len(img_ranges), "complete": complete, "assumptions": sorted(tags)}
    if ctx.eh:
        summary["eh_unmodelled"] = list(ctx.eh_reasons)
    return SliceResult("\n".join(lines) + "\n", complete, reasons, addresses,
                       [r for r in img_ranges if r in ctx.image_refs], summary)
