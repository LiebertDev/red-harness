"""x86/x64 transfer functions of the slicer: an explicit allowlist (docs/design/dataflow-slice.md section 3.2, MVP).

Modelled exactly: width-correct `mov` (x64: a 32-bit register write zeroes the upper half, 8/16-bit writes keep the rest),
`movzx`/`movsx`/`movsxd`, `cbw`/`cwde`/`cdqe`, `cwd`/`cdq`/`cqo`, `lea` (as arithmetic), `add sub and or xor shl sal shr
not neg inc dec`, `xchg`, `push`/`pop`/`leave` while the stack pointer offset is known, `call` (volatile registers of the
Windows x86/x64 ABIs become unknown, eax/rax is the call's return value), and instructions that write nothing tracked
(`cmp`, `test`, jumps, `nop`, ...).

Everything else is NOT interpreted: flag-dependent ops (`cmovcc`, `setcc`, `adc`, `sbb`), SSE/AVX, string ops with or
without `rep`, x87 stores: their destination becomes UNKNOWN with the reason `unmodelled <mnemonic> at <va>`. A mnemonic
whose implicit effects are not known at all makes every general register unknown (coverage partial).

Assumptions (printed with the result when they were used):
- A1: an indexed store, or a callee writing through an escaped frame address, does not write below that address.
- A2: a store addressed through the stack pointer register while its frame offset is unknown (argument pushes after a
  call with unknown stack cleanup, frames aligned with `and esp, -N`) does not overlap frame-pointer-relative slots.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ...engines.base import InsnInfo, OperandInfo
from .state import (CONST, EMPTY, FRAME, PTR_BYTES, PTRB, RANGE, RPTRB, STACK, UNINIT, UNKNOWN, State, Val, const,
                    fmt_off, from_bytes, split, taint, unknown)

# ---------------------------------------------------------------- registers
REG: dict[str, tuple[str, int, int]] = {}   # name -> (family, byte offset, size)
for _f, (_e, _x, _l, _h) in {"rax": ("eax", "ax", "al", "ah"), "rbx": ("ebx", "bx", "bl", "bh"),
                             "rcx": ("ecx", "cx", "cl", "ch"), "rdx": ("edx", "dx", "dl", "dh")}.items():
    REG.update({_f: (_f, 0, 8), _e: (_f, 0, 4), _x: (_f, 0, 2), _l: (_f, 0, 1), _h: (_f, 1, 1)})
for _f, (_e, _x, _l) in {"rsi": ("esi", "si", "sil"), "rdi": ("edi", "di", "dil"), "rbp": ("ebp", "bp", "bpl"),
                         "rsp": ("esp", "sp", "spl")}.items():
    REG.update({_f: (_f, 0, 8), _e: (_f, 0, 4), _x: (_f, 0, 2), _l: (_f, 0, 1)})
for _i in range(8, 16):
    REG.update({f"r{_i}": (f"r{_i}", 0, 8), f"r{_i}d": (f"r{_i}", 0, 4), f"r{_i}w": (f"r{_i}", 0, 2),
                f"r{_i}b": (f"r{_i}", 0, 1), f"r{_i}l": (f"r{_i}", 0, 1)})

FAMILIES64 = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp") + tuple(f"r{i}" for i in range(8, 16))
FAMILIES32 = FAMILIES64[:8]
VOLATILE64 = ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11")
VOLATILE32 = ("rax", "rcx", "rdx")
NAME32 = {"rax": "eax", "rbx": "ebx", "rcx": "ecx", "rdx": "edx", "rsi": "esi", "rdi": "edi", "rbp": "ebp",
          "rsp": "esp"}

CONDITIONAL = frozenset({
    "ja", "jae", "jb", "jbe", "jc", "je", "jg", "jge", "jl", "jle", "jna", "jnae", "jnb", "jnbe", "jnc", "jne", "jng",
    "jnge", "jnl", "jnle", "jno", "jnp", "jns", "jnz", "jo", "jp", "jpe", "jpo", "js", "jz", "jcxz", "jecxz", "jrcxz",
    "loop", "loope", "loopne", "loopz", "loopnz"})
RETURNS = frozenset({"ret", "retn", "retf", "iret", "iretd", "iretq", "hlt", "ud2", "int3"})
NO_EFFECT = frozenset({"cmp", "test", "nop", "jmp", "pause", "lfence", "mfence", "sfence", "clc", "stc", "cmc", "cld",
                       "std", "endbr32", "endbr64", "bt", "prefetch", "prefetchw", "prefetcht0", "prefetcht1",
                       "prefetcht2", "prefetchnta", "fnop", "wait", "fwait", "ucomiss", "ucomisd", "comiss", "comisd",
                       "ptest", "vptest", "emms", "vzeroupper", "sahf", "cli", "sti"}) | CONDITIONAL | RETURNS
# Destination = operand 0, no implicit register effects beyond flags (not interpreted: the destination becomes unknown)
OP0_ONLY = frozenset({"adc", "sbb", "sar", "rol", "ror", "rcl", "rcr", "shld", "shrd", "bts", "btr", "btc", "bsf", "bsr",
                      "tzcnt", "lzcnt", "popcnt", "andn", "bextr", "blsi", "blsr", "blsmsk", "pdep", "pext", "sarx",
                      "shlx", "shrx", "rorx", "movbe", "crc32", "bswap", "imul"})
# implicit register effects (family names) of instructions that are not interpreted
IMPLICIT = {
    "mul": ("rax", "rdx"), "div": ("rax", "rdx"), "idiv": ("rax", "rdx"), "cpuid": ("rax", "rbx", "rcx", "rdx"),
    "rdtsc": ("rax", "rdx"), "rdtscp": ("rax", "rcx", "rdx"), "xgetbv": ("rax", "rdx"), "rdmsr": ("rax", "rdx"),
    "rdpmc": ("rax", "rdx"), "lahf": ("rax",), "xlat": ("rax",), "xlatb": ("rax",), "in": ("rax",),
    "loop": ("rcx",), "loope": ("rcx",), "loopne": ("rcx",), "loopz": ("rcx",), "loopnz": ("rcx",),
    "cmpxchg": ("rax",), "cmpxchg8b": ("rax", "rdx"), "cmpxchg16b": ("rax", "rdx"), "xadd": (),
    "pcmpestri": ("rcx",), "pcmpistri": ("rcx",), "vpcmpestri": ("rcx",), "vpcmpistri": ("rcx",),
}
STRING_OPS = {"stos": ("rdi", "rcx"), "movs": ("rdi", "rsi", "rcx"), "lods": ("rax", "rsi", "rcx"),
              "scas": ("rdi", "rcx"), "cmps": ("rdi", "rsi", "rcx"), "ins": ("rdi", "rcx"), "outs": ("rsi", "rcx")}
X87_STORES = frozenset({"fst", "fstp", "fist", "fistp", "fisttp", "fbstp", "fnstsw", "fstsw", "fnstcw", "fstcw",
                        "fnstenv", "fstenv", "fnsave", "fsave", "fxsave", "fxsave64"})
_PTR_WIDTH = {"byte": 1, "word": 2, "dword": 4, "qword": 8, "tbyte": 10, "xmmword": 16, "oword": 16, "ymmword": 32,
              "zmmword": 64}
_PTR_RE = re.compile(r"\b(byte|word|dword|qword|tbyte|xmmword|oword|ymmword|zmmword)\s+ptr\b", re.I)
_SEG_RE = re.compile(r"\b[fg]s:", re.I)
_SIMD_RE = re.compile(r"^(?:xmm|ymm|zmm|mm|k)\d+$|^st\(?\d?\)?$")
_X87_RE = re.compile(r"^f(?:n?(?:init|clex|stenv|save)|i?ld|bld|ld(?:z|1|pi|l2e|l2t|lg2|ln2|cw|env)|i?add|addp|"
                     r"i?subr?p?|i?mul|mulp|i?divr?p?|i?comp?|compp|comip?|ucomi?p?|ucompp|tst|xam|chs|abs|sqrt|sin|cos|"
                     r"sincos|ptan|patan|2xm1|yl2xp?1?|scale|prem1?|rndint|xtract|xch|incstp|decstp|free|"
                     r"cmovn?(?:b|e|be|u)|rstor|xrstor(?:64)?)$")
_STRING_RE = re.compile(r"^(stos|movs|lods|scas|cmps|ins|outs)([bwdq]?)$")


def mask(nbytes: int) -> int:
    return (1 << (8 * nbytes)) - 1


def sext(v: int, from_bytes: int, to_bytes: int) -> int:
    v &= mask(from_bytes)
    if from_bytes < to_bytes and v >> (8 * from_bytes - 1):
        v |= mask(to_bytes) & ~mask(from_bytes)
    return v & mask(to_bytes)


def signed(v: int, nbytes: int) -> int:
    v &= mask(nbytes)
    return v - (1 << (8 * nbytes)) if v >> (8 * nbytes - 1) else v


def base_mnemonic(m: str) -> str:
    """Ghidra writes prefixes as a suffix (`stosd.rep`); IDA's contract mnemonic has no prefix."""
    return m.split(".", 1)[0]


@dataclass
class Ctx:
    bits: int
    image: object | None = None          # PeImageView-like: load(va, size) -> ImageLoad | None
    record: bool = False
    effects: dict = field(default_factory=dict)       # insn VA -> [effect text]
    image_refs: dict = field(default_factory=dict)    # (va, size) -> ImageLoad
    assumptions: set = field(default_factory=set)     # {"A1", "A2", "A3"}
    call_args: dict = field(default_factory=dict)     # call VA -> callee stack-parameter bytes (None/absent = unknown)
    partial: dict = field(default_factory=dict)       # reason -> first VA
    eh: frozenset = frozenset()                       # non-empty: unmodelled exception handler (see slicer._step)
    eh_reasons: tuple = ()

    @property
    def fw(self) -> int:
        return 8 if self.bits == 64 else 4

    @property
    def families(self) -> tuple[str, ...]:
        return FAMILIES64 if self.bits == 64 else FAMILIES32

    def rname(self, fam: str) -> str:
        return fam if self.bits == 64 else NAME32.get(fam, fam)

    def fx(self, va: int, text: str) -> None:
        if self.record:
            self.effects.setdefault(va, []).append(text)


def fmt_fx(v: Val) -> str:
    """A written value in a `writes ...` annotation; a value that holds only under A1/A2 says so (the verifier treats
    such a line as conditional, version 23)."""
    tags = sorted(x for x in v.srcs if isinstance(x, str))
    if v.parts is not None:
        tags = sorted(set(tags) | {x for p in v.parts for x in p.srcs if isinstance(x, str)})
    return fmt_val(v) + (" assumes=" + ",".join(tags) if tags and v.kind in (CONST, STACK) else "")


def fmt_val(v: Val) -> str:
    if v.kind == CONST:
        return f"0x{v.v:x}"
    if v.kind == STACK:
        return f"&{fmt_off(v.v)}"
    if v.kind == RANGE:
        return f"&{fmt_off(v.v)}+index"
    return "unknown"


# ---------------------------------------------------------------- registers
def tracked(name: str, ctx: Ctx) -> bool:
    r = REG.get(name)
    return r is not None and r[0] in ctx.families


def read_reg(st: State, name: str, ctx: Ctx) -> Val:
    if not tracked(name, ctx):
        return unknown(f"untracked register {name}")
    fam, off, sz = REG[name]
    v = st.regs[fam]
    if off == 0 and sz >= ctx.fw:
        return v
    if v.kind == CONST:
        return Val(CONST, (v.v >> (8 * off)) & mask(sz), v.sites, EMPTY, v.srcs)
    if v.parts is not None:
        return from_bytes(list(v.parts[off:off + sz]))
    if v.kind in FRAME:
        if fam != "rsp":
            st.escape(v.v)
        return taint([v], f"partial read {name} of a frame address")
    return v


def write_reg(st: State, name: str, val: Val, ctx: Ctx, site: int) -> None:
    if not tracked(name, ctx):
        return
    fam, off, sz = REG[name]
    val = val.with_site(site)
    if val.kind == CONST:
        val = Val(CONST, val.v & mask(sz), val.sites, EMPTY, val.srcs)
    if off == 0 and sz >= ctx.fw:
        new = val if val.parts is None or len(val.parts) == ctx.fw else from_bytes(split(val, sz)[:ctx.fw])
    elif off == 0 and sz == 4:     # x64: a 32-bit write zero-extends
        if val.kind in FRAME:
            new = taint([val], f"frame address truncated to 32 bits at 0x{site:x}")
            if fam != "rsp":
                st.escape(val.v)
        elif val.kind == CONST:
            new = val
        else:
            new = from_bytes(split(val, 4) + [const(0, {site})] * 4)
    else:                          # 8/16-bit write keeps the other bytes
        old = st.regs[fam]
        for x in (old, val):
            if x.kind in FRAME and fam != "rsp":
                st.escape(x.v)
        bs = split(old, ctx.fw)
        bs[off:off + sz] = split(val, sz)
        new = from_bytes(bs)
    st.regs[fam] = new
    ctx.fx(site, f"writes {ctx.rname(fam) if sz >= ctx.fw else name} value={fmt_fx(new if sz >= ctx.fw else val)}")


# ---------------------------------------------------------------- memory
@dataclass(frozen=True)
class Addr:
    kind: str            # "stack" | "stackidx" (frame base, index unknown) | "abs" | "unknown"
    off: int = 0         # frame offset (stack/stackidx) or VA (abs)
    sites: frozenset = EMPTY
    why: frozenset = EMPTY
    via_sp: bool = False  # addressed through the stack pointer register
    srcs: frozenset = EMPTY   # dependencies of the address itself (image ranges, assumption tags)


def width_of(op: OperandInfo, ctx: Ctx, other: OperandInfo | None = None) -> int | None:
    if op.kind == "reg":
        r = REG.get(op.reg)
        return r[2] if r else (op.size or None)
    if op.kind == "mem":
        if op.size:
            return op.size
        m = _PTR_RE.search(op.text or "")
        if m:
            return _PTR_WIDTH[m.group(1).lower()]
        if other is not None and other.kind == "reg" and other.reg in REG:
            return REG[other.reg][2]
        return None
    if op.kind == "imm":
        return op.size or None
    return op.size or None


def address(st: State, op: OperandInfo, insn: InsnInfo, ctx: Ctx) -> Addr:
    if _SEG_RE.search(op.text or ""):
        return Addr("unknown", why=frozenset([f"segment-relative memory ({op.text})"]))
    base, index = op.base or "", op.index or ""
    disp = op.disp or 0
    if not base and not index:
        if op.value is not None:
            return Addr("abs", op.value & mask(ctx.fw))
        return Addr("abs", disp & mask(ctx.fw))
    if base in ("rip", "eip") and not index:
        return Addr("abs", (insn.address + insn.size + disp) & mask(ctx.fw))
    via_sp = REG.get(base, ("",))[0] == "rsp"
    b = read_reg(st, base, ctx) if base else const(0)
    if via_sp and b.kind != STACK:
        return Addr("unknown", 0, b.sites, b.why | {"stack pointer offset unknown"}, via_sp=True)
    i = read_reg(st, index, ctx) if index else const(0)
    scale = op.scale or 1
    if b.kind == STACK and i.kind == CONST:
        return Addr("stack", b.v + signed(i.v, ctx.fw) * scale + disp, i.sites, via_sp=via_sp, srcs=i.srcs)
    if b.kind == CONST and i.kind == STACK and scale == 1:
        return Addr("stack", i.v + signed(b.v, ctx.fw) + disp, b.sites, via_sp=via_sp, srcs=b.srcs)
    if b.kind == RANGE and i.kind == CONST:
        return Addr("stackidx", b.v + signed(i.v, ctx.fw) * scale + disp, b.sites | i.sites,
                    frozenset([f"{base} points into the frame at a non-constant offset"]), via_sp=via_sp)
    if b.kind == CONST and i.kind == RANGE and scale == 1:
        return Addr("stackidx", i.v + signed(b.v, ctx.fw) + disp, b.sites | i.sites,
                    frozenset([f"{index} points into the frame at a non-constant offset"]), via_sp=via_sp)
    if b.kind == CONST and i.kind == CONST:
        return Addr("abs", (b.v + i.v * scale + disp) & mask(ctx.fw), b.sites | i.sites, via_sp=via_sp,
                    srcs=b.srcs | i.srcs)
    if b.kind in FRAME and i.kind not in FRAME:
        return Addr("stackidx", b.v + disp, b.sites | i.sites, i.why | {f"index {index} unknown"}, via_sp=via_sp)
    return Addr("unknown", 0, b.sites | i.sites, b.why | i.why, via_sp=via_sp)


def combine(bs: list[Val], fw: int = 0) -> Val:
    """Bytes read from the frame -> one value. A frame address spilled to a slot comes back whole (same width as a
    pointer, the bytes of one store in order); anything else that is not all CONST is UNKNOWN."""
    if fw and len(bs) == fw and all(b.kind in PTR_BYTES for b in bs) and len({b.v >> 4 for b in bs}) == 1             and [b.v & 15 for b in bs] == list(range(fw)):
        sites = frozenset().union(*(b.sites for b in bs))
        srcs = frozenset().union(*(b.srcs for b in bs))
        kind = STACK if all(b.kind == PTRB for b in bs) else RANGE
        return Val(kind, bs[0].v >> 4, sites, EMPTY, srcs)
    if all(b.kind == CONST for b in bs):
        v = 0
        for k, b in enumerate(bs):
            v |= (b.v & 0xFF) << (8 * k)
        sites, srcs = set(), set()
        for b in bs:
            sites |= b.sites
            srcs |= b.srcs
        return Val(CONST, v, frozenset(sites), EMPTY, frozenset(srcs))
    return taint(bs, None)


def load(st: State, op: OperandInfo, w: int | None, insn: InsnInfo, ctx: Ctx) -> Val:
    a = address(st, op, insn, ctx)
    site = insn.address
    if w is None:
        return unknown(f"access width unknown at 0x{site:x} ({op.text})")
    if a.kind == "stack":
        bs = [st.byte_at(a.off + k) for k in range(w)]
        v = combine(bs, ctx.fw)
        if v.kind == UNKNOWN:
            for b in bs:
                if b.kind in PTR_BYTES:   # part of a spilled frame address read back as data: lose track of it
                    st.escape(b.v >> 4)
            if any(b.kind in PTR_BYTES for b in bs):
                v = taint([v], f"partial or mixed read of a spilled frame address at 0x{site:x}")
        return v if not a.srcs else Val(v.kind, v.v, v.sites, v.why, v.srcs | a.srcs)
    if a.kind == "stackidx":
        return unknown(a.why | {f"load from frame buffer {fmt_off(a.off)} with unknown index at 0x{site:x}"}, a.sites)
    if a.kind == "abs":
        return image_load(a.off, w, a.sites, site, ctx, a.srcs)
    return unknown(a.why | {f"load through an unknown pointer at 0x{site:x} ({op.text})"}, a.sites)


def image_load(va: int, w: int, sites, site: int, ctx: Ctx, deps=EMPTY) -> Val:
    ld = ctx.image.load(va, w) if ctx.image is not None else None
    if ld is None:
        return unknown(f"memory 0x{va:x} at 0x{site:x} is outside the image (or no image)", sites)
    ctx.image_refs[(va, w)] = ld
    if ld.data is None:
        return unknown(f"image 0x{va:x} ({ld.section}): {ld.reason}", sites, {(va, w)})
    if ld.writable:
        return unknown(f"image 0x{va:x} is in writable section {ld.section} {ld.flags}: run-time value unknown "
                       "(file bytes shown as initial value only)", sites, {(va, w)})
    return Val(CONST, int.from_bytes(ld.data, "little"), frozenset(sites), EMPTY, frozenset({(va, w)}) | deps)


def store(st: State, op: OperandInfo, w: int | None, val: Val, insn: InsnInfo, ctx: Ctx) -> None:
    site = insn.address
    a = address(st, op, insn, ctx)
    spill = a.kind == "stack" and w == ctx.fw and val.kind in FRAME
    if val.kind in FRAME and not spill:
        st.escape(val.v)
    if spill:   # a frame address spilled into a frame slot: kept byte by byte so that a reload gives it back
        kind = PTRB if val.kind == STACK else RPTRB
        for k in range(w):
            st.put(a.off + k, Val(kind, (val.v << 4) | k, val.sites | {site}, EMPTY, val.srcs))
        ctx.fx(site, f"writes {fmt_off(a.off)} size={w} value={fmt_fx(val)}")
        return
    if a.kind == "stack" and w is not None:
        if val.parts is not None and w <= len(val.parts):
            for k, b in enumerate(val.parts[:w]):
                st.put(a.off + k, b.with_site(site))
            ctx.fx(site, f"writes {fmt_off(a.off)} size={w} value={fmt_fx(val)}")
            return
        if val.kind == CONST:
            bs = [Val(CONST, (val.v >> (8 * k)) & 0xFF, val.sites | {site}, EMPTY, val.srcs) for k in range(w)]
        else:
            why = f"frame address {fmt_val(val)} stored at 0x{site:x}" if val.kind in FRAME else None
            u = taint([val], why, {site})
            bs = [u] * w
        for k, b in enumerate(bs):
            st.put(a.off + k, b)
        ctx.fx(site, f"writes {fmt_off(a.off)} size={w} value={fmt_fx(val)}")
        return
    if a.kind in ("stack", "stackidx"):
        ctx.assumptions.add("A1")
        why = (f"store of unknown width at 0x{site:x}" if a.kind == "stack"
               else f"store with unknown index at 0x{site:x} into frame from {fmt_off(a.off)}")
        st.havoc_from(a.off, why, site)
        ctx.fx(site, f"writes {fmt_off(a.off)} and above: unknown")
        return
    if a.kind == "abs":
        ctx.fx(site, f"writes memory 0x{a.off:x} value={fmt_fx(val)} (global, not tracked)")
        return
    if a.via_sp:
        ctx.assumptions.add("A2")
        st.tag_all("A2")
        ctx.fx(site, "writes a stack slot at an unknown offset (A2)")
        return
    if st.esc:
        ctx.assumptions.add("A1")
        st.havoc_from(min(st.esc), f"store through an unknown pointer at 0x{site:x} may hit an escaped frame "
                                   "address", site)
    ctx.fx(site, "writes memory through an unknown pointer")


# ---------------------------------------------------------------- operand get/put
def get(st: State, op: OperandInfo, w: int | None, insn: InsnInfo, ctx: Ctx) -> Val:
    if op.kind == "reg":
        return read_reg(st, op.reg, ctx)
    if op.kind == "imm":
        if op.value is None or w is None:
            return unknown(f"immediate not decoded at 0x{insn.address:x}")
        v = op.value
        if op.size and op.size < w:
            v = sext(v, op.size, w)
        return const(v & mask(w))
    if op.kind == "mem":
        return load(st, op, w, insn, ctx)
    if op.kind == "near" and op.value is not None:
        return const(op.value)
    return unknown(f"operand {op.text!r} not modelled at 0x{insn.address:x}")


def put(st: State, op: OperandInfo, w: int | None, val: Val, insn: InsnInfo, ctx: Ctx) -> None:
    if op.kind == "reg":
        write_reg(st, op.reg, val, ctx, insn.address)
    elif op.kind == "mem":
        store(st, op, w, val, insn, ctx)


def _unmodelled(st: State, insn: InsnInfo, ctx: Ctx, why: str) -> None:
    ops = insn.operands
    if ops:
        d = ops[0]
        if d.kind == "reg" and tracked(d.reg, ctx):
            write_reg(st, d.reg, unknown(why), ctx, insn.address)
        elif d.kind == "mem":
            store(st, d, width_of(d, ctx, ops[1] if len(ops) > 1 else None), unknown(why), insn, ctx)


def _havoc_regs(st: State, fams, why: str, ctx: Ctx, site: int) -> None:
    for f in fams:
        if f in st.regs:
            old = st.regs[f]
            if old.kind in FRAME and f != "rsp":
                st.escape(old.v)
            st.regs[f] = unknown(why, {site})
            ctx.fx(site, f"writes {ctx.rname(f)} value=unknown")


# ---------------------------------------------------------------- the transfer function
def step(st: State, insn: InsnInfo, ctx: Ctx) -> None:
    m = base_mnemonic(insn.mnemonic)
    ops = insn.operands
    site = insn.address
    fw = ctx.fw
    if m in NO_EFFECT:
        return
    if m == "mov" or m == "movabs":
        if len(ops) != 2:
            return _unmodelled(st, insn, ctx, f"unmodelled {m} form at 0x{site:x}")
        d, s = ops
        if d.kind == "reg" and not tracked(d.reg, ctx):
            return                                    # segment/control/debug register destination: not tracked
        w = width_of(d, ctx, s) or width_of(s, ctx, d)
        return put(st, d, w, get(st, s, w, insn, ctx), insn, ctx)
    if m in ("movzx", "movsx", "movsxd") and len(ops) == 2:
        d, s = ops
        wd, ws = width_of(d, ctx), width_of(s, ctx)
        if ws is None or wd is None:
            return put(st, d, wd, unknown(f"source width unknown at 0x{site:x}"), insn, ctx)
        v = get(st, s, ws, insn, ctx)
        if v.kind == CONST:
            v = Val(CONST, sext(v.v, ws, wd) if m != "movzx" else v.v & mask(ws), v.sites, EMPTY, v.srcs)
        elif v.kind in FRAME:
            st.escape(v.v)
            v = taint([v], f"frame address extended at 0x{site:x}")
        return put(st, d, wd, v, insn, ctx)
    if m in ("cbw", "cwde", "cdqe"):
        frm, to, dst = {"cbw": (1, 2, "ax"), "cwde": (2, 4, "eax"), "cdqe": (4, 8, "rax")}[m]
        src = read_reg(st, {1: "al", 2: "ax", 4: "eax"}[frm], ctx)
        v = Val(CONST, sext(src.v, frm, to), src.sites, EMPTY, src.srcs) if src.kind == CONST else taint([src], None)
        return write_reg(st, dst, v, ctx, site)
    if m in ("cwd", "cdq", "cqo"):
        n, src_name, dst = {"cwd": (2, "ax", "dx"), "cdq": (4, "eax", "edx"), "cqo": (8, "rax", "rdx")}[m]
        src = read_reg(st, src_name, ctx)
        v = Val(CONST, mask(n) if src.v >> (8 * n - 1) else 0, src.sites, EMPTY, src.srcs) \
            if src.kind == CONST else taint([src], None)
        return write_reg(st, dst, v, ctx, site)
    if m == "lea" and len(ops) == 2 and ops[1].kind == "mem":
        d, s = ops
        a = address(st, s, insn, ctx)
        if a.kind == "stack":
            v = Val(STACK, a.off, a.sites)
        elif a.kind == "abs":
            v = const(a.off, a.sites, a.srcs)
        elif a.kind == "stackidx":   # into the frame at a non-constant offset from a.off
            v = Val(RANGE, a.off, a.sites)
        else:
            v = unknown(a.why | {f"lea of an unknown address at 0x{site:x}"}, a.sites)
        return write_reg(st, d.reg, v, ctx, site) if d.kind == "reg" else None
    if m in ("add", "sub", "and", "or", "xor") and len(ops) == 2:
        return _binop(st, m, insn, ctx)
    if m in ("shl", "sal", "shr") and len(ops) in (1, 2):
        return _shift(st, m, insn, ctx)
    if m in ("inc", "dec", "not", "neg") and len(ops) == 1:
        d = ops[0]
        w = width_of(d, ctx)
        a = get(st, d, w, insn, ctx)
        if a.kind == CONST and w:
            r = {"inc": a.v + 1, "dec": a.v - 1, "not": ~a.v, "neg": -a.v}[m] & mask(w)
            v = Val(CONST, r, a.sites, EMPTY, a.srcs)
        elif a.kind in FRAME and m in ("inc", "dec") and w == fw:
            v = Val(a.kind, a.v + (1 if m == "inc" else -1), a.sites)
        else:
            if a.kind in FRAME and not (d.kind == "reg" and REG.get(d.reg, ("",))[0] == "rsp"):
                st.escape(a.v)
            v = taint([a], None if a.kind == UNKNOWN else f"{m} of a non-constant at 0x{site:x}")
        return put(st, d, w, v, insn, ctx)
    if m == "xchg" and len(ops) == 2:
        a, b = ops
        if a.kind == b.kind == "reg" and a.reg == b.reg:
            return
        w = width_of(a, ctx, b) or width_of(b, ctx, a)
        va, vb = get(st, a, w, insn, ctx), get(st, b, w, insn, ctx)
        put(st, a, w, vb, insn, ctx)
        return put(st, b, w, va, insn, ctx)
    if m == "push" and len(ops) == 1:
        s = ops[0]
        w = fw if s.kind == "imm" else (width_of(s, ctx) or fw)
        v = get(st, s, w, insn, ctx)
        return _push(st, v, w, insn, ctx)
    if m == "pop" and len(ops) == 1:
        d = ops[0]
        w = width_of(d, ctx) or fw
        return _pop(st, d, w, insn, ctx)
    if m == "leave":
        st.regs["rsp"] = st.regs["rbp"].with_site(site)
        return _pop(st, OperandInfo("reg", ctx.rname("rbp"), reg=ctx.rname("rbp")), fw, insn, ctx)
    if m == "call":
        return _call(st, insn, ctx)
    # ---- not interpreted
    if m in ("pushf", "pushfd", "pushfq"):
        return _push(st, unknown(f"flags pushed at 0x{site:x}"), fw, insn, ctx)
    if m in ("popf", "popfd", "popfq"):
        sp = st.regs["rsp"]
        st.regs["rsp"] = Val(STACK, sp.v + fw, sp.sites | {site}) if sp.kind == STACK else sp
        return
    sm = _STRING_RE.match(m)
    if sm and not any(o.kind == "reg" and _SIMD_RE.match(o.reg or "") for o in ops):
        why = f"unmodelled string instruction {m} at 0x{site:x}"
        if sm.group(1) in ("stos", "movs", "ins"):
            di = read_reg(st, ctx.rname("rdi"), ctx)
            if di.kind in FRAME:
                ctx.assumptions.add("A1")
                st.havoc_from(di.v, why, site)
            elif di.kind != CONST:
                store(st, OperandInfo("mem", "[rdi]", base=ctx.rname("rdi")), None, unknown(why), insn, ctx)
        return _havoc_regs(st, STRING_OPS[sm.group(1)], why, ctx, site)
    if m in IMPLICIT:
        why = f"unmodelled {m} at 0x{site:x}"
        _unmodelled(st, insn, ctx, why)
        if m in ("xadd",) and len(ops) == 2:
            _unmodelled(st, InsnInfo(site, insn.size, insn.bytes_hex, m, (ops[1],), insn.text), ctx, why)
        return _havoc_regs(st, IMPLICIT[m], why, ctx, site)
    if m in ("imul",) and len(ops) == 1:
        return _havoc_regs(st, ("rax", "rdx"), f"unmodelled imul at 0x{site:x}", ctx, site)
    if m in OP0_ONLY or m.startswith("cmov") or (m.startswith("set") and len(ops) == 1):
        return _unmodelled(st, insn, ctx, f"unmodelled {m} at 0x{site:x}")
    if m in X87_STORES or _X87_RE.match(m):
        if m in X87_STORES:
            if m in ("fnstsw", "fstsw") and ops and ops[0].kind == "reg":
                return _unmodelled(st, insn, ctx, f"unmodelled {m} at 0x{site:x}")
            return _unmodelled(st, insn, ctx, f"unmodelled x87 store {m} at 0x{site:x}")
        return                                         # x87 arithmetic/loads: no general-register effect
    if any(o.kind == "reg" and _SIMD_RE.match(o.reg or "") for o in ops):
        return _unmodelled(st, insn, ctx, f"unmodelled SIMD instruction {m} at 0x{site:x}")
    if m in ("maskmovdqu", "maskmovq", "vmaskmovdqu"):
        return store(st, OperandInfo("mem", "[rdi]", base=ctx.rname("rdi")), None,
                     unknown(f"unmodelled {m} at 0x{site:x}"), insn, ctx)
    # unknown implicit effects: nothing in the general registers can be trusted after it
    ctx.partial.setdefault(f"instruction with unknown effects: {m}", site)
    why = f"instruction with unknown effects {m} at 0x{site:x}"
    _unmodelled(st, insn, ctx, why)
    _havoc_regs(st, ctx.families, why, ctx, site)


def _binop(st: State, m: str, insn: InsnInfo, ctx: Ctx) -> None:
    d, s = insn.operands
    site = insn.address
    w = width_of(d, ctx, s) or width_of(s, ctx, d)
    if m in ("xor", "sub") and d.kind == "reg" and s.kind == "reg" and d.reg == s.reg:
        return put(st, d, w, const(0), insn, ctx)    # zero idiom
    a, b = get(st, d, w, insn, ctx), get(st, s, w, insn, ctx)
    dst_sp = d.kind == "reg" and REG.get(d.reg, ("",))[0] == "rsp"
    if a.kind == CONST and b.kind == CONST and w:
        r = {"add": a.v + b.v, "sub": a.v - b.v, "and": a.v & b.v, "or": a.v | b.v, "xor": a.v ^ b.v}[m]
        v = Val(CONST, r & mask(w), a.sites | b.sites, EMPTY, a.srcs | b.srcs)
    elif m in ("add", "sub") and a.kind in FRAME and b.kind == CONST and w == ctx.fw:
        delta = signed(b.v, w)
        v = Val(a.kind, a.v + (delta if m == "add" else -delta), a.sites | b.sites)
    elif m == "add" and a.kind == CONST and b.kind in FRAME and w == ctx.fw:
        v = Val(b.kind, b.v + signed(a.v, w), a.sites | b.sites)
    elif m == "add" and not dst_sp and w == ctx.fw and (a.kind in FRAME) != (b.kind in FRAME)             and UNKNOWN in (a.kind, b.kind):
        f = a if a.kind in FRAME else b    # frame address + unknown index: offset not constant (A1: index >= 0)
        v = Val(RANGE, f.v, a.sites | b.sites)
    else:
        for x in (a, b):
            if x.kind in FRAME and not (dst_sp and x is a):
                st.escape(x.v)
        if dst_sp and a.kind in FRAME and m == "and":
            why = f"stack pointer aligned at 0x{site:x}: frame offset unknown"
        elif a.kind in FRAME or b.kind in FRAME:
            why = f"{m} on a frame address at 0x{site:x}"
        else:
            why = None
        v = taint([a, b], why)
    put(st, d, w, v, insn, ctx)


def _shift(st: State, m: str, insn: InsnInfo, ctx: Ctx) -> None:
    ops = insn.operands
    d = ops[0]
    w = width_of(d, ctx)
    a = get(st, d, w, insn, ctx)
    c = get(st, ops[1], 1, insn, ctx) if len(ops) == 2 else const(1)
    if a.kind == CONST and c.kind == CONST and w:
        n = c.v & (0x3F if w == 8 else 0x1F)
        r = (a.v << n) if m in ("shl", "sal") else (a.v >> n)
        v = Val(CONST, r & mask(w), a.sites | c.sites, EMPTY, a.srcs | c.srcs)
    else:
        if a.kind in FRAME:
            st.escape(a.v)
        v = taint([a, c], f"{m} of a frame address at 0x{insn.address:x}" if a.kind in FRAME else None)
    put(st, d, w, v, insn, ctx)


def _push(st: State, v: Val, w: int, insn: InsnInfo, ctx: Ctx) -> None:
    site = insn.address
    sp = st.regs["rsp"]
    if sp.kind != STACK:
        ctx.assumptions.add("A2")
        st.tag_all("A2")
        if v.kind in FRAME:
            st.escape(v.v)
        ctx.fx(site, "push with unknown stack pointer offset (A2)")
        return
    off = sp.v - w
    st.regs["rsp"] = Val(STACK, off, sp.sites | {site})
    if v.kind in FRAME and w == ctx.fw:     # spilled frame address (an argument for a call: escapes at the call)
        kind = PTRB if v.kind == STACK else RPTRB
        bs = [Val(kind, (v.v << 4) | k, v.sites | {site}, EMPTY, v.srcs) for k in range(w)]
    elif v.kind in FRAME:
        st.escape(v.v)
        b = taint([v], f"frame address {fmt_val(v)} pushed at 0x{site:x}", {site})
        bs = [b] * w
    elif v.kind == CONST:
        bs = [Val(CONST, (v.v >> (8 * k)) & 0xFF, v.sites | {site}, EMPTY, v.srcs) for k in range(w)]
    else:
        bs = [taint([v], None, {site})] * w
    for k, b in enumerate(bs):
        st.put(off + k, b)
    ctx.fx(site, f"writes {fmt_off(off)} size={w} value={fmt_fx(v)}")


def _pop(st: State, d: OperandInfo, w: int, insn: InsnInfo, ctx: Ctx) -> None:
    site = insn.address
    sp = st.regs["rsp"]
    if sp.kind != STACK:
        v = unknown(f"pop with unknown stack pointer offset at 0x{site:x}")
    else:
        v = combine([st.byte_at(sp.v + k) for k in range(w)], ctx.fw)
    is_sp = d.kind == "reg" and REG.get(d.reg, ("",))[0] == "rsp"
    if sp.kind == STACK and not is_sp:
        st.regs["rsp"] = Val(STACK, sp.v + w, sp.sites | {site})
    put(st, d, w, v, insn, ctx)


def callee_name(insn: InsnInfo) -> str:
    if not insn.operands:
        return "?"
    o = insn.operands[0]
    if o.sym:
        return o.sym
    if o.kind == "near" and o.value is not None:
        return f"0x{o.value:x}"
    return o.text or "?"


UNKNOWN_ARGS_WINDOW = {64: 0x20 + 8 * 16, 32: 4 * 16}   # A3: at most 16 stack arguments


def _callee_stack_args(st: State, ctx: Ctx, site: int, name: str) -> None:
    """The callee owns its stack parameters (and, on x64, the 32-byte home space): it may write them. With the callee's
    parameter list known (engine prototype), exactly that area becomes non-definite; unknown -> a 16-argument window,
    and every frame byte above it survives only under A3 (tagged). A definite byte keeps its last value."""
    sp = st.regs["rsp"]
    if sp.kind != STACK:
        return            # x86 after an earlier call: the pushed arguments were never tracked (A2)
    known = ctx.call_args.get(site)
    if known is not None:
        area = max(int(known), 0x20 if ctx.bits == 64 else 0)
        if area:
            st.havoc_range(sp.v, sp.v + area, f"parameter area of call 0x{site:x} ({name}, 0x{area:x} bytes): "
                                              "the callee may write it", site)
        return
    area = UNKNOWN_ARGS_WINDOW[ctx.bits]
    st.havoc_range(sp.v, sp.v + area, f"parameter area of call 0x{site:x} ({name}): parameter list unknown, "
                                      f"0x{area:x} bytes assumed (A3)", site)
    ctx.assumptions.add("A3")
    st.tag_from(sp.v + area, "A3")


def _call(st: State, insn: InsnInfo, ctx: Ctx) -> None:
    site = insn.address
    name = callee_name(insn)
    for f in (ctx.families if ctx.bits == 64 else FAMILIES32):
        v = st.regs.get(f)
        if v is not None and v.kind in FRAME and f not in ("rsp", "rbp"):
            st.escape(v.v)
    for b in st.stack.values():   # a frame address spilled anywhere in the frame (pushed arguments included)
        if b.kind in PTR_BYTES:
            st.escape(b.v >> 4)
    if st.esc:
        ctx.assumptions.add("A1")
        st.havoc_from(min(st.esc), f"call 0x{site:x} ({name}) may write through an escaped frame address "
                                   f"from {fmt_off(min(st.esc))}", site)
    _callee_stack_args(st, ctx, site, name)
    vol = VOLATILE64 if ctx.bits == 64 else VOLATILE32
    for f in vol:
        why = (f"return value of call 0x{site:x} ({name}), callee not followed" if f == "rax"
               else f"{ctx.rname(f)} clobbered by call 0x{site:x} ({name})")
        st.regs[f] = unknown(why, {site})
    ctx.fx(site, f"writes {ctx.rname('rax')} value=unknown (return value); volatile registers clobbered")
    if ctx.bits != 64:
        sp = st.regs["rsp"]
        if sp.kind == STACK:
            st.regs["rsp"] = unknown(f"stack pointer after call 0x{site:x} ({name}): callee stack cleanup unknown",
                                     {site})
