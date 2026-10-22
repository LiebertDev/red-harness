"""Function-level comparison of two builds of the same program (the original and the vendor's fixed build).

Engine-independent: the only inputs are function boundaries and the decoded instructions every engine delivers in the
common `InsnInfo` / `OperandInfo` contract (engines/base.py). Nothing is decided by an engine's own matching or naming
feature, and nothing is run.

Per function three fingerprints are kept:
- `bytes_sha256`: SHA-256 of the instruction bytes exactly as they are in the file;
- `norm_sha256`: SHA-256 of the NORMALIZED instruction stream: mnemonic, registers, immediates, stack/frame offsets and
  scales stay; the addresses of calls, jumps outside the function, absolute/RIP-relative data references and table-base displacements are
  normalized away (only a symbol with a stable name is kept, see `stable_name`); a jump inside the function is kept as the
  number of its target instruction. So a function that merely MOVED (every address in the image shifted) has another
  `bytes_sha256` and the same `norm_sha256`;
- `mnem_sha256`: SHA-256 of the mnemonic sequence (the similarity signal for pairing).

Pairing (deterministic, in this order): (1) a stable, unique function name present in both builds; (2) equal
`norm_sha256`, taken in address order; (3) inside every gap between order-consistent anchors, unpaired functions by the
similarity of their mnemonic sequences (greedy, best ratio first, threshold below). A pair is `matched` when the
normalized stream is equal, `changed` otherwise; an unpaired function is `removed` (original only) or `added` (fixed only).
The pairing method and ratio are reported per pair, so a claim can say how a pair was found.

Limits (stated, not hidden): reads of DATA are compared only through the symbol name of the operand (an engine that names
a string after its content, as IDA does, sees a changed string; a bare address is normalized away); a function whose only
difference is a different callee or a different data constant behind a nameless address is `matched`. `matched` means
"same normalized instruction stream", never "same behavior".
"""

from __future__ import annotations

import bisect
import hashlib
import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Iterable, Sequence

from ..engines.base import FunctionBody, InsnInfo, OperandInfo

# Names that embed an address (IDA sub_/dword_/loc_..., Ghidra FUN_/DAT_/LAB_..., ...) differ between two builds; a name
# is "stable" only if it carries no run of 6 or more hex digits.
_ADDRESS_IN_NAME = re.compile(r"[0-9A-Fa-f]{6,}")
SIMILARITY_MIN = 0.5            # unpaired functions are paired by mnemonic similarity at or above this ratio ...
SIMILARITY_MIN_SOLE = 0.3       # ... or this ratio when each side has exactly one unpaired function in the gap
GAP_PAIR_LIMIT = 2500           # a gap with more candidate pairs than this is not similarity-paired (stays added/removed)
HUNK_INSN_LIMIT = 4000          # hunks are computed for functions up to this many instructions on each side
HUNKS_SHOWN = 5
MASK64 = 0xFFFFFFFFFFFFFFFF


def stable_name(name: str) -> bool:
    return bool(name) and not _ADDRESS_IN_NAME.search(name)


@dataclass(frozen=True)
class FuncPrint:
    address: int
    name: str
    size: int
    insn_count: int
    complete: bool                      # False: the engine returned a prefix of the function's instructions
    bytes_sha256: str
    norm_sha256: str
    mnem_sha256: str
    mnemonics: tuple[str, ...] = field(repr=False, default=())
    norms: tuple[str, ...] = field(repr=False, default=())
    addrs: tuple[int, ...] = field(repr=False, default=())
    texts: tuple[str, ...] = field(repr=False, default=())


def _sym(o: OperandInfo) -> str:
    return o.sym if stable_name(o.sym) else ""


def _displacement(o: OperandInfo) -> str:
    """A register-relative displacement is part of the code (stack and structure offsets), EXCEPT when it looks like an
    image address or RVA (a table base: an indexed form with 0x1000 or more, or any 0x10000 or more): that moves with
    the layout and is normalized away. Stated limit: a structure offset of 64 KiB or more is not compared."""
    d = o.disp or 0
    if abs(d) >= 0x10000 or (o.index and d >= 0x1000):
        return "+@"
    return f"{d:+#x}"


def _norm_operand(o: OperandInfo, index_of: dict[int, int]) -> str:
    if o.kind == "reg":
        return "r:" + o.reg
    if o.kind == "imm":
        if o.sym:   # an address-like immediate (offset of a symbol): only a stable symbol name is kept
            return "i:@" + _sym(o)
        return f"i:{(o.value or 0) & MASK64:#x}"
    if o.kind == "mem":
        if o.base or o.index:
            return f"m{o.size}:{o.base}+{o.index}*{o.scale}{_displacement(o)}"
        return f"m{o.size}:@" + _sym(o)
    if o.kind == "near":
        k = index_of.get(o.value) if o.value is not None else None
        if k is not None:   # a target inside the function: the number of the instruction, not its address
            return f"n:#{k}"
        return "n:@" + _sym(o)
    return "o"


def normalize_insn(i: InsnInfo, index_of: dict[int, int]) -> str:
    return i.mnemonic + " " + ",".join(_norm_operand(o, index_of) for o in i.operands)


def _line_text(s: str) -> str:
    return re.sub(r"[\x00-\x1f\x7f]+", " ", s)[:160]


def fingerprint(body: FunctionBody) -> FuncPrint:
    dis = body.disassembly
    items = sorted(dis.items, key=lambda i: i.address)
    index_of = {i.address: k for k, i in enumerate(items)}
    norms = tuple(normalize_insn(i, index_of) for i in items)
    mnems = tuple(i.mnemonic for i in items)
    raw = b"".join(bytes.fromhex(i.bytes_hex) for i in items)
    return FuncPrint(
        body.address, body.name, body.size, len(items), bool(dis.complete),
        hashlib.sha256(raw).hexdigest(), hashlib.sha256("\n".join(norms).encode("utf-8")).hexdigest(),
        hashlib.sha256("\n".join(mnems).encode("utf-8")).hexdigest(), mnems, norms,
        tuple(i.address for i in items), tuple(_line_text(i.text) for i in items))


# ------------------------------------------------------------------------------------------------ the diff

@dataclass(frozen=True)
class Hunk:
    tag: str                            # replace | delete | insert
    original: tuple[int, int, str]      # (address of the first instruction, instruction count, its text)
    fixed: tuple[int, int, str]


@dataclass(frozen=True)
class Pair:
    status: str                         # matched | changed | added | removed
    original: FuncPrint | None
    fixed: FuncPrint | None
    pairing: str = ""                   # name | hash | similarity ("" for added / removed)
    ratio: float | None = None          # mnemonic similarity of a similarity pair
    hunks: tuple[Hunk, ...] = ()
    insns_added: int = 0
    insns_removed: int = 0

    @property
    def bytes_identical(self) -> bool:
        return bool(self.original and self.fixed and self.original.bytes_sha256 == self.fixed.bytes_sha256)

    @property
    def moved(self) -> bool:
        return bool(self.original and self.fixed and self.original.address != self.fixed.address)


@dataclass(frozen=True)
class BuildDiff:
    pairs: tuple[Pair, ...]             # changed, added, removed, then matched (each group by address)
    counts: dict
    limitations: tuple[str, ...]


def _lis(seq: Sequence[int]) -> list[int]:
    """Indexes of one longest strictly increasing subsequence of `seq` (O(n log n))."""
    tails: list[int] = []        # indexes into seq
    prev = [-1] * len(seq)
    heads: list[int] = []        # values at the tails (for bisect)
    for i, v in enumerate(seq):
        k = bisect.bisect_left(heads, v)
        if k == len(heads):
            heads.append(v)
            tails.append(i)
        else:
            heads[k] = v
            tails[k] = i
        prev[i] = tails[k - 1] if k else -1
    out: list[int] = []
    i = tails[-1] if tails else -1
    while i != -1:
        out.append(i)
        i = prev[i]
    return out[::-1]


def _hunks(o: FuncPrint, f: FuncPrint) -> tuple[tuple[Hunk, ...], int, int]:
    if max(len(o.norms), len(f.norms)) > HUNK_INSN_LIMIT:
        return (), 0, 0
    sm = SequenceMatcher(None, o.norms, f.norms, autojunk=False)
    hunks: list[Hunk] = []
    added = removed = 0
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        removed += i2 - i1
        added += j2 - j1
        if len(hunks) < HUNKS_SHOWN:
            # an insertion has no instruction on the other side: its address is the one it would sit before (the last
            # instruction when it is appended)
            hunks.append(Hunk(tag,
                              (o.addrs[min(i1, len(o.addrs) - 1)] if o.addrs else 0, i2 - i1, o.texts[i1] if i1 < i2 else ""),
                              (f.addrs[min(j1, len(f.addrs) - 1)] if f.addrs else 0, j2 - j1, f.texts[j1] if j1 < j2 else "")))
    return tuple(hunks), added, removed


def _pair(o: FuncPrint, f: FuncPrint, pairing: str, ratio: float | None = None) -> Pair:
    if o.norm_sha256 == f.norm_sha256:   # a truncated fingerprint (prefix only) is flagged on the row and counted
        return Pair("matched", o, f, pairing, ratio)
    hunks, added, removed = _hunks(o, f)
    return Pair("changed", o, f, pairing, ratio, hunks, added, removed)


def diff_builds(original: Iterable[FuncPrint], fixed: Iterable[FuncPrint]) -> BuildDiff:
    orig = sorted(original, key=lambda p: p.address)
    fix = sorted(fixed, key=lambda p: p.address)
    limits: list[str] = []
    used_o: set[int] = set()
    used_f: set[int] = set()
    pairs: list[tuple[int, int, str, float | None]] = []   # (orig index, fixed index, pairing, ratio)

    # (1) a stable name that occurs exactly once in each build
    by_name_o: dict[str, list[int]] = {}
    by_name_f: dict[str, list[int]] = {}
    for idx, p in enumerate(orig):
        if stable_name(p.name):
            by_name_o.setdefault(p.name, []).append(idx)
    for idx, p in enumerate(fix):
        if stable_name(p.name):
            by_name_f.setdefault(p.name, []).append(idx)
    for name, oi in by_name_o.items():
        fi = by_name_f.get(name)
        if fi and len(oi) == 1 and len(fi) == 1:
            pairs.append((oi[0], fi[0], "name", None))
            used_o.add(oi[0])
            used_f.add(fi[0])

    # (2) equal normalized stream, in address order
    by_hash_o: dict[str, list[int]] = {}
    by_hash_f: dict[str, list[int]] = {}
    for idx, p in enumerate(orig):
        if idx not in used_o:
            by_hash_o.setdefault(p.norm_sha256, []).append(idx)
    for idx, p in enumerate(fix):
        if idx not in used_f:
            by_hash_f.setdefault(p.norm_sha256, []).append(idx)
    for h, oi in by_hash_o.items():
        for a, b in zip(oi, by_hash_f.get(h, [])):
            pairs.append((a, b, "hash", None))
            used_o.add(a)
            used_f.add(b)

    # (3) similarity inside the gaps between order-consistent anchors
    pairs.sort()
    keep = _lis([fi for _, fi, _, _ in pairs])
    anchors = [(pairs[k][0], pairs[k][1]) for k in keep]
    bounds = [(-1, -1)] + anchors + [(len(orig), len(fix))]
    for (o_lo, f_lo), (o_hi, f_hi) in zip(bounds, bounds[1:]):
        go = [i for i in range(o_lo + 1, o_hi) if i not in used_o]
        gf = [j for j in range(f_lo + 1, f_hi) if j not in used_f]
        if not go or not gf:
            continue
        if len(go) * len(gf) > GAP_PAIR_LIMIT:
            limits.append(f"gap after original 0x{orig[o_lo].address:x}: {len(go)} original and {len(gf)} fixed unpaired "
                          "functions, too many to pair by similarity; reported as removed / added"
                          if o_lo >= 0 else
                          f"first gap: {len(go)} original and {len(gf)} fixed unpaired functions, too many to pair by "
                          "similarity; reported as removed / added")
            continue
        cands = []
        for i in go:
            for j in gf:
                r = SequenceMatcher(None, orig[i].mnemonics, fix[j].mnemonics, autojunk=False).ratio()
                cands.append((-r, abs((i - o_lo) - (j - f_lo)), i, j))
        cands.sort()
        floor = SIMILARITY_MIN_SOLE if len(go) == 1 and len(gf) == 1 else SIMILARITY_MIN
        for nr, _, i, j in cands:
            if -nr < floor:
                break
            if i in used_o or j in used_f:
                continue
            pairs.append((i, j, "similarity", round(-nr, 3)))
            used_o.add(i)
            used_f.add(j)

    rows = [_pair(orig[i], fix[j], how, ratio) for i, j, how, ratio in pairs]
    rows += [Pair("removed", p, None) for i, p in enumerate(orig) if i not in used_o]
    rows += [Pair("added", None, p) for j, p in enumerate(fix) if j not in used_f]
    order = {"changed": 0, "added": 1, "removed": 2, "matched": 3}
    rows.sort(key=lambda r: (order[r.status], (r.original or r.fixed).address, (r.fixed or r.original).address))
    counts = {s: sum(1 for r in rows if r.status == s) for s in order}
    counts["moved"] = sum(1 for r in rows if r.status in ("matched", "changed") and r.moved)
    counts["original_functions"] = len(orig)
    counts["fixed_functions"] = len(fix)
    counts["truncated_functions"] = sum(1 for p in (*orig, *fix) if not p.complete)
    if counts["truncated_functions"]:
        limits.append(f"{counts['truncated_functions']} function(s) were cut at the engine's per-function instruction cap: "
                      "their fingerprints cover a prefix only")
    return BuildDiff(tuple(rows), counts, tuple(limits))


# ------------------------------------------------------------------------------------------------ text form

def _h(p: FuncPrint | None, which: str) -> str:
    return getattr(p, which)[:16] if p else "-"


def pair_lines(pair: Pair) -> str:
    """One row (+ hunk lines) of the comparison text. Names and instruction texts come from the target: control
    characters are replaced, they stay untrusted data."""
    o, f = pair.original, pair.fixed
    name = _line_text((o or f).name)
    if pair.status == "removed":
        return (f"removed original=0x{o.address:x} name={name} size=0x{o.size:x} insns={o.insn_count} "
                f"bytes_sha256={_h(o, 'bytes_sha256')} norm_sha256={_h(o, 'norm_sha256')}"
                + ("" if o.complete else " truncated=yes") + "\n")
    if pair.status == "added":
        return (f"added fixed=0x{f.address:x} name={name} size=0x{f.size:x} insns={f.insn_count} "
                f"bytes_sha256={_h(f, 'bytes_sha256')} norm_sha256={_h(f, 'norm_sha256')}"
                + ("" if f.complete else " truncated=yes") + "\n")
    line = (f"{pair.status} original=0x{o.address:x} fixed=0x{f.address:x} name={name} "
            f"size=0x{o.size:x}->0x{f.size:x} insns={o.insn_count}->{f.insn_count} "
            f"bytes_sha256={_h(o, 'bytes_sha256')}->{_h(f, 'bytes_sha256')} "
            f"norm_sha256={_h(o, 'norm_sha256')}->{_h(f, 'norm_sha256')} "
            f"moved={'yes' if pair.moved else 'no'} bytes_identical={'yes' if pair.bytes_identical else 'no'} "
            f"pairing={pair.pairing}" + (f" ratio={pair.ratio}" if pair.ratio is not None else "")
            + ("" if o.complete and f.complete else " truncated=yes"))
    if pair.status == "changed":
        line += f" insns_added={pair.insns_added} insns_removed={pair.insns_removed}"
    out = [line + "\n"]
    for h in pair.hunks:
        out.append(f"  hunk {h.tag} original=0x{h.original[0]:x} ({h.original[1]} insns) fixed=0x{h.fixed[0]:x} "
                   f"({h.fixed[1]} insns): original `{h.original[2]}` | fixed `{h.fixed[2]}`\n")
    return "".join(out)
