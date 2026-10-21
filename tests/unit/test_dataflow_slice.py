"""Data-flow slicer (analysis/dataflow): synthetic instruction streams in the common engine contract, known answers.

Each program is written once with IDA-style operand text and once with Ghidra-style text (memory operands without a size
field, width only in the `byte ptr` keyword), so the slicer is shown to use the structural fields, not the text.
"""
from __future__ import annotations

import re

import pytest

from redharness.analysis.dataflow import PeImageView, SliceError, slice_function
from redharness.analysis.dataflow.x86 import REG
from redharness.analysis.pe_image import parse_pe
from redharness.engines.base import Disassembly, InsnInfo, OperandInfo
from tests.unit._pe_builder import build_pe

_W = {1: "byte", 2: "word", 4: "dword", 8: "qword", 16: "xmmword"}


# ---------------------------------------------------------------- program builder
def R(name):
    return OperandInfo("reg", name, reg=name, size=REG[name][2] if name in REG else 16)


def I(v, size=4):
    return OperandInfo("imm", hex(v), value=v & 0xFFFFFFFFFFFFFFFF, size=size)


def N(t):
    return OperandInfo("near", f"loc_{t:x}", value=t)


class M:
    """Memory operand spec, rendered per dialect."""

    def __init__(self, base="", disp=0, index="", scale=0, width=0, value=None, sym=""):
        self.base, self.disp, self.index, self.scale, self.width, self.value, self.sym = \
            base, disp, index, scale, width, value, sym

    def op(self, dialect):
        if dialect == "ida":
            inner = self.base
            if self.index:
                inner += f"+{self.index}" + (f"*{self.scale}" if self.scale > 1 else "")
            if self.disp:
                inner += f"{'+' if self.disp > 0 else '-'}{abs(self.disp):X}h"
            if not inner and self.value is not None:
                inner = f"{self.value:X}h"
            text = (f"{_W[self.width]} ptr " if self.width else "") + f"[{inner}]"
            return OperandInfo("mem", text, base=self.base, index=self.index, scale=self.scale,
                               disp=self.disp if (self.base or self.index) else None, value=self.value,
                               size=self.width, sym=self.sym)
        parts = [x.upper() for x in (self.base,) if x]
        if self.index:
            parts.append(f"{self.index.upper()}*0x{self.scale or 1:x}")
        if self.disp:
            parts.append(f"{self.disp:#x}" if self.disp > 0 else f"-{abs(self.disp):#x}")
        if not parts and self.value is not None:
            parts.append(f"{self.value:#x}")
        text = (f"{_W[self.width]} ptr " if self.width else "") + "[" + " + ".join(parts) + "]"
        return OperandInfo("mem", text, base=self.base, index=self.index, scale=self.scale if self.index else 0,
                           disp=self.disp if (self.base or self.index) else None, value=self.value, size=0,
                           sym=self.sym)


def prog(rows, dialect="ida", name="f", complete=True, function=None):
    """rows: (address, mnemonic, operands...). Sizes come from the next row's address (last: 1)."""
    rows = sorted(rows, key=lambda r: r[0])
    out = []
    for k, row in enumerate(rows):
        a, m, *ops = row
        size = (rows[k + 1][0] - a) if k + 1 < len(rows) else 1
        ops2 = tuple(o.op(dialect) if isinstance(o, M) else o for o in ops)
        text = m + (" " + ", ".join(o.text for o in ops2) if ops2 else "")
        out.append(InsnInfo(a, size, "90" * size, m, ops2, text))
    return Disassembly(out, function if function is not None else rows[0][0], name, len(out), complete,
                       "" if complete else "COUNT: truncated")


def run(rows, target, bits=32, dialect="ida", image=None, **kw):
    complete = kw.pop("complete", True)
    return slice_function(prog(rows, dialect, complete=complete), bits=bits, target=target, image=image, **kw)


def image32():
    raw = build_pe(is64=False)
    img = parse_pe(lambda off, n: raw[off:off + n], len(raw))
    return PeImageView(img, lambda off, n: raw[off:off + n])


DIALECTS = ("ida", "ghidra")

# x86 ebp frame: ebp = sp0-4, so [ebp-0x20] = sp0-0x24
STACK_STRING = [
    (0x401000, "push", R("ebp")),
    (0x401001, "mov", R("ebp"), R("esp")),
    (0x401003, "sub", R("esp"), I(0x40, 1)),
    (0x401006, "mov", M("ebp", -0x20, width=1), I(0x41, 1)),
    (0x40100A, "mov", R("eax"), I(0x1234)),                       # junk
    (0x40100F, "mov", M("ebp", -0x1F, width=1), I(0x42, 1)),
    (0x401013, "xchg", R("eax"), R("eax")),                       # junk
    (0x401014, "mov", M("ebp", -0x1E, width=4), I(0x46454443)),
    (0x40101B, "mov", M("ebp", -0x1A, width=1), I(0, 1)),
    (0x40101F, "xor", R("ecx"), R("ecx")),
    (0x401021, "mov", R("al"), M("esi", 0, index="ecx", scale=1, width=1)),
    (0x401024, "cmp", R("al"), M("ebp", -0x20, index="ecx", scale=1, width=1)),
    (0x401028, "jnz", N(0x401031)),
    (0x40102A, "inc", R("ecx")),
    (0x40102B, "cmp", R("ecx"), I(6, 1)),
    (0x40102E, "jl", N(0x401021)),
    (0x401030, "ret"),
    (0x401031, "ret"),
]


# ---------------------------------------------------------------- 1. stack string, junk interleaved
@pytest.mark.parametrize("dialect", DIALECTS)
def test_stack_string_reconstructed_per_byte(dialect):
    r = run(STACK_STRING, 0x401024, dialect=dialect)
    t = r.text
    assert 'run +0x0..+0x6 len=7 ascii="ABCDEF" nul_terminated=yes' in t
    assert "+0x0 definite src=0x401006" in t
    assert "+0x1 definite src=0x40100f" in t
    assert "+0x2..+0x5 definite src=0x401014" in t
    assert "+0x6 definite src=0x40101b" in t
    assert "frame buffer from sp0-0x24 (index not constant)" in t
    # junk writes are not part of the slice
    assert "0x40100a |" not in t and "0x401013 |" not in t
    # the other compared value: memory through the unknown argument pointer esi
    assert "load through an unknown pointer" in t or "value of esi at function entry" in t
    assert r.complete, r.reasons
    assert 0x401006 in r.addresses and 0x401024 in r.addresses


def test_dialects_agree_structurally():
    a = run(STACK_STRING, 0x401024, dialect="ida")
    b = run(STACK_STRING, 0x401024, dialect="ghidra")
    strip = lambda t: [ln for ln in t.splitlines() if ln.startswith(("  +", "  run", "  bytes", "defs:", "coverage"))]
    assert strip(a.text) == strip(b.text)
    assert a.summary == b.summary


# ---------------------------------------------------------------- 2. overlap
@pytest.mark.parametrize("dialect", DIALECTS)
def test_overlapping_writes_effective_bytes(dialect):
    rows = [(0x401000, "push", R("ebp")), (0x401001, "mov", R("ebp"), R("esp")),
            (0x401003, "mov", M("ebp", -0x10, width=4), I(0x64636261)),
            (0x40100A, "mov", M("ebp", -0x0E, width=1), I(0x58, 1)),
            (0x40100E, "lea", R("eax"), M("ebp", -0x10)),
            (0x401011, "cmp", R("ecx"), R("eax")),
            (0x401013, "ret")]
    r = run(rows, 0x401013, dialect=dialect, location="[ebp-0x10]", size=4)
    assert 'ascii="abXd"' in r.text
    assert "+0x0..+0x1 definite src=0x401003" in r.text
    assert "+0x2 definite src=0x401003,0x40100a" in r.text or "+0x2 definite src=0x40100a" in r.text


# ---------------------------------------------------------------- 3. constant through moves
@pytest.mark.parametrize("dialect", DIALECTS)
def test_constant_folded_through_moves(dialect):
    rows = [(0x401000, "mov", R("eax"), I(0x10)), (0x401005, "shl", R("eax"), I(4, 1)),
            (0x401008, "lea", R("ecx"), M("eax", 5)), (0x40100B, "mov", R("edx"), I(3)),
            (0x401010, "add", R("ecx"), R("edx")), (0x401012, "mov", R("ebx"), I(7)),
            (0x401017, "cmp", R("ecx"), R("ebx")), (0x401019, "ret")]
    r = run(rows, 0x401017, dialect=dialect, operand=0)
    assert "value=0x108 definite" in r.text
    for a in (0x401000, 0x401005, 0x401008, 0x40100B, 0x401010):
        assert f"0x{a:x} |" in r.text
    assert "0x401012 |" not in r.text
    assert "0x401008 | lea ecx" in r.text and "writes ecx value=0x105" in r.text


# ---------------------------------------------------------------- 4. image constants
@pytest.mark.parametrize("dialect", DIALECTS)
def test_rdata_load_through_pointer_arithmetic(dialect):
    rows = [(0x401000, "mov", R("esi"), I(0x402000)),
            (0x401005, "mov", R("eax"), M("esi", 0x40, width=4)),
            (0x401008, "mov", R("ecx"), M("esi", 4, width=4)),
            (0x40100B, "cmp", R("eax"), R("ecx")), (0x40100D, "ret")]
    r = run(rows, 0x40100B, dialect=dialect, image=image32())
    assert "value=0x6c6c6568 definite" in r.text            # "hell"
    assert "value=0x401020 definite" in r.text              # second table pointer
    assert "image 0x402040 size=4 section=.rdata R-- value=0x6c6c6568" in r.text
    assert "0x401000 | mov esi" in r.text                   # the pointer chain is part of the slice
    assert (0x402040, 4) in r.image_ranges


def test_writable_uninitialised_and_outside_image_are_unknown():
    rows = [(0x401000, "mov", R("eax"), M(width=4, value=0x403000)),
            (0x401006, "mov", R("ebx"), M(width=4, value=0x404000)),
            (0x40100C, "mov", R("ecx"), M(width=4, value=0x900000)),
            (0x401012, "cmp", R("eax"), R("ebx")), (0x401014, "cmp", R("ecx"), I(0)), (0x401016, "ret")]
    img = image32()
    r = run(rows, 0x401012, image=img)
    assert "writable section .data RW-" in r.text
    assert "note=initial file value only, section is writable" in r.text
    assert "not file-backed" in r.text
    assert "value=0x" not in r.text.split("defs:")[0]
    r2 = run(rows, 0x401014, image=img, operand=0)
    assert "outside the image" in r2.text


def test_import_address_slot_is_not_a_value():
    raw = build_pe(is64=False)
    img = PeImageView(parse_pe(lambda off, n: raw[off:off + n], len(raw)), lambda off, n: raw[off:off + n],
                      {0x402004: "kernel32.dll!GetTickCount"})
    rows = [(0x401000, "mov", R("eax"), M(width=4, value=0x402004)), (0x401006, "cmp", R("eax"), I(0, 1)),
            (0x401009, "ret")]
    r = run(rows, 0x401006, image=img, operand=0)
    assert "value=unknown" in r.text and "import address slot 0x402004 (kernel32.dll!GetTickCount)" in r.text


# ---------------------------------------------------------------- 5. call result
def test_call_result_is_explicit_unknown():
    call = OperandInfo("mem", "ds:GetTickCount", value=0x402010, sym="GetTickCount")
    rows = [(0x401000, "push", R("ebp")), (0x401001, "mov", R("ebp"), R("esp")),
            (0x401003, "call", call), (0x401009, "mov", M("ebp", -4, width=4), R("eax")),
            (0x40100C, "mov", R("ecx"), M("ebp", -4, width=4)), (0x40100F, "cmp", R("ecx"), I(5, 1)),
            (0x401012, "ret")]
    r = run(rows, 0x40100F, operand=0)
    assert "return value of call 0x401003 (GetTickCount), callee not followed" in r.text
    assert "0x401009 |" in r.text and "0x40100c |" in r.text


# ---------------------------------------------------------------- 6. escape to a call
def test_buffer_escaping_to_call_becomes_unknown_above_escape_point():
    rows = [(0x401000, "push", R("ebp")), (0x401001, "mov", R("ebp"), R("esp")),
            (0x401003, "mov", M("ebp", -0x30, width=4), I(0x44434241)),   # below the escaped buffer: kept (A1)
            (0x40100A, "mov", M("ebp", -0x20, width=4), I(0x48474645)),   # inside: unknown after the call
            (0x401011, "lea", R("eax"), M("ebp", -0x20)),
            (0x401014, "push", R("eax")),
            (0x401015, "call", N(0x402000)),
            (0x40101A, "cmp", R("ecx"), R("edx")), (0x40101C, "ret")]
    r = run(rows, 0x40101A, location="[ebp-0x30]", size=4)
    assert 'ascii="ABCD" assumes=A1' in r.text                 # kept only because of A1: marked, never unconditional
    assert "+0x0..+0x3 definite src=0x401003 assumes=A1" in r.text
    assert "A1:" in r.text and r.summary["assumptions"] == ["A1"]
    assert r.summary["buffers"][0]["assumes"] == ["A1"]
    r2 = run(rows, 0x40101A, location="[ebp-0x20]", size=4)
    assert "definite=0" in r2.text
    assert "may write through an escaped frame address" in r2.text
    assert "writes=0x40100a" in r2.text                       # the clobbered write stays as provenance
    assert "A1:" not in r2.text                               # printed only when it influenced a reported value
    # the last definite write of each clobbered byte is shown, never as a definite value
    assert "+0x0 unknown last=0x45" in r2.text
    assert 'candidate +0x0..+0x3 len=4 ascii="EFGH" NOT definite' in r2.text
    assert "run +0x0" not in r2.text and r2.summary["buffers"][0]["candidate_runs"] == [[0, 4]]


DEAD_INTO_JOIN = [(0x401000, "push", R("ebp")), (0x401001, "mov", R("ebp"), R("esp")),
                  (0x401003, "mov", M("ebp", -8, width=1), I(0x41, 1)), (0x401007, "jmp", N(0x401010)),
                  (0x401009, "mov", M("ebp", -8, width=1), I(0x42, 1)),      # no edge into it (handler?)
                  (0x40100D, "jmp", N(0x401010)),                            # ...but it flows into 0x401010
                  (0x401010, "mov", R("al"), M("ebp", -8, width=1)), (0x401013, "cmp", R("al"), I(0x41, 1)),
                  (0x401015, "mov", M("ebp", -12, width=1), I(0x43, 1)),     # written after the join
                  (0x401019, "cmp", R("eax"), R("ebx")), (0x40101B, "ret")]


def test_block_without_predecessor_is_not_entered_but_taints_where_it_flows_in():
    # its own writes are not merged (ebp stays a frame address), but nothing arriving at 0x401010 is definite any more
    r = run(DEAD_INTO_JOIN, 0x401013, operand=0)
    assert "value=0x41 definite" not in r.text and "value=unknown" in r.text
    assert not r.complete and "block without a known predecessor not analysed" in r.text
    assert "not-analysed block 0x401009 flows into 0x401010" in r.text
    rb = run(DEAD_INTO_JOIN, 0x401019, location="[ebp-8]", size=1)
    assert "+0x0 unknown last=0x41" in rb.text                    # the frame address survived; the byte is a candidate
    ra = run(DEAD_INTO_JOIN, 0x401019, location="[ebp-12]", size=1)
    assert "+0x0 definite src=0x401015" in ra.text                # written after the join: definite again
    r2 = run(DEAD_INTO_JOIN, 0x40100D, location="[ebp-8]", size=1)   # a query inside the dead block: nothing known
    assert "not reachable from the function entry" in r2.text and "value=unknown" in r2.text


def test_dead_block_that_flows_nowhere_does_not_taint():
    rows = [(0x401000, "push", R("ebp")), (0x401001, "mov", R("ebp"), R("esp")),
            (0x401003, "mov", M("ebp", -8, width=1), I(0x41, 1)), (0x401007, "jmp", N(0x401010)),
            (0x401009, "mov", M("ebp", -8, width=1), I(0x42, 1)), (0x40100D, "ret"),   # dead, ends in ret
            (0x401010, "mov", R("al"), M("ebp", -8, width=1)), (0x401013, "cmp", R("al"), I(0x41, 1)),
            (0x401015, "ret")]
    r = run(rows, 0x401013, operand=0)
    assert "value=0x41 definite" in r.text and "flows into" not in r.text


def test_x64_call_home_space_is_not_definite_after_the_call():
    rows = [(0x140001000, "sub", R("rsp"), I(0x28, 1)),
            (0x140001004, "mov", M("rsp", 8, width=8), I(1, 4)),
            (0x14000100D, "call", N(0x140002000)),
            (0x140001012, "cmp", M("rsp", 8, width=8), I(1, 1)),
            (0x140001018, "ret")]
    r = run(rows, 0x140001012, bits=64, operand=0)
    assert "definite=0" in r.text and "parameter area of call 0x14000100d" in r.text
    assert 'candidate' not in r.text or "NOT definite" in r.text
    assert "unknown last=0x01" in r.text                          # the last write stays visible as a candidate
    before = run(rows, 0x14000100D, bits=64, location="[rsp+0x8]", size=8)
    assert "definite=8" in before.text


def test_assumption_marker_follows_value_into_registers():
    rows = [(0x401000, "push", R("ebp")), (0x401001, "mov", R("ebp"), R("esp")),
            (0x401003, "mov", M("ebp", -0x30, width=4), I(0x44434241)),
            (0x40100A, "lea", R("eax"), M("ebp", -0x20)), (0x40100D, "push", R("eax")),
            (0x40100E, "call", N(0x402000)),
            (0x401013, "mov", R("ecx"), M("ebp", -0x30, width=4)), (0x401016, "add", R("ecx"), I(1, 1)),
            (0x401019, "cmp", R("ecx"), R("edx")), (0x40101B, "ret")]
    r = run(rows, 0x401019, operand=0)
    assert "value=0x44434242 definite assumes=A1" in r.text
    clean = [x for x in rows if x[0] not in (0x40100D, 0x40100E)]
    assert "value=0x44434242 definite\n" in run(clean, 0x401019, operand=0).text


# ---------------------------------------------------------------- 7. joins
def _diamond(v1, v2):
    return [(0x401000, "push", R("ebp")), (0x401001, "mov", R("ebp"), R("esp")),
            (0x401003, "test", R("ecx"), R("ecx")), (0x401005, "jz", N(0x40100F)),
            (0x401007, "mov", M("ebp", -8, width=1), I(v1, 1)), (0x40100B, "jmp", N(0x401013)),
            (0x40100F, "mov", M("ebp", -8, width=1), I(v2, 1)),
            (0x401013, "mov", R("al"), M("ebp", -8, width=1)), (0x401016, "cmp", R("al"), I(0x41, 1)),
            (0x401018, "ret")]


def test_join_different_values_is_unknown_with_both_sites():
    r = run(_diamond(0x41, 0x42), 0x401016, operand=0)
    assert "different values on different paths" in r.text
    assert "0x401007 |" in r.text and "0x40100f |" in r.text
    assert "value=unknown" in r.text


def test_join_same_value_from_different_writes_is_definite():
    r = run(_diamond(0x41, 0x41), 0x401016, operand=0)
    assert "value=0x41 definite" in r.text
    assert "0x401007 |" in r.text and "0x40100f |" in r.text


def test_written_on_one_path_only_is_unknown():
    rows = _diamond(0x41, 0x41)
    rows = [r for r in rows if r[0] != 0x40100F] + [(0x40100F, "nop")]
    r = run(rows, 0x401016, operand=0)
    assert "not written on every path" in r.text


# ---------------------------------------------------------------- 8. loop-varying store index
def test_loop_store_with_unknown_index_havocs_from_base():
    rows = [(0x401000, "push", R("ebp")), (0x401001, "mov", R("ebp"), R("esp")),
            (0x401003, "mov", M("ebp", -0x40, width=1), I(0x5A, 1)),
            (0x401007, "mov", M("ebp", -0x20, width=1), I(0x41, 1)),
            (0x40100B, "mov", M("ebp", -0x20, index="ecx", scale=1, width=1), R("al")),
            (0x40100F, "cmp", R("eax"), R("ebx")), (0x401011, "ret")]
    r = run(rows, 0x40100F, location="[ebp-0x20]", size=1)
    assert "definite=0" in r.text and "store with unknown index at 0x40100b" in r.text
    r2 = run(rows, 0x40100F, location="[ebp-0x40]", size=1)
    assert "definite=1" in r2.text


# ---------------------------------------------------------------- 9/10. stack pointer
def test_x86_call_makes_esp_unknown_but_ebp_slots_survive():
    rows = [(0x401000, "push", R("ebp")), (0x401001, "mov", R("ebp"), R("esp")),
            (0x401003, "sub", R("esp"), I(0x20, 1)),
            (0x401006, "mov", M("ebp", -8, width=4), I(0x31323334)),
            (0x40100D, "push", I(1, 1)), (0x40100F, "call", N(0x402000)),
            (0x401014, "push", I(2, 1)),                             # esp unknown: A2
            (0x401016, "mov", R("eax"), M("esp", 4, width=4)),
            (0x40101A, "cmp", R("eax"), M("ebp", -8, width=4)), (0x40101D, "ret")]
    r = run(rows, 0x40101A, call_args={0x40100F: 4})        # the callee's parameter list is known: 4 bytes
    assert "+0x0..+0x3 definite src=0x401006 assumes=A2" in r.text   # survived a push through an unknown esp
    assert "callee stack cleanup unknown" in r.text
    assert "A2:" in r.text
    # parameter list unknown: the 0x40-byte window above esp covers [ebp-8] -> only a candidate
    ru = run(rows, 0x40101A)
    assert "+0x0 unknown last=0x34" in ru.text and "parameter list unknown" in ru.text


def test_stack_alignment_makes_esp_slots_unknown():
    rows = [(0x401000, "push", R("ebp")), (0x401001, "mov", R("ebp"), R("esp")),
            (0x401003, "and", R("esp"), I(-16 & 0xFFFFFFFF, 1)),
            (0x401006, "mov", M("esp", 8, width=4), I(7)),
            (0x40100E, "mov", M("ebp", -4, width=4), I(9)),
            (0x401015, "mov", R("eax"), M("esp", 8, width=4)),
            (0x401019, "cmp", R("eax"), M("ebp", -4, width=4)), (0x40101C, "ret")]
    r = run(rows, 0x401019)
    assert "stack pointer aligned at 0x401003" in r.text
    assert "+0x0..+0x3 definite src=0x40100e" in r.text


def test_x64_frame_survives_call_without_escape():
    rows = [(0x140001000, "sub", R("rsp"), I(0x38, 1)),
            (0x140001004, "mov", M("rsp", 0x20, width=4), I(0x64636261)),
            (0x14000100C, "mov", M("rsp", 0x24, width=4), I(0x68676665)),
            (0x140001014, "mov", M("rsp", 0x28, width=1), I(0x69, 1)),
            (0x140001019, "call", N(0x140002000)),
            (0x14000101E, "lea", R("rcx"), M("rsp", 0x20)),
            (0x140001023, "call", N(0x140003000)),
            (0x140001028, "ret")]
    known = {0x140001019: 0, 0x140001023: 8}     # engine prototypes: no stack parameters
    r = run(rows, 0x14000101E, bits=64, location="[rsp+0x20]", size=9, call_args=known)
    assert 'run +0x0..+0x8 len=9 hex=616263646566676869 ascii="abcdefghi"' in r.text
    # parameter list unknown: the bytes at rsp+0x20 are in the A3 window (home space + 16 stack arguments)
    ru = run(rows, 0x14000101E, bits=64, location="[rsp+0x20]", size=9)
    assert "definite=0" in ru.text and 'candidate +0x0..+0x8 len=9 hex=616263646566676869' in ru.text
    r2 = run(rows, 0x140001028, bits=64, location="sp0-0x18", size=9, call_args=known)
    assert "definite=0" in r2.text                     # escaped to the second call


# ---------------------------------------------------------------- 11. widths
def test_x64_width_semantics():
    rows = [(0x140001000, "mov", R("rax"), I(-1, 8)),
            (0x14000100A, "mov", R("eax"), I(5)),                    # zero-extends
            (0x14000100F, "mov", R("rbx"), I(0x1122334455667788, 8)),
            (0x140001019, "mov", R("bl"), I(0x99, 1)),               # keeps the rest
            (0x14000101B, "mov", R("cx"), I(0xFF80, 2)),
            (0x14000101F, "movsx", R("edx"), R("cl")),
            (0x140001022, "movzx", R("esi"), R("cl")),
            (0x140001025, "mov", R("r8d"), I(0x80000000)),
            (0x14000102B, "mov", R("eax"), R("r8d")),
            (0x14000102E, "cdqe"),
            (0x140001030, "cmp", R("rax"), R("rbx")), (0x140001033, "cmp", R("edx"), R("esi")),
            (0x140001035, "ret")]
    r = run(rows, 0x140001030, bits=64)
    assert "value=0xffffffff80000000 definite" in r.text
    assert "value=0x1122334455667799 definite" in r.text
    r2 = run(rows, 0x140001033, bits=64)
    assert "value=0xffffff80 definite" in r2.text and "value=0x80 definite" in r2.text
    r3 = run(rows[:2] + [(0x14000100F, "cmp", R("rax"), I(0)), (0x140001011, "ret")], 0x14000100F, bits=64,
             operand=0)
    assert "value=0x5 definite" in r3.text


# ---------------------------------------------------------------- 12. not interpreted
@pytest.mark.parametrize("mnem,ops,expect", [
    ("cmovz", (R("eax"), R("ebx")), "unmodelled cmovz"),
    ("setnz", (R("al"),), "unmodelled setnz"),
    ("adc", (R("eax"), I(1, 1)), "unmodelled adc"),
    ("sbb", (R("eax"), R("eax")), "unmodelled sbb"),
    ("movd", (R("eax"), R("xmm0")), "unmodelled SIMD instruction movd"),
    ("mul", (R("ecx"),), "unmodelled mul"),
])
def test_unmodelled_instructions_give_unknown(mnem, ops, expect):
    rows = [(0x401000, "mov", R("eax"), I(1)), (0x401005, mnem, *ops),
            (0x401008, "cmp", R("eax"), I(1, 1)), (0x40100B, "ret")]
    r = run(rows, 0x401008, operand=0)
    assert expect in r.text and "value=unknown" in r.text


def test_rep_stos_and_sse_store_into_frame_are_unknown():
    rows = [(0x401000, "push", R("ebp")), (0x401001, "mov", R("ebp"), R("esp")),
            (0x401003, "mov", M("ebp", -0x20, width=4), I(0x41414141)),
            (0x40100A, "lea", R("edi"), M("ebp", -0x20)),
            (0x40100D, "stosd.rep" , ),
            (0x40100F, "movups", M("ebp", -0x40, width=16), R("xmm0")),
            (0x401013, "cmp", R("eax"), R("ebx")), (0x401015, "ret")]
    r = run(rows, 0x401013, location="[ebp-0x20]", size=4)
    assert "definite=0" in r.text and "unmodelled string instruction stosd at 0x40100d" in r.text
    r2 = run(rows, 0x401013, location="[ebp-0x40]", size=16)
    assert "definite=0" in r2.text


def test_unknown_mnemonic_havocs_registers_and_marks_partial():
    rows = [(0x401000, "mov", R("eax"), I(1)), (0x401005, "frobnicate"),
            (0x401008, "cmp", R("eax"), I(1, 1)), (0x40100B, "ret")]
    r = run(rows, 0x401008, operand=0)
    assert "instruction with unknown effects frobnicate" in r.text
    assert not r.complete and "coverage: partial" in r.text


# ---------------------------------------------------------------- CFG taint
def test_indirect_jump_edges_to_every_block():
    # 0x401010 is reached by the jz (eax=1) and, through the over-approximated indirect edge, with eax=2
    rows = [(0x401000, "mov", R("eax"), I(1)), (0x401005, "test", R("ecx"), R("ecx")),
            (0x401007, "jz", N(0x401010)), (0x401009, "mov", R("eax"), I(2)), (0x40100E, "jmp", R("ecx")),
            (0x401010, "cmp", R("eax"), I(1, 1)), (0x401013, "ret")]
    r = run(rows, 0x401010, operand=0)
    assert "value=0x1 definite" not in r.text and "different values on different paths" in r.text
    assert "indirect jump at 0x40100e" in r.text and not r.complete
    # without the indirect jump the same point is definite
    rows2 = [x if x[0] != 0x40100E else (0x40100E, "ret") for x in rows]
    rows2 = [x if x[0] != 0x401009 else (0x401009, "mov", R("ebx"), I(2)) for x in rows2]
    assert "value=0x1 definite" in run(rows2, 0x401010, operand=0).text


def test_truncated_disassembly_is_partial():
    r = run(STACK_STRING, 0x401024, complete=False)
    assert not r.complete and "function disassembly incomplete" in r.text


# ---------------------------------------------------------------- limits, errors, determinism, hygiene
def test_max_steps_cut():
    r = run(STACK_STRING, 0x401024, max_steps=2)
    assert "cut: " in r.text and not r.complete


def test_errors():
    with pytest.raises(SliceError) as e:
        run(STACK_STRING, 0x401025)
    assert e.value.code == "NO_INSTRUCTION"
    with pytest.raises(SliceError) as e:
        run(STACK_STRING, 0x401024, bits=16)
    assert e.value.code == "ARCH_UNSUPPORTED"
    with pytest.raises(SliceError) as e:
        run(STACK_STRING, 0x401024, size=5000)
    assert e.value.code == "BAD_ARGUMENT"
    with pytest.raises(SliceError):
        run(STACK_STRING, 0x401024, location="local_20")
    with pytest.raises(SliceError):
        run(STACK_STRING, 0x401024, operand=5)


def test_deterministic():
    a = run(STACK_STRING, 0x401024, image=image32())
    b = run(STACK_STRING, 0x401024, image=image32())
    assert a.text == b.text and a.summary == b.summary


def test_output_hygiene():
    r = run(STACK_STRING, 0x401024)
    for ln in r.text.splitlines():
        ann = ln.split(" | ")[-1] if " | " in ln else ln
        if ln.startswith("insn:"):
            continue
        if ln.startswith("read "):     # `read operand N: <engine operand text> -> <annotation>`
            ann = ln.split(" -> ", 1)[1] if " -> " in ln else ""
        assert not re.search(r"\b[0-9A-F]+h\b", ann), ln          # annotations use 0x form only
    assert "hex=" not in r.text                                   # 7-byte run: no short hex token
    assert "9090" not in r.text                                   # no instruction byte field


def test_quote_escaping():
    rows = [(0x401000, "push", R("ebp")), (0x401001, "mov", R("ebp"), R("esp")),
            (0x401003, "mov", M("ebp", -4, width=4), I(0x5C224241)),   # A B " \
            (0x40100A, "cmp", R("eax"), R("ebx")), (0x40100C, "ret")]
    r = run(rows, 0x40100A, location="[ebp-4]", size=4)
    assert 'ascii="AB\\"\\\\" escaped=yes' in r.text


# ---------------------------------------------------------------- spilled frame pointers (debug-build strcmp)
SPILLED_CMP = [
    (0x401000, "push", R("ebp")), (0x401001, "mov", R("ebp"), R("esp")),
    (0x401003, "mov", M("ebp", -0x64, width=4), I(0x64636261)),          # "abcd"
    (0x40100A, "mov", M("ebp", -0x60, width=1), I(0, 1)),
    (0x40100E, "lea", R("edx"), M("ebp", -0x64)),
    (0x401011, "mov", M("ebp", -0x1CC, width=4), R("edx")),               # pointer spilled to a frame slot
    (0x401017, "mov", R("ecx"), M("ebp", 8, width=4)),                     # argument: the input string
    (0x40101A, "mov", R("dl"), M("ecx", 0, width=1)),
    (0x40101C, "mov", R("eax"), M("ebp", -0x1CC, width=4)),               # reload of the spilled pointer
    (0x401022, "cmp", R("dl"), M("eax", 0, width=1)),
    (0x401024, "jnz", N(0x401034)),
    (0x401026, "add", R("ecx"), I(1, 1)),
    (0x401029, "add", M("ebp", -0x1CC, width=4), I(1, 1)),                # pointer advanced in the loop
    (0x401030, "test", R("dl"), R("dl")),
    (0x401032, "jnz", N(0x40101A)),
    (0x401034, "ret"),
]


@pytest.mark.parametrize("dialect", DIALECTS)
def test_spilled_pointer_advanced_in_loop_reads_the_frame_buffer(dialect):
    r = run(SPILLED_CMP, 0x401022, dialect=dialect, operand=1)
    assert "frame buffer from sp0-0x68" in r.text
    assert 'run +0x0..+0x4 len=5 ascii="abcd" nul_terminated=yes' in r.text
    assert "+0x0..+0x3 definite src=0x401003" in r.text
    r0 = run(SPILLED_CMP, 0x401022, dialect=dialect, operand=0)
    assert "value=unknown" in r0.text


def test_spilled_pointer_reload_gives_the_frame_address():
    rows = SPILLED_CMP[:9] + [(0x401022, "cmp", R("eax"), R("ecx")), (0x401024, "ret")]
    r = run(rows, 0x401022, operand=0)
    assert "value=&sp0-0x68 definite (frame address)" in r.text
    assert "0x401011 |" in r.text and "0x40101c |" in r.text


def test_spilled_pointer_escapes_at_a_call():
    rows = SPILLED_CMP[:6] + [(0x401017, "call", N(0x402000)), (0x40101C, "mov", R("eax"), M("ebp", -0x1CC, width=4)),
                              (0x401022, "cmp", R("dl"), M("eax", 0, width=1)), (0x401024, "ret")]
    r = run(rows, 0x401022, operand=1)
    assert "definite=0" in r.text and "may write through an escaped frame address" in r.text


# ---------------------------------------------------------------- x64 RIP-relative image load, size of work
def test_x64_rip_relative_rdata_load():
    raw = build_pe(is64=True)
    img = PeImageView(parse_pe(lambda off, n: raw[off:off + n], len(raw)), lambda off, n: raw[off:off + n])
    rip = OperandInfo("mem", "qword ptr [rip+0FF9h]", base="rip", disp=0x2040 - 0x1047, size=8)
    rows = [(0x140001040, "mov", R("rax"), rip), (0x140001047, "mov", R("rcx"), R("rax")),
            (0x14000104A, "cmp", R("rcx"), I(0, 1)), (0x14000104E, "ret")]
    r = run(rows, 0x14000104A, bits=64, image=img, operand=0)
    assert f"value=0x{int.from_bytes(b'hello' + bytes(3), 'little'):x} definite" in r.text
    assert "image 0x140002040 size=8 section=.rdata R--" in r.text


def test_large_function_with_loops_is_bounded():
    import time
    rows = [(0x401000, "push", R("ebp")), (0x401001, "mov", R("ebp"), R("esp"))]
    a = 0x401003
    for k in range(600):
        rows.append((a, "mov", M("ebp", -0x400 + k, width=1), I(0x41 + k % 26, 1)))
        a += 4
        if k % 50 == 49:      # a small loop every 50 stores
            rows.append((a, "inc", R("ecx")))
            rows.append((a + 1, "cmp", R("ecx"), I(9, 1)))
            rows.append((a + 4, "jl", N(a)))
            a += 6
    rows += [(a, "cmp", R("eax"), R("ebx")), (a + 2, "ret")]
    t0 = time.monotonic()
    r = run(rows, a, location="[ebp-0x400]", size=600, max_steps=1000)
    assert time.monotonic() - t0 < 20
    assert "definite=600" in r.text and r.complete


# ---------------------------------------------------------------- callee-writable stack parameters (slicer rev 4)
def test_x64_known_stack_parameters_are_callee_writable_exactly():
    rows = [(0x140001000, "sub", R("rsp"), I(0x58, 1)),
            (0x140001004, "mov", M("rsp", 0x20, width=8), I(5, 4)),      # 5th argument
            (0x14000100D, "mov", M("rsp", 0x28, width=8), I(6, 4)),      # 6th argument
            (0x140001016, "mov", M("rsp", 0x40, width=8), I(7, 4)),      # a local above the arguments
            (0x14000101F, "call", N(0x140002000)),
            (0x140001024, "cmp", R("rax"), R("rbx")), (0x140001027, "ret")]
    r = run(rows, 0x140001024, bits=64, location="[rsp+0x20]", size=0x28, call_args={0x14000101F: 0x30})
    assert "+0x0 unknown last=0x05" in r.text and "+0x8 unknown last=0x06" in r.text   # 0x30: home + 2 args
    assert "+0x20..+0x27 definite src=0x140001016" in r.text and "assumes=" not in r.text.split("defs:")[0]
    ru = run(rows, 0x140001024, bits=64, location="[rsp+0x40]", size=8)
    assert "+0x0 unknown last=0x07" in ru.text                       # inside the A3 window [rsp, rsp+0xa0)


def test_unknown_parameter_list_tags_the_frame_above_the_window_with_a3():
    rows = [(0x140001000, "sub", R("rsp"), I(0xc8, 4)),
            (0x140001007, "mov", M("rsp", 0xb0, width=8), I(9, 4)),       # above the 0xa0 window
            (0x140001010, "call", R("rax")),                                # indirect: parameter list unknown
            (0x140001012, "mov", R("rcx"), M("rsp", 0xb0, width=8)),
            (0x140001017, "cmp", R("rcx"), I(9, 1)), (0x14000101B, "ret")]
    r = run(rows, 0x140001017, bits=64, operand=0)
    assert "value=0x9 definite assumes=A3" in r.text and "A3:" in r.text


# ---------------------------------------------------------------- exception edges (slicer rev 4)
class _Edge:
    def __init__(self, b, e, t):
        self.try_begin, self.try_end, self.target = b, e, t


SEH = [(0x140001000, "sub", R("rsp"), I(0x28, 1)),
       (0x140001004, "mov", R("ebx"), I(1)),                              # try: ebx = 1
       (0x140001009, "call", N(0x140002000)),                             # may raise
       (0x14000100E, "mov", R("ebx"), I(2)),
       (0x140001013, "jmp", N(0x14000101A)),                              # normal path skips the __except block
       (0x140001015, "mov", R("esi"), I(7)),                              # __except block (no CFG predecessor)
       (0x14000101A, "cmp", R("ebx"), R("esi")), (0x14000101C, "ret")]


def test_exception_edge_makes_the_except_block_analysed():
    edges = [_Edge(0x140001004, 0x140001013, 0x140001015)]
    r = run(SEH, 0x14000101A, bits=64, operand=0, exc_edges=edges)
    assert "exception_edges=1" in r.text and "not-analysed" not in r.text and r.complete
    # ebx at the join: 2 on the normal path, 1 or 2 when the exception came from inside the try range
    assert "value=unknown" in r.text and "different values" in r.text
    re_ = run(SEH, 0x14000101A, bits=64, operand=1, exc_edges=edges)
    assert "0x140001015 |" in re_.text                                  # the handler's write is part of the slice
    # without the edge: the block is not analysed and its join is tainted (the conservative fallback)
    r0 = run(SEH, 0x14000101A, bits=64, operand=0)
    assert "exception_edges=0" in r0.text and "not-analysed block 0x140001015 flows into 0x14000101a" in r0.text


def test_handler_entry_has_volatile_registers_unknown():
    rows = SEH[:5] + [(0x140001015, "cmp", R("ecx"), R("ebx")), (0x140001017, "ret")]
    edges = [_Edge(0x140001004, 0x140001013, 0x140001015)]
    r = run(rows, 0x140001015, bits=64, operand=0, exc_edges=edges)
    assert "exception dispatch into 0x140001015" in r.text
    r1 = run(rows, 0x140001015, bits=64, operand=1, exc_edges=edges)
    assert "value=unknown" in r1.text                                    # ebx is 1 or 2 depending on the fault point


def test_edges_outside_the_function_are_ignored():
    r = run(SEH, 0x14000101A, bits=64, operand=0, exc_edges=[_Edge(0x150000000, 0x150000010, 0x150000020)])
    assert "exception_edges=0" in r.text
