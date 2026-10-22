"""Exception handlers the slicer cannot model (analysis/dataflow/eh.py, slicer revision 5): a catch funclet that is not in
the parent's decoded stream can write a frame slot and resume anywhere, so such a function reports no definite value.

Synthetic instruction streams in both operand dialects (IDA / Ghidra) plus a synthetic x64 PE whose unwind data is the
known answer for the handler classification.
"""
from __future__ import annotations

import struct

import pytest

from redharness.analysis.dataflow import SLICER_REV, UnwindData, slice_function
from redharness.analysis.dataflow.eh import x86_markers
from redharness.analysis.imports_view import iat_slot_names
from redharness.analysis.pe_dirs import scan_imports_image
from redharness.analysis.pe_image import parse_pe
from redharness.engines.base import InsnInfo, OperandInfo

from . import _synthpe as S
from .test_dataflow_slice import DIALECTS, I, M, N, R, STACK_STRING, image32, run

BASE = 0x140000000
THUNK = S.TEXT_RVA + 0x100
PDATA, XDATA, XDATA2 = S.RDATA_RVA + 0x900, S.RDATA_RVA + 0x800, S.RDATA_RVA + 0x840
FI3, FI4 = S.RDATA_RVA + 0xA00, S.RDATA_RVA + 0xA40
STATIC_HANDLER = S.TEXT_RVA + 0x200      # a statically linked handler: no import behind it
WHY = "exception handler not modelled"
CALLS64 = {0x14000100C: 0x20}
CALLS32 = {0x401013: 0}      # the callee takes no stack parameters: keeps the frame slot out of its writable area


def fs0(dialect):
    return OperandInfo("mem", "large fs:0" if dialect == "ida" else "dword ptr FS:[0x0]", value=0, size=4)


# ---------------------------------------------------------------- the analysis-doc counterexample
def counterexample(dialect, registered=True):
    """mov [ebp-4],0; call may_throw; jmp join; join: mov eax,[ebp-4] -- an omitted catch funclet writes 1 and resumes
    at the join."""
    rows = [(0x401000, "push", R("ebp")), (0x401001, "mov", R("ebp"), R("esp")), (0x401003, "sub", R("esp"), I(0x10, 1))]
    if registered:
        rows.append((0x401006, "mov", R("eax"), fs0(dialect)))
    rows += [(0x40100C, "mov", M("ebp", -4, width=4), I(0)),
             (0x401013, "call", N(0x402000)),
             (0x401018, "jmp", N(0x40101A)),
             (0x40101A, "mov", R("eax"), M("ebp", -4, width=4)),
             (0x40101D, "cmp", R("eax"), I(0, 1)),
             (0x401020, "ret")]
    return rows


@pytest.mark.parametrize("dialect", DIALECTS)
def test_unregistered_function_keeps_the_definite_value(dialect):
    r = run(counterexample(dialect, registered=False), 0x40101D, dialect=dialect, operand=0, call_args=CALLS32)
    assert "value=0x0 definite" in r.text and WHY not in r.text and "eh=unmodelled" not in r.text
    assert r.complete and "eh_unmodelled" not in r.summary


@pytest.mark.parametrize("dialect", DIALECTS)
def test_x86_fs0_registration_makes_the_join_value_unknown(dialect):
    r = run(counterexample(dialect), 0x40101D, dialect=dialect, operand=0, call_args=CALLS32)
    assert "definite" not in r.text.split("read operand 0")[1].split("defs:")[0]
    assert f"unknown: {WHY} (x86 SEH/EH frame handler: fs:[0] exception registration at 0x401006)" in r.text
    assert "eh=unmodelled" in r.text and not r.complete
    assert any(x.startswith(WHY) for x in r.reasons) and r.summary["eh_unmodelled"]
    # the slot itself, read straight from the frame
    r2 = run(counterexample(dialect), 0x40101A, dialect=dialect, operand=1, call_args=CALLS32)
    assert "definite=0" in r2.text and " definite src=" not in r2.text and " run +0x" not in r2.text
    assert "last=0x00" in r2.text                      # the parent's own write is still shown, as a non-definite candidate
    assert "0x40100c |" in r2.text                     # ... and stays in the provenance


@pytest.mark.parametrize("dialect", DIALECTS)
def test_x64_cpp_eh_reason_from_the_unwind_data(dialect):
    rows = [(0x140001000, "sub", R("rsp"), I(0x28, 1)),
            (0x140001004, "mov", M("rsp", 0x20, width=4), I(0)),
            (0x14000100C, "call", N(0x140002000)),
            (0x140001011, "jmp", N(0x140001013)),
            (0x140001013, "mov", R("eax"), M("rsp", 0x20, width=4)),
            (0x140001017, "cmp", R("eax"), I(0, 1)), (0x14000101A, "ret")]
    why = "C++ EH, handler __CxxFrameHandler4"
    r = run(rows, 0x140001017, bits=64, dialect=dialect, operand=0, eh_unmodelled=(why,), call_args=CALLS64)
    assert f"unknown: {WHY} ({why})" in r.text
    assert "value=0x0 definite" not in r.text and not r.complete
    base = run(rows, 0x140001017, bits=64, dialect=dialect, operand=0, call_args=CALLS64)
    assert "value=0x0 definite" in base.text and base.complete


@pytest.mark.parametrize("dialect", DIALECTS)
def test_stack_string_becomes_candidates_not_a_run(dialect):
    rows = [(0x40100A, "mov", R("eax"), fs0(dialect)) if r[0] == 0x40100A else r for r in STACK_STRING]   # junk -> marker
    r = run(rows, 0x401024, dialect=dialect)
    assert " run +0x" not in r.text and "definite src=" not in r.text
    assert 'candidate +0x0..+0x6 len=7 ascii="ABCDEF"' in r.text and "NOT definite" in r.text
    assert f"unknown: {WHY}" in r.text


def test_immediates_image_bytes_and_the_frame_pointer_stay_definite():
    rows = [(0x401000, "push", R("ebp")), (0x401001, "mov", R("ebp"), R("esp")),
            (0x401003, "mov", R("eax"), fs0("ida")),
            (0x401009, "mov", R("ecx"), I(5)),
            (0x40100E, "mov", R("eax"), M(value=0x402040, width=4)),
            (0x401013, "cmp", R("ecx"), I(5, 1)), (0x401016, "ret")]
    img = image32()
    load = run(rows, 0x40100E, image=img, operand=1)            # a read-only image dword, read directly
    assert "memory 0x402040 size=4" in load.text and "definite" in load.text.split("read operand 1")[1].split("defs:")[0]
    reg = run(rows, 0x401013, image=img, operand=0)             # ecx = 5 written earlier: a handler may have changed it
    assert "value=0x5 definite" not in reg.text and "value=unknown" in reg.text
    imm = run(rows, 0x401013, image=img, operand=1)             # the immediate operand itself
    assert "value=0x5 definite" in imm.text
    ebp = run(rows, 0x401013, image=img, location="ebp")
    assert "definite (frame address)" in ebp.text


def test_frame_address_in_a_scratch_register_is_dropped_and_escapes():
    rows = [(0x401000, "push", R("ebp")), (0x401001, "mov", R("ebp"), R("esp")),
            (0x401003, "mov", R("eax"), fs0("ida")),
            (0x401009, "mov", M("ebp", -0x10, width=1), I(0x41, 1)),
            (0x40100D, "lea", R("ecx"), M("ebp", -0x10)),
            (0x401010, "cmp", R("cl"), I(0, 1)), (0x401013, "ret")]
    r = run(rows, 0x401010, operand=0)
    assert "definite" not in r.text.split("read operand 0")[1].split("defs:")[0]


def test_slicer_revision_and_modelled_scope_tables_are_unchanged():
    assert SLICER_REV == 6
    from .test_dataflow_slice import SEH, _Edge
    r = run(SEH, 0x14000101A, bits=64, operand=0, exc_edges=[_Edge(0x140001004, 0x140001013, 0x140001015)])
    assert "eh=unmodelled" not in r.text and WHY not in r.text and r.complete


# ---------------------------------------------------------------- x86 marker recognition
@pytest.mark.parametrize("text,hit", [
    ("mov eax, large fs:0", True), ("mov large fs:0, esp", True), ("push dword ptr fs:0", True),
    ("MOV EAX,FS:[0x0]", True), ("PUSH dword ptr FS:[0x0]", True), ("mov dword ptr fs:[0], esp", True),
    ("mov eax, large fs:18h", False), ("MOV EAX,FS:[0x18]", False), ("mov eax, large fs:30h", False),
    ("mov eax, large fs:0Ch", False), ("call __SEH_prolog4", True), ("call ___CxxFrameHandler3", True),
    ("push offset __except_handler4", True), ("call __EH_prolog3_catch", True), ("call sub_401000", False),
    ("mov eax, [ebp-4]", False)])
def test_x86_marker_texts(text, hit):
    ins = InsnInfo(0x401000, 1, "90", "mov", (), text)
    assert bool(x86_markers([ins])) is hit


# ---------------------------------------------------------------- x64 unwind data classification
def _pe(handler="__CxxFrameHandler3", payload=b"", flags=0x1, extra=None, static=False, rows=((0x1000, 0x1080),),
        chain=False):
    """One or more RUNTIME_FUNCTIONs; the first one's UNWIND_INFO has `flags` and (handler thunk, payload)."""
    raw = bytearray(S.build_pe(is64=True, imports={"msvcrt.dll": [handler, "memset"]}))
    img = parse_pe(lambda o, n: bytes(raw[o:o + n]), len(raw))
    slots = {v: k for k, v in iat_slot_names(scan_imports_image(img, lambda o, n: bytes(raw[o:o + n]))).items()}
    slot = slots[f"msvcrt.dll!{handler}"] - BASE
    t_off = S.SIZE_HEADERS + (THUNK - S.TEXT_RVA)
    raw[t_off:t_off + 6] = b"\xff\x25" + struct.pack("<i", slot - (THUNK + 6))
    put = lambda rva, data: raw.__setitem__(slice(S.RDATA_FILE_OFFSET + rva - S.RDATA_RVA,
                                                  S.RDATA_FILE_OFFSET + rva - S.RDATA_RVA + len(data)), data)
    handler_rva = STATIC_HANDLER if static else THUNK
    unwind = lambda fl, tail: bytes([1 | (fl << 3), 4, 1, 0]) + b"\x04\x42" + b"\0\0" + tail
    if chain:   # XDATA is a chained entry whose parent RUNTIME_FUNCTION points to XDATA2 (the one with the handler)
        put(XDATA, unwind(0x4, struct.pack("<III", 0x1000, 0x1040, XDATA2)))
        put(XDATA2, unwind(flags, struct.pack("<I", handler_rva) + payload))
    else:
        put(XDATA, unwind(flags, struct.pack("<I", handler_rva) + payload))
    for rva, data in (extra or {}).items():
        put(rva, data)
    pd = b"".join(struct.pack("<III", b, e, XDATA) for b, e in rows)
    put(PDATA, pd)
    opt = S.E_LFANEW + 24
    struct.pack_into("<II", raw, opt + 112 + 8 * 3, PDATA, len(pd))
    return bytes(raw)


def _unmodelled(raw, va=BASE + 0x1010, resolve=None):
    img = parse_pe(lambda o, n: raw[o:o + n], len(raw))
    return UnwindData(img, lambda o, n: raw[o:o + n]).unmodelled([va], resolve)


def _fi3(n_try, magic=0x19930522):
    return struct.pack("<IiiIiiiiiI", magic, 2, 0, n_try, 0, 0, 0, 0, 0, 0)


def test_c_specific_handler_with_a_scope_table_is_modelled():
    rows = struct.pack("<IIII", 0x1010, 0x1020, 1, 0x1030)
    assert _unmodelled(_pe("__C_specific_handler", struct.pack("<I", 1) + rows)) == []
    assert _unmodelled(_pe("__GSHandlerCheck_SEH", struct.pack("<I", 1) + rows)) == []


def test_unreadable_c_scope_table_is_not_modelled():
    why = _unmodelled(_pe("__C_specific_handler", struct.pack("<I", 0xFFFF)))
    assert why == ["C scope table of handler __C_specific_handler unreadable"]


def test_cxx_handler_with_try_blocks_is_not_modelled():
    raw = _pe("__CxxFrameHandler3", struct.pack("<I", FI3), extra={FI3: _fi3(1)})
    assert _unmodelled(raw) == ["C++ EH, handler __CxxFrameHandler3"]
    raw = _pe("__GSHandlerCheck_EH", struct.pack("<II", FI3, 0x40), extra={FI3: _fi3(2)})
    assert _unmodelled(raw) == ["C++ EH, handler __GSHandlerCheck_EH"]


def test_cxx_handler_without_try_blocks_cannot_resume_in_the_frame():
    assert _unmodelled(_pe("__CxxFrameHandler3", struct.pack("<I", FI3), extra={FI3: _fi3(0)})) == []


def test_cxx_funcinfo_that_is_not_a_funcinfo_is_not_modelled():
    raw = _pe("__CxxFrameHandler3", struct.pack("<I", FI3), extra={FI3: _fi3(0, magic=0x12345678)})
    assert _unmodelled(raw) == ["C++ EH, handler __CxxFrameHandler3"]


def test_fh4_header_bits():
    fi4 = lambda hdr: bytes([hdr]) + struct.pack("<II", FI3, FI3)
    assert _unmodelled(_pe("__CxxFrameHandler4", struct.pack("<I", FI4), extra={FI4: fi4(0x28)})) == []   # unwind map only
    assert _unmodelled(_pe("__CxxFrameHandler4", struct.pack("<I", FI4), extra={FI4: fi4(0x38)})) == [
        "C++ EH, handler __CxxFrameHandler4"]                                                              # try blocks
    assert _unmodelled(_pe("__CxxFrameHandler4", struct.pack("<I", FI4), extra={FI4: fi4(0x29)})) == [
        "C++ EH, handler __CxxFrameHandler4"]                                                              # catch funclet


def test_unknown_named_handler_is_not_modelled():
    assert _unmodelled(_pe("__some_other_handler")) == ["exception handler __some_other_handler"]


def test_unnamed_static_handler_needs_the_engine_name():
    raw = _pe(static=True)
    assert _unmodelled(raw) == [f"language handler at 0x{BASE + STATIC_HANDLER:x} not identified"]
    assert _unmodelled(raw, resolve=lambda va: "__GSHandlerCheck") == []          # stack cookie check: cannot resume
    assert _unmodelled(raw, resolve=lambda va: "__C_specific_handler") == [
        "statically linked handler __C_specific_handler (scope table not parsed)"]
    assert _unmodelled(raw, resolve=lambda va: None) == [f"language handler at 0x{BASE + STATIC_HANDLER:x} not identified"]


def test_chained_unwind_info_is_followed_to_its_handler():
    raw = _pe("__CxxFrameHandler3", struct.pack("<I", FI3), extra={FI3: _fi3(1)}, chain=True)
    assert _unmodelled(raw) == ["C++ EH, handler __CxxFrameHandler3"]
    benign = _pe("__CxxFrameHandler3", struct.pack("<I", FI3), extra={FI3: _fi3(0)}, chain=True)
    assert _unmodelled(benign) == []


def test_unreadable_exception_directory_is_not_modelled():
    raw = bytearray(_pe(flags=0x0))
    struct.pack_into("<II", raw, S.E_LFANEW + 24 + 112 + 8 * 3, 0xFFFFF000, 12)   # exception directory off the image
    assert _unmodelled(bytes(raw)) == ["exception handler data unreadable (exception directory unreadable)"]


def test_truncated_exception_directory_is_not_modelled_past_the_cut(monkeypatch):
    import redharness.analysis.dataflow.eh as eh
    monkeypatch.setattr(eh, "MAX_FUNCTIONS", 1)
    raw = _pe(flags=0x0, rows=((0x1000, 0x1080), (0x1100, 0x1180)))
    assert _unmodelled(raw) == []                                  # inside the one row read: no handler
    assert _unmodelled(raw, va=BASE + 0x1110) == ["exception directory truncated at 1 entries"]


def test_unfollowable_chain_is_not_modelled():
    raw = bytearray(_pe(chain=True))
    off = S.RDATA_FILE_OFFSET + XDATA - S.RDATA_RVA + 4 + 4        # the chained RUNTIME_FUNCTION's UnwindData
    struct.pack_into("<I", raw, off + 8, 0xFFFFF000)                 # off the image
    assert _unmodelled(bytes(raw)) == ["unwind info unreadable"]


def test_no_handler_other_function_and_other_image_kinds_are_modelled():
    assert _unmodelled(_pe(flags=0x0)) == []
    assert _unmodelled(_pe("__CxxFrameHandler3", struct.pack("<I", FI3), extra={FI3: _fi3(1)}), va=BASE + 0x1100) == []
    raw = S.build_pe(is64=False)
    assert UnwindData(parse_pe(lambda o, n: raw[o:o + n], len(raw)), lambda o, n: raw[o:o + n]).unmodelled([0x401000]) == []
