"""x64 scope-table exception edges (analysis/dataflow/seh.py) from a synthetic PE whose unwind data is the known
answer: RUNTIME_FUNCTION -> UNWIND_INFO (EHANDLER) -> `jmp [IAT]` thunk to __C_specific_handler -> C_SCOPE_TABLE."""
from __future__ import annotations

import struct

from redharness.analysis.dataflow.seh import scope_edges
from redharness.analysis.imports_view import iat_slot_names
from redharness.analysis.pe_dirs import scan_imports_image
from redharness.analysis.pe_image import parse_pe

from . import _synthpe as S

BASE = 0x140000000
THUNK = S.TEXT_RVA + 0x100          # jmp [rip+X] -> IAT slot of the handler
XDATA, PDATA = S.RDATA_RVA + 0x800, S.RDATA_RVA + 0x900


def _pe(handler: str = "__C_specific_handler", rows=((0x1010, 0x1020, 1, 0x1030), (0x1040, 0x1050, 0x1060, 0)),
        is64: bool = True, chained: bool = False) -> bytes:
    raw = bytearray(S.build_pe(is64=is64, imports={"msvcrt.dll": [handler, "memset"]}))
    img = parse_pe(lambda o, n: bytes(raw[o:o + n]), len(raw))
    slots = {v: k for k, v in iat_slot_names(scan_imports_image(img, lambda o, n: bytes(raw[o:o + n]))).items()}
    slot = slots[f"msvcrt.dll!{handler}"] - BASE
    t_off = S.SIZE_HEADERS + (THUNK - S.TEXT_RVA)
    raw[t_off:t_off + 6] = b"\xff\x25" + struct.pack("<i", slot - (THUNK + 6))
    flags = 0x4 if chained else 0x1
    xdata = bytes([1 | (flags << 3), 4, 1, 0]) + b"\x04\x42" + b"\0\0"      # 1 unwind code, padded to an even count
    xdata += struct.pack("<II", THUNK, len(rows)) + b"".join(struct.pack("<IIII", *r) for r in rows)
    x_off = S.RDATA_FILE_OFFSET + (XDATA - S.RDATA_RVA)
    raw[x_off:x_off + len(xdata)] = xdata
    p_off = S.RDATA_FILE_OFFSET + (PDATA - S.RDATA_RVA)
    raw[p_off:p_off + 12] = struct.pack("<III", 0x1000, 0x1080, XDATA)
    opt = S.E_LFANEW + 24
    dirs_at = opt + 112 if is64 else opt + 96
    struct.pack_into("<II", raw, dirs_at + 8 * 3, PDATA, 12)
    return bytes(raw)


def _edges(raw: bytes):
    img = parse_pe(lambda o, n: raw[o:o + n], len(raw))
    return scope_edges(img, lambda o, n: raw[o:o + n])


def test_except_row_gives_an_edge_and_finally_row_none():
    edges = _edges(_pe())
    assert [(e.try_begin, e.try_end, e.target, e.filter) for e in edges] == [
        (BASE + 0x1010, BASE + 0x1020, BASE + 0x1030, 1)]
    assert edges[0].handler == "msvcrt.dll!__C_specific_handler" and edges[0].unwind_va == BASE + XDATA


def test_gs_seh_handler_is_accepted():
    assert len(_edges(_pe(handler="__GSHandlerCheck_SEH"))) == 1


def test_other_language_handlers_give_no_edges():
    assert _edges(_pe(handler="__CxxFrameHandler3")) == []


def test_chained_unwind_info_gives_no_edges():
    assert _edges(_pe(chained=True)) == []


def test_bad_rows_are_dropped():
    raw = _pe(rows=((0x1020, 0x1010, 1, 0x1030), (0x1010, 0x1020, 1, 0x9000)))   # begin >= end; target off-image
    assert _edges(raw) == []
