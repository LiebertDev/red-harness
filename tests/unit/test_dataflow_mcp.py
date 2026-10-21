"""`dataflow_slice` MCP wiring with a fake engine and a synthetic x86 PE: scope effect, step cache, evidence,
summary/full, section notes, image loads and the claim round trip (no verifier change)."""
from __future__ import annotations

import pytest

from redharness.config import Config
from redharness.core.result import Status
from redharness.engines.base import Disassembly, EngineResult
from redharness.mcp.effects import TOOL_EFFECTS
from redharness.mcp.session import Hub, ToolFailure

from ._fake_engine import FakeEngine
from ._pe_builder import build_pe
from .mcp_helpers import make_manifest
from .test_dataflow_slice import I, M, R, STACK_STRING, prog

RDATA_PROG = [(0x401040, "mov", R("esi"), I(0x402000)),
              (0x401045, "mov", R("eax"), M("esi", 0x40, width=4)),
              (0x401048, "cmp", R("eax"), I(0, 1)), (0x40104B, "ret")]


class SliceEngine(FakeEngine):
    calls = 0

    def disassemble(self, sha256, address, *, count=200, whole_function=False):
        SliceEngine.calls += 1
        rows = STACK_STRING if address < 0x401040 else RDATA_PROG
        d = prog(rows, "ida", name="check")
        if not any(i.address == address for i in d.items):
            return EngineResult(Status.ERROR, None, f"no function at 0x{address:x}")
        return EngineResult(Status.OK, d, untrusted_content=True)


def make_hub(tmp_path, ops=("static",)):
    target = tmp_path / "t.exe"
    target.write_bytes(build_pe(is64=False))
    manifest = make_manifest(tmp_path / "scope.json", target, allowed_operations=list(ops))
    hub = Hub(Config.load(tmp_path / "data"), SliceEngine())
    hub.target_open(str(target), str(manifest))
    return hub


def _call(hub, **kw):
    return hub.call("dataflow_slice", kw, lambda: hub.dataflow_slice(**kw))


def _evidence(hub, ev):
    return hub._s.ledger.state["evidence"][ev]


def test_effects_same_as_disassemble():
    assert TOOL_EFFECTS["dataflow_slice"] == TOOL_EFFECTS["disassemble"]


def test_summary_full_same_evidence_and_cache(tmp_path):
    hub = make_hub(tmp_path)
    SliceEngine.calls = 0
    s = _call(hub, address="0x401024")
    assert s["detail"] == "summary" and s["status"] == "OK"
    assert s["summary"]["buffers"][0]["runs"] == [[0, 7]]
    f = _call(hub, address="0x401024", detail="full")
    assert f["evidence_id"] == s["evidence_id"] and f["step_cached"] is True
    assert SliceEngine.calls == 1
    body = f["content"]
    assert 'ascii="ABCDEF" nul_terminated=yes' in body
    assert "; section .text R-X" in body
    ev = _evidence(hub, s["evidence_id"])
    assert ev["operation"] == "dataflow_slice" and ev["confidence"] == "derived"
    starts = {(loc["space"], loc["start"]) for loc in ev["locations"]}
    assert ("va", 0x401006) in starts and ("rva", 0x1006) in starts


def test_image_load_has_section_and_range_location(tmp_path):
    hub = make_hub(tmp_path)
    r = _call(hub, address="0x401048", operand=0, detail="full")
    assert "value=0x6c6c6568 definite" in r["content"]
    assert "image 0x402040 size=4 section=.rdata R--" in r["content"]
    assert "; section .rdata R--" in r["content"]
    ev = _evidence(hub, r["evidence_id"])
    assert any(loc["kind"] == "address-range" and loc["start"] == 0x402040 and loc["end"] == 0x402044
               for loc in ev["locations"])


def test_errors_are_tool_failures(tmp_path):
    hub = make_hub(tmp_path)
    with pytest.raises(ToolFailure) as e:
        _call(hub, address="0x401025")
    assert e.value.code in ("NO_INSTRUCTION", "ERROR")
    with pytest.raises(ToolFailure) as e:
        _call(hub, address="0x401024", size="big")
    assert e.value.code == "BAD_ARGUMENT"
    with pytest.raises(ToolFailure) as e:
        _call(hub, address="0x401024", location="local_20")
    assert e.value.code == "BAD_ARGUMENT"


def test_claim_round_trip_without_verifier_change(tmp_path):
    hub = make_hub(tmp_path)
    ev = _call(hub, address="0x401024")["evidence_id"]
    obs = hub.claim_add(text='The bytes compared at 0x401024 are "ABCDEF", written at 0x401006 and 0x401014.',
                        evidence_ids=[ev], kind="observation", requested="SUPPORTED",
                        atoms=[{"type": "quote", "evidence_id": ev, "text": "mov byte ptr [ebp-20h], 0x41"},
                               {"type": "address", "evidence_id": ev, "value": "0x401006"}])
    assert obs["status"] == "SUPPORTED", hub._s.ledger.state["claims"][obs["claim_id"]]["verification"]["issues"]
    beh = hub.claim_add(text='"ABCDEF" is the accepted password.', evidence_ids=[ev], kind="behavior",
                        requested="PROVEN")
    assert beh["status"] == "UNVERIFIED"
    wrong = hub.claim_add(text='The bytes compared at 0x401024 are "ABCDEG".', evidence_ids=[ev],
                          kind="observation", requested="SUPPORTED")
    assert wrong["status"] != "SUPPORTED"


def test_analysis_cache_is_keyed_by_the_instruction_stream(tmp_path):
    """Two hubs in one process, same target and same function size, different decoded instructions: the per-process
    analysis cache must not hand the first stream's analysis to the second."""
    from .test_dataflow_slice import prog as _prog

    def engine(imm):
        rows = [(0x401000, "mov", R("eax"), I(imm)), (0x401005, "cmp", R("eax"), I(0, 1)), (0x401008, "ret")]

        class E(FakeEngine):
            def disassemble(self, sha256, address, *, count=200, whole_function=False):
                return EngineResult(Status.OK, _prog(rows, "ida", name="f"), untrusted_content=True)
        return E()

    target = tmp_path / "t.exe"
    target.write_bytes(build_pe(is64=False))
    out = []
    for k, imm in enumerate((0x11, 0x22)):
        d = tmp_path / f"h{k}"
        d.mkdir()
        hub = Hub(Config.load(d / "data"), engine(imm))
        hub.target_open(str(target), str(make_manifest(d / "scope.json", target)))
        kw = {"address": "0x401005", "operand": 0, "detail": "full"}
        out.append(hub.call("dataflow_slice", kw, lambda h=hub: h.dataflow_slice(**kw))["content"])
        hub.close()
    assert "value=0x11 definite" in out[0] and "value=0x22 definite" in out[1]


def test_engine_call_args_reach_the_slicer(tmp_path):
    from redharness.engines._common import call_args_from_doc
    from .test_dataflow_slice import N, prog as _prog
    rows = [(0x401000, "push", R("ebp")), (0x401001, "mov", R("ebp"), R("esp")),
            (0x401003, "sub", R("esp"), I(0x10, 1)),
            (0x401006, "mov", M("ebp", -8, width=4), I(0x31323334)),
            (0x40100D, "push", I(1, 1)), (0x40100F, "call", N(0x402000)),
            (0x401014, "cmp", R("eax"), M("ebp", -8, width=4)), (0x401017, "ret")]

    def hub_with(call_args):
        class E(FakeEngine):
            def disassemble(self, sha256, address, *, count=200, whole_function=False):
                return EngineResult(Status.OK, _prog(rows, "ida", name="f"), untrusted_content=True)

            def call_args(self, sha256, address):
                return EngineResult(Status.OK, call_args, untrusted_content=True)
        d = tmp_path / f"h{len(call_args)}"
        d.mkdir()
        target = d / "t.exe"
        target.write_bytes(build_pe(is64=False))
        hub = Hub(Config.load(d / "data"), E())
        hub.target_open(str(target), str(make_manifest(d / "scope.json", target)))
        return hub

    kw = {"address": "0x401014", "operand": 1, "detail": "full"}
    hub = hub_with({0x40100F: 4})            # one 4-byte stack parameter: [esp, esp+4) only
    text = hub.call("dataflow_slice", kw, lambda: hub.dataflow_slice(**kw))["content"]
    assert "callee_parameter_lists=1/1 calls" in text and "+0x0..+0x3 definite src=0x401006" in text
    hub = hub_with({})                        # unknown: the 0x40 window covers [ebp-8]
    text = hub.call("dataflow_slice", kw, lambda: hub.dataflow_slice(**kw))["content"]
    assert "callee_parameter_lists=0/1 calls" in text and "definite=0" in text
    assert call_args_from_doc({"calls": [{"a": 16, "e": 8}, {"a": 32, "e": None}], "counts": {"calls": 2}}) == \
        ({16: 8, 32: None}, "")
    assert call_args_from_doc({"calls": [{"a": 16, "e": -1}], "counts": {"calls": 1}})[0] is None
    assert call_args_from_doc({"calls": [], "counts": {"calls": 3}})[0] is None


def test_without_engine_call_args_the_limitation_is_recorded(tmp_path):
    hub = make_hub(tmp_path)
    kw = {"address": "0x401024", "detail": "full"}
    r = hub.call("dataflow_slice", kw, lambda: hub.dataflow_slice(**kw))
    ev = hub._s.ledger.state["evidence"][r["evidence_id"]]
    assert any("callee parameter lists unavailable from the engine" in x for x in ev["limitations"])


def test_except_block_outside_the_engine_function_is_decoded_and_analysed(tmp_path):
    """The engine's function body lacks the __except block (it never decoded it); the unwind data's scope table names
    it; the tool decodes it through the engine and analyses it instead of tainting."""
    from redharness.engines.base import Disassembly
    from .test_dataflow_seh import _pe as seh_pe
    from .test_dataflow_slice import N, prog as _prog
    body = [(0x140001000, "sub", R("rsp"), I(0x28, 1)),
            (0x140001010, "mov", R("ebx"), I(1)),               # try range 0x1010..0x1020
            (0x140001015, "call", N(0x140002000)),
            (0x14000101A, "jmp", N(0x140001040)),               # normal path skips 0x1030
            (0x140001040, "cmp", R("ebx"), I(0, 1)), (0x140001043, "ret")]
    handler = [(0x140001030, "xor", R("ebx"), R("ebx")), (0x140001032, "jmp", N(0x140001040))]

    class E(FakeEngine):
        decoded = 0

        def disassemble(self, sha256, address, *, count=200, whole_function=False):
            if 0x140001030 <= address < 0x140001040:   # like Ghidra: the handler is in no function
                return EngineResult(Status.ERROR, None, f"LOOKUP: no function at address: 0x{address:x}")
            return EngineResult(Status.OK, _prog(body, "ida", name="f"), untrusted_content=True)

        def decode(self, sha256, address, *, count=64):
            E.decoded += 1
            d = _prog(handler, "ida", name="", function=None)
            return EngineResult(Status.OK, Disassembly(d.items, None, "", len(d.items), True, ""),
                                untrusted_content=True)

    target = tmp_path / "t.dll"
    target.write_bytes(seh_pe())
    hub = Hub(Config.load(tmp_path / "data"), E())
    hub.target_open(str(target), str(make_manifest(tmp_path / "scope.json", target)))
    kw = {"address": "0x140001032", "location": "ebx", "detail": "full"}
    r = hub.call("dataflow_slice", kw, lambda: hub.dataflow_slice(**kw))
    assert "exception_edges=1" in r["content"] and "value=0x0 definite" in r["content"]
    assert "0x140001030 |" in r["content"] and E.decoded >= 1
    ev = hub._s.ledger.state["evidence"][r["evidence_id"]]
    assert any("decoded by the engine outside its function body" in x for x in ev["limitations"])
