"""`dataflow_slice` wiring of the unmodelled-exception-handler rule (slicer revisions 5-8): the function's x64 unwind
data (and the engine's name for a statically linked handler) decide whether any value may be reported definite."""
from __future__ import annotations

import struct

from redharness.config import Config
from redharness.core.result import Status
from redharness.engines.base import EngineResult
from redharness.mcp.session import Hub

from ._fake_engine import FakeEngine
from .mcp_helpers import make_manifest
from .test_dataflow_eh import FI3, STATIC_HANDLER, _fi3, _pe as eh_pe
from .test_dataflow_slice import I, M, N, R, prog


def _hub(tmp_path, raw, names=None):
    """x64 function 0x140001000 covered by the PE's only RUNTIME_FUNCTION; `names`: engine names by function start."""
    body = [(0x140001000, "sub", R("rsp"), I(0x28, 1)),
            (0x140001004, "mov", M("rsp", 0x20, width=4), I(7)),
            (0x14000100C, "call", N(0x140002000)),
            (0x140001011, "mov", R("eax"), M("rsp", 0x20, width=4)),
            (0x140001015, "cmp", R("eax"), I(7, 1)), (0x140001018, "ret")]

    class E(FakeEngine):
        def disassemble(self, sha256, address, *, count=200, whole_function=False):
            if address in (names or {}):
                return EngineResult(Status.OK, prog([(address, "ret")], "ida", name=names[address]),
                                    untrusted_content=True)
            return EngineResult(Status.OK, prog(body, "ida", name="f"), untrusted_content=True)

        def call_args(self, sha256, address):
            return EngineResult(Status.OK, {0x14000100C: 0x20})

    tmp_path.mkdir(parents=True, exist_ok=True)
    target = tmp_path / "t.dll"
    target.write_bytes(raw)
    hub = Hub(Config.load(tmp_path / "data"), E())
    hub.target_open(str(target), str(make_manifest(tmp_path / "scope.json", target)))
    return hub


def _slice(hub):
    kw = {"address": "0x140001011", "operand": 1, "detail": "full"}
    return hub.call("dataflow_slice", kw, lambda: hub.dataflow_slice(**kw))


def test_cxx_try_blocks_in_the_unwind_data_make_the_slice_unknown(tmp_path):
    hub = _hub(tmp_path, eh_pe("__CxxFrameHandler3", struct.pack("<I", FI3), extra={FI3: _fi3(1)}))
    r = _slice(hub)
    assert "unknown: exception handler not modelled (C++ EH, handler __CxxFrameHandler3)" in r["content"]
    assert "+0x3 definite src=" not in r["content"] and "coverage: partial" in r["content"]
    ev = hub._s.ledger.state["evidence"][r["evidence_id"]]
    assert any("exception handler not modelled" in x for x in ev["limitations"])


def test_cxx_without_try_blocks_stays_definite(tmp_path):
    r = _slice(_hub(tmp_path, eh_pe("__CxxFrameHandler3", struct.pack("<I", FI3), extra={FI3: _fi3(0)})))
    assert "+0x3 definite src=" in r["content"] and "coverage: complete" in r["content"]


def test_statically_linked_handler_is_decided_by_the_engine_name(tmp_path):
    va = 0x140000000 + STATIC_HANDLER
    r = _slice(_hub(tmp_path / "gs", eh_pe(static=True), names={va: "__GSHandlerCheck"}))   # cookie check only
    assert "+0x3 definite src=" in r["content"] and "exception handler not modelled" not in r["content"]
    r = _slice(_hub(tmp_path / "auto", eh_pe(static=True), names={va: "sub_140001200"}))    # automatic name
    assert "+0x3 definite src=" not in r["content"] and "not identified" in r["content"]
