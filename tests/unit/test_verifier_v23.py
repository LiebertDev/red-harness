"""Verifier version 23: values and quotes backed ONLY by conditional `dataflow_slice` lines (`candidate ... NOT
definite`, `assumes=A1/A2`, a clobbered byte's `last=0x..`) cannot make a claim SUPPORTED; the same value backed
unconditionally (another line or another cited evidence item) can. Real slice evidence through the MCP path (fake
engine, synthetic PE)."""
from __future__ import annotations

from redharness.config import Config
from redharness.core.result import Status
from redharness.engines.base import EngineResult
from redharness.evidence.verifier import (QUOTE_ONLY_CONDITIONAL, VALUE_ISSUE_CODES, VALUE_ONLY_CONDITIONAL,
                                          VERIFIER_VERSION, is_conditional_line, unconditional_raw)
from redharness.mcp.session import Hub

from ._fake_engine import FakeEngine
from ._pe_builder import build_pe
from .mcp_helpers import make_manifest
from .test_dataflow_slice import I, M, N, R, prog

# buffer at [ebp-0x20] = "EFGH" (definite until the call), escapes through the pushed pointer: unknown after the call
# with last=.. bytes -> a `candidate` line; [ebp-0x30] = "ABCD" below the escape point survives under A1 (assumes=A1)
ESCAPE = [(0x401000, "push", R("ebp")), (0x401001, "mov", R("ebp"), R("esp")),
          (0x401003, "mov", M("ebp", -0x30, width=4), I(0x44434241)),
          (0x40100A, "mov", M("ebp", -0x20, width=4), I(0x48474645)),
          (0x401011, "lea", R("eax"), M("ebp", -0x20)),
          (0x401014, "push", R("eax")),
          (0x401015, "call", N(0x402000)),
          (0x40101A, "mov", R("ecx"), M("ebp", -0x30, width=4)), (0x40101D, "add", R("ecx"), I(1, 1)),
          (0x401020, "cmp", R("ecx"), R("edx")), (0x401022, "ret")]


class Engine(FakeEngine):
    def disassemble(self, sha256, address, *, count=200, whole_function=False):
        return EngineResult(Status.OK, prog(ESCAPE, "ida", name="check"), untrusted_content=True)


def _hub(tmp_path):
    target = tmp_path / "t.exe"
    target.write_bytes(build_pe(is64=False))
    hub = Hub(Config.load(tmp_path / "data"), Engine())
    hub.target_open(str(target), str(make_manifest(tmp_path / "scope.json", target)))
    return hub


def _slice(hub, **kw):
    kw = {"detail": "full", **kw}
    r = hub.call("dataflow_slice", kw, lambda: hub.dataflow_slice(**kw))
    return r["evidence_id"], r["content"]


def _claim(hub, text, evs, **kw):
    c = hub.claim_add(text=text, evidence_ids=evs, kind="observation", requested="SUPPORTED", **kw)
    rec = hub._s.ledger.state["claims"][c["claim_id"]]["verification"]
    return c["status"], [i["code"] for i in rec["issues"]], rec


def test_version_and_issue_code():
    assert VERIFIER_VERSION == "24" and VALUE_ONLY_CONDITIONAL in VALUE_ISSUE_CODES


def test_conditional_lines_are_blanked_only_in_slice_evidence():
    raw = (b'  run +0x0..+0x3 len=4 ascii="ABCD" assumes=A1\n  candidate +0x0..+0x3 len=4 ascii="EFGH" NOT definite\n'
           b"  +0x0 unknown last=0x45 writes=0x40100a: x\n  0x401003 | mov dword ptr [ebp-30h], 44434241h | writes\n")
    out = unconditional_raw(raw, {"operation": "dataflow_slice"}).split(b"\n")
    assert out[:3] == [b"", b"", b""] and out[3].startswith(b"  0x401003")
    assert unconditional_raw(raw, {"operation": "disassemble"}) == raw
    assert is_conditional_line("  candidate +0x0 len=2") and not is_conditional_line("  run +0x0..+0x3 len=4")


def test_candidate_only_value_is_unverified(tmp_path):
    hub = _hub(tmp_path)
    ev, text = _slice(hub, address="0x401020", location="[ebp-0x20]", size=4)
    assert 'candidate +0x0..+0x3 len=4 ascii="EFGH" NOT definite' in text and "run +0x0" not in text
    status, codes, rec = _claim(hub, 'The four bytes at sp0-0x24 compared at 0x401020 are "EFGH".', [ev])
    assert status == "UNVERIFIED" and VALUE_ONLY_CONDITIONAL in codes
    assert {"code": "UNCONDITIONAL_BACKING", "ok": False} in rec["checks"]


def test_candidate_only_quote_is_unverified(tmp_path):
    hub = _hub(tmp_path)
    ev, _ = _slice(hub, address="0x401020", location="[ebp-0x20]", size=4)
    status, codes, _ = _claim(hub, "The slice shows a candidate buffer at 0x401020.", [ev],
                              atoms=[{"type": "quote", "evidence_id": ev, "text": 'ascii="EFGH" NOT definite'}])
    assert status == "UNVERIFIED" and QUOTE_ONLY_CONDITIONAL in codes


def test_assumption_only_value_is_unverified(tmp_path):
    hub = _hub(tmp_path)
    ev, text = _slice(hub, address="0x401020", operand=0)
    assert "value=0x44434242 definite assumes=A1" in text
    assert "writes ecx value=0x44434242 assumes=A1" in text      # the def line carries the marker too
    status, codes, _ = _claim(hub, "At 0x401020 ecx holds 0x44434242.", [ev])
    assert status == "UNVERIFIED" and VALUE_ONLY_CONDITIONAL in codes
    status, codes, _ = _claim(hub, "At 0x401020 ecx holds a value.", [ev],
                              atoms=[{"type": "constant", "evidence_id": ev, "value": "0x44434242"}])
    assert status == "UNVERIFIED" and VALUE_ONLY_CONDITIONAL in codes


def test_unconditional_line_in_the_same_evidence_backs_the_value(tmp_path):
    hub = _hub(tmp_path)
    ev, text = _slice(hub, address="0x401020", operand=0)
    # 0x44434241 is also the immediate of the store at 0x401003 (an unconditional def line)
    status, codes, _ = _claim(hub, "The store at 0x401003 writes 0x44434241.", [ev])
    assert status == "SUPPORTED", codes


def test_mixed_conditional_and_independent_unconditional_backing_is_supported(tmp_path):
    hub = _hub(tmp_path)
    ev_after, _ = _slice(hub, address="0x401020", location="[ebp-0x20]", size=4)    # candidate only
    ev_before, text = _slice(hub, address="0x401014", location="[ebp-0x20]", size=4)  # before the call: definite
    assert 'run +0x0..+0x3 len=4 ascii="EFGH"' in text and "assumes=" not in text.split("defs:")[0]
    status, codes, _ = _claim(hub, 'The four bytes at sp0-0x24 are "EFGH".', [ev_after, ev_before])
    assert status == "SUPPORTED", codes


def test_claims_without_slice_evidence_keep_their_checks(tmp_path):
    hub = _hub(tmp_path)
    r = hub.call("disassemble", {"address": "0x401000"}, lambda: hub.disassemble("0x401000"))
    status, codes, rec = _claim(hub, "The code at 0x401000 is shown.", [r["evidence_id"]])
    assert not any(c["code"] == "UNCONDITIONAL_BACKING" for c in rec["checks"])
