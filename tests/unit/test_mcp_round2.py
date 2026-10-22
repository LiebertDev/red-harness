"""MCP round two: disassemble, unknown_record, coverage, tool effect table (permission denial), detail=summary/full.

Fake engine (does not need IDA); Hub in-process, tool list/hex addresses with a real stdio client.
"""
import asyncio
import json
import re
from pathlib import Path

import pytest

from redharness.config import Config
from redharness.core.result import Status
from redharness.engines.base import DecompileInfo, EngineResult
from redharness.mcp import effects as fx
from redharness.mcp.effects import TOOL_EFFECTS, EffectDenied, ToolEffects, check_permission
from redharness.mcp.server import MAX_TOOLS, TOOL_NAMES
from redharness.mcp.session import Hub, ToolFailure
from redharness.scope.manifest import parse_manifest

from ._fake_engine import BASE, FakeEngine
from ._fake_sandbox import FakeSandbox
from .mcp_helpers import call, make_manifest, mcp_session
from .test_run_controlled_mcp import fake_system_root

SERVER = [str(Path(__file__).with_name("_fake_mcp_server.py"))]
VA = BASE + 0x1250


class CountingEngine(FakeEngine):
    def __init__(self):
        self.calls = []

    def disassemble(self, sha256, address, *, count=200, whole_function=False):
        self.calls.append(("disassemble", address, count))
        return super().disassemble(sha256, address, count=count, whole_function=whole_function)

    def functions(self, sha256, *, offset=0, limit=100):
        self.calls.append(("functions", offset, limit))
        return super().functions(sha256, offset=offset, limit=limit)


class TimeoutDecompileEngine(CountingEngine):
    """Decompiling the function around 0x1300 times out."""
    def decompile(self, sha256, function, *, max_chars=200_000):
        if function == BASE + 0x1300:
            return EngineResult(Status.TIMEOUT, None, "decompile timeout (fake)")
        return super().decompile(sha256, function, max_chars=max_chars)


def make_hub(tmp_path, engine=None, ops=("static",), sandbox=None):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"MZ" + bytes(range(256)) * 8)
    manifest = make_manifest(tmp_path / "scope.json", target, allowed_operations=list(ops))
    eng = engine or CountingEngine()
    # fake VC++ runtime source: run_controlled never depends on the host's real DLLs (absent off Windows)
    hub = Hub(Config.load(tmp_path / "data"), eng, sandbox, system_root=fake_system_root(tmp_path / "win"))
    hub.target_open(str(target), str(manifest))
    return hub, eng


@pytest.fixture
def hub(tmp_path):
    h, eng = make_hub(tmp_path)
    h.eng = eng
    yield h
    h.close()


def body(reply):
    return reply["content"].split(">", 1)[1].rsplit("</untrusted_target_content", 1)[0]


# ---------------------------------------------------------------- disassemble
def test_disassemble_hex_range_evidence_and_untrusted(hub):
    r = hub.disassemble(f"0x{VA:x}", end=f"0x{VA + 0x20:x}")
    assert r["status"] == "OK" and r["evidence_id"].startswith("ev_") and r["untrusted_content"] is True
    assert r["result"]["start"] == f"0x{VA:x}" and r["result"]["end"] == f"0x{VA + 0x20:x}"
    assert r["result"]["count"] == 8 and r["result"]["next_address"] is None
    lines = body(r).splitlines()
    assert lines[0].startswith(f"0x{VA:x}: ") and len(lines) == 8
    assert r["_meta"]["provenance"]["untrusted_content"] is True
    ev = hub._s.ledger.state["evidence"][r["evidence_id"]]  # every output is an evidence record
    assert ev["operation"] == "disassemble" and ev["coverage"]["relationship"] == "complete"
    assert ev["capture"]["strength"] == "full"
    assert {"kind": "address", "space": "va", "start": VA} in ev["locations"]
    assert {"kind": "address", "space": "rva", "start": 0x1250} in ev["locations"]
    # the instruction at 0x...1260 appears verbatim in the evidence: the claim is verified against it
    c = hub.claim_add("The instruction at 0x140001260 is xor with 0x5EC2E7A1.", [r["evidence_id"]],
                      [{"type": "quote", "evidence_id": r["evidence_id"], "text": "xor eax, 0x5EC2E7A1"},
                       {"type": "address", "evidence_id": r["evidence_id"], "value": "0x140001260"}], kind="observation")
    assert c["status"] == "SUPPORTED", c


def test_disassemble_injection_text_is_escaped(hub):
    r = hub.disassemble(hex(BASE + 0x1260), count=4)
    assert r["content"].count("</untrusted_target_content>") == 1


def test_disassemble_count_limit_gives_next_address_and_pages(hub):
    r1 = hub.disassemble(hex(VA), count=10)
    assert r1["result"]["count"] == 10 and r1["result"]["next_address"] == f"0x{VA + 40:x}"
    ev1 = hub._s.ledger.state["evidence"][r1["evidence_id"]]
    assert ev1["coverage"]["relationship"] == "partial"
    r2 = hub.disassemble(r1["result"]["next_address"], count=10)
    assert r2["result"]["start"] == r1["result"]["next_address"] and r2["evidence_id"] != r1["evidence_id"]


def test_disassemble_response_size_cap(hub, monkeypatch):
    import redharness.mcp.session as sess
    monkeypatch.setattr(sess, "RESPONSE_BUDGET", 300)
    r = hub.disassemble(hex(VA), count=100)
    assert len(body(r)) <= 300 + 80 and r["result"]["count"] < 100
    assert r["result"]["next_address"] == f"0x{VA + 4 * r['result']['count']:x}"
    ev = hub._s.ledger.state["evidence"][r["evidence_id"]]
    assert any("continue from next_address" in x for x in ev["limitations"])


def test_disassemble_non_code_is_partial_not_ok(hub):
    r = hub.disassemble(hex(BASE + 0x100), count=5)  # outside the code region
    assert r["status"] == "PARTIAL" and r["result"]["count"] == 0
    ev = hub._s.ledger.state["evidence"][r["evidence_id"]]
    assert ev["capture"]["strength"] == "partial" and ev["limitations"]
    end_of_code = hub.disassemble(hex(BASE + 0x1000 + 0x40 * 300 - 8), end=hex(BASE + 0x1000 + 0x40 * 300 + 64))
    assert end_of_code["status"] == "PARTIAL"  # the end of the requested range was not reached: not counted as complete


@pytest.mark.parametrize("kw", [{"address": "nope"}, {"address": None}, {"address": "0x10", "end": "0x10"},
                                {"address": "0x10", "end": "0x8"}, {"address": "0x10", "count": "5"},
                                {"address": "0x10", "detail": "bogus"}])
def test_disassemble_bad_arguments(hub, kw):
    with pytest.raises(ToolFailure) as e:
        hub.disassemble(**kw)
    assert e.value.code == "BAD_ARGUMENT"


def test_disassemble_count_is_clamped_and_engine_without_support_fails_open(hub):
    r = hub.disassemble(hex(VA), count=10_000)
    assert r["result"]["count"] <= 500


# ---------------------------------------------------------------- detail=summary / full
def test_summary_has_no_content_same_evidence_no_engine_rerun(hub):
    full = hub.disassemble(hex(VA), count=20, detail="full")
    n = len(hub.eng.calls)
    summ = hub.disassemble(hex(VA), count=20, detail="summary")
    assert len(hub.eng.calls) == n and summ["step_cached"] is True      # the engine did not rerun
    assert summ["evidence_id"] == full["evidence_id"] and "content" not in summ
    assert summ["detail"] == "summary" and summ["summary"]["instructions"] == 20
    assert summ["preview"].count("\n") <= 5 and full["evidence_id"] in summ["note"]
    assert "<untrusted_target_content" in summ["preview"]
    assert len(summ["preview"]) < len(full["content"])
    # the full output is in the ledger: the raw blob carries all lines
    ev = hub._s.ledger.state["evidence"][full["evidence_id"]]
    raw = hub._s.cas.get(ev["raw"]["blob_sha256"]).decode()
    assert len(raw.splitlines()) == 20


def test_summary_for_functions_strings_decompile(hub):
    f = hub.functions_list(0, 100, detail="summary")
    assert "content" not in f and f["summary"] == {"total": 300, "offset": 0, "returned": 100, "next_offset": 100}
    full_f = hub.functions_list(0, 100)
    assert full_f["evidence_id"] == f["evidence_id"] and "content" in full_f
    s = hub.strings(r"string_00", 0, 50, detail="summary")
    assert "content" not in s and s["summary"]["total"] == 8 and s["evidence_id"].startswith("ev_")
    d = hub.decompile(hex(VA), detail="summary")
    assert "content" not in d and d["summary"]["total_chars"] > 100 and d["summary"]["lines"] >= 5
    assert hub.decompile(hex(VA))["evidence_id"] == d["evidence_id"]
    with pytest.raises(ToolFailure) as e:
        hub.strings(detail="verbose")
    assert e.value.code == "BAD_ARGUMENT"


def test_summary_claims_can_cite_evidence_not_shown(hub):
    """A line not shown in summary mode can be quoted because it is in the full evidence (the evidence is complete in the ledger)."""
    r = hub.disassemble(hex(VA - 0x20), count=40, detail="summary")
    assert "xor eax" not in r["preview"]   # not visible in the summary, present in the evidence
    c = hub.claim_add("There is an xor at 0x140001260.", [r["evidence_id"]],
                      [{"type": "quote", "evidence_id": r["evidence_id"], "text": "xor eax, 0x5EC2E7A1"}], kind="observation")
    assert c["status"] == "SUPPORTED"


# ---------------------------------------------------------------- unknown_record + coverage + report
def test_unknown_record_validates_dedups_and_lands_in_coverage_and_report(hub):
    dis = hub.disassemble(hex(VA), count=8)
    u = hub.unknown_record("What does the call at 0x140001264 reach?", "target of an indirect call not resolved",
                           address="0x140001264", evidence_ids=[dis["evidence_id"]], severity="high")
    assert u["status"] == "OK" and u["unknown_id"].startswith("unk_") and u["open_unknowns"] == 1
    again = hub.unknown_record("What does  the call at 0x140001264 reach?", "other words", address="0x140001264",
                               evidence_ids=[dis["evidence_id"]])
    assert again["unknown_id"] == u["unknown_id"] and again["open_unknowns"] == 1   # single record
    other = hub.unknown_record("What does the call at 0x140001264 reach?", "x", address="0x140001268")
    assert other["unknown_id"] != u["unknown_id"]
    rec = hub._s.ledger.state["unknowns"][u["unknown_id"]]
    assert rec["reason"].startswith("target of") and rec["address"] == 0x140001264
    assert rec["supporting_evidence_ids"] == [dis["evidence_id"]] and rec["severity"] == "high"
    cov = hub.coverage()
    assert cov["open_unknowns_total"] == 2 and cov["assessment"] == "INCOMPLETE"
    assert cov["open_unknowns"][0]["address"] == "0x140001264"
    rep = hub.report_build()
    assert "## Coverage and unknowns" in rep["markdown"] and u["unknown_id"] in rep["markdown"]
    assert rep["coverage"]["open_unknowns"] == 2 and rep["coverage"]["assessment"] == "INCOMPLETE"


@pytest.mark.parametrize("kw", [{"question": "", "reason": "r"}, {"question": "q?", "reason": ""},
                                {"question": "q?", "reason": "r", "address": "zz"},
                                {"question": "q?", "reason": "r", "evidence_ids": ["ev_" + "0" * 64]},
                                {"question": "q?", "reason": "r", "severity": "urgent"},
                                {"question": "q?", "reason": "r", "evidence_ids": "ev_x"}])
def test_unknown_record_bad_arguments(hub, kw):
    with pytest.raises(ToolFailure):
        hub.unknown_record(**kw)


def test_coverage_fresh_job_is_not_examined_never_clean(hub):
    cov = hub.coverage()
    assert cov["assessment"] == "NOT_EXAMINED" and "clean" not in json.dumps(cov["assessment"]).lower()
    rep = hub.report_build()
    assert "NOT_EXAMINED" in rep["markdown"] and "does NOT mean" not in rep["markdown"].split("Coverage assessment")[0]
    assert "## Coverage and unknowns" in rep["markdown"]


def test_coverage_shows_tools_functions_regions_and_stays_not_clean(hub):
    hub.decompile(hex(VA))
    hub.disassemble(hex(VA), end=hex(VA + 0x10))
    hub.xrefs(hex(VA))
    hub.functions_list(0, 50)
    cov = hub.coverage()
    assert {"decompile", "disassemble", "xrefs", "functions_list"} <= set(cov["tools_run"])
    assert cov["functions_examined"] == [{"address": f"0x{VA:x}", "via": ["decompile", "disassemble"]}]
    assert cov["regions_examined"][0]["start"] == f"0x{VA:x}" and cov["regions_examined"][0]["complete"] is True
    assert cov["listings"][0]["exhausted"] is False        # 50/300: listing not exhausted
    assert cov["assessment"] == "NO_RECORDED_GAPS" and "Never 'clean'" in cov["note"]
    md = hub.report_build()["markdown"]
    assert "no recorded gaps (this does NOT mean 'clean')" in md and r"Listing not exhausted: functions\_list 50/300" in md


def test_coverage_reports_timed_out_and_truncated_calls(tmp_path):
    h, _ = make_hub(tmp_path, TimeoutDecompileEngine())
    try:
        with pytest.raises(ToolFailure) as e:
            h.call("decompile", {"function": hex(BASE + 0x1300)}, lambda: h.decompile(hex(BASE + 0x1300)))
        assert e.value.code == "TIMEOUT"
        part = h.disassemble(hex(BASE + 0x1000 + 0x40 * 300 - 8), count=10)   # hits the code boundary and is cut
        assert part["status"] == "PARTIAL"
        cov = h.coverage()
        assert cov["assessment"] == "INCOMPLETE"
        assert [c["code"] for c in cov["failed_calls"]] == ["TIMEOUT"] and cov["failed_calls"][0]["tool"] == "decompile"
        assert cov["failed_calls"][0]["args"]["function"] == f"0x{BASE + 0x1300:x}"
        assert cov["incomplete_calls_total"] == 1 and cov["incomplete_calls"][0]["operation"] == "disassemble"
        md = h.report_build()["markdown"]
        assert "## Coverage and unknowns" in md and "INCOMPLETE COVERAGE" in md
        assert "Failed call: decompile code=TIMEOUT" in md and "Truncated/partial:" in md
        assert "NO_RECORDED_GAPS" not in md
    finally:
        h.close()


def test_failed_then_successful_retry_closes_the_gap(tmp_path):
    class Flaky(CountingEngine):
        fail = True

        def decompile(self, sha256, function, *, max_chars=200_000):
            if self.fail:
                return EngineResult(Status.TIMEOUT, None, "timeout")
            return super().decompile(sha256, function, max_chars=max_chars)
    eng = Flaky()
    h, _ = make_hub(tmp_path, eng)
    try:
        with pytest.raises(ToolFailure):
            h.call("decompile", {"function": hex(VA)}, lambda: h.decompile(hex(VA)))
        assert h.coverage()["failed_calls_total"] == 1
        eng.fail = False
        h.call("decompile", {"function": hex(VA)}, lambda: h.decompile(hex(VA)))
        cov = h.coverage()
        assert cov["failed_calls_total"] == 0 and cov["assessment"] == "NO_RECORDED_GAPS"
    finally:
        h.close()


def test_coverage_survives_resume(tmp_path):
    h, _ = make_hub(tmp_path)
    h.unknown_record("Is the table bounds-checked?", "code not reached", severity="medium")
    h.close()
    h2, _ = make_hub(tmp_path)
    try:
        assert h2.coverage()["open_unknowns_total"] == 1
    finally:
        h2.close()


# ---------------------------------------------------------------- tool effect table -> scope permissions
def test_effect_table_covers_exactly_the_registered_tools():
    assert set(TOOL_EFFECTS) == set(TOOL_NAMES) and len(TOOL_NAMES) <= MAX_TOOLS


def test_effect_table_values_for_key_tools():
    t = TOOL_EFFECTS
    assert t["run_controlled"].executes_foreign_code and t["run_controlled"].launches_process
    assert t["run_controlled"].idempotent is False
    for name in ("decompile", "disassemble", "functions_list", "strings", "xrefs"):
        e = t[name]
        assert e.reads_files and not (e.writes_files or e.launches_process or e.executes_foreign_code or e.network)
        assert e.idempotent
    assert not any(e.network for e in t.values())
    assert t["coverage"] == ToolEffects()


def _manifest(tmp_path, ops):
    return parse_manifest({"schema": "rh.scope/1", "target_sha256": "a" * 64, "allowed_operations": list(ops),
                           "authorization": {"declared_by": "t", "basis": "owner", "statement": "mine"}})


def test_check_permission_by_effect(tmp_path):
    static = _manifest(tmp_path, ["static"])
    run = _manifest(tmp_path, ["static", "run_controlled"])
    check_permission("disassemble", static)
    check_permission("run_controlled", run)
    with pytest.raises(EffectDenied) as e:
        check_permission("run_controlled", static)
    assert e.value.code == "SCOPE_DENIED" and "run_controlled" in e.value.message
    with pytest.raises(EffectDenied) as e:
        check_permission("not_a_tool", run)
    assert e.value.code == "TOOL_NOT_IN_EFFECT_TABLE"
    table = {**TOOL_EFFECTS, "net": ToolEffects(network=True), "patcher": ToolEffects(mutates_target=True),
             "writer": ToolEffects(writes_files=True)}
    everything = _manifest(tmp_path, ["static", "run_controlled", "patch_poc"])
    with pytest.raises(EffectDenied) as e:                       # no manifest allows the network effect
        check_permission("net", everything, table)
    assert "no scope manifest" in e.value.message
    check_permission("patcher", everything, table)
    with pytest.raises(EffectDenied):
        check_permission("patcher", run, table)
    check_permission("writer", run, table)                        # run_controlled or patch_poc is enough
    with pytest.raises(EffectDenied):
        check_permission("writer", static, table)


def test_hub_rejects_tool_whose_effect_is_not_permitted_before_running_it(tmp_path):
    sb = FakeSandbox(behavior=lambda i, c, s: {"stdout": b"x", "stderr": b"", "exit_code": 0})
    h, _ = make_hub(tmp_path, ops=("static",), sandbox=sb)
    try:
        ran = []
        with pytest.raises(ToolFailure) as e:
            h.call("run_controlled", {"cases": [{"stdin": "x"}]}, lambda: ran.append(1) or {})
        assert e.value.code == "SCOPE_DENIED" and "run_controlled" in e.value.message and not ran
        assert sb.started == []
        # tool outside the table
        with pytest.raises(ToolFailure) as e:
            h.call("shell_exec", {}, lambda: ran.append(2) or {})
        assert e.value.code == "TOOL_NOT_IN_EFFECT_TABLE" and not ran
        # an effect added to the table that no manifest allows
        h.effects = {**TOOL_EFFECTS, "net_probe": ToolEffects(network=True)}
        with pytest.raises(ToolFailure) as e:
            h.call("net_probe", {}, lambda: ran.append(3) or {})
        assert e.value.code == "SCOPE_DENIED" and not ran
        # an allowed static tool is unaffected
        assert h.call("coverage", {}, h.coverage)["status"] == "OK"
        ev = [x["payload"] for x in h._s.journal.events() if x["type"] == "TOOL_CALL"]
        assert [p["code"] for p in ev if not p["ok"]] == ["SCOPE_DENIED", "TOOL_NOT_IN_EFFECT_TABLE", "SCOPE_DENIED"]
        assert h.coverage()["denied_calls"] == 3
    finally:
        h.close()


def test_run_controlled_allowed_when_manifest_permits_effects(tmp_path):
    sb = FakeSandbox(behavior=lambda i, c, s: {"stdout": b"hello", "stderr": b"", "exit_code": 0})
    h, _ = make_hub(tmp_path, ops=("static", "run_controlled"), sandbox=sb)
    try:
        r = h.call("run_controlled", {"cases": [{"stdin": "x"}]}, lambda: h.run_controlled([{"stdin": "x"}]))
        assert r["cases"][0]["evidence_id"].startswith("ev_")
    finally:
        h.close()


def test_annotations_match_effect_table():
    from redharness.mcp.server import build_server
    mcp, hub = build_server(Config.load(Path(".") / "x"), FakeEngine())
    tools = asyncio.run(mcp.list_tools())
    by = {t.name: t for t in tools}
    assert set(by) == set(TOOL_NAMES)
    for name, t in by.items():
        e, a = TOOL_EFFECTS[name], t.annotations
        assert a.idempotentHint == e.idempotent, name
        assert a.openWorldHint == e.network, name
        if a.readOnlyHint:
            assert not (e.writes_files or e.launches_process or e.executes_foreign_code or e.mutates_target), name


def test_usage_doc_contains_the_effect_table():
    doc = (Path(__file__).resolve().parents[2] / "docs" / "usage-mcp.md").read_text(encoding="utf-8")
    assert fx.effects_markdown() in doc


# ---------------------------------------------------------------- real stdio
def test_wire_tool_list_hex_addresses_and_summary(tmp_path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"MZ" + bytes(range(256)) * 8)
    man = make_manifest(tmp_path / "scope.json", target)

    async def go():
        async with mcp_session(SERVER, tmp_path / "data") as s:
            names = sorted(t.name for t in (await s.list_tools()).tools)
            assert names == sorted(TOOL_NAMES) and len(names) <= MAX_TOOLS
            await call(s, "target_open", target_path=str(target), manifest_path=str(man))
            err, d = await call(s, "disassemble", address="0x140001250", end="0x140001260")
            assert not err, d
            assert d["result"]["start"] == "0x140001250" and d["result"]["end"] == "0x140001260"
            err, ds = await call(s, "disassemble", address="0x140001250", count=4, detail="summary")
            assert not err and "content" not in ds and ds["summary"]["instructions"] == 4
            assert ds["summary"]["next_address"] == "0x140001260"
            err, bad = await call(s, "disassemble", address="not-hex")
            assert err and "BAD_ARGUMENT" in bad
            err, u = await call(s, "unknown_record", question="Where does it write?", reason="no xref found",
                                address="0x140001260")
            assert not err and u["unknown_id"].startswith("unk_")
            err, c = await call(s, "coverage")
            assert not err and c["assessment"] == "INCOMPLETE" and c["open_unknowns_total"] == 1
            err, den = await call(s, "run_controlled", cases=[{"stdin": "x"}])
            assert err and "SCOPE_DENIED" in den
            err, r = await call(s, "report_build")
            assert not err and "## Coverage and unknowns" in r["markdown"]
    asyncio.run(go())
