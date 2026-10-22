"""functions_list(engines='both'): where two engines disagree about function boundaries, with synthetic engines.

Two fake engines ("ida", "ghidra") serve scripted function layouts of the same target. The classification itself
(analysis/engine_disagreement.py) is checked on hand-made inventories; the tool path (evidence per engine, both ids on
every row, coverage states, report section, schema) through the Hub."""
import hashlib
import json
import re
from pathlib import Path

import pytest

from redharness.analysis import engine_disagreement as ed
from redharness.config import Config
from redharness.core.result import Status
from redharness.engines.base import Disassembly, EngineResult, FunctionInfo, InsnInfo, Page, TargetInfo
from redharness.mcp.session import Hub, ToolFailure

from ._fake_engine import BASE, FakeEngine
from .mcp_helpers import make_manifest
from .test_run_controlled_mcp import fake_system_root

B = BASE


def fn(start, name, *ranges, insns=None):
    return ed.EngineFunc(B + start, name, tuple((B + a, B + b) for a, b in ranges),
                         insns if insns is not None else sum((b - a) // 4 for a, b in ranges))


def inv(engine, *funcs, extents=True, note=""):
    return ed.Inventory(engine, tuple(funcs), extents, note)


# ------------------------------------------------------------------------------------------------ classification

def test_every_category_and_the_agreed_count():
    ida = inv("ida",
              fn(0x1000, "sub_140001000", (0x1000, 0x1040)),                 # agrees
              fn(0x1100, "sub_140001100", (0x1100, 0x1140)),                 # ends differ
              fn(0x1200, "sub_140001200", (0x1200, 0x1240)),                 # only in ida (nothing of ghidra's holds it)
              fn(0x1300, "MyName", (0x1300, 0x1340)),                        # names differ
              fn(0x1400, "sub_140001400", (0x1400, 0x1460)),                 # ghidra splits it at 0x1430
              fn(0x1500, "NamedByIda", (0x1500, 0x1520)))                    # ghidra has a generated name
    ghi = inv("ghidra",
              fn(0x1000, "FUN_140001000", (0x1000, 0x1040)),
              fn(0x1100, "FUN_140001100", (0x1100, 0x1148)),
              fn(0x1300, "YourName", (0x1300, 0x1340)),
              fn(0x1400, "FUN_140001400", (0x1400, 0x1430)),
              fn(0x1430, "FUN_140001430", (0x1430, 0x1460)),
              fn(0x1500, "FUN_140001500", (0x1500, 0x1520)),
              fn(0x1700, "FUN_140001700", (0x1700, 0x1710)))                 # only in ghidra
    d = ed.classify(ida, ghi)
    assert (d.a, d.b, d.state) == ("ghidra", "ida", ed.BOTH_ENGINES)          # engines are ordered by name
    assert d.counts == {"END_DIFFERS": 2, "ONLY_IN_ONE": 2, "SPLIT_MERGED": 1, "NAME_DIFFERS": 1}
    assert (d.common, d.agreed, d.functions) == (5, 2, {"ghidra": 7, "ida": 6})
    assert d.named_only_by == {"ghidra": 0, "ida": 1}
    by = {(r.category, r.start - B): r for r in d.rows}
    assert ("END_DIFFERS", 0x1100) in by and ("NAME_DIFFERS", 0x1300) in by
    assert by["ONLY_IN_ONE", 0x1200].has == "b" and by["ONLY_IN_ONE", 0x1700].has == "a"      # b = ida, a = ghidra
    split = by["SPLIT_MERGED", 0x1430]
    assert split.has == "a" and split.container.start == B + 0x1400                          # ghidra's, inside ida's
    assert by["END_DIFFERS", 0x1400].explained_by == (B + 0x1430,)                           # the same disagreement
    assert d.explained_end_differs == 1 and d.only_in["SPLIT_MERGED"] == {"ghidra": 1, "ida": 0}
    assert [r.category for r in d.rows] == sorted((r.category for r in d.rows), key=ed.CATEGORIES.index)


def test_a_chunk_of_one_function_is_the_other_engines_split_function():
    ida = inv("ida", fn(0x1000, "sub_140001000", (0x1000, 0x1020), (0x2000, 0x2010)))
    ghi = inv("ghidra", fn(0x1000, "FUN_140001000", (0x1000, 0x1020)), fn(0x2000, "FUN_140002000", (0x2000, 0x2010)))
    d = ed.classify(ida, ghi)
    assert d.counts["SPLIT_MERGED"] == 1 and d.counts["END_DIFFERS"] == 1 and d.counts["ONLY_IN_ONE"] == 0
    row = next(r for r in d.rows if r.category == "SPLIT_MERGED")
    assert row.start == B + 0x2000 and row.container.name == "sub_140001000"


def test_names_compare_only_real_names():
    assert not ed.names_differ("sub_140001000", "FUN_140001000")
    assert not ed.names_differ("sub_140001000", "RealName") and not ed.names_differ("", "RealName")
    assert not ed.names_differ("FID_conflict:StringCchCopyW", "StringCchCopyW")
    assert ed.names_differ("_tlgWriteTransfer_EtwWriteTransfer", "_tlgWriteTransfer_EventWriteTransfer")


def test_without_extents_only_starts_and_names_are_compared():
    a = inv("ida", fn(0x1000, "A", (0x1000, 0x1040)), fn(0x1100, "B", (0x1100, 0x1140)))
    g = inv("ghidra", ed.EngineFunc(B + 0x1000, "A"), ed.EngineFunc(B + 0x1110, "C"), extents=False,
            note="bulk disassembly failed")
    d = ed.classify(a, g)
    assert d.state == ed.BOTH_STARTS_ONLY and d.counts["END_DIFFERS"] == d.counts["SPLIT_MERGED"] == 0
    assert d.counts["ONLY_IN_ONE"] == 2 and "bulk disassembly failed" in d.limitations[0]


def test_a_function_without_instructions_has_no_end_but_does_not_drop_the_comparison():
    a = inv("ida", fn(0x1000, "A", (0x1000, 0x1040)), fn(0x1100, "B", (0x1100, 0x1140)))
    g = inv("ghidra", ed.EngineFunc(B + 0x1000, "A"),                         # forwarded-export record: no instructions
            fn(0x1100, "B", (0x1100, 0x1148)), ed.EngineFunc(B + 0x2000, "Fwd"))
    d = ed.classify(a, g)
    assert d.state == ed.BOTH_ENGINES and (g.unmeasured, a.unmeasured) == (2, 0)
    assert d.counts == {"END_DIFFERS": 1, "ONLY_IN_ONE": 1, "SPLIT_MERGED": 0, "NAME_DIFFERS": 0} and d.agreed == 1
    assert "ghidra 2" in d.limitations[0] and "ida 0" in d.limitations[0]


def test_an_overlapping_function_is_found_by_its_lowest_start():
    find = ed._locator([fn(0x1000, "big", (0x1000, 0x1800)), fn(0x1100, "inner", (0x1100, 0x1120))])
    assert find(B + 0x1110).name == "big" and find(B + 0x1790).name == "big" and find(B + 0x1800) is None


def test_the_row_names_both_evidence_ids_and_both_sides():
    ida = inv("ida", fn(0x1100, "sub_140001100", (0x1100, 0x1140)))
    ghi = inv("ghidra", fn(0x1100, "FUN_140001100", (0x1100, 0x1148)))
    line = ed.row_line(ed.classify(ida, ghi).rows[0], "ghidra", "ida", "ev_g", "ev_i")
    assert line.startswith("END_DIFFERS start=0x140001100 ghidra:name=FUN_140001100 end=0x140001148 ")
    assert "ida:name=sub_140001100 end=0x140001140" in line and "end_delta=-8" in line
    assert line.rstrip().endswith("ghidra_ev=ev_g ida_ev=ev_i")


# ------------------------------------------------------------------------------------------------ the tool

class LayoutEngine(FakeEngine):
    """Serves a scripted function layout (the base class default bulk path: functions page + whole-function disassembly)."""

    def __init__(self, name, funcs, version="1.0", fail_open=False):
        self.name, self.funcs, self.version, self.fail_open, self.opened = name, funcs, version, fail_open, 0

    def probe(self):
        from redharness.engines.base import EngineInfo
        return EngineInfo(self.name, True, self.version, "scripted")

    def open_target(self, path):
        self.opened += 1
        if self.fail_open:
            return EngineResult(Status.ERROR, None, "analysis failed")
        sha = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        return EngineResult(Status.OK, TargetInfo(sha, str(path), "metapc", 64, B + 0x1000, len(self.funcs), 0, True, B))

    def functions(self, sha256, *, offset=0, limit=100):
        rows = self.funcs[offset:offset + limit]
        items = [FunctionInfo(f.start, f.name, 0) for f in rows]
        return EngineResult(Status.OK, Page(items, len(self.funcs), offset, offset + len(items) < len(self.funcs)))

    def disassemble(self, sha256, address, *, count=200, whole_function=False):
        f = next(x for x in self.funcs if x.start == address or any(lo <= address < hi for lo, hi in x.ranges))
        items = [InsnInfo(a, 4, "90909090", "nop", (), "nop") for lo, hi in f.ranges for a in range(lo, hi, 4)]
        return EngineResult(Status.OK, Disassembly(items, f.start, f.name, len(items), True, ""))


IDA = [fn(0x1000, "sub_140001000", (0x1000, 0x1040)), fn(0x1100, "sub_140001100", (0x1100, 0x1140)),
       fn(0x1200, "OnlyIda", (0x1200, 0x1240)), fn(0x1400, "sub_140001400", (0x1400, 0x1460))]
GHIDRA = [fn(0x1000, "FUN_140001000", (0x1000, 0x1040)), fn(0x1100, "FUN_140001100", (0x1100, 0x1148)),
          fn(0x1400, "FUN_140001400", (0x1400, 0x1430)), fn(0x1430, "FUN_140001430", (0x1430, 0x1460))]


def make(tmp_path, second="ghidra", ghidra_fail=False):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"MZ" + bytes(range(256)) * 8)
    manifest = make_manifest(tmp_path / "scope.json", target, allowed_operations=["static"])
    ida = LayoutEngine("ida", IDA, "9.4")
    ghi = LayoutEngine("ghidra", GHIDRA, "12.1.3", fail_open=ghidra_fail) if second else None
    hub = Hub(Config.load(tmp_path / "data"), ida, None, system_root=fake_system_root(tmp_path / "win"),
              second_engine=ghi)
    hub.target_open(str(target), str(manifest))
    return hub, ida, ghi


def body(reply):
    return reply["content"].split(">", 1)[1].rsplit("</untrusted_target_content", 1)[0]


@pytest.fixture
def both(tmp_path):
    hub, ida, ghi = make(tmp_path)
    yield hub, ida, ghi
    hub.close()


def test_both_engines_give_counts_rows_and_both_evidence_ids(both):
    hub, ida, ghi = both
    r = hub.functions_list(0, 100, "full", None, "both")
    assert r["status"] == "OK" and r["result"]["state"] == "BOTH_ENGINES"
    assert r["result"]["counts"] == {"END_DIFFERS": 2, "ONLY_IN_ONE": 1, "SPLIT_MERGED": 1, "NAME_DIFFERS": 0}
    assert r["result"]["agreed"] == 1 and r["result"]["common"] == 3
    ids = {n: e["evidence_id"] for n, e in r["result"]["engine_status"].items()}
    assert set(ids) == {"ida", "ghidra"} and r["evidence_id"] not in ids.values()
    text = body(r)
    rows = [ln for ln in text.splitlines() if not ln.startswith("#")]
    assert [ln.split()[0] for ln in rows] == ["END_DIFFERS", "END_DIFFERS", "ONLY_IN_ONE", "SPLIT_MERGED"]
    assert all(f"ghidra_ev={ids['ghidra']} ida_ev={ids['ida']}" in ln for ln in rows)
    assert "state=BOTH_ENGINES" in text and "END_DIFFERS=2 ONLY_IN_ONE=1 SPLIT_MERGED=1 NAME_DIFFERS=0" in text
    # each inventory evidence is that engine's own list: one quotable line per function, bound to the job target
    st = hub._s.ledger.state["evidence"]
    for name, eng in (("ida", ida), ("ghidra", ghi)):
        e = st[ids[name]]
        assert e["operation"] == "functions_list" and e["subject"]["sha256"] == hub._s.sha
        assert e["parameters"] == {"engines": "both", "engine": name} and e["source"]["engine"] == name
        assert e["result"]["function_count"] == len(eng.funcs) and e["result"]["extents"] is True
        assert (st[ids[name]]["capture"]["strength"]) == "full"
    raw = hub._s.cas.get(st[ids["ida"]]["raw"]["blob_sha256"]).decode()
    assert f"0x{B + 0x1200:x} OnlyIda end=0x{B + 0x1240:x} insns=16 chunks=1\n" in raw
    cmp_ev = st[r["evidence_id"]]
    assert cmp_ev["parameters"] == {"offset": 0, "limit": 100, "engines": "both"}
    assert cmp_ev["source"]["engine"] == "ghidra+ida" and cmp_ev["coverage"]["relationship"] == "complete"


def test_a_claim_can_quote_a_row_and_an_inventory_line(both):
    hub, _, _ = both
    r = hub.functions_list(0, 100, "full", None, "both")
    ids = [e["evidence_id"] for e in r["result"]["engine_status"].values()]
    row = next(ln for ln in body(r).splitlines() if ln.startswith("ONLY_IN_ONE"))
    c = hub.claim_add(f"Only one engine defines a function at 0x{B + 0x1200:x}: OnlyIda.", [r["evidence_id"], *ids],
                      [{"type": "quote", "evidence_id": r["evidence_id"], "text": f"ONLY_IN_ONE start=0x{B + 0x1200:x}"},
                       {"type": "address", "evidence_id": r["evidence_id"], "value": f"0x{B + 0x1200:x}"}],
                      "observation", "present", "SUPPORTED")
    assert c["status"] == "SUPPORTED", c
    assert "ida:name=OnlyIda" in row and "ghidra=-" in row


def test_the_second_call_runs_no_engine_and_paging_keeps_the_counts(both):
    hub, ida, ghi = both
    first = hub.functions_list(0, 1, "full", None, "both")
    assert first["result"]["returned"] == 1 and first["result"]["next_offset"] == 1
    assert first["result"]["counts"]["END_DIFFERS"] == 2                      # counts are of the whole comparison
    n = (ida.opened, ghi.opened)
    rest = hub.functions_list(1, 100, "full", None, "both")
    assert rest["result"]["returned"] == 3 and rest["result"]["next_offset"] is None and rest["step_cached"] is False
    assert (ida.opened, ghi.opened) == n                                       # inventories came from the step cache
    again = hub.functions_list(0, 1, "full", None, "both")
    assert again["step_cached"] is True and again["evidence_id"] == first["evidence_id"]
    assert (ida.opened, ghi.opened) == n
    cov = hub._coverage_data(hub._s)
    li = [x for x in cov["listings"] if x["tool"] == "functions_list"]
    assert len(li) == 1 and li[0]["exhausted"] is True                         # its own listing, not the plain function list


def test_summary_detail_and_an_ordinary_listing_are_unchanged(both):
    hub, _, _ = both
    s = hub.functions_list(0, 100, "summary", None, "both")
    assert s["detail"] == "summary" and s["summary"]["counts"]["ONLY_IN_ONE"] == 1 and "content" not in s
    assert len(s["summary"]["inventory_evidence"]) == 2
    plain = hub.functions_list(0, 5, "full")
    assert hub._s.ledger.state["evidence"][plain["evidence_id"]]["parameters"] == {"offset": 0, "limit": 5}


def test_bad_arguments(both):
    hub, _, _ = both
    with pytest.raises(ToolFailure) as e:
        hub.functions_list(0, 10, "full", None, "ida")
    assert e.value.code == "BAD_ARGUMENT"
    with pytest.raises(ToolFailure) as e:
        hub.functions_list(0, 10, "full", "fixed", "both")
    assert e.value.code == "BAD_ARGUMENT"


@pytest.mark.parametrize("variant", ["no_second", "open_fails"])
def test_one_engine_is_partial_and_says_nothing_was_compared(tmp_path, variant):
    hub, ida, ghi = make(tmp_path, second=None if variant == "no_second" else "ghidra",
                         ghidra_fail=variant == "open_fails")
    try:
        r = hub.functions_list(0, 100, "full", None, "both")
        assert r["status"] == "PARTIAL" and r["result"]["state"] == "ONE_ENGINE" and r["result"]["counts"] is None
        status = r["result"]["engine_status"]
        assert status["ida"]["ran"] is True
        miss = next(e for n, e in status.items() if n != "ida")
        assert miss["ran"] is False and miss["reason"]
        text = body(r)
        assert "state=ONE_ENGINE" in text and "unknown, not agreement" in text
        ev = hub._s.ledger.state["evidence"][r["evidence_id"]]
        assert ev["coverage"]["relationship"] == "partial"
        cov = hub._coverage_data(hub._s)
        assert any(c["evidence_id"] == r["evidence_id"] for c in cov["incomplete_calls"])   # a gap, never "clean"
        rep = hub.report_build("both")
        block = rep["report_json"]["engine_disagreement"]
        assert block["state"] == "ONE_ENGINE" and block["counts"] is None
        assert "Only ida ran" in rep["markdown"] and "unknown, not agreement" in rep["markdown"]
    finally:
        hub.close()


def test_the_report_carries_one_engine_disagreement_section_from_the_same_document(both):
    jsonschema = pytest.importorskip("jsonschema")
    hub, _, _ = both
    plain = hub.report_build("both")
    assert "engine_disagreement" not in plain["report_json"] and "Engine disagreement" not in plain["markdown"]
    r = hub.functions_list(0, 100, "full", None, "both")
    rep = hub.report_build("both")
    doc = rep["report_json"]
    block = doc["engine_disagreement"]
    assert block["evidence_id"] == r["evidence_id"] and block["state"] == "BOTH_ENGINES"
    assert block["counts"] == r["result"]["counts"] and block["engines"] == ["ghidra", "ida"]
    assert block["engine_status"]["ida"]["functions"] == 4 and block["named_only_by"] == {"ghidra": 0, "ida": 0}
    md = rep["markdown"]
    assert "## Engine disagreement" in md and md.index("## Engine disagreement") < md.index("## Coverage and unknowns")
    assert ("END_DIFFERS 2; ONLY_IN_ONE 1 (the function is defined by: ida 1); "
            "SPLIT_MERGED 1 (the function is defined by: ghidra 1); NAME_DIFFERS 0") in md
    assert f"comparison `{r['evidence_id']}`" in md and "neither engine is trusted" in md
    schema = json.loads((Path(__file__).resolve().parents[2] / "docs" / "schema" / "rh.report.1.schema.json")
                        .read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(doc)
    assert re.search(r"state BOTH_ENGINES|coverage state BOTH_ENGINES", md)


def test_the_tool_is_an_option_of_functions_list_and_the_server_passes_it(tmp_path):
    import asyncio
    from redharness.mcp import server
    mcp, hub = server.build_server(Config.load(tmp_path / "x"), FakeEngine())
    try:
        tools = {t.name: t for t in asyncio.run(mcp.list_tools())}
    finally:
        hub.close()
    props = tools["functions_list"].inputSchema["properties"]
    assert "engines" in props and len(tools) <= server.MAX_TOOLS
    assert "ONE_ENGINE" in tools["functions_list"].description
