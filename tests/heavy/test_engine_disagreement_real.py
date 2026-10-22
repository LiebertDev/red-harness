"""REAL proof for `functions_list(engines="both")`: IDA and Ghidra on the same system binaries, through the full MCP path
(target_open, evidence per engine, comparison evidence, claim, report).

Targets: notepad.exe and kernel32.dll (copies of the Windows system files). Skipped when either engine or a target is absent.

Ground truth is computed INDEPENDENTLY of the classifier, from the evidence the tool recorded and from the PE file:
- the per-engine inventory evidence (one line per function) is parsed with plain string code; the number of starts only
  one engine defines equals ONLY_IN_ONE + SPLIT_MERGED, the number of common starts whose `end=` differ equals
  END_DIFFERS, and common = agreed + END_DIFFERS + NAME_DIFFERS;
- the engines themselves confirm rows: for sampled SPLIT_MERGED rows the container engine's own whole-function disassembly
  contains the start address; for sampled ONLY_IN_ONE rows the other engine's own `disassemble` at that start does not
  begin a function there;
- the PE exception directory (.pdata RUNTIME_FUNCTION begin / end) is a third source: how many of the disagreeing starts it
  knows, and which engine's end it matches for END_DIFFERS rows (reported, not asserted: it is a different notion of end).

The counts are printed (and written as JSON when RH_DISAGREEMENT_OUT names a file) so a run is a recorded disagreement list.
"""
from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path

import pytest

from redharness.config import Config
from redharness.mcp.session import Hub

from tests.unit.mcp_helpers import make_manifest

from ._pe_pdata import parse_pdata

pytestmark = pytest.mark.heavy

SYSTEM32 = Path(r"C:\Windows\System32")
TARGETS = ("notepad.exe", "kernel32.dll")
LINE = re.compile(r"^0x([0-9a-f]+) (.*) end=(0x[0-9a-f]+|\?) insns=(\d+) chunks=(\d+)$")
SAMPLE = 6


def _engine(which: str, root: Path):
    cfg = Config.load(root)
    if which == "ghidra":
        from redharness.engines.ghidra import GhidraEngine
        eng = GhidraEngine(cfg)
    else:
        from redharness.engines.ida import IdaEngine
        eng = IdaEngine(cfg)
    info = eng.probe()
    if not info.available:
        pytest.skip(f"{which} unavailable: {info.detail}")
    return eng


def _inventory(hub, ev_id):
    """{start: (name, end or None)} parsed from the inventory evidence text."""
    st = hub._s.ledger.state["evidence"][ev_id]
    out = {}
    for ln in hub._s.cas.get(st["raw"]["blob_sha256"]).decode("utf-8").splitlines():
        m = LINE.match(ln)
        assert m, ln
        out[int(m.group(1), 16)] = (m.group(2), None if m.group(3) == "?" else int(m.group(3), 16))
    return out


def _body(reply):
    return reply["content"].split(">", 1)[1].rsplit("</untrusted_target_content", 1)[0]


def _run(name: str, primary: str, heavy_data_root: Path, tmp_path: Path):
    src = SYSTEM32 / name
    if not src.is_file():
        pytest.skip(f"{name} not found")
    exe = tmp_path / name
    shutil.copyfile(src, exe)
    other = "ghidra" if primary == "ida" else "ida"
    first, second = _engine(primary, heavy_data_root), _engine(other, heavy_data_root)
    manifest = make_manifest(tmp_path / "scope.json", exe)
    hub = Hub(Config.load(tmp_path / "data"), first, None, second_engine=second)
    opened = hub.target_open(str(exe), str(manifest), None, "summary")
    assert opened["status"] == "OK", opened
    return hub, exe, {primary: first, other: second}


def _page_all(hub):
    """(first page, every row line, {row line: evidence id of the page that shows it})."""
    rows, page_of, off, first = [], {}, 0, None
    while True:
        r = hub.call("functions_list", {"engines": "both", "offset": off},
                     lambda off=off: hub.functions_list(off, 200, "full", None, "both"))
        first = first or r
        got = [ln for ln in _body(r).splitlines() if not ln.startswith("#")]
        rows += got
        page_of.update({ln: r["evidence_id"] for ln in got})
        if r["result"]["next_offset"] is None:
            return first, rows, page_of
        off = r["result"]["next_offset"]


@pytest.mark.parametrize("name", TARGETS)
def test_ida_and_ghidra_disagreements_are_classified_and_independently_recounted(name, heavy_data_root, tmp_path):
    hub, exe, engines = _run(name, "ida", heavy_data_root, tmp_path)
    try:
        first, rows, page_of = _page_all(hub)
        res = first["result"]
        assert first["status"] == "OK" and res["state"] == "BOTH_ENGINES", res
        counts = res["counts"]
        assert res["rows"] == sum(counts.values()) == len(rows) and res["engines"] == ["ghidra", "ida"]
        ids = {n: e["evidence_id"] for n, e in res["engine_status"].items()}
        assert set(ids) == {"ida", "ghidra"} and all(e["extents"] for e in res["engine_status"].values())
        assert all(f"ghidra_ev={ids['ghidra']} ida_ev={ids['ida']}" in ln for ln in rows)
        # independent recount from the two inventory evidences
        inv = {n: _inventory(hub, ids[n]) for n in ids}
        assert {n: len(v) for n, v in inv.items()} == res["functions"]
        both, only = set(inv["ida"]) & set(inv["ghidra"]), set(inv["ida"]) ^ set(inv["ghidra"])
        ends_differ = {a for a in both if None not in (inv["ida"][a][1], inv["ghidra"][a][1])
                       and inv["ida"][a][1] != inv["ghidra"][a][1]}   # a function without instructions has no end
        assert res["common"] == len(both) and counts["ONLY_IN_ONE"] + counts["SPLIT_MERGED"] == len(only)
        assert counts["END_DIFFERS"] == len(ends_differ)
        assert res["common"] == res["agreed"] + counts["END_DIFFERS"] + counts["NAME_DIFFERS"]
        starts = {cat: {int(re.search(r"start=0x([0-9a-f]+)", ln).group(1), 16) for ln in rows if ln.startswith(cat)}
                  for cat in counts}
        assert starts["END_DIFFERS"] == ends_differ and starts["ONLY_IN_ONE"] | starts["SPLIT_MERGED"] == only
        # the engines confirm sampled rows with their OWN disassembly (not the bulk run the inventory used)
        sha = hub._s.sha
        for a in sorted(starts["SPLIT_MERGED"])[:SAMPLE]:
            row = next(ln for ln in rows if ln.startswith("SPLIT_MERGED") and f"start=0x{a:x} " in ln)
            m = re.search(r"container=(\w+):0x([0-9a-f]+)\.\.", row)
            holder, cstart = engines[m.group(1)], int(m.group(2), 16)
            d = holder.disassemble(sha, cstart, count=20_000, whole_function=True)
            assert d.data is not None and a in {i.address for i in d.data.items}, row
        for a in sorted(starts["ONLY_IN_ONE"])[:SAMPLE]:
            row = next(ln for ln in rows if ln.startswith("ONLY_IN_ONE") and f"start=0x{a:x} " in ln)
            lacks = "ghidra" if "ghidra=-" in row else "ida"
            d = engines[lacks].disassemble(sha, a, count=4)
            assert d.data is None or d.data.function_address != a, row
        # third source: .pdata
        _, pdata = parse_pdata(exe)
        primary_starts = {e["begin"]: e for e in pdata if not e["chained"]}
        ends = {"ghidra": 0, "ida": 0, "neither": 0, "no_pdata": 0}
        for a in ends_differ:
            e = primary_starts.get(a)
            if e is None:
                ends["no_pdata"] += 1
            else:
                hit = [n for n in ("ghidra", "ida") if inv[n][a][1] is not None and inv[n][a][1] >= e["end"] >= inv[n][a][1] - 16]
                ends[hit[0] if len(hit) == 1 else "neither"] += 1
        summary = {"target": name, "sha256": hub._s.sha, "engine_versions": {n: e.probe().version for n, e in engines.items()},
                   "functions": res["functions"], "common": res["common"], "agreed": res["agreed"], "counts": counts,
                   "only_in": res["only_in"], "named_only_by": res["named_only_by"],
                   "explained_end_differs": res["explained_end_differs"],
                   "only_in_one_or_split_starts_in_pdata": sum(1 for a in only if a in primary_starts),
                   "end_differs_pdata_end_within_16_bytes_of": ends}
        print("\nDISAGREEMENT", json.dumps(summary, sort_keys=True))
        out = os.environ.get("RH_DISAGREEMENT_OUT")
        if out:
            with open(out, "a", encoding="utf-8") as f:
                f.write(json.dumps(summary, sort_keys=True) + "\n")
        # a claim quotes a row of the comparison; the report carries the same numbers
        pick = next((c for c in ("ONLY_IN_ONE", "SPLIT_MERGED", "END_DIFFERS") if starts[c]), None)
        if pick:
            a = min(starts[pick])
            page = page_of[next(ln for ln in rows if ln.startswith(pick) and f"start=0x{a:x} " in ln)]
            c = hub.claim_add(f"The two engines disagree about the function boundary at 0x{a:x} ({pick}).",
                              [page, *ids.values()],
                              [{"type": "quote", "evidence_id": page, "text": f"{pick} start=0x{a:x}"},
                               {"type": "address", "evidence_id": page, "value": f"0x{a:x}"}],
                              "observation", "present", "SUPPORTED")
            assert c["status"] == "SUPPORTED", c
        rep = hub.report_build("both")
        block = rep["report_json"]["engine_disagreement"] if not rep.get("report_json_truncated") else None
        if block is not None:
            assert block["counts"] == counts and block["state"] == "BOTH_ENGINES"
        assert "## Engine disagreement" in rep["markdown"]
    finally:
        hub.close()


def test_the_counts_do_not_depend_on_which_engine_is_the_job_engine(heavy_data_root, tmp_path):
    (tmp_path / "a").mkdir()
    a, _, _ = _run("notepad.exe", "ida", heavy_data_root, tmp_path / "a")
    try:
        ra = a.functions_list(0, 5, "full", None, "both")["result"]
    finally:
        a.close()
    (tmp_path / "b").mkdir()
    b, _, _ = _run("notepad.exe", "ghidra", heavy_data_root, tmp_path / "b")
    try:
        rb = b.functions_list(0, 5, "full", None, "both")["result"]
    finally:
        b.close()
    keys = ("state", "engines", "functions", "common", "agreed", "counts", "only_in", "named_only_by")
    assert {k: ra[k] for k in keys} == {k: rb[k] for k in keys}
