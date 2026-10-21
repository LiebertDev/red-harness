"""IDA <-> Ghidra comparison: function counts and start addresses on the same binary.

Expected explanation of a count difference: Ghidra also lists import stubs in the External space (records that are not
in the code and have fake addresses). The remaining difference (a few functions) is classified with an independent third
source (.pdata RUNTIME_FUNCTION).

The test leaves no unclassified difference: every unexplained difference BREAKS the test (-> an `unknown_record` must be opened).
"""
import bisect
import json

import pytest

from redharness.config import Config
from redharness.engines.ghidra import GhidraEngine
from redharness.engines.ida import IdaEngine

from ._pe_pdata import parse_pdata

pytestmark = pytest.mark.heavy
SMALL_STUB = 32  # upper bound (bytes) for artificial small functions IDA carves out and Ghidra does not


@pytest.fixture(scope="module")
def both(heavy_data_root, notepad_copy):
    cfg = Config.load(heavy_data_root)
    ida, ghi = IdaEngine(cfg), GhidraEngine(cfg)
    if not ida.probe().available:
        pytest.skip(f"IDA unavailable: {ida.probe().detail}")
    if not ghi.probe().available:
        pytest.skip(f"Ghidra unavailable: {ghi.probe().detail}")
    ri, rg = ida.open_target(notepad_copy), ghi.open_target(notepad_copy)
    assert ri.ok, ri.detail
    assert rg.ok, rg.detail
    assert ri.data.sha256 == rg.data.sha256  # same binary
    sha = ri.data.sha256
    ida_rows = {f.address: f for f in ida.functions(sha, limit=1_000_000).data.items}
    gdir = ghi._tdir(ghi.probe().version, sha)
    ghi_rows = {r["address"]: r for r in json.loads((gdir / "functions.json").read_text(encoding="utf-8"))}
    meta = json.loads((gdir / "meta.json").read_text(encoding="utf-8"))
    _, pdata = parse_pdata(notepad_copy)
    return {"ida": ida_rows, "ghidra": ghi_rows, "ext": meta["info"]["external_function_count"], "pdata": pdata}


def test_counts_reconcile_and_every_difference_is_classified(both):
    I, G, ext, pdata = both["ida"], both["ghidra"], both["ext"], both["pdata"]
    pd_primary = {e["begin"] for e in pdata if not e["chained"]}
    pd_chained = {e["begin"] for e in pdata if e["chained"]}
    common, ida_only, ghi_only = set(I) & set(G), set(I) - set(G), set(G) - set(I)
    ghidra_total = len(G) + ext  # Ghidra FunctionManager.getFunctionCount() = internal + External space

    # 1) Main difference: import stubs in the External space (IDA does not count them as functions)
    assert ext > 0
    assert ghidra_total - len(I) == ext + len(ghi_only) - len(ida_only)  # the accounting balances
    assert ext >= 0.9 * (ghidra_total - len(I))  # most of the difference is import stubs

    # 2) Start addresses are almost identical
    assert len(common) >= 0.98 * max(len(I), len(G))

    # 3) All of the remaining difference must be explained
    ghi_unexplained = [hex(a) for a in sorted(ghi_only)
                       if not (G[a]["thunk"] or a in pd_primary or a in pd_chained)]
    starts = sorted(G)

    def ghidra_fn_containing(a):
        i = bisect.bisect_right(starts, a) - 1
        return i >= 0 and starts[i] <= a < starts[i] + G[starts[i]]["size"]

    ida_unexplained = [hex(a) for a in sorted(ida_only)
                       if not (I[a].size <= SMALL_STUB and a not in pd_primary)]
    print(f"\nIDA={len(I)} Ghidra_internal={len(G)} Ghidra_external={ext} Ghidra_total={ghidra_total} common={len(common)} "
          f"IDA_only={len(ida_only)} Ghidra_only={len(ghi_only)}")
    print("Ghidra only:", [(hex(a), G[a]["name"], G[a]["thunk"], a in pd_primary) for a in sorted(ghi_only)])
    print("IDA only:", [(hex(a), I[a].name, I[a].size, a in pd_primary, ghidra_fn_containing(a))
                          for a in sorted(ida_only)])
    assert not ghi_unexplained, f"unexplained Ghidra-only: {ghi_unexplained} -> unknown_record"
    assert not ida_unexplained, f"unexplained IDA-only: {ida_unexplained} -> unknown_record"


def test_pdata_cross_check_each_engine_covers_exception_table(both):
    """Third source: every independent (unchained) .pdata record is a function start in at least one engine."""
    I, G, pdata = both["ida"], both["ghidra"], both["pdata"]
    prim = {e["begin"] for e in pdata if not e["chained"]}
    assert prim, ".pdata empty"
    assert not [hex(a) for a in prim if a not in I and a not in G]
    print(f"\n.pdata independent records {len(prim)}: IDA missing {len(prim - set(I))}, Ghidra missing {len(prim - set(G))}")
