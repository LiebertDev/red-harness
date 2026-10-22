"""REAL proof of the stable engine error codes (docs/usage-mcp.md "Engine error codes"): the same bad `decompile` calls on the
host's own notepad.exe through the full MCP path (target_open + scope manifest + journal) with the real IDA and the real
Ghidra engine must give the SAME tool error code. Skipped when an engine is not installed."""
from __future__ import annotations

import pytest

from redharness.analysis.pe_image import parse_pe
from redharness.config import Config
from redharness.engines.ghidra import GhidraEngine
from redharness.engines.ida import IdaEngine
from redharness.mcp.session import Hub, ToolFailure

from tests.unit.mcp_helpers import make_manifest

pytestmark = pytest.mark.heavy


@pytest.fixture(scope="module")
def hubs(heavy_data_root, notepad_copy, tmp_path_factory):
    cfg = Config.load(heavy_data_root)
    out = {}
    for name, eng in (("ida", IdaEngine(cfg)), ("ghidra", GhidraEngine(cfg))):
        info = eng.probe()
        if not info.available:
            pytest.skip(f"{name} unavailable: {info.detail}")
        tmp = tmp_path_factory.mktemp(f"codes_{name}")
        h = Hub(Config.load(tmp / "data"), eng)
        h.target_open(str(notepad_copy), str(make_manifest(tmp / "scope.json", notepad_copy)))
        out[name] = h
    data = notepad_copy.read_bytes()
    img = parse_pe(lambda off, n: data[off:off + n], len(data))
    yield out, img
    for h in out.values():
        h.close()


def decompile_code(h, function):
    with pytest.raises(ToolFailure) as e:
        h.call("decompile", {"function": function}, lambda: h.decompile(function))
    return e.value.code, e.value.message


def test_no_function_at_address_is_the_same_code_on_ida_and_ghidra(hubs):
    hs, img = hubs
    inside = f"0x{img.image_base + 0x10:x}"        # the DOS header: in the image, no function there
    got = {n: decompile_code(h, inside) for n, h in hs.items()}
    print("\nno-function decompile at", inside, "->", {n: c for n, (c, _) in got.items()})
    assert {c for c, _ in got.values()} == {"NO_FUNCTION_AT_ADDRESS"}, got
    for n, (_, msg) in got.items():
        assert inside in msg and "worker error" not in msg and "script error" not in msg, (n, msg)


def test_unknown_name_is_the_same_code_on_ida_and_ghidra(hubs):
    hs, _ = hubs
    got = {n: decompile_code(h, "rh_no_such_function_xyz")[0] for n, h in hs.items()}
    print("\nunknown-name decompile ->", got)
    assert set(got.values()) == {"NAME_NOT_RESOLVED"}, got


def test_address_beyond_the_image_is_out_of_image_on_both(hubs):
    hs, img = hubs
    outside = f"0x{img.image_base + img.size_of_image + 0x1000:x}"
    got = {n: decompile_code(h, outside)[0] for n, h in hs.items()}
    print("\noutside-image decompile ->", got)
    assert set(got.values()) == {"OUT_OF_IMAGE"}, got


def test_dataflow_slice_reports_the_same_code(hubs):
    hs, img = hubs
    inside = f"0x{img.image_base + 0x10:x}"
    got = {}
    for n, h in hs.items():
        with pytest.raises(ToolFailure) as e:
            h.call("dataflow_slice", {"address": inside}, lambda h=h: h.dataflow_slice(inside))
        got[n] = e.value.code
    print("\ndataflow_slice at", inside, "->", got)
    assert set(got.values()) == {"NO_FUNCTION_AT_ADDRESS"}, got


def test_engine_level_result_carries_the_code(hubs):
    hs, img = hubs
    for n, h in hs.items():
        sha = h._s.sha
        r = h.engine.decompile(sha, img.image_base + 0x10)
        assert not r.ok and r.code == "NO_FUNCTION_AT_ADDRESS", (n, r.status, r.code, r.detail)
        r = h.engine.decompile(sha, "rh_no_such_function_xyz")
        assert not r.ok and r.code == "NAME_NOT_RESOLVED", (n, r.status, r.code, r.detail)
