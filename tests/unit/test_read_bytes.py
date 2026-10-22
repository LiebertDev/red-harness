"""read_bytes: static raw bytes from a PE file. Synthetic PE (tests/unit/_pe_builder.py), no engine call.

Scope: VA/RVA/section+offset mapping, .bss (not in the file; never presented as zero bytes), out-of-image error,
length cap, typed views, evidence id stability, claim binding through the (unmodified) verifier,
tool count and effect table.
"""
import asyncio
import re
from pathlib import Path

import pytest

from redharness.analysis.pe_image import (READ_MAX, PeError, normalize_views, parse_pe, read_range)
from redharness.config import Config
from redharness.mcp.effects import TOOL_EFFECTS, check_permission
from redharness.mcp.server import MAX_TOOLS, TOOL_NAMES, build_server
from redharness.mcp.session import Hub, ToolFailure
from redharness.scope.manifest import parse_manifest

from ._fake_engine import FakeEngine
from ._pe_builder import build_pe
from .mcp_helpers import make_manifest

BASE64 = 0x140000000
BASE32 = 0x400000


def make_hub(tmp_path, is64=True, ops=("static",), marker=b""):
    tmp_path.mkdir(parents=True, exist_ok=True)
    target = tmp_path / "t.exe"
    target.write_bytes(build_pe(is64, data_marker=marker))
    manifest = make_manifest(tmp_path / "scope.json", target, allowed_operations=list(ops))
    hub = Hub(Config.load(tmp_path / "data"), FakeEngine())
    hub.target_open(str(target), str(manifest))
    return hub


@pytest.fixture
def hub(tmp_path):
    h = make_hub(tmp_path)
    yield h
    h.close()


def text(reply):
    return reply["content"].split(">", 1)[1].rsplit("</untrusted_target_content", 1)[0]


def img_of(is64=True, marker=b""):
    data = build_pe(is64, data_marker=marker)
    return data, parse_pe(lambda o, n: data[o:o + n], len(data))


# ---------------------------------------------------------------- VA -> file mapping (pure)
def test_parse_and_va_mapping_across_sections():
    data, img = img_of()
    assert img.is64 and img.image_base == BASE64 and img.size_of_image == 0x5000
    assert [s.name for s in img.sections] == [".text", ".rdata", ".data", ".bss"]
    rd = lambda o, n: data[o:o + n]  # noqa: E731
    # .rdata RVA 0x2000 -> file 0x600: the first pointer
    out = read_range(img, rd, 0x2000, 8, ("ptr",))
    seg = out.result["segments"][0]
    assert seg["kind"] == "file" and seg["file_offset"] == 0x600 and seg["section"] == ".rdata"
    assert data[0x600:0x608] == (BASE64 + 0x1010).to_bytes(8, "little")
    # .text -> file 0x400
    assert read_range(img, rd, 0x1000, 4, ()).result["file_offset"] == 0x400
    # .data -> file 0x800; with an offset
    assert read_range(img, rd, 0x3010, 4, ()).result["file_offset"] == 0x810
    # headers RVA 0 -> file 0
    h = read_range(img, rd, 0, 2, ())
    assert h.result["section"] == "(headers)" and h.result["file_offset"] == 0 and "4d5a" in h.raw


def test_range_crossing_sections_is_split_with_gap_unmapped():
    data, img = img_of()
    rd = lambda o, n: data[o:o + n]  # noqa: E731
    # end of .text (vsize 0x100) -> gap (0x1100..0x2000 is in no section) -> .rdata
    chunks = img.plan(0x10F0, 0x20)
    assert [(c.kind, c.rva, c.length) for c in chunks] == [("file", 0x10F0, 0x10), ("unmapped", 0x1100, 0x10)]
    out = read_range(img, rd, 0x10F0, 0x20, ())
    assert out.status == "PARTIAL" and out.result["file_bytes"] == 16 and out.result["unmapped_bytes"] == 16
    assert any("not mapped" in x for x in out.limitations)


def test_pe_errors():
    with pytest.raises(PeError):
        parse_pe(lambda o, n: b"", 10)
    junk = b"MZ" + bytes(range(256)) * 8
    with pytest.raises(PeError):
        parse_pe(lambda o, n: junk[o:o + n], len(junk))
    data, img = img_of()
    with pytest.raises(PeError):
        read_range(img, lambda o, n: data[o:o + n], 0x5000, 4, ())
    with pytest.raises(PeError, match="not found"):
        img.find_section(".nope")


# ---------------------------------------------------------------- .bss / uninitialized
def test_bss_is_never_presented_as_zeros(hub):
    r = hub.read_bytes(section=".bss", offset=0, length=32, view="all")
    t = text(r)
    assert r["status"] == "PARTIAL"
    assert r["result"]["file_bytes"] == 0 and r["result"]["uninitialized_bytes"] == 32
    assert "UNINITIALIZED" in t and "runtime-only" in t and "not in file" in t
    assert "00000000" not in t and "0x00000000" not in t       # zero bytes/values are NOT invented
    assert r["result"]["segments"][0]["kind"] == "uninitialized" and r["result"]["segments"][0]["file_offset"] is None
    # the evidence has no location: an address atom is not supported for a bss address
    c = hub.claim_add("a value exists at the start of bss", [r["evidence_id"]],
                      [{"type": "address", "evidence_id": r["evidence_id"], "value": f"0x{BASE64 + 0x4000:x}"}],
                      kind="observation")
    assert c["status"] != "SUPPORTED"


def test_data_section_tail_beyond_raw_size_is_uninitialized_and_split(hub):
    # .data: the first 0x200 bytes are in the file, 0x200..0x300 only in memory
    r = hub.read_bytes(address=f"0x{BASE64 + 0x31F0:x}", length=0x20, view="u32")
    res = r["result"]
    assert r["status"] == "PARTIAL" and res["file_bytes"] == 0x10 and res["uninitialized_bytes"] == 0x10
    kinds = [s["kind"] for s in res["segments"]]
    assert kinds == ["file", "uninitialized"]
    assert res["segments"][0]["end"] == f"0x{BASE64 + 0x3200:x}" and res["segments"][1]["file_offset"] is None
    # the typed view is produced only for the file-backed part (4 u32 rows)
    assert len(re.findall(r"^\s+0x[0-9a-f]+: 0x[0-9a-f]{8} \d+$", text(r), re.M)) == 4


def test_gap_between_sections_is_unmapped(hub):
    r = hub.read_bytes(rva=0x3400, length=16)
    assert r["status"] == "PARTIAL" and r["result"]["unmapped_bytes"] == 16 and "UNMAPPED" in text(r)


# ---------------------------------------------------------------- out-of-image and argument errors
@pytest.mark.parametrize("kw,code", [
    (dict(address=f"0x{BASE64 - 1:x}"), "OUT_OF_IMAGE"),
    (dict(address=f"0x{BASE64 + 0x5000:x}"), "OUT_OF_IMAGE"),
    (dict(address="0x1000"), "OUT_OF_IMAGE"),
    (dict(rva="0x5000"), "OUT_OF_IMAGE"),
    (dict(section=".data", offset=0x300), "OUT_OF_IMAGE"),
    (dict(section=".nope"), "BAD_ARGUMENT"),
    (dict(), "BAD_ARGUMENT"),
    (dict(address="0x140001000", rva="0x1000"), "BAD_ARGUMENT"),
    (dict(address="zzz"), "BAD_ARGUMENT"),
    (dict(address="0x140001000", offset=4), "BAD_ARGUMENT"),
    (dict(address="0x140001000", view="u128"), "BAD_ARGUMENT"),
    (dict(address="0x140001000", length="8"), "BAD_ARGUMENT"),
    (dict(address="0x140001000", detail="tiny"), "BAD_ARGUMENT"),
])
def test_out_of_image_and_bad_arguments(hub, kw, code):
    with pytest.raises(ToolFailure) as ei:
        hub.read_bytes(**kw)
    assert ei.value.code == code
    assert hub.coverage()["failed_calls_total"] == 0     # an out-of-image/bad question does not count as a coverage gap


def test_not_a_pe_target(tmp_path):
    target = tmp_path / "x.bin"
    target.write_bytes(b"MZ" + bytes(range(256)) * 8)
    man = make_manifest(tmp_path / "s.json", target)
    h = Hub(Config.load(tmp_path / "d"), FakeEngine())
    h.target_open(str(target), str(man))
    try:
        with pytest.raises(ToolFailure) as ei:
            h.read_bytes(rva=0x10)
        assert ei.value.code == "NOT_PE"
    finally:
        h.close()


# ---------------------------------------------------------------- length cap
def test_length_cap_and_next_address(hub):
    r = hub.read_bytes(section=".text", length=100_000, view="u32")  # .text is only 0x100 bytes: the rest is a gap
    res = r["result"]
    assert res["length"] == READ_MAX and res["requested_length"] == 100_000
    assert res["next_address"] == f"0x{BASE64 + 0x1000 + READ_MAX:x}" and r["status"] == "PARTIAL"
    assert "capped" in text(r) and len(text(r)) <= 24_000
    small = hub.read_bytes(section=".data", length=16, view="u8")
    assert small["result"]["next_address"] is None and small["status"] == "OK"
    assert hub.read_bytes(section=".data", length=0)["result"]["length"] == 1       # the lower bound is clamped


def test_reply_size_guard_is_explicit_not_silent(hub, monkeypatch):
    monkeypatch.setattr("redharness.mcp.session.RESPONSE_BUDGET", 600)
    with pytest.raises(ToolFailure) as ei:
        hub.read_bytes(rva=0x3000, length=0x200, view="all")
    assert ei.value.code == "BAD_ARGUMENT" and "fewer views" in ei.value.message


# ---------------------------------------------------------------- typed views
def test_typed_views_values(hub):
    r = hub.read_bytes(section=".data", length=24, view="u8,u16,u32,u64")
    t = text(r)
    va = BASE64 + 0x3000
    assert f"0x{va:x}: 0x00000064 100" in t and f"0x{va + 16:x}: 0xdeadbeef 3735928559" in t
    assert f"0x{va + 20:x}: 0xffffffff 4294967295" in t
    assert "0x0064=100" in t and "0x0000=0" in t                       # u16
    assert f"0x{va:x}: 0x0000001200000064 {0x1200000064}" in t         # u64 (LE: 100 | 18<<32)
    assert f"0x{va:x}: 100 0 0 0 18 0 0 0 1 0 0 0 1 0 0 0\n" in t       # u8
    assert "64000000_12000000_01000000_01000000" in t                  # hex dump, file order


def test_ptr_view_x64_and_x86_widths_and_section_notes(tmp_path):
    h = make_hub(tmp_path / "a")
    h2 = make_hub(tmp_path / "b", is64=False)
    try:
        t = text(h.read_bytes(section=".rdata", length=32, view="ptr"))
        assert f"0x{BASE64 + 0x2000:x}: 0x{BASE64 + 0x1010:016x} -> .text" in t
        assert f"0x{BASE64 + 0x2018:x}: 0x{BASE64 + 0x3008:016x} -> .data" in t
        t32 = text(h2.read_bytes(section=".rdata", length=16, view="ptr"))
        assert f"0x{BASE32 + 0x2000:x}: 0x{BASE32 + 0x1010:08x} -> .text" in t32
        assert f"0x{BASE32 + 0x200c:x}: 0x{BASE32 + 0x3008:08x} -> .data" in t32
        # default view = ptr
        assert "-- ptr --" in text(h.read_bytes(section=".rdata", length=8))
        null = text(h.read_bytes(section=".rdata", offset=0x30, length=8))
        assert "0x0000000000000000 null" in null
    finally:
        h.close()
        h2.close()


def test_ascii_and_utf16_views(hub):
    t = text(hub.read_bytes(rva=0x2040, length=32, view="ascii,utf16"))
    assert f'0x{BASE64 + 0x2040:x}: "hello"' in t
    assert f'0x{BASE64 + 0x2048:x}: "Wide"' in t
    # the extracted string is quote/backslash escaped
    t2 = text(hub.read_bytes(rva=0x3000, length=0x30, view="ascii"))
    assert "-- ascii --" in t2 and "(nothing to show in this segment)" in t2


def test_view_normalization():
    assert normalize_views(None) == ("ptr",)
    assert normalize_views("U32, u8 ,hex") == ("u8", "u32")
    assert normalize_views(["all"]) == ("u8", "u16", "u32", "u64", "ptr", "ascii", "utf16")
    with pytest.raises(ValueError):
        normalize_views(5)


# ---------------------------------------------------------------- evidence id and step cache
def test_evidence_id_is_stable_across_addressing_forms_calls_and_sessions(tmp_path):
    h = make_hub(tmp_path)
    try:
        a = h.read_bytes(address=f"0x{BASE64 + 0x3000:x}", length=32, view="u32")
        b = h.read_bytes(rva="0x3000", length=32, view="u32")
        c = h.read_bytes(section=".DATA", offset="0x0", length=32, view=["u32"])
        d = h.read_bytes(section=".data", length=32, view="u32", detail="summary")
        assert a["evidence_id"].startswith("ev_")
        assert a["evidence_id"] == b["evidence_id"] == c["evidence_id"] == d["evidence_id"]
        assert a["step_cached"] is False and b["step_cached"] is True and "content" not in d
        assert d["summary"]["file_bytes"] == 32 and "preview" in d
        other = h.read_bytes(rva="0x3000", length=32, view="u16")
        assert other["evidence_id"] != a["evidence_id"]
    finally:
        h.close()
    h2 = Hub(Config.load(tmp_path / "data"), FakeEngine())
    h2.target_open(str(tmp_path / "t.exe"), str(tmp_path / "scope.json"))
    try:
        e = h2.read_bytes(rva="0x3000", length=32, view="u32")
        assert e["evidence_id"] == a["evidence_id"] and e["step_cached"] is True
    finally:
        h2.close()


def test_evidence_record_is_not_engine_labelled_and_raw_is_stored(hub):
    r = hub.read_bytes(section=".data", length=16, view="u32")
    ev = hub._s.ledger.state["evidence"][r["evidence_id"]]
    assert ev["source"]["engine"] == "pe-static" and ev["operation"] == "read_bytes"
    assert ev["untrusted_content"] is True and ev["capture"]["strength"] == "full"
    raw = hub._s.cas.get(ev["raw"]["blob_sha256"]).decode("utf-8")
    assert raw.strip() == text(r).strip()
    spaces = {loc["space"] for loc in ev["locations"]}
    assert spaces == {"va", "rva"} and all(loc["kind"] == "address-range" for loc in ev["locations"])


# ---------------------------------------------------------------- claim binding through the (unmodified) verifier
def test_claims_quote_values_from_raw_bytes(hub):
    r = hub.read_bytes(section=".data", length=24, view="u32")
    ev = r["evidence_id"]
    ok = hub.claim_add("The dword at 0x%x is 0xdeadbeef." % (BASE64 + 0x3010), [ev],
                       [{"type": "quote", "evidence_id": ev, "text": "0xdeadbeef"},
                        {"type": "address", "evidence_id": ev, "value": f"0x{BASE64 + 0x3010:x}"}],
                       kind="observation")
    assert ok["status"] == "SUPPORTED", ok
    rva_atom = hub.claim_add("The first dword (RVA 0x3000) is 100.", [ev],
                             [{"type": "address", "evidence_id": ev, "value": "0x3000", "space": "rva"}],
                             kind="observation")
    assert rva_atom["status"] == "SUPPORTED", rva_atom
    # value not in the evidence -> not supported
    bad = hub.claim_add("The first dword is `4242`.", [ev], [], kind="observation", values=["4242"])
    assert bad["status"] != "SUPPORTED" and "VALUE_NOT_IN_EVIDENCE" in str(bad)
    # quote not in the evidence -> REJECTED
    nope = hub.claim_add("A dword equals 0xcafebabe.", [ev], [{"type": "quote", "evidence_id": ev, "text": "0xcafebabe"}],
                         kind="observation")
    assert nope["status"] == "REJECTED"


# ---------------------------------------------------------------- coverage, effect table, tool list
def test_coverage_lists_data_regions(hub):
    hub.read_bytes(rva=0x3000, length=16)
    hub.read_bytes(rva=0x4000, length=16)
    cov = hub.coverage()
    assert cov["tools_run"]["read_bytes"]["evidence"] == 2 and cov["data_regions_examined_total"] == 2
    by = {r["start"]: r for r in cov["data_regions_examined"]}
    assert by[f"0x{BASE64 + 0x3000:x}"]["complete"] is True and by[f"0x{BASE64 + 0x4000:x}"]["complete"] is False
    assert cov["incomplete_calls_total"] == 1            # only the .bss read (PARTIAL) counts as incomplete coverage


def test_static_scope_is_enough_and_effect_flags():
    e = TOOL_EFFECTS["read_bytes"]
    assert e.reads_files and not (e.writes_files or e.launches_process or e.executes_foreign_code or e.network
                                  or e.mutates_target) and e.idempotent
    assert e.active() == []                                           # no effects -> no new permission
    man = parse_manifest({"schema": "rh.scope/1", "target_sha256": "0" * 64,
                          "authorization": {"declared_by": "t", "basis": "owner",
                                            "statement": "I own this test binary and authorize static analysis."},
                          "allowed_operations": ["static"]})
    check_permission("read_bytes", man)                                # does not raise


def test_tool_listing_has_read_only_annotation():
    assert "read_bytes" in TOOL_NAMES and len(TOOL_NAMES) <= MAX_TOOLS
    mcp, _ = build_server(Config.load(Path(".") / "x"), FakeEngine())
    by = {t.name: t for t in asyncio.run(mcp.list_tools())}
    assert set(by) == set(TOOL_NAMES)
    a = by["read_bytes"].annotations
    assert a.readOnlyHint and a.idempotentHint and not a.openWorldHint
    props = by["read_bytes"].inputSchema["properties"]
    assert {"address", "rva", "section", "offset", "length", "view", "detail"} <= set(props)
