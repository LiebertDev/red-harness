"""Protection diagnosis in target_open (`target.protection`): packed-looking synthetic PE, plain PE, malformed PE.

Fake engine (no IDA/Ghidra) and the synthetic PEs of tests/unit/_synthpe.py; nothing is ever run. The real-engine
proof is a manual run on real binaries (see docs/usage-mcp.md, "Protection diagnosis").
"""
import json
import struct

import pytest

from redharness.config import Config
from ._synthpe import RDATA_FILE_OFFSET, build_pe
from redharness.mcp import protection_tool
from redharness.mcp.session import Hub, ToolFailure

from ._fake_engine import FakeEngine
from .mcp_helpers import make_manifest

TEXT_REC, RDATA_REC = 0, 1


def _rec(pe: bytes, index: int) -> int:
    e = struct.unpack_from("<I", pe, 0x3C)[0]
    sizeopt = struct.unpack_from("<H", pe, e + 20)[0]
    return e + 24 + sizeopt + 40 * index


def _set_name(pe: bytes, index: int, name: bytes) -> bytes:
    out = bytearray(pe)
    out[_rec(pe, index):_rec(pe, index) + 8] = name.ljust(8, b"\0")
    return bytes(out)


def _set_ep(pe: bytes, rva: int) -> bytes:
    out = bytearray(pe)
    e = struct.unpack_from("<I", pe, 0x3C)[0]
    struct.pack_into("<I", out, e + 24 + 16, rva)
    return bytes(out)


def _packed_pe() -> bytes:
    """UPX-looking: UPX0/UPX1 section names, a UPX! signature, entry point in the non-executable second section."""
    pe = _set_name(_set_name(build_pe(markers=(b"UPX!",)), TEXT_REC, b"UPX0"), RDATA_REC, b"UPX1")
    return _set_ep(pe, 0x2000)


def _open(tmp_path, data: bytes, detail: str | None = None):
    tmp_path.mkdir(parents=True, exist_ok=True)
    target = tmp_path / "t.exe"
    target.write_bytes(data)
    manifest = make_manifest(tmp_path / "scope.json", target)
    hub = Hub(Config.load(tmp_path / "data"), FakeEngine())
    reply = hub.target_open(str(target), str(manifest), None, *([detail] if detail else []))
    return hub, reply, target, manifest


def _prot(reply):
    return reply["target"]["protection"]


def _raw(hub, ev_id: str) -> str:
    rec = hub._s.ledger.state["evidence"][ev_id]
    return hub._s.cas.get(rec["raw"]["blob_sha256"]).decode("utf-8")


def test_plain_pe_reports_no_known_indicators_never_clean(tmp_path):
    hub, reply, *_ = _open(tmp_path, build_pe())
    try:
        p = _prot(reply)
        assert reply["status"] == "OK"
        assert p["diagnosis"] == "NO_KNOWN_INDICATORS" and p["static_coverage"] == "no_known_indicators"
        assert p["indicator_count"] == 0 and p["indicators"] == [] and p["vendors"] == []
        assert "No known protector indicators found" in p["statement"]
        assert "does not establish that the binary is unprotected" in p["statement"]
        low = json.dumps(p).lower()
        assert "not protected" not in low and "clean" not in low
        assert "sections" not in p            # summary: the section table is in the evidence / detail='full'
        assert p["evidence_id"].startswith("ev_")
        assert _raw(hub, p["evidence_id"]).startswith("protection_scan diagnosis=NO_KNOWN_INDICATORS")
    finally:
        hub.close()


def test_packed_looking_pe_lists_evidence_bound_indicators_and_coverage_caveat(tmp_path):
    hub, reply, *_ = _open(tmp_path, _packed_pe())
    try:
        p = _prot(reply)
        assert p["diagnosis"] == "INDICATORS_FOUND" and p["static_coverage"] == "likely_partial"
        assert "likely partial" in p["statement"] and "unknown, not as absent" in p["statement"]
        by_name = {i["name"]: i for i in p["indicators"]}
        assert {"name:upx0", "name:upx1", "sig:UPX!", "anomaly:entry_point_outside_code"} <= set(by_name)
        assert by_name["name:upx0"]["strength"] == "strong" and by_name["name:upx0"]["section"] == "UPX0"
        assert by_name["name:upx0"]["rva"] == "0x1000"                       # hex string, not an int
        assert by_name["sig:UPX!"]["strength"] == "moderate"
        assert by_name["sig:UPX!"]["file_offset"].startswith("0x")
        raw = _raw(hub, p["evidence_id"])
        for i in p["indicators"]:
            assert i["evidence_id"] == p["evidence_id"]
            assert i["quote"] in raw and len(i["quote"]) >= 4                  # citable in claim_add
        ev = hub._s.ledger.state["evidence"][p["evidence_id"]]
        assert ev["operation"] == "protection_scan"
        assert any(loc["space"] == "rva" and loc["start"] == 0x1000 for loc in ev["locations"])
    finally:
        hub.close()


def test_indicator_quote_is_accepted_by_claim_add(tmp_path):
    hub, reply, *_ = _open(tmp_path, _packed_pe())
    try:
        p = _prot(reply)
        ind = next(i for i in p["indicators"] if i["name"] == "name:upx0")
        r = hub.claim_add("Section UPX0 is a known packer section name.", [p["evidence_id"]],
                          [{"type": "quote", "evidence_id": p["evidence_id"], "text": ind["quote"]}],
                          kind="observation")
        assert r["status"] == "SUPPORTED", r
    finally:
        hub.close()


def test_vendor_attribution_has_score_confidence_and_evidence(tmp_path):
    pe = _set_name(build_pe(markers=(b"VMProtect begin",)), RDATA_REC, b".vmp0")
    hub, reply, *_ = _open(tmp_path, pe)
    try:
        p = _prot(reply)
        v = next(x for x in p["vendors"] if x["id"] == "vmprotect")
        assert v["kind"] == "protector" and v["confidence"] in ("moderate", "strong") and v["score"] >= 6
        assert v["evidence_id"] == p["evidence_id"]
        ind = next(i for i in p["indicators"] if i["name"] == "vendor:vmprotect")
        assert ind["vendor"] == "VMProtect" and ind["quote"] in _raw(hub, p["evidence_id"])
        assert p["static_coverage"] == "likely_partial"
    finally:
        hub.close()


def test_malformed_pe_gives_unknown_and_target_open_still_succeeds(tmp_path):
    hub, reply, *_ = _open(tmp_path, b"MZ" + bytes(range(256)) * 8)
    try:
        p = _prot(reply)
        assert reply["status"] == "OK" and reply["target"]["function_count"] > 0
        assert p["diagnosis"] == "UNKNOWN" and p["static_coverage"] == "unassessed"
        assert "could not be assessed" in p["statement"] and "UNKNOWN" in p["statement"]
        assert p["reason"].startswith("not a readable PE")
        assert p["status"] == "PARTIAL" and p["indicators"] == []
        assert "unknown protection not assessed" in _raw(hub, p["evidence_id"])
    finally:
        hub.close()


def test_truncated_pe_is_unknown_not_clean(tmp_path):
    hub, reply, *_ = _open(tmp_path, build_pe()[:RDATA_FILE_OFFSET + 0x20])
    try:
        p = _prot(reply)
        assert p["diagnosis"] == "UNKNOWN" and "No known protector" not in p["statement"]
    finally:
        hub.close()


def test_oversized_file_is_unknown_with_reason(tmp_path, monkeypatch):
    monkeypatch.setattr(protection_tool, "MAX_FILE_BYTES", 1024)
    hub, reply, *_ = _open(tmp_path, build_pe())
    try:
        p = _prot(reply)
        assert p["diagnosis"] == "UNKNOWN" and "protection-scan limit" in p["reason"]
    finally:
        hub.close()


def test_vendor_scan_failure_keeps_the_protection_diagnosis_and_says_partial(tmp_path, monkeypatch):
    def boom(_data):
        raise protection_tool.PeError("import table unreadable")
    monkeypatch.setattr(protection_tool, "scan_antianalysis", boom)
    hub, reply, *_ = _open(tmp_path, _packed_pe(), "full")
    try:
        p = _prot(reply)
        assert p["diagnosis"] == "INDICATORS_FOUND" and p["status"] == "PARTIAL"
        assert any("vendor attribution unavailable" in n for n in p["notes"])
    finally:
        hub.close()


def test_weak_signals_alone_are_not_a_protector_diagnosis():
    out = protection_tool.diagnose(_set_ep(build_pe(markers=(b"PECompact",)), 0))   # weak signature + EP rva 0
    res = out["result"]
    assert res["diagnosis"] == "NO_KNOWN_INDICATORS"
    assert {i["strength"] for i in res["indicators"]} == {"weak"}
    assert "weak signal(s)" in res["statement"]


def test_summary_caps_indicators_and_full_adds_sections_and_reasoning(tmp_path, monkeypatch):
    monkeypatch.setattr(protection_tool, "SUMMARY_INDICATORS", 2)
    hub, reply, target, manifest = _open(tmp_path, _packed_pe())
    try:
        s = _prot(reply)
        assert s["indicator_count"] > 2 and len(s["indicators"]) == 2 and s["indicators_truncated"] is True
        assert [i["strength"] for i in s["indicators"]] == ["strong", "strong"]      # strongest first
        assert "why" not in s["indicators"][0] and "sections" not in s
        full = hub.target_open(str(target), str(manifest), None, "full")["target"]["protection"]
        assert full["evidence_id"] == s["evidence_id"] and full["step_cached"] is True
        assert len(full["indicators"]) == full["indicator_count"] and "indicators_truncated" not in full
        assert all("why" in i for i in full["indicators"])
        assert [x["name"] for x in full["sections"]] == ["UPX0", "UPX1"]
        assert full["sections"][0]["rva"] == "0x1000" and full["entry_point"]["rva"] == "0x2000"
    finally:
        hub.close()


def test_reopen_reuses_the_cached_evidence(tmp_path):
    hub, reply, target, manifest = _open(tmp_path, _packed_pe())
    try:
        first = _prot(reply)
        again = hub.target_open(str(target), str(manifest))["target"]["protection"]
        assert again["evidence_id"] == first["evidence_id"] and again["step_cached"] is True
    finally:
        hub.close()


def test_bad_detail_is_refused(tmp_path):
    hub, _reply, target, manifest = _open(tmp_path, build_pe())
    try:
        with pytest.raises(ToolFailure) as e:
            hub.target_open(str(target), str(manifest), None, "everything")
        assert e.value.code == "BAD_ARGUMENT"
    finally:
        hub.close()


def test_section_name_is_sanitized_on_the_evidence_line():
    out = protection_tool.diagnose(_set_name(build_pe(), RDATA_REC, b"UPX1\n\x01"))
    assert "\n\x01" not in out["raw"] and "UPX1\\x0a\\x01" in out["raw"]


def test_open_time_scan_is_not_a_code_examination_but_coverage_reports_the_diagnosis(tmp_path):
    hub, reply, *_ = _open(tmp_path, b"MZ" + bytes(range(256)) * 8)      # malformed: diagnosis UNKNOWN (PARTIAL evidence)
    try:
        cov = hub.coverage()
        assert cov["assessment"] == "NOT_EXAMINED" and cov["incomplete_calls_total"] == 0
        assert cov["protection"] == {"evidence_id": _prot(reply)["evidence_id"], "diagnosis": "UNKNOWN",
                                     "static_coverage": "unassessed"}
    finally:
        hub.close()
