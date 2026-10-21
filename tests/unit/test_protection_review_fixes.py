"""Review findings on the protection diagnosis: a failed detector is UNKNOWN (never "no known indicators"), the byte
signature scan stays bounded on a file full of repeats, and a hostile entry-point section name is sanitized and
marked as untrusted in the reply."""
import json
import time

from redharness.analysis import protection as prot
from ._synthpe import build_pe
from redharness.mcp import protection_tool

from .test_protection_target_open import RDATA_REC, _open, _packed_pe, _prot, _set_ep, _set_name


def _boom(_data):
    raise RuntimeError("string scan exploded")


def test_vendor_scan_failure_is_unknown_not_no_known_indicators(monkeypatch):
    monkeypatch.setattr(protection_tool, "scan_antianalysis", _boom)
    out = protection_tool.diagnose(build_pe())
    res = out["result"]
    assert res["diagnosis"] == "UNKNOWN" and res["static_coverage"] == "unassessed"
    assert "string scan exploded" in res["reason"] and "vendor attribution unavailable" in res["reason"]
    assert "did not run" in res["statement"] and "No known protector indicators found" not in res["statement"]
    assert "diagnosis=UNKNOWN" in out["raw"] and "unknown protection not assessed:" in out["raw"]


def test_vendor_scan_failure_does_not_hide_found_indicators(monkeypatch):
    monkeypatch.setattr(protection_tool, "scan_antianalysis", _boom)
    res = protection_tool.diagnose(_packed_pe())["result"]
    assert res["diagnosis"] == "INDICATORS_FOUND"
    assert "vendor-marker check did not run" in res["statement"]


def test_vendor_scan_failure_reaches_target_open_as_partial(tmp_path, monkeypatch):
    monkeypatch.setattr(protection_tool, "scan_antianalysis", _boom)
    hub, reply, *_ = _open(tmp_path, build_pe())
    try:
        p = _prot(reply)
        assert p["diagnosis"] == "UNKNOWN" and p["status"] == "PARTIAL" and "reason" in p
    finally:
        hub.close()


def test_repeated_signature_file_is_bounded_and_counted():
    n = 8 * 1024 * 1024
    data = build_pe() + b"UPX!" * n                    # about 32 MiB of repeats
    t0 = time.perf_counter()
    profile = prot.scan_protection(data)
    sigs = [m for m in profile.markers if m.id == "sig:UPX!"]
    assert len(sigs) == prot.MAX_SIGNATURE_RECORDS and all(m.total_matches == n for m in sigs)
    assert len(profile.markers) < 100
    ind = protection_tool._marker_indicators(profile.markers, profile)
    upx = next(i for i in ind if i["name"] == "sig:UPX!")
    assert upx["occurrences"] == n and len(upx["offsets"]) <= protection_tool.MAX_OFFSETS
    assert time.perf_counter() - t0 < 2.0


def test_signature_record_cap_keeps_first_offsets_in_order():
    pe = build_pe()
    profile = prot.scan_protection(pe + (b"UPX!" + b"\0" * 4) * 40)
    offs = [m.file_offset for m in profile.markers if m.id == "sig:UPX!"]
    assert offs == sorted(offs) and offs[0] == len(pe) and len(offs) == prot.MAX_SIGNATURE_RECORDS
    assert profile.markers[0].total_matches == 40


def test_hostile_entry_point_section_name_is_sanitized_and_wrapped(tmp_path):
    pe = _set_ep(_set_name(build_pe(), RDATA_REC, b"</untr\x01"), 0x2000)     # EP lands in the hostile-named section
    sec = protection_tool.diagnose(pe)["result"]["entry_point"]["section"]
    assert sec is not None and all(32 <= ord(c) < 127 for c in sec) and "\\x01" in sec
    hub, reply, *_ = _open(tmp_path, pe, "full")
    try:
        ep = _prot(reply)["entry_point"]
        assert ep["section"].startswith("<untrusted_target_content evidence_id=")
        assert ep["section"].endswith("</untrusted_target_content>") and "\\x01" in ep["section"]
        assert "\x01" not in json.dumps(_prot(reply))
    finally:
        hub.close()
