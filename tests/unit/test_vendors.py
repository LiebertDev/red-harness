"""Vendor attribution: marker/threshold boundaries, provenance fields, ordering and rendering.

The profile is built by hand (the scanner is tested elsewhere); a few cases run the real
`scan_antianalysis` over a synthetic PE to check the wiring end to end.
"""

import pytest

from redharness.analysis.antianalysis import (
    AntiAnalysisProfile,
    CapabilityCoverage,
    Hit,
    MARKER_TECHNIQUES,
    scan_antianalysis,
)
from redharness.analysis.vendors import (
    VENDOR_RULES,
    VendorIndicator,
    VendorRule,
    attribute_vendors,
    render_vendors,
)
from ._synthpe import build_pe


def _hit(needle: str, file_offset: int | None = 0x600, occurrences: int = 1) -> Hit:
    return Hit(family="test", technique="marker", strength="strong", source="string",
               detail=f"string {needle!r}", needle=needle, file_offset=file_offset,
               occurrences=occurrences)


def _profile(needles=(), sections=()) -> AntiAnalysisProfile:
    hits = tuple(_hit(n, 0x600 + i) for i, n in enumerate(needles))
    coverage = CapabilityCoverage(True, True, 0, len(hits), 0, 0, False, False, (), ())
    return AntiAnalysisProfile("0" * 64, 0x1600, "x64", 0x140000000, tuple(sections), "file",
                               hits, (), coverage, ())


def _ids(vendors) -> list[str]:
    return [v.vendor_id for v in vendors]


def test_empty_profile_has_no_attribution():
    assert attribute_vendors(_profile()) == ()
    text = render_vendors(())
    assert text.startswith("vendors (0):")
    assert "heuristic" in text and "not proof" in text


def test_single_strong_indicator_is_moderate_never_strong():
    vendors = attribute_vendors(_profile(["GameGuard"]))
    assert _ids(vendors) == ["nprotect-gameguard"]
    v = vendors[0]
    assert (v.score, v.confidence, v.groups) == (3, "moderate", ("name",))
    assert v.kind == "anti-cheat" and v.name == "nProtect GameGuard"
    assert len(v.matches) == 1
    assert v.matches[0].file_offset == 0x600


def test_weak_indicator_alone_stays_below_min_score():
    # 2 points is below the default min_score=3; a weak name is not enough on its own.
    assert attribute_vendors(_profile(["vanguard"])) == ()
    assert attribute_vendors(_profile(["nprotect"])) == ()
    assert attribute_vendors(_profile()) == ()


def test_score_five_with_two_groups_is_moderate():
    vendors = attribute_vendors(_profile(["nProtect", "GameMon"]))
    assert _ids(vendors) == ["nprotect-gameguard"]
    v = vendors[0]
    assert (v.score, v.confidence, v.groups) == (5, "moderate", ("module", "name"))


def test_six_points_and_two_groups_is_strong():
    vendors = attribute_vendors(_profile(["GameGuard", "GameMon"]))
    v = vendors[0]
    assert (v.score, v.confidence, v.groups) == (6, "strong", ("module", "name"))
    assert [m.value for m in v.matches] == ["gameguard", "gamemon"]


def test_six_points_in_one_group_stays_moderate():
    # denuvo/denuvo64 are two needles but both belong to the "name" group.
    vendors = attribute_vendors(_profile(["Denuvo", "Denuvo64"]))
    v = next(x for x in vendors if x.vendor_id == "denuvo")
    assert (v.score, v.confidence, v.groups) == (6, "moderate", ("name",))


def test_section_indicators_are_case_and_space_normalized():
    vendors = attribute_vendors(_profile([], [" .VMP0 ", ".vmp1"]))
    v = next(x for x in vendors if x.vendor_id == "vmprotect")
    assert (v.score, v.groups, v.confidence) == (6, ("section",), "moderate")
    assert {m.kind for m in v.matches} == {"section"}
    assert all(m.file_offset is None for m in v.matches)


def test_string_provenance_offset_and_occurrences_are_preserved():
    profile = _profile()
    hit = _hit("GameGuard", file_offset=0x640, occurrences=3)
    profile = AntiAnalysisProfile(profile.sha256, profile.file_size, profile.arch,
                                  profile.image_base, profile.sections, profile.layout,
                                  (hit,), (), profile.coverage, ())
    v = attribute_vendors(profile)[0]
    m = v.matches[0]
    assert (m.kind, m.value, m.weight, m.group) == ("string", "gameguard", 3, "name")
    assert m.file_offset == 0x640 and m.occurrences == 3
    text = render_vendors((v,))
    assert "file_offset 0x640" in text and "occurrences=3" in text


def test_attribution_order_is_score_then_vendor_id_and_deterministic():
    profile = _profile(["GameGuard", "GameMon", "mhyprot", "xigncode", "VMProtect"])
    first = attribute_vendors(profile)
    assert _ids(first) == ["nprotect-gameguard", "mhyprot", "vmprotect", "xigncode"]
    assert first[0].score > first[1].score
    assert attribute_vendors(profile) == first


def test_real_scan_of_synthetic_pe_feeds_attribution():
    pe = build_pe(markers=(b"GameGuard\0", b"nProtect\0", b"GameMon.des\0"))
    vendors = attribute_vendors(scan_antianalysis(pe))
    v = vendors[0]
    assert v.vendor_id == "nprotect-gameguard" and v.confidence == "strong"
    assert [m.value for m in v.matches] == ["gameguard", "gamemon", "nprotect"]
    low = pe.lower()
    assert all(m.file_offset == low.find(m.value.encode()) for m in v.matches)


def test_custom_rule_min_score_boundary_and_weight_gate():
    weak = VendorRule("weak", "Weak", "protector",
                      (VendorIndicator("string", "weak", 1, "g", "w"),), min_score=1)
    # Reaching min_score is not enough: at least one indicator of weight >= 2 is required.
    assert attribute_vendors(_profile(["weak"]), rules=(weak,)) == ()

    exact = VendorRule("exact", "Exact", "protector",
                       (VendorIndicator("string", "one", 2, "g1", "w"),
                        VendorIndicator("string", "two", 2, "g2", "w")), min_score=4)
    v = attribute_vendors(_profile(["one", "two"]), rules=(exact,))[0]
    assert (v.score, v.confidence, v.groups) == (4, "moderate", ("g1", "g2"))


def test_catalog_string_markers_exist_in_the_marker_table():
    needles = {m.needle.lower() for m in MARKER_TECHNIQUES}
    missing = [(r.id, i.value) for r in VENDOR_RULES for i in r.indicators
               if i.kind == "string" and i.value not in needles]
    assert missing == []


@pytest.mark.parametrize("needle,vendor_id", [("safedisc", "safedisc"),
                                              ("securom", "securom"),
                                              ("starforce", "starforce")])
def test_single_name_drm_rule_is_attributed(needle, vendor_id):
    vendors = attribute_vendors(_profile([needle]))
    assert _ids(vendors) == [vendor_id], f"{needle} has no reachable indicator"
    assert (vendors[0].score, vendors[0].confidence) == (3, "moderate")
