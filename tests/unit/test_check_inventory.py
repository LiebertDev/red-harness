"""Check inventory: the closed taxonomy C1..C8, the engine-free scan, and the `target.protection.checks`
block of `target_open`.

Synthetic PEs (tests/unit/_synthpe.py) give the known answer for every rule. Nothing is run and no engine is needed
(the fake engine only answers target_open).
"""
from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from redharness.analysis import check_inventory as ci
from redharness.analysis import check_taxonomy as tax
from redharness.analysis.antianalysis import API_TECHNIQUES, MARKER_TECHNIQUES
from redharness.config import Config
from redharness.mcp import check_tool
from redharness.mcp.session import Hub

from ._fake_engine import FakeEngine
from ._synthpe import RDATA_FILE_OFFSET, RDATA_RVA, build_pe
from .mcp_helpers import make_manifest

ROOT = Path(__file__).resolve().parents[2]
TEXT_FILE_OFFSET = 0x400          # _synthpe: .text raw data starts right after the headers
TEXT_RVA = 0x1000


def _planted(imports: dict[str, list[str]] | None = None, **kw) -> dict:
    """Inventory of a synthetic PE; imports default to one harmless API so the import table is not empty."""
    imports = imports if imports is not None else {"KERNEL32.dll": ["Sleep"]}
    return ci.inventory(build_pe(imports=imports, **kw))


def _codes(res: dict) -> list[str]:
    return [c["code"] for c in res["candidates"]]


def _patch_text(pe: bytes, code: bytes, at: int = 0) -> bytes:
    out = bytearray(pe)
    out[TEXT_FILE_OFFSET + at:TEXT_FILE_OFFSET + at + len(code)] = code
    return bytes(out)


# ------------------------------------------------------------------------------------------------ taxonomy
def test_taxonomy_is_closed_and_every_row_is_complete():
    assert tuple(tax.CATEGORIES) == ("C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8")
    for s in ci.ALL_SIGNALS:
        assert s.code in tax.CATEGORIES and s.kind in tax.KINDS and s.strength in tax.STRENGTH_ORDER
        assert s.match and all(m for m in s.match)
        assert s.fp.strip() and s.why.strip(), f"{s.name}: a signal needs a false-positive note and a reason"
    for code in tax.CATEGORIES:
        assert any(s.code == code for s in ci.ALL_SIGNALS), f"no signal for {code}"
    for kind in tax.KINDS:
        assert any(s.kind == kind for s in ci.ALL_SIGNALS), f"no {kind} signals"
    assert {s.name for s in tax.PATTERN_SIGNALS} == set(ci.PATTERNS)


def test_catalogue_rows_are_reused_not_copied():
    catalogue = {t.technique for t in API_TECHNIQUES} | {m.technique for m in MARKER_TECHNIQUES}
    assert set(tax.FROM_CATALOGUE) <= catalogue
    reused = {s.name for s in ci.ALL_IMPORT_SIGNALS + ci.ALL_STRING_SIGNALS} & set(tax.FROM_CATALOGUE)
    assert reused == set(tax.FROM_CATALOGUE)
    # the strength is the weaker of the catalogue row and the cap
    api = next(s for s in ci.ALL_IMPORT_SIGNALS if s.name == "kernel-debugger-query")
    assert api.strength == "weak"
    # ordinary-program behaviour of the catalogue is NOT a check
    assert not {"process-enumeration", "process-open", "exception-filter", "timing-query",
                "executable-memory-write"} & set(tax.FROM_CATALOGUE)


def test_a_catalogue_technique_that_does_not_exist_fails_loudly(monkeypatch):
    monkeypatch.setitem(tax.FROM_CATALOGUE, "no-such-technique", ("C2", "weak", "x"))
    with pytest.raises(RuntimeError, match="no-such-technique"):
        ci._catalogue_signals()


# ------------------------------------------------------------------------------- one planted API per category
PLANTED = {
    "C1": {"USER32.dll": ["GetDlgItemTextA"]},
    "C2": {"KERNEL32.dll": ["CheckRemoteDebuggerPresent"]},
    "C3": {"KERNEL32.dll": ["GetSystemFirmwareTable"]},
    "C4": {"BCRYPT.dll": ["BCryptHashData"]},
    "C5": {"ADVAPI32.dll": ["GetCurrentHwProfileA"]},
    "C6": {"WINTRUST.dll": ["WinVerifyTrust"]},
    "C7": {"KERNEL32.dll": ["GetLocalTime"]},
    "C8": {"WININET.dll": ["InternetOpenA"]},
}


@pytest.mark.parametrize("code", sorted(PLANTED))
def test_one_planted_import_gives_exactly_one_candidate_with_the_right_code(code):
    res = _planted(PLANTED[code])
    assert res["state"] == "CANDIDATES_FOUND" and _codes(res) == [code], res["candidates"]
    c = res["candidates"][0]
    assert c["kind"] == "import" and c["id"] == "K1" and c["category"] == tax.CATEGORIES[code]
    assert c["fp"] and c["strength"] in tax.STRENGTH_ORDER
    line = ci.candidate_line(c)
    assert line.startswith(f"check K1 {code} signal={c['signal']} kind=import ")
    assert f"function={c['function']}" in line and "false positives:" in line


def test_a_second_planted_api_in_the_same_signal_stays_one_candidate_with_its_apis():
    res = _planted({"BCRYPT.dll": ["BCryptHashData", "BCryptCreateHash", "BCryptFinishHash"]})
    assert _codes(res) == ["C4"] and len(res["candidates"]) == 1
    assert res["candidates"][0]["apis"] == ["BCryptCreateHash", "BCryptFinishHash", "BCryptHashData"]


def test_no_planted_signal_is_not_the_same_as_no_checks():
    res = _planted({"KERNEL32.dll": ["Sleep", "ExitProcess"]})
    assert res["state"] == "NO_KNOWN_CANDIDATES" and res["candidates"] == []
    assert "does not mean the binary has no checks" in res["statement"]
    low = res["statement"].lower()
    assert "no checks." not in low and "clean" not in low and "unprotected" not in low


# ------------------------------------------------------------------------------------------ UNKNOWN, never "none"
def test_empty_imports_are_unknown_not_clean():
    res = ci.inventory(build_pe())
    assert res["state"] == "UNKNOWN" and res["candidates"] == []
    assert any("no named imports" in u for u in res["unknowns"]) and res["reason"]


def test_not_a_pe_is_unknown_and_still_scans_strings():
    res = ci.inventory(b"MZ" + bytes(range(256)) * 4)
    assert res["state"] == "UNKNOWN" and any("not a readable PE" in u for u in res["unknowns"])
    res = ci.inventory(b"junk junk Enter license key: junk junk")
    assert res["state"] == "CANDIDATES_FOUND" and _codes(res) == ["C1"]
    assert any("not a readable PE" in u for u in res["unknowns"])        # found something, but the gap is stated


def test_an_unreadable_import_table_is_a_coverage_gap_not_absence():
    res = ci.inventory(build_pe(imports={"KERNEL32.dll": ["Sleep"]}, import_dir=0x7FFF0))
    assert res["state"] == "UNKNOWN" and res["unknowns"], res
    assert not res["coverage"]["imports"].get("complete", False) or res["coverage"]["imports"]["scanned"] is False


def test_file_over_the_size_limit_is_unknown():
    res = ci.inventory(None)
    assert res["state"] == "UNKNOWN" and "larger than" in res["reason"]


def test_a_packed_image_makes_an_empty_result_unknown_but_keeps_found_candidates():
    pe = build_pe(imports={"KERNEL32.dll": ["Sleep"]})
    res = ci.inventory(pe, protection="likely_partial")
    assert res["state"] == "UNKNOWN" and any("stub" in u for u in res["unknowns"])
    res = ci.inventory(build_pe(imports=PLANTED["C6"]), protection="likely_partial")
    assert res["state"] == "CANDIDATES_FOUND" and any("stub" in u for u in res["unknowns"])
    assert "Coverage gaps" in res["statement"]


# -------------------------------------------------------------------------------------- CRT false positives
CRT_CLUSTER = ["SetUnhandledExceptionFilter", "UnhandledExceptionFilter", "IsProcessorFeaturePresent",
               "GetSystemTimeAsFileTime", "QueryPerformanceCounter", "GetCurrentProcessId", "GetModuleHandleW"]


def test_isdebuggerpresent_alone_is_a_c2_candidate():
    res = _planted({"KERNEL32.dll": ["IsDebuggerPresent"]})
    assert _codes(res) == ["C2"] and res["candidates"][0]["strength"] == "strong"
    assert res["suppressed"] == []


def test_crt_startup_cluster_suppresses_isdebuggerpresent_with_a_stated_rule():
    res = _planted({"KERNEL32.dll": ["IsDebuggerPresent", *CRT_CLUSTER]})
    assert res["candidates"] == [] and res["state"] == "NO_KNOWN_CANDIDATES"
    names = {s["function"] for s in res["suppressed"]}
    assert {"IsDebuggerPresent", "GetSystemTimeAsFileTime"} <= names
    assert all(s["rule"] == "crt-startup-cluster" and "crt-startup-cluster:" in s["why"] for s in res["suppressed"])
    raw = "\n".join(ci.render_lines(res))
    assert "suppressed rule=crt-startup-cluster signal=debugger-present code=C2" in raw


def test_a_non_runtime_check_next_to_the_cluster_is_not_suppressed():
    res = _planted({"KERNEL32.dll": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", *CRT_CLUSTER]})
    assert _codes(res) == ["C2"] and res["candidates"][0]["function"] == "CheckRemoteDebuggerPresent"


def test_module_path_reads_need_a_hash_partner():
    res = _planted({"KERNEL32.dll": ["GetModuleFileNameW", "VirtualQuery"]})
    assert res["candidates"] == [] and {s["rule"] for s in res["suppressed"]} == {"needs-hash-partner"}
    res = _planted({"KERNEL32.dll": ["GetModuleFileNameW"], "BCRYPT.dll": ["BCryptHashData"]})
    assert sorted(c["signal"] for c in res["candidates"]) == ["hash-api", "module-path-query"]
    assert next(c for c in res["candidates"] if c["signal"] == "module-path-query")["with"] == ["hash-api"]


def test_process_probing_and_timing_reads_are_not_checks():
    res = _planted({"KERNEL32.dll": ["OpenProcess", "CreateToolhelp32Snapshot", "ReadProcessMemory",
                                      "GetTickCount", "QueryPerformanceCounter", "VirtualProtect"]})
    assert res["candidates"] == []


# ----------------------------------------------------------------------------------------------- strings
def test_license_and_trial_strings_are_candidates_with_the_exact_text():
    res = _planted(markers=(b"Enter license key: \0", b"Trial expired.\0"))
    by = {c["string"]: c for c in res["candidates"]}
    assert by["Enter license key: "]["code"] == "C1" and by["Trial expired."]["code"] == "C7"
    assert by["Enter license key: "]["strength"] == "moderate" and by["Enter license key: "]["rva"] >= RDATA_RVA
    assert 'string="Enter license key: "' in ci.candidate_line(by["Enter license key: "])


def test_utf16_strings_are_found_and_whole_words_are_enforced():
    res = _planted(markers=(b"\0\0" + "Activation key".encode("utf-16-le") + b"\0\0", b"licensed to everyone\0", b"trialled\0"))
    assert [c["signal"] for c in res["candidates"]] == ["licence-phrase"]      # 'licensed' / 'trialled' are other words
    assert res["candidates"][0]["encoding"] == "utf-16le"


def test_one_string_is_one_candidate_with_the_strongest_signal_and_the_others_as_also():
    res = _planted(markers=(b"Your license has expired.\0",))
    assert len(res["candidates"]) == 1
    c = res["candidates"][0]
    assert c["strength"] == "moderate" and c["code"] == "C7" and c["also"] == ["C1"]
    assert "also=C1" in ci.candidate_line(c)


def test_the_import_tables_own_name_strings_are_not_program_strings():
    res = _planted({"NTDLL.dll": ["NtQueryInformationProcess"]})
    assert [c["kind"] for c in res["candidates"]] == ["import"]


def test_a_dynamically_resolved_api_name_string_is_a_c2_candidate():
    res = _planted(markers=(b"NtQueryInformationProcess\0",))
    assert [(c["code"], c["signal"], c["kind"]) for c in res["candidates"]] == [("C2", "debugger-message", "string")]


def test_urls_to_namespaces_are_suppressed_and_other_urls_are_weak_c8():
    res = _planted(markers=(b'xmlns="http://schemas.microsoft.com/win/2004/08/events"\0',
                            b"https://files.example.org/v1\0"))
    urls = [c for c in res["candidates"] if c["signal"] == "url"]
    assert len(urls) == 1 and urls[0]["strength"] == "weak" and urls[0]["string"].startswith("https://files")
    assert any(s["rule"] == "benign-url-host" for s in res["suppressed"])


def test_target_text_cannot_inject_lines_into_the_evidence():
    res = _planted({"EVIL\nSPOOF.dll": ["WinVerifyTrust"]}, markers=(b"license key\r\ncheck K99 C2 fake\0",))
    lines = ci.render_lines(res)
    assert not any(ln.startswith("check K99") for ln in lines)
    assert all("\n" not in ln and "\r" not in ln for ln in lines)


# -------------------------------------------------------------------------------------- instruction patterns
def test_peb_beingdebugged_read_is_a_strong_c2_pattern_x64():
    code = bytes.fromhex("65488b042560000000") + bytes.fromhex("0fb64002")        # mov rax,gs:[60h]; movzx eax,[rax+2]
    res = ci.inventory(_patch_text(build_pe(imports={"KERNEL32.dll": ["Sleep"]}), code, 0x10))
    assert _codes(res) == ["C2"]
    c = res["candidates"][0]
    assert c["signal"] == "peb-beingdebugged" and c["strength"] == "strong" and c["rva"] == TEXT_RVA + 0x10
    assert c["file_offset"] == TEXT_FILE_OFFSET + 0x10 and c["bytes"].startswith("65488b042560")


def test_peb_pointer_load_without_the_beingdebugged_read_is_not_a_candidate():
    res = ci.inventory(_patch_text(build_pe(imports={"KERNEL32.dll": ["Sleep"]}), bytes.fromhex("65488b042560000000")))
    assert res["candidates"] == []


def test_peb_beingdebugged_x86():
    code = bytes.fromhex("64a130000000") + bytes.fromhex("807802" "00")             # mov eax,fs:[30h]; cmp byte [eax+2],0
    res = ci.inventory(_patch_text(build_pe(is64=False, imports={"KERNEL32.dll": ["Sleep"]}), code))
    assert [c["signal"] for c in res["candidates"]] == ["peb-beingdebugged"]


def test_other_patterns_cpuid_rdtsc_fnv_crc():
    pe = build_pe(imports={"KERNEL32.dll": ["Sleep"]}, markers=(bytes.fromhex("0000000096300777" "2c610eeeba510999"),))
    code = (bytes.fromhex("b800000040" "0fa2") + b"\x90" * 4 + bytes.fromhex("0f31") + b"\x90" * 8 + bytes.fromhex("0f31")
            + b"\x90" * 4 + bytes.fromhex("69d193010001"))
    res = ci.inventory(_patch_text(pe, code))
    got = {c["signal"]: c for c in res["candidates"]}
    assert set(got) == {"cpuid-hypervisor", "rdtsc-pair", "fnv-1a-prime", "crc32-table"}, got.keys()
    assert got["cpuid-hypervisor"]["code"] == "C3" and got["rdtsc-pair"]["code"] == "C2"
    assert got["fnv-1a-prime"]["code"] == "C1" and got["crc32-table"]["code"] == "C4"
    assert got["crc32-table"]["file_offset"] >= RDATA_FILE_OFFSET


def test_one_rdtsc_alone_and_cpuid_leaf_1_alone_are_not_candidates():
    code = bytes.fromhex("0f31") + b"\x90" * 200 + bytes.fromhex("0f31") + bytes.fromhex("b801000000" "0fa2")
    res = ci.inventory(_patch_text(build_pe(imports={"KERNEL32.dll": ["Sleep"]}), code))
    assert res["candidates"] == []


# ----------------------------------------------------------------------------------------- code references
def test_a_string_candidate_gets_the_code_location_that_points_at_it_x64():
    pe = build_pe(imports={"KERNEL32.dll": ["Sleep"]}, markers=(b"Enter license key: \0",))
    str_rva = RDATA_RVA + pe.index(b"Enter license key: ") - RDATA_FILE_OFFSET
    lea = b"\x48\x8d\x0d" + struct.pack("<i", str_rva - (TEXT_RVA + 0x20 + 7))      # lea rcx,[rip+disp]
    res = ci.inventory(_patch_text(pe, lea, 0x20))
    c = res["candidates"][0]
    assert c["refs"] == [{"rva": TEXT_RVA + 0x20, "function": None}] and c["ref_count"] == 1
    assert f"refs={hex(TEXT_RVA + 0x20)}" in ci.candidate_line(c)


def test_an_import_candidate_gets_its_call_sites_x64():
    pe = build_pe(imports={"WINTRUST.dll": ["WinVerifyTrust"]})
    res0 = ci.inventory(pe)
    iat = res0["candidates"][0]["iat_rva"]
    call = b"\xff\x15" + struct.pack("<i", iat - (TEXT_RVA + 0x40 + 6))             # call [rip+disp]
    res = ci.inventory(_patch_text(pe, call, 0x40))
    assert res["candidates"][0]["refs"][0]["rva"] == TEXT_RVA + 0x40
    assert "calls=" in ci.candidate_line(res["candidates"][0])


def test_a_string_candidate_gets_its_reference_x86():
    base = 0x400000
    pe = build_pe(is64=False, imports={"KERNEL32.dll": ["Sleep"]}, markers=(b"Trial expired.\0",))
    str_rva = RDATA_RVA + pe.index(b"Trial expired.") - RDATA_FILE_OFFSET
    push = b"\x68" + struct.pack("<I", base + str_rva)                                  # push offset str
    res = ci.inventory(_patch_text(pe, push, 0x30))
    assert res["candidates"][0]["refs"][0]["rva"] == TEXT_RVA + 0x30


# ------------------------------------------------------------------------------------------ determinism, caps
def test_the_inventory_is_deterministic_and_ids_follow_the_ranking():
    pe = build_pe(imports={**PLANTED["C6"], **PLANTED["C7"]}, markers=(b"Enter license key: \0",))
    a, b = ci.inventory(pe), ci.inventory(pe)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    ranks = [tax.STRENGTH_ORDER[c["strength"]] for c in a["candidates"]]
    assert ranks == sorted(ranks) and [c["id"] for c in a["candidates"]] == [f"K{i}" for i in range(1, len(ranks) + 1)]


def test_the_candidate_list_is_capped_and_the_total_is_kept():
    many = {f"DLL{i}.dll": ["WinVerifyTrust"] for i in range(3)}
    res = _planted(many)
    assert res["candidate_count"] == len(res["candidates"])
    markers = tuple(f"license key number {i:04d}\0".encode() for i in range(70))
    res = _planted(markers=markers)
    assert len([c for c in res["candidates"] if c["signal"] == "licence-phrase"]) == ci.MAX_RUNS_PER_SIGNAL
    assert any("not listed" in n for n in res["notes"])
    assert any("more than" in n and "license key" in n for n in res["notes"])    # the examination cap is stated


def test_a_capped_string_scan_is_a_coverage_gap_not_no_known_candidates():
    """70 benign URLs: the 'https://' needle reaches the per-needle examination cap and every match that WAS examined
    is suppressed as a namespace / certificate host, so no candidate is left. The cap hides candidates: the state is
    UNKNOWN (the cap is the reason), never NO_KNOWN_CANDIDATES."""
    urls = tuple(f"https://example.com/x{i:03d}\0".encode() for i in range(70))
    res = _planted(markers=urls)
    assert res["candidates"] == [] and res["suppressed"], res["candidates"]
    assert res["state"] == "UNKNOWN", res["statement"]
    assert str(ci.MAX_MATCHES_PER_NEEDLE) in res["reason"] and "capped" in res["reason"]
    assert "No known check signal found" not in res["statement"]
    assert res["coverage"]["strings"]["capped_needles"] >= 1
    assert any("capped" in u for u in res["unknowns"])
    # with a candidate found the state stays CANDIDATES_FOUND, and the statement says the coverage is partial
    res = _planted(markers=urls + (b"Enter license key: \0",))
    assert res["state"] == "CANDIDATES_FOUND" and _codes(res) == ["C1"]
    assert "Coverage gaps" in res["statement"] and "capped" in res["statement"]
    assert "partial" in res["statement"]


def test_by_code_counts_every_candidate_before_the_evidence_is_capped(monkeypatch):
    """MAX_CANDIDATES keeps 200 entries in the evidence; by_code and candidate_count must cover all of them, so the
    per-code counts sum to the total (250 here) and the dropped ones are stated."""
    monkeypatch.setattr(ci, "MAX_RUNS_PER_SIGNAL", 1000)     # else one signal lists at most 4 strings
    monkeypatch.setattr(ci, "MAX_MATCHES_PER_NEEDLE", 1000)  # else one needle examines at most 64 matches
    res = _planted(markers=(b"license\0",) * 250)
    assert res["state"] == "CANDIDATES_FOUND" and "250 check candidate(s)" in res["statement"]
    assert res["candidate_count"] == 250 and len(res["candidates"]) == ci.MAX_CANDIDATES
    assert sum(res["by_code"].values()) == res["by_code"]["C1"] == 250
    assert len([c for c in res["candidates"] if c["code"] == "C1"]) == ci.MAX_CANDIDATES
    assert any("not listed in the evidence" in n and "50" in n for n in res["notes"])
    assert res["by_code"] == {code: (250 if code == "C1" else 0) for code in tax.CATEGORIES}


# --------------------------------------------------------------------------------- target_open (fake engine)
def _open(tmp_path: Path, data: bytes, detail: str | None = None):
    tmp_path.mkdir(parents=True, exist_ok=True)
    target = tmp_path / "t.exe"
    target.write_bytes(data)
    manifest = make_manifest(tmp_path / "scope.json", target)
    hub = Hub(Config.load(tmp_path / "data"), FakeEngine())
    reply = hub.target_open(str(target), str(manifest), None, *([detail] if detail else []))
    return hub, reply, target, manifest


def _checks(reply: dict) -> dict:
    return reply["target"]["protection"]["checks"]


def _raw(hub, ev_id: str) -> str:
    rec = hub._s.ledger.state["evidence"][ev_id]
    return hub._s.cas.get(rec["raw"]["blob_sha256"]).decode("utf-8")


def _licence_pe() -> bytes:
    return build_pe(imports={**PLANTED["C6"], "KERNEL32.dll": ["IsDebuggerPresent"]},
                    markers=(b"Enter license key: \0", b"Trial expired.\0"))


def test_target_open_lists_the_candidates_with_evidence_and_quotes(tmp_path):
    hub, reply, *_ = _open(tmp_path, _licence_pe())
    try:
        ch = _checks(reply)
        assert ch["state"] == "CANDIDATES_FOUND" and ch["candidate_count"] == 4 and ch["untrusted_content"] is True
        assert ch["by_code"] == {"C1": 1, "C2": 1, "C6": 1, "C7": 1}
        raw = _raw(hub, ch["evidence_id"])
        assert raw.startswith("check_inventory state=CANDIDATES_FOUND")
        for c in ch["candidates"]:
            assert c["evidence_id"] == ch["evidence_id"] and c["quote"] in raw and len(c["quote"]) >= 4
            assert c["code"] in tax.CATEGORIES and c["category"] and c["strength"]
        s = next(c for c in ch["candidates"] if c["kind"] == "string" and c["code"] == "C1")
        assert s["string"].startswith("<untrusted_target_content") and "Enter license key: " in s["string"]
        ev = hub._s.ledger.state["evidence"][ch["evidence_id"]]
        assert ev["operation"] == "check_inventory" and ev["confidence"] == "derived"
        assert ev["coverage"]["relationship"] == "partial"                      # a candidate list is never exhaustive
        assert ch["evidence_id"] != reply["target"]["protection"]["evidence_id"]
    finally:
        hub.close()


def test_summary_and_full_detail_caps(tmp_path):
    many = {"WINTRUST.dll": ["WinVerifyTrust"], "WININET.dll": ["InternetOpenA"],
            "KERNEL32.dll": ["GetLocalTime", "GetComputerNameExA", "GetSystemFirmwareTable",
                             "CheckRemoteDebuggerPresent"],
            "BCRYPT.dll": ["BCryptHashData"], "USER32.dll": ["GetDlgItemTextA"], "NTDLL.dll": ["NtQueryObject"],
            "ADVAPI32.dll": ["GetCurrentHwProfileA"], "IMAGEHLP.dll": ["MapFileAndChecksumA"],
            "WINHTTP.dll": ["WinHttpOpen"], "CRYPT32.dll": ["CertGetCertificateChain"]}
    hub, reply, *_ = _open(tmp_path / "a", build_pe(imports=many))
    hub2, reply2, *_ = _open(tmp_path / "b", build_pe(imports=many), "full")
    try:
        a, b = _checks(reply), _checks(reply2)
        assert a["candidate_count"] == b["candidate_count"] == 12
        assert len(a["candidates"]) == check_tool.SUMMARY_CANDIDATES == 10 and a["candidates_truncated"] is True
        assert len(b["candidates"]) == 12 and "candidates_truncated" not in b
        assert "why" not in a["candidates"][0] and b["candidates"][0]["why"] and b["candidates"][0]["false_positives"]
        assert "coverage" in b and "coverage" not in a and "suppressed" in b
    finally:
        hub.close()
        hub2.close()


def test_unknown_when_nothing_could_be_read(tmp_path):
    hub, reply, *_ = _open(tmp_path, build_pe())
    try:
        ch = _checks(reply)
        assert ch["state"] == "UNKNOWN" and ch["candidate_count"] == 0 and ch["reason"]
        assert ch["status"] == "PARTIAL" and "not 'no checks'" in ch["statement"]
    finally:
        hub.close()


def test_a_packed_target_is_unknown_for_the_checks(tmp_path):
    from .test_protection_target_open import _packed_pe
    hub, reply, *_ = _open(tmp_path, _packed_pe())
    try:
        assert reply["target"]["protection"]["static_coverage"] == "likely_partial"
        assert _checks(reply)["state"] == "UNKNOWN"
    finally:
        hub.close()


def test_a_failing_inventory_does_not_fail_target_open(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("inventory blew up")
    monkeypatch.setattr(check_tool, "inventory", boom)
    hub, reply, *_ = _open(tmp_path, _licence_pe())
    try:
        assert reply["status"] == "OK" and reply["target"]["protection"]["diagnosis"] in (
            "NO_KNOWN_INDICATORS", "INDICATORS_FOUND")
        ch = _checks(reply)
        assert ch["state"] == "UNKNOWN" and ch["status"] in ("ERROR", "INTERNAL") and "blew up" in ch["error"]
    finally:
        hub.close()


def test_reopen_reuses_the_step(tmp_path):
    hub, r1, target, manifest = _open(tmp_path, _licence_pe())
    try:
        r2 = hub.target_open(str(target), str(manifest))
        assert _checks(r2)["evidence_id"] == _checks(r1)["evidence_id"] and _checks(r2)["step_cached"] is True
    finally:
        hub.close()


def test_coverage_does_not_count_the_open_time_scans_as_examination(tmp_path):
    hub, reply, *_ = _open(tmp_path, _licence_pe())
    try:
        cov = hub.coverage()
        assert cov["assessment"] == "NOT_EXAMINED" and cov["incomplete_calls_total"] == 0
        assert cov["checks"]["state"] == "CANDIDATES_FOUND" and cov["checks"]["candidate_count"] == 4
    finally:
        hub.close()


# ------------------------------------------------------------- how the verifier treats the new evidence lines
def _quote(hub, ch: dict, signal: str) -> tuple[str, str]:
    raw = _raw(hub, ch["evidence_id"])
    line = next(ln for ln in raw.splitlines() if ln.startswith("check ") and f"signal={signal} " in ln)
    return line, line.split(" | ")[0]


def test_a_candidate_claim_verifies_like_other_static_evidence(tmp_path):
    hub, reply, *_ = _open(tmp_path, _licence_pe())
    try:
        ch = _checks(reply)
        ev = ch["evidence_id"]
        _, q = _quote(hub, ch, "debugger-present")
        r = hub.claim_add("Candidate C2 (anti-debug): KERNEL32.dll imports IsDebuggerPresent.", [ev],
                          [{"type": "quote", "evidence_id": ev, "text": q}], kind="observation")
        assert r["status"] == "SUPPORTED", r
        _, q = _quote(hub, ch, "licence-phrase")
        r = hub.claim_add('Candidate C1: the file contains the string "Enter license key: ".', [ev],
                          [{"type": "quote", "evidence_id": ev, "text": q}], kind="observation")
        assert r["status"] == "SUPPORTED", r
    finally:
        hub.close()


def test_a_candidate_can_never_prove_behavior_or_absence(tmp_path):
    hub, reply, *_ = _open(tmp_path, _licence_pe())
    try:
        ch = _checks(reply)
        ev = ch["evidence_id"]
        _, q = _quote(hub, ch, "licence-phrase")
        atoms = [{"type": "quote", "evidence_id": ev, "text": q}]
        r = hub.claim_add("The program validates the license key and rejects an invalid key.", [ev], atoms,
                          kind="behavior")
        assert r["status"] not in ("SUPPORTED", "PROVEN"), r
        r = hub.claim_add("The program has no anti-debug check.", [ev], atoms, kind="observation", polarity="absent")
        assert r["status"] not in ("SUPPORTED", "PROVEN"), r
        assert any(i["code"] == "ABSENCE_WITHOUT_COMPLETE_COVERAGE" for i in r["issues"]), r
    finally:
        hub.close()


def test_term_binding_ties_the_claim_text_to_the_evidence(tmp_path):
    hub, reply, *_ = _open(tmp_path, _licence_pe())
    try:
        ch = _checks(reply)
        ev = ch["evidence_id"]
        _, q = _quote(hub, ch, "debugger-present")
        atoms = [{"type": "quote", "evidence_id": ev, "text": q}]
        ok = hub.claim_add("IsDebuggerPresent is imported from kernel32.dll (candidate C2).", [ev], atoms,
                           kind="observation")
        assert ok["status"] == "SUPPORTED", ok
        bad = hub.claim_add("NtQueryInformationProcess is imported (candidate C2).", [ev], atoms, kind="observation")
        assert bad["status"] != "SUPPORTED" and any(i["code"] == "TERM_NOT_IN_EVIDENCE" for i in bad["issues"]), bad
        wrong_line = hub.claim_add("IsDebuggerPresent is imported.", [ev],
                                   [{"type": "quote", "evidence_id": ev, "text": "check K9 C2 signal=debugger-present"}],
                                   kind="observation")
        assert wrong_line["status"] != "SUPPORTED"
    finally:
        hub.close()


def test_a_candidate_address_is_an_evidence_location(tmp_path):
    pe = build_pe(imports={"KERNEL32.dll": ["Sleep"]}, markers=(b"Enter license key: \0",))
    str_rva = RDATA_RVA + pe.index(b"Enter license key: ") - RDATA_FILE_OFFSET
    lea = b"\x48\x8d\x0d" + struct.pack("<i", str_rva - (TEXT_RVA + 0x20 + 7))
    hub, reply, *_ = _open(tmp_path, _patch_text(pe, lea, 0x20))
    try:
        ch = _checks(reply)
        c = ch["candidates"][0]
        assert c["refs"] == [hex(TEXT_RVA + 0x20)] and c["rva"] == hex(str_rva)
        ev = ch["evidence_id"]
        line, q = _quote(hub, ch, "licence-phrase")
        r = hub.claim_add(f"The string at {c['rva']} is referenced by code at {c['refs'][0]}.", [ev],
                          [{"type": "quote", "evidence_id": ev, "text": q},
                           {"type": "address", "evidence_id": ev, "value": c["refs"][0]}], kind="observation")
        assert r["status"] == "SUPPORTED", r
        assert any(loc["space"] == "rva" and loc["start"] == TEXT_RVA + 0x20
                   for loc in hub._s.ledger.state["evidence"][ev]["locations"])
    finally:
        hub.close()
