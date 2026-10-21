"""Static PE profile (analysis/pe_profile.py): synthetic PE fixtures, fixed known answers.

The fixtures are built here byte by byte (no real binary); the layout is the expected answer. The profile and the
protection diagnosis must agree on the facts they share (entry point, overlay, W+X).
"""
import os
import random
import struct

import pytest

from redharness.analysis.pe_image import PeError
from redharness.analysis.pe_profile import esc, profile_bytes, profile_dict, profile_lines
from redharness.analysis.protection import compute_entropy
from redharness.mcp.protection_tool import diagnose

X, R, W = 0x20000000, 0x40000000, 0x80000000
CODE, INIT = 0x20, 0x40
SA, FA, HDR = 0x1000, 0x200, 0x400
E = 0x80


def make_pe(sections, *, is64=True, entry=0x1000, dirs=None, overlay=b"", dllchars=0xC160, ts=0x5F000000,
            subsystem=3, linker=(14, 29), base=None, size_of_image=None, HDR=HDR):
    """sections: [(name bytes, rva, vsize, data bytes, characteristics)]; raw data placed sequentially."""
    base = base if base is not None else (0x140000000 if is64 else 0x400000)
    sizeopt = 0xF0 if is64 else 0xE0
    hdr = bytearray(HDR)
    hdr[0:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3C, E)
    hdr[E:E + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", hdr, E + 4, 0x8664 if is64 else 0x14C, len(sections), ts, 0, 0, sizeopt, 0x22)
    opt = E + 24
    struct.pack_into("<H", hdr, opt, 0x20B if is64 else 0x10B)
    hdr[opt + 2], hdr[opt + 3] = linker
    struct.pack_into("<I", hdr, opt + 16, entry)
    struct.pack_into("<Q" if is64 else "<I", hdr, opt + (24 if is64 else 28), base)
    struct.pack_into("<II", hdr, opt + 32, SA, FA)
    last = max(r + max(v, len(d)) for _n, r, v, d, _c in sections)
    soi = size_of_image or ((last + SA - 1) // SA * SA)
    struct.pack_into("<II", hdr, opt + 56, soi, HDR)
    struct.pack_into("<HH", hdr, opt + 68, subsystem, dllchars)
    cnt_at, dirs_at = (opt + 108, opt + 112) if is64 else (opt + 92, opt + 96)
    struct.pack_into("<I", hdr, cnt_at, 16)
    for idx, (rva, size) in (dirs or {}).items():
        struct.pack_into("<II", hdr, dirs_at + 8 * idx, rva, size)
    body = bytearray()
    for i, (nm, rva, vs, data, ch) in enumerate(sections):
        raw = (len(data) + FA - 1) // FA * FA
        ptr = HDR + len(body) if raw else 0
        struct.pack_into("<8sIIIIIIHHI", hdr, opt + sizeopt + 40 * i, nm, vs, rva, raw, ptr, 0, 0, 0, 0, ch)
        body += data.ljust(raw, b"\0")
    return bytes(hdr) + bytes(body) + overlay


def basic(**kw):
    sections = [(b".text", 0x1000, 0x200, bytes([0x90]) * 0x200, X | R | CODE),
                (b".data", 0x2000, 0x200, bytes(0x200), R | W | INIT)]
    return make_pe(sections, **kw)


def lines(data):
    return profile_lines(profile_bytes(data))


def find(ls, key):
    return [ln for ln in ls if key in ln]


def test_basic_pe32plus_fields_and_sections():
    p = profile_bytes(basic())
    assert (p.pe_format, p.arch, p.subsystem, p.linker) == ("PE32+", "x64", 3, "14.29")
    assert p.dll_flags == {"aslr": True, "dep": True, "cfg": True, "high_entropy_va": True, "relocs_stripped": False}
    t, d = p.sections
    assert (t.name, t.rva, t.vsize, t.raw_size, t.perms) == (".text", 0x1000, 0x200, 0x200, "R-X")
    assert t.flags == ("CODE",) and t.entropy == "0.00"
    assert d.perms == "RW-" and not d.notes
    ls = profile_lines(p)
    assert ls[0].startswith("pe_profile format=PE32+ machine=x64(0x8664) subsystem=windows_cui(3) linker=14.29")
    assert "pe_profile timestamp=0x5f000000 (2020-" in ls[1]
    assert find(ls, "entry_point rva=0x1000 section=\".text\" executable=yes")
    assert find(ls, "overlay offset=0x800 size=0 signature=none")
    assert find(ls, "tls present=no")
    assert find(ls, "imports functions=0 dlls=0") and find(ls, "exports functions=0 (no export directory)")
    assert find(ls, "debug entries=0")


def test_pe32_format_and_flags_off():
    p = profile_bytes(basic(is64=False, dllchars=0))
    assert p.pe_format == "PE32" and p.arch == "x86"
    assert not any(p.dll_flags[k] for k in ("aslr", "dep", "cfg", "high_entropy_va"))
    assert "aslr=no dep=no cfg=no high_entropy_va=no" in lines(basic(is64=False, dllchars=0))[2]


def test_overlay_and_signature_location():
    ov = bytes(range(256)) * 4
    sig_off = 0x800 + 0x10
    data = basic(overlay=ov, dirs={4: (sig_off, 0x100)})
    p = profile_bytes(data)
    assert (p.overlay_offset, p.overlay_size) == (0x800, len(ov))
    assert p.sig_in_overlay is True and p.sig_offset == sig_off
    ln = find(lines(data), "pe_profile overlay")[0]
    assert "offset=0x800 size=1024 signature_offset=0x810 signature_size=0x100 signature_in_overlay=yes" in ln
    assert "NOT validated" in ln


def test_signature_outside_overlay_and_past_eof():
    # signature offset inside the section area: not in the overlay
    p = profile_bytes(basic(overlay=bytes(64), dirs={4: (0x500, 0x20)}))
    assert p.sig_in_overlay is False
    # past end of file
    ln = find(lines(basic(overlay=bytes(64), dirs={4: (0x810, 0x1000)})), "pe_profile overlay")[0]
    assert "signature_extends_past_end_of_file=yes" in ln and "signature_in_overlay=no" in ln


def tls_pe(is64, cbs, nonterminated=False):
    psz = 8 if is64 else 4
    base = 0x140000000 if is64 else 0x400000
    rdata = bytearray(0x200)
    arr_rva = 0x2000 + 0x80
    fmt = "<" + ("Q" if is64 else "I") * 4 + "II"
    struct.pack_into(fmt, rdata, 0, 0, 0, 0, base + arr_rva, 0, 0)
    for i, c in enumerate(cbs):
        struct.pack_into("<Q" if is64 else "<I", rdata, 0x80 + i * psz, base + c)
    if nonterminated:   # array runs to the end of the section without a terminator
        for i in range(0x80 // psz):
            struct.pack_into("<Q" if is64 else "<I", rdata, 0x80 + i * psz, base + 0x1000)
    secs = [(b".text", 0x1000, 0x200, bytes([0xCC]) * 0x200, X | R | CODE), (b".rdata", 0x2000, 0x200, bytes(rdata), R | INIT)]
    return make_pe(secs, is64=is64, dirs={9: (0x2000, 4 * psz + 8)})


@pytest.mark.parametrize("is64", [True, False])
def test_tls_callbacks_listed(is64):
    base = 0x140000000 if is64 else 0x400000
    ln = find(lines(tls_pe(is64, [0x1010, 0x1020])), "pe_profile tls")[0]
    assert "present=yes directory_rva=0x2000 callback_array_rva=0x2080 callbacks=2" in ln
    assert "va=[0x%x,0x%x]" % (base + 0x1010, base + 0x1020) in ln


def test_tls_unreadable_is_marked_not_dropped():
    # callback array runs off the end of the section without a null terminator
    ln = find(lines(tls_pe(True, [], nonterminated=True)), "pe_profile tls")[0]
    assert "callbacks=unreadable" in ln or "callbacks=" in ln
    # directory pointing outside the image
    ln2 = find(lines(basic(dirs={9: (0x90000, 0x28)})), "pe_profile tls")[0]
    assert "callbacks=unreadable" in ln2 and "outside the image" in ln2


def test_tls_callback_list_capped():
    ls = find(lines(tls_pe(True, [0x1000 + 0x10 * i for i in range(12)])), "pe_profile tls")[0]
    assert "callbacks=12 (list truncated)" in ls and ls.count("0x1400") == 8


def test_entry_outside_sections():
    data = basic(entry=0x5000, size_of_image=0x6000)
    p = profile_bytes(data)
    assert p.entry_section is None and p.entry_in_exec is False
    assert "section=outside any section executable=no" in find(lines(data), "entry_point")[0]
    far = basic(entry=0x9000000)
    assert "executable=unknown (outside the image)" in find(lines(far), "entry_point")[0]


def test_entry_in_nonexecutable_section():
    p = profile_bytes(basic(entry=0x2000))
    assert p.entry_section == ".data" and p.entry_in_exec is False


def test_wx_section_flagged():
    secs = [(b".text", 0x1000, 0x200, bytes([0x90]) * 0x200, X | W | R | CODE)]
    p = profile_bytes(make_pe(secs))
    assert "writable+executable" in p.sections[0].notes and p.sections[0].perms == "RWX"


def test_high_entropy_and_virtual_size_notes():
    rnd = random.Random(7).randbytes(0x2000)
    secs = [(b".text", 0x1000, 0x2000, rnd, X | R | CODE),
            (b".bss", 0x4000, 0x40000, bytes(0x200), R | W | INIT)]
    p = profile_bytes(make_pe(secs))
    t, b = p.sections
    assert float(t.entropy) > 7.5 and any("high entropy" in n for n in t.notes)
    assert t.entropy == f"{compute_entropy(rnd):.2f}"
    assert "virtual size >> raw size" in b.notes
    assert "virtual size >> raw size" in find(profile_lines(p), "section[1]")[0]


def test_section_without_raw_data_not_measured():
    secs = [(b".text", 0x1000, 0x200, bytes([0x90]) * 0x200, X | R | CODE),
            (b".bss", 0x2000, 0x1000, b"", R | W | 0x80)]
    p = profile_bytes(make_pe(secs))
    assert p.sections[1].entropy is None
    assert "entropy=not-measured" in find(profile_lines(p), "section[1]")[0]


def test_untrusted_section_name_escaped():
    secs = [(b'.te"\x01\x1b', 0x1000, 0x200, bytes(0x200), X | R | CODE)]
    ln = find(lines(make_pe(secs)), "section[0]")[0]
    assert 'name=".te\\"\\x01\\x1b"' in ln and "\x1b" not in ln
    assert esc("a" * 100, 10) == "a" * 10 + "..."


def test_imports_minimal_and_exports_counts():
    from tests.unit._synthpe import build_pe as synth
    data = synth(imports={"KERNEL32.dll": ["LoadLibraryA", "GetProcAddress"]}, tls_callbacks=(0x1010,))
    p = profile_bytes(data)
    assert p.imports["functions"] == 2 and p.imports["minimal"] and p.imports["loader_only"]
    assert p.tls["status"] == "ok" and len(p.tls["callbacks"]) == 1
    ln = find(profile_lines(p), "pe_profile imports")[0]
    assert "minimal_table=yes only_loader_functions=yes" in ln and "not a verdict" in ln
    many = synth(imports={"a.dll": [f"F{i}" for i in range(30)]})
    assert not profile_bytes(many).imports["minimal"]
    assert not profile_bytes(synth(imports={"a.dll": ["CreateFileW"]})).imports["loader_only"]


def test_broken_import_dir_marked_unavailable_but_profile_survives():
    from tests.unit._synthpe import build_pe as synth
    p = profile_bytes(synth(import_dir=0x3F00000))
    ln = find(profile_lines(p), "pe_profile imports")[0]
    assert "imports unavailable(" in ln
    assert p.sections and p.entry_section == ".text"


def test_debug_directory_codeview_name_only():
    rsds = b"RSDS" + bytes(16) + struct.pack("<I", 1) + b"C:\\build\\secret_dir\\app.pdb\0"
    dbg = bytearray(28)
    # entry: chars, ts, maj, min, type=2, size, addr_raw(rva), ptr_raw(file offset) -- ptr patched below
    rd = bytearray(0x200)
    rd[0x40:0x40 + len(rsds)] = rsds
    secs = [(b".text", 0x1000, 0x200, bytes([0x90]) * 0x200, X | R | CODE), (b".rdata", 0x2000, 0x200, bytes(rd), R | INIT)]
    ptr = HDR + 0x200 + 0x40
    struct.pack_into("<IIHHIIII", dbg, 0, 0, 0, 0, 0, 2, len(rsds), 0x2040, ptr)
    rd[0x80:0x80 + 28] = dbg
    secs[1] = (b".rdata", 0x2000, 0x200, bytes(rd), R | INIT)
    data = make_pe(secs, dirs={6: (0x2080, 28)})
    ln = find(lines(data), "pe_profile debug")[0]
    assert 'types=[codeview] codeview_pdb="app.pdb"' in ln and "secret_dir" not in ln


def test_deterministic_and_dict_has_no_floats():
    d = basic(overlay=b"xyz")
    assert lines(d) == lines(d)
    def walk(o):
        if isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, (list, tuple)):
            for v in o:
                walk(v)
        else:
            assert not isinstance(o, float)
    walk(profile_dict(profile_bytes(d)))


def test_not_a_pe_raises():
    with pytest.raises(PeError):
        profile_bytes(b"MZ" + bytes(100))


@pytest.mark.parametrize("data", [
    basic(), basic(entry=0x5000, size_of_image=0x6000), basic(overlay=b"ab" * 100),
    make_pe([(b".text", 0x1000, 0x200, bytes(0x200), X | W | R | CODE)]),
    make_pe([(b"UPX0", 0x1000, 0x2000, b"", X | W | R), (b"UPX1", 0x3000, 0x1000, random.Random(1).randbytes(0x1000), X | W | R)],
            entry=0x3000)])
def test_profile_and_diagnosis_agree(data):
    out = diagnose(data)
    res = out["result"]
    pp = res["pe_profile"]
    ids = {i["name"] for i in res["indicators"]}
    ep = res["entry_point"]
    assert ep["in_executable_section"] == pp["entry_point"]["executable"]
    assert ep["section"] == pp["entry_point"]["section"]
    assert (pp["overlay"]["size"] > 0) == any("overlay" in n for n in ids)
    assert not any("INCONSISTENT" in n for n in res["notes"])
    assert "pe_profile format=" in out["raw"]
    for s, ps in zip(res["sections"], pp["sections"]):
        assert s["entropy"] == ps["entropy"] and s["rva"] == ps["rva"] and s["raw_size"] == ps["raw_size"]


def _open(tmp_path, data, detail=None):
    from redharness.config import Config
    from redharness.mcp.session import Hub
    from ._fake_engine import FakeEngine
    from .mcp_helpers import make_manifest
    tmp_path.mkdir(parents=True, exist_ok=True)
    target = tmp_path / "t.exe"
    target.write_bytes(data)
    manifest = make_manifest(tmp_path / "scope.json", target)
    hub = Hub(Config.load(tmp_path / "data"), FakeEngine())
    return hub, hub.target_open(str(target), str(manifest), None, *([detail] if detail else []))


def test_target_open_reply_and_evidence_carry_profile(tmp_path):
    hub, reply = _open(tmp_path, basic(overlay=bytes(32), dirs={4: (0x800, 0x20)}))
    try:
        prof = reply["target"]["protection"]["pe_profile"]
        ev_id = reply["target"]["protection"]["evidence_id"]
        assert prof["evidence_id"] == ev_id and "not a packer verdict" in prof["note"]
        assert prof["lines"][0].startswith("pe_profile format=PE32+")
        rec = hub._s.ledger.state["evidence"][ev_id]
        raw = hub._s.cas.get(rec["raw"]["blob_sha256"]).decode("utf-8")
        for ln in prof["lines"]:
            assert ln in raw                       # every reply line is quotable from the evidence
        assert "signature_in_overlay=yes" in raw
        assert rec["source"]["tool_version"] == "6"
    finally:
        hub.close()


def test_target_open_summary_caps_profile_lines(tmp_path):
    secs = [(b".s%d" % i, 0x1000 * (i + 1), 0x10, bytes([i]) * 0x200, R | INIT) for i in range(60)]
    hub, reply = _open(tmp_path, make_pe(secs, entry=0x1000, HDR=0x1000))
    try:
        prof = reply["target"]["protection"]["pe_profile"]
        assert len(prof["lines"]) == 40 and prof["lines_truncated"] > 0
    finally:
        hub.close()
    hub, reply = _open(tmp_path / "f", make_pe(secs, entry=0x1000, HDR=0x1000), "full")
    try:
        assert len(reply["target"]["protection"]["pe_profile"]["lines"]) > 60
    finally:
        hub.close()
