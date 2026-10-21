"""REAL-binary proof for `dataflow_slice` on the host's own system DLLs, through the full MCP path (target_open + scope
manifest, real engine, evidence, claim), with ground truth computed INDEPENDENTLY from the raw file bytes in this file:

- stack string: a run of immediate stores to `[rbp+disp]`/`[rsp+disp]` is decoded from the raw instruction bytes here
  (no engine); the slice at the instruction after the last store must rebuild exactly those bytes, each byte pointing
  to one of those stores;
- `.rdata` constant: a RIP-relative 32-bit register load whose target lies in a read-only data section (not the IAT);
  the slice at the next instruction must give the file's little-endian value, and `read_bytes` at the same address must
  show the same bytes in the same section.

The candidates are found by scanning the DLL's executable sections (file versions differ between Windows builds), so
the test adapts to the host. Engine: `RH_DF_ENGINE=ida` (default) or `ghidra`; run one engine at a time.
"""
from __future__ import annotations

import os
import re
import shutil
import struct
from pathlib import Path

import pytest

from redharness.config import Config
from redharness.mcp.session import Hub

from tests.unit.mcp_helpers import make_manifest

pytestmark = pytest.mark.heavy

SYSTEM32 = Path(r"C:\Windows\System32")
STACK_DLLS = ("vdsutil.dll", "sspicli.dll")
RDATA_DLLS = ("vdsutil.dll", "sspicli.dll")


# ---------------------------------------------------------------- independent raw-byte decoding
def _sections(data: bytes):
    e = struct.unpack_from("<I", data, 0x3C)[0]
    if struct.unpack_from("<H", data, e + 4)[0] != 0x8664:
        return None
    nsec, sizeopt = struct.unpack_from("<H", data, e + 6)[0], struct.unpack_from("<H", data, e + 20)[0]
    opt = e + 24
    base = struct.unpack_from("<Q", data, opt + 24)[0]
    iat = struct.unpack_from("<II", data, opt + 112 + 12 * 8)
    secs = []
    for k in range(nsec):
        o = opt + sizeopt + 40 * k
        vs, va, rs, rp = struct.unpack_from("<IIII", data, o + 8)
        secs.append((data[o:o + 8].rstrip(b"\0").decode("latin-1"), va, vs, rp, rs,
                     struct.unpack_from("<I", data, o + 36)[0]))
    return base, iat, secs


_STORES = []   # (encoding prefix, base register, displacement size, immediate size)
for _b, _m8, _m32 in (("rsp", b"\x44\x24", b"\x84\x24"), ("rbp", b"\x45", b"\x85")):
    for _op, _imm in ((b"\xc6", 1), (b"\xc7", 4), (b"\x66\xc7", 2)):
        _STORES += [(_op + _m8, _b, 1, _imm), (_op + _m32, _b, 4, _imm)]
_STORE_RX = re.compile(b"|".join(re.escape(p[0]) for p in _STORES))


def _store_at(data: bytes, i: int):
    for pre, base, ds, imm in _STORES:
        if data.startswith(pre, i):
            j = i + len(pre)
            disp = struct.unpack_from("<b" if ds == 1 else "<i", data, j)[0]
            return len(pre) + ds + imm, base, disp, imm, int.from_bytes(data[j + ds:j + ds + imm], "little")
    return None


def stack_string(data: bytes) -> dict | None:
    """Longest printable run of consecutive immediate stores to one frame register (raw decoding)."""
    base, _iat, secs = _sections(data)
    best = None
    for _n, va, _vs, rp, rs, fl in secs:
        if not fl & 0x20000000:
            continue
        i = rp
        while True:
            m = _STORE_RX.search(data, i, rp + rs)
            if not m:
                break
            run, j = [], m.start()
            while (d := _store_at(data, j)) and (not run or d[1] == run[0]["base"]):
                run.append({"va": base + va + j - rp, "len": d[0], "base": d[1], "disp": d[2], "imm": d[3], "val": d[4]})
                j += d[0]
            i = j if run else m.start() + 1
            if len(run) < 4:
                continue
            buf = {}
            for s in run:
                for k in range(s["imm"]):
                    buf[s["disp"] + k] = ((s["val"] >> (8 * k)) & 0xFF, s["va"])
            lo, n = min(buf), 0
            while lo + n in buf:
                n += 1
            raw = bytes(buf[lo + k][0] for k in range(n))
            txt = raw.rstrip(b"\0")
            if n >= 9 and txt and all(0x20 <= c < 0x7F for c in txt) and (best is None or n > best["n"]):
                best = {"stores": run, "lo": lo, "n": n, "bytes": raw, "srcs": {k: buf[lo + k][1] for k in range(n)},
                        "after": run[-1]["va"] + run[-1]["len"], "base": run[0]["base"]}
    return best


def rdata_load(data: bytes) -> dict | None:
    """First `mov r32, [rip+disp32]` (no REX) whose target is in a read-only, non-executable section, outside the IAT,
    with non-zero bytes."""
    base, (iat_rva, iat_size), secs = _sections(data)
    regs = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
    for _n, va, _vs, rp, rs, fl in secs:
        if not fl & 0x20000000:
            continue
        for m in re.finditer(rb"\x8b[\x05\x0d\x15\x1d\x35\x3d]", data[rp:rp + rs]):
            i = rp + m.start()
            if 0x40 <= data[i - 1] <= 0x4F:
                continue
            rva = va + i - rp
            tgt = rva + 6 + struct.unpack_from("<i", data, i + 2)[0]
            if iat_rva <= tgt < iat_rva + iat_size:
                continue
            for sn, sva, svs, srp, srs, sfl in secs:
                if sva <= tgt < sva + max(svs, srs) and not sfl & 0xA0000000 and tgt - sva + 4 <= srs:
                    raw = data[srp + tgt - sva:srp + tgt - sva + 4]
                    if raw != b"\0\0\0\0":
                        return {"insn": base + rva, "next": base + rva + 6, "reg": regs[(data[i + 1] >> 3) & 7],
                                "target": base + tgt, "section": sn, "bytes": raw}
                    break
    return None


# ---------------------------------------------------------------- harness
def _engine(root: Path):
    which = os.environ.get("RH_DF_ENGINE", "ida").lower()
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
    return which, eng


def _hub(name: str, heavy_data_root: Path, tmp_path: Path):
    src = SYSTEM32 / name
    if not src.is_file():
        pytest.skip(f"{src} not present")
    target = tmp_path / name
    shutil.copyfile(src, target)
    which, eng = _engine(heavy_data_root)
    manifest = make_manifest(tmp_path / "scope.json", target)
    hub = Hub(Config.load(tmp_path / "data"), eng)
    hub.target_open(str(target), str(manifest))
    return which, target.read_bytes(), hub


def _call(hub, tool, **kw):
    return hub.call(tool, kw, lambda: getattr(hub, tool)(**kw))


@pytest.mark.parametrize("name", STACK_DLLS)
def test_stack_string_matches_raw_store_decoding(name, heavy_data_root, tmp_path):
    which, data, hub = _hub(name, heavy_data_root, tmp_path)
    try:
        want = stack_string(data)
        if want is None:
            pytest.skip(f"no stack-string store run in this build of {name}")
        loc = f"[{want['base']}{want['lo']:+#x}]".replace("+-", "-")
        r = _call(hub, "dataflow_slice", address=hex(want["after"]), location=loc, size=want["n"], detail="full",
                  max_steps=1000)
        text = r["content"]
        print(f"\n[{which}] {name} slice at 0x{want['after']:x} location={loc} size={want['n']} "
              f"ev={r['evidence_id']} status={r['status']}\n{text}")
        assert f"hex={want['bytes'].hex()}" in text
        assert f"definite={want['n']}" in text
        for s in {x["va"] for x in want["stores"]}:
            assert f"0x{s:x} |" in text, f"store 0x{s:x} missing from the defs"
        for ln in text.splitlines():   # every byte's source store equals the raw decoding
            m = re.match(r"\s+\+0x([0-9a-f]+)(?:\.\.\+0x([0-9a-f]+))? definite src=(\S+)", ln)
            if m:
                a, b = int(m.group(1), 16), int(m.group(2) or m.group(1), 16)
                srcs = {int(x, 16) for x in m.group(3).split(",")}
                for k in range(a, b + 1):
                    assert want["srcs"][k] in srcs, f"byte +0x{k:x}: source 0x{want['srcs'][k]:x} not in {srcs}"
        claim = hub.claim_add(text=f"The {want['n']} bytes from {loc} at 0x{want['after']:x} are "
                                   f"{want['bytes'].hex()}.", evidence_ids=[r["evidence_id"]], kind="observation",
                              requested="SUPPORTED")
        print(f"[{which}] claim {claim['status']}")
        assert claim["status"] == "SUPPORTED"
    finally:
        hub.close()


@pytest.mark.parametrize("name", RDATA_DLLS)
def test_rdata_constant_matches_read_bytes(name, heavy_data_root, tmp_path):
    which, data, hub = _hub(name, heavy_data_root, tmp_path)
    try:
        want = rdata_load(data)
        if want is None:
            pytest.skip(f"no .rdata register load in this build of {name}")
        value = int.from_bytes(want["bytes"], "little")
        r = _call(hub, "dataflow_slice", address=hex(want["next"]), location=want["reg"], detail="full")
        text = r["content"]
        rb = _call(hub, "read_bytes", address=hex(want["target"]), length=4)
        print(f"\n[{which}] {name} slice at 0x{want['next']:x} location={want['reg']} ev={r['evidence_id']} "
              f"status={r['status']}\n{text}\nread_bytes ev={rb['evidence_id']}\n{rb['content']}")
        assert f"value=0x{value:x} definite" in text
        assert f"image 0x{want['target']:x} size=4 section={want['section']} R--" in text
        assert f"0x{want['insn']:x} |" in text
        assert want["bytes"].hex(" ") in rb["content"] or want["bytes"].hex() in rb["content"].replace(" ", "")
        assert want["section"] in rb["content"]
        claim = hub.claim_add(text=f"At 0x{want['next']:x} {want['reg']} holds 0x{value:x}, loaded from "
                                   f"0x{want['target']:x}.", evidence_ids=[r["evidence_id"]], kind="observation",
                              requested="SUPPORTED")
        print(f"[{which}] claim {claim['status']}")
        assert claim["status"] == "SUPPORTED"
    finally:
        hub.close()


# ---------------------------------------------------------------- slicer revision 4: exception edges, callee parameters
SEH_DLLS = ("dnsext.dll", "comcat.dll", "shfolder.dll")       # tiny x64 DLLs with __try/__except scope tables
CREATEFILE_DLL = "DDACLSys.dll"                                 # calls CreateFileW (7 parameters) through the IAT


@pytest.mark.parametrize("name", SEH_DLLS)
def test_except_block_is_analysed_through_scope_table_edges(name, heavy_data_root, tmp_path):
    from redharness.analysis.dataflow import scope_edges, slice_function
    which, data, hub = _hub(name, heavy_data_root, tmp_path)
    try:
        img = hub._pe_image(hub._s)
        edges = scope_edges(img, lambda o, n: data[o:o + n])
        if not edges:
            pytest.skip(f"no __try/__except scope table in this build of {name}")
        e = edges[0]
        dis = hub.engine.disassemble(hub._s.sha, e.try_begin, count=20_000, whole_function=True)
        assert dis.ok, dis.detail
        in_body = any(i.address == e.target for i in dis.data.items)
        aug, decoded = hub._with_except_blocks(hub._s, dis.data, tuple(edges))   # what the tool slices
        print(f"\n[{which}] __except block in the engine's function body: {in_body}; {decoded[:1]}")
        dis_data = aug
        items = list(dis_data.items)
        k = next((n for n, i in enumerate(items) if i.address == e.target), None)
        assert k is not None, "the engine's function does not contain the __except block"
        q = items[k + 1]          # the second instruction of the __except block
        r = _call(hub, "dataflow_slice", address=hex(q.address), operand=0, detail="full")
        text = r["content"]
        bare = slice_function(dis_data, bits=64, target=q.address, operand=0).text   # the same, no exception edges
        x = _call(hub, "xrefs", address=hex(e.target))
        print(f"\n[{which}] {name} try 0x{e.try_begin:x}-0x{e.try_end:x} -> __except 0x{e.target:x} ({e.handler}) "
              f"slice at 0x{q.address:x} ev={r['evidence_id']} status={r['status']}\n"
              + "\n".join(ln for ln in text.splitlines() if ln.startswith(("flow:", "read ", "  value", "coverage")))
              + f"\n[{which}] without edges: "
              + " | ".join(ln for ln in bare.splitlines() if ln.startswith(("coverage",)))
              + f"\n[{which}] engine xrefs to the __except block: ev={x['evidence_id']} "
              + " | ".join(ln.strip() for ln in x["content"].splitlines() if ln.startswith("0x"))[:300])
        assert "exception_edges=0 " not in text and "not reachable from the function entry" not in text
        assert "not reachable from the function entry" in bare and "exception_edges=0 " in bare
        if items[k].mnemonic == "xor" and len(items[k].operands) == 2 and \
                items[k].operands[0].reg == items[k].operands[1].reg:
            reg = items[k].operands[0].reg
            rr = _call(hub, "dataflow_slice", address=hex(q.address), location=reg, detail="full")
            print(f"[{which}] {reg} at 0x{q.address:x}: "
                  + " ".join(ln.strip() for ln in rr["content"].splitlines() if ln.startswith("  value")))
            assert "value=0x0 definite" in rr["content"] and f"0x{e.target:x} |" in rr["content"]
    finally:
        hub.close()


def test_known_callee_parameter_area_is_exact(heavy_data_root, tmp_path):
    from redharness.analysis.imports_view import iat_slot_names
    from redharness.analysis.pe_dirs import scan_imports_image
    which, data, hub = _hub(CREATEFILE_DLL, heavy_data_root, tmp_path)
    try:
        img = hub._pe_image(hub._s)
        slots = {va for va, nm in iat_slot_names(scan_imports_image(img, lambda o, n: data[o:o + n])).items()
                 if nm.endswith("!CreateFileW")}
        text_sec = next(sct for sct in img.sections if sct.name == ".text")
        blob = data[text_sec.raw_ptr:text_sec.raw_ptr + text_sec.raw_size]
        site = None
        for m in re.finditer(rb"\xff\x15", blob):
            va = img.image_base + text_sec.rva + m.start()
            if va + 6 + struct.unpack_from("<i", blob, m.start() + 2)[0] in slots:
                site = va
                break
        if site is None:
            pytest.skip("no CreateFileW call in this build")
        dis = hub.engine.disassemble(hub._s.sha, site, count=20_000, whole_function=True)
        site = next(i.address for i in dis.data.items if i.address <= site < i.address + i.size)  # REX prefix
        ca = hub.engine.call_args(hub._s.sha, site)
        print(f"\n[{which}] {CREATEFILE_DLL} call 0x{site:x} CreateFileW: engine parameter area = "
              f"{ca.data.get(site) if ca.ok else ca.status.value}")
        # ground truth: CreateFileW has 7 parameters -> home space 0x20 + 3 stack parameters = 0x38 bytes
        assert ca.ok and ca.data.get(site) == 0x38
        nxt = next(i.address for i in dis.data.items if i.address > site)
        r = _call(hub, "dataflow_slice", address=hex(nxt), location="[rsp+0x20]", size=0x18, detail="full")
        print(f"[{which}] slice after the call at 0x{nxt:x} ev={r['evidence_id']}\n"
              + "\n".join(ln for ln in r["content"].splitlines() if "parameter area" in ln or ln.startswith("  bytes")))
        assert f"parameter area of call 0x{site:x}" in r["content"] and "0x38 bytes" in r["content"]
        assert "definite=0" in r["content"]
    finally:
        hub.close()
