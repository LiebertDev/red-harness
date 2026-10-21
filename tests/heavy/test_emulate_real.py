"""REAL-binary proof for `emulate`: exported functions of the host's own ntdll.dll (x64 and the WOW64 x86 copy) are
emulated through the full MCP path (target_open + scope manifest, bounded worker process, evidence, claim) and the
recovered values are compared with an INDEPENDENT computation in Python:

- RtlComputeCrc32(initial, buffer, length) -> zlib.crc32 (x64 ms64 and x86 stdcall);
- _itoa(value, buffer, radix) -> Python's own number formatting (the output buffer is read back).

Version 2 (image pointers, scratch buffers, pre-writes, code ranges) is covered by the unit tests in
`tests/unit/test_emulate_v2.py`.

The export address is found by a small export-table reader in this file (not by the emulator). Nothing is executed
natively: the CPU emulator interprets the code, so this runs on the host (no Windows Sandbox). Marked heavy because
it depends on the host's system DLLs and the optional `unicorn` package.
"""
import shutil
import struct
import zlib
from pathlib import Path

import pytest

from redharness.config import Config
from redharness.mcp.session import Hub

from tests.unit._fake_engine import FakeEngine
from tests.unit.mcp_helpers import make_manifest

pytestmark = pytest.mark.heavy

SYSTEM = Path(r"C:\Windows")
DLLS = {"x64": SYSTEM / "System32" / "ntdll.dll", "x86": SYSTEM / "SysWOW64" / "ntdll.dll"}
MESSAGE = b"The quick brown fox jumps over the lazy dog"


def export_va(data: bytes, name: str) -> int:
    """VA of a named export (independent of the harness: plain PE export-directory walk)."""
    e = struct.unpack_from("<I", data, 0x3C)[0]
    magic = struct.unpack_from("<H", data, e + 24)[0]
    is64 = magic == 0x20B
    base = struct.unpack_from("<Q" if is64 else "<I", data, e + 24 + (24 if is64 else 28))[0]
    nsec, sizeopt = struct.unpack_from("<H", data, e + 6)[0], struct.unpack_from("<H", data, e + 20)[0]
    secs = [struct.unpack_from("<IIII", data, e + 24 + sizeopt + 40 * i + 8) for i in range(nsec)]

    def off(rva: int) -> int:
        for vs, va, rs, rp in secs:
            if va <= rva < va + max(vs, rs):
                return rp + rva - va
        raise KeyError(hex(rva))
    exp_rva = struct.unpack_from("<I", data, e + 24 + (112 if is64 else 96))[0]
    o = off(exp_rva)
    n_names = struct.unpack_from("<I", data, o + 24)[0]
    funcs, names, ords = struct.unpack_from("<III", data, o + 28)
    for i in range(n_names):
        nrva = struct.unpack_from("<I", data, off(names) + 4 * i)[0]
        if data[off(nrva):off(nrva) + len(name) + 1] == name.encode() + b"\0":
            ordinal = struct.unpack_from("<H", data, off(ords) + 2 * i)[0]
            return base + struct.unpack_from("<I", data, off(funcs) + 4 * ordinal)[0]
    raise KeyError(name)


@pytest.fixture(params=["x64", "x86"])
def ntdll(request, tmp_path):
    pytest.importorskip("unicorn")
    src = DLLS[request.param]
    if not src.is_file():
        pytest.skip(f"{src} not present")
    target = tmp_path / f"ntdll_{request.param}.dll"
    shutil.copyfile(src, target)
    manifest = make_manifest(tmp_path / "scope.json", target, allowed_operations=["static", "emulate"])
    hub = Hub(Config.load(tmp_path / "data"), FakeEngine())   # default runner: the bounded worker process
    hub.target_open(str(target), str(manifest))
    yield request.param, target.read_bytes(), hub
    hub.close()


def _emulate(hub, **kw):
    return hub.call("emulate", kw, lambda: hub.emulate(**kw))


def test_rtl_compute_crc32_matches_zlib(ntdll):
    arch, data, hub = ntdll
    va = export_va(data, "RtlComputeCrc32")
    conv = "ms64" if arch == "x64" else "stdcall"
    for initial, msg in ((0, MESSAGE), (0, b""), (0x12345678, bytes(range(256)) * 3)):
        args = [initial, {"hex": msg.hex()} if msg else 0, len(msg)]
        r = _emulate(hub, function=hex(va), convention=conv, args=args)
        reg = "rax" if arch == "x64" else "eax"
        got = int(r["registers"][reg], 16) & 0xFFFFFFFF
        want = zlib.crc32(msg, initial)
        print(f"[{arch}] RtlComputeCrc32@{va:#x}(0x{initial:x}, {len(msg)} bytes) emulated=0x{got:08x} "
              f"zlib=0x{want:08x} ev={r['evidence_id'][:15]}")
        assert got == want and r["stack_balanced"]
    ev = r["evidence_id"]
    # The emulation evidence does not carry the export NAME (only the address): a claim naming RtlComputeCrc32 needs
    # evidence that names it (functions_list/decompile); this claim states only what the emulation shows.
    claim = hub.claim_add(
        text=f"Under emulation the function at {hex(va)} returns 0x{want:08x} for initial value 0x12345678 and the "
             f"768 byte buffer", evidence_ids=[ev], kind="observation", requested="SUPPORTED")
    ver = hub._s.ledger.state["claims"][claim["claim_id"]]["verification"]
    print(f"[{arch}] claim {claim['status']} checks={[c['code'] for c in ver['checks'] if c['ok']]}")
    assert claim["status"] == "SUPPORTED", ver["issues"]
    named = hub.claim_add(text=f"Under emulation RtlComputeCrc32 returns 0x{want:08x}", evidence_ids=[ev],
                          kind="observation", requested="SUPPORTED")
    assert named["status"] == "UNVERIFIED"   # TERM_NOT_IN_EVIDENCE: the name is not in the cited evidence


def test_itoa_output_buffer_matches_python_formatting(ntdll):
    arch, data, hub = ntdll
    va = export_va(data, "_itoa")
    for value, radix, want in ((-123456789, 10, "-123456789"), (0x7EADBEEF, 16, "7eadbeef"), (5, 2, "101")):
        r = _emulate(hub, function=hex(va), args=[value, {"buffer": 40}, radix], outputs=[{"arg": 1, "length": 40}])
        assert r["outputs"][0]["length"] == 40
        content = r["content"]
        got = next(ln.split('"')[1] for ln in content.splitlines() if ln.strip().startswith("0x") and '"' in ln)
        print(f"[{arch}] _itoa@{va:#x}({value}, buf, {radix}) emulated={got!r} python={want!r}")
        assert got == want
