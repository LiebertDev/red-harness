"""REAL proof for `imports`: the import and delay-import tables of the host's own notepad.exe through the full MCP path
(target_open + scope manifest, evidence, step cache). The tool parses the PE from the SHA-verified job copy and needs no
engine (the fake engine only answers target_open). Ground truth: an independent, minimal import-directory walk written
here (struct only, no harness code) gives the IAT slot VAs of a few named imports, which must equal the tool's lines.
"""
from __future__ import annotations

import re
import struct
from pathlib import Path

import pytest

from redharness.config import Config
from redharness.mcp.session import Hub

from tests.unit._fake_engine import FakeEngine
from tests.unit.mcp_helpers import make_manifest

pytestmark = pytest.mark.heavy
_LINE = re.compile(r"^(0x[0-9a-f]+) (\S+?)!(\S+)( \[delay\])?$")


def _independent_slots(data: bytes) -> dict[tuple[str, str, bool], int]:
    """(dll, name, delay) -> IAT slot VA, from the raw file (x64 only)."""
    e = struct.unpack_from("<I", data, 0x3C)[0]
    assert struct.unpack_from("<H", data, e + 24)[0] == 0x20B, "x64 notepad expected"
    nsec, sizeopt = struct.unpack_from("<H", data, e + 6)[0], struct.unpack_from("<H", data, e + 20)[0]
    base = struct.unpack_from("<Q", data, e + 24 + 24)[0]
    dirs = e + 24 + 112
    secs = [struct.unpack_from("<IIII", data, e + 24 + sizeopt + 40 * k + 8) for k in range(nsec)]

    def off(rva: int) -> int:
        for vs, va, rs, rp in secs:
            if va <= rva < va + max(vs, rs):
                return rp + rva - va
        raise KeyError(hex(rva))

    def cstr(rva: int) -> str:
        o = off(rva)
        return data[o:data.index(b"\0", o)].decode("ascii")

    out: dict[tuple[str, str, bool], int] = {}

    def walk(dll: str, names_rva: int, iat_rva: int, delay: bool) -> None:
        k = 0
        while True:
            entry = struct.unpack_from("<Q", data, off(names_rva) + 8 * k)[0]
            if not entry:
                return
            if not entry >> 63:                                    # by name (hint + name)
                out[(dll, cstr((entry & 0x7FFFFFFF) + 2), delay)] = base + iat_rva + 8 * k
            k += 1

    imp_rva = struct.unpack_from("<I", data, dirs + 8 * 1)[0]
    o = off(imp_rva)
    while True:
        oft, _ts, _fc, name, ft = struct.unpack_from("<IIIII", data, o)
        if not (oft or name or ft):
            break
        walk(cstr(name), oft or ft, ft, False)
        o += 20
    dly_rva = struct.unpack_from("<I", data, dirs + 8 * 13)[0]
    if dly_rva:
        o = off(dly_rva)
        while True:
            attrs, name, _mod, iat, intt = struct.unpack_from("<IIIII", data, o)
            if not name:
                break
            walk(cstr(name), intt, iat, True)
            o += 32
    return out


@pytest.fixture
def hub(tmp_path, notepad_copy):
    manifest = make_manifest(tmp_path / "scope.json", notepad_copy)
    h = Hub(Config.load(tmp_path / "data"), FakeEngine())
    h.target_open(str(notepad_copy), str(manifest))
    yield h, notepad_copy
    h.close()


def _imports(h, **kw):
    kw = {"detail": "full", **kw}
    return h.call("imports", kw, lambda: h.imports(**kw))


def test_notepad_imports_match_an_independent_parse(hub):
    h, exe = hub
    r = _imports(h)
    rows, page, pages = {}, r, 0
    while True:                                   # the reply is size-capped: follow next_offset to the end
        pages += 1
        body = page["content"]
        body = body[body.index(">") + 1:body.rindex("</untrusted_target_content>")]   # the evidence wrapper
        for ln in body.splitlines():
            m = _LINE.match(ln.strip())
            if m:
                rows[(m.group(2), m.group(3), bool(m.group(4)))] = int(m.group(1), 16)
        nxt = (page.get("result") or {}).get("next_offset")
        if nxt is None:
            break
        page = _imports(h, offset=nxt)
    truth = _independent_slots(Path(exe).read_bytes())
    print(f"\nimports ev={r['evidence_id']} status={r['status']}: {len(rows)} lines in {pages} page(s), independent parse "
          f"{len(truth)} named imports ({sum(1 for k in truth if k[2])} delay-load)")
    assert ("KERNEL32.dll", "CreateFileW", False) in rows
    assert any(k[2] for k in rows), "no delay-load import marked [delay]"
    checked = [k for k in (("KERNEL32.dll", "CreateFileW", False), ("KERNEL32.dll", "ReadFile", False),
                           ("KERNEL32.dll", "GetProcAddress", False)) if k in truth]
    checked += [k for k in truth if k[2]][:3]                       # a few delay-load slots too
    for k in checked:
        assert rows.get(k) == truth[k], (k, rows.get(k), truth[k])
    assert {k for k in truth} <= set(rows), "an import the independent parse found is missing from the tool"
    again = _imports(h)
    assert again["evidence_id"] == r["evidence_id"] and again["step_cached"]


def test_dll_filter_and_paging(hub):
    h, _ = hub
    r = _imports(h, dll="KERNEL32.dll", limit=5)
    body = r["content"][r["content"].index(">") + 1:r["content"].rindex("</untrusted_target_content>")]
    lines = [ln for ln in body.splitlines() if _LINE.match(ln.strip())]
    assert len(lines) == 5 and all("KERNEL32.dll!" in ln for ln in lines)
    assert r["result"]["next_offset"] == 5 and r["result"]["total"] > 5
