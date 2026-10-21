"""Section notes (analysis/section_notes.py; session TOOL_VERSION 5, emulate TOOL_VERSION 2): disassemble, decompile
and emulate outputs name the PE section (+ R/W/X) of the addresses they show, so a correct ".rdata"/".text" in a claim
can be backed by the evidence the model actually cites. A plain number
is never annotated; a lexicon word such as "decrypt" still needs its own backing."""
from __future__ import annotations

import pytest

from redharness.analysis import section_notes as SN
from redharness.analysis.pe_image import parse_pe
from redharness.config import Config
from redharness.core.result import Status
from redharness.engines.base import DecompileInfo, EngineResult
from redharness.mcp.session import Hub, TOOL_VERSION

from ._fake_engine import BASE, FakeEngine
from ._pe_builder import build_pe
from .mcp_helpers import make_manifest

DECOMP_REFS = ("void __fastcall sub_140001000(char *out)\n{\n  for ( i = 0; i < 6; ++i )\n"
               "    out[i] = byte_140002040[i] ^ 0x5A;\n  qword_140009000 = 1;\n  return 0x140002040;\n}\n")


@pytest.fixture(autouse=True, scope="module")
def _quiet_faulthandler():   # unicorn's handled access faults would print through faulthandler (as test_emulate_v2)
    import faulthandler
    import sys
    was = faulthandler.is_enabled()
    faulthandler.disable()
    yield
    if was:
        faulthandler.enable(file=sys.stderr)


def img(data: bytes):
    return parse_pe(lambda o, n: data[o:o + n], len(data))


def test_flags_where_and_notes_are_from_the_section_headers():
    im = img(build_pe(True))
    assert SN.flags(0x60000020) == "R-X" and SN.flags(0x40000040) == "R--" and SN.flags(0xC0000040) == "RW-"
    assert SN.where(im, BASE + 0x1004) == ".text R-X" and SN.where(im, BASE + 0x2040) == ".rdata R--"
    assert SN.where(im, BASE + 0x10) is None and SN.where(im, BASE + 0x9000) is None and SN.where(im, 5) is None
    assert SN.range_notes(im, [BASE + 0x1000, BASE + 0x1004, BASE + 0x2000], "x") == [
        "section .text R-X: 0x140001000..0x140001004 (x)", "section .rdata R--: 0x140002000 (x)"]
    notes = SN.name_notes(im, DECOMP_REFS + " byte_140002040 unk_00000010 DAT_140002000 my_byte_140002040")
    assert notes == ["ref sub_140001000 = 0x140001000 in section .text R-X",
                     "ref byte_140002040 = 0x140002040 in section .rdata R--",
                     "ref DAT_140002000 = 0x140002000 in section .rdata R--"]   # outside/identifier parts: no note
    assert SN.name_notes(im, "0x140002040 and 5368717376") == []                 # plain numbers are never annotated
    many = " ".join(f"byte_{BASE + 0x2000 + i:x}" for i in range(40))
    out = SN.name_notes(im, many, limit=32)
    assert len(out) == 33 and out[-1] == "(8 more auto-named references not annotated)"


class RefEngine(FakeEngine):
    def decompile(self, sha256, function, *, max_chars=200_000):
        return EngineResult(Status.OK, DecompileInfo(BASE + 0x1000, "sub_140001000", DECOMP_REFS, len(DECOMP_REFS)),
                            untrusted_content=True)


@pytest.fixture
def hub(tmp_path):
    target = tmp_path / "t.exe"
    target.write_bytes(build_pe(True))
    manifest = make_manifest(tmp_path / "scope.json", target)
    h = Hub(Config.load(tmp_path / "data"), RefEngine())
    h.target_open(str(target), str(manifest))
    yield h
    h.close()


def test_tool_version_is_6():
    assert TOOL_VERSION == "6"


def test_disassemble_ends_with_the_section_of_the_instructions(hub):
    r = hub.disassemble(hex(BASE + 0x1000), count=3)
    raw = hub._s.ledger.state["evidence"][r["evidence_id"]]
    assert "; section .text R-X: 0x140001000..0x140001008 (instructions above)\n" in r["content"]
    ok = hub.claim_add(text="The code at 0x140001000 lies in .text", evidence_ids=[r["evidence_id"]],
                       kind="observation", requested="SUPPORTED")
    assert ok["status"] == "SUPPORTED", ok
    bad = hub.claim_add(text="The code at 0x140001000 lies in .rdata", evidence_ids=[r["evidence_id"]],
                        kind="observation", requested="SUPPORTED")
    assert bad["status"] == "UNVERIFIED", bad          # the note names .text only
    assert raw["source"]["tool_version"] == "6"


def test_decompile_notes_back_the_referenced_table_and_its_section(hub):
    r = hub.decompile("0x140001000")
    assert "// section .text R-X: 0x140001000 (decompiled function)" in r["content"]
    assert "// ref byte_140002040 = 0x140002040 in section .rdata R--" in r["content"]
    assert "qword_140009000" in r["content"] and "ref qword_140009000" not in r["content"]   # outside every section
    ok = hub.claim_add(text="sub_140001000 reads the table byte_140002040 at 0x140002040 in .rdata and XORs it with "
                            "0x5A", evidence_ids=[r["evidence_id"]], kind="observation", requested="SUPPORTED")
    assert ok["status"] == "SUPPORTED", ok
    # a lexicon word is still a term that needs backing: the note does not say what the code means
    dec = hub.claim_add(text="sub_140001000 decrypts the table at 0x140002040 in .rdata",
                        evidence_ids=[r["evidence_id"]], kind="observation", requested="SUPPORTED")
    assert dec["status"] == "UNVERIFIED" and "decrypts" in str(dec), dec


def test_emulate_names_the_sections_of_the_request_addresses(tmp_path):
    pytest.importorskip("unicorn")
    from .test_emulate_v2 import RDATA_HELLO, UPPER_COPY, _call, make_hub
    from .test_emulate import B64, with_code
    h = make_hub(tmp_path, with_code(build_pe(True), UPPER_COPY))
    try:
        r = _call(h, function=hex(B64 + 0x1000), args=[{"va": hex(RDATA_HELLO), "length": 5}, {"buffer": 5}, 5],
                  outputs=[{"arg": 1, "length": 5, "views": ["ascii"]}])
        assert "section .text R-X: function 0x140001000\n" in r["content"]
        assert "section .rdata R--: arg0 0x140002040\n" in r["content"]
        ev = h._s.ledger.state["evidence"][r["evidence_id"]]
        assert ev["source"]["tool_version"] == "2"
        ok = h.claim_add(text='Under emulation the routine at 0x140001000 copies the 5-byte table at 0x140002040 in '
                              '.rdata to a buffer as "HELLO"', evidence_ids=[r["evidence_id"]], kind="observation",
                         requested="SUPPORTED")
        assert ok["status"] == "SUPPORTED", ok
    finally:
        h.close()
