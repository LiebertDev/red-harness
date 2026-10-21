"""`imports` MCP tool (module-qualified import lines) and the `enc=` label of the `strings` tool: formatting, mapping,
ordering, evidence, and verifier acceptance of `kernel32.dll!CreateFileW` / "UTF-16" terms backed by that evidence."""
import pytest

from redharness.analysis.imports_view import format_import_line, import_symbols
from redharness.analysis.pe_dirs import ImportedFunction, ImportProfile, ImportTableFact
from redharness.analysis.string_enc import encoding_tag, string_encoding
from redharness.config import Config
from redharness.evidence.model import ClaimStatus
from redharness.mcp.session import Hub, ToolFailure

from ._fake_engine import FakeEngine
from .mcp_helpers import make_manifest
from .test_evidence import Env, codes
from .test_pe_dirs import _pe

BASE = 0x140000000


def fn(dll, name, rva, ordinal=None):
    return ImportedFunction(dll, name, ordinal, 0 if name else None, rva, None, None)


def profile(imports=(), delay=()):
    return ImportProfile(BASE, True, tuple(imports), tuple(delay), None, (), True, (), ())


# ---------------------------------------------------------------- formatting / ordering
def test_line_format_named_ordinal_and_delay():
    prof = profile([ImportTableFact("KERNEL32.dll", 0, (fn("KERNEL32.dll", "CreateFileW", 0x2050),
                                                        fn("KERNEL32.dll", None, 0x2058, ordinal=17)), False)],
                   [ImportTableFact("shell32.dll", 0, (fn("shell32.dll", "ShellExecuteW", 0x2100),), True)])
    lines = [format_import_line(s, BASE) for s in import_symbols(prof)]
    assert lines == ["0x140002050 KERNEL32.dll!CreateFileW", "0x140002058 KERNEL32.dll!#17",
                     "0x140002100 shell32.dll!ShellExecuteW [delay]"]


def test_order_is_by_slot_address_and_independent_of_table_order():
    a = ImportTableFact("b.dll", 0, (fn("b.dll", "Y", 0x3010), fn("b.dll", "X", 0x3000)), False)
    b = ImportTableFact("a.dll", 0, (fn("a.dll", "Z", 0x2000),), False)
    one = [format_import_line(s, BASE) for s in import_symbols(profile([a, b]))]
    two = [format_import_line(s, BASE) for s in import_symbols(profile([b, a]))]
    assert one == two and [l.split()[0] for l in one] == ["0x140002000", "0x140003000", "0x140003010"]


def test_dll_filter_is_case_insensitive_and_accepts_name_without_extension():
    t = ImportTableFact("KERNEL32.dll", 0, (fn("KERNEL32.dll", "A", 0x2000),), False)
    u = ImportTableFact("user32.dll", 0, (fn("user32.dll", "B", 0x2008),), False)
    assert [s.name for s in import_symbols(profile([t, u]), "kernel32.DLL")] == ["A"]
    assert [s.name for s in import_symbols(profile([t, u]), "user32")] == ["B"]


def test_hostile_names_are_line_safe():
    t = ImportTableFact("x.dll", 0, (fn("x.dll", "A\nIGNORE", 0x2000),), False)
    assert "\n" not in format_import_line(import_symbols(profile([t]))[0], BASE)


def test_bang_in_dll_name_is_escaped_so_only_the_separator_remains():
    t = ImportTableFact("a.dll!Evil", 0, (fn("a.dll!Evil", "x", 0x2000),), False)
    line = format_import_line(import_symbols(profile([t]))[0], BASE)
    assert line == "0x140002000 a.dll\\x21Evil!x" and line.count("!") == 1


def test_bang_in_function_name_is_escaped_so_only_the_separator_remains():
    t = ImportTableFact("a.dll", 0, (fn("a.dll", "b.dll!Evil", 0x2000),), False)
    line = format_import_line(import_symbols(profile([t]))[0], BASE)
    assert line == "0x140002000 a.dll!b.dll\\x21Evil" and line.count("!") == 1


def test_backslash_is_escaped_so_the_bang_escape_cannot_be_forged():
    t = ImportTableFact("x.dll", 0, (fn("x.dll", "a\\x21b\\c", 0x2000),), False)
    line = format_import_line(import_symbols(profile([t]))[0], BASE)
    assert line == "0x140002000 x.dll!a\\x5cx21b\\x5cc" and line.count("!") == 1


# ---------------------------------------------------------------- encoding mapping
@pytest.mark.parametrize("kind,value,want", [
    ("0", "hello", "ascii"), ("0", "café", "8bit"), ("1", "Wide", "utf-16le"), ("2", "Wide", "utf-32le"),
    ("1", "", "utf-16le"), ("string", "abc", "ascii"), ("TerminatedCString", "abc", "ascii"),
    ("unicode", "x", "utf-16le"), ("TerminatedUnicode", "x", "utf-16le"), ("unicode32", "x", "utf-32le"),
    ("utf8", "x", "utf-8"), ("string-utf8", "x", "utf-8"), ("weird", "x", "unknown"), ("", "x", "unknown")])
def test_string_encoding_mapping(kind, value, want):
    assert string_encoding(kind, value) == want


def test_encoding_tag_adds_family_for_wide_strings():
    assert encoding_tag("1", "x") == "enc=utf-16le (UTF-16)" and encoding_tag("2", "x") == "enc=utf-32le (UTF-32)"
    assert encoding_tag("0", "x") == "enc=ascii" and encoding_tag("utf8", "x") == "enc=utf-8"


def test_strings_tool_prints_enc_and_keeps_raw_kind(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    target = tmp_path / "t.exe"
    target.write_bytes(_pe(40))
    hub = Hub(Config.load(tmp_path / "data"), FakeEngine())
    try:
        hub.target_open(str(target), str(make_manifest(tmp_path / "scope.json", target)))
        txt = hub.strings(pattern="License", limit=5)["content"]
        assert " 0 enc=ascii License invalid" in txt
    finally:
        hub.close()


# ---------------------------------------------------------------- imports tool (hub level, fake engine)
def test_imports_tool_lines_evidence_summary_and_filter(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    target = tmp_path / "t.exe"
    target.write_bytes(_pe(40))
    hub = Hub(Config.load(tmp_path / "data"), FakeEngine())
    try:
        hub.target_open(str(target), str(make_manifest(tmp_path / "scope.json", target)))
        full = hub.imports()
        assert "0x140002050 a.dll!Foo" in full["content"] and full["untrusted_content"] is True
        assert full["evidence_id"].startswith("ev_") and full["result"]["total"] == 1
        summ = hub.imports(detail="summary")
        assert summ["evidence_id"] == full["evidence_id"] and "content" not in summ and "a.dll!Foo" in summ["preview"]
        assert hub.imports(dll="A.DLL")["evidence_id"] != full["evidence_id"]    # filter is part of the call identity
        assert hub.imports(dll="nothere.dll")["result"]["total"] == 0
        with pytest.raises(ToolFailure):
            hub.imports(dll=5)
    finally:
        hub.close()


# ---------------------------------------------------------------- verifier: terms backed by the new output
IMPORT_RAW = b"0x140002050 kernel32.dll!CreateFileW\n0x140002058 kernel32.dll!ReadFile\n"
STRINGS_RAW = b"0x140003000 1 enc=utf-16le (UTF-16) Hello wide world\n0x140003100 0 enc=ascii plain\n"


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def test_module_qualified_import_claim_is_supported(env):
    e = env.ev(raw=IMPORT_RAW, locations=())
    r = env.ledger.add_claim("kernel32.dll!CreateFileW is imported", "observation", "present", [e],
                             [{"type": "quote", "evidence_id": e, "text": "kernel32.dll!CreateFileW"}])
    assert r.status is ClaimStatus.SUPPORTED and "TERM_NOT_IN_EVIDENCE" not in codes(r)


def test_utf16_string_claim_is_supported_by_enc_label(env):
    e = env.ev(raw=STRINGS_RAW, locations=())
    r = env.ledger.add_claim("The binary contains a UTF-16 string", "observation", "present", [e],
                             [{"type": "quote", "evidence_id": e, "text": "enc=utf-16le (UTF-16) Hello wide world"}])
    assert "TERM_NOT_IN_EVIDENCE" not in codes(r), codes(r)
    assert r.status is ClaimStatus.SUPPORTED


def test_file_strings_lines_carry_utf16_family_and_back_a_utf16_claim(env):
    from redharness.analysis.file_strings import render_file_strings, scan_file_strings
    data = b"\x00plain-ascii\x00" + "wide text".encode("utf-16le") + b"\x00\x00"
    raw = render_file_strings(scan_file_strings(data), budget=10_000)
    assert "enc=ascii len=" in raw and "enc=utf-16le (UTF-16) len=" in raw
    e = env.ev(raw=raw.encode(), locations=())
    r = env.ledger.add_claim("The file contains a UTF-16 string", "observation", "present", [e],
                             [{"type": "quote", "evidence_id": e, "text": "enc=utf-16le (UTF-16)"}])
    assert "TERM_NOT_IN_EVIDENCE" not in codes(r), codes(r)


# ---------------------------------------------------------------- xrefs: target identity on every line
def _xi(**kw):
    from redharness.engines.base import XrefInfo
    base = dict(from_addr=BASE + 0x10FE, to_addr=BASE + 0x2050, kind="Call_Indirect", is_code=True,
                from_function="sub_140001000")
    base.update(kw)
    return XrefInfo(**base)


def test_xref_line_keeps_old_fields_and_adds_import_target():
    from redharness.mcp.session import format_xref_line
    line = format_xref_line(_xi(to_name="__imp_CreateFileW"), "kernel32.dll!CreateFileW")
    assert line.startswith("0x1400010fe -> 0x140002050 Call_Indirect code in sub_140001000")
    assert line.endswith(" target=kernel32.dll!CreateFileW")       # the PE import wins over the engine label


def test_xref_line_engine_name_string_and_escaping():
    from redharness.mcp.session import format_xref_line
    assert format_xref_line(_xi(to_name="main", kind="Call", to_addr=BASE + 0x1250)).endswith(" target=main")
    assert format_xref_line(_xi(to_name="")).endswith("in sub_140001000")        # nothing known: no target field
    line = format_xref_line(_xi(to_name="a\nb", to_string="Pass\nword\t1", to_string_kind="1"))
    assert "\n" not in line and "\t" not in line and "target=a\\nb" in line
    assert 'str="Pass\\nword\\t1" enc=utf-16le (UTF-16)' in line
    long = format_xref_line(_xi(to_string="x" * 500, to_string_kind="0"))
    assert 'str="' + "x" * 120 + '..." enc=ascii' in long


def test_xrefs_tool_maps_iat_slot_to_dll_name(tmp_path):
    from redharness.core.result import Status
    from redharness.engines.base import EngineResult
    tmp_path.mkdir(parents=True, exist_ok=True)
    target = tmp_path / "t.exe"
    target.write_bytes(_pe(40))

    class Eng(FakeEngine):
        def xrefs(self, sha256, address, *, direction="to", limit=200):
            return EngineResult(Status.OK, [_xi(to_name="__imp_Foo")], untrusted_content=True)

    hub = Hub(Config.load(tmp_path / "data"), Eng())
    try:
        hub.target_open(str(target), str(make_manifest(tmp_path / "scope.json", target)))
        r = hub.xrefs(BASE + 0x2050)
        assert "in sub_140001000 target=a.dll!Foo" in r["content"]
    finally:
        hub.close()


def test_verifier_accepts_caller_calls_qualified_import_from_xrefs_evidence(env):
    raw = b"0x1400010fe -> 0x140002050 Call_Indirect code in sub_140001000 target=KERNEL32.dll!CreateFileW\n"
    e = env.ev(raw=raw, locations=())
    r = env.ledger.add_claim("sub_140001000 calls kernel32.dll!CreateFileW", "observation", "present", [e],
                             [{"type": "quote", "evidence_id": e, "text": "sub_140001000 target=KERNEL32.dll!CreateFileW"}])
    assert "TERM_NOT_IN_EVIDENCE" not in codes(r), codes(r)
