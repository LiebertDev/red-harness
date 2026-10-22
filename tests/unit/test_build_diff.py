"""Original-vs-fixed build comparison: functions_list(compare='fixed') and the engine-independent diff behind it.

Fake engine with two synthetic builds that differ the way a real fix does: one function changed (and grown, so the
functions after it MOVE and their call targets shift), one removed, one added, one function with a stable name rewritten."""
import hashlib
from pathlib import Path

import pytest

from redharness.analysis.build_diff import diff_builds, fingerprint, pair_lines, stable_name
from redharness.config import Config
from redharness.core.result import Status
from redharness.engines._common import bodies_from_doc
from redharness.engines.base import (Disassembly, EngineResult, FunctionBody, FunctionInfo, InsnInfo, OperandInfo,
                                     Page)
from redharness.mcp.session import Hub, ToolFailure

from ._fake_engine import BASE, FakeEngine
from .mcp_helpers import make_manifest
from .test_run_controlled_mcp import fake_system_root


def reg(r):
    return OperandInfo("reg", r, reg=r, size=8)


def imm(v):
    return OperandInfo("imm", hex(v), value=v, size=4)


def mem(base, disp):
    return OperandInfo("mem", f"[{base}{disp:+#x}]", base=base, disp=disp, size=8)


def near(v, sym=""):
    return OperandInfo("near", hex(v), value=v, sym=sym)


def data(v, sym=""):
    return OperandInfo("mem", f"[{v:#x}]", value=v, size=8, sym=sym)


class Func:
    """A function laid out at `address`: `code(address)` returns [(mnemonic, operands)]."""

    def __init__(self, name, address, code):
        self.name, self.address = name, address
        rows = code(address)
        self.insns = []
        a = address
        for mnem, ops in rows:
            text = mnem + " " + ",".join(o.text for o in ops)
            self.insns.append(InsnInfo(a, 4, hashlib.sha256(text.encode()).hexdigest()[:8], mnem, tuple(ops), text))
            a += 4
        self.size = 4 * len(rows)


def build(moved: int):
    """`moved` = how far everything after `validate` shifts in the fixed build (0 = the original)."""
    grown = moved > 0
    a = Func("sub_140001000", BASE + 0x1000,
             lambda at: [("push", [reg("rbp")]), ("mov", [reg("rbp"), reg("rsp")]), ("pop", [reg("rbp")]), ("ret", [])])
    # the fixed validate_license has an extra range check (4 more instructions, so it is 0x10 bytes longer)
    v = Func("sub_140001100", BASE + 0x1100, lambda at: (
        [("mov", [reg("eax"), mem("rbp", -4)]), ("cmp", [reg("eax"), imm(0x10)]), ("jne", [near(at + 0x14)]),
         ("xor", [reg("eax"), imm(0x5EC2E7A1)]), ("ret", [])] if not grown else
        [("mov", [reg("eax"), mem("rbp", -4)]), ("test", [reg("eax"), reg("eax")]), ("jz", [near(at + 0x24)]),
         ("cmp", [reg("eax"), imm(0x10)]), ("jne", [near(at + 0x24)]),
         ("xor", [reg("eax"), imm(0x5EC2E7A1)]), ("ret", []), ("int3", [])]))
    base = BASE + 0x1200 + moved
    # c calls "the function at 0x1400" and reads a data word: both addresses shift by `moved` in the fixed build
    c = Func("sub_140001200", base, lambda at: [("call", [near(BASE + 0x1400 + moved)]),
                                                ("mov", [reg("rax"), data(BASE + 0x3000 + moved)]), ("ret", [])])
    d = Func("sub_140001300", BASE + 0x1300 + moved, lambda at: [("mov", [reg("rax"), imm(1)]), ("ret", [])])
    tail = Func("sub_140001400", BASE + 0x1400 + moved, lambda at: [("nop", []), ("ret", [])])
    # a function with a stable name whose body is rewritten (found by name, reported changed)
    n = Func("check_serial", BASE + 0x1500 + moved, lambda at: ([("mov", [reg("rax"), imm(2)]), ("ret", [])] if not grown
                                                              else [("lea", [reg("rax"), mem("rsp", 8)]), ("ret", [])]))
    fns = [a, v, c, d, tail, n] if not grown else [a, v, c, tail, n]   # d removed in the fixed build
    if grown:
        fns.append(Func("sub_140001600", BASE + 0x1600 + moved, lambda at: [("sub", [reg("rsp"), imm(8)]), ("ret", [])]))
    return fns


class TwoBuildEngine(FakeEngine):
    """Serves the synthetic builds by SHA-256. It does NOT override disassemble_functions: the base class default
    (functions page + whole-function disassemble) is what runs here."""

    def __init__(self, shas):
        self.by_sha = {shas[0]: build(0), shas[1]: build(0x10)}
        self.calls = []

    def functions(self, sha256, *, offset=0, limit=100):
        rows = self.by_sha[sha256]
        items = [FunctionInfo(f.address, f.name, f.size) for f in rows[offset:offset + limit]]
        return EngineResult(Status.OK, Page(items, len(rows), offset, offset + len(items) < len(rows)))

    def disassemble(self, sha256, address, *, count=200, whole_function=False):
        self.calls.append((sha256, address))
        f = next(x for x in self.by_sha[sha256] if x.address <= address < x.address + x.size)
        return EngineResult(Status.OK, Disassembly(list(f.insns), f.address, f.name, len(f.insns), True, ""))


class Builds:
    def __init__(self, tmp_path: Path):
        self.orig = tmp_path / "product.bin"
        self.fixed = tmp_path / "product-fixed.bin"
        self.orig.write_bytes(b"MZ" + bytes(range(256)) * 8)
        self.fixed.write_bytes(b"MZ" + bytes(range(256)) * 8 + b"FIXED")
        self.orig_sha = hashlib.sha256(self.orig.read_bytes()).hexdigest()
        self.fixed_sha = hashlib.sha256(self.fixed.read_bytes()).hexdigest()
        self.manifest = make_manifest(tmp_path / "scope.json", self.orig, allowed_operations=["static"],
                                      fixed_target_sha256=self.fixed_sha)
        self.engine = TwoBuildEngine((self.orig_sha, self.fixed_sha))
        self.hub = Hub(Config.load(tmp_path / "data"), self.engine, None, system_root=fake_system_root(tmp_path / "win"))

    def open(self, fixed=True):
        return self.hub.target_open(str(self.orig), str(self.manifest), str(self.fixed) if fixed else None)

    def compare(self, **kw):
        kw.setdefault("detail", "full")
        return self.hub.call("functions_list", {"compare": "fixed", **kw},
                             lambda: self.hub.functions_list(kw.pop("offset", 0), kw.pop("limit", 100), kw["detail"], "fixed"))


@pytest.fixture
def b(tmp_path):
    x = Builds(tmp_path)
    x.open()
    yield x
    x.hub.close()


def body(reply):
    return reply["content"].split(">", 1)[1].rsplit("</untrusted_target_content", 1)[0]


def rows(reply):
    return [ln for ln in body(reply).splitlines() if not ln.startswith(("#", "  hunk"))]


# ------------------------------------------------------------------------------------------------ the tool

def test_compare_reports_changed_added_removed_and_matched_with_both_builds(b):
    r = b.compare()
    assert r["status"] == "OK" and r["evidence_id"].startswith("ev_")
    text = body(r)
    assert f"original sha256={b.orig_sha}" in text and f"fixed sha256={b.fixed_sha}" in text
    assert "matched=3 (moved=3) changed=2 added=1 removed=1" in text
    kinds = [ln.split()[0] for ln in rows(r)]
    assert kinds == ["changed", "changed", "added", "removed", "matched", "matched", "matched"]   # interesting rows first
    by_name = {ln.split("name=")[1].split()[0] + ":" + ln.split()[0]: ln for ln in rows(r)}
    validate = by_name["sub_140001100:changed"]
    assert "original=0x140001100 fixed=0x140001100" in validate and "size=0x14->0x20" in validate
    assert "insns=5->8" in validate and "pairing=similarity" in validate and "bytes_identical=no" in validate
    assert any(ln.startswith("  hunk") for ln in text.splitlines())
    serial = by_name["check_serial:changed"]
    assert "pairing=name" in serial and "original=0x140001500 fixed=0x140001510" in serial
    # a function that only moved (its call target and data reference shifted too) is matched, not changed
    moved = by_name["sub_140001200:matched"]
    assert "moved=yes" in moved and "bytes_identical=no" in moved and "pairing=hash" in moved
    assert "original=0x140001200 fixed=0x140001210" in moved
    assert "moved=no bytes_identical=yes" in by_name["sub_140001000:matched"]
    assert by_name["sub_140001300:removed"].startswith("removed original=0x140001300")
    assert by_name["sub_140001600:added"].startswith("added fixed=0x140001610")
    # both builds' fingerprints are on the row, so the claim can cite either side
    assert f"bytes_sha256=" in validate and validate.count("->") >= 4


def test_compare_evidence_is_bound_to_both_hashes_and_keeps_listing_apart(b):
    r = b.compare()
    ev = b.hub._s.ledger.state["evidence"][r["evidence_id"]]
    assert ev["subject"]["sha256"] == b.orig_sha                     # the job's target; the fixed build is bound below
    assert ev["parameters"] == {"offset": 0, "limit": 100, "compare": "fixed", "fixed_sha256": b.fixed_sha}
    assert ev["result"]["compare"]["fixed_sha256"] == b.fixed_sha and ev["result"]["compare"]["changed"] == 2
    assert {loc["start"] for loc in ev["locations"] if loc["space"] == "va"} <= {
        f.address for f in b.engine.by_sha[b.orig_sha]}              # addresses of the ORIGINAL build only
    plain = b.hub.functions_list(0, 5, "full")                       # an ordinary listing is unchanged
    pe = b.hub._s.ledger.state["evidence"][plain["evidence_id"]]
    assert pe["parameters"] == {"offset": 0, "limit": 5} and plain["evidence_id"] != r["evidence_id"]
    cov = b.hub._coverage_data(b.hub._s)
    assert {li["tool"] for li in cov["listings"]} == {"functions_list"} and len(cov["listings"]) == 2
    assert all(li["exhausted"] is (li["reached"] >= li["total"]) for li in cov["listings"])


def test_a_claim_about_a_changed_function_can_cite_the_comparison(b):
    r = b.compare()
    changed = next(ln for ln in rows(r) if ln.startswith("changed") and "sub_140001100" in ln)
    c = b.hub.claim_add("The function at 0x140001100 differs between the original build and the fixed build: "
                        "it grows from 5 to 8 instructions.",
                        [r["evidence_id"]], [{"type": "quote", "evidence_id": r["evidence_id"], "text": "insns=5->8"},
                                             {"type": "address", "evidence_id": r["evidence_id"], "value": "0x140001100"}],
                        "observation", "present", "SUPPORTED")
    assert c["status"] == "SUPPORTED", c
    assert "insns=5->8" in changed


def test_paging_and_summary(b):
    first = b.hub.functions_list(0, 2, "full", "fixed")
    assert [ln.split()[0] for ln in rows(first)] == ["changed", "changed"]
    assert first["result"]["next_offset"] == 2 and first["result"]["total"] == 7
    last = b.hub.functions_list(5, 10, "full", "fixed")
    assert [ln.split()[0] for ln in rows(last)] == ["matched", "matched"] and last["result"]["next_offset"] is None
    s = b.hub.functions_list(0, 2, "summary", "fixed")
    assert s["detail"] == "summary" and s["evidence_id"] == first["evidence_id"]   # same step, same evidence


def test_the_second_call_does_not_disassemble_again(b):
    b.compare()
    n = len(b.engine.calls)
    assert n >= 10   # every function of both builds went through the engine once
    b.hub.functions_list(2, 2, "full", "fixed")
    assert len(b.engine.calls) == n


def test_compare_needs_the_fixed_build(tmp_path):
    x = Builds(tmp_path)
    try:
        x.open(fixed=False)
        with pytest.raises(ToolFailure) as e:
            x.hub.functions_list(0, 10, "full", "fixed")
        assert e.value.code == "FIXED_BUILD_NOT_OPEN"
        with pytest.raises(ToolFailure) as e:
            x.hub.functions_list(0, 10, "full", "original")
        assert e.value.code == "BAD_ARGUMENT"
    finally:
        x.hub.close()


def test_the_fixed_file_changing_after_the_check_is_refused(b):
    b.fixed.write_bytes(b"MZ" + b"changed")
    b.engine.by_sha[hashlib.sha256(b.fixed.read_bytes()).hexdigest()] = []
    with pytest.raises(ToolFailure) as e:
        b.hub.functions_list(0, 10, "full", "fixed")
    assert e.value.code == "ARTIFACT_CHANGED"


def test_an_engine_without_bulk_disassembly_error_is_reported_not_swallowed(b):
    def broken(sha256, address, *, count=200, whole_function=False):
        return EngineResult(Status.ERROR, None, "decode failed")
    b.engine.disassemble = broken
    with pytest.raises(ToolFailure) as e:
        b.hub.functions_list(0, 10, "full", "fixed")
    assert "decode failed" in e.value.message


def test_report_carries_the_comparison_evidence(b):
    r = b.compare()
    b.hub.claim_add("sub_140001100 grows from 5 to 8 instructions in the fixed build.", [r["evidence_id"]],
                    [{"type": "quote", "evidence_id": r["evidence_id"], "text": "insns=5->8"}], "observation")
    rep = b.hub.report_build("json")["report_json"]
    ev = rep["evidence"][r["evidence_id"]]
    assert ev["parameters"]["compare"] == "fixed" and ev["parameters"]["fixed_sha256"] == b.fixed_sha
    assert rep["target"]["fixed_build_sha256"] == b.fixed_sha and len(rep["findings"]) == 1


# ------------------------------------------------------------------------------------------------ the diff itself

def prints(fns):
    return [fingerprint(FunctionBody(f.address, f.name, f.size, Disassembly(list(f.insns), f.address, f.name,
                                                                              len(f.insns), True, ""))) for f in fns]


def test_diff_is_deterministic_and_a_pure_move_is_matched():
    o, f = prints(build(0)), prints(build(0x10))
    d1, d2 = diff_builds(o, f), diff_builds(list(reversed(o)), list(reversed(f)))
    assert [pair_lines(p) for p in d1.pairs] == [pair_lines(p) for p in d2.pairs]
    only_moved = diff_builds(prints([build(0)[2]]), prints([build(0x10)[2]]))
    assert [p.status for p in only_moved.pairs] == ["matched"] and only_moved.pairs[0].moved


def test_identical_builds_are_all_matched():
    o = prints(build(0))
    d = diff_builds(o, prints(build(0)))
    assert d.counts["matched"] == len(o) and d.counts["changed"] == d.counts["added"] == d.counts["removed"] == 0


def test_register_and_immediate_changes_are_changes():
    base = prints(build(0))[:1]
    fx = Func("sub_140001000", BASE + 0x1000, lambda at: [("push", [reg("rbp")]), ("mov", [reg("rbp"), reg("rsi")]),
                                                           ("pop", [reg("rbp")]), ("ret", [])])
    d = diff_builds(base, prints([fx]))
    assert d.counts["changed"] == 1 and d.pairs[0].insns_added == 1 and d.pairs[0].insns_removed == 1
    assert d.pairs[0].pairing in ("name", "similarity")


def test_unrelated_function_in_a_gap_is_added_and_removed_not_paired():
    o = prints([Func("sub_140001000", BASE + 0x1000, lambda at: [("push", [reg("rbp")])] * 6)])
    f = prints([Func("sub_140009000", BASE + 0x9000, lambda at: [("syscall", [])] * 6)])
    d = diff_builds(o, f)
    assert (d.counts["added"], d.counts["removed"], d.counts["changed"]) == (1, 1, 0)


def test_stable_names():
    assert stable_name("main") and stable_name("CreateFileW") and stable_name("aLicenseValid")
    assert not stable_name("sub_140001250") and not stable_name("FUN_140001250") and not stable_name("dword_140005000")
    assert not stable_name("")


def test_hostile_names_and_texts_cannot_break_a_row():
    evil = Func("evil\nremoved original=0x1 name=x", BASE + 0x1000,
                lambda at: [("mov", [reg("rax"), imm(1)]), ("ret", [])])
    d = diff_builds(prints([evil]), [])
    text = pair_lines(d.pairs[0])
    assert text.count("\n") == 1 and "\x00" not in text


# ------------------------------------------------------------------------------------------------ engine documents

def _fn_doc(addr, n):
    return {"function_address": addr, "function_name": f"f{addr:x}", "size": 4 * n, "total": n, "full": True,
            "stop_reason": "", "counts": {"insns": n},
            "insns": [{"a": addr + 4 * i, "s": 4, "b": "90909090", "m": "nop", "t": "nop", "o": []} for i in range(n)]}


def test_bulk_document_is_validated():
    doc = {"functions": [_fn_doc(0x1000, 2), _fn_doc(0x1100, 1)], "function_total": 3, "first": 0, "next_index": 2,
           "counts": {"functions": 2}}
    bodies, bad = bodies_from_doc(doc)
    assert bad == "" and [f.address for f in bodies.items] == [0x1000, 0x1100] and bodies.next_index == 2
    for broken in ({**doc, "next_index": 5}, {**doc, "next_index": None}, {**doc, "counts": {"functions": 1}},
                   {**doc, "functions": [{**_fn_doc(0x1000, 2), "total": 1}, _fn_doc(0x1100, 1)]},
                   {k: v for k, v in doc.items() if k != "function_total"}):
        assert bodies_from_doc(broken)[0] is None
