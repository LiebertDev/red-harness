"""emulate version 2 (docs/design/emulation.md section 13): image pointers, scratch buffers, memory pre-writes, initial
registers, register outputs, register-pointer and digest-only outputs, code ranges (`end`) and verifier version 20.

Synthetic PEs with hand-assembled code; the known answer is the arithmetic of that code. The real-binary proof on the
host's ntdll.dll is tests/heavy/test_emulate_real.py.
"""
import hashlib
import json
import struct
import sys

import pytest

from redharness.analysis.pe_dirs import scan_imports
from redharness.config import Config
from redharness.emulate import loader, spec
from redharness.emulate.spec import SpecError, build_request, check_pe_image
from redharness.evidence.model import EMULATION_AUTHORITY, build_evidence
from redharness.evidence.verifier import verify_claim
from redharness.mcp.session import Hub, ToolFailure

from . import _synthpe
from ._fake_engine import FakeEngine
from ._pe_builder import build_pe
from .mcp_helpers import make_manifest
from .test_emulate import B32, B64, ENC, SECRET, SUM5_X64, XOR_LOOP, img, with_code

# x64: for (; r8; r8--) *rdx++ = *rcx++ ^ 0x20   (copies an image table into a buffer, upper-casing ASCII)
UPPER_COPY = bytes.fromhex("4d85c0" "7411" "8a01" "3420" "8802" "48ffc1" "48ffc2" "49ffc8" "ebea" "c3")
RDATA_HELLO = B64 + 0x2040            # "hello\0" in the builder's .rdata
# x64 struct walk: rdx = [rcx] (data pointer), r8 = [rcx+8] (length); XOR 0x5A over it in place
STRUCT_XOR = bytes.fromhex("488b11" "4c8b4108" "4d85c0" "740b" "80325a" "48ffc2" "49ffc8" "ebf0" "c3")
# x64: 0x1000 xor eax,eax (skipped by the range) | 0x1002 mov eax,[rsp+0x20] | 0x1006 imul eax,eax | 0x1009 ret
RANGE_SQUARE = bytes.fromhex("31c0" "8b442420" "0fafc0" "c3")
# x64: rax = rbx + rsi; rdi = rax
LEA_SUM = bytes.fromhex("488d0433" "4889c7" "c3")


@pytest.fixture(autouse=True, scope="module")
def _quiet_faulthandler():
    import faulthandler
    import sys
    was = faulthandler.is_enabled()
    faulthandler.disable()
    yield
    if was:
        faulthandler.enable(file=sys.stderr)


def run(data: bytes, **kw):
    pytest.importorskip("unicorn")
    from redharness.emulate.engine import run_request
    req = build_request(arch=img(data).arch, **kw)
    check_pe_image(req, img(data))
    return run_request(data, req)


# ---------------------------------------------------------------- request (no emulator)
def test_version1_request_is_canonically_unchanged():
    r = build_request(arch="x64", function=0x140001000, args=[1, {"hex": "00"}], outputs=[{"arg": 1, "length": 1}])
    assert set(r) == {"function", "arch", "convention", "args", "outputs", "max_instructions", "timeout_ms",
                      "stack_size", "layout_version"}
    data = build_pe(True)
    assert "scratch" not in loader.plan(img(data), lambda o, n: data[o:o + n], r).describe()


def test_references_and_new_fields_are_canonical():
    r = build_request(arch="x64", function="0x140001000", end="0x140001010",
                      args=[{"va": "0x140002040", "length": 6}, {"buf": 1, "offset": 1}, {"arg": 3}, {"buffer": 8}],
                      buffers=[{"buffer": 16}, {"hex": "aabb"}],
                      memory=[{"sp": "0x20", "hex": "5a"}, {"buf": 0, "ptr": {"buf": 1}},
                              {"buf": 0, "offset": 8, "ptr": 2}, {"va": "0x140003030", "ascii": "hi"}],
                      registers={"RBX": {"arg": 3}, "rax": 7}, output_registers=["rdi", "rax", "rsp"],
                      outputs=[{"buf": 1, "length": 2}, {"reg": "rdi", "length": 4, "digest": True}])
    assert r["args"] == [{"kind": "image_ptr", "value": 0x140002040, "length": 6},
                         {"kind": "buf_ptr", "buf": 1, "offset": 1}, {"kind": "arg_ptr", "arg": 3, "offset": 0},
                         {"kind": "buffer", "size": 8, "init_hex": ""}]
    assert r["buffers"][1] == {"kind": "buffer", "size": 2, "init_hex": "aabb"}
    assert r["memory"][0] == {"target": "sp", "offset": 0x20, "hex": "5a"}
    assert r["memory"][1] == {"target": "buf", "buf": 0, "offset": 0, "ptr": {"kind": "buf_ptr", "buf": 1,
                                                                              "offset": 0}}
    assert r["memory"][3] == {"target": "va", "va": 0x140003030, "hex": "6869"}     # no NUL in a pre-write
    assert list(r["registers"]) == ["rax", "rbx"] and r["registers"]["rbx"]["kind"] == "arg_ptr"
    assert r["output_registers"] == ["rdi", "rsp"]                                     # rax is always reported
    assert r["outputs"][1] == {"source": "reg", "reg": "rdi", "offset": 0, "length": 4, "digest": True}
    assert r["end"] == 0x140001010
    allregs = build_request(arch="x86", function=1, output_registers="all")["output_registers"]
    assert allregs == sorted({"ebx", "ecx", "esi", "edi", "ebp", "esp"})


@pytest.mark.parametrize("kw,needle", [
    ({"args": [{"arg": 1}, 5]}, "not a buffer argument"),
    ({"args": [{"buf": 0}]}, "not a scratch buffer"),
    ({"args": [{"va": "0x1", "offset": 2}]}, "image pointer is"),
    ({"registers": {"rsp": 1}}, "not a settable register"),
    ({"args": [1], "registers": {"rcx": 2}}, "already loaded from args"),
    ({"output_registers": ["xmm0"]}, "not a general-purpose register"),
    ({"memory": [{"va": 1, "sp": 2, "hex": "00"}]}, "exactly one target"),
    ({"memory": [{"buf": 0, "offset": 3, "hex": "0000"}], "buffers": [{"buffer": 4}]}, "outside the buffer"),
    ({"memory": [{"sp": 0, "hex": ""}]}, "empty data"),
    ({"outputs": [{"va": 1, "length": 4097}]}, "digest:true allows"),
    ({"outputs": [{"va": 1, "length": (1 << 20) + 1, "digest": True}]}, "length must be"),
    ({"end": "0x140001000"}, "different from the start"),
    ({"buffers": [{"size": 4}]}, "exactly one of"),
])
def test_v2_request_rejects_malformed_fields(kw, needle):
    with pytest.raises(SpecError) as e:
        build_request(arch="x64", function=0x140001000, **kw)
    assert needle in e.value.message


# ---------------------------------------------------------------- size limits (checked before any decoding)
def _oversize_literal(field: str) -> str:
    """A literal one byte past MAX_BUFFER (hex: two characters per byte, utf16: two bytes per character, + NUL)."""
    if field == "hex":
        return "aa" * (spec.MAX_BUFFER + 1)
    if field == "ascii":
        return "a" * (spec.MAX_BUFFER + 1)
    return "a" * (spec.MAX_BUFFER // 2 + 1)


@pytest.mark.parametrize("field", ["hex", "ascii", "utf16"])
def test_oversize_buffer_literal_is_refused_before_decoding(monkeypatch, field):
    calls = []
    real = spec._bytes

    def spy(a, k, what, *, nul):
        calls.append(what)
        return real(a, k, what, nul=nul)

    monkeypatch.setattr(spec, "_bytes", spy)
    for kw in ({"args": [{field: _oversize_literal(field)}]}, {"buffers": [{field: _oversize_literal(field)}]}):
        with pytest.raises(SpecError) as e:
            build_request(arch="x64", function=0x140001000, **kw)
        assert e.value.code == "BAD_ARGUMENT" and f"1..{spec.MAX_BUFFER}" in e.value.message
    assert calls == []          # the oversize literal never reached the decoder


def test_oversize_prewrite_total_is_refused_before_decoding(monkeypatch):
    calls = []
    real = spec._bytes

    def spy(a, k, what, *, nul):
        calls.append(what)
        return real(a, k, what, nul=nul)

    monkeypatch.setattr(spec, "_bytes", spy)
    chunk = "aa" * (40 << 10)   # 40 KiB each: fine alone, together over the aggregate budget
    with pytest.raises(SpecError) as e:
        build_request(arch="x64", function=0x140001000,
                      memory=[{"va": "0x140002000", "hex": chunk}, {"va": "0x140012000", "hex": chunk}])
    assert e.value.code == "BAD_ARGUMENT" and str(spec.MAX_PREWRITE_TOTAL) in e.value.message
    assert calls == ["memory[0]"]   # only the pre-write that still fits the running budget is decoded


@pytest.mark.parametrize("kw,needle", [
    ({"args": [{"va": hex(B64 + 0x5000)}]}, "outside the image"),
    ({"args": [{"va": hex(RDATA_HELLO), "length": 0x4000}]}, "outside the image"),
    ({"memory": [{"va": hex(B64 + 0x1004), "hex": "90"}]}, "executable section .text"),
    ({"memory": [{"va": hex(B64 + 0x10), "hex": "00"}]}, "PE headers"),
    ({"registers": {"rbx": {"va": "0x1000"}}}, "outside the image"),
    ({"end": hex(B64 + 0x9000)}, "outside the image"),
])
def test_image_checks_refuse_pointers_outside_and_code_prewrites(kw, needle):
    data = build_pe(True)
    req = build_request(arch="x64", function=B64 + 0x1000, **kw)
    with pytest.raises(SpecError) as e:
        check_pe_image(req, img(data))
    assert needle in e.value.message
    with pytest.raises(loader.LayoutError):           # the worker's layout refuses it as well (defense)
        loader.plan(img(data), lambda o, n: data[o:o + n], req)


def test_scratch_buffers_follow_argument_buffers_in_the_arena():
    data = build_pe(True)
    req = build_request(arch="x64", function=B64 + 0x1000, args=[{"buffer": 10}], buffers=[{"buffer": 0x1001}])
    lay = loader.plan(img(data), lambda o, n: data[o:o + n], req)
    v1 = loader.plan(img(data), lambda o, n: data[o:o + n],
                     build_request(arch="x64", function=B64 + 0x1000, args=[{"buffer": 10}]))
    assert lay.buffers == v1.buffers                  # the argument buffer keeps its version 1 address
    (r0, s0, _), = lay.buffers
    (r1, s1, b1), = lay.scratch
    assert r1 >= r0 + s0 + loader.BUFFER_GAP and s1 == 0x2000 and lay.describe()["scratch"] == [b1]


# ---------------------------------------------------------------- engine (Unicorn)
def test_image_pointer_argument_reads_a_table_in_rdata():
    r = run(with_code(build_pe(True), UPPER_COPY), function=B64 + 0x1000,
            args=[{"va": hex(RDATA_HELLO), "length": 5}, {"buffer": 5}, 5], outputs=[{"arg": 1, "length": 5}])
    assert r["ok"] and bytes.fromhex(r["outputs"][0]["hex"]) == b"HELLO" and r["arg_values"][0] == RDATA_HELLO


def test_structure_with_pointer_prewrite_and_register_and_digest_outputs():
    r = run(with_code(build_pe(True), STRUCT_XOR), function=B64 + 0x1000,
            buffers=[{"buffer": 16}, {"hex": ENC.hex()}], args=[{"buf": 0}],
            memory=[{"buf": 0, "ptr": {"buf": 1}}, {"buf": 0, "offset": 8, "hex": struct.pack("<Q", len(ENC)).hex()}],
            outputs=[{"buf": 1, "length": len(ENC)}, {"buf": 1, "length": len(ENC), "digest": True},
                     {"reg": "rcx", "length": 8}], output_registers=["rcx"])
    assert r["ok"] and r["stop"] == "return" and r["stack_balanced"]
    s0, s1 = r["layout"]["scratch"]
    assert bytes.fromhex(r["outputs"][0]["hex"]) == SECRET
    assert r["outputs"][1] == {"index": 1, "address": s1, "length": len(ENC), "digest": True,
                               "sha256": hashlib.sha256(SECRET).hexdigest()}
    assert r["registers"]["rcx"] == s0 == r["arg_values"][0]
    assert r["outputs"][2]["hex"] == struct.pack("<Q", s1).hex()      # the pointer the analyst pre-wrote


def test_initial_registers_and_extra_output_registers():
    r = run(with_code(build_pe(True), LEA_SUM), function=B64 + 0x1000, registers={"rbx": 5, "rsi": 0x30},
            output_registers=["rdi", "rbx"])
    assert r["ok"] and r["registers"] == {"rax": 0x35, "rdx": 0, "rbx": 5, "rdi": 0x35}


def test_prewrite_of_a_global_in_image_data():
    code = b"\x48\xa1" + struct.pack("<Q", B64 + 0x3030) + b"\xc3"       # mov rax, [abs .data+0x30]; ret
    r = run(with_code(build_pe(True), code), function=B64 + 0x1000,
            memory=[{"va": hex(B64 + 0x3030), "hex": struct.pack("<Q", 42).hex()}])
    assert r["ok"] and r["registers"]["rax"] == 42
    plain = run(with_code(build_pe(True), code), function=B64 + 0x1000)
    assert plain["registers"]["rax"] == 0


def test_code_range_stops_at_end_with_a_stack_local():
    data = with_code(build_pe(True), RANGE_SQUARE)
    r = run(data, function=B64 + 0x1002, end=B64 + 0x1009, memory=[{"sp": "0x20", "hex": "07000000"}])
    assert r["ok"] and r["stop"] == "range_end" and r["pc"] == B64 + 0x1009 and r["registers"]["rax"] == 49
    assert "stack_balanced" not in r
    # the stack pointer has room above it for the enclosing function's locals
    assert r["layout"]["stack"][1] - r["sp_entry"] >= 0x2000


def test_code_range_that_returns_before_end_is_not_a_result():
    r = run(with_code(build_pe(True), RANGE_SQUARE), function=B64 + 0x1002, end=B64 + 0x100A,
            memory=[{"sp": "0x20", "hex": "07000000"}])
    assert not r["ok"] and r["stop"] == "left_range" and r["end"] == B64 + 0x100A


def test_code_range_still_stops_at_an_import_call():
    data = _synthpe.build_pe(is64=False, imports={"KERNEL32.dll": ["VirtualAlloc"]})
    slot = B32 + scan_imports(data).imports[0].functions[0].thunk_rva
    code = b"\x90\xff\x15" + struct.pack("<I", slot) + b"\x90\xc3"           # nop; call [slot]; nop; ret
    r = run(with_code(data, code), function=B32 + 0x1000, end=B32 + 0x1007)
    assert not r["ok"] and r["stop"] == "import_call" and r["api"] == "KERNEL32.dll!VirtualAlloc"


def test_stack_prewrite_outside_the_stack_is_a_bad_request():
    r = run(with_code(build_pe(True), RANGE_SQUARE), function=B64 + 0x1002, end=B64 + 0x1009,
            memory=[{"sp": "0x4000", "hex": "00"}])
    assert not r["ok"] and r["stop"] == "bad_request" and "outside the mapped stack" in r["error"]


# ---------------------------------------------------------------- MCP tool, evidence, verifier v20
def _in_process(path, sha, request):
    from redharness.emulate.worker import handle
    return json.loads(json.dumps(handle({"target_path": path, "target_sha256": sha, "request": request},
                                        harden=False)))


def make_hub(tmp_path, data):
    target = tmp_path / "t.exe"
    target.write_bytes(data)
    manifest = make_manifest(tmp_path / "scope.json", target, allowed_operations=["static", "emulate"])
    hub = Hub(Config.load(tmp_path / "data"), FakeEngine())
    hub.emulate_runner = _in_process
    hub.target_open(str(target), str(manifest))
    return hub


def _call(hub, **kw):
    return hub.call("emulate", kw, lambda: hub.emulate(**kw))


def test_range_evidence_is_reproducible_and_supports_an_observation(tmp_path):
    pytest.importorskip("unicorn")
    hub = make_hub(tmp_path, with_code(build_pe(True), RANGE_SQUARE))
    try:
        kw = dict(function=hex(B64 + 0x1002), end=hex(B64 + 0x1009), memory=[{"sp": "0x20", "hex": "07000000"}])
        r1, r2 = _call(hub, **kw), _call(hub, **kw)
        assert r1["evidence_id"] == r2["evidence_id"] and r1["stop"] == "range_end" and "stack_balanced" not in r1
        assert r1["registers"]["rax"] == "0x31"
        ev = hub._s.ledger.state["evidence"][r1["evidence_id"]]
        assert ev["result"]["stop"] == "range_end" and ev["parameters"]["end"] == B64 + 0x1009
        assert ev["parameters"]["memory"] == [{"target": "sp", "offset": 0x20, "hex": "07000000"}]
        assert any("code range" in lim for lim in ev["limitations"])
        assert "pre-write memory[0] sp+0x20: 4 bytes (analyst input" in r1["content"]
        assert "07000000" not in r1["content"]           # analyst bytes are not printed as output
        ok = hub.claim_add(text="Under emulation the code range from 0x140001002 to 0x140001009 leaves 0x31 in eax",
                           evidence_ids=[r1["evidence_id"]], kind="observation", requested="SUPPORTED")
        assert ok["status"] == "SUPPORTED", ok
        ver = hub._s.ledger.state["claims"][ok["claim_id"]]["verification"]
        assert ver["verifier_version"] == "23" and {"code": "EMULATION", "ok": True} in ver["checks"]
        beh = hub.claim_add(text="The program computes 0x31 when it runs", evidence_ids=[r1["evidence_id"]],
                            kind="behavior", requested="PROVEN")
        assert beh["status"] != "PROVEN"
    finally:
        hub.close()


def test_digest_output_backs_the_hash_in_an_observation(tmp_path):
    pytest.importorskip("unicorn")
    hub = make_hub(tmp_path, with_code(build_pe(True), XOR_LOOP))
    try:
        r = _call(hub, function=hex(B64 + 0x1000), args=[{"hex": ENC.hex()}, len(ENC)],
                  outputs=[{"arg": 0, "length": len(ENC), "digest": True}])
        digest = hashlib.sha256(SECRET).hexdigest()
        assert r["outputs"][0]["digest_only"] and f"sha256={digest}" in r["content"]
        assert SECRET.decode() not in r["content"]
        ok = hub.claim_add(text=f"Under emulation the decoded buffer has SHA-256 {digest}",
                           evidence_ids=[r["evidence_id"]], kind="observation", requested="SUPPORTED",
                           values=[digest])
        assert ok["status"] == "SUPPORTED", ok
        wrong = hashlib.sha256(SECRET + b"x").hexdigest()
        bad = hub.claim_add(text=f"Under emulation the decoded buffer has SHA-256 {wrong}",
                            evidence_ids=[r["evidence_id"]], kind="observation", requested="SUPPORTED",
                            values=[wrong])
        assert bad["status"] != "SUPPORTED"
    finally:
        hub.close()


def test_tool_refuses_code_prewrites_and_reports_left_range(tmp_path):
    pytest.importorskip("unicorn")
    hub = make_hub(tmp_path, with_code(build_pe(True), RANGE_SQUARE))
    try:
        with pytest.raises(ToolFailure) as e:
            _call(hub, function=hex(B64 + 0x1002), memory=[{"va": hex(B64 + 0x1006), "hex": "90"}])
        assert e.value.code == "BAD_ARGUMENT" and "executable section" in e.value.message
        with pytest.raises(ToolFailure) as e2:
            _call(hub, function=hex(B64 + 0x1002), end=hex(B64 + 0x100A), memory=[{"sp": "0x20", "hex": "07"}])
        assert e2.value.code == "EMU_BAD_RETURN" and "before execution reached end" in e2.value.message
        with pytest.raises(ToolFailure) as e3:
            _call(hub, function=hex(B64 + 0x1002), end=hex(B64 + 0x1009), memory=[{"sp": "-0x2000000", "hex": "07"}])
        assert e3.value.code == "BAD_ARGUMENT"
        assert not [x for x in hub._s.ledger.state["evidence"].values() if x["operation"] == "emulate"]
    finally:
        hub.close()


@pytest.mark.parametrize("params_end,stop,valid", [
    (None, "return", True), (0x140001009, "range_end", True),
    (None, "range_end", False), (0x140001009, "return", False),
])
def test_verifier_v20_requires_the_stop_to_match_the_request(tmp_path, params_end, stop, valid):
    from redharness.core.cas import Cas
    from redharness.core.result import Status
    cas = Cas(tmp_path / "cas")
    sha = "a" * 64
    params = {k: 0 for k in ("function", "arch", "convention", "args", "outputs", "max_instructions", "timeout_ms",
                             "stack_size", "layout_version", "emulator")}
    if params_end is not None:
        params["end"] = params_end
    ev = build_evidence(cas, subject_sha256=sha, tool="emulate", operation="emulate", raw=b"final rax=0x31 (49)\n",
                        status=Status.OK, confidence="derived", authority=EMULATION_AUTHORITY, parameters=params,
                        result={"stop": stop, "deterministic": True},
                        environment={"isolation": "process", "native_execution": False})
    claim = {"text": "Emulation leaves 0x31 in rax", "kind": "observation", "polarity": "present",
             "requested": "SUPPORTED", "evidence_ids": [ev["evidence_id"]], "atoms": []}
    v = verify_claim(claim, {ev["evidence_id"]: ev}, {}, cas, sha)
    assert (v.status.value == "SUPPORTED") is valid
    assert ("EMULATION_RECORD_INVALID" in v.codes) is (not valid)


@pytest.mark.skipif(sys.platform != "win32", reason="the hardened emulate worker is Windows only; the off-Windows refusal over stdio is test_emulate.py::test_emulate_over_the_real_stdio_protocol")
def test_v2_fields_over_the_real_stdio_protocol(tmp_path):
    """The registered MCP tool passes the version 2 fields through (stdio client -> server -> worker -> evidence)."""
    pytest.importorskip("unicorn")
    import asyncio
    from pathlib import Path

    from .mcp_helpers import call, mcp_session
    target = tmp_path / "t.exe"
    target.write_bytes(with_code(build_pe(True), RANGE_SQUARE))
    manifest = make_manifest(tmp_path / "scope.json", target, allowed_operations=["static", "emulate"])
    server = [str(Path(__file__).with_name("_fake_mcp_server.py"))]

    async def go():
        async with mcp_session(server, tmp_path / "data") as s:
            err, opened = await call(s, "target_open", target_path=str(target), manifest_path=str(manifest))
            assert not err, opened
            return await call(s, "emulate", function=hex(B64 + 0x1002), end=hex(B64 + 0x1009),
                              memory=[{"sp": "0x20", "hex": "07000000"}], buffers=[{"buffer": 4}],
                              registers={"rbx": {"buf": 0}}, output_registers=["rbx"],
                              outputs=[{"buf": 0, "length": 4, "digest": True}])
    err, r = asyncio.run(go())
    assert not err, r
    assert r["stop"] == "range_end" and r["registers"]["rax"] == "0x31"
    assert r["registers"]["rbx"] == r["outputs"][0]["address"] and r["outputs"][0]["digest_only"]
