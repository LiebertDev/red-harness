"""emulate: CPU emulation of one function of the target (Unicorn), evidence and verifier rules.

Synthetic PEs only (tests/unit/_pe_builder.py, tests/unit/_synthpe.py) with hand-assembled code patched into .text;
the known answer is the arithmetic of that code. The real-binary proof is tests/heavy/test_emulate_real.py.
"""
import json
import struct

import pytest

from redharness.analysis.pe_dirs import scan_imports
from redharness.analysis.pe_image import PeImage, Section, parse_pe
from redharness.config import Config
from redharness.emulate import loader
from redharness.emulate.spec import SpecError, build_request
from redharness.evidence.model import EMULATION_AUTHORITY, build_evidence, compute_evidence_id
from redharness.evidence.verifier import verify_claim
from redharness.mcp.effects import TOOL_EFFECTS, EffectDenied, check_permission
from redharness.mcp.session import Hub, ToolFailure
from redharness.scope.manifest import parse_manifest

from . import _synthpe
from ._fake_engine import FakeEngine
from ._pe_builder import build_pe
from .mcp_helpers import make_manifest

B64, B32 = 0x140000000, 0x400000
TEXT = 0x400            # file offset of .text (rva 0x1000) in both builders


@pytest.fixture(autouse=True, scope="module")
def _quiet_faulthandler():
    """Unicorn on Windows raises and itself handles an access violation inside the first mem_map of every emulator
    instance; Python's faulthandler (enabled by pytest) prints it as 'Windows fatal exception' although nothing
    failed. The worker process used by the tool does not enable faulthandler."""
    import faulthandler
    import sys
    was = faulthandler.is_enabled()
    faulthandler.disable()
    yield
    if was:
        faulthandler.enable(file=sys.stderr)


def with_code(pe: bytes, code: bytes, at: int = 0) -> bytes:
    return pe[:TEXT + at] + code + pe[TEXT + at + len(code):]


def img(data: bytes) -> PeImage:
    return parse_pe(lambda o, n: data[o:o + n], len(data))


# x64 ms64: rax = rcx + rdx + r8 + r9 + [rsp+0x28] (5th argument, after the 32-byte shadow space)
SUM5_X64 = bytes.fromhex("488d0411" "4c01c0" "4c01c8" "4803442428" "c3")
# x86: eax = [esp+4] - [esp+8]; `ret` (cdecl) or `ret 8` (stdcall)
SUB_CDECL = bytes.fromhex("8b442404" "2b442408" "c3")
SUB_STDCALL = bytes.fromhex("8b442404" "2b442408" "c20800")
SUB_FASTCALL = bytes.fromhex("89c8" "29d0" "c3")                 # eax = ecx - edx
ADD_THISCALL = bytes.fromhex("89c8" "03442404" "c20400")         # eax = ecx + [esp+4]; ret 4
# x64: for (; rdx; rdx--, rcx++) *rcx ^= 0x5A;
XOR_LOOP = bytes.fromhex("4885d2" "740b" "80315a" "48ffc1" "48ffca" "75f5" "c3")
SECRET = b"kernel32.dll"
ENC = bytes(b ^ 0x5A for b in SECRET)


def run(data: bytes, **kw):
    pytest.importorskip("unicorn")
    from redharness.emulate.engine import run_request
    req = build_request(arch=img(data).arch, **kw)
    return run_request(data, req)


# ---------------------------------------------------------------- request validation (no emulator needed)
def test_request_is_canonical_and_float_free():
    r = build_request(arch="x64", function="0x140001000", args=[1, "0x10", -1, {"hex": "00ff"}, {"ascii": "ab"},
                                                               {"utf16": "A"}, {"buffer": 8}, {"hex": "01", "size": 4}],
                      outputs=[{"arg": 3, "length": 2}, {"va": "0x140003000", "length": 4, "view": "u32"},
                               {"ret": True, "length": 1}], timeout_s=2.5)
    assert r["function"] == 0x140001000 and r["convention"] == "ms64" and r["timeout_ms"] == 2500
    assert r["args"][:3] == [{"kind": "int", "value": 1}, {"kind": "int", "value": 16},
                             {"kind": "int", "value": (1 << 64) - 1}]
    assert r["args"][3:] == [{"kind": "buffer", "size": 2, "init_hex": "00ff"},
                             {"kind": "buffer", "size": 3, "init_hex": "616200"},
                             {"kind": "buffer", "size": 4, "init_hex": "41000000"},
                             {"kind": "buffer", "size": 8, "init_hex": ""},
                             {"kind": "buffer", "size": 4, "init_hex": "01"}]
    assert r["outputs"][1] == {"source": "va", "va": 0x140003000, "length": 4, "views": ["u32"]}
    assert r["outputs"][2]["source"] == "ret" and r["outputs"][0]["views"] == ["ascii"]

    def floats(o):
        return isinstance(o, float) or (isinstance(o, dict) and any(floats(v) for v in o.values())) or (
            isinstance(o, list) and any(floats(v) for v in o))
    assert not floats(r)
    assert build_request(arch="x86", function=0x401000)["convention"] == "cdecl"


@pytest.mark.parametrize("kw,needle", [
    ({"arch": "x64", "function": 0x1000, "convention": "stdcall"}, "not valid for x64"),
    ({"arch": "x86", "function": 0x1000, "convention": "ms64"}, "not valid for x86"),
    ({"arch": "x86", "function": 0x1000, "args": [1 << 32]}, "does not fit in 32 bits"),
    ({"arch": "x64", "function": 0x1000, "args": [{"buffer": (1 << 20) + 1}]}, "buffer size"),
    ({"arch": "x64", "function": 0x1000, "args": [{"hex": "0"}]}, "even-length"),
    ({"arch": "x64", "function": 0x1000, "args": [7], "outputs": [{"arg": 0, "length": 4}]}, "not a buffer"),
    ({"arch": "x64", "function": 0x1000, "args": [{"buffer": 4}], "outputs": [{"arg": 0, "length": 8}]}, "outside"),
    ({"arch": "x64", "function": 0x1000, "outputs": [{"va": 1, "length": 5000}]}, "length must be"),
    ({"arch": "x64", "function": 0x1000, "max_instructions": 0}, "max_instructions"),
    ({"arch": "x64", "function": 0x1000, "timeout_s": 61}, "timeout_s"),
    ({"arch": "x64", "function": True}, "bool"),
    ({"arch": "arm64", "function": 0x1000}, "x86 and x64"),
])
def test_request_rejects_malformed_arguments(kw, needle):
    with pytest.raises(SpecError) as e:
        build_request(**kw)
    assert needle in e.value.message


# ---------------------------------------------------------------- layout (no emulator needed)
def test_layout_maps_file_bytes_and_section_permissions():
    data = build_pe(True)
    lay = loader.plan(img(data), lambda o, n: data[o:o + n], build_request(arch="x64", function=B64 + 0x1000))
    assert lay.image_base == B64 and lay.image_size == 0x5000 and lay.perms_enforced
    assert lay.perms == [(B64, 0x1000, "r"), (B64 + 0x1000, 0x1000, "rx"), (B64 + 0x2000, 0x1000, "r"),
                         (B64 + 0x3000, 0x2000, "rw")]
    got = dict(lay.chunks)
    assert got[B64 + 0x1000] == data[0x400:0x500] and got[B64 + 0x3000] == data[0x800:0xA00]  # .data: file part only
    assert lay.arena == 0x10000000 and lay.ret_sentinel == 0x13000000 and lay.stack_top == 0x11000000


def test_layout_arena_avoids_the_image_and_is_deterministic():
    data = build_pe(False, base=0x10000000)
    req = build_request(arch="x86", function=0x10001000, args=[{"buffer": 10}, 5, {"buffer": 0x1001}])
    a = loader.plan(img(data), lambda o, n: data[o:o + n], req)
    b = loader.plan(img(data), lambda o, n: data[o:o + n], req)
    assert a.arena == 0x20000000 and a.describe() == b.describe()
    (r0, s0, b0), (r1, s1, b1) = a.buffers
    assert (s0, s1) == (0x1000, 0x2000) and b0 == (r0 + s0 - 10) & ~0xF and r1 >= r0 + s0 + loader.BUFFER_GAP


def test_layout_redirects_every_import_slot_to_a_named_sentinel():
    data = _synthpe.build_pe(is64=False, imports={"KERNEL32.dll": ["GetTickCount", 17]},
                             delay_imports={"USER32.dll": ["MessageBoxA"]})
    lay = loader.plan(img(data), lambda o, n: data[o:o + n], build_request(arch="x86", function=B32 + 0x1000))
    assert sorted(lay.thunks.values()) == ["KERNEL32.dll!#17", "KERNEL32.dll!GetTickCount", "USER32.dll!MessageBoxA"]
    prof = scan_imports(data)
    slots = {B32 + f.thunk_rva for t in prof.all_tables for f in t.functions}
    assert {s for s, _ in lay.iat_writes} == slots
    assert all(lay.import_at(t) == lay.thunks[t] for _, t in lay.iat_writes)


def test_unaligned_sections_disable_permission_enforcement():
    im = PeImage(0x1000, True, 0x8664, B64, 0x3000, 0x200,
                 (Section(".text", 0x200, 0x100, 0x200, 0x200, 0x60000020),), 0)
    assert loader._image_perms(im) == ([], False)


# ---------------------------------------------------------------- calling conventions and results (Unicorn)
def test_x64_ms64_passes_four_register_and_stack_arguments():
    r = run(with_code(build_pe(True), SUM5_X64), function=B64 + 0x1000, args=[1, 2, 3, 4, 5])
    assert r["ok"] and r["stop"] == "return" and r["registers"]["rax"] == 15
    assert r["stack_balanced"] and r["deterministic"] and r["runs"] == 2
    assert (r["sp_entry"] + 8) % 16 == 0


@pytest.mark.parametrize("code,conv,args,want", [
    (SUB_CDECL, "cdecl", [10, 3], 7),
    (SUB_STDCALL, "stdcall", [10, 3], 7),
    (SUB_FASTCALL, "fastcall", [10, 3], 7),
    (ADD_THISCALL, "thiscall", [0x100, 0x23], 0x123),
])
def test_x86_conventions(code, conv, args, want):
    r = run(with_code(build_pe(False), code), function=B32 + 0x1000, convention=conv, args=args)
    assert r["ok"] and r["registers"]["eax"] == want and r["stack_balanced"]
    assert (r["sp_entry"] + 4) % 16 == 0


@pytest.mark.parametrize("code,conv,args", [
    (SUB_STDCALL, "cdecl", [10, 3]),       # callee pops 8 bytes, cdecl expects none
    (SUB_CDECL, "stdcall", [10, 3]),       # callee pops nothing, stdcall expects 8 bytes
])
def test_wrong_convention_is_not_a_return(code, conv, args):
    r = run(with_code(build_pe(False), code), function=B32 + 0x1000, convention=conv, args=args)
    assert not r["ok"] and r["stop"] == "bad_return" and r["ret_slot_read"] and r["sp_after"] != r["sp_expected"]


def test_jump_to_the_return_address_is_not_a_return():
    sentinel = 0x10000000 + loader.RET_OFF                    # arena of a 0x140000000 image + return sentinel
    code = b"\x48\xb8" + struct.pack("<Q", sentinel) + b"\xff\xe0"   # mov rax, sentinel; jmp rax
    r = run(with_code(build_pe(True), code), function=B64 + 0x1000)
    assert not r["ok"] and r["stop"] == "bad_return" and r["ret_slot_read"] is False


def test_unreadable_import_tables_refuse_the_layout(monkeypatch):
    bad = _synthpe.build_pe(is64=True, import_dir=0x9000)    # import directory outside the image
    with pytest.raises(loader.LayoutError, match="import tables cannot be read"):
        loader.plan(img(bad), lambda o, n: bad[o:o + n], build_request(arch="x64", function=B64 + 0x1000))
    good = _synthpe.build_pe(is64=True, imports={"KERNEL32.dll": ["GetTickCount"]})
    prof = scan_imports(good)
    from dataclasses import replace
    monkeypatch.setattr(loader, "scan_imports_image",
                        lambda i, r: replace(prof, complete=False, unknowns=("KERNEL32.dll: thunk 1 unreadable",)))
    with pytest.raises(loader.LayoutError, match="incomplete"):
        loader.plan(img(good), lambda o, n: good[o:o + n], build_request(arch="x64", function=B64 + 0x1000))


def test_unreadable_import_tables_stop_the_engine_without_a_result():
    bad = with_code(_synthpe.build_pe(is64=True, import_dir=0x9000), bytes.fromhex("31c0c3"))
    r = run(bad, function=B64 + 0x1000)
    assert not r["ok"] and r["stop"] == "layout_error" and "import" in r["error"]


def test_buffer_argument_is_decoded_and_read_back():
    r = run(with_code(build_pe(True), XOR_LOOP), function=B64 + 0x1000, args=[{"hex": ENC.hex()}, len(ENC)],
            outputs=[{"arg": 0, "length": len(ENC)}])
    assert r["ok"] and bytes.fromhex(r["outputs"][0]["hex"]) == SECRET
    assert r["outputs"][0]["address"] == r["arg_values"][0]


def test_global_table_decoded_in_place_is_read_from_image_memory():
    data_va = B64 + 0x3030                                   # .data + 0x30: the builder's marker slot
    code = (b"\x48\xb9" + struct.pack("<Q", data_va)          # mov rcx, data_va
            + b"\x48\xc7\xc2" + struct.pack("<I", len(ENC))  # mov rdx, len
            + XOR_LOOP)
    r = run(with_code(build_pe(True, data_marker=ENC), code), function=B64 + 0x1000,
            outputs=[{"va": hex(data_va), "length": len(ENC)}])
    assert r["ok"] and bytes.fromhex(r["outputs"][0]["hex"]) == SECRET


# ---------------------------------------------------------------- explicit stops: never a result
def test_call_into_an_import_stops_with_its_name():
    data = _synthpe.build_pe(is64=False, imports={"KERNEL32.dll": ["GetTickCount"]})
    slot = B32 + scan_imports(data).imports[0].functions[0].thunk_rva
    code = b"\xff\x15" + struct.pack("<I", slot) + b"\xc3"   # call dword [slot]; ret
    r = run(with_code(data, code), function=B32 + 0x1000)
    assert not r["ok"] and r["stop"] == "import_call" and r["api"] == "KERNEL32.dll!GetTickCount"


@pytest.mark.parametrize("code,stop,extra", [
    (bytes.fromhex("488b042500000000c3"), "unmapped_read", {"address": 0}),          # mov rax,[0]
    (bytes.fromhex("65488b042560000000c3"), "teb_access", {"offset": 0x60}),         # mov rax,gs:[0x60]
    (bytes.fromhex("0f05c3"), "instruction", {"instruction": "syscall"}),
    (bytes.fromhex("0fa2c3"), "instruction", {"instruction": "cpuid"}),
    (bytes.fromhex("ccc3"), "interrupt", {"number": 3}),
    (b"\x48\xb9" + struct.pack("<Q", B64 + 0x2000) + b"\xc6\x01\x01\xc3", "protection_write", {}),  # write .rdata
    (bytes.fromhex("ebfe"), "instruction_limit", {}),
])
def test_unsupported_events_stop_the_emulation(code, stop, extra):
    r = run(with_code(build_pe(True), code), function=B64 + 0x1000, max_instructions=1000)
    assert not r["ok"] and r["stop"] == stop
    assert {k: r[k] for k in extra} == extra


def test_x86_fs_relative_teb_read_is_reported_as_low_address():
    r = run(with_code(build_pe(False), bytes.fromhex("64a130000000c3")), function=B32 + 0x1000)
    assert r["stop"] == "unmapped_read" and r["address"] == 0x30 and "TEB" in r["note"]


def test_rdtsc_result_is_rejected_as_nondeterministic():
    r = run(with_code(build_pe(True), bytes.fromhex("0f31" "48c1e220" "4809d0" "c3")), function=B64 + 0x1000)
    assert not r["ok"] and r["stop"] == "nondeterministic"


def test_unreadable_output_is_not_a_result():
    r = run(with_code(build_pe(True), bytes.fromhex("31c0c3")), function=B64 + 0x1000,
            outputs=[{"ret": True, "length": 4}])
    assert not r["ok"] and r["stop"] == "output_unreadable" and r["address"] == 0


# ---------------------------------------------------------------- MCP tool, evidence, verifier
def _in_process(path, sha, request):
    from redharness.emulate.worker import handle
    # harden=False: lowering the integrity of the test process itself would break the rest of the session
    return json.loads(json.dumps(handle({"target_path": path, "target_sha256": sha, "request": request},
                                        harden=False)))


def make_hub(tmp_path, data, ops=("static", "emulate")):
    tmp_path.mkdir(parents=True, exist_ok=True)
    target = tmp_path / "t.exe"
    target.write_bytes(data)
    manifest = make_manifest(tmp_path / "scope.json", target, allowed_operations=list(ops))
    hub = Hub(Config.load(tmp_path / "data"), FakeEngine())
    hub.emulate_runner = _in_process
    hub.target_open(str(target), str(manifest))
    return hub


def _emu_evidence(hub):
    return [e for e in hub._s.ledger.state["evidence"].values() if e["operation"] == "emulate"]


def _call(hub, tool, **kw):
    return hub.call(tool, kw, lambda: getattr(hub, tool)(**kw))


def test_effect_table_and_manifest_need_the_emulate_operation(tmp_path):
    assert TOOL_EFFECTS["emulate"].active() == ["launches_process", "emulates_target_code"]
    for ops in (["static"], ["static", "compute"], ["static", "run_controlled"]):
        with pytest.raises(EffectDenied):
            check_permission("emulate", parse_manifest(_doc(ops)))
    check_permission("emulate", parse_manifest(_doc(["static", "emulate"])))


def _doc(ops):
    return {"schema": "rh.scope/1", "target_sha256": "0" * 64, "allowed_operations": ops,
            "authorization": {"declared_by": "t", "basis": "owner", "statement": "mine"}}


def test_emulate_is_refused_without_permission(tmp_path):
    pytest.importorskip("unicorn")
    hub = make_hub(tmp_path, with_code(build_pe(True), SUM5_X64), ops=("static",))
    try:
        with pytest.raises(ToolFailure) as e:
            _call(hub, "emulate", function=hex(B64 + 0x1000), args=[1, 2, 3, 4, 5])
        assert e.value.code == "SCOPE_DENIED" and not _emu_evidence(hub)
    finally:
        hub.close()


def test_emulation_becomes_reproducible_evidence_and_supports_only_observations(tmp_path):
    pytest.importorskip("unicorn")
    hub = make_hub(tmp_path, with_code(build_pe(True), XOR_LOOP))
    try:
        kw = dict(function=hex(B64 + 0x1000), args=[{"hex": ENC.hex()}, len(ENC)],
                  outputs=[{"arg": 0, "length": len(ENC)}])
        r1 = _call(hub, "emulate", **kw)
        r2 = _call(hub, "emulate", **kw)
        assert r1["evidence_id"] == r2["evidence_id"] and r1["stack_balanced"]
        ev = hub._s.ledger.state["evidence"][r1["evidence_id"]]
        assert ev["authority"] == EMULATION_AUTHORITY and ev["confidence"] == "derived"
        assert ev["environment"]["native_execution"] is False
        p = ev["parameters"]
        assert p["function"] == B64 + 0x1000 and p["args"][0]["init_hex"] == ENC.hex()
        assert p["emulator"]["name"] == "unicorn" and p["layout_version"] == 1
        assert '"kernel32.dll"' in r1["content"]

        obs = hub.claim_add(text="Emulating 0x140001000 over the buffer decodes it to kernel32.dll",
                            evidence_ids=[r1["evidence_id"]], kind="observation", requested="SUPPORTED",
                            values=["kernel32.dll"])
        assert obs["status"] == "SUPPORTED", obs
        ver = hub._s.ledger.state["claims"][obs["claim_id"]]["verification"]
        assert {"code": "EMULATION", "ok": True} in ver["checks"] and ver["verifier_version"] == "23"
        assert [v.get("support") for v in ver["values"]] == ["emulation"]

        beh = hub.claim_add(text="The program accepts kernel32.dll as the correct password",
                            evidence_ids=[r1["evidence_id"]], kind="behavior", requested="PROVEN",
                            values=["kernel32.dll"])
        assert beh["status"] == "UNVERIFIED"
    finally:
        hub.close()


def test_emulated_hex_value_backs_an_observation_literal(tmp_path):
    pytest.importorskip("unicorn")
    hub = make_hub(tmp_path, with_code(build_pe(True), SUM5_X64))
    try:
        r = _call(hub, "emulate", function=hex(B64 + 0x1000), args=[1, 2, 3, 4, 0x1000])
        assert r["registers"]["rax"] == "0x100a"
        ok = hub.claim_add(text="Under emulation the function at 0x140001000 returns 0x100a for these arguments",
                           evidence_ids=[r["evidence_id"]], kind="observation", requested="SUPPORTED")
        assert ok["status"] == "SUPPORTED", ok
        bad = hub.claim_add(text="Under emulation the function at 0x140001000 returns 0x100b",
                            evidence_ids=[r["evidence_id"]], kind="observation", requested="SUPPORTED")
        assert bad["status"] == "REJECTED"
    finally:
        hub.close()


def test_stop_is_an_error_with_no_evidence(tmp_path):
    pytest.importorskip("unicorn")
    data = _synthpe.build_pe(is64=True, imports={"KERNEL32.dll": ["IsDebuggerPresent"]})
    slot = B64 + scan_imports(data).imports[0].functions[0].thunk_rva
    code = b"\x48\xb8" + struct.pack("<Q", slot) + b"\xff\x10\xc3"     # mov rax, slot; call [rax]; ret
    hub = make_hub(tmp_path, with_code(data, code))
    try:
        with pytest.raises(ToolFailure) as e:
            _call(hub, "emulate", function=hex(B64 + 0x1000))
        assert e.value.code == "EMU_UNSUPPORTED_API" and "KERNEL32.dll!IsDebuggerPresent" in e.value.message
        assert "unknown_record" in e.value.message and not _emu_evidence(hub)
        with pytest.raises(ToolFailure) as e2:
            _call(hub, "emulate", function=hex(B64 + 0x9000))
        assert e2.value.code == "OUT_OF_IMAGE"
    finally:
        hub.close()


def test_missing_emulator_is_reported_and_nothing_runs(tmp_path, monkeypatch):
    from redharness.emulate import engine
    hub = make_hub(tmp_path, with_code(build_pe(True), SUM5_X64))

    def missing():
        raise engine.EmulatorMissing("not installed")
    monkeypatch.setattr(engine, "emulator_identity", missing)
    try:
        with pytest.raises(ToolFailure) as e:
            _call(hub, "emulate", function=hex(B64 + 0x1000))
        assert e.value.code == "EMULATOR_MISSING" and not _emu_evidence(hub)
    finally:
        hub.close()


def test_worker_process_gives_the_same_result_as_in_process(tmp_path):
    pytest.importorskip("unicorn")
    import hashlib
    from redharness.emulate.host import run_in_worker
    data = with_code(build_pe(True), SUM5_X64)
    p = tmp_path / "t.exe"
    p.write_bytes(data)
    sha = hashlib.sha256(data).hexdigest()
    req = build_request(arch="x64", function=B64 + 0x1000, args=[1, 2, 3, 4, 5])
    got = run_in_worker(str(p), sha, req)
    assert got == _in_process(str(p), sha, req) and got["registers"]["rax"] == 15
    assert run_in_worker(str(p), "0" * 64, req)["stop"] == "target_changed"


def test_verifier_rejects_a_record_that_is_not_a_returned_emulation(tmp_path):
    from redharness.core.cas import Cas
    from redharness.core.result import Status
    cas = Cas(tmp_path / "cas")
    sha = "a" * 64
    params = {k: 0 for k in ("function", "arch", "convention", "args", "outputs", "max_instructions", "timeout_ms",
                             "stack_size", "layout_version", "emulator")}
    ev = build_evidence(cas, subject_sha256=sha, tool="emulate", operation="emulate", raw=b"return rax=0x5 (5)\n",
                        status=Status.OK, confidence="derived", authority=EMULATION_AUTHORITY, parameters=params,
                        result={"stop": "import_call", "deterministic": True},
                        environment={"isolation": "process", "native_execution": False})
    claim = {"text": "Emulation returns 0x5", "kind": "observation", "polarity": "present", "requested": "SUPPORTED",
             "evidence_ids": [ev["evidence_id"]], "atoms": []}
    v = verify_claim(claim, {ev["evidence_id"]: ev}, {}, cas, sha)
    assert v.status.value == "REJECTED" and "EMULATION_RECORD_INVALID" in v.codes
    good = dict(ev, result={"stop": "return", "deterministic": True})
    good["evidence_id"] = compute_evidence_id(good)
    v2 = verify_claim(dict(claim, evidence_ids=[good["evidence_id"]]), {good["evidence_id"]: good}, {}, cas, sha)
    assert v2.status.value == "SUPPORTED" and {"code": "EMULATION", "ok": True} in v2.checks
    with pytest.raises(ValueError):
        build_evidence(cas, subject_sha256=sha, tool="emulate", operation="emulate", raw=b"x", status=Status.OK,
                       confidence="observed", authority=EMULATION_AUTHORITY,
                       environment={"isolation": "process", "native_execution": False})


def test_emulate_over_the_real_stdio_protocol(tmp_path):
    """The registered MCP tool end to end: stdio client -> server -> bounded worker process -> evidence."""
    pytest.importorskip("unicorn")
    import asyncio
    from pathlib import Path

    from .mcp_helpers import call, mcp_session
    target = tmp_path / "t.exe"
    target.write_bytes(with_code(build_pe(True), XOR_LOOP))
    manifest = make_manifest(tmp_path / "scope.json", target, allowed_operations=["static", "emulate"])
    server = [str(Path(__file__).with_name("_fake_mcp_server.py"))]

    async def go():
        async with mcp_session(server, tmp_path / "data") as s:
            err, opened = await call(s, "target_open", target_path=str(target), manifest_path=str(manifest))
            assert not err, opened
            return await call(s, "emulate", function=hex(B64 + 0x1000), args=[{"hex": ENC.hex()}, len(ENC)],
                              outputs=[{"arg": 0, "length": len(ENC), "view": "ascii"}])
    err, r = asyncio.run(go())
    assert not err, r
    assert r["evidence_id"].startswith("ev_") and r["deterministic"] and '"kernel32.dll"' in r["content"]


def test_worker_runs_at_low_integrity_and_cannot_write_or_spawn(tmp_path):
    """Real worker process (no emulation): Low integrity, no file in a normal (Medium) folder such as the test's temp
    folder or the repository, no child process (one-process job). A folder explicitly labelled Low is the control."""
    import subprocess
    from pathlib import Path

    from redharness.emulate.harden import LOW_RID
    from redharness.emulate.host import probe_worker
    repo = Path(__file__).resolve().parents[2]
    for d in (tmp_path, repo):
        r = probe_worker(str(d))
        assert r["integrity_rid"] == LOW_RID
        assert r["file_created"] is False and "Permission" in r["file_error"]
        assert r["child_started"] is False
        assert not (d / "rh_emulate_probe.txt").exists()
    low = tmp_path / "low"
    low.mkdir()
    subprocess.run(["icacls", str(low), "/setintegritylevel", "L"], check=True, capture_output=True)
    assert probe_worker(str(low))["file_created"] is True      # the write probe itself works where Low may write
