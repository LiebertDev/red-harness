"""The `compute` tool: scope (default deny), pinned interpreter, limits, determinism, evidence binding, verifier semantics.

A real Windows Sandbox is NOT opened: the fake sandbox (tests/unit/_fake_sandbox.py) imitates the guest contract and runs the real
bootstrap (compute/rh_boot.py) with the host's test Python as the "target". The only code that runs is the test code in this file.
Real sandbox path: tests/heavy/test_compute_real.py (real_sandbox, UNVERIFIED).
"""
import hashlib
import subprocess
import sys
import zipfile

import pytest

from redharness.compute import runtime as crt
from redharness.compute.runtime import RuntimeMissing, RuntimeSpec, install_runtime, load_runtime
from redharness.config import Config
from redharness.core.result import Status
from redharness.evidence import compute as compute_ev
from redharness.evidence.model import COMPUTE_AUTHORITY, ISOLATED, build_evidence
from redharness.mcp.effects import EffectDenied, check_permission
from redharness.mcp.session import Hub, ToolFailure
from redharness.scope.manifest import ScopeManifest

from ._fake_engine import FakeEngine
from ._fake_sandbox import FakeSandbox
from .mcp_helpers import make_manifest
from .test_run_controlled_mcp import fake_system_root, oracle

STATIC_TEXT = (b"int main() {\n  uint32_t h = 0x811c9dc5; // FNV offset\n  const char *key = \"RH-PREFIX-\";\n"
               b"  if (fnv1a(buf) == 0x2f8c5b11) puts(\"ok\");\n}\n")
FNV_CODE = """
h = INPUTS['basis']
for b in INPUTS['key']:
    h = ((h ^ b) * 0x01000193) & 0xffffffff
print(h)
"""


def _fnv(data: bytes, h: int = 0x811C9DC5) -> int:
    for b in data:
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h


@pytest.fixture(autouse=True)
def _short_sandbox_waits(monkeypatch):
    from redharness.sandbox import runner
    for name, v in (("BOOT_ALLOWANCE_S", 5.0), ("PER_CASE_OVERHEAD_S", 2.0), ("FINISH_SLACK_S", 1.0),
                    ("RETRY_BACKOFF_S", 0.0)):
        monkeypatch.setattr(runner, name, v)


def python_guest(idx, spec_case, stdin: bytes) -> dict:
    """The fake guest's "target": on a compute call runs the bootstrap in a real process (the timeout is real)."""
    if "rh_boot.py" not in spec_case["argv_line"]:
        return oracle(idx, spec_case, stdin)
    assert spec_case["argv_line"] == "-I -B -X utf8 rh_boot.py"
    try:
        r = subprocess.run([sys.executable, "-I", "-B", "-X", "utf8", str(crt.BOOT_SOURCE)], input=stdin,
                           capture_output=True, timeout=spec_case["timeout_s"])
    except subprocess.TimeoutExpired as e:
        return {"stdout": e.stdout or b"", "stderr": e.stderr or b"", "exit_code": None, "timed_out": True}
    return {"stdout": r.stdout, "stderr": r.stderr, "exit_code": r.returncode}


def fake_runtime_zip(tmp_path):
    files = {"python.exe": b"MZ-fake-python", "python312.dll": b"fake-dll", "python312._pth": b"python312.zip\n.\n"}
    zp = tmp_path / "fake-embed.zip"
    with zipfile.ZipFile(zp, "w") as z:
        for n, b in files.items():
            z.writestr(n, b)
        z.writestr("_socket.pyd", b"not-staged")
    spec = RuntimeSpec("test-cpython-embed", zp.name, hashlib.sha256(zp.read_bytes()).hexdigest(), "file://none",
                       "python.exe", {n: hashlib.sha256(b).hexdigest() for n, b in files.items()})
    return zp, spec


def make_hub(tmp_path, ops=("static", "compute"), install=True, behavior=python_guest):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"MZ" + bytes(range(256)) * 8)
    manifest = make_manifest(tmp_path / "scope.json", target, allowed_operations=list(ops))
    sb = FakeSandbox(behavior=behavior)
    cfg = Config.load(tmp_path / "data")
    hub = Hub(cfg, FakeEngine(), sb, system_root=fake_system_root(tmp_path / "win"))
    zp, spec = fake_runtime_zip(tmp_path)
    hub.compute_runtime_spec = spec
    if install:
        install_runtime(cfg, zp, spec)
    hub.target_open(str(target), str(manifest))
    return hub, sb, spec


def static_ev(hub, raw: bytes = STATIC_TEXT, fn: str = "main") -> str:
    s = hub._s
    rec = build_evidence(s.cas, subject_sha256=s.sha, tool="decompile", operation="decompile", raw=raw,
                         status=Status.OK, confidence="observed", authority="shipped-artifact",
                         parameters={"function": fn})
    return s.ledger.record_evidence(rec)["evidence_id"]


def fnv_inputs(ev: str) -> list[dict]:
    return [{"name": "basis", "evidence_id": ev, "const": "0x811c9dc5"},
            {"name": "key", "evidence_id": ev, "quote": "RH-PREFIX-"}]


def n_evidence(hub) -> int:
    return len(hub._s.ledger.state["evidence"])


@pytest.fixture
def ch(tmp_path):
    h, sb, spec = make_hub(tmp_path)
    yield h, sb
    h.close()


# ---------------------------------------------------------------- scope / effect: default DENY
def test_compute_denied_by_default_scope_and_sandbox_untouched(tmp_path):
    h, sb, _ = make_hub(tmp_path, ops=("static", "run_controlled"))
    try:
        with pytest.raises(ToolFailure) as e:
            h.call("compute", {}, lambda: h.compute("print(1)"))
        assert e.value.code == "SCOPE_DENIED" and "compute" in e.value.message
        assert sb.started == []
    finally:
        h.close()


def test_effect_table_compute_needs_its_own_operation():
    def man(*ops):
        return ScopeManifest("a" * 64, "t", "owner", "s", ("static",) + ops, None, "")
    for ops in ((), ("run_controlled",), ("patch_poc",), ("run_controlled", "patch_poc")):
        with pytest.raises(EffectDenied):
            check_permission("compute", man(*ops))
    check_permission("compute", man("compute"))
    with pytest.raises(EffectDenied):  # the compute permission does NOT grant permission to run the target
        check_permission("run_controlled", man("compute"))


# ---------------------------------------------------------------- interpreter: pinned digest
def test_runtime_install_rejects_wrong_zip_and_detects_tamper(tmp_path):
    cfg = Config.load(tmp_path / "d")
    zp, spec = fake_runtime_zip(tmp_path)
    bad = RuntimeSpec(spec.runtime_id, spec.zip_name, "0" * 64, spec.url, spec.exe, spec.files)
    with pytest.raises(RuntimeMissing):
        install_runtime(cfg, zp, bad)
    assert not crt.runtime_dir(cfg, bad).exists()
    root = install_runtime(cfg, zp, spec)
    rt = load_runtime(cfg, spec)
    assert not (root / "_socket.pyd").exists()  # only the listed files are staged
    assert {p.name for p in rt.files} == set(spec.files) | {"rh_boot.py"}
    (root / "python312.dll").write_bytes(b"evil")
    with pytest.raises(RuntimeMissing, match="python312.dll"):
        load_runtime(cfg, spec)


def test_pinned_runtime_is_a_hashed_closed_file_set():
    p = crt.PINNED
    assert len(p.zip_sha256) == 64 and p.url.startswith("https://www.python.org/ftp/python/3.12.10/")
    assert p.exe in p.files and "python312.zip" in p.files
    for banned in ("_socket.pyd", "_ssl.pyd", "select.pyd", "_ctypes.pyd", "_multiprocessing.pyd", "_hashlib.pyd"):
        assert banned not in p.files


def test_missing_runtime_is_an_explicit_error_and_runs_nothing(tmp_path):
    h, sb, _ = make_hub(tmp_path, install=False)
    try:
        with pytest.raises(ToolFailure) as e:
            h.compute("print(1)")
        assert e.value.code == "COMPUTE_RUNTIME_MISSING" and sb.started == []
    finally:
        h.close()


# ---------------------------------------------------------------- success + evidence + rerun equality
def test_compute_records_derived_evidence_bound_to_inputs(ch):
    h, sb = ch
    ev = static_ev(h)
    out = h.call("compute", {}, lambda: h.compute(FNV_CODE, fnv_inputs(ev), 20))
    want = str(_fnv(b"RH-PREFIX-"))
    assert out["status"] == "OK" and out["deterministic"] is True and out["runs"] == 2
    assert want in out["output"] and out["untrusted_content"] is True
    rec = h._s.ledger.state["evidence"][out["evidence_id"]]
    assert rec["authority"] == COMPUTE_AUTHORITY and rec["confidence"] == "derived"
    assert rec["environment"]["isolation"] in ISOLATED and rec["environment"]["networking"] == "disabled"
    assert rec["coverage"]["relationship"] == "unknown" and rec["evidence_links"] == [ev]
    p = rec["parameters"]
    assert h._s.cas.get(p["code_sha256"]).decode() == FNV_CODE  # the code was stored: it can be re-run
    assert [(b["name"], b["kind"], b["evidence_id"]) for b in p["inputs"]] == [("basis", "const", ev), ("key", "quote", ev)]
    assert p["inputs"][1]["sha256"] == hashlib.sha256(b"RH-PREFIX-").hexdigest()
    assert p["runtime"]["id"] == "test-cpython-embed" and p["runs"] == 2
    assert h._s.cas.get(rec["raw"]["blob_sha256"]).decode().strip() == want
    # two cases, same stdin, fixed argv; staged files: interpreter + bootstrap
    spec = sb.seen_specs[-1]
    assert spec["exe"] == "python.exe" and len(spec["cases"]) == 2
    assert spec["cases"][0]["stdin_b64"] == spec["cases"][1]["stdin_b64"]
    assert spec["max_stream_bytes"] == 64 * 1024
    assert "<Networking>Disable</Networking>" in sb.seen_wsb[-1]


def test_rerun_gives_the_same_evidence_id(ch):
    h, sb = ch
    ev = static_ev(h)
    a = h.compute(FNV_CODE, fnv_inputs(ev), 20)
    n = n_evidence(h)
    b = h.compute(FNV_CODE, fnv_inputs(ev), 20)
    assert a["evidence_id"] == b["evidence_id"] and n_evidence(h) == n and len(sb.started) == 2


def test_raw_input_passes_the_whole_evidence_output(ch):
    h, _ = ch
    ev = static_ev(h)
    out = h.compute("import hashlib\nprint(hashlib.sha256(INPUTS['src']).hexdigest(), len(INPUTS['src']))",
                    [{"name": "src", "evidence_id": ev, "raw": True}])
    assert f"{hashlib.sha256(STATIC_TEXT).hexdigest()} {len(STATIC_TEXT)}" in out["output"]


# ---------------------------------------------------------------- limits: timeout, output, error, determinism
def test_timeout_is_an_explicit_error_never_a_result(ch):
    h, _ = ch
    n = n_evidence(h)
    with pytest.raises(ToolFailure) as e:
        h.call("compute", {}, lambda: h.compute("while True:\n    pass\n", None, 1))
    assert e.value.code == "COMPUTE_TIMEOUT" and "never a result" in e.value.message
    assert n_evidence(h) == n


def test_output_over_cap_is_rejected(ch):
    h, _ = ch
    n = n_evidence(h)
    with pytest.raises(ToolFailure) as e:
        h.compute("print('x' * 70000)")
    assert e.value.code == "OUTPUT_LIMIT" and n_evidence(h) == n


def test_exception_returns_traceback_without_evidence(ch):
    h, _ = ch
    n = n_evidence(h)
    with pytest.raises(ToolFailure) as e:
        h.compute("raise ValueError('table index out of range')")
    assert e.value.code == "COMPUTE_ERROR" and "table index out of range" in e.value.message
    assert n_evidence(h) == n


def test_nondeterministic_code_is_rejected(ch):
    h, _ = ch
    n = n_evidence(h)
    with pytest.raises(ToolFailure) as e:
        h.compute("import os\nprint(os.urandom(16).hex())")
    assert e.value.code == "NONDETERMINISTIC" and n_evidence(h) == n


def test_random_is_seeded_so_seeded_code_is_deterministic(ch):
    h, _ = ch
    out = h.compute("import random\nprint(random.randrange(10**12))")
    assert out["deterministic"] is True


@pytest.mark.parametrize("args,code", [
    (("",), "BAD_ARGUMENT"),
    (("x = 1\n" * 20000,), "BAD_ARGUMENT"),
    (("print(1)", None, 0), "BAD_ARGUMENT"),
    (("print(1)", None, 301), "BAD_ARGUMENT"),
    (("print(1)", [{"name": f"i{i}", "evidence_id": "ev_x", "raw": True} for i in range(9)]), "BAD_ARGUMENT"),
])
def test_bad_arguments_are_refused_before_the_sandbox(ch, args, code):
    h, sb = ch
    with pytest.raises(ToolFailure) as e:
        h.compute(*args)
    assert e.value.code == code and sb.started == []


# ---------------------------------------------------------------- input binding
def test_inputs_must_come_from_this_jobs_evidence(ch):
    h, sb = ch
    ev = static_ev(h)
    cases = [
        ({"name": "a", "evidence_id": "ev_" + "0" * 64, "raw": True}, "COMPUTE_INPUT_UNKNOWN_EVIDENCE"),
        ({"name": "a", "evidence_id": ev, "quote": "not in the output"}, "COMPUTE_INPUT_NOT_IN_RAW"),
        ({"name": "a", "evidence_id": ev, "const": "0x12345678"}, "COMPUTE_INPUT_NOT_IN_RAW"),
        ({"name": "a", "evidence_id": ev, "quote": "RH-PREFIX-", "raw": True}, "BAD_ARGUMENT"),
        ({"name": "1bad", "evidence_id": ev, "raw": True}, "BAD_ARGUMENT"),
    ]
    for spec, code in cases:
        with pytest.raises(ToolFailure) as e:
            h.compute("print(1)", [spec])
        assert e.value.code == code, spec
    out = h.compute("print(1)", [{"name": "a", "evidence_id": ev, "raw": True}])
    with pytest.raises(ToolFailure) as e:  # a computation's output cannot be the input of a new computation
        h.compute("print(1)", [{"name": "a", "evidence_id": out["evidence_id"], "raw": True}])
    assert e.value.code == "COMPUTE_INPUT_NOT_ALLOWED"
    assert len(sb.started) == 1


# ---------------------------------------------------------------- verifier semantics (version 7)
def ver(h, r) -> dict:
    return h._s.ledger.state["claims"][r["claim_id"]]["verification"]


def _computed(h):
    ev = static_ev(h)
    out = h.compute(FNV_CODE, fnv_inputs(ev), 20)
    return ev, out["evidence_id"], str(_fnv(b"RH-PREFIX-"))


def test_observation_with_bound_compute_is_supported_at_most(ch):
    h, _ = ch
    ev, cev, val = _computed(h)
    r = h.claim_add(f"The computation over the prefix quoted in main gives `{val}`.", [ev, cev], None, "observation",
                    "present", "PROVEN", [{"value": val, "derived": True}])
    assert r["status"] == "SUPPORTED"
    v = [x for x in ver(h, r)["values"] if x["value"] == val][0]
    assert v["supported"] is True and v["support"] == "computation"
    assert "PROVEN_STATIC_CLAIM" in [i["code"] for i in ver(h, r)["issues"]]
    assert {"code": "COMPUTE", "ok": True} in ver(h, r)["checks"]
    assert ver(h, r)["verifier_version"] == "24"
    rep = h.report_build()  # stays SUPPORTED on re-verification too
    assert rep["counts"]["unsupported_claims"] == 0


def test_compute_alone_is_rejected(ch):
    h, _ = ch
    _, cev, val = _computed(h)
    r = h.claim_add(f"The computed FNV value is `{val}`.", [cev], None, "observation", "present", "SUPPORTED",
                    [{"value": val, "derived": True}])
    assert r["status"] == "REJECTED" and "COMPUTE_ONLY" in [i["code"] for i in r["issues"]]


def test_unbound_compute_does_not_back_a_value(ch):
    h, _ = ch
    _, cev, val = _computed(h)
    other = static_ev(h, b"void other(void) { return; }\n", "other")
    r = h.claim_add(f"The computed FNV value is `{val}`.", [other, cev], None, "observation", "present",
                    "SUPPORTED", [{"value": val, "derived": True}])
    assert r["status"] == "UNVERIFIED"
    assert "VALUE_COMPUTE_NOT_BOUND" in [i["code"] for i in ver(h, r)["issues"]]
    # the same value as a 0x literal in the text: an unbound computation does not support it -> rejected per the existing rule
    r = h.claim_add(f"The computed FNV value is {hex(int(val))}.", [other, cev], None, "observation", "present")
    assert r["status"] == "REJECTED" and "HEX_LITERAL_UNSUPPORTED" in [i["code"] for i in r["issues"]]


def test_compute_never_backs_a_behavior_claim(ch):
    h, _ = ch
    ev, cev, val = _computed(h)
    r = h.claim_add(f"The correct key hash `{val}` is accepted by the program.", [ev, cev],
                    [{"type": "quote", "evidence_id": cev, "text": val}], "behavior", "present", "PROVEN",
                    [{"value": val, "derived": True}], behavior_class="ordinary")
    assert r["status"] == "UNVERIFIED"
    codes = [i["code"] for i in ver(h, r)["issues"]]
    assert "BEHAVIOR_NEEDS_EXECUTION" in codes and "PROVEN_NEEDS_CONTROLLED_REPLAY" in codes
    assert "VALUE_DERIVED_NEEDS_EXECUTION" in codes


def test_tampered_compute_record_is_rejected_by_the_verifier(ch):
    h, _ = ch
    ev, cev, _ = _computed(h)
    s = h._s
    rec = dict(s.ledger.state["evidence"][cev])
    raw = s.cas.get(rec["raw"]["blob_sha256"])
    ok = compute_ev.validate_record(rec, raw, s.ledger.state["evidence"], s.cas, ISOLATED)
    assert ok == []
    params = {**rec["parameters"], "inputs": [dict(b) for b in rec["parameters"]["inputs"]]}
    params["inputs"][1]["quote"] = "RH-PREFIX"   # different bytes, old digest
    bad = compute_ev.validate_record({**rec, "parameters": params}, raw, s.ledger.state["evidence"], s.cas, ISOLATED)
    assert "COMPUTE_INPUT_MISMATCH" in [c for c, _ in bad]
    assert "COMPUTE_NONDETERMINISTIC" in [c for c, _ in compute_ev.validate_record(
        {**rec, "result": {**rec["result"], "deterministic": False}}, raw, s.ledger.state["evidence"], s.cas, ISOLATED)]
    assert "COMPUTE_NOT_ISOLATED" in [c for c, _ in compute_ev.validate_record(
        rec, raw, s.ledger.state["evidence"], s.cas, frozenset({"virtual-machine"}))]


def test_compute_found_key_is_proven_only_by_run_controlled(tmp_path):
    """Flow: compute finds a candidate (an observation is at most SUPPORTED) -> run_controlled tries it on the target -> behavior PROVEN."""
    from .test_run_controlled_mcp import GOOD_KEY, WRONG_KEY, pair_atom
    h, _, _ = make_hub(tmp_path, ops=("static", "run_controlled", "compute"))
    try:
        ev = static_ev(h, b'char *k = "synthetic-input";\nint tail = 66;\n')
        out = h.compute("print(INPUTS['k'].decode() + '-' + str(INPUTS['t']))",
                        [{"name": "k", "evidence_id": ev, "quote": "synthetic-input"},
                         {"name": "t", "evidence_id": ev, "const": 66}])
        assert GOOD_KEY in out["output"]
        run = h.run_controlled([{"stdin": GOOD_KEY + "\n"}, {"stdin": WRONG_KEY + "\n"}], 5)
        rev, wrong = run["cases"][0]["evidence_id"], run["cases"][1]["evidence_id"]
        r = h.claim_add(f"The license key `{GOOD_KEY}` is accepted by the program.",
                        [rev, wrong, out["evidence_id"], ev],
                        [{"type": "quote", "evidence_id": rev, "text": "License valid"}, pair_atom(rev, wrong)],
                        "behavior", "present", "PROVEN", [{"value": GOOD_KEY, "derived": True}], behavior_class="ordinary")
        assert r["status"] == "PROVEN"
    finally:
        h.close()
