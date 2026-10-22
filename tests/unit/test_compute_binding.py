"""compute input binding (verifier version 11): explicit `{evidence_id, select}` ranges of read_bytes evidence, auto-binding of
pasted literals that EXACTLY equal a read_bytes region, and the verifier treating both alike.

Fake sandbox only (see test_compute.py); the target is a synthetic PE so that `read_bytes` evidence is real.
"""
import hashlib

import pytest

from redharness.config import Config
from redharness.evidence import compute as compute_ev
from redharness.evidence.model import ISOLATED
from redharness.mcp.session import Hub, ToolFailure
from redharness.compute.runtime import install_runtime

from ._fake_engine import FakeEngine
from ._fake_sandbox import FakeSandbox
from ._pe_builder import build_pe
from .mcp_helpers import make_manifest
from .test_compute import FNV_CODE, _fnv, fake_runtime_zip, python_guest, static_ev, fnv_inputs  # noqa: F401
from .test_compute import _short_sandbox_waits  # noqa: F401  (autouse fixture)
from .test_run_controlled_mcp import fake_system_root

BASE = 0x140000000
DATA_VA = BASE + 0x3030          # .data (RVA 0x3000) + 0x30: where the builder puts the marker


def marker(seed: int, n: int = 125) -> bytes:
    return bytes((i * seed + 11) % 256 for i in range(n))


def pe_hub(tmp_path, mk: bytes):
    tmp_path.mkdir(parents=True, exist_ok=True)
    target = tmp_path / "t.exe"
    target.write_bytes(build_pe(True, data_marker=mk))
    manifest = make_manifest(tmp_path / "scope.json", target, allowed_operations=["static", "compute"])
    cfg = Config.load(tmp_path / "data")
    hub = Hub(cfg, FakeEngine(), FakeSandbox(behavior=python_guest), system_root=fake_system_root(tmp_path / "win"))
    zp, spec = fake_runtime_zip(tmp_path)
    hub.compute_runtime_spec = spec
    install_runtime(cfg, zp, spec)
    hub.target_open(str(target), str(manifest))
    return hub


@pytest.fixture
def ph(tmp_path):
    mk = marker(37)
    h = pe_hub(tmp_path / "a", mk)
    yield h, mk
    h.close()


def read_marker(h, length=125, offset=0x30) -> str:
    return h.read_bytes(section=".data", offset=offset, length=length)["evidence_id"]


SHA_CODE = "import hashlib\nprint(hashlib.sha256(INPUTS['blob']).hexdigest())"
# the packer shape: keystream s = 33*s + 7 from seed 90 XORed over the payload, then SHA-256
PACKER_CODE = """
import hashlib
s = 90
out = bytearray()
for b in INPUTS['blob']:
    out.append(b ^ (s & 0xff))
    s = (33 * s + 7) & 0xffffffff
print(hashlib.sha256(bytes(out)).hexdigest())
"""
PACKER_STATIC = b"void unpack(uint8_t *p, int n) {\n  uint32_t s = 90;\n  for (i = 0; i < n; i++) { p[i] ^= s; s = 33 * s + 7; }\n}\n"


def packer_digest(mk: bytes) -> str:
    s, out = 90, bytearray()
    for b in mk:
        out.append(b ^ (s & 0xFF))
        s = (33 * s + 7) & 0xFFFFFFFF
    return hashlib.sha256(bytes(out)).hexdigest()


def ver(h, r) -> dict:
    return h._s.ledger.state["claims"][r["claim_id"]]["verification"]


def codes(v) -> list[str]:
    return [i["code"] for i in v["issues"]]


def rec_of(h, out) -> dict:
    return h._s.ledger.state["evidence"][out["evidence_id"]]


# ---------------------------------------------------------------- 1. explicit evidence-bound input
def test_explicit_select_hands_the_ledger_bytes_to_the_code(ph):
    h, mk = ph
    ev = read_marker(h)
    out = h.compute(SHA_CODE, [{"name": "blob", "evidence_id": ev, "select": {"offset": 0, "length": 125}}])
    assert hashlib.sha256(mk).hexdigest() in out["output"] and "warnings" not in out
    b = rec_of(h, out)["parameters"]["inputs"][0]
    assert (b["kind"], b["evidence_id"], b["va"], b["bytes"], b["auto"]) == ("range", ev, DATA_VA, 125, False)
    assert b["sha256"] == hashlib.sha256(mk).hexdigest() and rec_of(h, out)["evidence_links"] == [ev]
    # name optional (in0), select optional for a one-segment dump, sub-range by offset or by address
    o2 = h.compute("print(len(INPUTS['in0']))", [{"evidence_id": ev}])
    assert "125" in o2["output"]
    sub = h.compute("print(INPUTS['in0'].hex())", [{"evidence_id": ev, "select": {"offset": 5, "length": 10}}])
    assert mk[5:15].hex() in sub["output"]
    sub2 = h.compute("print(INPUTS['in0'].hex())",
                     [{"evidence_id": ev, "select": {"address": hex(DATA_VA + 5), "length": 10}}])
    assert mk[5:15].hex() in sub2["output"]


def test_select_errors_are_explicit_and_run_nothing(ph):
    h, _ = ph
    ev = read_marker(h)
    dec = static_ev(h)
    started = len(h.sandbox_backend.started)
    cases = [
        ([{"evidence_id": ev, "select": {"offset": 0, "length": 126}}], "COMPUTE_INPUT_NOT_IN_RAW"),
        ([{"evidence_id": ev, "select": {"offset": 125, "length": 1}}], "COMPUTE_INPUT_NOT_IN_RAW"),
        ([{"evidence_id": ev, "select": {"offset": 0}}], "BAD_ARGUMENT"),
        ([{"evidence_id": ev, "select": {"offset": 0, "address": "0x1", "length": 1}}], "BAD_ARGUMENT"),
        ([{"evidence_id": ev, "select": {"offset": 0, "length": 1}, "raw": True}], "BAD_ARGUMENT"),
        ([{"evidence_id": dec, "select": {"offset": 0, "length": 4}}], "COMPUTE_INPUT_NOT_BYTES"),
        ([{"evidence_id": "ev_" + "0" * 64, "select": {"offset": 0, "length": 4}}], "COMPUTE_INPUT_UNKNOWN_EVIDENCE"),
        ([{"hex": "abcd", "evidence_id": ev}], "BAD_ARGUMENT"),
        ([{"hex": "abc"}], "BAD_ARGUMENT"),
    ]
    for inputs, code in cases:
        with pytest.raises(ToolFailure) as e:
            h.compute("print(1)", inputs)
        assert e.value.code == code, inputs
    assert len(h.sandbox_backend.started) == started
    # non-read_bytes evidence without select behaves as raw
    o = h.compute("print(len(INPUTS['in0']))", [{"evidence_id": dec}])
    assert o["inputs"][0]["kind"] == "raw"


def test_dump_region_parsing_is_exact(ph):
    h, _ = ph
    r = h.read_bytes(rva="0x10F0", length=0x20)   # end of .text + unmapped gap: one FILE segment
    ev = r["evidence_id"]
    assert h.compute("print(len(INPUTS['in0']))", [{"evidence_id": ev}])["status"] == "OK"
    # region parsing is exact: rows must be contiguous and the header length must match
    rec = h._s.ledger.state["evidence"][ev]
    raw = h._s.cas.get(rec["raw"]["blob_sha256"])
    regs = compute_ev.dump_regions(rec, raw)
    assert len(regs) == 1 and len(regs[0][1]) == 0x10
    broken = raw.replace(b"0x1400010f0:", b"0x1400010f4:", 1)
    assert compute_ev.dump_regions(rec, broken) == []


# ---------------------------------------------------------------- 2. auto-binding of pasted literals
def test_pasted_literal_equal_to_read_bytes_auto_binds_and_claim_is_supported(ph):
    h, mk = ph
    ev = read_marker(h)
    dec = static_ev(h, PACKER_STATIC, "unpack")
    out = h.compute(PACKER_CODE.replace("INPUTS['blob']", "INPUTS['p']"), [{"name": "p", "hex": mk.hex()}])
    b = rec_of(h, out)["parameters"]["inputs"][0]
    assert (b["kind"], b["evidence_id"], b["va"], b["bytes"], b["auto"]) == ("range", ev, DATA_VA, 125, True)
    assert out["inputs"][0]["auto"] is True and any("auto-bound" in w for w in out["warnings"])
    assert rec_of(h, out)["evidence_links"] == [ev]
    digest = packer_digest(mk)
    assert digest in out["output"]
    r = h.claim_add(f"The payload digest after the 33*s+7 keystream from seed 90 is `{digest}`.", [ev, out["evidence_id"], dec],
                    None, "observation", "present", "SUPPORTED", [{"value": digest, "derived": True}])
    assert r["status"] == "SUPPORTED", r
    v = [x for x in ver(h, r)["values"] if x["value"] == digest][0]
    assert v["supported"] is True and v["support"] == "computation"
    assert {"code": "COMPUTE", "ok": True} in ver(h, r)["checks"]
    assert h.report_build()["counts"]["unsupported_claims"] == 0   # still SUPPORTED on re-verification


def test_dump_style_hex_with_separators_binds_too(ph):
    h, mk = ph
    ev = read_marker(h)
    spaced = "_".join(mk[i:i + 4].hex() for i in range(0, len(mk), 4))
    out = h.compute("print(len(INPUTS['x']))", [{"name": "x", "hex": spaced.upper().replace("_", " _ ")}])
    assert out["inputs"][0]["evidence_id"] == ev and out["inputs"][0]["auto"] is True


def test_explicit_and_auto_bound_inputs_verify_alike(ph):
    h, mk = ph
    ev = read_marker(h)
    dec = static_ev(h, PACKER_STATIC, "unpack")
    digest = packer_digest(mk)
    res = []
    for spec in ({"name": "blob", "evidence_id": ev, "select": {"offset": 0, "length": 125}},
                 {"name": "blob", "hex": mk.hex()}):
        out = h.compute(PACKER_CODE, [spec])
        r = h.claim_add(f"Digest `{digest}` of the unpacked payload.", [ev, out["evidence_id"], dec], None,
                        "observation", "present", "SUPPORTED", [{"value": digest, "derived": True}])
        res.append((r["status"], {k: ver(h, r)[k] for k in ("checks", "issues", "values")}))
        # the record validates the same way (bytes re-derived from the evidence, SHA-256 compared)
        assert compute_ev.validate_record(rec_of(h, out), h._s.cas.get(rec_of(h, out)["raw"]["blob_sha256"]),
                                          h._s.ledger.state["evidence"], h._s.cas, ISOLATED) == []
    assert res[0] == res[1] and res[0][0] == "SUPPORTED"


def test_auto_bound_input_still_needs_its_evidence_cited(ph):
    h, mk = ph
    ev = read_marker(h)
    dec = static_ev(h, PACKER_STATIC, "unpack")
    out = h.compute(PACKER_CODE, [{"name": "blob", "hex": mk.hex()}])
    digest = packer_digest(mk)
    r = h.claim_add(f"Digest `{digest}`.", [dec, out["evidence_id"]], None, "observation", "present", "SUPPORTED",
                    [{"value": digest, "derived": True}])
    assert r["status"] == "UNVERIFIED" and "VALUE_COMPUTE_NOT_BOUND" in codes(ver(h, r))


# ---------------------------------------------------------------- 3. no binding without an exact match
def test_literal_with_one_changed_byte_does_not_bind(ph):
    h, mk = ph
    ev = read_marker(h)
    dec = static_ev(h, PACKER_STATIC, "unpack")
    bad = bytearray(mk)
    bad[60] ^= 1
    out = h.compute(PACKER_CODE, [{"name": "blob", "hex": bytes(bad).hex()}])
    b = rec_of(h, out)["parameters"]["inputs"][0]
    assert (b["kind"], b["evidence_id"], b["authority"]) == ("literal", None, None) and "va" not in b
    assert b["sha256"] == hashlib.sha256(bytes(bad)).hexdigest() and rec_of(h, out)["evidence_links"] == []
    assert any("UNBOUND" in w for w in out["warnings"]) and any("NOT bound" in w for w in out["warnings"])
    digest = packer_digest(bytes(bad))
    r = h.claim_add(f"Digest `{digest}`.", [ev, out["evidence_id"], dec], None, "observation", "present", "SUPPORTED",
                    [{"value": digest, "derived": True}])
    assert r["status"] == "UNVERIFIED" and "VALUE_COMPUTE_NOT_BOUND" in codes(ver(h, r))
    # the record itself is valid (not REJECTED): an unbound literal is honest, it just binds nothing
    assert compute_ev.validate_record(rec_of(h, out), h._s.cas.get(rec_of(h, out)["raw"]["blob_sha256"]),
                                      h._s.ledger.state["evidence"], h._s.cas, ISOLATED) == []


def test_partial_short_or_mixed_literals_do_not_bind(ph):
    h, mk = ph
    ev = read_marker(h)
    for hx in (mk[:3].hex(), (mk + b"\x00").hex(), (b"\x00" + mk).hex(), (mk[:20] + mk[22:40]).hex()):
        out = h.compute("print(1)", [{"hex": hx}])
        assert out["inputs"][0]["kind"] == "literal", hx
    # a sub-range of at least 4 bytes that IS contiguous in the dump does bind (exact region match, not whole-dump match)
    out = h.compute("print(1)", [{"hex": mk[20:40].hex()}])
    assert out["inputs"][0]["evidence_id"] == ev and out["inputs"][0]["va"] == DATA_VA + 20
    # one bound input and one unbound literal: the whole computation is unbound
    dec = static_ev(h, PACKER_STATIC, "unpack")
    out = h.compute("print(1234)", [{"name": "a", "hex": mk[:8].hex()}, {"name": "b", "hex": "00112233445566"}])
    r = h.claim_add("Value `1234`.", [ev, out["evidence_id"], dec], None, "observation", "present", "SUPPORTED",
                    [{"value": "1234", "derived": True}])
    assert r["status"] == "UNVERIFIED" and "VALUE_COMPUTE_NOT_BOUND" in codes(ver(h, r))


def test_literal_from_another_targets_evidence_does_not_bind(tmp_path):
    mk_a, mk_b = marker(37), marker(91)
    ha, hb = pe_hub(tmp_path / "a", mk_a), pe_hub(tmp_path / "b", mk_b)
    try:
        read_marker(ha)
        evb = read_marker(hb)
        assert ha._s.sha != hb._s.sha
        # B's bytes pasted into job A: B's evidence is not in A's ledger
        out = ha.compute("print(1)", [{"name": "x", "hex": mk_b.hex()}])
        assert out["inputs"][0]["kind"] == "literal" and out["inputs"][0]["evidence_id"] is None
        # even if B's record is smuggled into A's ledger state, the subject check refuses it
        recb = hb._s.ledger.state["evidence"][evb]
        ha._s.cas.put(hb._s.cas.get(recb["raw"]["blob_sha256"]))
        ha._s.ledger.state["evidence"][evb] = recb
        out = ha.compute("print(2)", [{"name": "x", "hex": mk_b.hex()}])
        assert out["inputs"][0]["kind"] == "literal"
        with pytest.raises(ToolFailure) as e:
            ha.compute("print(3)", [{"name": "x", "evidence_id": evb, "select": {"offset": 0, "length": 8}}])
        assert e.value.code == "COMPUTE_INPUT_UNKNOWN_EVIDENCE"
    finally:
        ha.close()
        hb.close()


def test_literal_equal_to_non_dump_evidence_text_does_not_bind(ph):
    h, _ = ph
    read_marker(h)
    dec = static_ev(h, PACKER_STATIC, "unpack")
    out = h.compute("print(1)", [{"hex": PACKER_STATIC[:16].hex()}])   # exact bytes of a decompile text: use quote/raw for that
    assert out["inputs"][0]["kind"] == "literal" and dec not in str(out["inputs"])


def test_code_embedded_bytes_stay_unbound_as_before(ph):
    """Failure mode: bytes pasted INTO the code with inputs=[]: unbound, the claim stays UNVERIFIED."""
    h, mk = ph
    ev = read_marker(h)
    dec = static_ev(h, PACKER_STATIC, "unpack")
    code = f"INPUTS = {{'blob': bytes.fromhex('{mk.hex()}')}}\n" + PACKER_CODE
    out = h.compute(code, [])
    assert rec_of(h, out)["parameters"]["inputs"] == [] and any("NOT bound" in w for w in out["warnings"])
    digest = packer_digest(mk)
    r = h.claim_add(f"Digest `{digest}`.", [ev, out["evidence_id"], dec], None, "observation", "present", "SUPPORTED",
                    [{"value": digest, "derived": True}])
    assert r["status"] == "UNVERIFIED" and "VALUE_COMPUTE_NOT_BOUND" in codes(ver(h, r))


# ---------------------------------------------------------------- 4. packer-xor scenario replay (fakes) and old records
def test_packer_scenario_replay_reaches_supported_with_explicit_and_pasted_input(ph):
    h, mk = ph
    ev = read_marker(h)                                    # the 125 packed bytes (read_bytes)
    dec = static_ev(h, PACKER_STATIC, "unpack")            # the decompiled stub: seed 90, 33*s+7
    digest = packer_digest(mk)
    for spec in ({"name": "blob", "hex": mk.hex()},        # what the model did, but as an input
                 {"name": "blob", "evidence_id": ev, "select": {"offset": 0, "length": 125}}):   # the easy path
        out = h.compute(PACKER_CODE, [spec])
        r = h.claim_add(f"The computation over the payload and keystream (seed 90, s = 33 * s + 7) gives `{digest}`.",
                        [out["evidence_id"], ev, dec], None, "observation", "present", "SUPPORTED",
                        [{"value": digest, "derived": True}])
        assert r["status"] == "SUPPORTED", (spec, r)
        assert "VALUE_COMPUTE_NOT_BOUND" not in codes(ver(h, r))


def test_old_kinds_keep_their_record_shape_and_verdict_in_version_11(ph):
    h, _ = ph
    ev = static_ev(h)
    out = h.compute(FNV_CODE, fnv_inputs(ev), 20)
    ins = rec_of(h, out)["parameters"]["inputs"]
    assert [sorted(b) for b in ins] == [["authority", "bytes", "const", "evidence_id", "kind", "name", "sha256"],
                                        ["authority", "bytes", "evidence_id", "kind", "name", "quote", "sha256"]]
    val = str(_fnv(b"RH-PREFIX-"))
    r = h.claim_add(f"The computation over the prefix quoted in main gives `{val}`.", [ev, out["evidence_id"]], None, "observation",
                    "present", "SUPPORTED", [{"value": val, "derived": True}])
    assert r["status"] == "SUPPORTED"
    body = {k: ver(h, r)[k] for k in ("checks", "issues", "values")}
    # a record verified by version 10 is re-verified by 11 with the same checks/issues/values
    h._s.ledger.state["claims"][r["claim_id"]]["verification"]["verifier_version"] = "11"
    again = h._s.ledger.reverify(r["claim_id"]).to_record()
    assert again["verifier_version"] == "24" and {k: again[k] for k in body} == body
