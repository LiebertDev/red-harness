"""Fix verification: the vendor rebuilds the product from source; the harness checks, with the evidence rules, that a
finding reproduces on the original build and not on the fixed build. Fake engine and fake Windows Sandbox (the real run is
tests/heavy/test_fix_verification_real.py). The harness never edits a binary: there is no patch tool.
"""
import hashlib
from pathlib import Path

import pytest

from redharness.config import Config
from redharness.mcp.server import MAX_TOOLS, TOOL_NAMES
from redharness.mcp.session import Hub, ToolFailure
from redharness.scope.manifest import ScopeError, parse_manifest

from ._fake_engine import FakeEngine
from ._fake_sandbox import FakeSandbox
from .mcp_helpers import make_manifest
from .test_run_controlled_mcp import _short_sandbox_waits, fake_system_root  # noqa: F401  (autouse fixture re-used)

GOOD_KEY = "synthetic-input-B"
ALT_KEY = "synthetic-input-A"
WRONG_KEY = "synthetic-input-C"
VALID, INVALID = "License valid", "License invalid"


class Builds:
    """Two different binaries; the fake guest behaves per staged binary (the original accepts ALT_KEY, the fixed does not)."""

    def __init__(self, tmp_path: Path, **sandbox_kw):
        self.orig = tmp_path / "product.bin"
        self.fixed = tmp_path / "product-fixed.bin"
        self.orig.write_bytes(b"MZ" + bytes(range(256)) * 8)
        self.fixed.write_bytes(b"MZ" + bytes(range(256)) * 8 + b"FIXED")
        self.orig_sha = hashlib.sha256(self.orig.read_bytes()).hexdigest()
        self.fixed_sha = hashlib.sha256(self.fixed.read_bytes()).hexdigest()
        self.manifest = make_manifest(tmp_path / "scope.json", self.orig, allowed_operations=["static", "run_controlled"],
                                      fixed_target_sha256=self.fixed_sha)
        self.fixed_behavior = sandbox_kw.pop("fixed_behavior", None)
        self.sb = FakeSandbox(behavior=self._behavior, **sandbox_kw)
        self.hub = Hub(Config.load(tmp_path / "data"), FakeEngine(), self.sb,
                       system_root=fake_system_root(tmp_path / "win"))

    def _behavior(self, idx, spec_case, stdin: bytes) -> dict:
        key = stdin.decode("utf-8", "replace").strip()
        if self.sb.current_sha == self.fixed_sha:
            if self.fixed_behavior:
                return self.fixed_behavior(key)
            ok = key == GOOD_KEY
        else:
            ok = key in (GOOD_KEY, ALT_KEY)
        return {"stdout": (VALID if ok else INVALID).encode() + b"\n", "stderr": b"", "exit_code": 0 if ok else 1}

    def open(self, fixed=True):
        return self.hub.target_open(str(self.orig), str(self.manifest), str(self.fixed) if fixed else None)

    def run(self, key, target):
        r = self.hub.call("run_controlled", {}, lambda: self.hub.run_controlled([{"stdin": key + "\n"}], 10, None,
                                                                                "summary", target))
        return r["cases"][0]["evidence_id"], r

    def claim(self, ev_o, ev_f, *, kind="fix_verification", oq=VALID, fq=INVALID, key=ALT_KEY, ids=None, requested="PROVEN"):
        atoms = [{"type": "fix_pair", "original": {"evidence_id": ev_o, "quote": oq},
                  "fixed": {"evidence_id": ev_f, "quote": fq}}]
        return self.hub.claim_add(f"The license key `{key}` is accepted by the original build and rejected by the fixed build.",
                                  ids if ids is not None else [ev_o, ev_f], atoms, kind, "present", requested,
                                  [{"value": key, "derived": True}])


@pytest.fixture
def b(tmp_path):
    x = Builds(tmp_path)
    yield x
    x.hub.close()


def codes(out):
    return [i["code"] for i in out["issues"]]


# ---------------------------------------------------------------- binding both builds
def test_target_open_binds_the_fixed_build_and_both_hashes(b):
    out = b.open()
    assert out["scope"]["fixed_target_sha256"] == b.fixed_sha and out["target_sha256"] == b.orig_sha
    assert out["fixed_build"]["bound"] is True and out["fixed_build"]["sha256"] == b.fixed_sha
    assert b.hub._s.cas.path_for(b.fixed_sha).is_file()   # the fixed binary is in the content store under its own hash


def test_open_without_fixed_path_keeps_target_fixed_unavailable(b):
    out = b.open(fixed=False)
    assert out["fixed_build"]["bound"] is False
    with pytest.raises(ToolFailure) as e:
        b.run(ALT_KEY, "fixed")
    assert e.value.code == "FIXED_BUILD_NOT_OPEN"


def test_fixed_path_without_manifest_hash_or_with_wrong_file_is_refused(tmp_path):
    x = Builds(tmp_path)
    plain = make_manifest(tmp_path / "plain.json", x.orig, allowed_operations=["static", "run_controlled"])
    with pytest.raises(ToolFailure) as e:
        x.hub.target_open(str(x.orig), str(plain), str(x.fixed))
    assert e.value.code == "SCOPE_DENIED" and "fixed_target_sha256" in e.value.message
    other = tmp_path / "other.bin"
    other.write_bytes(b"MZ-something-else")
    with pytest.raises(ToolFailure) as e:
        x.hub.target_open(str(x.orig), str(x.manifest), str(other))
    assert e.value.code == "SCOPE_DENIED" and "does not match" in e.value.message
    x.hub.close()


def test_manifest_fixed_hash_validation():
    base = {"schema": "rh.scope/1", "target_sha256": "a" * 64, "allowed_operations": ["static"],
            "authorization": {"declared_by": "x", "basis": "owner", "statement": "ours"}}
    assert parse_manifest({**base, "fixed_target_sha256": "b" * 64}).fixed_target_sha256 == "b" * 64
    assert parse_manifest(base).fixed_target_sha256 is None and "fixed_target_sha256" not in parse_manifest(base).to_summary()
    for bad in ("a" * 64, "XYZ", 5):
        with pytest.raises(ScopeError):
            parse_manifest({**base, "fixed_target_sha256": bad})


def test_run_controlled_target_argument_is_checked(b):
    b.open()
    with pytest.raises(ToolFailure) as e:
        b.hub.run_controlled([{"stdin": "x\n"}], 10, None, "summary", "patched")
    assert e.value.code == "BAD_ARGUMENT"
    with pytest.raises(ToolFailure) as e:
        b.hub.run_controlled([{"stdin": "x\n"}], 10, {"channels": ["api_trace"]}, "summary", "fixed")
    assert e.value.code == "BAD_ARGUMENT" and "original build only" in e.value.message
    assert not b.sb.started   # nothing ran on a refusal


def test_each_build_run_is_its_own_hash_bound_evidence(b):
    b.open()
    ev_o, ro = b.run(ALT_KEY, "original")
    ev_f, rf = b.run(ALT_KEY, "fixed")
    ev = b.hub._s.ledger.state["evidence"]
    assert ev[ev_o]["subject"]["sha256"] == b.orig_sha and ev[ev_f]["subject"]["sha256"] == b.fixed_sha
    assert ev[ev_f]["parameters"]["build"] == "fixed" and "build" not in ev[ev_o]["parameters"]
    assert ev_o != ev_f and len(b.sb.started) == 2     # two sandbox sessions, never mixed
    assert (ro["build"], rf["build"]) == ("original", "fixed") and rf["target_sha256"] == b.fixed_sha
    assert VALID not in rf["cases"][0]["content"] and INVALID in rf["cases"][0]["content"]
    assert VALID in ro["cases"][0]["content"]


# ---------------------------------------------------------------- the evidence rule
def test_both_builds_same_input_is_proven(b):
    b.open()
    ev_o, _ = b.run(ALT_KEY, "original")
    ev_f, _ = b.run(ALT_KEY, "fixed")
    out = b.claim(ev_o, ev_f)
    assert out["status"] == "PROVEN", out["issues"]
    assert {"code": "FIX_PAIR", "ok": True} in b.hub._s.ledger.state["claims"][out["claim_id"]]["verification"]["checks"]
    rep = b.hub.report_build()
    assert rep["counts"]["findings"] == 1 and rep["counts"]["unsupported_claims"] == 0 and rep["counts"]["failed_reverify"] == 0


def test_proven_claim_survives_reopen_and_reverification(tmp_path):
    x = Builds(tmp_path)
    x.open()
    ev_o, _ = x.run(ALT_KEY, "original")
    ev_f, _ = x.run(ALT_KEY, "fixed")
    assert x.claim(ev_o, ev_f)["status"] == "PROVEN"
    x.hub.close()
    hub = Hub(Config.load(tmp_path / "data"), FakeEngine(), FakeSandbox(), system_root=fake_system_root(tmp_path / "win"))
    out = hub.target_open(str(x.orig), str(x.manifest))     # reopened WITHOUT the fixed file: the manifest still binds its hash
    assert out["resumed"] is True and out["fixed_build"]["bound"] is False
    rep = hub.report_build()
    assert rep["counts"]["findings"] == 1 and rep["counts"]["failed_reverify"] == 0
    hub.close()


def test_original_run_alone_is_never_proven_as_a_fix(b):
    b.open()
    ev_o, _ = b.run(ALT_KEY, "original")
    out = b.hub.claim_add("The key is accepted by the original build; the fixed build rejects it.", [ev_o], [
        {"type": "quote", "evidence_id": ev_o, "text": VALID}], "fix_verification", "present", "PROVEN",
        [{"value": ALT_KEY, "derived": True}])
    assert out["status"] == "UNVERIFIED" and "FIX_NEEDS_BOTH_BUILDS" in codes(out)


def test_fixed_run_alone_cannot_back_any_claim(b):
    b.open()
    ev_f, _ = b.run(ALT_KEY, "fixed")
    out = b.hub.claim_add("The key is rejected.", [ev_f], [{"type": "quote", "evidence_id": ev_f, "text": INVALID}],
                          "behavior", "present", "PROVEN")
    assert out["status"] == "REJECTED" and "FIX_BUILD_EVIDENCE_NEEDS_PAIR" in codes(out)
    out = b.hub.claim_add("Fix claim with one side only.", [ev_f], [
        {"type": "fix_pair", "original": {"evidence_id": ev_f, "quote": VALID}, "fixed": {"evidence_id": ev_f, "quote": INVALID}}],
        "fix_verification", "present", "PROVEN")
    assert out["status"] == "REJECTED" and "FIX_PAIR_BUILD_MISMATCH" in codes(out)


def test_input_differing_between_builds_is_rejected(b):
    b.open()
    ev_o, _ = b.run(ALT_KEY, "original")
    ev_f, _ = b.run(WRONG_KEY, "fixed")      # a different key on the fixed build proves nothing about the same finding
    out = b.claim(ev_o, ev_f)
    assert out["status"] == "REJECTED" and "FIX_INPUTS_DIFFER" in codes(out)


def test_fixed_build_that_still_accepts_the_input_is_rejected(b):
    b.open()
    ev_o, _ = b.run(GOOD_KEY, "original")
    ev_f, _ = b.run(GOOD_KEY, "fixed")       # the recorded key stays valid: the "fix" claim must not hold for it
    out = b.claim(ev_o, ev_f, fq="valid", key=GOOD_KEY)
    assert out["status"] == "REJECTED" and "FIX_STILL_REPRODUCES" in codes(out)


def test_wrong_quotes_and_swapped_builds_are_rejected(b):
    b.open()
    ev_o, _ = b.run(ALT_KEY, "original")
    ev_f, _ = b.run(ALT_KEY, "fixed")
    assert "FIX_QUOTE_NOT_IN_RAW" in codes(b.claim(ev_o, ev_f, oq="Access granted"))
    assert "FIX_QUOTE_NOT_IN_RAW" in codes(b.claim(ev_o, ev_f, fq="Totally fixed"))
    assert "FIX_PAIR_BUILD_MISMATCH" in codes(b.claim(ev_f, ev_o))
    assert "FIX_PAIR_MALFORMED" in codes(b.claim(ev_o, ev_f, fq=VALID))
    assert "FIX_PAIR_EVIDENCE_NOT_LISTED" in codes(b.claim(ev_o, ev_f, ids=[ev_o]))


def test_fix_pair_needs_the_fix_kind(b):
    b.open()
    ev_o, _ = b.run(ALT_KEY, "original")
    ev_f, _ = b.run(ALT_KEY, "fixed")
    out = b.claim(ev_o, ev_f, kind="behavior")
    assert out["status"] == "REJECTED" and "FIX_PAIR_WRONG_KIND" in codes(out)


def test_fixed_run_that_is_not_complete_cannot_prove(tmp_path):
    x = Builds(tmp_path, fixed_behavior=lambda key: {"stdout": INVALID.encode() + b"\n", "exit_code": 1, "truncated": True})
    x.open()
    ev_o, _ = x.run(ALT_KEY, "original")
    ev_f, rf = x.run(ALT_KEY, "fixed")
    assert rf["cases"][0]["truncated"] is True
    out = x.claim(ev_o, ev_f)
    assert out["status"] != "PROVEN" and "FIX_RUN_NOT_COMPLETE" in codes(out)
    x.hub.close()


def test_fixed_build_that_crashes_without_output_is_not_a_fix(tmp_path):
    x = Builds(tmp_path, fixed_behavior=lambda key: {"stdout": b"", "stderr": b"", "exit_code": 3})
    x.open()
    ev_o, _ = x.run(ALT_KEY, "original")
    ev_f, _ = x.run(ALT_KEY, "fixed")
    out = x.claim(ev_o, ev_f)      # "not reproducing" because it crashed is not a positive rejection: the quote must be there
    assert out["status"] == "REJECTED" and "FIX_QUOTE_NOT_IN_RAW" in codes(out)
    x.hub.close()


def test_job_without_a_fixed_build_rejects_fix_pairs(tmp_path):
    x = Builds(tmp_path)
    plain = make_manifest(tmp_path / "plain.json", x.orig, allowed_operations=["static", "run_controlled"])
    x.hub.target_open(str(x.orig), str(plain))
    ev_o, _ = x.run(ALT_KEY, "original")
    out = x.claim(ev_o, ev_o)
    assert out["status"] == "REJECTED" and "FIX_NO_FIXED_BUILD" in codes(out)
    x.hub.close()


def test_tool_count_is_unchanged():
    assert len(TOOL_NAMES) == 18 <= MAX_TOOLS   # 15th: emulate, 16th: imports, 17th: captured_region, 18th: dataflow_slice
