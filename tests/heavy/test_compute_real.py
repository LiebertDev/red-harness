"""`compute` inside a real Windows Sandbox: does the pinned embeddable CPython run as a separate user + Low IL,
are two runs deterministic, is a timeout an explicit error. UNVERIFIED: this file has never been run yet.

To run: `RH_ALLOW_REAL_SANDBOX=1` and `RH_COMPUTE_RUNTIME_ZIP=<path to python-3.12.10-embed-amd64.zip>` (the zip is verified
against the pinned SHA-256 and installed into a temporary data_root). Skipped if there is no sandbox or another instance is running.
"""
import os
from pathlib import Path

import pytest

from redharness.compute.runtime import PINNED, install_runtime
from redharness.config import Config
from redharness.core.result import Status
from redharness.evidence.model import COMPUTE_AUTHORITY, build_evidence
from redharness.mcp.session import Hub, ToolFailure
from redharness.sandbox.backend import WindowsSandboxBackend

from tests.unit._fake_engine import FakeEngine
from tests.unit.mcp_helpers import make_manifest

pytestmark = [pytest.mark.heavy, pytest.mark.real_sandbox]

SRC = b'uint32_t h = 0x811c9dc5; const char *p = "RH-PREFIX-"; if (fnv(p, digits) == 0x5be2a2d6) ok();\n'
# Meet-in-the-middle: prefix + 6 digits, FNV-1a-32. 10^3 states forward, 10^3 backward; seconds in pure Python.
MITM = """
P, INV = 0x01000193, pow(0x01000193, -1, 1 << 32)
h0, prefix, target = INPUTS['basis'], INPUTS['prefix'], INPUTS['target']
for b in prefix:
    h0 = ((h0 ^ b) * P) & 0xffffffff
fwd = {}
for i in range(1000):
    h = h0
    for b in b'%03d' % i:
        h = ((h ^ b) * P) & 0xffffffff
    fwd.setdefault(h, []).append(i)
out = []
for j in range(1000):
    h = target
    for b in reversed(b'%03d' % j):
        h = ((h * INV) & 0xffffffff) ^ b
    for i in fwd.get(h, []):
        out.append('%03d%03d' % (i, j))
print(sorted(out))
"""


def _fnv(data: bytes, h: int = 0x811C9DC5) -> int:
    for b in data:
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h


@pytest.fixture(scope="module")
def hub(tmp_path_factory):
    zp = os.environ.get("RH_COMPUTE_RUNTIME_ZIP")
    if not zp or not Path(zp).is_file():
        pytest.skip("RH_COMPUTE_RUNTIME_ZIP missing (the pinned-digest embeddable CPython zip)")
    b = WindowsSandboxBackend()
    ok, why = b.available()
    if not ok:
        pytest.skip(f"Windows Sandbox missing: {why}")
    if b.running_processes():
        pytest.skip("another Windows Sandbox instance is running (single-instance limit; not closed)")
    root = tmp_path_factory.mktemp("rh_compute_real")
    cfg = Config.load(root / "data")
    install_runtime(cfg, zp, PINNED)
    target = root / "sample.bin"
    target.write_bytes(b"MZ" + bytes(range(256)) * 8)
    man = make_manifest(root / "scope.json", target, allowed_operations=["static", "compute"])
    h = Hub(cfg, FakeEngine(), b)
    h.target_open(str(target), str(man))
    yield h
    h.close()


def test_real_sandbox_compute_is_deterministic_and_bound(hub):
    s = hub._s
    want = _fnv(b"RH-PREFIX-123456")
    src = SRC.replace(b"0x5be2a2d6", hex(want).encode())
    ev = s.ledger.record_evidence(build_evidence(
        s.cas, subject_sha256=s.sha, tool="decompile", operation="decompile", raw=src, status=Status.OK,
        confidence="observed", authority="shipped-artifact", parameters={"function": "main"}))["evidence_id"]
    out = hub.compute(MITM, [{"name": "basis", "evidence_id": ev, "const": "0x811c9dc5"},
                             {"name": "prefix", "evidence_id": ev, "quote": "RH-PREFIX-"},
                             {"name": "target", "evidence_id": ev, "const": hex(want)}], 120)
    print(f"\n[real compute] {out['evidence_id']} {out['output'][-200:]!r}")
    assert out["status"] == "OK" and out["deterministic"] is True and "'123456'" in out["output"]
    rec = s.ledger.state["evidence"][out["evidence_id"]]
    assert rec["authority"] == COMPUTE_AUTHORITY and rec["environment"]["isolation"] == "windows-sandbox"
    assert any("separate-user" in x for x in rec["limitations"])


def test_real_sandbox_compute_timeout_is_an_error(hub):
    with pytest.raises(ToolFailure) as e:
        hub.compute("while True:\n    pass\n", None, 5)
    assert e.value.code == "COMPUTE_TIMEOUT"
