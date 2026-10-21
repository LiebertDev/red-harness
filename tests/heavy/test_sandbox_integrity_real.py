"""Output integrity in a real Windows Sandbox: the "malicious" test target (tests/fixtures/tamper.c) tries to write a fake
result to the output folder, overwrite the runner's files and spy on the runner/nonce.

FACT: the mapped `C:\\out` is writable by everyone inside the guest; the Low
integrity label, a DACL deny and a separate user do NOT prevent writing to that folder. So the protection rests on the principle
"even if it writes, it is not accepted", not "it cannot write": (1) the nonce exists nowhere while the target runs and the target cannot
read the runner's memory, (2) in the seal phase the runner compares the files with in-memory values and repairs them, (3) the host verifies every record
with a nonce-keyed HMAC. This file shows with a real guest (a) that behavior and the isolation level, (b) that none of the target's
attempts changed the result, (c) that the host rejects surviving fake files.

The target runs ONLY inside the sandbox. Skipped if there is no sandbox or MSVC.
"""
import json
import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from redharness.config import Config
from redharness.core.cas import Cas
from redharness.core.result import Status
from redharness.sandbox import Code, RunCase, build_run_evidence_all, run_controlled
from redharness.sandbox.backend import WindowsSandboxBackend
from redharness.scope.manifest import ScopeManifest, sha256_file

pytestmark = [pytest.mark.heavy, pytest.mark.real_sandbox]

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
EXE = FIXTURES / "build" / "rh-tamper.exe"
LEVEL = "windows-sandbox+separate-user+low-il"


@pytest.fixture(scope="module")
def backend():
    b = WindowsSandboxBackend()
    ok, why = b.available()
    if not ok:
        pytest.skip(f"Windows Sandbox missing: {why}")
    if b.running_processes():
        pytest.skip("another Windows Sandbox instance is running (single-instance limit; not closed)")
    return b


@pytest.fixture(scope="module")
def tamper_exe():
    if not EXE.is_file():
        r = subprocess.run(["cmd", "/c", str(FIXTURES / "build_tamper.bat")], capture_output=True, timeout=300)
        if not EXE.is_file():
            pytest.skip(f"rh-tamper.exe could not be built (no MSVC Build Tools?): {r.stdout[-300:]!r}")
    return EXE


def _scope(sha):
    return ScopeManifest(sha, "test", "owner", "our own tamper test target", ("static", "run_controlled"), None, "")


def kv(stdout: bytes) -> dict:
    out = {}
    for line in stdout.decode("ascii", "replace").splitlines():
        m = re.match(r"([A-Z_]+ [\w.]+|[A-Z_]+)=(.*)", line.strip())
        if m:
            out[m.group(1)] = m.group(2)
    return out


@pytest.fixture(scope="module")
def attack_run(backend, tamper_exe, tmp_path_factory):
    sha = sha256_file(tamper_exe)
    cfg = Config.load(tmp_path_factory.mktemp("rh_sbx_integrity"))
    # 0: identity (il)  1: creating fake files  2: overwriting/deleting/moving earlier cases' files  3: spying on the runner/nonce
    cases = [RunCase(argv=("il",)), RunCase(argv=("forge",)), RunCase(argv=("overwrite",)), RunCase(argv=("peek",))]
    t = time.monotonic()
    run = run_controlled(sha, _scope(sha), cases, 30, cfg=cfg, backend=backend, target_path=tamper_exe)
    print(f"\n[integrity real] {time.monotonic() - t:.1f} s, status {run.status.value}, code {run.code}, "
          f"level {run.isolation_level}, verified {run.integrity_verified}")
    for c in run.cases:
        print(f"[integrity real] case {c.index}: {c.status.value} exit={c.exit_code} {c.elapsed_ms} ms "
              f"verified={c.integrity_verified}\n{c.stdout.decode('ascii', 'replace')}")
    return cfg, run, sha


def test_session_is_verified_and_level_is_recorded(attack_run):
    cfg, run, sha = attack_run
    assert run.code is None, run.detail
    assert run.status is Status.OK and run.ok and run.integrity_verified is True
    assert run.isolation_level == LEVEL
    assert all(c.integrity_verified and c.isolation_level == LEVEL and c.status is Status.OK for c in run.cases)
    assert run.sandbox_closed is True and run.workdir_removed is True


def test_target_runs_low_integrity_as_separate_user(attack_run):
    _, run, _ = attack_run
    # single line: "INTEGRITY_RID=0x1000 INTEGRITY=low" (kv() reads it as one pair); parse it, but really verify the value
    m = re.search(rb"INTEGRITY_RID=(0x[0-9A-Fa-f]+) INTEGRITY=(\w+)", run.cases[0].stdout)
    assert m, run.cases[0].stdout
    assert m.group(2) == b"low" and int(m.group(1), 16) == 0x1000
    assert run.isolation_level == LEVEL and all(c.isolation_level == LEVEL for c in run.cases)  # the separate user is checked


def test_forge_and_overwrite_attempts_do_not_change_the_result(attack_run):
    """The target wrote/overwrote/deleted everything it could; the result the host accepts is still the runner's real output."""
    _, run, _ = attack_run
    out = {c.index: c.stdout for c in run.cases}
    assert b"INTEGRITY=low" in out[0]                      # case 0's stdout was not overwritten (not "OVERWRITTEN")
    assert b"FORGE_CREATE" in out[1] and b"OVERWRITE" in out[2]   # the runner's pipe carried the output
    for c in run.cases:
        assert b"FORGED" not in c.stdout and b"OVERWRITTEN" not in c.stdout
        assert c.exit_code == 0 and not c.truncated and not c.timed_out
    for k, v in kv(out[1]).items():
        print(f"[integrity real] forge {k} -> {v}")
    for k, v in kv(out[2]).items():
        print(f"[integrity real] overwrite {k} -> {v}")


def test_target_cannot_read_runner_memory_or_nonce(attack_run):
    _, run, _ = attack_run
    p = kv(run.cases[3].stdout)
    assert p["PEEK open_parent_vm_read"].startswith("DENIED")      # runner memory cannot be read (separate user)
    assert p["PEEK env_RH_NONCE"] == "absent"
    assert "nonce_found=0" in p["PEEK read_cases_json"] or p["PEEK read_cases_json"].startswith("DENIED")
    assert "wmic_nonce_found=0" in p["PEEK wmic_bytes"]            # no nonce in the command lines either
    for k, v in p.items():
        print(f"[integrity real] peek {k} -> {v}")


def test_nonce_never_persisted_and_evidence_carries_level(attack_run):
    cfg, run, sha = attack_run
    cas = Cas(cfg.cas_dir)
    evs = build_run_evidence_all(cas, run)
    assert len(evs) == 4
    for ev in evs:
        assert f"isolation level: {LEVEL}" in ev["limitations"]
        assert ev["capture"]["status"] == "OK"
        assert not re.search(r"\b[0-9a-f]{64}\b", cas.get(ev["raw"]["blob_sha256"]).decode("ascii", "replace")
                             .replace(sha, ""))  # no nonce-like 64-hex in the output (except the target SHA)


# ---- surviving fake files: the host rejects them (real guest records, real nonce, real format)

class TamperingBackend(WindowsSandboxBackend):
    """Tampers with the output folder AFTER the sandbox closes (before the host reads the output): a model of a fake
    file surviving in the guest. Works on real guest records, so it also tests that the canonical form really matches."""

    def __init__(self, tamper):
        super().__init__()
        self._tamper, self._out = tamper, None

    def start(self, wsb_path):
        self._out = Path(wsb_path).parent / "out"
        super().start(wsb_path)

    def kill_all(self, wait_s=20.0):
        left = super().kill_all(wait_s)
        if not left and self._out and (self._out / "done.json").exists():
            self._tamper(self._out)
        return left


def _forge(out: Path):
    # case 0: the record is real but the stdout file is fake (hash mismatch)
    (out / "c000.stdout").write_bytes(b"License valid\r\n")
    # case 1: a from-scratch fake triple; the hashes match the files but no MAC can be produced since the nonce is unknown
    so, se = b"FORGED\r\n", b""
    import hashlib
    rec = {"version": 1, "case_id": "x:1", "stdout_sha256": hashlib.sha256(so).hexdigest(),
           "stderr_sha256": hashlib.sha256(se).hexdigest(), "exit_code": 0, "nonce_commit": "0" * 64,
           "target_integrity": "low", "separate_user": True, "mac": "0" * 64}
    (out / "c001.stdout").write_bytes(so)
    (out / "c001.stderr").write_bytes(se)
    (out / "c001.json").write_text(json.dumps({"index": 1, "exit_code": 0, "timed_out": False, "truncated": False,
                                                "launch_error": None, "elapsed_ms": 1, "stdout_total": len(so),
                                                "stderr_total": 0, "integrity": rec}))
    # case 2: the integrity record is deleted
    meta = json.loads((out / "c002.json").read_text())
    meta.pop("integrity")
    (out / "c002.json").write_text(json.dumps(meta))


def test_host_rejects_surviving_forged_results(tamper_exe, tmp_path):
    b = TamperingBackend(_forge)
    ok, why = b.available()
    if not ok:
        pytest.skip(why)
    if b.running_processes():
        pytest.skip("another Windows Sandbox instance is running")
    sha = sha256_file(tamper_exe)
    cfg = Config.load(tmp_path / "data")
    cases = [RunCase(argv=("il",)), RunCase(argv=("il",)), RunCase(argv=("il",))]
    run = run_controlled(sha, _scope(sha), cases, 30, cfg=cfg, backend=b, target_path=tamper_exe)
    print(f"\n[integrity real 2] status {run.status.value} code {run.code}\n{run.detail}")
    assert run.code == Code.INTEGRITY and run.status is Status.ERROR and not run.ok
    assert run.cases == [] and run.integrity_verified is False and len(run.integrity_problems) == 3
    assert any("c000" in p and "stdout SHA-256 mismatch" in p for p in run.integrity_problems)
    assert any("c001" in p and "case id" in p for p in run.integrity_problems)
    assert any("c002" in p and "integrity record missing" in p for p in run.integrity_problems)
    assert build_run_evidence_all(Cas(cfg.cas_dir), run) == []
    assert not any(p.is_file() for p in cfg.cas_dir.rglob("*"))   # the fake output did not enter CAS
    assert run.sandbox_closed is True and b.running_processes() == []
