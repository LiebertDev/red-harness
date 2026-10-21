"""BYTE FIDELITY in a real Windows Sandbox: the stdin/argv bytes the host sends must be seen byte-for-byte by the target.

Target: tests/fixtures/bytedump.c (dumps stdin and argv as hex). Encoding conversion, BOM, CRLF<->LF change,
truncation or extra bytes = test fails. Real sandbox: RH_ALLOW_REAL_SANDBOX=1 (see tests/heavy/test_sandbox_real.py).
"""
import subprocess
from pathlib import Path

import pytest

from redharness.config import Config
from redharness.core.result import Status
from redharness.sandbox import RunCase, run_controlled
from redharness.sandbox.backend import WindowsSandboxBackend
from redharness.scope.manifest import ScopeManifest, sha256_file

pytestmark = [pytest.mark.heavy, pytest.mark.real_sandbox]

FIX = Path(__file__).resolve().parents[1] / "fixtures"
EXE = FIX / "build" / "rh-bytedump.exe"

CASES = [
    RunCase(stdin="hello"),                                   # ASCII, no line ending
    RunCase(stdin="a\r\nb\r\n"),                              # CRLF
    RunCase(stdin="a\nb\n"),                                  # LF
    RunCase(stdin="\u015f\u011f\u00fc \u20ac \U0001F600\n"),  # multi-byte UTF-8
    RunCase(stdin=None),                                      # empty input
    RunCase(stdin="\x00\x01\x1a\x7f\r\rx\n\n"),               # NUL, ^Z, lone CR
    RunCase(stdin="<input-A>\n"),                             # synthetic placeholder, not a real key
    RunCase(argv=("a b", 'c"d', "e\\", "f\\ g", "", "h'i"), stdin="x"),  # space/quote/backslash/empty arg
]


def _parse(stdout: bytes) -> dict:
    d: dict = {"args": {}}
    for ln in stdout.decode("ascii").split("\n"):
        p = ln.split(" ")
        if p[0] == "CMDLINE":
            d["cmdline"] = bytes.fromhex(p[1])
        elif p[0] == "ARGC":
            d["argc"] = int(p[1])
        elif p[0] == "ARG":
            d["args"][int(p[1])] = bytes.fromhex(p[2])
        elif p[0] == "STDIN":
            d["stdin_len"] = int(p[1])
            d["stdin"] = bytes.fromhex(p[2] if len(p) > 2 else "")
    return d


def check_case(case: RunCase, stdout: bytes) -> None:
    """Bytes the host sent == bytes the target saw (shared by the fake and real sandbox tests)."""
    d = _parse(stdout)
    assert d["stdin"] == case.stdin_bytes() and d["stdin_len"] == len(case.stdin_bytes()), (d["stdin"], case.stdin_bytes())
    assert d["argc"] == 1 + len(case.argv)
    for i, a in enumerate(case.argv, 1):
        assert d["args"][i] == a.encode("utf-8"), (i, d["args"][i], a)
    want_tail = subprocess.list2cmdline(list(case.argv)).encode("utf-8")
    cl = d["cmdline"]
    assert cl.endswith(b'rh-bytedump.exe"' + (b" " + want_tail if want_tail else b"")) or \
        cl.endswith(b"rh-bytedump.exe" + (b" " + want_tail if want_tail else b"")), (cl, want_tail)


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
def run(backend, tmp_path_factory):
    if not EXE.is_file():
        pytest.skip("tests/fixtures/build/rh-bytedump.exe missing (tests/fixtures/build_bytedump.bat)")
    sha = sha256_file(EXE)
    cfg = Config.load(tmp_path_factory.mktemp("rh_sbx_bytes"))
    scope = ScopeManifest(sha, "test", "owner", "our own byte-fidelity target", ("run_controlled",), None, "")
    r = run_controlled(sha, scope, CASES, 30, cfg=cfg, backend=backend, target_path=EXE)
    print(f"\n[real sandbox bytes] status {r.status.value} code {r.code} {r.detail}")
    for c in r.cases:
        print(f"[real sandbox bytes] case {c.index}: {c.status.value} exit={c.exit_code} stdout={c.stdout[:200]!r}")
    return r


def test_stdin_and_argv_bytes_identical_in_real_sandbox(run):
    assert run.code is None, run.detail
    assert run.status is Status.OK and len(run.cases) == len(CASES)
    for case, res in zip(CASES, run.cases):
        assert res.status is Status.OK and res.exit_code == 0 and not res.truncated, (res.index, res.stderr)
        check_case(case, res.stdout)
