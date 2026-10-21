"""Byte-fidelity unit tests (fake sandbox): are the stdin/argv the runner puts in cases.json identical to the bytes the target will
see (raw bytes, no BOM/encoding/line-ending conversion). Real sandbox: tests/heavy/test_sandbox_bytes_real.py."""
import base64
import ctypes
import hashlib
import re
import subprocess
from ctypes import wintypes
from pathlib import Path

import pytest

from redharness.config import Config
from redharness.sandbox import RunCase, run_controlled
from redharness.sandbox.runner import GUEST_SCRIPT
from redharness.scope.manifest import ScopeManifest

from ..heavy.test_sandbox_bytes_real import CASES, check_case
from ._fake_sandbox import FakeSandbox

TARGET = b"MZ-fake-bytedump"
SHA = hashlib.sha256(TARGET).hexdigest()
FAST = dict(poll_interval_s=0.01, proc_check_interval_s=0.05)


def _crt_argv(line: str) -> list[str]:
    """MSVC CRT command-line parsing (same rules as CommandLineToArgvW)."""
    f = ctypes.windll.shell32.CommandLineToArgvW
    f.restype = ctypes.POINTER(wintypes.LPWSTR)
    n = ctypes.c_int()
    ptr = f("rh-bytedump.exe " + line, ctypes.byref(n))
    try:
        return [ptr[i] for i in range(1, n.value)]
    finally:
        ctypes.windll.kernel32.LocalFree(ptr)


def bytedump_behavior(idx, spec_case, stdin: bytes) -> dict:
    """Produces the output of tests/fixtures/bytedump.c from the bytes the guest GIVES the target."""
    line = spec_case["argv_line"]
    args = _crt_argv(line)
    exe = '"C:/work/c000/rh-bytedump.exe"'
    cl = (exe + (" " + line if line else "")).encode("utf-8")
    out = [b"CMDLINE " + cl.hex().encode(), b"ARGC %d" % (1 + len(args))]
    out += [b"ARG %d %s" % (i, a.encode("utf-8").hex().encode()) for i, a in enumerate(args, 1)]
    out.append(b"STDIN %d %s" % (len(stdin), stdin.hex().encode()))
    return {"stdout": b"\n".join(out) + b"\n", "stderr": b"", "exit_code": 0}


@pytest.fixture
def target(tmp_path):
    p = tmp_path / "rh-bytedump.exe"
    p.write_bytes(TARGET)
    return p


def test_runner_sends_exact_stdin_and_argv_bytes(tmp_path, target):
    cfg = Config.load(tmp_path / "data")
    scope = ScopeManifest(SHA, "test", "owner", "test", ("run_controlled",), None, "")
    fake = FakeSandbox(behavior=bytedump_behavior)
    run = run_controlled(SHA, scope, CASES, 5, cfg=cfg, backend=fake, target_path=target, **FAST)
    assert run.code is None, run.detail
    assert len(run.cases) == len(CASES)
    for case, res in zip(CASES, run.cases):
        check_case(case, res.stdout)
    # cases.json: stdin base64(raw UTF-8 bytes), CRLF/BOM/NUL preserved
    sent = [base64.b64decode(c["stdin_b64"]) for c in fake.seen_specs[0]["cases"]]
    assert sent == [c.stdin_bytes() for c in CASES]
    assert not any(s.startswith(b"\xef\xbb\xbf") for s in sent)
    assert sent[1] == b"a\r\nb\r\n"


def test_runner_argv_line_roundtrips_through_crt_parsing():
    for c in CASES:
        assert _crt_argv(subprocess.list2cmdline(list(c.argv))) == list(c.argv)


def test_guest_script_passes_stdin_as_raw_bytes():
    s = Path(GUEST_SCRIPT).read_text(encoding="utf-8")
    # BOM-less writer encoding + raw byte writing; no text writer (WriteLine/Write(string)) or PowerShell pipe
    assert 'GetProperty("StandardInputEncoding")' in s and "new System.Text.UTF8Encoding(false)" in s  # C# 5: reflection
    assert "StandardInput.BaseStream.Write(stdin, 0, stdin.Length)" in s
    assert not re.search(r"StandardInput\.(Write|WriteLine)\(", s)
    assert "$stdin | " not in s and "$input" not in s
