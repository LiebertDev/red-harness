"""Emulation worker process: reads one JSON job from stdin, writes one JSON result to stdout.

Job: {"target_path": str, "target_sha256": str, "request": <spec.build_request>}. Order (fail closed):
1. read the job from stdin (harness data only);
2. lower this process to Low integrity (harden.py); if that fails, refuse (`hardening_failed`) and emulate nothing;
3. re-hash the target file and refuse a mismatch, so the bytes it emulates are the job's target;
4. emulate.
It runs under a Job Object (host.py: memory and time caps, one active process, so no children): an emulator crash or
runaway ends this process, not the MCP server.

A job {"probe": {"write_dir": str}} skips 3-4 and reports what the hardened process can do (tests and diagnostics):
whether it is at Low integrity, may create a file in `write_dir`, and may start a child process.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys


def _probe(spec: dict) -> dict:
    from .harden import integrity_rid
    out: dict = {"ok": True, "stop": "probe", "integrity_rid": integrity_rid()}
    path = os.path.join(spec.get("write_dir") or ".", "rh_emulate_probe.txt")
    try:
        with open(path, "x", encoding="ascii") as f:
            f.write("x")
        out["file_created"] = True
        os.remove(path)
    except OSError as e:
        out["file_created"], out["file_error"] = False, f"{type(e).__name__}: {e}"
    try:
        subprocess.run([sys.executable, "-c", "pass"], timeout=20, capture_output=True)
        out["child_started"] = True
    except OSError as e:
        out["child_started"], out["child_error"] = False, f"{type(e).__name__}: {e}"
    return out


def handle(job: dict, *, harden: bool = True) -> dict:
    """`harden=False` only for in-process unit tests (the caller is the test process itself)."""
    if harden:
        try:
            from .harden import lower_to_low_integrity
            lower_to_low_integrity()
        except Exception as e:  # noqa: BLE001 - any failure to harden refuses the job
            return {"ok": False, "stop": "hardening_failed", "error": f"{type(e).__name__}: {e}"}
    if "probe" in job:
        return _probe(job["probe"])
    from .engine import EmulatorMissing, run_request
    with open(job["target_path"], "rb") as f:
        data = f.read()
    if hashlib.sha256(data).hexdigest() != job["target_sha256"]:
        return {"ok": False, "stop": "target_changed", "error": "target file does not match its SHA-256"}
    try:
        return run_request(data, job["request"])
    except EmulatorMissing as e:
        return {"ok": False, "stop": "emulator_missing", "error": str(e)}


def main() -> int:
    job = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    res = handle(job)
    sys.stdout.buffer.write(json.dumps(res, sort_keys=True).encode("utf-8"))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
