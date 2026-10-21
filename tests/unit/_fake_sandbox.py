"""Fake Windows Sandbox backend: imitates guest.ps1's file contract (ready/session.json, cNNN.*, done.json).

No real sandbox/target is run. The contract's agreement with the real guest.ps1 is tested in tests/heavy/test_sandbox_real.py.

The integrity contract (sandbox/integrity.py) is imitated too: read nonce.txt -> ready.json -> wait until the host deletes it ->
the TARGET (behavior) runs only after that -> records are HMAC'd with the nonce. The `integrity=` modes model tampering.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path

from redharness.sandbox import integrity as itg


def default_behavior(idx, spec_case, stdin: bytes) -> dict:
    return {"stdout": b"echo:" + stdin, "stderr": b"", "exit_code": 0}


class FakeSandbox:
    """mode: ok | hang | crash | fatal | bad_hash | no_done | bad_done
    behavior(idx, spec_case, stdin) -> dict(stdout, stderr, exit_code, timed_out, truncated, stdout_total, launch_error)

    integrity: ok | no_record (no integrity block in the record) | wrong_nonce (signed with a different nonce) | bad_mac (commit
      correct, MAC corrupt) | no_session_record | skip_case_write (the runner COULD NOT WRITE the cNNN files: what the target put stays)
    target_writes(out_dir, idx): writes the TARGET makes to the out folder while a case runs (fake-result/overwrite attempt);
      the runner writes its own files afterwards (overwrites them, as in guest.ps1).
    """

    def __init__(self, mode="ok", behavior=default_behavior, kill_fails=False, preexisting=(), available=True,
                 crash_after=1, post_start=None, integrity="ok", target_writes=None):
        self.mode, self.behavior, self.kill_fails = mode, behavior, kill_fails
        self.pids = list(preexisting)
        self.pids_before: set[int] = set()   # sandbox PIDs present before start(): not ours
        self._available = available
        self.crash_after = crash_after
        self.post_start = post_start  # post_start(out_dir): tampering after the guest output is written
        self.integrity, self.target_writes = integrity, target_writes
        self.nonce_present_at_target: list[bool] = []   # was nonce.txt present when the target started, per case
        self.seen_nonce: str | None = None
        self.started: list[Path] = []
        self.kill_calls = 0
        self.max_concurrent_started = 0
        self.seen_specs: list[dict] = []
        self.seen_wsb: list[str] = []
        self._mu = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ---- interface
    def available(self):
        return (True, "") if self._available else (False, "fake: no sandbox")

    def running_processes(self):
        with self._mu:
            return list(self.pids)

    def start(self, wsb_path):
        if self.pids:
            raise AssertionError("attempted to start a second sandbox instance")
        self.started.append(Path(wsb_path))
        text = Path(wsb_path).read_text(encoding="utf-8")
        self.seen_wsb.append(text)
        folders = re.findall(r"<HostFolder>(.*?)</HostFolder>", text)
        in_dir, out_dir = Path(folders[0]), Path(folders[1])
        with self._mu:
            self.pids_before = set(self.pids)
            self.pids = [101, 102]
        self._stop.clear()
        self._thread = threading.Thread(target=self._guest, args=(in_dir, out_dir), daemon=True)
        self._thread.start()

    def kill_all(self, wait_s=20.0):
        self.kill_calls += 1
        if self.kill_fails:
            return self.running_processes()
        self._stop.set()
        if self._thread:
            self._thread.join(5)
        with self._mu:
            self.pids = []
        return []

    # ---- ownership API (sandbox/backend.py): start time of fake process p is 1000 + p
    def owned_processes(self):
        with self._mu:
            return [{"pid": p, "start": 1000 + p} for p in self.pids if p not in self.pids_before]

    def alive_owned(self, procs):
        with self._mu:
            return [r["pid"] for r in procs if r["pid"] in self.pids and r.get("start") == 1000 + r["pid"]]

    def kill_owned(self, procs, wait_s=20.0):
        self.owned_kill_calls = getattr(self, "owned_kill_calls", 0) + 1
        mine = self.alive_owned(procs)
        if self.kill_fails:
            return mine
        with self._mu:
            self.pids = [p for p in self.pids if p not in mine]
        if not self.pids:
            self._stop.set()
            if self._thread:
                self._thread.join(5)
        return []

    # ---- guest imitation
    def _save(self, out: Path, name: str, data: bytes):
        tmp = out / (name + ".tmp")
        for attempt in range(50):  # the host may be reading the file right now (guest.ps1 retries too)
            try:
                tmp.write_bytes(data)
                os.replace(tmp, out / name)
                return
            except PermissionError:
                if attempt == 49:
                    raise
                time.sleep(0.02)

    def _guest(self, in_dir: Path, out_dir: Path):
        spec = json.loads((in_dir / "cases.json").read_text(encoding="ascii"))
        self.seen_specs.append(spec)
        assert (in_dir / "bin" / spec["exe"]).is_file() and (in_dir / "guest.ps1").is_file()
        mode = self.mode
        run_id = spec["run_id"]
        sha = __import__("hashlib").sha256((in_dir / "bin" / spec["exe"]).read_bytes()).hexdigest()
        self.current_sha = sha   # which staged binary this session runs (fix-verification tests pick behavior by it)
        if mode == "bad_hash":
            sha = "0" * 64
        # --- nonce handshake: read, acknowledge, wait until the host deletes it (the target is not running yet)
        nonce = (in_dir / itg.NONCE_FILE).read_text(encoding="ascii").strip()
        self.seen_nonce = nonce
        key = itg.new_nonce() if self.integrity == "wrong_nonce" else nonce  # signing key
        commit = itg.nonce_commit(nonce)
        self._save(out_dir, "ready.json", json.dumps({"run_id": run_id, "nonce_commit": commit}).encode())
        t0 = time.monotonic()
        while (in_dir / itg.NONCE_FILE).exists():
            if self._stop.is_set() or time.monotonic() - t0 > 20:
                return
            time.sleep(0.005)
        sess = {"run_id": run_id, "target_sha256": sha, "os": "fake"}
        if self.integrity != "no_session_record":
            sess["integrity"] = itg.sign_session(key, run_id, sha, commit=commit)
            if self.integrity == "bad_mac":
                sess["integrity"]["mac"] = "0" * 64
        self._save(out_dir, "session.json", json.dumps(sess).encode())
        if mode == "hang":
            self._stop.wait(60)
            return
        if mode == "fatal":
            msg = "boom"
            self._save(out_dir, "fatal.json", json.dumps({"error": msg, "mac": itg.sign_fatal(nonce, msg)}).encode())
            return
        import base64
        macs: list[str] = []
        for n, c in enumerate(spec["cases"]):
            if self._stop.is_set():
                return
            stdin = base64.b64decode(c["stdin_b64"])
            self.nonce_present_at_target.append((in_dir / itg.NONCE_FILE).exists())
            if self.target_writes:  # touches the out folder while the target runs (fake-result/overwrite attempt)
                self.target_writes(out_dir, c["index"])
                if self._stop.is_set():  # the host closed the sandbox (kill_all): a dead guest no longer writes files
                    return
            r = self.behavior(c["index"], c, stdin)
            so, se = r.get("stdout", b""), r.get("stderr", b"")
            cap = spec["max_stream_bytes"]
            so_w, se_w = so[:cap], se[:cap]
            meta = {"index": c["index"], "exit_code": r.get("exit_code", 0), "timed_out": r.get("timed_out", False),
                    "truncated": r.get("truncated", False), "launch_error": r.get("launch_error"),
                    "elapsed_ms": r.get("elapsed_ms", 12), "stdout_total": r.get("stdout_total", len(so)),
                    "stderr_total": r.get("stderr_total", len(se))}
            if self.integrity != "no_record":
                rec = itg.sign_case(key, run_id, c["index"], so_w, se_w, meta, commit=commit)
                if self.integrity == "bad_mac":
                    rec["mac"] = "f" * 64
                meta["integrity"] = rec
                macs.append(rec["mac"])
            if self.integrity != "skip_case_write":
                self._save(out_dir, f"c{c['index']:03d}.stdout", so_w)
                self._save(out_dir, f"c{c['index']:03d}.stderr", se_w)
                self._save(out_dir, f"c{c['index']:03d}.json", json.dumps(meta).encode())
            if mode == "crash" and n + 1 >= self.crash_after:
                with self._mu:
                    self.pids = []  # the sandbox closed before finishing
                return
        if mode == "no_done":
            self._stop.wait(60)
            return
        # seal (same as guest.ps1): target dead; session.json is rewritten, a fatal.json left by the target is deleted
        self._save(out_dir, "session.json", json.dumps(sess).encode())
        if mode != "fatal":
            (out_dir / "fatal.json").unlink(missing_ok=True)
        done = {"run_id": run_id, "cases": len(spec["cases"])}
        if self.integrity != "no_record":
            done["mac"] = itg.sign_done(key, run_id, macs)
        if mode == "bad_done":
            done["run_id"] = "other"
        if self.post_start:
            self.post_start(out_dir)
        self._save(out_dir, "done.json", json.dumps(done).encode())
