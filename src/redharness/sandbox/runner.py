"""Controlled execution (`run_controlled`): runs the target inside Windows Sandbox with inputs and OBSERVES the result.

Flow (all fail-closed; only a clean, complete session can be OK):
  1. input/scope/SHA check (BEFORE the lock, cheap rejection): reject if the scope does not grant "run_controlled" or the SHA does not match.
  2. global sandbox lock (core/lock.py). If busy returns BUSY; does not wait and never tries to open a second instance.
  3. under the lock, recovery of half-finished sessions (journal has SANDBOX_STARTED, no finish): sandbox processes
     are killed, the work folder is deleted, the job is marked SANDBOX_RUN_FAILED. A partial result is never accepted.
  4. per-job work folder `<data_root>/work/sandbox/<run_id>/{in,out}`; the target is copied and its SHA re-verified;
     SANDBOX_STARTED is written to the journal; the sandbox is opened.
  5. wait for `out/done.json` (at most boot allowance + case durations); timeout/crash -> sandbox processes are killed.
  6. outputs are read AFTER the sandbox has CLOSED (never read if it did not close: SANDBOX_NOT_CLOSED); raw output goes to CAS.
  7. SANDBOX_FINISHED is written to the journal, the work folder is deleted, the lock is released.

Case status: process finished by itself + output not truncated + exit code obtained = OK. A NON-ZERO exit code is NOT an error
(a license check may give exit 1 for "License invalid"; we only observe). Timeout = TIMEOUT, truncated output = PARTIAL,
launch error/no result = ERROR. If the session did not end cleanly (timeout, crash, not closed...) even finished cases
are at most PARTIAL.

Output integrity (integrity.py, guest.ps1): the target can write a fake result to `C:\\out` or overwrite the runner's file
(mapped folders are open to everyone inside the guest; a Low IL label or a separate user does not prevent it). Therefore: (a) the target's stdout/stderr goes through the runner's pipe and never touches files;
(b) the target runs as a non-admin user separate from the runner, with Low IL (cannot read the runner's memory/nonce);
(c) at session start the host provides a one-time nonce, the host deletes the file once the guest has read it, the target starts after that;
(d) every record is HMAC'd with the nonce and the host verifies it with the bytes it read itself; mismatch = INTEGRITY, NO evidence.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from ..analysis.pe_image import PeError, kernel_mode_reasons, parse_pe
from ..config import Config, sandbox_memory_mb
from ..core.cas import Cas
from ..core.procinfo import process_start_time
from ..core.journal import Journal, JournalCorrupt
from ..core.heavy import heavy_lock, sandbox_global_lock
from ..core.lock import JobLock, LockError, LockHeldError
from ..core.result import Status
from ..scope.manifest import ScopeManifest, sha256_file
from . import hostres, integrity
from .backend import SandboxBackend, WindowsSandboxBackend, render_wsb
from .model import (ISOLATION, MAX_ARGV, MAX_CASES, MAX_STDIN_BYTES, MAX_STREAM_BYTES, MAX_TIMEOUT_S, CaseResult,
                    Code, ObservePlan, RunCase, SandboxRun, sha256_bytes)

BOOT_ALLOWANCE_S = 90.0     # cold start takes roughly 20 s; the allowance is kept generous
PER_CASE_OVERHEAD_S = 5.0   # per-case copy/launch allowance
FINISH_SLACK_S = 10.0
PROC_CHECK_INTERVAL_S = 2.0
KILL_WAIT_S = 20.0
RETRY_BACKOFF_S = 20.0      # wait before the single retry after a resource error (let Hyper-V resources recover)
BACKOFF_CAP_MULT = 6.0      # persisted cross-run backoff: base * 2**(failures-1), capped at base * 6 (20 s -> 20/40/80/120 s)
BACKOFF_MAX_WAIT_MULT = 3.0  # a remaining cooldown up to base * 3 is waited out; a longer one returns RESOURCE_UNAVAILABLE
MAX_ATTEMPTS = 2            # first attempt + AT MOST 1 retry; no endless/back-to-back launches
RESOURCE_HINT = ("Windows Sandbox/Hyper-V resources unavailable (may be 0x800705AA); other VMs/WSL/Sandbox can be closed or "
                 "the computer restarted, then retry. At most 1 automatic retry was made.")
_SHA = re.compile(r"[0-9a-f]{64}")
_SAFE_NAME = re.compile(r"[A-Za-z0-9._-]{1,64}\.exe", re.I)
_SAFE_SUPPORT = re.compile(r"[A-Za-z0-9._-]{1,64}\.dll", re.I)   # support DLLs placed next to the target (VC++ runtime)
_SAFE_ARGS = re.compile(r"[0-9 ]{1,128}")                            # observe tool argument prefix: numbers only
MAX_OBSERVE_TIMEOUT_S = 2 * MAX_TIMEOUT_S + 60
MAX_SUPPORT_FILES = 8
MAX_SUPPORT_BYTES = 16 << 20
_REPARSE = 0x400
_JSON_MAX = 64 * 1024
_TRANSIENT_READ = (PermissionError, FileNotFoundError)   # the guest replacing a file during polling

GUEST_SCRIPT = Path(__file__).with_name("guest.ps1")
RUN_CMD = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\in\\guest.ps1\r\n"


class _BadOutput(Exception):
    pass


# ---------------------------------------------------------------- helpers

def sandbox_dir(cfg: Config) -> Path:
    return cfg.data_root / "sandbox"


def workdir_root(cfg: Config) -> Path:
    return cfg.work_dir / "sandbox"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _rmtree(path: Path, tries: int = 4) -> bool:
    """Deletes the folder; was it deleted? (does not enter the TARGET of a junction/symlink: Python >= 3.12.)"""
    def onerror(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError:
            pass
    for i in range(tries):
        if not os.path.lexists(path):
            return True
        shutil.rmtree(path, onerror=onerror)
        if not os.path.lexists(path):
            return True
        time.sleep(0.3 * (i + 1))
    return not os.path.lexists(path)


MAX_SIDE_EFFECT_ENTRIES = 2000


def _list_workdir_files(root: Path, limit: int = MAX_SIDE_EFFECT_ENTRIES) -> list[str]:
    """Host-side side-effect observation: relative paths of plain files under `root` (the mapped work folder).

    Called BEFORE the folder is deleted. The sandbox maps `in/` and `out/` under this root, so anything the target
    wrote to a mapped folder shows up here. Files inside the guest-only %TEMP are NOT visible (not mapped) and
    are reported as `unknown` via the note below. Empty list = nothing observed (never "clean").

    Walked with os.scandir and lstat identity: symlinks and reparse points (junctions) are never followed, and
    every resolved path must stay inside `root`. Skipped links are reported as `<skipped link: ...>` markers.
    At most `limit` entries are listed; a `<truncated: ...>` marker records that more were present."""
    out: list[str] = []
    if limit <= 0:
        return out
    try:
        root_stat = os.lstat(root)
    except OSError:
        return out
    if (stat.S_ISLNK(root_stat.st_mode)
            or bool(getattr(root_stat, "st_file_attributes", 0) & _REPARSE)):
        return ["<skipped link: .>"]
    if not stat.S_ISDIR(root_stat.st_mode):
        return out
    try:
        root_resolved = Path(os.path.realpath(root))
    except OSError:
        return out

    def relative(p: Path) -> str:
        try:
            return p.relative_to(root).as_posix()
        except ValueError:
            return p.name

    def walk(directory: Path) -> bool:
        """True = complete; False = the entry cap was reached."""
        try:
            with os.scandir(directory) as it:
                entries = sorted(it, key=lambda e: e.name.lower())
        except OSError:
            return True
        for entry in entries:
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            p = Path(entry.path)
            rel = relative(p)
            is_link = (entry.is_symlink() or stat.S_ISLNK(st.st_mode)
                       or bool(getattr(st, "st_file_attributes", 0) & _REPARSE))
            if is_link:
                if len(out) >= limit:
                    return False
                out.append(f"<skipped link: {rel}>")
                continue
            try:
                Path(os.path.realpath(p)).relative_to(root_resolved)
            except (OSError, ValueError):
                if len(out) >= limit:
                    return False
                out.append(f"<skipped link: {rel}>")
                continue
            if stat.S_ISDIR(st.st_mode):
                if not walk(p):
                    return False
            elif stat.S_ISREG(st.st_mode):
                if len(out) >= limit:
                    return False
                out.append(rel)
        return True

    if not walk(root):
        out.append(f"<truncated: more than {limit} entries>")
    return out


_HARNESS_OUT = re.compile(r"^out/(?:(?:ready|session|done|fatal)\.json|c\d{3}\.(?:json|stdout|stderr))$")


_HASH_MAX = 16 * 1024 * 1024


def _file_state(root: Path, rel: str) -> tuple | None:
    """(size, mtime_ns, sha256-or-None) of a staged plain file; sha256 only for files <= 16 MiB. None: unreadable."""
    try:
        p = root / rel
        st = os.lstat(p)
        if not _is_plain_file(p):
            return None
        digest = None
        if st.st_size <= _HASH_MAX:
            h = hashlib.sha256()
            with open(p, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            digest = h.hexdigest()
        return (st.st_size, st.st_mtime_ns, digest)
    except OSError:
        return None


def _staged_baseline(root: Path) -> dict[str, tuple | None]:
    """Baseline of the host-staged files. The nonce file is not compared: the harness deletes it by design."""
    return {i: (None if Path(i).name == integrity.NONCE_FILE else _file_state(root, i))
            for i in _list_workdir_files(root) if not i.startswith("<")}


def _new_workdir_files(root: Path, staged: "set[str] | dict[str, tuple | None]") -> list[str]:
    """Side effects of the target: files in the work folder now that the host did not stage and the guest harness
    did not write itself (ready/session/done/fatal.json, cNNN.json/.stdout/.stderr). Markers (skipped links,
    truncation) are kept. A staged file whose size, mtime or SHA-256 changed is reported as `modified: <name>`, a
    missing one as `deleted: <name>`. Harness result files are always excluded."""
    now = _list_workdir_files(root)
    out = [i for i in now if i not in staged and not _HARNESS_OUT.match(i)]
    if isinstance(staged, dict):
        present = set(now)
        for name, before in staged.items():
            if _HARNESS_OUT.match(name) or before is None:
                continue
            if name not in present:
                out.append(f"deleted: {name}")
            elif _file_state(root, name) != before:
                out.append(f"modified: {name}")
    return out


def _is_plain_file(p: Path) -> bool:
    try:
        st = os.lstat(p)
    except OSError:
        return False
    return (stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode)
            and not (getattr(st, "st_file_attributes", 0) & _REPARSE))


def _read_plain(p: Path, limit: int) -> bytes | None:
    """None: absent. _BadOutput: not a plain file (symlink/junction/directory). Reads at most limit+1 bytes."""
    if not os.path.lexists(p):
        return None
    if not _is_plain_file(p):
        raise _BadOutput(f"{p.name}: not a plain file (symlink/junction/directory)")
    with open(p, "rb") as f:
        return f.read(limit + 1)


def _read_json(p: Path) -> dict | None:
    raw = _read_plain(p, _JSON_MAX)
    if raw is None:
        return None
    if len(raw) > _JSON_MAX:
        raise _BadOutput(f"{p.name}: too large")
    try:
        doc = json.loads(raw.decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError) as e:
        raise _BadOutput(f"{p.name}: not JSON ({e})") from e
    if not isinstance(doc, dict):
        raise _BadOutput(f"{p.name}: not a JSON object")
    return doc


def _fail(run_id: str, sha: str, status: Status, code: str, detail: str, t0: float, **kw) -> SandboxRun:
    return SandboxRun(run_id, sha, status, code, detail, duration_s=time.monotonic() - t0, **kw)


def _kernel_problem(src: Path) -> str | None:
    """Header-only check of the staged target: kernel-mode images (NATIVE subsystem, WDM driver flag) cannot run as a
    Win32 process; the run is refused before any sandbox is touched. Unparseable headers are not a kernel finding."""
    try:
        with open(src, "rb") as fh:
            size = os.fstat(fh.fileno()).st_size

            def read(off: int, n: int) -> bytes:
                fh.seek(off)
                return fh.read(n)
            why = kernel_mode_reasons(parse_pe(read, size))
    except (OSError, PeError):
        return None
    if not why:
        return None
    return "kernel-mode image (" + "; ".join(why) + "); it is never run in Win32 mode. Static tools still work."


def _scope_problem(scope: Any, target_sha: str) -> str | None:
    if scope is None or not isinstance(scope, ScopeManifest):
        return "scope manifest is required"
    if not scope.allows("run_controlled"):
        return "scope manifest does not allow 'run_controlled'"
    if target_sha not in (scope.target_sha256, getattr(scope, "fixed_target_sha256", None)):
        return "scope manifest target SHA-256 does not match the requested target"
    if scope.expires:
        try:
            exp = (datetime.fromisoformat(scope.expires) if "T" in scope.expires
                   else datetime.fromisoformat(scope.expires + "T23:59:59.999999"))
        except ValueError:
            return "scope manifest expires could not be parsed"
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp < datetime.now(timezone.utc):
            return f"scope manifest has expired: {scope.expires}"
    return None


def _support_problem(files: Any) -> tuple[list[Path], str | None]:
    """support_files check: name pattern, plain file, count/size limit, no duplicates."""
    if not files:
        return [], None
    if isinstance(files, (str, os.PathLike)) or len(files) > MAX_SUPPORT_FILES:
        return [], f"support_files must be a list of at most {MAX_SUPPORT_FILES} files"
    out: list[Path] = []
    total = 0
    for f in files:
        p = Path(f)
        if not _SAFE_SUPPORT.fullmatch(p.name):
            return [], f"support_files: invalid file name {p.name[:70]!r} (only [A-Za-z0-9._-]+.dll)"
        if not _is_plain_file(p):
            return [], f"support_files: {p.name} is not a plain file / missing"
        if any(q.name.lower() == p.name.lower() for q in out):
            return [], f"support_files: {p.name} is duplicated"
        total += p.stat().st_size
        out.append(p)
    if total > MAX_SUPPORT_BYTES:
        return [], "support_files total size too large"
    return out, None


def _observe_problem(observe: Any, n: int) -> str | None:
    if observe is None:
        return None
    if not isinstance(observe, ObservePlan):
        return "observe must be an ObservePlan"
    t = observe.tool
    if not _SAFE_NAME.fullmatch(t.name) or not isinstance(t.sha256, str) or not _SHA.fullmatch(t.sha256):
        return "observe tool name/SHA-256 invalid"
    if not _is_plain_file(Path(t.path)):
        return "observe tool is not a plain file / missing"
    if len(observe.args) != n or not all(isinstance(a, str) and _SAFE_ARGS.fullmatch(a) for a in observe.args):
        return "observe args must give one numeric argument prefix per case"
    ts = observe.timeout_s
    if isinstance(ts, bool) or not isinstance(ts, (int, float)) or not 0 < ts <= MAX_OBSERVE_TIMEOUT_S:
        return f"observe timeout_s must be in (0, {MAX_OBSERVE_TIMEOUT_S:g}]"
    return None


def _input_problem(inputs: Any, timeout_s: Any) -> str | None:
    if isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float)) or not 0 < timeout_s <= MAX_TIMEOUT_S:
        return f"timeout_s must be a number between 0 and {MAX_TIMEOUT_S:g}"
    if not isinstance(inputs, (list, tuple)) or not inputs:
        return "inputs must be a non-empty list of RunCase"
    if len(inputs) > MAX_CASES:
        return f"at most {MAX_CASES} cases"
    for i, c in enumerate(inputs):
        if not isinstance(c, RunCase):
            return f"inputs[{i}] is not a RunCase"
        if c.stdin is not None and not isinstance(c.stdin, str):
            return f"inputs[{i}].stdin must be text"
        if len(c.stdin_bytes()) > MAX_STDIN_BYTES:
            return f"inputs[{i}].stdin is larger than {MAX_STDIN_BYTES} bytes"
        if len(c.argv) > MAX_ARGV or not all(isinstance(a, str) and "\0" not in a for a in c.argv):
            return f"inputs[{i}].argv invalid (list of strings, no NUL, at most {MAX_ARGV})"
        if len(subprocess.list2cmdline(list(c.argv))) > 8000:
            return f"inputs[{i}].argv too long"
    return None


# ---------------------------------------------------------------- journal / recovery

def _open_runs(journal: Journal) -> dict[str, str]:
    """Sessions without a finish (verified closure): run_id -> 'started' | 'not_closed'."""
    open_: dict[str, str] = {}
    for ev in journal.events():
        p = ev["payload"] if isinstance(ev["payload"], dict) else {}
        rid = p.get("run_id")
        if not rid:
            continue
        if ev["type"] == "SANDBOX_STARTED":
            open_[rid] = "started"
        elif ev["type"] == "SANDBOX_FINISHED":
            if p.get("closed") is True:
                open_.pop(rid, None)
            else:
                open_[rid] = "not_closed"
        elif ev["type"] == "SANDBOX_RUN_FAILED":
            open_.pop(rid, None)
    return open_


def run_status(cfg: Config, run_id: str) -> str | None:
    """Session state from the journal: STARTED | FINISHED | FAILED | None (unknown). Needs no lock."""
    jp = sandbox_dir(cfg) / "journal.jsonl"
    if not jp.exists():
        return None
    state = None
    with Journal(jp) as j:
        for ev in j.events():
            p = ev["payload"] if isinstance(ev["payload"], dict) else {}
            if p.get("run_id") != run_id:
                continue
            state = {"SANDBOX_STARTED": "STARTED", "SANDBOX_FINISHED": "FINISHED",
                     "SANDBOX_RUN_FAILED": "FAILED"}.get(ev["type"], state)
    return state


def _recorded_procs(journal: Journal) -> dict[str, list[dict]]:
    """run_id -> sandbox processes WE started for that run (SANDBOX_PROCS events; written right after launch)."""
    out: dict[str, list[dict]] = {}
    for ev in journal.events():
        p = ev["payload"] if isinstance(ev["payload"], dict) else {}
        if ev["type"] == "SANDBOX_PROCS" and p.get("run_id"):
            out.setdefault(p["run_id"], []).extend(r for r in p.get("procs", []) if isinstance(r, dict))
    return out


def _recover(cfg: Config, journal: Journal, backend: SandboxBackend) -> tuple[list[str], str | None]:
    """Called UNDER the lock. (run_ids marked FAILED, error detail). If there is an error no run is made.

    Ownership rule: only the Windows Sandbox processes recorded for the half-finished run (pid + creation time, written
    to the journal right after launch) are killed. A sandbox someone else started is never touched; it stays and a
    following run_controlled answers BUSY. A run without recorded processes (the host died before they were noted)
    cannot be attributed, so its processes are left alone as well and reported as `foreign_pids_left`."""
    open_ = _open_runs(journal)
    root = workdir_root(cfg)
    leftovers = [d for d in root.iterdir() if d.name not in open_] if root.is_dir() else []
    if not open_ and not leftovers:
        return [], None
    failed: list[str] = []
    if open_:
        recorded = _recorded_procs(journal)
        owner_api = hasattr(backend, "kill_owned") and hasattr(backend, "alive_owned")
        alive: dict[str, list[int]] = {}
        remaining_all: list[int] = []
        for rid in sorted(open_):
            mine = recorded.get(rid, []) if owner_api else []
            if not mine:
                alive[rid] = []
                continue
            try:
                alive[rid] = list(backend.alive_owned(mine))
            except (OSError, subprocess.SubprocessError):
                alive[rid] = []
            remaining_all += backend.kill_owned(mine, KILL_WAIT_S)
        if remaining_all:
            return [], (f"sandbox processes for half-finished session {sorted(open_)} could not be closed "
                        f"(PID: {remaining_all}); no new session opened")
        try:
            foreign = backend.running_processes()
        except (OSError, subprocess.SubprocessError):
            foreign = []
        for rid, phase in sorted(open_.items()):
            wd = root / rid
            removed = _rmtree(wd) if os.path.lexists(wd) else True
            journal.append("SANDBOX_RUN_FAILED", {
                "run_id": rid, "reason": Code.INTERRUPTED if phase == "started" else Code.SANDBOX_NOT_CLOSED,
                "killed_pids": alive[rid], "foreign_pids_left": foreign, "workdir_removed": removed})
            failed.append(rid)
    for d in leftovers:  # leftover folders unrelated to the journal (we hold the lock: no active session possible)
        _rmtree(d)
    return failed, None


def pending_recovery(cfg: Config) -> bool:
    """Cheap, lock-free check: does the sandbox journal hold a session without a verified close, or a leftover work folder?"""
    root = workdir_root(cfg)
    if root.is_dir() and any(root.iterdir()):
        return True
    jp = sandbox_dir(cfg) / "journal.jsonl"
    if not jp.exists():
        return False
    try:
        return bool(_open_runs_from_file(jp))
    except JournalCorrupt:
        return True


def _open_runs_from_file(path: Path) -> dict[str, str]:
    """Read-only variant of _open_runs (does not truncate a torn tail: it only parses the complete lines)."""
    data = path.read_bytes()
    keep = data.rfind(b"\n") + 1
    tmp: dict[str, str] = {}
    for line in data[:keep].splitlines():
        try:
            ev = json.loads(line)
        except ValueError as e:
            raise JournalCorrupt(str(e)) from e
        p = ev.get("payload") if isinstance(ev.get("payload"), dict) else {}
        rid = p.get("run_id")
        if not rid:
            continue
        t = ev.get("type")
        if t == "SANDBOX_STARTED":
            tmp[rid] = "started"
        elif t == "SANDBOX_FINISHED":
            if p.get("closed") is True:
                tmp.pop(rid, None)
            else:
                tmp[rid] = "not_closed"
        elif t == "SANDBOX_RUN_FAILED":
            tmp.pop(rid, None)
    return tmp


def recover_interrupted(cfg: Config | None = None, backend: SandboxBackend | None = None) -> SandboxRun:
    """Called at startup: cleans up half-finished sandbox sessions and marks them FAILED.
    run_id='recovery'; recovered_runs is filled. BUSY if the lock is held."""
    cfg = cfg or Config.load()
    backend = backend or WindowsSandboxBackend()
    t0 = time.monotonic()
    rid = "recovery"
    lock = JobLock(sandbox_dir(cfg) / "sandbox.lock")
    glock = sandbox_global_lock()
    try:
        glock.acquire()
    except LockError as e:
        return _fail(rid, "", Status.ERROR, Code.BUSY, f"could not acquire the global sandbox lock: {e}", t0)
    try:
        lock.acquire()
    except LockError as e:  # includes LockHeldError
        glock.release()
        return _fail(rid, "", Status.ERROR, Code.BUSY, f"could not acquire the sandbox lock: {e}", t0)
    try:
        try:
            journal = Journal(sandbox_dir(cfg) / "journal.jsonl")
        except JournalCorrupt as e:
            return _fail(rid, "", Status.ERROR, Code.JOURNAL_CORRUPT, f"sandbox journal corrupt: {e}", t0)
        try:
            failed, err = _recover(cfg, journal, backend)
        finally:
            journal.close()
        if err:
            return _fail(rid, "", Status.ERROR, Code.RECOVERY_FAILED, err, t0)
        return SandboxRun(rid, "", Status.OK, None, "", recovered_runs=failed, duration_s=time.monotonic() - t0)
    finally:
        lock.release()
        glock.release()


# ---------------------------------------------------------------- main entry

def run_controlled(target_sha: str, scope: ScopeManifest, inputs: Sequence[RunCase], timeout_s: float, *,
                   cfg: Config | None = None, backend: SandboxBackend | None = None,
                   target_path: str | os.PathLike | None = None,
                   boot_allowance_s: float | None = None, poll_interval_s: float = 0.25,
                   proc_check_interval_s: float | None = None,
                   max_stream_bytes: int = MAX_STREAM_BYTES, retry_backoff_s: float | None = None,
                   support_files: Sequence[str | os.PathLike] = (), observe: ObservePlan | None = None) -> SandboxRun:
    """Runs the target (target_sha) inside Windows Sandbox with `inputs`, in order, in a single session.

    timeout_s is PER CASE. Target file: `target_path`, otherwise CAS (`cfg.cas_dir`, the copy target_open wrote).
    No expected output is given; the result is only observed. Expected situations (rejection, BUSY, timeout...) are not
    exceptions; they are returned as `SandboxRun.status/code`.

    support_files (optional): `.dll` files to place next to the target (read-only input folder `in/bin`), e.g. the
    VC++ runtime from the host's System32 (the sandbox is a clean Windows; no vcruntime140_1.dll etc.). Only file
    names `[A-Za-z0-9._-]+.dll`, at most 8 files, 16 MB total; their names + SHA-256 are written to the journal.

    observe (optional, dynamic observation): after the plain cases every case runs once more under the pinned tool in the
    SAME session; results in `SandboxRun.observed` (`cases`, `status` and the isolation level stay those of the plain
    cases). Without `observe` the session is exactly as before.
    """
    t0 = time.monotonic()
    run_id = f"sbx_{_now()}_{uuid.uuid4().hex[:8]}"
    cfg = cfg or Config.load()
    backend = backend or WindowsSandboxBackend()

    def fail(status, code, detail, **kw):
        return _fail(run_id, target_sha if isinstance(target_sha, str) else "", status, code, detail, t0, **kw)

    # 1. cheap rejections (before the lock)
    if not isinstance(target_sha, str) or not _SHA.fullmatch(target_sha):
        return fail(Status.ERROR, Code.INVALID_INPUT, "target_sha must be 64 lowercase hex characters")
    prob = _input_problem(inputs, timeout_s)
    if prob:
        return fail(Status.ERROR, Code.INVALID_INPUT, prob)
    prob = _scope_problem(scope, target_sha)
    if prob:
        return fail(Status.ERROR, Code.SCOPE_DENIED, prob)
    support, prob = _support_problem(support_files)
    if prob:
        return fail(Status.ERROR, Code.INVALID_INPUT, prob)
    prob = _observe_problem(observe, len(inputs))
    if prob:
        return fail(Status.ERROR, Code.INVALID_INPUT, prob)
    src = Path(target_path) if target_path is not None else Cas(cfg.cas_dir).path_for(target_sha)
    if not src.is_file():
        return fail(Status.ERROR, Code.TARGET_MISSING, "target file not found (not in CAS nor at target_path)")
    try:
        actual = sha256_file(src)
    except OSError as e:
        return fail(Status.ERROR, Code.TARGET_MISSING, f"target unreadable: {e}")
    if actual != target_sha:
        return fail(Status.ERROR, Code.SHA_MISMATCH, f"target SHA-256 mismatch: file {actual}, requested {target_sha}")
    kernel = _kernel_problem(src)   # whatever the scope manifest says: a driver / NATIVE image is never run here
    if kernel:
        return fail(Status.ERROR, Code.KERNEL_TARGET_NO_USERMODE_RUN, kernel)
    ok, why = backend.available()
    if not ok:
        return fail(Status.TOOL_MISSING, Code.SANDBOX_UNAVAILABLE, why)
    exe_name = src.name if target_path is not None and _SAFE_NAME.fullmatch(src.name) else "target.exe"

    # 2. locks (non-blocking): machine-wide single-sandbox lock, heavy-engine lock, data-root lock
    glock, hlock = sandbox_global_lock(), heavy_lock()
    lock = JobLock(sandbox_dir(cfg) / "sandbox.lock")
    try:
        glock.acquire()
    except LockError as e:
        return fail(Status.ERROR, Code.BUSY, f"another sandbox session is in progress (machine-wide lock): {e}")
    try:
        hlock.acquire()
    except LockError as e:
        glock.release()
        return fail(Status.ERROR, Code.BUSY,
                    f"a heavy engine job such as IDA/Ghidra is in progress (heavy lock); sandbox not started, retry when it finishes: {e}")
    try:
        lock.acquire()
    except LockError as e:
        hlock.release()
        glock.release()
        return fail(Status.ERROR, Code.BUSY, f"another controlled run is in progress (sandbox lock): {e}")
    journal = None
    try:
        try:
            journal = Journal(sandbox_dir(cfg) / "journal.jsonl")
        except JournalCorrupt as e:
            return fail(Status.ERROR, Code.JOURNAL_CORRUPT, f"sandbox journal corrupt, no silent repair: {e}")
        # 3. half-finished session recovery
        recovered, err = _recover(cfg, journal, backend)
        if err:
            return fail(Status.ERROR, Code.RECOVERY_FAILED, err, recovered_runs=recovered)
        try:
            foreign = backend.running_processes()
        except (OSError, subprocess.SubprocessError) as e:
            return fail(Status.ERROR, Code.SANDBOX_UNAVAILABLE, f"could not list sandbox processes: {e}",
                        recovered_runs=recovered)
        if foreign:
            return fail(Status.ERROR, Code.BUSY,
                        f"another Windows Sandbox instance is running (PID {foreign}); not closed, no second instance opened",
                        recovered_runs=recovered)
        # defaults are resolved AT CALL TIME (unit tests shorten the waits by changing the module constants);
        # host-resource pre-check and the machine-wide failure cool-down live in _run_locked (shared with compute)
        backoff_s = RETRY_BACKOFF_S if retry_backoff_s is None else retry_backoff_s
        res = _run_locked(cfg, backend, journal, run_id, target_sha, src, exe_name, list(inputs), float(timeout_s),
                           recovered, t0, BOOT_ALLOWANCE_S if boot_allowance_s is None else boot_allowance_s,
                           poll_interval_s,
                           PROC_CHECK_INTERVAL_S if proc_check_interval_s is None else proc_check_interval_s,
                           max_stream_bytes, backoff_s, support, observe)
        return res
    finally:
        if journal is not None:
            journal.close()
        lock.release()
        hlock.release()
        glock.release()


def _preflight(backend, backoff: "hostres.Backoff", base_s: float) -> str | None:
    """Reason NOT to launch (explicit RESOURCE_UNAVAILABLE, instantly, no launch), else None. (1) the machine-wide
    cool-down after repeated failed starts; (2) host RAM/commit headroom below the sandbox's memory request; (3) a short
    exponential backoff, which is waited out. 0x800705AA can also occur with plenty of free memory and at any
    MemoryInMB, so (2) is only a floor; (1) is what stops the stream of error dialogs."""
    if backoff.cooling_down():
        wait = backoff.remaining()
        return (f"the last {backoff.failures()} sandbox starts failed in a row; no start is attempted for another "
                f"{wait:.0f} s (retry_after_s={wait:.0f}). " + RESOURCE_HINT)
    fn = getattr(backend, "memory_status", None)
    if callable(fn):
        try:
            problem = hostres.headroom_problem(fn(), sandbox_memory_mb())
        except Exception:  # noqa: BLE001 - an unreadable status never blocks a run
            problem = None
        if problem:
            return problem + ". " + RESOURCE_HINT
    wait = backoff.remaining()
    if wait > 0:
        if wait > base_s * BACKOFF_MAX_WAIT_MULT:
            return (f"the previous sandbox start failed {backoff.failures()} time(s) in a row; cooling down, retry in "
                    f"{wait:.0f} s (retry_after_s={wait:.0f}); sandbox not started. " + RESOURCE_HINT)
        time.sleep(wait)
    return None


def _run_locked(cfg, backend, journal, run_id, target_sha, src, exe_name, inputs, timeout_s, recovered, t0,
                boot_allowance_s, poll_interval_s, proc_check_interval_s, max_stream_bytes,
                retry_backoff_s=RETRY_BACKOFF_S, support=(), observe: ObservePlan | None = None) -> SandboxRun:
    backoff = hostres.default_backoff(retry_backoff_s, BACKOFF_CAP_MULT)
    pre = _preflight(backend, backoff, retry_backoff_s)
    if pre:   # nothing is staged, nothing is launched: no dialog can appear
        return _fail(run_id, target_sha, Status.ERROR, Code.RESOURCE_UNAVAILABLE, pre, t0, recovered_runs=recovered)
    wd = workdir_root(cfg) / run_id
    in_dir, out_dir = wd / "in", wd / "out"
    run = SandboxRun(run_id, target_sha, Status.ERROR, Code.START_FAILED, "", recovered_runs=recovered)
    started = False
    staged: dict[str, tuple | None] = {}   # files the host put into the work folder (side-effect baseline)
    n_plain = len(inputs)
    all_inputs = list(inputs) + (list(inputs) if observe else [])
    timeouts = [timeout_s] * n_plain + ([float(observe.timeout_s)] * n_plain if observe else [])
    try:
        # 4. preparation
        (in_dir / "bin").mkdir(parents=True)
        out_dir.mkdir(parents=True)
        shutil.copyfile(src, in_dir / "bin" / exe_name)
        if sha256_file(in_dir / "bin" / exe_name) != target_sha:  # the source changed after verification
            run.code, run.detail = Code.SHA_MISMATCH, "target changed while being copied (copy SHA-256 mismatch)"
            return run
        support_meta = []
        for sp in support:  # support DLLs next to the target (the guest copies in/bin/* in every case)
            shutil.copyfile(sp, in_dir / "bin" / sp.name)
            support_meta.append({"name": sp.name, "sha256": sha256_file(in_dir / "bin" / sp.name)})
        run.support_files = support_meta
        if observe:   # the tool is staged read-only under in/tools; the guest copies it and re-checks the SHA-256
            (in_dir / "tools").mkdir()
            shutil.copyfile(observe.tool.path, in_dir / "tools" / observe.tool.name)
            if sha256_file(in_dir / "tools" / observe.tool.name) != observe.tool.sha256:
                run.code, run.detail = Code.SHA_MISMATCH, "observe tool changed while being copied (SHA-256 mismatch)"
                return run
            run.observe_tool = {"name": observe.tool.name, "sha256": observe.tool.sha256}
        cases = []
        for i, c in enumerate(all_inputs):
            entry = {"index": i, "argv_line": subprocess.list2cmdline(list(c.argv)),
                     "stdin_b64": base64.b64encode(c.stdin_bytes()).decode("ascii"), "timeout_s": timeouts[i]}
            if i >= n_plain:
                entry["observe"] = {"tool": observe.tool.name, "sha256": observe.tool.sha256,
                                    "args": observe.args[i - n_plain], "of": i - n_plain}
            cases.append(entry)
        spec = {"run_id": run_id, "exe": exe_name, "max_stream_bytes": max_stream_bytes, "cases": cases}
        (in_dir / "cases.json").write_text(json.dumps(spec, ensure_ascii=True), encoding="ascii")
        shutil.copyfile(GUEST_SCRIPT, in_dir / "guest.ps1")
        nonce = integrity.new_nonce()  # one-time; only in memory and in nonce.txt (DELETED once the guest has read it)
        (in_dir / integrity.NONCE_FILE).write_text(nonce, encoding="ascii")
        (in_dir / "run.cmd").write_bytes(RUN_CMD.encode("ascii"))
        wsb = wd / "run.wsb"
        wsb.write_text(render_wsb(in_dir, out_dir), encoding="utf-8")
        staged = _staged_baseline(wd)

        # 5. start (journal FIRST)
        journal.append("SANDBOX_STARTED", {
            "run_id": run_id, "target_sha256": target_sha, "cases": len(inputs), "host_pid": os.getpid(),
            "host_start_time": process_start_time(os.getpid()),
            "timeout_s_per_case": timeout_s, "isolation": ISOLATION, "support_files": support_meta,
            **({"observe": dict(run.observe_tool), "observed_cases": n_plain} if observe else {})})
        started = True
        span = boot_allowance_s + sum(t + PER_CASE_OVERHEAD_S for t in timeouts) + FINISH_SLACK_S
        resource_fail = False
        remaining: list[int] = []
        noted: set[tuple] = set()

        def note_procs() -> None:
            """Journal the sandbox processes WE started (pid + creation time) so a later process can clean up exactly these."""
            if not hasattr(backend, "owned_processes"):
                return
            try:
                new = [r for r in backend.owned_processes() if (r["pid"], r["start"]) not in noted]
            except Exception:  # noqa: BLE001 - listing trouble must not fail the run; recovery then leaves processes alone
                return
            if new:
                noted.update((r["pid"], r["start"]) for r in new)
                journal.append("SANDBOX_PROCS", {"run_id": run_id, "procs": new})

        for attempt in range(1, MAX_ATTEMPTS + 1):
            run.attempts = attempt
            try:
                backend.start(wsb)
                note_procs()
                outcome = _wait_done(backend, in_dir, out_dir, nonce, run_id, len(all_inputs),
                                     time.monotonic() + span, poll_interval_s, proc_check_interval_s, note_procs)
            except OSError as e:
                outcome = f"start_failed:{e}"

            # 6. close in every case, verify closure
            if outcome != "done" and hasattr(backend, "dismiss_start_error"):
                try:
                    backend.dismiss_start_error()   # only OUR dialog/processes; kill_all below verifies closure
                except Exception:  # noqa: BLE001
                    pass
            remaining = backend.kill_all(KILL_WAIT_S)
            # resource error: process could not start / closed before the ready marker (ready.json) or timed out
            resource_fail = (outcome.startswith("start_failed") or outcome in ("crashed", "timeout"))                 and not os.path.lexists(out_dir / "ready.json")
            if resource_fail:   # a launch that failed to come up moves the MACHINE-WIDE counter, per attempt
                backoff.record_failure()
                if backoff.cooling_down():   # the cool-down just engaged: no retry, no further dialog
                    break
            elif outcome == "done":
                backoff.record_success()
            if not resource_fail or remaining or attempt >= MAX_ATTEMPTS or outcome == "timeout":
                break
            # single retry: wait, clear the output (no ready marker: nonce.txt still in place), restart
            time.sleep(retry_backoff_s)
            if _memory_short(backend):   # still no headroom after the wait: do not launch into a certain failure
                break
            for f in out_dir.iterdir():
                if f.is_file() or f.is_symlink():
                    f.unlink()
                else:
                    _rmtree(f)
            if backend.running_processes():  # someone else opened a sandbox: do not open a second instance
                break
        run.sandbox_closed = not remaining
        if remaining:
            run.status, run.code = Status.ERROR, Code.SANDBOX_NOT_CLOSED
            run.detail = f"Windows Sandbox processes could not be closed (PID {remaining}); outputs UNTRUSTED, not read"
            run.cases = _error_cases(inputs, "sandbox did not close, so output was not read")
        else:
            _collect(run, all_inputs, out_dir, outcome, target_sha, Cas(cfg.cas_dir), max_stream_bytes, nonce,
                     n_plain)
            if resource_fail and run.code != Code.INTEGRITY and run.status is not Status.OK:
                run.status, run.code = Status.ERROR, Code.RESOURCE_UNAVAILABLE
                mem = ""
                try:
                    mem = " Host memory now: " + hostres.describe_memory(backend.memory_status()) + "."
                except Exception:  # noqa: BLE001 - diagnosis text only
                    pass
                run.detail = (f"Sandbox could not be started ({outcome}, {run.attempts} attempts)." + mem + " "
                              + RESOURCE_HINT)
        return run
    except OSError as e:
        run.status, run.code, run.detail = Status.ERROR, run.code or Code.START_FAILED, f"I/O error: {e}"
        if not run.cases:
            run.cases = _error_cases(inputs, "session ended with an I/O error")
        return run
    finally:
        if started:
            if run.sandbox_closed is None:  # unexpected exit (error/KeyboardInterrupt): do not leave the sandbox behind
                try:
                    run.sandbox_closed = not backend.kill_all(KILL_WAIT_S)
                except Exception:  # noqa: BLE001 - closure unverified = not closed
                    run.sandbox_closed = False
            # 'closed' only if closure was verified: an unclosed session stays open in the journal, the next call cleans it up
            journal.append("SANDBOX_FINISHED", {
                "run_id": run_id, "status": run.status.value, "code": run.code, "closed": run.sandbox_closed is True,
                "integrity_verified": run.integrity_verified, "isolation_level": run.isolation_level,
                "integrity_problems": run.integrity_problems, "cases": [c.summary() for c in run.cases],
                **({"observed": [c.summary() for c in run.observed]} if observe else {})})
        run.side_effects = _new_workdir_files(wd, staged)
        run.workdir_removed = _rmtree(wd)
        run.duration_s = time.monotonic() - t0


def _memory_short(backend) -> bool:
    fn = getattr(backend, "memory_status", None)
    if not callable(fn):
        return False
    try:
        return hostres.headroom_problem(fn(), sandbox_memory_mb()) is not None
    except Exception:  # noqa: BLE001
        return False


def _error_cases(inputs, detail: str) -> list[CaseResult]:
    return [CaseResult(i, c.argv, c.stdin, sha256_bytes(c.stdin_bytes()), Status.ERROR, detail)
            for i, c in enumerate(inputs)]


def _ack(in_dir: Path, out_dir: Path, nonce: str, run_id: str) -> str | None:
    """The guest reported it read the nonce (ready.json): verify, DELETE the nonce file. Returns the text if there is a problem.
    The guest waits for this deletion and starts the target only afterwards: while the target runs the nonce is in no file."""
    try:
        doc = _read_json(out_dir / "ready.json")
    except _BadOutput as e:
        return str(e)
    if (doc or {}).get("run_id") != run_id:
        return "ready.json run_id mismatch"
    c = (doc or {}).get("nonce_commit")
    if not isinstance(c, str) or c != integrity.nonce_commit(nonce):
        return "ready.json nonce mismatch (guest read a different nonce)"
    try:
        (in_dir / integrity.NONCE_FILE).unlink(missing_ok=True)
    except OSError as e:
        return f"nonce file could not be deleted: {e}"
    return None


def _done_valid(out_dir: Path, nonce: str, run_id: str, n: int) -> bool:
    """done.json counts as completion only if its MAC is valid: a fake done.json written by the target cannot end the session early."""
    try:
        done = _read_json(out_dir / "done.json")
        if done is None:
            return False
        macs = []
        for i in range(n):
            meta = _read_json(out_dir / f"c{i:03d}.json")
            macs.append(((meta or {}).get("integrity") or {}).get("mac"))
        if not all(isinstance(m, str) for m in macs):
            return False
        integrity.verify_done(done, nonce, run_id, macs)
        return True
    except (_BadOutput, integrity.IntegrityError, AttributeError, TypeError):
        return False


def _fatal_valid(out_dir: Path, nonce: str, acked: bool) -> bool:
    """fatal.json: trusted before the nonce is read (no target yet); afterwards only if MAC'd (no fake-fatal DoS)."""
    if not os.path.lexists(out_dir / "fatal.json"):
        return False
    if not acked:
        return True
    try:
        doc = _read_json(out_dir / "fatal.json")
    except _BadOutput:
        return False
    return doc is not None and integrity.fatal_valid(doc, nonce)


def _sig(p: Path) -> tuple | None:
    """File identity (stat; does NOT open the file). So the same file is not re-read in a loop: an open handle
    would block the guest from overwriting it via os.replace/Move-Item."""
    try:
        st = os.lstat(p)
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size, st.st_ino)


def _wait_done(backend, in_dir: Path, out_dir: Path, nonce: str, run_id: str, ncases: int, deadline: float,
               poll_s: float, proc_check_s: float, on_procs=None) -> str:
    """'done' | 'fatal' | 'timeout' | 'crashed' | 'integrity:<reason>'. First the nonce handshake (ready.json -> delete
    the nonce), then the MAC'd done/fatal. If the sandbox processes vanished after being seen (closed before finishing) -> crashed."""
    seen = False
    acked = False
    session_checked = False
    done_sig = None
    next_check = 0.0
    while True:
        try:
            if not acked and os.path.lexists(out_dir / "ready.json"):
                problem = _ack(in_dir, out_dir, nonce, run_id)
                if problem:
                    return f"integrity:{problem}"
                acked = True
            if acked:
                sig = _sig(out_dir / "done.json")
                if sig is not None and sig != done_sig:  # only a new/changed done.json is re-read
                    if _done_valid(out_dir, nonce, run_id, ncases):
                        return "done"
                    done_sig = sig  # read SUCCEEDED and done is invalid: this identity is not read again (not skipped on a transient read error)
            if acked and not session_checked:
                # session.json is written before the target starts: if its MAC is invalid the session is untrusted; report INTEGRITY
                # immediately instead of waiting the full time for a done.json (which cannot get a valid MAC) (fail-closed; not retried)
                try:
                    sess = _read_json(out_dir / "session.json")
                    if sess is not None:
                        session_checked = True
                        integrity.verify_session(sess, nonce, run_id)
                except integrity.IntegrityError as e:
                    return f"integrity:{e}"
                except _BadOutput:
                    pass
            if _fatal_valid(out_dir, nonce, acked):
                return "fatal"
        except _TRANSIENT_READ:
            # The guest is replacing the file right now via os.replace/Move-Item (Windows sharing violation / brief disappearance):
            # this is NOT a launch error; it is re-read on the next poll. If persistent the time runs out and _collect reports
            # the same error explicitly. (Nothing is accepted: an unreadable record is not counted as verified.)
            pass
        now = time.monotonic()
        if now >= deadline:
            return "timeout"
        if now >= next_check:
            next_check = now + proc_check_s
            try:
                pids = backend.running_processes()
            except (OSError, subprocess.SubprocessError):
                pids = None
            if pids:
                seen = True
                if on_procs is not None:
                    on_procs()   # sandbox helper processes appear over time: note the new ones
                if not acked and hasattr(backend, "start_error"):
                    # WindowsSandbox.exe does NOT exit on a start failure (0x800705AA): it shows a dialog and waits.
                    # Seeing it for a process WE launched ends the attempt now instead of after the whole timeout.
                    try:
                        err = backend.start_error()
                    except Exception:  # noqa: BLE001 - unknown is not a failure
                        err = None
                    if err:
                        return "start_failed:" + err[:200]
            elif pids is not None and seen:
                try:
                    if acked and _done_valid(out_dir, nonce, run_id, ncases):
                        return "done"
                except _TRANSIENT_READ:
                    next_check = 0.0  # a transient read error is not interpreted as 'crashed': look again on the next poll
                    time.sleep(poll_s)
                    continue
                return "crashed"
        time.sleep(poll_s)


def _collect(run: SandboxRun, inputs, out_dir: Path, outcome: str, target_sha: str, cas: Cas, cap: int,
             nonce: str, n_plain: int | None = None) -> None:
    n_plain = len(inputs) if n_plain is None else n_plain
    code: str | None = None
    detail = ""
    session = done = fatal = None
    try:
        session = _read_json(out_dir / "session.json")
        done = _read_json(out_dir / "done.json")
        fatal = _read_json(out_dir / "fatal.json")
    except _BadOutput as e:
        code, detail = Code.BAD_OUTPUT, str(e)

    # --- integrity: EVERY record the guest wrote is verified with the host's nonce and the bytes it read itself
    problems: list[str] = []
    if outcome.startswith("integrity:"):
        problems.append(outcome.split(":", 1)[1])
    if session is not None:
        try:
            integrity.verify_session(session, nonce, run.run_id)
        except integrity.IntegrityError as e:
            problems.append(str(e))
    raw_cases: list[tuple[CaseResult, bytes, bytes]] = []
    facts: list[integrity.CaseFacts] = []
    plain_facts: list[integrity.CaseFacts] = []   # the isolation level is that of the plain executions
    for i, c in enumerate(inputs):
        cr, out, err, why, f = _read_case(i, c, out_dir, nonce, run.run_id, cap)
        raw_cases.append((cr, out, err))
        if why:
            problems.append(why)
        elif f is not None:
            facts.append(f)
            if i < n_plain:
                plain_facts.append(f)
    if done is not None and not problems:
        try:
            if len(facts) != len(inputs):
                raise integrity.IntegrityError("done.json exists but some case records are missing (deleted)")
            integrity.verify_done(done, nonce, run.run_id, [f.mac for f in facts])
        except integrity.IntegrityError as e:
            problems.append(str(e))
    if problems:  # untrusted session: NO case is accepted, nothing is written to CAS, no evidence is produced
        run.integrity_verified = False
        run.integrity_problems = problems
        run.cases = []
        run.status, run.code = Status.ERROR, Code.INTEGRITY
        run.detail = ("INTEGRITY: " + "; ".join(problems))[:600]
        return

    # --- integrity intact: original logic (session status, case status)
    if outcome.startswith("start_failed"):
        code, detail = Code.START_FAILED, f"Windows Sandbox could not be started: {outcome.split(':', 1)[1]}"
    elif code is None and outcome == "timeout":
        code, detail = Code.SESSION_TIMEOUT, "session time ran out; sandbox processes killed"
    elif code is None and (outcome in ("crashed", "fatal") or fatal is not None):
        code = Code.SANDBOX_CRASHED
        detail = ("sandbox closed before finishing" if outcome == "crashed"
                  else "guest script failed" + (f": {fatal.get('error')}" if fatal else ""))
    elif code is None:
        if not done or done.get("run_id") != run.run_id or done.get("cases") != len(inputs):
            code, detail = Code.BAD_OUTPUT, "done.json run_id/case count does not match the expected"
    if code is None and (not session or session.get("run_id") != run.run_id):
        code, detail = Code.BAD_OUTPUT, "session.json missing or run_id mismatch"
    if code is None and session.get("target_sha256") != target_sha:
        code, detail = Code.GUEST_HASH_MISMATCH, "target SHA-256 inside the sandbox differs from the expected"

    level = integrity.isolation_level(plain_facts)
    cases = []
    for cr, out, err in raw_cases:
        _finish_case(cr, out, err, code, cas, cap)
        cr.isolation_level = level
        cases.append(cr)
    if code in (Code.GUEST_HASH_MISMATCH, Code.BAD_OUTPUT):
        for cr in cases:  # untrusted session: no case is accepted
            cr.status, cr.detail = Status.ERROR, (cr.detail + "; " if cr.detail else "") + code
    elif code is not None:
        for cr in cases:
            if cr.status is Status.OK:
                cr.status, cr.detail = Status.PARTIAL, f"session did not end cleanly ({code}); result counted as partial"
    cases, run.observed = cases[:n_plain], cases[n_plain:]
    run.cases = cases
    run.code, run.detail = code, detail
    run.integrity_verified = True if facts else None
    run.isolation_level = level
    order = [Status.ERROR, Status.MEMORY_LIMIT, Status.TIMEOUT, Status.PARTIAL, Status.LIMIT_REACHED]
    if code == Code.SESSION_TIMEOUT:
        run.status = Status.TIMEOUT
    elif code is not None:
        run.status = Status.ERROR
    else:
        run.status = next((s for s in order if any(c.status is s for c in cases)), Status.OK)
        bad = [c.index for c in cases if c.status is not Status.OK]
        if bad:
            run.detail = f"case(s) {bad} not OK"


def _int(v: Any) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None


def _read_case(i: int, c: RunCase, out_dir: Path, nonce: str, run_id: str, cap: int):
    """(result, stdout, stderr, integrity problem, verified facts). If the problem is not None the result is UNTRUSTED.
    A missing case record is NOT an integrity problem (session was cut off); an existing record is never used unverified."""
    tag = f"c{i:03d}"
    cr = CaseResult(i, c.argv, c.stdin, sha256_bytes(c.stdin_bytes()), Status.ERROR)
    try:
        meta = _read_json(out_dir / f"{tag}.json")
        if meta is None:
            cr.detail = "no result for this case (session cut off before finishing)"
            return cr, b"", b"", None, None
        out = _read_plain(out_dir / f"{tag}.stdout", cap)
        err = _read_plain(out_dir / f"{tag}.stderr", cap)
    except _BadOutput as e:
        # record/file exists but is unreadable (symlink, corrupt JSON...): may be forged -> untrusted
        return cr, b"", b"", f"{tag}: {e}", None
    if out is None or err is None:
        return cr, b"", b"", f"{tag}: output files missing (deleted)", None
    if meta.get("index") != i:
        return cr, b"", b"", f"{tag}: index mismatch", None
    try:
        # the bytes the host READ (up to cap+1) are verified
        facts = integrity.verify_case(meta, out, err, nonce, run_id, i)
    except integrity.IntegrityError as e:
        return cr, b"", b"", str(e), None
    if not facts.separate_user and not meta.get("launch_error"):
        # fail-closed: the design requires a separate user (runner memory/nonce); a result produced with weaker isolation is not accepted
        return cr, b"", b"", f"{tag}: target did not run as a separate user (separate_user=false)", None
    cr.integrity_verified = True
    cr.meta = meta
    return cr, out, err, None, facts


def _finish_case(cr: CaseResult, out: bytes, err: bytes, session_code: str | None, cas: Cas, cap: int) -> None:
    meta = cr.meta
    if meta is None:  # no record
        cr.status = Status.TIMEOUT if session_code == Code.SESSION_TIMEOUT else Status.ERROR
        return
    host_trunc = len(out) > cap or len(err) > cap
    cr.stdout, cr.stderr = out[:cap], err[:cap]
    cr.stdout_blob, cr.stderr_blob = cas.put(cr.stdout), cas.put(cr.stderr)
    cr.stdout_total = _int(meta.get("stdout_total")) or len(cr.stdout)
    cr.stderr_total = _int(meta.get("stderr_total")) or len(cr.stderr)
    cr.truncated = bool(meta.get("truncated")) or host_trunc or cr.stdout_total > cap or cr.stderr_total > cap
    cr.elapsed_ms = _int(meta.get("elapsed_ms")) or 0
    ec = meta.get("exit_code")
    ec = ec if isinstance(ec, int) and not isinstance(ec, bool) else None
    cr.timed_out = meta.get("timed_out") is True
    if meta.get("launch_error"):
        cr.status, cr.detail = Status.ERROR, f"target could not be launched: {str(meta['launch_error'])[:200]}"
    elif cr.timed_out:
        cr.status, cr.detail = Status.TIMEOUT, "case timed out (process tree killed)"
    elif cr.truncated:
        cr.exit_code = ec
        cr.status, cr.detail = Status.PARTIAL, f"output truncated (limit {cap} bytes/stream)"
    elif ec is not None:
        cr.exit_code, cr.status = ec, Status.OK
    else:
        cr.status, cr.detail = Status.ERROR, "exit code unavailable"
