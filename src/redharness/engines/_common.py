"""Common helpers for the engine backends (IDA and Ghidra).

`HEAVY`: memory budget: ONE heavy engine operation at a time within
the process; a second one (whichever engine) queues. Cross-process ordering is only a per-target file lock (no global semaphore).
"""

from __future__ import annotations

import hashlib
import re
import threading
import time
from pathlib import Path

from ..core.lock import JobLock, LockError
from ..core.result import Status
from .base import EngineResult, Page, split_error

SHA_RE = re.compile(r"^[0-9a-f]{64}$")
HEAVY = threading.Lock()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fail(status: Status, detail: str, t0: float, **kw) -> EngineResult:
    kw.setdefault("code", split_error(detail)[0])
    return EngineResult(status, None, detail, duration_s=time.monotonic() - t0, **kw)


def make_page(rows: list, offset: int, limit: int, make) -> Page:
    offset, limit = max(offset, 0), max(limit, 0)
    items = [make(r) for r in rows[offset:offset + limit]]
    return Page(items, len(rows), offset, offset + len(items) < len(rows))


def acquire_dir_lock(tdir: Path, wait_s: float) -> JobLock:
    """Acquires the `<tdir>.lock` lock, waiting up to `wait_s`; raises LockError if it cannot."""
    lock = JobLock(tdir.with_name(tdir.name + ".lock"))
    deadline = time.monotonic() + wait_s
    while True:
        try:
            lock.acquire()
            return lock
        except LockError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.5)


MASK64 = 0xFFFFFFFFFFFFFFFF


def disassembly_from_doc(doc: dict):
    """Backend result document -> `Disassembly`. For an inconsistent/truncated document returns (None, reason) (fail-closed)."""
    from .base import Disassembly, InsnInfo, OperandInfo
    try:
        rows = doc["insns"]
        if doc.get("counts", {}).get("insns", len(rows)) != len(rows):
            return None, "instruction count mismatch"
        items = []
        for r in rows:
            ops = tuple(OperandInfo(
                kind=o["k"], text=o["t"], reg=o.get("r", ""), base=o.get("b", ""), index=o.get("i", ""),
                scale=int(o.get("sc") or 0), disp=o.get("d"),
                value=None if o.get("v") is None else int(o["v"]) & MASK64, size=int(o.get("sz") or 0),
                sym=o.get("y", "") or "")
                for o in r["o"])
            items.append(InsnInfo(int(r["a"]), int(r["s"]), r["b"], r["m"], ops, r["t"]))
        total = int(doc["total"])
        full = bool(doc["full"])
        if total < len(items) or (full and total != len(items)):
            return None, "total instruction count inconsistent"
        fa = doc.get("function_address")
        return Disassembly(items, None if fa is None else int(fa), doc.get("function_name", ""), total, full,
                           doc.get("stop_reason", "")), ""
    except (KeyError, TypeError, ValueError) as e:
        return None, f"field missing/corrupt: {e}"


def call_args_from_doc(doc: dict):
    """Backend `callargs` document -> {call VA: stack-parameter bytes | None}; (None, reason) when inconsistent."""
    try:
        rows = doc["calls"]
        if doc.get("counts", {}).get("calls", len(rows)) != len(rows):
            return None, "call count mismatch"
        out: dict[int, int | None] = {}
        for r in rows:
            e = r.get("e")
            if e is not None and (not isinstance(e, int) or isinstance(e, bool) or not 0 <= e <= 0x10000):
                return None, f"bad parameter extent at 0x{int(r['a']):x}"
            out[int(r["a"])] = e
        return out, ""
    except (KeyError, TypeError, ValueError) as e:
        return None, f"field missing/corrupt: {e}"


def bodies_from_doc(doc: dict):
    """Backend `disasm_funcs` document -> `FunctionBodies`; (None, reason) when inconsistent/truncated (fail-closed)."""
    from .base import FunctionBodies, FunctionBody
    try:
        rows = doc["functions"]
        if doc.get("counts", {}).get("functions", len(rows)) != len(rows):
            return None, "function count mismatch"
        items = []
        for r in rows:
            dis, bad = disassembly_from_doc(r)
            if dis is None:
                return None, f"function 0x{int(r.get('function_address', 0)):x}: {bad}"
            items.append(FunctionBody(int(r["function_address"]), str(r["function_name"]), int(r["size"]), dis))
        total, nxt = int(doc["function_total"]), doc.get("next_index")
        first = int(doc.get("first", 0))
        if nxt is not None and (not isinstance(nxt, int) or isinstance(nxt, bool) or nxt != first + len(items)):
            return None, "next_index inconsistent"
        if nxt is None and first + len(items) != total:
            return None, "chunk ends before the last function without a next_index"
        return FunctionBodies(items, total, nxt), ""
    except (KeyError, TypeError, ValueError) as e:
        return None, f"field missing/corrupt: {e}"
