"""Append-only, hash-chained event journal (JSONL), fsync'd after every line.

Line: {seq, ts, type, payload, prev_hash, hash}. hash = sha256(canonical JSON(seq, ts, type, payload, prev_hash)).
On open, a last line not ending in a newline (torn write) is truncated; if the chain is broken,
JournalCorrupt is raised, there is no silent repair.

DECISION (last line has a newline but a corrupt body): EXPLICIT ERROR (JournalCorrupt), NO truncation. Why: append()
writes each event as line + newline in a single os.write; a torn write (process/power loss) leaves the newline
last, so it always produces a tail WITHOUT a newline. A line that has a newline but bad JSON or a mismatched hash
therefore CANNOT be a torn write; it is tampering or disk corruption. Truncating it would silently destroy
possible evidence (chain integrity is the whole point of the journal). The operator inspects the file and decides.
Verification happens BEFORE truncation: on a corrupt file the error is raised without modifying the file bytes.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

GENESIS_HASH = "0" * 64


class JournalCorrupt(Exception):
    pass


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def event_hash(seq: int, ts: str, type_: str, payload: Any, prev_hash: str) -> str:
    return sha256_hex(canonical(
        {"seq": seq, "ts": ts, "type": type_, "payload": payload, "prev_hash": prev_hash}))


def atomic_write_bytes(path: str | os.PathLike, data: bytes) -> None:
    """tmp + fsync + os.replace."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


@dataclass(frozen=True)
class VerifyReport:
    ok: bool
    count: int
    last_hash: str
    error: str | None = None


def _iter_verified(data: bytes) -> Iterator[dict]:
    if not data:
        return
    lines = data.split(b"\n")
    if lines[-1] == b"":
        lines.pop()
    prev, expect_seq = GENESIS_HASH, 1
    for lineno, raw in enumerate(lines, 1):
        try:
            ev = json.loads(raw.decode("utf-8"))
            seq, ts, typ, payload = ev["seq"], ev["ts"], ev["type"], ev["payload"]
            prev_hash, h = ev["prev_hash"], ev["hash"]
        except (ValueError, KeyError, TypeError) as e:
            raise JournalCorrupt(f"line {lineno}: could not parse ({e!r})") from e
        if seq != expect_seq:
            raise JournalCorrupt(f"line {lineno}: seq {seq}, expected {expect_seq}")
        if prev_hash != prev:
            raise JournalCorrupt(f"line {lineno}: prev_hash chain broken")
        if event_hash(seq, ts, typ, payload, prev_hash) != h:
            raise JournalCorrupt(f"line {lineno}: hash mismatch (tampering)")
        prev, expect_seq = h, expect_seq + 1
        yield ev


def verify_file(path: str | os.PathLike) -> VerifyReport:
    """Read-only verification (does not truncate the torn tail; every corruption, including a tail without newline, counts as an error)."""
    p = Path(path)
    if not p.exists():
        return VerifyReport(True, 0, GENESIS_HASH)
    data = p.read_bytes()
    if data and not data.endswith(b"\n"):
        return VerifyReport(False, 0, GENESIS_HASH, "tail without newline (torn)")
    n, last = 0, GENESIS_HASH
    try:
        for ev in _iter_verified(data):
            n, last = n + 1, ev["hash"]
    except JournalCorrupt as e:
        return VerifyReport(False, n, last, str(e))
    return VerifyReport(True, n, last)


class Journal:
    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._mu = threading.Lock()
        self._failed = False
        data = self.path.read_bytes() if self.path.exists() else b""
        keep = data.rfind(b"\n") + 1  # complete lines, excluding a tail without newline
        self._seq, self._last_hash = 0, GENESIS_HASH
        for ev in _iter_verified(data[:keep]):  # verify first: if corrupt, raise JournalCorrupt without touching the file
            self._seq, self._last_hash = ev["seq"], ev["hash"]
        self.torn_bytes_dropped = self._drop_torn_tail(keep, len(data))
        self._fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0))

    def _drop_torn_tail(self, keep: int, total: int) -> int:
        if keep == total:
            return 0
        with open(self.path, "r+b") as f:
            f.truncate(keep)
            f.flush()
            os.fsync(f.fileno())
        return total - keep

    @property
    def last_hash(self) -> str:
        return self._last_hash

    @property
    def seq(self) -> int:
        return self._seq

    def append(self, type_: str, payload: Any = None) -> dict:
        with self._mu:
            if self._failed:
                raise JournalCorrupt("previous write failed; the journal must be reopened")
            seq = self._seq + 1
            ts = datetime.now(timezone.utc).isoformat(timespec="microseconds")
            payload = {} if payload is None else payload
            h = event_hash(seq, ts, type_, payload, self._last_hash)
            ev = {"seq": seq, "ts": ts, "type": type_, "payload": payload,
                  "prev_hash": self._last_hash, "hash": h}
            line = canonical(ev) + b"\n"
            try:
                if os.write(self._fd, line) != len(line):
                    raise OSError("partial write")
                os.fsync(self._fd)
            except BaseException:
                self._failed = True
                raise
            self._seq, self._last_hash = seq, h
            return ev

    def events(self) -> list[dict]:
        return list(_iter_verified(self.path.read_bytes()))

    def replay(self, reducer: Callable[[Any, dict], Any], initial: Any) -> Any:
        state = initial
        for ev in self.events():
            state = reducer(state, ev)
        return state

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def __enter__(self) -> "Journal":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def state_hash(state: Any) -> str:
    return sha256_hex(canonical(state))


def write_snapshot(path: str | os.PathLike, state: Any, journal: Journal) -> None:
    doc = {"state": state, "state_hash": state_hash(state),
           "last_seq": journal.seq, "last_event_hash": journal.last_hash}
    atomic_write_bytes(path, canonical(doc))


def load_snapshot(path: str | os.PathLike, journal: Journal,
                  reducer: Callable[[Any, dict], Any], initial: Any) -> Any:
    """Returns the snapshot if it matches the last event, otherwise the state replayed from the events (and writes it)."""
    p = Path(path)
    if p.exists():
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
            if (doc["last_event_hash"] == journal.last_hash
                    and doc["state_hash"] == state_hash(doc["state"])):
                return doc["state"]
        except (ValueError, KeyError, TypeError):
            pass
    state = journal.replay(reducer, initial)
    write_snapshot(p, state, journal)
    return state
