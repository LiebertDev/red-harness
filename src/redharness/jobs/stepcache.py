"""Step cache. Key = sha256(tool, version, canonical arguments, target SHA, engine version).

A finished step (STEP_FINISHED + intact result file) does not run again. One with STEP_STARTED that never finished runs.
Results must be JSON-serializable. A cache hit is not written to the journal (state stays deterministic).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ..core.journal import Journal, atomic_write_bytes, canonical, sha256_hex


def step_key(tool: str, args: Any, target_sha256: str, *, tool_version: str = "",
             engine_version: str = "") -> str:
    return sha256_hex(canonical({"tool": tool, "tool_version": tool_version, "args": args,
                                 "target_sha256": target_sha256, "engine_version": engine_version}))


@dataclass(frozen=True)
class StepOutcome:
    key: str
    result: Any
    cached: bool


class StepCache:
    def __init__(self, journal: Journal, steps_dir: str | Path):
        self.journal = journal
        self.dir = Path(steps_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._finished: dict[str, str] = {}
        for ev in journal.events():
            if ev["type"] == "STEP_FINISHED":
                self._finished[ev["payload"]["key"]] = ev["payload"]["digest"]
            elif ev["type"] == "STEP_CACHE_INVALID":
                self._finished.pop(ev["payload"]["key"], None)

    @property
    def finished_count(self) -> int:
        return len(self._finished)

    def _path(self, key: str) -> Path:
        return self.dir / f"{key}.json"

    def _lookup(self, key: str) -> tuple[bool, Any]:
        digest = self._finished.get(key)
        if digest is None:
            return False, None
        try:
            result = json.loads(self._path(key).read_text(encoding="utf-8"))["result"]
            if sha256_hex(canonical(result)) == digest:
                return True, result
        except (OSError, ValueError, KeyError):
            pass
        self.journal.append("STEP_CACHE_INVALID", {"key": key})
        del self._finished[key]
        return False, None

    def run(self, tool: str, args: Any, target_sha256: str, fn: Callable[[], Any], *,
            tool_version: str = "", engine_version: str = "") -> StepOutcome:
        key = step_key(tool, args, target_sha256, tool_version=tool_version, engine_version=engine_version)
        hit, result = self._lookup(key)
        if hit:
            return StepOutcome(key, result, True)
        self.journal.append("STEP_STARTED", {"key": key, "tool": tool})
        try:
            result = fn()
            digest = sha256_hex(canonical(result))
        except BaseException as e:
            self.journal.append("STEP_FAILED", {"key": key, "tool": tool, "error": repr(e)})
            raise
        atomic_write_bytes(self._path(key), canonical({"key": key, "result": result}))
        self.journal.append("STEP_FINISHED", {"key": key, "tool": tool, "digest": digest})
        self._finished[key] = digest
        return StepOutcome(key, result, False)
