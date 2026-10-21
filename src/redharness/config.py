"""Configuration and data_root resolution. Writes nothing to disk at import time."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ENV_DATA_ROOT = "RH_DATA_ROOT"
ENV_SANDBOX_MEMORY_MB = "RH_SANDBOX_MEMORY_MB"
DEFAULT_SANDBOX_MEMORY_MB = 2048


def default_data_root() -> Path:
    """RH_DATA_ROOT, else %USERPROFILE%/RedHarnessData (the per-user default)."""
    env = os.environ.get(ENV_DATA_ROOT)
    if env:
        return Path(env).expanduser().resolve()
    return (Path.home() / "RedHarnessData").resolve()


@dataclass(frozen=True)
class Config:
    data_root: Path

    @classmethod
    def load(cls, data_root: str | os.PathLike | None = None) -> "Config":
        root = Path(data_root).expanduser().resolve() if data_root else default_data_root()
        return cls(data_root=root)

    @property
    def cas_dir(self) -> Path:
        return self.data_root / "cas" / "sha256"

    @property
    def cache_dir(self) -> Path:
        return self.data_root / "cache"

    @property
    def jobs_dir(self) -> Path:
        return self.data_root / "jobs"

    @property
    def work_dir(self) -> Path:
        return self.data_root / "work"

    @property
    def corpus_dir(self) -> Path:
        return self.data_root / "corpus"

    def job_dir(self, job_id: str) -> Path:
        return self.jobs_dir / job_id

    def ensure_dirs(self) -> None:
        """Requires an explicit call; no module calls this at import time."""
        for d in (self.cas_dir, self.cache_dir, self.jobs_dir, self.work_dir, self.corpus_dir):
            d.mkdir(parents=True, exist_ok=True)


def sandbox_memory_mb() -> int:
    """Windows Sandbox <MemoryInMB>: RH_SANDBOX_MEMORY_MB (integer in 512..16384), 2048 if unset or invalid."""
    raw = os.environ.get(ENV_SANDBOX_MEMORY_MB)
    try:
        v = int(raw) if raw else DEFAULT_SANDBOX_MEMORY_MB
    except ValueError:
        return DEFAULT_SANDBOX_MEMORY_MB
    return v if 512 <= v <= 16384 else DEFAULT_SANDBOX_MEMORY_MB
