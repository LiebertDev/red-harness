"""Content-addressed blob store: <root>/<sha[:2]>/<sha>. Immutable; re-hashed on read.

Write: temp file + fsync + os.replace (a partial blob is never visible). Read: CasCorrupt on hash mismatch.
Root is usually Config.cas_dir (data_root/cas/sha256). Writes nothing to disk at import time.
"""

from __future__ import annotations

import hashlib
import os
import re
import uuid
from pathlib import Path

_SHA = re.compile(r"[0-9a-f]{64}")
_CHUNK = 1 << 20


class CasError(Exception):
    pass


class CasMissing(CasError):
    pass


class CasCorrupt(CasError):
    pass


def _check_sha(sha: str) -> str:
    if not isinstance(sha, str) or not _SHA.fullmatch(sha):
        raise CasError(f"invalid sha256: {sha!r}")
    return sha


class Cas:
    def __init__(self, root: str | os.PathLike):
        self.root = Path(root)

    def path_for(self, sha: str) -> Path:
        _check_sha(sha)
        return self.root / sha[:2] / sha

    def has(self, sha: str) -> bool:
        return self.path_for(sha).is_file()

    def put(self, data: bytes) -> str:
        sha = hashlib.sha256(data).hexdigest()
        p = self.path_for(sha)
        if p.is_file() and self._file_sha(p) == sha:
            return sha
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(f".{sha}.{uuid.uuid4().hex}.tmp")
        try:
            with open(tmp, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, p)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        return sha

    def put_file(self, path: str | os.PathLike) -> str:
        """Copies a large file by streaming (target binaries). The source is hashed while being copied."""
        h = hashlib.sha256()
        self.root.mkdir(parents=True, exist_ok=True)
        tmp = self.root / f".incoming.{uuid.uuid4().hex}.tmp"
        try:
            with open(path, "rb") as src, open(tmp, "wb") as dst:
                while chunk := src.read(_CHUNK):
                    h.update(chunk)
                    dst.write(chunk)
                dst.flush()
                os.fsync(dst.fileno())
            sha = h.hexdigest()
            p = self.path_for(sha)
            if p.is_file() and self._file_sha(p) == sha:
                return sha
            p.parent.mkdir(parents=True, exist_ok=True)
            os.replace(tmp, p)
            return sha
        finally:
            tmp.unlink(missing_ok=True)

    @staticmethod
    def _file_sha(p: Path) -> str:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            while chunk := f.read(_CHUNK):
                h.update(chunk)
        return h.hexdigest()

    def get(self, sha: str) -> bytes:
        p = self.path_for(sha)
        try:
            data = p.read_bytes()
        except FileNotFoundError as e:
            raise CasMissing(sha) from e
        if hashlib.sha256(data).hexdigest() != sha:
            raise CasCorrupt(f"blob hash mismatch: {sha}")
        return data

    def get_range(self, sha: str, offset: int = 0, length: int | None = None) -> bytes:
        """Paged read; the whole blob is verified first."""
        if offset < 0 or (length is not None and length < 0):
            raise CasError("negatif offset/length")
        data = self.get(sha)
        return data[offset:] if length is None else data[offset:offset + length]

    def verify(self, sha: str) -> bool:
        """Whether the blob exists and its digest matches its name (streamed; not loaded into memory)."""
        p = self.path_for(sha)
        return p.is_file() and self._file_sha(p) == sha

    def read_at(self, sha: str, offset: int, length: int) -> bytes:
        """Small-range read from a large blob without verifying (the caller pins identity with `verify` first)."""
        if offset < 0 or length < 0:
            raise CasError("negatif offset/length")
        try:
            with open(self.path_for(sha), "rb") as f:
                f.seek(offset)
                return f.read(length)
        except FileNotFoundError as e:
            raise CasMissing(sha) from e

    def size(self, sha: str) -> int:
        try:
            return self.path_for(sha).stat().st_size
        except FileNotFoundError as e:
            raise CasMissing(sha) from e
