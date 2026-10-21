"""Scope manifest: the target's SHA-256, ownership/test-authorization statement, allowed operations.

A small JSON document (`rh.scope/1`). `ScopeError` is raised if the manifest is missing, corrupt, expired, or the target's
SHA-256 does not match (fail-closed). In this skeleton the allowed operation is `static` (static analysis);
the names `run_controlled` and `patch_poc` are recognized in the schema; `patch_poc` has no tool (the harness does not
edit binaries; a vendor-rebuilt fixed binary is bound by the optional `fixed_target_sha256` instead).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

SCOPE_SCHEMA = "rh.scope/1"
# compute: the model's code, run in Sandbox. dynamic_observe: run_controlled(observe=...) instruments the target
# process (api_trace); dynamic_memory: the memory channel (reads/digests target memory), needs dynamic_observe.
# emulate: the target's own code in a CPU emulator on the host (nothing runs natively; docs/design/emulation.md).
KNOWN_OPERATIONS = ("static", "run_controlled", "patch_poc", "compute", "dynamic_observe", "dynamic_memory",
                    "emulate")
AUTH_BASES = ("owner", "authorized-test")
_SHA = re.compile(r"[0-9a-f]{64}")


class ScopeError(Exception):
    """Scope manifest rejection. The message may be shown to the user/model (contains no target text)."""


@dataclass(frozen=True)
class ScopeManifest:
    target_sha256: str
    declared_by: str
    basis: str
    statement: str
    allowed_operations: tuple[str, ...]
    expires: str | None
    path: str
    # Fix verification: SHA-256 of the vendor's rebuilt (fixed) binary. It is a second, hash-bound build of the
    # SAME analysis; run_controlled(target="fixed") may run it. The harness never edits a binary.
    fixed_target_sha256: str | None = None

    def allows(self, operation: str) -> bool:
        return operation in self.allowed_operations

    def to_summary(self) -> dict:
        out = {"schema": SCOPE_SCHEMA, "target_sha256": self.target_sha256, "declared_by": self.declared_by,
               "basis": self.basis, "allowed_operations": list(self.allowed_operations),
               "expires": self.expires}
        if self.fixed_target_sha256:   # only when set: summaries (and the journal) of ordinary jobs are unchanged
            out["fixed_target_sha256"] = self.fixed_target_sha256
        return out


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _nonempty_str(doc: dict, key: str, where: str) -> str:
    v = doc.get(key)
    if not isinstance(v, str) or not v.strip():
        raise ScopeError(f"manifest invalid: {where}{key} must be a non-empty string")
    return v.strip()


def parse_manifest(doc: Any, *, source: str = "") -> ScopeManifest:
    if not isinstance(doc, dict):
        raise ScopeError("manifest invalid: root must be a JSON object")
    if doc.get("schema") != SCOPE_SCHEMA:
        raise ScopeError(f"manifest invalid: schema must be {SCOPE_SCHEMA!r}")
    sha = doc.get("target_sha256")
    if not isinstance(sha, str) or not _SHA.fullmatch(sha):
        raise ScopeError("manifest invalid: target_sha256 must be 64 lowercase hex characters")
    fixed = doc.get("fixed_target_sha256")
    if fixed is not None:
        if not isinstance(fixed, str) or not _SHA.fullmatch(fixed):
            raise ScopeError("manifest invalid: fixed_target_sha256 must be 64 lowercase hex characters")
        if fixed == sha:
            raise ScopeError("manifest invalid: fixed_target_sha256 equals target_sha256 (the fixed build must differ)")
    auth = doc.get("authorization")
    if not isinstance(auth, dict):
        raise ScopeError("manifest invalid: authorization (ownership/test-authorization statement) is missing")
    declared_by = _nonempty_str(auth, "declared_by", "authorization.")
    statement = _nonempty_str(auth, "statement", "authorization.")
    basis = auth.get("basis")
    if basis not in AUTH_BASES:
        raise ScopeError(f"manifest invalid: authorization.basis must be one of {list(AUTH_BASES)}")
    ops = doc.get("allowed_operations")
    if (not isinstance(ops, list) or not ops or not all(isinstance(o, str) for o in ops)
            or any(o not in KNOWN_OPERATIONS for o in ops)):
        raise ScopeError(f"manifest invalid: allowed_operations must be a subset of {list(KNOWN_OPERATIONS)}")
    if "dynamic_memory" in ops and "dynamic_observe" not in ops:
        raise ScopeError("manifest invalid: dynamic_memory requires dynamic_observe")
    if "dynamic_observe" in ops and "run_controlled" not in ops:
        raise ScopeError("manifest invalid: dynamic_observe requires run_controlled")
    expires = doc.get("expires")
    if expires is not None:
        if not isinstance(expires, str):
            raise ScopeError("manifest invalid: expires must be an ISO date string")
        try:
            exp = (datetime.fromisoformat(expires) if "T" in expires
                   else datetime.combine(date.fromisoformat(expires), datetime.max.time()))
        except ValueError as e:
            raise ScopeError(f"manifest invalid: expires could not be parsed ({e})") from e
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp < datetime.now(timezone.utc):
            raise ScopeError(f"manifest has expired: {expires}")
    return ScopeManifest(sha, declared_by, basis, statement, tuple(dict.fromkeys(ops)), expires, source, fixed)


def load_manifest(manifest_path: str | Path | None, target_path: str | Path, *,
                  required_operation: str = "static") -> tuple[ScopeManifest, str]:
    """Reads the manifest, computes the target's SHA-256 and matches them. Returns (manifest, target_sha256)."""
    if not manifest_path:
        raise ScopeError("scope manifest is required: manifest_path was not given")
    mp = Path(manifest_path)
    if not mp.is_file():
        raise ScopeError(f"scope manifest not found: {mp}")
    tp = Path(target_path)
    if not tp.is_file():
        raise ScopeError(f"target file not found: {tp}")
    try:
        doc = json.loads(mp.read_text(encoding="utf-8-sig"))   # a BOM (PowerShell 5.1 "utf8") is tolerated
    except (OSError, ValueError) as e:
        raise ScopeError(f"manifest unreadable / not JSON: {e}") from e
    man = parse_manifest(doc, source=str(mp))
    sha = sha256_file(tp)
    if sha != man.target_sha256:
        raise ScopeError(f"target SHA-256 does not match the manifest: target {sha}, manifest {man.target_sha256}")
    if not man.allows(required_operation):
        raise ScopeError(f"manifest does not allow {required_operation!r}")
    return man, sha
