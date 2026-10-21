"""Observation seal: HMAC-SHA256 signature of the document bound to the run identity (same approach as sandbox/integrity.py).

Problem: the target or another process can write a forged/edited observation into the observation output folder, or can carry
over the observation of another run. The defense is a one-time secret the target cannot know (the run nonce;
given to the guest before the target starts via the handshake in sandbox/integrity.py, and it stays on the host):

- The trusted wrapper on the guest side seals the observation: MAC = HMAC-SHA256(nonce, "rh-dynamic/1|obs|<run_id>|
  <target_sha256>|<scope_sha256>|<body SHA-256>"). Body = canonical JSON of the document EXCLUDING `integrity`.
- The host verifies with the bytes IT read and its OWN nonce; mismatch = `DYNAMIC_INTEGRITY`, no evidence is produced.
- Domain separation: the prefix is `rh-dynamic/1`, so MACs of sandbox records are invalid for this document (and vice versa).

Root of trust: nonce secrecy (same boundary as sandbox output integrity). If the nonce leaks to the target a forged observation
becomes valid; a guest kernel/sandbox escape is out of scope and was NOT MEASURED.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any, Mapping

from ..core.journal import canonical
from .model import ObservationError, body_digest, split_document

VERSION = 1
PREFIX = f"rh-dynamic/{VERSION}"
_HEX64 = re.compile(r"[0-9a-f]{64}")


def nonce_commit(nonce: str) -> str:
    """Nonce commitment (does not reveal the nonce). Separate prefix from the sandbox commitment: domain separation."""
    return hashlib.sha256(b"rh-dynamic-nonce-commit/1:" + nonce.encode("ascii")).hexdigest()


class SealError(ObservationError):
    def __init__(self, message: str):
        super().__init__(message, "DYNAMIC_INTEGRITY")


def _mac(nonce: str, body: Mapping[str, Any]) -> str:
    ident = body["identity"]
    canon = (f"{PREFIX}|obs|{ident['run_id']}|{ident['target_sha256']}|{ident['scope_sha256']}|"
             f"{body_digest(body)}")
    return hmac.new(nonce.encode("ascii"), canon.encode("utf-8"), hashlib.sha256).hexdigest()


def seal_body(body: Mapping[str, Any], nonce: str, *, commit: str | None = None) -> dict:
    """Seals the body (called only by the fake guest/backend and tests). Returns the document dict."""
    doc = dict(body)
    doc["integrity"] = {"version": VERSION, "nonce_commit": commit or nonce_commit(nonce), "mac": _mac(nonce, body)}
    return doc


def document_bytes(doc: Mapping[str, Any]) -> bytes:
    return canonical(doc)


def verify_seal(doc_bytes: bytes, nonce: str) -> tuple[dict, str]:
    """(body, body_digest). SealError (DYNAMIC_INTEGRITY) if the seal is missing/malformed or nonce or MAC does not match."""
    body, rec = split_document(doc_bytes)
    ident = body.get("identity")
    if (not isinstance(ident, dict)
            or not all(isinstance(ident.get(k), str) for k in ("run_id", "target_sha256", "scope_sha256"))):
        raise SealError("identity unreadable")
    if rec.get("version") != VERSION:
        raise SealError("seal version not supported")
    c = rec.get("nonce_commit")
    if not isinstance(c, str) or not hmac.compare_digest(c, nonce_commit(nonce)):
        raise SealError("nonce mismatch (document carried over from another run, or forged)")
    m = rec.get("mac")
    if not isinstance(m, str) or not _HEX64.fullmatch(m):
        raise SealError("MAC missing/malformed")
    if not hmac.compare_digest(m, _mac(nonce, body)):
        raise SealError("MAC mismatch (document forged or modified)")
    return body, body_digest(body)
