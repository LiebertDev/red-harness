"""Output integrity: host-side verification of the result records the guest writes.

Problem: inside the sandbox the target can write a fake result to the `C:\\out` folder or overwrite the runner's file.
Measurement: mapped folders are writable by EVERYONE inside the guest (a Low
integrity label, an ACL or a separate user did not prevent writing to `C:\\out`). So file access control is not trusted;
integrity comes from a one-time secret (nonce) the target cannot know:

1. At session start the host writes `in/nonce.txt`. The guest reads it into memory and acknowledges via `out/ready.json`
   (nonce_commit); on seeing the acknowledgement the host DELETES the file; the guest waits for the deletion and starts
   the target ONLY after that. The target runs as a non-admin user separate from the runner (cannot read the runner's
   memory); while the target runs the nonce exists nowhere.
2. The guest attaches HMAC-SHA256(nonce) to every record (case id, stdout/stderr SHA-256, exit code, flags, isolation).
   The nonce is NEVER written in clear text (a later case's target could read an earlier record).
3. The host verifies records against the SHA-256 of the bytes it read ITSELF and its own nonce. Any mismatch
   (missing record, nonce, hash, exit code, MAC) = INTEGRITY: the session is untrusted, no evidence is produced.

The canonical form must be BYTE-FOR-BYTE identical to guest.ps1 (the real Sandbox test checks this).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from typing import Any

VERSION = 1
NONCE_FILE = "nonce.txt"
_HEX64 = re.compile(r"[0-9a-f]{64}")
PREFIX = f"rh-integrity/{VERSION}"
BASE_ISOLATION = "windows-sandbox"


class IntegrityError(Exception):
    """Integrity verification failed. The message goes into the `INTEGRITY: ...` detail."""


@dataclass(frozen=True)
class CaseFacts:
    target_integrity: str   # measured by the guest from the target process token: low | medium | high | system | unknown
    separate_user: bool     # did the target run as a different user than the runner (token SID measured)
    mac: str


def new_nonce() -> str:
    return secrets.token_hex(32)


def nonce_commit(nonce: str) -> str:
    return hashlib.sha256(b"rh-nonce-commit/1:" + nonce.encode("ascii")).hexdigest()


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _mac(nonce: str, canon: str) -> str:
    return hmac.new(nonce.encode("ascii"), canon.encode("utf-8"), hashlib.sha256).hexdigest()


def _b01(v: bool) -> str:
    return "1" if v else "0"


def session_canon(run_id: str, target_sha256: str, separate_user: bool, low_il_label: bool) -> str:
    return f"{PREFIX}|session|{run_id}|{target_sha256}|{_b01(separate_user)}|{_b01(low_il_label)}"


def case_canon(run_id: str, index: int, stdout_sha: str, stderr_sha: str, exit_code: int | None, timed_out: bool,
               truncated: bool, stdout_total: int, stderr_total: int, launch_error: str | None, elapsed_ms: int,
               target_integrity: str, separate_user: bool) -> str:
    ec = "-" if exit_code is None else str(exit_code)
    le = _sha(launch_error.encode("utf-8")) if launch_error else "-"
    return (f"{PREFIX}|case|{run_id}|{index}|{stdout_sha}|{stderr_sha}|{ec}|{_b01(timed_out)}|{_b01(truncated)}|"
            f"{stdout_total}|{stderr_total}|{le}|{elapsed_ms}|{target_integrity}|{_b01(separate_user)}")


def done_canon(run_id: str, n: int, case_macs: list[str]) -> str:
    return f"{PREFIX}|done|{run_id}|{n}|{_sha(','.join(case_macs).encode('utf-8'))}"


def fatal_canon(message: str) -> str:
    return f"{PREFIX}|fatal|{message}"


# ---------------------------------------------------------------- signing (used only by the fake guest and tests)

def sign_session(nonce: str, run_id: str, target_sha256: str, *, commit: str | None = None) -> dict:
    return {"version": VERSION, "nonce_commit": commit or nonce_commit(nonce), "separate_user": True,
            "low_il_label": True, "mac": _mac(nonce, session_canon(run_id, target_sha256, True, True))}


def sign_case(nonce: str, run_id: str, index: int, stdout: bytes, stderr: bytes, meta: dict, *,
              target_integrity: str = "low", separate_user: bool = True, commit: str | None = None) -> dict:
    osha, esha = _sha(stdout), _sha(stderr)
    canon = case_canon(run_id, index, osha, esha, meta.get("exit_code"), bool(meta.get("timed_out")),
                       bool(meta.get("truncated")), meta.get("stdout_total", 0), meta.get("stderr_total", 0),
                       meta.get("launch_error"), meta.get("elapsed_ms", 0), target_integrity, separate_user)
    return {"version": VERSION, "case_id": f"{run_id}:{index}", "stdout_sha256": osha, "stderr_sha256": esha,
            "exit_code": meta.get("exit_code"), "nonce_commit": commit or nonce_commit(nonce),
            "target_integrity": target_integrity, "separate_user": separate_user, "mac": _mac(nonce, canon)}


def sign_done(nonce: str, run_id: str, case_macs: list[str]) -> str:
    return _mac(nonce, done_canon(run_id, len(case_macs), case_macs))


def sign_fatal(nonce: str, message: str) -> str:
    return _mac(nonce, fatal_canon(message))


# ---------------------------------------------------------------- verification

def _int(v: Any, what: str) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        raise IntegrityError(f"{what}: integer expected")
    return v


def _bool(v: Any, what: str) -> bool:
    if not isinstance(v, bool):
        raise IntegrityError(f"{what}: bool expected")
    return v


def _record(doc: dict, what: str) -> dict:
    rec = doc.get("integrity")
    if not isinstance(rec, dict):
        raise IntegrityError(f"{what}: integrity record missing")
    if rec.get("version") != VERSION:
        raise IntegrityError(f"{what}: integrity record version unsupported")
    return rec


def _check_commit(rec: dict, nonce: str, what: str) -> None:
    c = rec.get("nonce_commit")
    if not isinstance(c, str) or not hmac.compare_digest(c, nonce_commit(nonce)):
        raise IntegrityError(f"{what}: nonce mismatch")


def _check_mac(rec: dict, nonce: str, canon: str, what: str) -> str:
    m = rec.get("mac")
    if not isinstance(m, str) or not _HEX64.fullmatch(m):
        raise IntegrityError(f"{what}: MAC missing/malformed")
    if not hmac.compare_digest(m, _mac(nonce, canon)):
        raise IntegrityError(f"{what}: MAC mismatch (record forged or altered)")
    return m


def verify_session(doc: dict, nonce: str, run_id: str) -> None:
    what = "session.json"
    rec = _record(doc, what)
    if doc.get("run_id") != run_id:
        raise IntegrityError(f"{what}: run_id mismatch")
    sha = doc.get("target_sha256")
    if not isinstance(sha, str) or not _HEX64.fullmatch(sha):
        raise IntegrityError(f"{what}: target_sha256 malformed")
    _check_commit(rec, nonce, what)
    _check_mac(rec, nonce, session_canon(run_id, sha, _bool(rec.get("separate_user"), what),
                                         _bool(rec.get("low_il_label"), what)), what)


def verify_case(meta: dict, stdout: bytes, stderr: bytes, nonce: str, run_id: str, index: int) -> CaseFacts:
    """meta: cNNN.json; stdout/stderr: bytes the HOST read itself. Raises IntegrityError on mismatch."""
    what = f"c{index:03d}"
    rec = _record(meta, what)
    if rec.get("case_id") != f"{run_id}:{index}":
        raise IntegrityError(f"{what}: case id mismatch (record carried over from another session/case)")
    _check_commit(rec, nonce, what)
    osha, esha = _sha(stdout), _sha(stderr)
    if rec.get("stdout_sha256") != osha:
        raise IntegrityError(f"{what}: stdout SHA-256 mismatch (file changed after the record or forged)")
    if rec.get("stderr_sha256") != esha:
        raise IntegrityError(f"{what}: stderr SHA-256 mismatch (file changed after the record or forged)")
    ec = meta.get("exit_code")
    rec_ec = rec.get("exit_code")
    for v in (ec, rec_ec):  # a negative exit code is valid (NTSTATUS); not bool/text
        if v is not None and (isinstance(v, bool) or not isinstance(v, int)):
            raise IntegrityError(f"{what}: exit_code is not an integer")
    if rec_ec != ec:
        raise IntegrityError(f"{what}: exit code mismatch (record {rec_ec!r}, file {ec!r})")
    til = rec.get("target_integrity")
    if not isinstance(til, str) or til not in ("low", "medium", "high", "system", "unknown"):
        raise IntegrityError(f"{what}: target_integrity invalid")
    su = _bool(rec.get("separate_user"), what)
    le = meta.get("launch_error")
    if le is not None and not isinstance(le, str):
        raise IntegrityError(f"{what}: launch_error is not text")
    canon = case_canon(run_id, index, osha, esha, ec, _bool(meta.get("timed_out"), what),
                       _bool(meta.get("truncated"), what), _int(meta.get("stdout_total"), what),
                       _int(meta.get("stderr_total"), what), le, _int(meta.get("elapsed_ms"), what), til, su)
    return CaseFacts(til, su, _check_mac(rec, nonce, canon, what))


def verify_done(doc: dict, nonce: str, run_id: str, case_macs: list[str]) -> None:
    if doc.get("run_id") != run_id or doc.get("cases") != len(case_macs):
        raise IntegrityError("done.json: run_id/case count mismatch")
    m = doc.get("mac")
    if not isinstance(m, str) or not _HEX64.fullmatch(m):
        raise IntegrityError("done.json: MAC missing/malformed")
    if not hmac.compare_digest(m, sign_done(nonce, run_id, case_macs)):
        raise IntegrityError("done.json: MAC mismatch (completion marker forged)")


def fatal_valid(doc: dict, nonce: str) -> bool:
    msg, mac = doc.get("error"), doc.get("mac")
    return (isinstance(msg, str) and isinstance(mac, str) and _HEX64.fullmatch(mac) is not None
            and hmac.compare_digest(mac, sign_fatal(nonce, msg)))


def isolation_level(facts: list[CaseFacts]) -> str:
    """Isolation level from verified case records. With no records, just the base sandbox."""
    if not facts:
        return BASE_ISOLATION
    parts = [BASE_ISOLATION]
    if all(f.separate_user for f in facts):
        parts.append("separate-user")
    if all(f.target_integrity == "low" for f in facts):
        parts.append("low-il")
    return "+".join(parts)
