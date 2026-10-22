"""docs/verifier-messages.md must not drift from the code: every code it lists exists in the source, and every code the
verifier groups or the claim reply gives a hint for is listed."""
from __future__ import annotations

import re
from pathlib import Path

from redharness.evidence import verifier as V
from redharness.mcp.session import ISSUE_HINTS

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "verifier-messages.md"
SRC = ROOT / "src" / "redharness"
CODE = re.compile(r"`([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)`")


def _doc_codes() -> set[str]:
    return set(CODE.findall(DOC.read_text(encoding="utf-8")))


def _source_text() -> str:
    parts = []
    for sub in ("evidence", "mcp", "report", "dynamic"):
        for p in sorted((SRC / sub).rglob("*.py")):
            parts.append(p.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(parts)


def test_every_documented_code_exists_in_the_source():
    text = _source_text()
    missing = sorted(c for c in _doc_codes() if f'"{c}"' not in text and f"'{c}'" not in text)
    assert missing == [], f"documented but not in the source: {missing}"


def test_every_code_the_verifier_groups_or_hints_is_documented():
    doc = _doc_codes()
    grouped = (set(V.COMPUTE_REJECTS) | set(V._FIX_REJECTS) | set(V.EXIT_CODE_REJECTS) | set(V._API_SEQ_REJECTS)
               | set(V.DERIVATION_REJECTS) | set(V.VALUE_ISSUE_CODES) | set(V._CAP_ONLY_BLOCKERS)
               | {V.TERM_ISSUE_CODE, V.BEHAVIOR_ISSUE_CODE, V.DYNAMIC_PAIR_CODE, V.API_SEQ_INCOMPLETE,
                  V.FIX_NEEDS_BOTH, V.FIX_RUN_INCOMPLETE, V.EXIT_CODE_NOT_RECORDED, V.EXIT_CODE_RUN_INCOMPLETE,
                  V.QUOTE_ONLY_CONDITIONAL})
    missing = sorted((grouped | set(ISSUE_HINTS)) - doc)
    assert missing == [], f"in the code but not documented: {missing}"


def test_the_documented_verifier_version_is_current():
    m = re.search(r"verifier\s+version\s+(\d+)", DOC.read_text(encoding="utf-8"), re.I)
    assert m and m.group(1) == V.VERIFIER_VERSION
