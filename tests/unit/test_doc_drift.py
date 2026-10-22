"""No documentation drift for facts the code defines.

`README.md` and `docs/usage-mcp.md` advertise the size of the MCP tool surface and the claim-verifier version. Both are
constants in the code (`TOOL_NAMES` in `mcp/registry.py`, `VERIFIER_VERSION` in `evidence/verifier.py`), so a changed
constant must not leave a stale number in the documents.

The public copies of those two files live in `public-overlay/`; `tools/export_public.py` applies them as the public
`README.md` / `docs/usage-mcp.md`. When the overlay exists (the vault) it is checked too; in the public export the
exported documents are checked in its place and the overlay directory does not exist.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from redharness.evidence.verifier import VERIFIER_VERSION
from redharness.mcp.registry import TOOL_NAMES
from redharness.mcp.server import MAX_TOOLS

ROOT = Path(__file__).resolve().parents[2]
VAULT = (ROOT / "tools" / "export_public.py").is_file()

_DOC_PATHS = ("README.md", "docs/usage-mcp.md",
              "public-overlay/README.md", "public-overlay/docs/usage-mcp.md")
DOCS = [ROOT / rel for rel in _DOC_PATHS if (ROOT / rel).is_file()]

# "<number> tools" / "<number> MCP tools", tolerant of spacing and case.
TOOL_COUNT = re.compile(r"(?i)\b(\d+)\s+(?:MCP\s+)?tools\b")
# The reference table heading: "## Tools (18; ...)".
TOOL_HEADING = re.compile(r"(?im)^##\s+Tools\s*\((\d+)\b")
# "verifier version N", "verifier is version N", "verifier vN" (also "Verifier is vN").
VERIFIER_VERSION_PHRASE = re.compile(r"(?i)\bverifier(?:\s+(?:is|was))?\s+(?:version|v)\s*\.?\s*(\d+)\b")

# Historical statements are tolerated by exact phrase. Keep this tiny: a changelog-style line ("since verifier v17")
# records when a rule was introduced and must NOT be updated with the current constant. Keyed by (repo path, phrase).
HISTORICAL: dict[tuple[str, str], str] = {
    # ("docs/usage-mcp.md", "since verifier v17"): "records when the rule was introduced",
}


def _rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _historical(rel: str, phrase: str) -> bool:
    return any(key == (rel, phrase) for key in HISTORICAL)


def _drift(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    rel = _rel(path)
    problems: list[str] = []
    for m in TOOL_COUNT.finditer(text):
        if int(m.group(1)) != len(TOOL_NAMES) and not _historical(rel, m.group(0)):
            problems.append(f"{rel}:{_line_of(text, m.start())}: {m.group(0)!r}; "
                            f"TOOL_NAMES has {len(TOOL_NAMES)} tools")
    for m in TOOL_HEADING.finditer(text):
        if int(m.group(1)) != len(TOOL_NAMES):
            problems.append(f"{rel}:{_line_of(text, m.start())}: table says {m.group(1)} tools; "
                            f"TOOL_NAMES has {len(TOOL_NAMES)}")
    for m in VERIFIER_VERSION_PHRASE.finditer(text):
        if m.group(1) != VERIFIER_VERSION and not _historical(rel, m.group(0)):
            problems.append(f"{rel}:{_line_of(text, m.start())}: {m.group(0)!r}; "
                            f"VERIFIER_VERSION is {VERIFIER_VERSION}")
    return problems


@pytest.mark.parametrize("path", DOCS, ids=[_rel(p) for p in DOCS])
def test_documented_tool_count_and_verifier_version_match_the_code(path):
    assert _drift(path) == []


def test_the_cap_leaves_room_for_the_registered_tools():
    assert MAX_TOOLS >= len(TOOL_NAMES)


def test_both_documents_and_both_public_copies_are_checked():
    checked = {_rel(p) for p in DOCS}
    assert {"README.md", "docs/usage-mcp.md"} <= checked
    if VAULT:   # the overlay copies exist in the vault; the public export has no public-overlay/ directory
        assert {"public-overlay/README.md", "public-overlay/docs/usage-mcp.md"} <= checked
