"""REAL proof for `file_strings`: the raw string scan of the host's own notepad.exe through the full MCP path (target_open +
scope manifest, evidence, step cache; no engine is used, the fake engine only answers target_open). Ground truth: every
reported entry is re-read from the file at its reported offset and must decode to the reported value; an ASCII import
name and a UTF-16 resource string found independently with a plain byte search must be among the entries.
"""
from __future__ import annotations

import re

import pytest

from redharness.config import Config
from redharness.mcp.session import Hub

from tests.unit._fake_engine import FakeEngine
from tests.unit.mcp_helpers import make_manifest

pytestmark = pytest.mark.heavy


@pytest.fixture
def hub(tmp_path, notepad_copy):
    h = Hub(Config.load(tmp_path / "data"), FakeEngine())
    h.target_open(str(notepad_copy), str(make_manifest(tmp_path / "scope.json", notepad_copy)))
    yield h, notepad_copy.read_bytes()
    h.close()


def _scan(h, **kw):
    kw = {"detail": "full", **kw}
    r = h.call("file_strings", kw, lambda: h.file_strings(**kw))
    return r, h._s.ledger.state["evidence"][r["evidence_id"]]["result"]["entries"]


def test_entries_reread_from_the_file_and_independent_hits_present(hub):
    h, data = hub
    r, entries = _scan(h, pattern=r"(?i)^kernel32\.dll$|Notepad")
    print(f"\nfile_strings ev={r['evidence_id']} status={r['status']}: {len(entries)} entries")
    assert r["status"] == "OK" and entries
    for e in entries:                                        # each entry is exactly what the file holds there
        off, n = int(e["file_offset"], 16), e["byte_length"]
        raw = data[off:off + n]
        text = raw.decode("utf-16-le" if e["encoding"].startswith("utf-16") else "latin-1").rstrip("\0")
        assert text == e["value"], (e, text)
    offsets = {int(e["file_offset"], 16) for e in entries}
    ascii_hits = [m.start() for m in re.finditer(rb"(?<![\x20-\x7e])KERNEL32\.dll(?![\x20-\x7e])", data)]
    wide_hits = [m.start() for m in re.finditer("Notepad".encode("utf-16-le"), data)]
    assert ascii_hits and set(ascii_hits) <= offsets
    assert wide_hits and any(any(o <= w < o + 400 for o in offsets) for w in wide_hits)
    again, _ = _scan(h, pattern=r"(?i)^kernel32\.dll$|Notepad")
    assert again["evidence_id"] == r["evidence_id"] and again["step_cached"]
