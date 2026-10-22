"""Closing an unknown through `unknown_record(resolves=..., status=resolved|withdrawn)`: evidence-bound resolution,
journaled, visible in coverage and the report, never deleting history, surviving resume."""
from __future__ import annotations

import pytest

from redharness.mcp.session import ToolFailure

from ._fake_engine import BASE
from .test_mcp_round2 import make_hub

VA = BASE + 0x1250


@pytest.fixture
def hub(tmp_path):
    h, _ = make_hub(tmp_path)
    yield h
    h.close()


def record(hub, ev):
    return hub.unknown_record("What does the call at 0x140001264 reach?", "target of an indirect call not resolved",
                              address="0x140001264", evidence_ids=[ev], severity="high")


def test_resolve_cites_evidence_and_keeps_history(hub):
    dis = hub.disassemble(hex(VA), count=8)
    u = record(hub, dis["evidence_id"])
    dec = hub.decompile(hex(VA))
    r = hub.unknown_record(resolves=u["unknown_id"], status="resolved", evidence_ids=[dec["evidence_id"]],
                           reason="the decompilation shows the callee")
    assert r["status"] == "OK" and r["unknown_status"] == "resolved" and r["open_unknowns"] == 0
    assert r["resolution"] == {"status": "resolved", "evidence_ids": [dec["evidence_id"]],
                               "reason": "the decompilation shows the callee"}
    rec = hub._s.ledger.state["unknowns"][u["unknown_id"]]
    # history is intact: the question, its reason, address and supporting evidence are still there
    assert rec["question"].startswith("What does the call") and rec["reason"].startswith("target of")
    assert rec["address"] == 0x140001264 and rec["supporting_evidence_ids"] == [dis["evidence_id"]]
    assert rec["status"] == "resolved" and rec["revision"] == 2
    types = [e["type"] for e in hub._s.journal.events() if e["type"].startswith("UNKNOWN")]
    assert types == ["UNKNOWN_RECORDED", "UNKNOWN_UPDATED"]


def test_resolved_unknown_is_no_longer_open_but_is_listed_as_closed(hub):
    dis = hub.disassemble(hex(VA), count=8)
    u = record(hub, dis["evidence_id"])
    assert hub.coverage()["open_unknowns_total"] == 1 and hub.coverage()["assessment"] == "INCOMPLETE"
    hub.unknown_record(resolves=u["unknown_id"], evidence_ids=[dis["evidence_id"]])   # status defaults to resolved
    cov = hub.coverage()
    assert cov["open_unknowns_total"] == 0 and cov["closed_unknowns_total"] == 1
    assert cov["resolved_unknowns_total"] == 1 and cov["withdrawn_unknowns_total"] == 0
    row = cov["closed_unknowns"][0]
    assert row["unknown_id"] == u["unknown_id"] and row["status"] == "resolved"
    assert row["resolution"]["evidence_ids"] == [dis["evidence_id"]]
    rep = hub.report_build()
    md = rep["markdown"]
    assert "### Resolved and withdrawn unknowns" in md and u["unknown_id"] in md and dis["evidence_id"] in md
    assert "resolved: 1, withdrawn: 0" in md
    assert rep["coverage"]["open_unknowns"] == 0
    # the closed unknown is not listed under the open ones
    open_part = md.split("### Open unknowns")[1].split("### Resolved and withdrawn unknowns")[0]
    assert u["unknown_id"] not in open_part


def test_withdrawn_needs_a_reason_and_appears_in_the_report(hub):
    u = hub.unknown_record("Is the table bounds-checked?", "code not reached")
    with pytest.raises(ToolFailure) as e:
        hub.unknown_record(resolves=u["unknown_id"], status="withdrawn")
    assert e.value.code == "BAD_RESOLUTION"
    r = hub.unknown_record(resolves=u["unknown_id"], status="withdrawn", reason="the table is not used by this build")
    assert r["unknown_status"] == "withdrawn" and r["open_unknowns"] == 0
    cov = hub.coverage()
    assert cov["withdrawn_unknowns_total"] == 1 and cov["assessment"] != "INCOMPLETE"
    md = hub.report_build()["markdown"]
    assert "**withdrawn**" in md and "the table is not used by this build" in md


@pytest.mark.parametrize("kw,code", [
    ({"resolves": "nope"}, "BAD_ARGUMENT"),
    ({"resolves": "unk_" + "0" * 64, "evidence_ids": ["ev_x"]}, "UNKNOWN_EVIDENCE_ID"),
    ({"resolves": "unk_" + "0" * 64}, "BAD_RESOLUTION"),                       # resolved without evidence
    ({"status": "withdrawn", "reason": "r"}, "BAD_ARGUMENT"),                  # status without resolves
    ({"resolves": "unk_" + "0" * 64, "status": "closed"}, "BAD_ARGUMENT"),
    ({"resolves": "unk_" + "0" * 64, "status": "withdrawn", "reason": "r"}, "UNKNOWN_NOT_FOUND"),
])
def test_bad_closing_arguments(hub, kw, code):
    with pytest.raises(ToolFailure) as e:
        hub.unknown_record(**kw)
    assert e.value.code == code


def test_closing_does_not_accept_a_question(hub):
    dis = hub.disassemble(hex(VA), count=8)
    u = record(hub, dis["evidence_id"])
    with pytest.raises(ToolFailure) as e:
        hub.unknown_record("another question", resolves=u["unknown_id"], evidence_ids=[dis["evidence_id"]])
    assert e.value.code == "BAD_ARGUMENT"
    assert hub._s.ledger.state["unknowns"][u["unknown_id"]]["status"] == "open"


def test_invalidated_evidence_cannot_resolve(hub):
    dis = hub.disassemble(hex(VA), count=8)
    u = record(hub, dis["evidence_id"])
    hub._s.ledger.state["invalidated"][dis["evidence_id"]] = "test"
    with pytest.raises(ToolFailure) as e:
        hub.unknown_record(resolves=u["unknown_id"], evidence_ids=[dis["evidence_id"]])
    assert e.value.code == "UNKNOWN_EVIDENCE_ID"


def test_close_is_idempotent_but_a_different_resolution_is_refused(hub):
    dis = hub.disassemble(hex(VA), count=8)
    dec = hub.decompile(hex(VA))
    u = record(hub, dis["evidence_id"])
    hub.unknown_record(resolves=u["unknown_id"], evidence_ids=[dis["evidence_id"]])
    n = len([e for e in hub._s.journal.events() if e["type"] == "UNKNOWN_UPDATED"])
    again = hub.unknown_record(resolves=u["unknown_id"], evidence_ids=[dis["evidence_id"]])   # retry of a lost reply
    assert again["unknown_status"] == "resolved"
    assert len([e for e in hub._s.journal.events() if e["type"] == "UNKNOWN_UPDATED"]) == n
    for kw in ({"status": "withdrawn", "reason": "changed my mind"}, {"evidence_ids": [dec["evidence_id"]]}):
        with pytest.raises(ToolFailure) as e:
            hub.unknown_record(resolves=u["unknown_id"], **kw)
        assert e.value.code == "UNKNOWN_ALREADY_CLOSED"
    # asking the same question again returns the closed record, it does not reopen it
    q = hub.unknown_record("What does the call at 0x140001264 reach?", "again", address="0x140001264")
    assert q["unknown_status"] == "resolved" and q["open_unknowns"] == 0


def test_resolution_survives_resume(tmp_path):
    h, _ = make_hub(tmp_path)
    dis = h.disassemble(hex(VA), count=8)
    u = record(h, dis["evidence_id"])
    h.unknown_record(resolves=u["unknown_id"], evidence_ids=[dis["evidence_id"]])
    h.close()
    h2, _ = make_hub(tmp_path)
    try:
        cov = h2.coverage()
        assert cov["open_unknowns_total"] == 0 and cov["resolved_unknowns_total"] == 1
        rec = h2._s.ledger.state["unknowns"][u["unknown_id"]]
        assert rec["status"] == "resolved" and rec["revision"] == 2
    finally:
        h2.close()


def test_stale_revision_update_is_ignored_by_replay():
    from redharness.evidence.ledger import empty_state, reduce_event
    st = empty_state()
    rec = {"unknown_id": "unk_a", "status": "open", "revision": 1, "resolution": None}
    reduce_event(st, {"type": "UNKNOWN_RECORDED", "payload": rec})
    reduce_event(st, {"type": "UNKNOWN_UPDATED", "payload": {"unknown_id": "unk_a", "expected_revision": 5,
                                                              "status": "resolved", "resolution": {"status": "resolved"}}})
    assert st["unknowns"]["unk_a"]["status"] == "open"
