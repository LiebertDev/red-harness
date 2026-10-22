"""Verifier rules for `dynamic-region-view` evidence (verifier version 22): lineage, ceiling and format-aware numbers.

Synthetic records only: the observation is a sealed fake-backend document ingested through the production path; the
view record is built the way the `captured_region` tool builds it. No tracer, sandbox or premium module is involved.
"""
import hashlib

import pytest

from redharness.core.result import Status
from redharness.evidence import verifier as V
from redharness.evidence.model import REGION_VIEW_AUTHORITY, build_evidence

from .test_dynamic import ID, TARGET, Env, fake, request

BASE = 0x400000
PAYLOAD = b"MZ\x90\x00" + b"decoded-config-text\x00" + bytes(64)
VIEW_TEXT = (
    "captured_region observation=ev_x event=0 kind=exec_transition base=0x400000 size=%d protection=RX captured=%d\n"
    "segment 1 CAPTURED 0x400000..0x400010 len=16 offset=0x0\n"
    "  0x400000: 4d5a9000_64656365_12345678_00000000\n"
    "  -- strings --\n"
    "0x400004 offset=0x4 enc=ascii len=19 'decoded-config-text'\n"
    "  -- disasm --\n"
    "0x400000: 4d5a dec ebp\n" % (len(PAYLOAD), len(PAYLOAD)))


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def observation(env, **kw):
    be = fake(api_calls=(), dumps=[(BASE, PAYLOAD, "exec_transition", "RX")], **kw)
    return env.dyn(be, request(channels=("memory",), memory_capture_bytes=256))


def view_record(env, parent, *, status=Status.OK, truncated=False, text=VIEW_TEXT, links=None, **over):
    prec = env.ledger.state["evidence"][parent]
    params = {"observation_evidence_id": parent, "observation_blob_sha256": prec["raw"]["blob_sha256"],
              "observation_sha256": prec["parameters"]["observation_sha256"], "event": 0, "source_event": 0, "offset": 0,
              "length": None, "views": ["hex", "strings"], "arch": "x64"}
    kw = dict(subject_sha256=TARGET, tool="captured_region", operation="captured_region", raw=text.encode(), status=status,
              confidence="derived", authority=REGION_VIEW_AUTHORITY, parameters=params, truncated=truncated,
              result={"views": {}}, locations=[{"kind": "address-range", "space": "va", "start": BASE, "end": BASE + 16}],
              coverage={"scope": "captured_region:x", "relationship": "partial", "channels": {"memory": "complete"}},
              evidence_links=[parent] if links is None else links)
    kw.update(over)
    return env.ledger.record_evidence(build_evidence(env.cas, **kw))["evidence_id"]


QUOTE = "'decoded-config-text'"
TEXT = "The region holds the text decoded-config-text."


def claim(env, evs, quote_ev, *, polarity="present", req="SUPPORTED", kind="observation", text=TEXT):
    return env.claim(evs, text=text, kind=kind, polarity=polarity, req=req,
                     atoms=[{"type": "quote", "evidence_id": quote_ev, "text": QUOTE}])


def codes(res):
    return {i["code"] for i in res.issues}


def test_a_view_with_its_observation_backs_an_observation_claim_but_not_proven(env):
    parent = observation(env)
    view = view_record(env, parent)
    ok = claim(env, [parent, view], view)
    assert ok.status.value == "SUPPORTED" and ok.claim["verification"]["verifier_version"] == "24"
    proven = claim(env, [parent, view], view, req="PROVEN")
    assert proven.status.value == "SUPPORTED" and "PROVEN_REGION_VIEW" in codes(proven)


def test_a_claim_citing_a_view_must_also_cite_its_observation(env):
    parent = observation(env)
    view = view_record(env, parent)
    res = claim(env, [view], view)
    assert res.status.value == "REJECTED" and "REGION_VIEW_PARENT_NOT_CITED" in codes(res)


def test_the_text_of_a_view_must_really_be_in_it(env):
    parent = observation(env)
    view = view_record(env, parent)
    res = env.claim([parent, view], text=TEXT, kind="observation", atoms=[
        {"type": "quote", "evidence_id": view, "text": "'invented-text'"}])
    assert res.status.value == "REJECTED" and "QUOTE_NOT_IN_RAW" in codes(res)


@pytest.mark.parametrize("what", ["operation", "confidence", "complete", "no_link", "other_link", "blob", "digest",
                                  "other_subject"])
def test_a_view_record_that_does_not_match_its_observation_is_rejected(env, what):
    parent = observation(env)
    other = env.static()
    prec = env.ledger.state["evidence"][parent]
    over = {"operation": {"operation": "strings"}, "confidence": {"confidence": "observed"},
            "complete": {"coverage": {"scope": "x", "relationship": "complete"}}, "no_link": {"evidence_links": []},
            "other_link": {"evidence_links": [other]}, "other_subject": {"subject_sha256": hashlib.sha256(b"x").hexdigest()}}.get(what, {})
    rec_over = dict(over)
    if what == "blob":
        rec_over["parameters"] = {"observation_evidence_id": parent, "observation_blob_sha256": "0" * 64,
                                  "observation_sha256": prec["parameters"]["observation_sha256"]}
    if what == "digest":
        rec_over["parameters"] = {"observation_evidence_id": parent, "observation_blob_sha256": prec["raw"]["blob_sha256"],
                                  "observation_sha256": "0" * 64}
    if "evidence_links" in rec_over:
        links = rec_over.pop("evidence_links")
        view = view_record(env, parent, links=links, **rec_over)
    else:
        view = view_record(env, parent, **rec_over)
    res = claim(env, [parent, view], view)
    if what == "other_subject":
        assert res.status.value == "REJECTED"        # the generic subject check fires first
    else:
        assert res.status.value == "REJECTED" and "REGION_VIEW_INVALID" in codes(res)


def test_a_view_cannot_be_stronger_than_its_observation(env):
    parent = observation(env, dropped_events=2)                       # an incomplete observation: strength partial
    assert env.ledger.state["evidence"][parent]["capture"]["status"] == "PARTIAL"
    strong = view_record(env, parent)                                 # claims OK/full anyway
    res = claim(env, [parent, strong], strong)
    assert res.status.value == "REJECTED" and "REGION_VIEW_INVALID" in codes(res)
    weak = view_record(env, parent, status=Status.PARTIAL, truncated=True)
    ok = claim(env, [parent, weak], weak)
    assert ok.status.value == "SUPPORTED"                             # an honest partial view still backs a present claim


def test_a_view_never_backs_an_absence_claim(env):
    parent = observation(env)
    view = view_record(env, parent)
    res = claim(env, [parent, view], view, polarity="absent", text="The region holds no further text.")
    assert res.status.value != "SUPPORTED"


def test_an_invalidated_observation_invalidates_its_view(env):
    parent = observation(env)
    view = view_record(env, parent)
    env.ledger.invalidate_evidence(parent, "test")
    res = claim(env, [parent, view], view)
    assert res.status.value == "REJECTED"
    res2 = claim(env, [view], view)
    assert res2.status.value == "REJECTED" and "REGION_VIEW_INVALID" in codes(res2)


def test_hex_rows_and_instruction_bytes_of_a_view_are_not_numbers(env):
    parent = observation(env)
    view = view_record(env, parent)
    rec = env.ledger.state["evidence"][view]
    hexes, decs = V.numbers_of(env.cas.get(rec["raw"]["blob_sha256"]), rec)
    assert BASE in hexes and len(PAYLOAD) in decs                     # the header's address and size are numbers
    assert 12345678 not in decs                                       # a digits-only byte group is bytes
    assert 0x4d5a9000 not in hexes
    bad = env.claim([parent, view], text="The region holds the value 12345678.", kind="observation", polarity="present",
                    req="SUPPORTED", atoms=[{"type": "quote", "evidence_id": view, "text": QUOTE}])
    assert bad.status.value != "SUPPORTED" and ("VALUE_NOT_IN_EVIDENCE" in codes(bad) or bad.status.value == "REJECTED")


def test_claims_without_a_view_verify_as_before(env):
    ev = env.dyn()
    res = env.claim([ev])
    assert res.claim["verification"]["verifier_version"] == "24" and not any(c.startswith("REGION") for c in codes(res))
