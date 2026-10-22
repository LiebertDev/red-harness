"""Imported evidence bundle: claim status cap, provenance in target_open, report header and side_effects in the
run_controlled result (fake engine + fake Windows Sandbox; nothing real runs). The imported job is marked with the
records `jobs.bundle` writes, so this file needs no bundle code; the CLI round trip is covered by separate bundle tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from redharness.config import Config
from redharness.evidence.model import ClaimStatus
from redharness.evidence.verifier import Verdict
from redharness.mcp.session import Hub

from ._fake_engine import BASE, FakeEngine
from ._fake_sandbox import FakeSandbox
from .mcp_helpers import make_manifest
from .test_run_controlled_mcp import GOOD_KEY, WRONG_KEY, fake_system_root, oracle, prove

VA = BASE + 0x1250
IMPORT_NOTE = "imported bundle: authenticity not established"
PROVENANCE_ISSUE = "imported bundle: provenance file missing or altered"


@pytest.fixture(autouse=True)
def _short_sandbox_waits(monkeypatch):
    from redharness.sandbox import runner
    for name, v in (("BOOT_ALLOWANCE_S", 1.0), ("PER_CASE_OVERHEAD_S", 0.0), ("FINISH_SLACK_S", 0.0), ("RETRY_BACKOFF_S", 0.0)):
        monkeypatch.setattr(runner, name, v)


def _target(tmp_path: Path) -> tuple[Path, Path]:
    target = tmp_path / "sample.bin"
    target.write_bytes(b"MZ" + bytes(range(256)) * 8)
    manifest = make_manifest(tmp_path / "scope.json", target, allowed_operations=["static", "run_controlled"])
    return target, manifest


def _hub(data_root: Path, **sb_kw) -> Hub:
    return Hub(Config.load(data_root), FakeEngine(), FakeSandbox(behavior=sb_kw.pop("behavior", oracle), **sb_kw),
               system_root=fake_system_root(data_root.parent / (data_root.name + "-win")))


OBS_TEXT = "The instruction at 0x140001260 is xor with 0x5EC2E7A1."


def _build_source_job(tmp_path: Path):
    """A job with one PROVEN behavior claim and one SUPPORTED observation claim. Returns ids and the data root."""
    target, manifest = _target(tmp_path)
    root = tmp_path / "src-data"
    h = _hub(root)
    opened = h.target_open(str(target), str(manifest))
    run = h.call("run_controlled", {}, lambda: h.run_controlled([{"stdin": GOOD_KEY + "\n"},
                                                                 {"stdin": WRONG_KEY + "\n"}], 10))
    proven = prove(h, GOOD_KEY, run["evidence_ids"][0], against=run["evidence_ids"][1])
    assert proven["status"] == "PROVEN", proven
    dis = h.disassemble(hex(VA + 0x10), count=4)
    sup = h.claim_add(OBS_TEXT, [dis["evidence_id"]],
                      [{"type": "quote", "evidence_id": dis["evidence_id"], "text": "xor eax, 0x5EC2E7A1"},
                       {"type": "address", "evidence_id": dis["evidence_id"], "value": "0x140001260"}],
                      kind="observation")
    assert sup["status"] == "SUPPORTED", sup
    job_id = opened["job_id"]
    h.close()
    return target, manifest, root, job_id, proven["claim_id"], sup["claim_id"]


BUNDLE_SHA = "ab" * 32
IMPORTED_AT = "2026-01-01T00:00:00Z"


def _mark_imported(job_dir: Path, statuses: dict) -> None:
    """Marks a job as imported exactly like `jobs.bundle.import_job` records it (provenance.json + a BUNDLE_IMPORTED
    event on the hash-chained journal), without the bundle code: the cap only needs these two records."""
    from redharness.core.journal import Journal
    (job_dir / "provenance.json").write_text(json.dumps({
        "schema": "rh.bundle.provenance/1", "imported": True, "source_bundle_sha256": BUNDLE_SHA,
        "imported_at": IMPORTED_AT, "authenticity": "not established", "note": IMPORT_NOTE,
        "claim_statuses": statuses}, indent=2, sort_keys=True), encoding="utf-8")
    journal = Journal(job_dir / "events.jsonl")
    with journal:
        journal.append("BUNDLE_IMPORTED", {
            "schema": "rh.bundle.import/1", "source_bundle_sha256": BUNDLE_SHA, "imported_at": IMPORTED_AT,
            "authenticity": "not established", "note": IMPORT_NOTE, "claim_statuses": statuses})


def _imported_hub_from(root: Path, target: Path, manifest: Path):
    h = _hub(root)
    return h, h.target_open(str(target), str(manifest))


def _imported_hub(tmp_path, *, mutate=None):
    target, manifest, root, job_id, proven_id, sup_id = _build_source_job(tmp_path)
    job_dir = root / "jobs" / job_id
    _mark_imported(job_dir, {proven_id: "PROVEN", sup_id: "SUPPORTED"})
    if mutate is not None:
        mutate(job_dir)
    h, opened = _imported_hub_from(root, target, manifest)
    return h, opened, BUNDLE_SHA, proven_id, sup_id


def _delete_provenance(job_dir: Path) -> None:
    (job_dir / "provenance.json").unlink()


def _unmark_provenance(job_dir: Path) -> None:
    path = job_dir / "provenance.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["imported"] = False
    path.write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")


# ---------------------------------------------------------------- CLI round trip + provenance in target_open
def test_imported_job_target_open_provenance(tmp_path):
    h, opened, bundle_sha, proven_id, sup_id = _imported_hub(tmp_path)
    try:
        prov = opened["provenance"]
        assert prov["imported"] is True and prov["statement"] == IMPORT_NOTE
        assert prov["source_bundle_sha256"] == bundle_sha
        assert prov["bundle_claim_statuses"] == {proven_id: "PROVEN", sup_id: "SUPPORTED"}
        assert opened["resumed"] is True and opened["resume"]["imported_bundle"] == IMPORT_NOTE
        claims = {c["claim_id"]: c["status"] for c in opened["previous"]["claims"]}
        assert claims == {proven_id: "PROVEN", sup_id: "SUPPORTED"}   # statuses came across unchanged
    finally:
        h.close()


@pytest.mark.parametrize("mutate", [_delete_provenance, _unmark_provenance],
                         ids=["deleted-provenance", "imported-flag-false"])
def test_altered_provenance_still_imported_with_strict_cap_and_issue(tmp_path, mutate):
    h, opened, bundle_sha, proven_id, sup_id = _imported_hub(tmp_path, mutate=mutate)
    try:
        prov = opened["provenance"]
        assert prov["imported"] is True
        assert prov["provenance_issue"] == PROVENANCE_ISSUE
        # The journal record is authoritative: no recorded bundle status is trusted any more.
        assert h._s.ledger.reverify(proven_id).status is ClaimStatus.SUPPORTED
        v = h._s.ledger.reverify(proven_id)
        assert any(i["detail"] == PROVENANCE_ISSUE for i in v.issues)
        assert h._s.ledger.reverify(sup_id).status is ClaimStatus.SUPPORTED
        rep = h.report_build()
        assert f"- Imported bundle: authenticity not established (source sha256 `{bundle_sha}`)" in rep["markdown"]
        assert f"### {proven_id} - PROVEN" not in rep["markdown"]
    finally:
        h.close()


# ---------------------------------------------------------------- claim cap
def test_proven_in_bundle_stays_proven_and_report_header_states_import(tmp_path):
    h, _, bundle_sha, proven_id, sup_id = _imported_hub(tmp_path)
    try:
        v = h._s.ledger.reverify(proven_id)
        assert v.status is ClaimStatus.PROVEN                      # the bundle said PROVEN: not lowered
        assert any(i["code"] == "IMPORTED_BUNDLE_UNAUTHENTICATED" and i["detail"] == IMPORT_NOTE for i in v.issues)
        assert h._s.ledger.reverify(sup_id).status is ClaimStatus.SUPPORTED
        rep = h.report_build()
        assert (f"- Imported bundle: authenticity not established (source sha256 `{bundle_sha}`)") in rep["markdown"]
        assert rep["counts"]["findings"] == 2 and rep["counts"]["unsupported_claims"] == 0
        assert f"### {proven_id} - PROVEN" in rep["markdown"] and f"### {sup_id} - SUPPORTED" in rep["markdown"]
    finally:
        h.close()


def test_supported_in_bundle_cannot_become_proven_even_if_the_verifier_says_proven(tmp_path, monkeypatch):
    """Tampered/forged evidence is emulated by a verifier that always answers PROVEN: the cap must still hold."""
    h, _, _, proven_id, sup_id = _imported_hub(tmp_path)
    try:
        monkeypatch.setattr("redharness.evidence.ledger.verify_claim",
                            lambda *a, **k: Verdict(ClaimStatus.PROVEN))
        assert h._s.ledger.reverify(sup_id).status is ClaimStatus.SUPPORTED          # reverify
        assert h._s.ledger.reverify(proven_id).status is ClaimStatus.PROVEN
        res = h._s.ledger.add_claim(OBS_TEXT, "observation", "present", [], requested="PROVEN")   # add_claim, same claim
        assert res.claim_id == sup_id and res.status is ClaimStatus.SUPPORTED
        assert any(i["detail"] == IMPORT_NOTE for i in res.issues)
        new = h._s.ledger.add_claim("A claim the bundle never recorded.", "observation", "present", [], requested="PROVEN")
        assert new.status is ClaimStatus.SUPPORTED                                   # unrecorded claims stay <= SUPPORTED
        rep = h.report_build()
        assert f"### {sup_id} - SUPPORTED" in rep["markdown"] and f"### {sup_id} - PROVEN" not in rep["markdown"]
    finally:
        h.close()


def test_native_job_is_not_capped_and_has_no_import_header(tmp_path, monkeypatch):
    target, manifest = _target(tmp_path)
    h = _hub(tmp_path / "native")
    try:
        opened = h.target_open(str(target), str(manifest))
        assert "provenance" not in opened
        monkeypatch.setattr("redharness.evidence.ledger.verify_claim", lambda *a, **k: Verdict(ClaimStatus.PROVEN))
        res = h._s.ledger.add_claim("native claim", "observation", "present", [], requested="PROVEN")
        assert res.status is ClaimStatus.PROVEN and not any(i["detail"] == IMPORT_NOTE for i in res.issues)
        assert "Imported bundle" not in h.report_build()["markdown"]
    finally:
        h.close()


# ---------------------------------------------------------------- side effects in the run result
def test_run_controlled_exposes_side_effects_from_the_mapped_folder(tmp_path):
    target, manifest = _target(tmp_path)

    def drop(out_dir, idx):
        (out_dir / "dropped.txt").write_text("x", encoding="utf-8")
        (out_dir / "sub").mkdir(exist_ok=True)
        (out_dir / "sub" / "payload.bin").write_bytes(b"\x00")

    h = _hub(tmp_path / "se", target_writes=drop)
    try:
        h.target_open(str(target), str(manifest))
        r = h.call("run_controlled", {}, lambda: h.run_controlled([{"stdin": GOOD_KEY + "\n"}], 10))
        assert r["status"] == "OK"
        assert r["side_effects"] == ["out/dropped.txt", "out/sub/payload.bin"]   # staged inputs and guest records are not listed
        ev = h._s.ledger.state["evidence"][r["evidence_ids"][0]]
        assert ev["parameters"]["side_effects"] == r["side_effects"]
    finally:
        h.close()


def test_run_controlled_without_side_effects_returns_an_empty_list(tmp_path):
    target, manifest = _target(tmp_path)
    h = _hub(tmp_path / "se0")
    try:
        h.target_open(str(target), str(manifest))
        r = h.call("run_controlled", {}, lambda: h.run_controlled([{"stdin": GOOD_KEY + "\n"}], 10))
        assert r["side_effects"] == [] and "side_effects_total" not in r
        ev = h._s.ledger.state["evidence"][r["evidence_ids"][0]]
        assert "side_effects" not in ev["parameters"]
    finally:
        h.close()
