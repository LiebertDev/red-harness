"""MCP server: with a real stdio client (SDK client), with a fake engine. Does not need IDA."""
import asyncio
import json
from pathlib import Path

import pytest

from redharness.config import Config
from redharness.core.journal import Journal, verify_file
from redharness.mcp.server import MAX_TOOLS, TOOL_NAMES
from redharness.scope.manifest import ScopeError, load_manifest, parse_manifest

from .mcp_helpers import call, make_manifest, mcp_session

SERVER = [str(Path(__file__).with_name("_fake_mcp_server.py"))]
BASE = 0x140000000


@pytest.fixture
def env(tmp_path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"MZ" + bytes(range(256)) * 8)
    return {"target": target, "manifest": make_manifest(tmp_path / "scope.json", target),
            "data": tmp_path / "data", "log": tmp_path / "engine.log", "tmp": tmp_path}


def run(coro):
    return asyncio.run(coro)


def engine_calls(env, op=None):
    if not env["log"].exists():
        return []
    rows = [json.loads(x) for x in env["log"].read_text(encoding="utf-8").splitlines()]
    return [r for r in rows if op is None or r["op"] == op]


def session(env):
    return mcp_session(SERVER, env["data"], {"FAKE_ENGINE_LOG": str(env["log"])})


def open_args(env):
    return {"target_path": str(env["target"]), "manifest_path": str(env["manifest"])}


def test_tool_listing_matches_the_registry():
    async def go():
        async with mcp_session(SERVER, Path(".")) as s:
            return [t.name for t in (await s.list_tools()).tools]
    names = run(go())
    assert sorted(names) == sorted(TOOL_NAMES)
    assert len(names) <= MAX_TOOLS


def test_tool_count_is_pinned():
    # The single intentional pin of the tool count: adding or removing a tool is a surface change that needs a
    # deliberate decision. The public docs state this number too; tests/unit/test_doc_drift.py keeps them equal to
    # the registry, so both must move together.
    assert len(TOOL_NAMES) == 18


def test_instructions_are_client_neutral_but_mention_name_prefixes():
    from redharness.mcp.server import INSTRUCTIONS
    assert "Your client may prefix tool names" in INSTRUCTIONS
    assert "use the names your client lists" in INSTRUCTIONS
    assert "Call tools only by these exact names." not in INSTRUCTIONS   # that sentence belongs to the eval prompt


def test_target_open_refused_without_valid_scope(env):
    async def go():
        async with session(env) as s:
            out = {}
            out["no_manifest_file"] = await call(s, "target_open", target_path=str(env["target"]),
                                                 manifest_path=str(env["tmp"] / "missing.json"))
            wrong = make_manifest(env["tmp"] / "wrong.json", env["target"], target_sha256="0" * 64)
            out["sha_mismatch"] = await call(s, "target_open", target_path=str(env["target"]),
                                             manifest_path=str(wrong))
            nostate = make_manifest(env["tmp"] / "nostate.json", env["target"])
            d = json.loads(nostate.read_text())
            del d["authorization"]
            nostate.write_text(json.dumps(d))
            out["no_authorization"] = await call(s, "target_open", target_path=str(env["target"]),
                                                 manifest_path=str(nostate))
            out["expired"] = await call(s, "target_open", target_path=str(env["target"]), manifest_path=str(
                make_manifest(env["tmp"] / "exp.json", env["target"], expires="2020-01-01")))
            out["no_static"] = await call(s, "target_open", target_path=str(env["target"]), manifest_path=str(
                make_manifest(env["tmp"] / "ns.json", env["target"], allowed_operations=["patch_poc"])))
            out["before_open"] = await call(s, "functions_list")
            return out
    out = run(go())
    for k, (is_err, msg) in out.items():
        assert is_err, k
    assert "SCOPE_DENIED" in out["no_manifest_file"][1]
    assert "does not match" in out["sha_mismatch"][1]
    assert "authorization" in out["no_authorization"][1]
    assert "expired" in out["expired"][1]
    assert "NO_TARGET" in out["before_open"][1]
    assert not engine_calls(env)  # the engine never ran for the refused open
    assert not any((env["data"] / "jobs").glob("*")) if (env["data"] / "jobs").exists() else True
    # refused calls were also written to the journal (hash-chained)
    logs = list((env["data"] / "mcp").glob("pre-open-*.jsonl"))
    assert logs and verify_file(logs[0]).ok
    ev = Journal(logs[0]).events()
    assert [e["payload"]["tool"] for e in ev].count("target_open") == 5
    assert all(e["payload"]["ok"] is False for e in ev)


def test_manifest_unit_rules(tmp_path):
    with pytest.raises(ScopeError):
        parse_manifest({"schema": "rh.scope/1"})
    with pytest.raises(ScopeError):
        load_manifest(None, tmp_path / "x")


def test_end_to_end_with_resume(env):
    async def first():
        async with session(env) as s:
            is_err, o = await call(s, "target_open", **open_args(env))
            assert not is_err, o
            assert o["resumed"] is False and o["previous"]["claim_count"] == 0
            sha = o["target_sha256"]

            # pagination + size limit
            _, f1 = await call(s, "functions_list", offset=0, limit=50)
            assert f1["evidence_id"].startswith("ev_") and f1["untrusted_content"] is True
            assert f1["result"]["returned"] == 50 and f1["result"]["next_offset"] == 50
            assert len(f1["content"]) < 30_000
            _, f2 = await call(s, "functions_list", offset=50, limit=200)
            assert f2["result"]["offset"] == 50 and f2["evidence_id"] != f1["evidence_id"]
            assert (await call(s, "functions_list", limit=0))[0] is False  # limit is clamped to at least 1

            # decompile (address), untrusted marker and escaping
            _, d = await call(s, "decompile", function="0x140001250")
            assert d["status"] == "OK" and d["result"]["name"] == "validate_license"
            assert d["_meta"]["provenance"]["untrusted_content"] is True
            body = d["content"]
            assert body.startswith('<untrusted_target_content evidence_id="' + d["evidence_id"])
            assert body.count("</untrusted_target_content>") == 1  # the target's closing tag was escaped
            _, d2 = await call(s, "decompile", function="0x140001250", max_chars=40)
            assert d2["evidence_id"] == d["evidence_id"] and d2["shown"]["next_offset"] == 40
            assert (await call(s, "decompile", function="0x1"))[0] is True  # no such function -> error

            _, x = await call(s, "xrefs", address="0x140001250", direction="to")
            assert x["evidence_id"].startswith("ev_") and "0x1400010fe" in x["content"]
            _, st = await call(s, "strings", pattern="License", limit=10)
            assert st["result"]["total"] == 1 and "License invalid" in st["content"]

            ev = d["evidence_id"]
            # good claim: quote + address
            _, c1 = await call(s, "claim_add", text="validate_license at 0x140001250 (RVA 0x1250) xors with 0x5EC2E7A1.",
                               evidence_ids=[ev], atoms=[
                                   {"type": "quote", "evidence_id": ev, "text": "0x811C9DC5 ^ 0x5EC2E7A1"},
                                   {"type": "address", "evidence_id": ev, "space": "va", "value": "0x140001250"}], kind="observation")
            assert c1["status"] == "SUPPORTED" and c1["accepted"], c1
            # NEGATIVE: a claim without evidence is rejected
            _, bad = await call(s, "claim_add", text="The program phones home to evil.example.", kind="observation")
            assert bad["status"] == "REJECTED" and not bad["accepted"]
            assert [i["code"] for i in bad["issues"]] == ["NO_EVIDENCE"]
            # NEGATIVE: quote not in the evidence, made-up evidence id, wrong address
            _, bq = await call(s, "claim_add", text="It calls CreateFileW.", evidence_ids=[ev], atoms=[
                {"type": "quote", "evidence_id": ev, "text": "CreateFileW(path)"}], kind="observation")
            assert bq["status"] == "REJECTED" and "QUOTE_NOT_IN_RAW" in [i["code"] for i in bq["issues"]]
            _, bf = await call(s, "claim_add", text="Imaginary.", evidence_ids=["ev_" + "0" * 64], kind="observation")
            assert bf["status"] == "REJECTED" and bf["issues"][0]["code"] == "UNKNOWN_EVIDENCE_ID"
            _, ba = await call(s, "claim_add", text="Entry at 0x140009999.", evidence_ids=[ev], kind="observation")
            assert ba["status"] == "REJECTED"
            # PROVEN is not granted from static evidence
            _, pr = await call(s, "claim_add", text="validate_license compares a 16-bit value.",
                               evidence_ids=[ev], atoms=[{"type": "quote", "evidence_id": ev, "text": "& 0xFFFF"}],
                               requested="PROVEN", kind="observation")
            assert pr["status"] == "SUPPORTED" and pr["issues"][0]["code"] == "PROVEN_STATIC_CLAIM"
            # hypothesis: no evidence but explicitly UNVERIFIED
            _, hy = await call(s, "claim_add", text="Maybe the secret is rotated per build.", requested="UNVERIFIED", kind="observation")
            assert hy["status"] == "UNVERIFIED" and hy["hypothesis"] is True

            _, rep = await call(s, "report_build")
            md = rep["markdown"]
            assert rep["counts"] == {"findings": 2, "hypotheses": 1, "rejected_at_add": 4,
                                     "failed_reverify": 0, "superseded": 0, "unsupported_claims": 0,
                                     "claims_without_evidence": 0, "claims_value_not_in_evidence": 0,
                                     "claims_behavior_without_execution": 0,
                                     "hypotheses_without_evidence": 1, "hypotheses_value_not_in_evidence": 0,
                                     "hypotheses_behavior_needs_execution": 0, "hypotheses_other": 0}
            assert md.index("## Unverified hypotheses") > md.index("## Verified findings")
            findings, hyp = md.split("## Unverified hypotheses")
            assert "validate_license at 0x140001250" in findings.replace("\\", "")
            assert "Maybe the secret" in hyp and "Maybe the secret" not in findings
            assert "phones home" not in md and "CreateFileW" not in md  # rejected claims do not enter the report
            return sha, ev, c1["claim_id"], f1["evidence_id"], rep["counts"]

    sha, ev, claim_id, f1_ev, counts1 = run(first())
    n_functions = len(engine_calls(env, "functions"))
    n_decompile = len(engine_calls(env, "decompile"))
    jdir = Config.load(env["data"]).job_dir("job_" + sha[:16])
    assert verify_file(jdir / "events.jsonl").ok  # the journal chain is intact

    async def second():  # new session, new process
        async with session(env) as s:
            _, o = await call(s, "target_open", **open_args(env))
            assert o["resumed"] is True
            ids = [e["evidence_id"] for e in o["previous"]["evidence"]]
            assert ev in ids and f1_ev in ids
            claims = {c["claim_id"]: c["status"] for c in o["previous"]["claims"]}
            assert claims[claim_id] == "SUPPORTED" and len(claims) == 3  # SUPPORTED x2 + hypothesis
            # same steps: the engine does not rerun, the ids are the same
            _, f1 = await call(s, "functions_list", offset=0, limit=50)
            assert f1["step_cached"] is True and f1["evidence_id"] == f1_ev
            _, d = await call(s, "decompile", function="0x140001250")
            assert d["step_cached"] is True and d["evidence_id"] == ev
            # a new claim using the earlier evidence is still verified
            _, c = await call(s, "claim_add", text="validate_license masks the value with 0x00FFFF",
                              evidence_ids=[ev], kind="observation")
            assert c["status"] == "SUPPORTED"  # 0x00FFFF == 0xFFFF numerically is in the evidence
            _, c = await call(s, "claim_add", text="validate_license uses seed 0x1234567", evidence_ids=[ev], kind="observation")
            assert c["status"] == "REJECTED"
            _, rep = await call(s, "report_build")
            assert rep["counts"]["findings"] == 3 and rep["counts"]["unsupported_claims"] == 0
            assert rep["counts"]["hypotheses_without_evidence"] == 1  # hypothesis without evidence (from the earlier session), not a finding
            return None

    run(second())
    assert len(engine_calls(env, "functions")) == n_functions
    assert len(engine_calls(env, "decompile")) == n_decompile
    # all calls are in the journal
    j = Journal(jdir / "events.jsonl")
    calls = [e["payload"]["tool"] for e in j.events() if e["type"] == "TOOL_CALL"]
    assert calls.count("target_open") == 2 and calls.count("report_build") == 2
    assert {"functions_list", "decompile", "xrefs", "strings", "claim_add"} <= set(calls)
    types = [e["type"] for e in j.events()]
    assert types.count("TARGET_OPENED") == 2 and "REPORT_BUILT" in types and "EVIDENCE_RECORDED" in types
    j.close()


def test_second_server_on_same_job_is_refused(env):
    async def go():
        async with session(env) as s1:
            assert not (await call(s1, "target_open", **open_args(env)))[0]
            async with session(env) as s2:
                return await call(s2, "target_open", **open_args(env))
    is_err, msg = run(go())
    assert is_err and "JOB_LOCKED" in msg
