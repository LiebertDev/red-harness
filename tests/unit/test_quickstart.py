"""`rh quickstart`: manifest generation, engine selection and the whole orchestration with a fake engine (no Ghidra or
IDA needed). The pass goes through Hub.call, the dispatch the MCP server uses, so the effect table, the scope manifest
check and the claim verifier are the real ones."""
import hashlib
import json
from pathlib import Path

import pytest

from redharness import cli, quickstart
from redharness.config import Config
from redharness.mcp.server import EngineSelectionError
from redharness.scope.manifest import load_manifest

from . import _synthpe
from ._fake_engine import FakeEngine


@pytest.fixture
def target(tmp_path) -> Path:
    p = tmp_path / "sample.exe"
    p.write_bytes(_synthpe.build_pe(imports={"KERNEL32.dll": ["CreateFileW", "ReadFile"], "user32.dll": ["MessageBoxW"]}))
    return p


def _fake_make(name, config):
    if name != "ghidra":
        raise EngineSelectionError(f"engine {name!r} requested but unavailable: not installed")
    return FakeEngine()


# ---------------------------------------------------------------- manifest
def test_manifest_has_hash_static_only_and_the_authorization_statement(target, tmp_path):
    path, sha = quickstart.write_manifest(target, tmp_path / "q")
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert sha == hashlib.sha256(target.read_bytes()).hexdigest() == doc["target_sha256"]
    assert doc["schema"] == "rh.scope/1" and doc["allowed_operations"] == ["static"]
    assert doc["authorization"]["basis"] == "authorized-test"
    stmt = doc["authorization"]["statement"].lower()
    assert "theirs" in stmt and "authorized to analyse" in stmt and "static analysis only" in stmt
    man, sha2 = load_manifest(path, target)    # the real loader accepts it
    assert sha2 == sha and man.allows("static") and not man.allows("run_controlled")


def test_manifest_basis_is_validated_and_missing_file_refused(target, tmp_path):
    p, _ = quickstart.write_manifest(target, tmp_path / "q", basis="owner")
    assert json.loads(p.read_text())["authorization"]["basis"] == "owner"
    with pytest.raises(quickstart.QuickstartError):
        quickstart.write_manifest(target, tmp_path / "q2", basis="whatever")
    with pytest.raises(quickstart.QuickstartError):
        quickstart.write_manifest(tmp_path / "nope.exe", tmp_path / "q3")


# ---------------------------------------------------------------- engine selection
def test_select_engine_prefers_ghidra_then_falls_back_to_ida(tmp_path):
    cfg = Config.load(tmp_path / "d")
    e, name, notes = quickstart.select_engine(cfg, None, _fake_make)
    assert name == "ghidra" and e is not None and notes == []
    tried = []

    def only_ida(n, c):
        tried.append(n)
        if n == "ghidra":
            raise EngineSelectionError("engine 'ghidra' requested but unavailable: no JDK")
        return FakeEngine()
    e, name, notes = quickstart.select_engine(cfg, None, only_ida)
    assert name == "ida" and tried == ["ghidra", "ida"] and "no JDK" in notes[0]


def test_select_engine_explicit_choice_has_no_fallback_and_none_is_reported(tmp_path):
    cfg = Config.load(tmp_path / "d")
    e, name, notes = quickstart.select_engine(cfg, "ida", _fake_make)
    assert e is None and name == "" and len(notes) == 1 and notes[0].startswith("ida:")
    with pytest.raises(quickstart.QuickstartError):
        quickstart.select_engine(cfg, "binja", _fake_make)


# ---------------------------------------------------------------- orchestration
def test_full_pass_with_a_fake_engine(target, tmp_path):
    lines: list[str] = []
    rc = quickstart.main([str(target), "--data-root", str(tmp_path / "data")], make_engine_fn=_fake_make,
                         out=lines.append)
    text = "\n".join(lines)
    assert rc == 0, text
    for step in ("target_open", "functions_list", "imports", "strings", "claim_add"):
        assert step in text
    assert "SUPPORTED: The target imports KERNEL32.dll!" in text
    assert "SUPPORTED: The target contains the string" in text
    assert "pe profile PE32+ x64" in text and "not 'clean'" in text
    assert "0 unsupported claims" in text and "2 recorded, 2 verified" in text
    report = Path(next(l for l in lines if l.startswith("Report: ")).split(": ", 1)[1])
    md = report.read_text(encoding="utf-8")
    assert "KERNEL32.dll!" in md and report.parent.name == "report"
    qdir = tmp_path / "data" / "quickstart" / hashlib.sha256(target.read_bytes()).hexdigest()[:16]
    cfg = json.loads((qdir / "mcp.json").read_text())["mcpServers"]["red-harness"]
    assert cfg["args"] == ["mcp", "--engine", "ghidra"] and cfg["env"]["RH_DATA_ROOT"] == str(tmp_path / "data")
    assert "Next step" in text and ".mcp.json" in text and "Total time" in text


def test_pass_runs_only_static_tools_and_records_them_in_the_journal(target, tmp_path):
    from redharness.mcp.session import Hub
    cfg = Config.load(tmp_path / "data")
    man, _ = quickstart.write_manifest(target, tmp_path / "q")
    hub = Hub(cfg, FakeEngine())
    try:
        res = quickstart.run_pass(target, man, hub, lambda s: None)
    finally:
        hub.close()
    assert res.ok and res.counts["unsupported_claims"] == 0 and res.counts["findings"] == 2
    assert set(res.timings) >= {"target_open", "imports", "strings", "report_build"}
    journal = (cfg.job_dir(res.job_id) / "events.jsonl").read_text(encoding="utf-8")
    assert "run_controlled" not in journal and "report_build" in journal


def test_no_usable_engine_is_a_clear_error(target, tmp_path, capsys):
    def none(n, c):
        raise EngineSelectionError(f"engine {n!r} requested but unavailable: nothing installed")
    rc = quickstart.main([str(target), "--data-root", str(tmp_path / "d")], make_engine_fn=none, out=lambda s: None)
    err = capsys.readouterr().err
    assert rc == 1 and "no analysis engine is usable" in err and "rh deps show ghidra" in err


def test_missing_target_and_bad_usage(tmp_path, capsys):
    assert quickstart.main([str(tmp_path / "nope.exe"), "--data-root", str(tmp_path / "d")],
                           make_engine_fn=_fake_make, out=lambda s: None) == 1
    assert "not found" in capsys.readouterr().err
    assert quickstart.main([], out=lambda s: None) == 2
    assert quickstart.main(["--help"], out=lambda s: None) == 0


def test_scope_refusal_from_the_hub_is_reported_not_raised(target, tmp_path, capsys, monkeypatch):
    def bad(t, d, basis="authorized-test"):
        d.mkdir(parents=True, exist_ok=True)
        p = d / "scope.json"
        p.write_text("{}", encoding="utf-8")
        return p, "0" * 64
    monkeypatch.setattr(quickstart, "write_manifest", bad)
    rc = quickstart.main([str(target), "--data-root", str(tmp_path / "d")], make_engine_fn=_fake_make,
                         out=lambda s: None)
    assert rc == 1 and "SCOPE_DENIED" in capsys.readouterr().err


def test_cli_dispatches_quickstart(monkeypatch):
    seen = {}

    def fake_main(argv, **kw):
        seen["argv"] = argv
        return 0
    monkeypatch.setattr(quickstart, "main", fake_main)
    assert cli.main(["quickstart", "x.exe", "--engine", "ghidra"]) == 0
    assert seen["argv"] == ["x.exe", "--engine", "ghidra"]
    assert "quickstart" in cli.HELP
