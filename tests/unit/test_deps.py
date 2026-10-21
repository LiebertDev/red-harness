"""`rh deps`: the optional third-party component registry and its list / show / install commands.

pip is never run for real here: the install path takes an injected runner, so this tests the UX logic (notice before
install, confirmation, refusal of anything not in the registry) and keeps the registry in step with THIRD_PARTY_NOTICES.md.
"""
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from redharness import deps
from redharness.cli import main as cli_main

ROOT = Path(__file__).resolve().parents[2]


class FakeRun:
    def __init__(self, rc=0):
        self.calls, self.rc = [], rc

    def __call__(self, cmd, *a, **k):
        self.calls.append(list(cmd))
        return subprocess.CompletedProcess(cmd, self.rc)


def no_prompt(_msg):
    raise AssertionError("must not ask")


def test_registry_ids_are_unique_and_only_pip_components_carry_a_spec():
    ids = [c.id for c in deps.REGISTRY] + [a for c in deps.REGISTRY for a in c.aliases]
    assert len(ids) == len(set(ids))
    for c in deps.REGISTRY:
        assert (c.kind == "pip") == bool(c.pip_spec), c.id
        assert c.license_url.startswith("https://") and c.upstream_url.startswith("https://")
        if c.kind == "pip":   # exactly one pinned requirement, nothing else could ever reach pip
            assert re.fullmatch(rf"{c.pip_package}==\d+(\.\d+)+", c.pip_spec)


def test_pinned_specs_match_pyproject_extras():
    extras = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["optional-dependencies"]
    for c in deps.REGISTRY:
        if c.kind == "pip" and c.extra in extras:   # the Core build has no `disasm` extra
            assert extras[c.extra] == [c.pip_spec], c.id
    assert extras["emulate"] == [deps.find("unicorn").pip_spec]


def test_third_party_notices_covers_every_component_and_says_not_ours():
    text = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    for c in deps.REGISTRY:
        assert c.pip_spec == "" or c.pip_spec in text, c.id
    for needle in ("Unicorn", "Capstone", "Ghidra", "IDA Pro", "embeddable", "Windows Sandbox", "Apache-2.0",
                   "https://github.com/unicorn-engine/unicorn", "https://github.com/capstone-engine/capstone"):
        assert needle in text, needle
    assert text.count("not covered by Red Harness's Apache-2.0 licence") >= 6
    assert "Bundled:** no" in text and "bundles and redistributes none" in text
    assert (ROOT / "licenses" / "README.md").is_file()


def test_find_resolves_aliases_and_rejects_unknown():
    assert deps.find("emulate").id == "unicorn" and deps.find("DISASM").id == "capstone"
    assert deps.find("pip-evil") is None


def test_list_shows_every_component_with_licence_and_link(capsys, monkeypatch):
    monkeypatch.setattr(deps, "status", lambda c: (c.id == "unicorn", "2.1.4" if c.id == "unicorn" else ""))
    assert deps.main(["list"]) == 0
    out = capsys.readouterr().out
    for c in deps.REGISTRY:
        assert c.id in out and c.upstream_url in out
    assert "installed 2.1.4" in out and "not found" in out and "GPL-2.0" in out and "BSD-3-Clause" in out
    assert "nothing is bundled" in out


def test_list_json_is_machine_readable_and_never_claims_bundling(capsys, monkeypatch):
    monkeypatch.setattr(deps, "status", lambda c: (False, ""))
    assert deps.main(["list", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert [r["id"] for r in rows] == [c.id for c in deps.REGISTRY]
    assert all(r["bundled"] is False for r in rows)
    assert {r["id"] for r in rows if r["installable"]} == {"unicorn", "capstone"}


def test_detection_never_raises(monkeypatch):
    def boom():
        raise RuntimeError("probe broke")
    monkeypatch.setitem(deps._DETECTORS, "ghidra", boom)
    assert deps.status(deps.find("ghidra")) == (False, "")


def test_install_yes_prints_notice_then_runs_exactly_the_pinned_pip_command(capsys, monkeypatch):
    run = FakeRun()
    versions = iter([None, "2.1.4"])   # before / after
    monkeypatch.setattr(deps, "pip_version", lambda _p: next(versions))
    assert deps.main(["install", "emulate", "--yes"], run=run, ask=no_prompt) == 0
    assert run.calls == [[sys.executable, "-m", "pip", "install", "unicorn==2.1.4"]]
    out = capsys.readouterr().out
    assert out.index("GPL-2.0") < out.index("installed: unicorn 2.1.4")   # notice comes before the install result
    assert "Not part of Red Harness" in out


def test_install_asks_and_aborts_by_default(capsys, monkeypatch):
    monkeypatch.setattr(deps, "pip_version", lambda _p: None)
    for answer in ("", "n", "no", "maybe"):
        run = FakeRun()
        assert deps.main(["install", "capstone"], run=run, ask=lambda _m, a=answer: a) == 1
        assert run.calls == []
    assert "aborted" in capsys.readouterr().out


def test_install_confirmed_by_typing_yes(monkeypatch):
    versions = iter([None, "5.0.6"])
    monkeypatch.setattr(deps, "pip_version", lambda _p: next(versions))
    run = FakeRun()
    assert deps.main(["install", "capstone"], run=run, ask=lambda _m: "y") == 0
    assert run.calls == [[sys.executable, "-m", "pip", "install", "capstone==5.0.6"]]


def test_install_without_a_terminal_aborts(monkeypatch):
    monkeypatch.setattr(deps, "pip_version", lambda _p: None)

    def eof(_m):
        raise EOFError
    run = FakeRun()
    assert deps.main(["install", "emulate"], run=run, ask=eof) == 1 and run.calls == []


def test_dry_run_only_prints_the_command(capsys, monkeypatch):
    monkeypatch.setattr(deps, "pip_version", lambda _p: None)
    run = FakeRun()
    assert deps.main(["install", "emulate", "--dry-run"], run=run, ask=no_prompt) == 0
    assert run.calls == []
    assert "pip install unicorn==2.1.4" in capsys.readouterr().out


def test_pip_failure_is_reported_and_not_called_success(capsys, monkeypatch):
    monkeypatch.setattr(deps, "pip_version", lambda _p: None)
    assert deps.main(["install", "emulate", "--yes"], run=FakeRun(rc=7), ask=no_prompt) == 7
    assert "pip failed (exit 7)" in capsys.readouterr().out


@pytest.mark.parametrize("ident", ["ghidra", "ida", "python-embed", "windows-sandbox"])
def test_bring_your_own_components_are_never_installed(ident, capsys):
    run = FakeRun()
    assert deps.main(["install", ident, "--yes"], run=run, ask=no_prompt) == 1
    assert run.calls == []
    out = capsys.readouterr().out
    assert "does not install" in out and "How to get it" in out


def test_ghidra_and_ida_guidance_names_the_environment_variables_the_code_reads(capsys):
    from redharness.engines.ghidra.backend import ENV_GHIDRA_DIR
    from redharness.engines.ida.backend import ENV_IDA_DIR, ENV_IDA_PYTHON
    assert ENV_GHIDRA_DIR in deps.find("ghidra").env
    assert {ENV_IDA_DIR, ENV_IDA_PYTHON} <= set(deps.find("ida").env)
    assert deps.main(["show", "ida"]) == 0
    out = capsys.readouterr().out
    assert "RH_IDA_DIR" in out and "hex-rays.com/eula" in out and "Proprietary" in out


@pytest.mark.parametrize("argv", [["install", "requests", "--yes"], ["install", "unicorn==9.9", "--yes"],
                                  ["install", "../evil", "--yes"], ["install", "unicorn", "extra", "--yes"],
                                  ["install"], ["install", "unicorn", "--index-url=http://x"], ["show"], ["bogus"],
                                  ["list", "--nope"]])
def test_anything_not_listed_or_malformed_is_refused_without_running_pip(argv, capsys):
    run = FakeRun()
    assert deps.main(argv, run=run, ask=no_prompt) == 2
    assert run.calls == []
    capsys.readouterr()


def test_cli_dispatches_rh_deps(capsys, monkeypatch):
    monkeypatch.setattr(deps, "status", lambda c: (False, ""))
    assert cli_main(["deps"]) == 0
    assert "unicorn" in capsys.readouterr().out
    assert cli_main(["help"]) == 0
    assert "deps" in capsys.readouterr().out
