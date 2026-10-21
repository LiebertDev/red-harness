"""IDA install discovery: all 9.4 editions are considered, Pro tier is preferred, override wins, idalib.dll required."""
import logging
from pathlib import Path

import pytest

from redharness.config import Config
from redharness.engines.base import EngineInfo
from redharness.engines.ida import IdaEngine
from redharness.engines.ida import backend as backend_mod
from redharness.engines.ida.backend import discover_ida_dir, discover_ida_install

FAKE = Path(__file__).with_name("_fake_ida_worker.py")


@pytest.fixture
def program_files(tmp_path, monkeypatch):
    """Empty Program Files plus no override in the environment."""
    pf = tmp_path / "Program Files"
    pf.mkdir()
    monkeypatch.setenv("ProgramFiles", str(pf))
    for var in ("RH_IDA_DIR", "IDADIR"):
        monkeypatch.delenv(var, raising=False)
    return pf


def make_install(base: Path, name: str, *, idalib: bool = True) -> Path:
    d = base / name
    d.mkdir(parents=True)
    if idalib:
        (d / "idalib.dll").write_bytes(b"x")
    return d


def test_professional_preferred_over_newer_home(program_files):
    pro = make_install(program_files, "IDA Professional 9.4")
    make_install(program_files, "IDA Home 9.5")
    install = discover_ida_install()
    assert install is not None and install.path == pro and install.edition == "professional"
    assert discover_ida_dir() == pro


def test_newest_pro_tier_version_first(program_files):
    make_install(program_files, "IDA Professional 9.3")
    make_install(program_files, "IDA Ultimate 9.4")
    make_install(program_files, "IDA Expert 9.4.1")  # newest of all
    chosen = discover_ida_install()
    assert chosen is not None and chosen.path == program_files / "IDA Expert 9.4.1"


def test_home_used_when_only_home_exists(program_files):
    home = make_install(program_files, "IDA Home 9.4")
    install = discover_ida_install()
    assert install is not None and install.path == home and install.edition == "home"


def test_classroom_edition_is_exposed(program_files):
    make_install(program_files, "IDA Classroom 9.4")
    install = discover_ida_install()
    assert install is not None and install.edition == "classroom"


def test_dir_without_idalib_is_skipped_with_debug_note(program_files, caplog):
    make_install(program_files, "IDA Professional 9.5", idalib=False)
    home = make_install(program_files, "IDA Home 9.4")
    caplog.set_level(logging.DEBUG, logger="redharness.engines.ida.backend")
    install = discover_ida_install()
    assert install is not None and install.path == home
    assert "idalib.dll not found" in caplog.text
    assert "may not ship idalib" in caplog.text


def test_only_dir_without_idalib_gives_no_install(program_files):
    make_install(program_files, "IDA Home 9.4", idalib=False)
    assert discover_ida_install() is None and discover_ida_dir() is None


def test_env_override_wins_over_professional(program_files, monkeypatch):
    make_install(program_files, "IDA Professional 9.4")
    home = make_install(program_files.parent / "custom", "my ida home")
    monkeypatch.setenv("RH_IDA_DIR", str(home))
    install = discover_ida_install()
    assert install is not None and install.path == home and install.edition == "home"


def test_explicit_argument_wins_over_env(program_files, tmp_path, monkeypatch):
    pf_pro = make_install(program_files, "IDA Professional 9.4")
    from_env = make_install(tmp_path / "env", "env ida")
    explicit = make_install(tmp_path / "arg", "arg ida")
    monkeypatch.setenv("RH_IDA_DIR", str(from_env))
    assert discover_ida_install(explicit).path == explicit
    assert discover_ida_install().path == from_env
    assert discover_ida_install(pf_pro).path == pf_pro


def test_engine_info_exposes_home_edition(program_files, tmp_path, monkeypatch):
    home = make_install(program_files, "IDA Home 9.4")
    log = tmp_path / "calls.log"
    monkeypatch.setenv("FAKE_LOG", str(log))
    monkeypatch.setenv("FAKE_MODE", "ok")
    engine = IdaEngine(Config.load(tmp_path / "data"), worker=FAKE)
    info = engine.probe()
    assert isinstance(info, EngineInfo) and info.available
    assert info.edition == "home" and info.install_dir == str(home)
    assert "edition=home" in info.detail
    assert engine.edition == "home"


def test_worker_receives_pro_dir_when_home_also_exists(program_files, tmp_path, monkeypatch):
    make_install(program_files, "IDA Home 9.4")
    pro = make_install(program_files, "IDA Professional 9.4")
    log = tmp_path / "calls.log"
    monkeypatch.setenv("FAKE_LOG", str(log))
    monkeypatch.setenv("FAKE_MODE", "ok")
    engine = IdaEngine(Config.load(tmp_path / "data"), worker=FAKE)
    assert engine.probe().edition == "professional"
    first = log.read_text(encoding="utf-8").splitlines()[0]
    assert pro.name in first
    assert backend_mod.discover_ida_dir() == pro


def make_beta(base: Path, name: str, header: str = "# IDA 9.5 Beta") -> Path:
    d = make_install(base, name)
    (d / "release-notes.md").write_text(header + "\n\nA summary.\n", encoding="utf-8")
    return d


def test_stable_preferred_over_newer_beta(program_files):
    stable = make_install(program_files, "IDA Professional 9.4")
    make_beta(program_files, "IDA Professional 9.5")
    install = discover_ida_install()
    assert install is not None and install.path == stable and not install.beta


def test_stable_home_preferred_over_beta_pro(program_files):
    home = make_install(program_files, "IDA Home 9.4")
    make_beta(program_files, "IDA Professional 9.5")
    assert discover_ida_install().path == home


def test_beta_used_when_it_is_the_only_install(program_files, caplog):
    beta = make_beta(program_files, "IDA Professional 9.5")
    with caplog.at_level(logging.WARNING, logger=backend_mod.log.name):
        install = discover_ida_install()
    assert install is not None and install.path == beta and install.beta
    assert any("beta" in r.getMessage() for r in caplog.records)


def test_beta_detected_from_directory_name(program_files):
    make_install(program_files, "IDA Professional 9.5 beta")
    assert discover_ida_install().beta


def test_release_notes_without_beta_header_is_stable(program_files):
    make_beta(program_files, "IDA Professional 9.5", header="# IDA 9.5")
    assert not discover_ida_install().beta


@pytest.mark.parametrize("header", [
    "# IDA 9.5 Beta",
    "# IDA Pro 9.5 beta 2",
    "# 9.5.261001 Beta",
    "# IDA 9.5 Beta 2",
])
def test_explicit_beta_release_marker_is_detected(program_files, header):
    d = make_beta(program_files, "IDA Professional 9.5", header=header)
    assert backend_mod._is_beta(d)


@pytest.mark.parametrize("header", [
    "# IDA 9.5 SP1 — beta migration notes",  # the reviewer's false positive
    "# IDA 9.5 SP1 - beta migration notes",
    "# IDA 9.5 — beta migration notes",  # a mention, but not a release marker
    "# IDA 9.5 (beta migration notes)",
])
def test_beta_mention_is_not_a_beta_release(program_files, header):
    d = make_beta(program_files, "IDA Professional 9.5", header=header)
    assert not backend_mod._is_beta(d)


def test_beta_detected_from_standalone_directory_token(program_files):
    d = make_install(program_files, "IDA Professional 9.5 Beta")
    assert backend_mod._is_beta(d) and discover_ida_install().beta


def test_explicit_beta_override_still_wins(program_files, monkeypatch):
    make_install(program_files, "IDA Professional 9.4")
    beta = make_beta(program_files, "IDA Professional 9.5")
    monkeypatch.setenv("RH_IDA_DIR", str(beta))
    assert discover_ida_install().path == beta


def test_engine_info_marks_beta_build(program_files, tmp_path, monkeypatch):
    make_beta(program_files, "IDA Professional 9.5")
    monkeypatch.setenv("FAKE_LOG", str(tmp_path / "calls.log"))
    monkeypatch.setenv("FAKE_MODE", "ok")
    info = IdaEngine(Config.load(tmp_path / "data"), worker=FAKE).probe()
    assert info.available and "BETA" in info.detail
