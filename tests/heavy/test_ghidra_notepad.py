"""Real Ghidra 12.x headless integration test: on a COPY of notepad.exe. Skipped if Ghidra/JDK is absent."""
import os
import sys
import time
from pathlib import Path

import pytest

from redharness.config import Config
from redharness.core.result import Status
from redharness.engines.ghidra import GhidraEngine

from tests.unit.engine_contract import EngineContract, pick_function, sha_of

pytestmark = pytest.mark.heavy
GLOBAL_SETTINGS = Path(os.environ.get("APPDATA", "")) / "ghidra"


def snapshot(root: Path):
    if not root.exists():
        return None
    return sorted((str(p.relative_to(root)), p.stat().st_size, p.stat().st_mtime_ns)
                  for p in root.rglob("*") if p.is_file())


@pytest.fixture(scope="module")
def global_before():
    """State of the user's global Ghidra settings directory (%APPDATA%\\ghidra) BEFORE the engine is used."""
    return snapshot(GLOBAL_SETTINGS)


@pytest.fixture(scope="module")
def sample(notepad_copy):
    return notepad_copy


@pytest.fixture(scope="module")
def engine(heavy_data_root, global_before):
    e = GhidraEngine(Config.load(heavy_data_root))
    info = e.probe()
    if not info.available:
        pytest.skip(f"Ghidra/JDK unavailable: {info.detail}")
    runs = []
    orig = e._run

    def counting(op, req, proj_parent, mode, timeout_s, **kw):
        runs.append((op, tuple(mode)))
        return orig(op, req, proj_parent, mode, timeout_s, **kw)

    e._run = counting
    e.runs = runs
    return e


@pytest.fixture(scope="module")
def analysis_count(engine):
    return lambda: sum(1 for op, _ in engine.runs if op == "analyze")


class TestGhidraContract(EngineContract):
    """The same contract suite as with the fake process, with real Ghidra."""


@pytest.fixture(scope="module")
def target(engine, sample):
    r = engine.open_target(sample)
    assert r.ok, r.detail
    return r


def test_probe_reports_real_version(engine):
    info = engine.probe()
    assert info.available and info.version.count(".") == 2


def test_function_count_arch_and_externals(engine, target):
    t = target.data
    assert t.function_count > 100  # the exact count is version-dependent and not pinned
    assert t.bits == 64 and t.arch == "x86" and t.decompiler
    assert t.image_base and t.entry > t.image_base  # for the RVA computation (MCP server)
    page = engine.functions(t.sha256, limit=10_000).data
    assert page.total == t.function_count and len(page.items) == t.function_count
    # 794 = internal functions + import stubs in the External space
    ext = engine._meta(engine._tdir(engine.probe().version, t.sha256), t.sha256)["info"]["external_function_count"]
    assert ext > 0


def test_decompile_real_function(engine, target):
    sha = target.data.sha256
    fn = pick_function(engine, sha)
    d = engine.decompile(sha, fn.address)
    assert d.ok and d.untrusted_content
    assert "{" in d.data.text and "}" in d.data.text and "(" in d.data.text
    assert d.data.address == fn.address
    byname = engine.decompile(sha, fn.name)
    assert byname.ok and byname.data.address == fn.address
    assert not engine.decompile(sha, "no_such_function").ok


def test_second_open_hits_cache_without_reanalysis(engine, sample, heavy_data_root, target):
    before = sum(1 for op, _ in engine.runs if op == "analyze")
    t0 = time.monotonic()
    r = engine.open_target(sample)
    dt = time.monotonic() - t0
    assert r.ok and r.cached and sum(1 for op, _ in engine.runs if op == "analyze") == before
    assert dt < 5, dt
    fresh = GhidraEngine(Config.load(heavy_data_root))  # a new session must also get a hit
    t1 = time.monotonic()
    r3 = fresh.open_target(sample)
    assert r3.ok and r3.cached
    print(f"\nfirst analysis {target.duration_s:.1f} s ({target.extra}); cache hit {dt:.3f} s; "
          f"new session hit {time.monotonic() - t1:.3f} s")


def test_queries_never_reimport_and_use_readonly_process(engine, target):
    fn = pick_function(engine, target.data.sha256)
    assert engine.xrefs(target.data.sha256, fn.address, direction="from").data is not None
    imports = [m for op, m in engine.runs if m and m[0] == "-import"]
    assert len(imports) <= 1  # no import other than the first analysis
    for op, m in engine.runs:
        if op != "analyze":
            assert m == ("-process", "target.exe", "-noanalysis", "-readOnly")


def test_jvm_not_in_this_process_and_peak_memory_bounded(engine, target):
    assert "jpype" not in sys.modules and "pyghidra" not in sys.modules
    peak = target.extra.get("peak_job_memory")
    if not target.cached and peak:
        assert peak < 6 * 1024 ** 3


def test_analysis_timeout_is_never_ok(tmp_path, sample):
    e = GhidraEngine(Config.load(tmp_path / "d"), analyze_timeout_s=2)
    if not e.probe().available:
        pytest.skip("Ghidra not available")
    r = e.open_target(sample)
    assert r.status is Status.TIMEOUT and not r.ok and r.data is None
    assert not e._tdir(e.probe().version, sha_of(sample)).exists()
    assert not list(e._tdir(e.probe().version, sha_of(sample)).parent.glob("*.partial-*"))


def test_user_global_ghidra_settings_untouched(engine, target, global_before):
    fn = pick_function(engine, target.data.sha256)
    # a unique limit on every run to avoid the result cache -> a new JVM is really started
    fresh_limit = 1000 + (time.time_ns() % 100_000)
    before_runs = len(engine.runs)
    assert engine.xrefs(target.data.sha256, fn.address, direction="to", limit=fresh_limit).data is not None
    assert len(engine.runs) == before_runs + 1
    assert snapshot(GLOBAL_SETTINGS) == global_before  # probe+analysis+queries did not change the global settings
    assert (engine.user_dir / "settings").is_dir()
