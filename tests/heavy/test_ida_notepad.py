"""Real IDA (idalib) integration test: on a COPY of notepad.exe. Skipped if IDA is absent (the reason is visible)."""
import shutil
import sys
import time
from pathlib import Path

import pytest

from redharness.config import Config
from redharness.core.result import Status
from redharness.engines.ida import IdaEngine

from tests.unit.engine_contract import EngineContract, pick_function, sha_of

pytestmark = pytest.mark.heavy
NOTEPAD = Path(r"C:\Windows\System32\notepad.exe")


@pytest.fixture(scope="module")
def data_root(tmp_path_factory):
    return tmp_path_factory.mktemp("rh_data")


@pytest.fixture(scope="module")
def sample(tmp_path_factory):
    if not NOTEPAD.is_file():
        pytest.skip("notepad.exe not found")
    p = tmp_path_factory.mktemp("target") / "notepad_copy.exe"
    shutil.copyfile(NOTEPAD, p)
    return p


GLOBAL_CFG = Path.home() / "AppData" / "Roaming" / "Hex-Rays" / "IDA Pro" / "ida-config.json"


@pytest.fixture(scope="module")
def global_cfg_before():
    """State of the user's global IDA config BEFORE the engine is set up."""
    return GLOBAL_CFG.read_bytes() if GLOBAL_CFG.exists() else None


@pytest.fixture(scope="module")
def engine(data_root, global_cfg_before):
    e = IdaEngine(Config.load(data_root))
    info = e.probe()
    if not info.available:
        pytest.skip(f"IDA/idalib unavailable: {info.detail}")
    runs = []
    orig = e._run

    def counting(op, req, timeout_s):
        runs.append(op)
        return orig(op, req, timeout_s)

    e._run = counting
    e.runs = runs
    return e


@pytest.fixture(scope="module")
def analysis_count(engine):
    return lambda: engine.runs.count("analyze")


class TestIdaContract(EngineContract):
    """The same contract suite as with the fake worker, with real IDA."""


@pytest.fixture(scope="module")
def target(engine, sample):
    r = engine.open_target(sample)
    assert r.ok, r.detail
    return r


def test_function_count_and_arch(engine, target):
    t = target.data
    assert t.function_count > 100  # the exact count is version-dependent and not pinned
    assert t.bits == 64 and t.decompiler
    page = engine.functions(t.sha256, limit=10_000).data
    assert page.total == t.function_count and len(page.items) == t.function_count


def test_decompile_real_function(engine, target):
    sha = target.data.sha256
    fn = pick_function(engine, sha)
    d = engine.decompile(sha, fn.address)
    assert d.ok and d.untrusted_content
    assert "{" in d.data.text and "}" in d.data.text and "(" in d.data.text
    assert d.data.address == fn.address


def test_disassembly_operand_text_has_no_ida_color_tags(engine, target):
    """print_operand returns colorized text (\\x01/\\x02 + color codes); the contract text must be plain."""
    sha = target.data.sha256
    fn = pick_function(engine, sha)
    d = engine.disassemble(sha, fn.address, count=400, whole_function=True)
    assert d.ok or d.status is Status.PARTIAL
    ops = [o for i in d.data.items for o in i.operands]
    assert ops, "no operands decoded"
    for i in d.data.items:
        for s in [i.text] + [o.text for o in i.operands]:
            assert all(ord(c) >= 0x20 for c in s), (hex(i.address), repr(s))
    assert any(o.kind == "reg" and o.text == o.reg for o in ops)  # e.g. 'rax' is exactly the register name
    mems = [o for o in ops if o.kind == "mem" and o.base and o.disp]
    assert mems and all(o.base in o.text for o in mems)


def test_second_open_hits_cache_without_reanalysis(engine, sample, data_root, target):
    before = engine.runs.count("analyze")
    t0 = time.monotonic()
    r = engine.open_target(sample)
    dt = time.monotonic() - t0
    assert r.ok and r.cached and engine.runs.count("analyze") == before
    assert dt < 5, dt
    # a completely new object (new session) must also get a hit
    fresh = IdaEngine(Config.load(data_root))
    r3 = fresh.open_target(sample)
    assert r3.ok and r3.cached
    print(f"\nfirst analysis {target.duration_s:.1f} s ({target.extra}); cache hit {dt:.3f} s")


def test_idalib_not_loaded_in_this_process(engine, target):
    assert "idapro" not in sys.modules and "ida_funcs" not in sys.modules


def test_analysis_timeout_is_never_ok(tmp_path, sample):
    e = IdaEngine(Config.load(tmp_path / "d"), analyze_timeout_s=1)
    if not e.probe().available:
        pytest.skip("IDA not available")
    r = e.open_target(sample)
    assert r.status is Status.TIMEOUT and not r.ok
    assert not e._tdir(e.probe().version, sha_of(sample)).exists()


def test_user_global_ida_config_untouched(engine, target, global_cfg_before):
    fn = pick_function(engine, target.data.sha256)
    assert engine.xrefs(target.data.sha256, fn.address, direction="from").data is not None
    now = GLOBAL_CFG.read_bytes() if GLOBAL_CFG.exists() else None
    assert now == global_cfg_before  # the global config is byte-for-byte identical after probe+analysis+queries
    assert (engine.ida_user_dir).is_dir()  # our own user directory was used
