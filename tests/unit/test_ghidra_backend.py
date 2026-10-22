"""GhidraEngine unit tests: do NOT require Ghidra/JVM (fake `analyzeHeadless` process).

Fail-closed matrix + cache + environment isolation + demonstrations that three classic failure modes do not occur
(a result recovered after a timeout, a trusted pre-existing result file, data truncated by the log cap).
"""
import json
import os
import sys
import threading
from pathlib import Path

import pytest

from redharness.config import Config
from redharness.core.result import Status
from redharness.engines.base import Engine
from redharness.engines.ghidra import GhidraEngine
from redharness.engines.ghidra import backend as backend_mod

from .engine_contract import EngineContract, sha_of

FAKE = Path(__file__).with_name("_fake_ghidra.py")
PROBE = Path(__file__).with_name("_fake_ghidra_probe.py")
MB = 1024 * 1024
VER = "99.9.9"


@pytest.fixture
def gdir(tmp_path):
    d = tmp_path / "fake_ghidra"
    (d / "support").mkdir(parents=True)
    (d / "Ghidra").mkdir()
    (d / "support" / "analyzeHeadless.bat").write_text("rem fake")
    (d / "Ghidra" / "application.properties").write_text(f"application.name=Ghidra\napplication.version={VER}\n")
    return d


@pytest.fixture
def log(tmp_path, monkeypatch):
    p = tmp_path / "calls.log"
    monkeypatch.setenv("FAKE_LOG", str(p))
    monkeypatch.setenv("FAKE_MODE", "ok")
    monkeypatch.setenv("FAKE_PROBE", "ok")
    return p


def calls(log, op=None):
    if not log.exists():
        return []
    rows = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    return [r for r in rows if op is None or r["op"] == op]


def make(tmp_path, gdir, data="data", **kw):
    return GhidraEngine(Config.load(tmp_path / data), ghidra_dir=gdir, launcher=[sys.executable, "-I", str(FAKE)],
                        probe_argv=[sys.executable, "-I", str(PROBE)], **kw)


@pytest.fixture
def sample(tmp_path):
    p = tmp_path / "target.exe"
    p.write_bytes(b"MZ" + os.urandom(2048))
    return p


def tdir_of(e, sample):
    return e._tdir(VER, sha_of(sample))


class TestContractWithFakeProcess(EngineContract):
    @pytest.fixture
    def engine(self, tmp_path, gdir, log):
        return make(tmp_path, gdir)

    @pytest.fixture
    def analysis_count(self, log):
        return lambda: len(calls(log, "analyze"))


def test_is_engine_and_cache_path_uses_ghidra_version(tmp_path, gdir, log, sample):
    e = make(tmp_path, gdir)
    assert isinstance(e, Engine)
    assert e.probe().available and e.probe().version == VER
    r = e.open_target(sample)
    assert r.ok
    assert (tmp_path / "data" / "cache" / "ghidra" / VER / sha_of(sample) / "meta.json").is_file()


def test_one_analysis_serves_all_queries_with_same_project(tmp_path, gdir, log, sample):
    e = make(tmp_path, gdir)
    sha = e.open_target(sample).data.sha256
    e.decompile(sha, 0x140001000)
    e.xrefs(sha, 0x140001000, direction="to")
    e.xrefs(sha, 0x140001000, direction="from")
    rows = calls(log)
    imports = [r for r in rows if r["import"]]
    assert len(imports) == 1 and imports[0]["op"] == "analyze"  # a single import+analysis
    queries = [r for r in rows if not r["import"]]
    assert len(queries) == 3
    assert all(r["process"] and r["noanalysis"] and r["readonly"] for r in queries)  # no re-analysis, read-only
    assert not any(r["analysis_timeout_flag"] for r in rows)  # the internal timeout is not used (silent partial analysis)


def test_target_info_carries_image_base(tmp_path, gdir, log, sample):
    assert make(tmp_path, gdir).open_target(sample).data.image_base == 0x140000000


def test_cache_survives_new_engine_instance(tmp_path, gdir, log, sample):
    assert make(tmp_path, gdir).open_target(sample).ok
    r = make(tmp_path, gdir).open_target(sample)
    assert r.ok and r.cached and len(calls(log, "analyze")) == 1


def test_cache_keyed_by_sha_not_path(tmp_path, gdir, log, sample):
    e = make(tmp_path, gdir)
    assert e.open_target(sample).ok
    copy = tmp_path / "other_name.bin"
    copy.write_bytes(sample.read_bytes())
    r = e.open_target(copy)
    assert r.ok and r.cached and len(calls(log, "analyze")) == 1
    other = tmp_path / "different.exe"
    other.write_bytes(b"MZ" + os.urandom(100))
    assert e.open_target(other).ok and len(calls(log, "analyze")) == 2


def test_result_cache_does_not_respawn_jvm(tmp_path, gdir, log, sample):
    e = make(tmp_path, gdir)
    sha = e.open_target(sample).data.sha256
    e.decompile(sha, 0x140001000)
    n = len(calls(log))
    assert e.decompile(sha, 0x140001000).cached
    assert len(calls(log)) == n


def test_missing_ghidra_is_clear_unavailable_error(tmp_path, sample, monkeypatch):
    for v in ("RH_GHIDRA_DIR", "GHIDRA_INSTALL_DIR"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setattr(backend_mod, "discover_ghidra_dir", lambda explicit=None: None)
    e = GhidraEngine(Config.load(tmp_path / "data"))
    info = e.probe()
    assert not info.available and "unavailable" in info.detail
    r = e.open_target(sample)
    assert r.status is Status.TOOL_MISSING and not r.ok and "unavailable" in r.detail
    assert e.functions("a" * 64).status is Status.TOOL_MISSING


def test_explicit_invalid_dir_is_not_ghidra(tmp_path):
    found = backend_mod.discover_ghidra_dir(tmp_path)
    assert found != tmp_path  # an invalid explicit directory is not accepted


@pytest.mark.parametrize("mode", ["fail", "nopath"])
def test_no_working_jdk_is_unavailable(tmp_path, gdir, log, sample, monkeypatch, mode):
    monkeypatch.setenv("FAKE_PROBE", mode)
    e = make(tmp_path, gdir)
    assert not e.probe().available
    r = e.open_target(sample)
    assert r.status is Status.TOOL_MISSING and not r.ok and "unavailable" in r.detail


def test_missing_launcher_executable(tmp_path, gdir, log, sample):
    e = GhidraEngine(Config.load(tmp_path / "data"), ghidra_dir=gdir, launcher=[str(tmp_path / "missing" / "x.bat")],
                     probe_argv=[sys.executable, "-I", str(PROBE)])
    r = e.open_target(sample)
    assert r.status is Status.TOOL_MISSING and not r.ok


# --------------------------------------------------------------------------- fail-closed matrix
ANALYZE_FAILURES = [
    ("timeout", Status.TIMEOUT),
    ("timeout_after_result", Status.TIMEOUT),   # full result written, process hung -> never OK
    ("crash", Status.ERROR),                    # result file exists but the process crashed -> never OK
    ("noresult", Status.ERROR),                 # script error: Ghidra still exits 0
    ("errdoc", Status.ERROR),
    ("trunc_json", Status.ERROR),
    ("nocomplete", Status.ERROR),
    ("wrongnonce", Status.ERROR),
    ("badcount", Status.ERROR),                 # array truncated, count intact
    ("stillanalyzing", Status.ERROR),
]


@pytest.mark.parametrize("mode,expected", ANALYZE_FAILURES)
def test_analysis_failures_are_never_ok_and_leave_no_cache(tmp_path, gdir, log, sample, monkeypatch, mode, expected):
    e = make(tmp_path, gdir, analyze_timeout_s=3)
    assert e.probe().available
    monkeypatch.setenv("FAKE_MODE", mode)
    r = e.open_target(sample)
    assert r.status is expected and not r.ok and r.data is None
    parent = tdir_of(e, sample).parent
    assert not tdir_of(e, sample).exists()
    assert not list(parent.glob("*.partial-*"))  # no half-finished project directory was left behind
    assert not e.functions(sha_of(sample)).ok
    monkeypatch.setenv("FAKE_MODE", "ok")  # once fixed it is retried (the failure did not enter the cache)
    assert e.open_target(sample).ok


def test_timeout_after_complete_result_is_not_ok_on_query(tmp_path, gdir, log, sample, monkeypatch):
    e = make(tmp_path, gdir, query_timeout_s=3)
    sha = e.open_target(sample).data.sha256
    monkeypatch.setenv("FAKE_MODE", "timeout_after_result")
    d = e.decompile(sha, 0x140001000)
    assert d.status is Status.TIMEOUT and not d.ok and d.data is None
    x = e.xrefs(sha, 0x140001000)
    assert x.status is Status.TIMEOUT and not x.ok and x.data is None
    monkeypatch.setenv("FAKE_MODE", "ok")
    again = e.decompile(sha, 0x140001000)
    assert again.ok and not again.cached  # the timeout result did not enter the cache


def test_existing_result_file_is_not_trusted(tmp_path, gdir, log, sample, monkeypatch):
    e = make(tmp_path, gdir)
    sha = e.open_target(sample).data.sha256
    for mode in ("crash", "wrongnonce"):  # a valid-looking file + failed process / foreign document
        monkeypatch.setenv("FAKE_MODE", mode)
        r = e.xrefs(sha, 0x1234)
        assert r.status is Status.ERROR and not r.ok and r.data is None, mode
    # every call uses a new working directory: the previous call's file cannot be reused
    dirs = {row["result_dir"] for row in calls(log)}
    assert len(dirs) == len(calls(log))


def test_log_truncation_cannot_truncate_data(tmp_path, gdir, log, sample, monkeypatch):
    monkeypatch.setenv("FAKE_MODE", "noisy")  # 12 MB log: the stdout cap is exceeded
    e = make(tmp_path, gdir)
    r = e.open_target(sample)
    assert r.ok and r.extra["log_truncated"] is True          # the diagnostic output was truncated and FLAGGED
    assert r.data.function_count == 25                         # but the data comes from the file, complete
    assert len(e.functions(r.data.sha256, limit=100).data.items) == 25
    # if the data is truncated (count mismatch) it is not OK: see ANALYZE_FAILURES badcount/trunc_json
    # if the decompile text exceeds the caller's cap it is PARTIAL (truncated output is not OK)
    monkeypatch.setenv("FAKE_MODE", "ok")
    cut = e.decompile(r.data.sha256, 0x140001000, max_chars=10)
    assert cut.status is Status.PARTIAL and not cut.ok and len(cut.data.text) == 10 and cut.data.total_chars > 10


def test_log_noise_with_fake_json_on_stdout_is_ignored(tmp_path, gdir, log, sample):
    # the "ok" mode prints '{"ok": false, ...}' to stdout; the result must still be read from the file.
    assert make(tmp_path, gdir).open_target(sample).ok


def test_memory_limit_is_enforced(tmp_path, gdir, log, sample, monkeypatch):
    e = make(tmp_path, gdir, memory_limit_bytes=300 * MB, analyze_timeout_s=60)
    assert e.probe().available
    monkeypatch.setenv("FAKE_MODE", "mem")
    r = e.open_target(sample)
    # Windows: the Job Object reports the overrun as MEMORY_LIMIT. POSIX: RLIMIT_AS makes the allocation fail inside
    # the child, which exits non-zero: ERROR (core/proc.py). Never OK on either platform.
    assert r.status is (Status.MEMORY_LIMIT if sys.platform == "win32" else Status.ERROR) and not r.ok


@pytest.mark.parametrize("mode,expected", [("timeout", Status.TIMEOUT), ("decomp_timeout", Status.TIMEOUT),
                                           ("crash", Status.ERROR), ("noresult", Status.ERROR),
                                           ("badcount", Status.ERROR)])
def test_query_failures_not_cached(tmp_path, gdir, log, sample, monkeypatch, mode, expected):
    e = make(tmp_path, gdir, query_timeout_s=3)
    sha = e.open_target(sample).data.sha256
    monkeypatch.setenv("FAKE_MODE", mode)
    r = e.decompile(sha, 0x140001000)
    assert r.status is expected and not r.ok and r.data is None
    monkeypatch.setenv("FAKE_MODE", "ok")
    d = e.decompile(sha, 0x140001000)
    assert d.ok and not d.cached


def test_incomplete_cache_without_meta_is_reanalyzed(tmp_path, gdir, log, sample):
    e = make(tmp_path, gdir)
    r = e.open_target(sample)
    (e._tdir(VER, r.data.sha256) / "meta.json").unlink()  # as if interrupted mid-analysis
    r2 = e.open_target(sample)
    assert r2.ok and not r2.cached and len(calls(log, "analyze")) == 2


def test_tampered_project_is_detected_not_trusted(tmp_path, gdir, log, sample):
    e = make(tmp_path, gdir)
    r = e.open_target(sample)
    tdir = e._tdir(VER, r.data.sha256)
    db = next((tdir / "proj").rglob("db.1.gbf"))
    db.write_bytes(b"corrupt")
    d = e.decompile(r.data.sha256, 0x140001000)
    assert not d.ok and d.status is Status.ERROR and "corrupt" in d.detail
    assert e.open_target(sample).cached is False  # invalidated -> re-analysis


def test_index_rewrites_by_readonly_queries_do_not_invalidate(tmp_path, gdir, log, sample):
    e = make(tmp_path, gdir)
    sha = e.open_target(sample).data.sha256
    tdir = e._tdir(VER, sha)
    (tdir / "proj" / "rh.rep" / "idata").mkdir(parents=True, exist_ok=True)
    (tdir / "proj" / "rh.rep" / "idata" / "~index.dat").write_bytes(b"changed")  # Ghidra rewrites this
    assert e.decompile(sha, 0x140001000).ok


def test_target_changed_during_copy_is_rejected(tmp_path, gdir, log, sample, monkeypatch):
    real = backend_mod.shutil.copyfile

    def evil(src, dst, *a, **k):
        real(src, dst, *a, **k)
        with open(dst, "ab") as f:
            f.write(b"\0tampered")
        return dst

    monkeypatch.setattr(backend_mod.shutil, "copyfile", evil)
    r = make(tmp_path, gdir).open_target(sample)
    assert not r.ok and "ARTIFACT_CHANGED" in r.detail and not calls(log, "analyze")


def test_jvm_budget_env_and_user_isolation(tmp_path, gdir, log, sample, monkeypatch):
    monkeypatch.setenv("GHIDRA_MAXMEM", "64G")
    monkeypatch.setenv("GHIDRA_HEADLESS_MAXMEM", "32G")
    monkeypatch.setenv("JAVA_TOOL_OPTIONS", "-Xmx1m")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path / "bad"))
    e = make(tmp_path, gdir)
    assert e.open_target(sample).ok
    row = calls(log, "analyze")[0]
    assert row["maxmem"] == "4G"                      # -Xmx4g
    assert row["ghidra_maxmem"] is None and row["pythonpath"] is None
    assert "-Xmx1m" not in row["java_opts"]
    settings = (tmp_path / "data" / "ghidra_user" / "settings").as_posix()
    assert f'-Dapplication.settingsdir="{settings}"' in row["java_opts"]   # the global %APPDATA%\\ghidra is not used
    assert Path(row["xdg"]) == tmp_path / "data" / "ghidra_user" / "xdg"  # LaunchSupport does not write java_home.save to the global location
    assert os.environ["GHIDRA_MAXMEM"] == "64G"       # our own process was not changed
    assert e.memory_limit == 6 * 1024 ** 3            # Job limit 6 GB


def test_data_root_with_spaces_works(tmp_path, gdir, log, sample):
    e = make(tmp_path, gdir, data="data röot dir")
    assert e.open_target(sample).ok
    row = calls(log, "analyze")[0]
    assert "data röot dir" in row["java_opts"] and 'settingsdir="' in row["java_opts"]


def test_work_dirs_are_cleaned_up(tmp_path, gdir, log, sample):
    e = make(tmp_path, gdir)
    sha = e.open_target(sample).data.sha256
    e.decompile(sha, 0x140001000)
    assert not any((tmp_path / "data" / "work").glob("ghidra-*"))


def test_request_properties_escaping():
    esc = backend_mod._prop_escape
    assert esc("a\\b") == "a\\\\b" and esc("x\ny") == "x\\ny" and esc(" ab") == "\\ ab" and esc(5) == "5"


def test_concurrent_open_analyzes_once(tmp_path, gdir, log, sample):
    e = make(tmp_path, gdir)
    out = []
    ts = [threading.Thread(target=lambda: out.append(e.open_target(sample))) for _ in range(3)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert all(r.ok for r in out) and sum(1 for r in out if not r.cached) == 1
    assert len(calls(log, "analyze")) == 1


def test_heavy_lock_shared_between_engines():
    from redharness.engines import _common
    from redharness.engines.ida import backend as ida_backend
    assert ida_backend._HEAVY is _common.HEAVY  # one heavy engine operation: IDA and Ghidra share the same lock
