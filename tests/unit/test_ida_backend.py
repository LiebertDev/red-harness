"""IdaEngine unit tests: do NOT require IDA (fake worker). Fail-closed matrix + cache + environment isolation."""
import json
import os
import sys
import threading
from pathlib import Path

import pytest

from redharness.config import Config
from redharness.core.result import Status
from redharness.engines.base import Engine
from redharness.engines.ida import IdaEngine
from redharness.engines.ida import backend as backend_mod

from .engine_contract import EngineContract, sha_of

FAKE = Path(__file__).with_name("_fake_ida_worker.py")
MB = 1024 * 1024


@pytest.fixture
def ida_dir(tmp_path):
    d = tmp_path / "fake_ida"
    d.mkdir()
    (d / "idalib.dll").write_bytes(b"x")
    return d


@pytest.fixture
def log(tmp_path, monkeypatch):
    p = tmp_path / "calls.log"
    monkeypatch.setenv("FAKE_LOG", str(p))
    monkeypatch.setenv("FAKE_MODE", "ok")
    return p


def calls(log, op=None):
    if not log.exists():
        return []
    rows = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    return [r for r in rows if op is None or r["op"] == op]


def make(tmp_path, ida_dir, **kw):
    return IdaEngine(Config.load(tmp_path / "data"), ida_dir=ida_dir, worker=FAKE, **kw)


@pytest.fixture
def sample(tmp_path):
    p = tmp_path / "target.exe"
    p.write_bytes(b"MZ" + os.urandom(2048))
    return p


class TestContractWithFakeWorker(EngineContract):
    @pytest.fixture
    def engine(self, tmp_path, ida_dir, log):
        return make(tmp_path, ida_dir)

    @pytest.fixture
    def analysis_count(self, log):
        return lambda: len(calls(log, "analyze"))


def test_is_engine_subclass_and_never_imports_idapro_in_process(tmp_path, ida_dir, log, sample):
    e = make(tmp_path, ida_dir)
    assert isinstance(e, Engine)
    assert e.open_target(sample).ok
    assert "idapro" not in sys.modules  # idalib does not run in the main process


def test_cache_survives_new_engine_instance(tmp_path, ida_dir, log, sample):
    assert make(tmp_path, ida_dir).open_target(sample).ok
    r = make(tmp_path, ida_dir).open_target(sample)  # new object = new "session"
    assert r.ok and r.cached
    assert len(calls(log, "analyze")) == 1


def test_cache_keyed_by_sha_not_path(tmp_path, ida_dir, log, sample):
    e = make(tmp_path, ida_dir)
    assert e.open_target(sample).ok
    copy = tmp_path / "other_name.bin"
    copy.write_bytes(sample.read_bytes())
    r = e.open_target(copy)
    assert r.ok and r.cached and len(calls(log, "analyze")) == 1
    other = tmp_path / "different.exe"
    other.write_bytes(b"MZ" + os.urandom(100))
    assert e.open_target(other).ok and len(calls(log, "analyze")) == 2


def test_result_cache_does_not_respawn_worker(tmp_path, ida_dir, log, sample):
    e = make(tmp_path, ida_dir)
    sha = e.open_target(sample).data.sha256
    e.decompile(sha, 0x1000)
    n = len(calls(log))
    assert e.decompile(sha, 0x1000).cached
    assert len(calls(log)) == n


def test_too_long_database_path_fails_up_front_with_clear_reason(tmp_path, ida_dir, log, sample):
    """idalib cannot open a database whose path is 260+ characters (open_database rc=4); never reach the worker."""
    sha = sha_of(sample)
    base = len(str(make(tmp_path, ida_dir)._tdir("9.9.1", sha) / "target.exe.i64"))  # with root tmp_path/data
    pad = backend_mod.MAX_IDB_PATH - base + 1  # one character over the limit
    e = IdaEngine(Config.load(tmp_path / "data" / ("p" * (pad - 1))), ida_dir=ida_dir, worker=FAKE)
    assert len(str(e._tdir("9.9.1", sha) / "target.exe.i64")) == backend_mod.MAX_IDB_PATH + 1
    assert e.probe().available
    r = e.open_target(sample)
    assert r.status is Status.ERROR and not r.ok and "PATH_TOO_LONG" in r.detail and "RH_DATA_ROOT" in r.detail
    assert not calls(log, "analyze")
    assert not e._tdir("9.9.1", sha).exists()


def test_too_long_database_path_refused_before_probe_worker_starts(tmp_path, ida_dir, log, sample, monkeypatch):
    """A fresh engine must refuse a too-long database path before starting the probe worker."""
    sha = sha_of(sample)
    base = len(str(make(tmp_path, ida_dir)._tdir("9.9.1", sha) / "target.exe.i64"))
    pad = backend_mod.MAX_IDB_PATH - base + 1  # one character over the limit
    e = IdaEngine(Config.load(tmp_path / "data" / ("p" * (pad - 1))), ida_dir=ida_dir, worker=FAKE)
    started = []
    real_probe = e.probe

    def spy():
        started.append(True)
        return real_probe()

    monkeypatch.setattr(e, "probe", spy)
    r = e.open_target(sample)
    assert r.status is Status.ERROR and "PATH_TOO_LONG" in r.detail and "RH_DATA_ROOT" in r.detail
    assert started == []  # the probe method was never called
    assert calls(log) == []  # ... and no probe/analyze worker process was started


def test_database_path_at_the_limit_is_accepted(tmp_path):
    tdir = tmp_path / "x"
    tdir = tmp_path / ("x" * (1 + backend_mod.MAX_IDB_PATH - len(str(tdir / "target.exe.i64"))))
    assert len(str(tdir / "target.exe.i64")) == backend_mod.MAX_IDB_PATH
    assert backend_mod.idb_path_problem(tdir, ".EXE") == ""
    assert "PATH_TOO_LONG" in backend_mod.idb_path_problem(tdir.with_name(tdir.name + "x"), ".exe")


def test_missing_ida_is_clear_unavailable_error(tmp_path, sample, monkeypatch):
    for v in ("RH_IDA_DIR", "IDADIR"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "missing"))
    e = IdaEngine(Config.load(tmp_path / "data"))
    info = e.probe()
    assert not info.available and "unavailable" in info.detail
    r = e.open_target(sample)
    assert r.status is Status.TOOL_MISSING and not r.ok and "unavailable" in r.detail
    assert e.functions("a" * 64).status is Status.TOOL_MISSING


def test_idapro_import_error_is_unavailable(tmp_path, ida_dir, log, sample, monkeypatch):
    monkeypatch.setenv("FAKE_MODE", "importerr")
    e = make(tmp_path, ida_dir)
    assert not e.probe().available
    r = e.open_target(sample)
    assert r.status is Status.TOOL_MISSING and not r.ok


def test_missing_python_interpreter(tmp_path, ida_dir, sample):
    e = IdaEngine(Config.load(tmp_path / "data"), ida_dir=ida_dir, worker=FAKE,
                  python=tmp_path / "missing" / "python.exe")
    r = e.open_target(sample)
    assert r.status is Status.TOOL_MISSING and not r.ok


@pytest.mark.parametrize("mode,expected", [("timeout", Status.TIMEOUT), ("crash", Status.ERROR),
                                           ("noresult", Status.ERROR), ("errdoc", Status.ERROR)])
def test_analysis_failures_are_never_ok_and_leave_no_cache(tmp_path, ida_dir, log, sample, monkeypatch,
                                                           mode, expected):
    e = make(tmp_path, ida_dir, analyze_timeout_s=2)
    assert e.probe().available  # probe succeeds (the mode only breaks analyze)
    monkeypatch.setenv("FAKE_MODE", mode)
    r = e.open_target(sample)
    assert r.status is expected and not r.ok and r.data is None
    tdir = e._tdir("9.9.1", sha_of(sample))
    assert not tdir.exists()  # no partial database was left behind
    assert not e.functions(sha_of(sample)).ok
    # once fixed it is retried (the failure did not enter the cache)
    monkeypatch.setenv("FAKE_MODE", "ok")
    assert e.open_target(sample).ok


def test_memory_limit_is_enforced(tmp_path, ida_dir, log, sample, monkeypatch):
    e = make(tmp_path, ida_dir, memory_limit_bytes=300 * MB, analyze_timeout_s=60)
    assert e.probe().available
    monkeypatch.setenv("FAKE_MODE", "mem")
    r = e.open_target(sample)
    # Windows: the Job Object reports the overrun as MEMORY_LIMIT. POSIX: RLIMIT_AS makes the allocation fail inside
    # the child, which exits non-zero: ERROR (core/proc.py). Never OK on either platform.
    assert r.status is (Status.MEMORY_LIMIT if sys.platform == "win32" else Status.ERROR) and not r.ok


def test_query_failure_not_cached(tmp_path, ida_dir, log, sample, monkeypatch):
    e = make(tmp_path, ida_dir, query_timeout_s=2)
    sha = e.open_target(sample).data.sha256
    monkeypatch.setenv("FAKE_MODE", "timeout")
    r = e.decompile(sha, 0x1000)
    assert r.status is Status.TIMEOUT and not r.ok
    monkeypatch.setenv("FAKE_MODE", "ok")
    d = e.decompile(sha, 0x1000)
    assert d.ok and not d.cached


def test_incomplete_cache_without_meta_is_reanalyzed(tmp_path, ida_dir, log, sample):
    e = make(tmp_path, ida_dir)
    r = e.open_target(sample)
    tdir = e._tdir("9.9.1", r.data.sha256)
    (tdir / "meta.json").unlink()  # as if interrupted mid-analysis
    r2 = e.open_target(sample)
    assert r2.ok and not r2.cached and len(calls(log, "analyze")) == 2


def test_tampered_idb_is_detected_not_trusted(tmp_path, ida_dir, log, sample):
    e = make(tmp_path, ida_dir)
    r = e.open_target(sample)
    tdir = e._tdir("9.9.1", r.data.sha256)
    (tdir / "target.i64").write_bytes(b"corrupt")
    d = e.decompile(r.data.sha256, 0x2000)
    assert not d.ok and d.status is Status.ERROR and "corrupt" in d.detail
    assert e.open_target(sample).cached is False  # invalidated -> re-analysis


def test_target_changed_during_copy_is_rejected(tmp_path, ida_dir, log, sample, monkeypatch):
    real = backend_mod.shutil.copyfile

    def evil(src, dst, *a, **k):
        real(src, dst, *a, **k)
        with open(dst, "ab") as f:
            f.write(b"\0tampered")
        return dst

    monkeypatch.setattr(backend_mod.shutil, "copyfile", evil)
    r = make(tmp_path, ida_dir).open_target(sample)
    assert not r.ok and "ARTIFACT_CHANGED" in r.detail and not calls(log, "analyze")


def test_env_isolation_user_dir_and_ida_dir(tmp_path, ida_dir, log, sample, monkeypatch):
    monkeypatch.setenv("IDAUSR", str(tmp_path / "user_global"))
    monkeypatch.setenv("PYTHONPATH", str(tmp_path / "bad"))
    e = make(tmp_path, ida_dir)
    assert e.open_target(sample).ok
    row = calls(log, "analyze")[0]
    assert Path(row["idausr"]) == tmp_path / "data" / "ida_user"  # the global IDAUSR is not touched
    assert Path(row["idadir"]) == ida_dir
    assert row["pythonpath"] is None
    assert not (tmp_path / "user_global").exists()
    assert os.environ["IDAUSR"] == str(tmp_path / "user_global")  # our own process was not changed


def test_no_ida_config_written_by_engine(tmp_path, ida_dir, log, sample):
    make(tmp_path, ida_dir).open_target(sample)
    assert not list((tmp_path / "data").rglob("ida-config.json"))


def test_concurrent_open_analyzes_once(tmp_path, ida_dir, log, sample):
    e = make(tmp_path, ida_dir)
    out = []
    ts = [threading.Thread(target=lambda: out.append(e.open_target(sample))) for _ in range(3)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert all(r.ok for r in out) and sum(1 for r in out if not r.cached) == 1
    assert len(calls(log, "analyze")) == 1


def test_old_cache_without_strings_rev_is_reanalyzed(tmp_path, ida_dir, log, sample):
    """A cache written before UTF-16LE string support (no strings_rev) would give incomplete strings: re-analysis."""
    import json
    e = make(tmp_path, ida_dir)
    r = e.open_target(sample)
    tdir = e._tdir("9.9.1", r.data.sha256)
    meta = json.loads((tdir / "meta.json").read_text(encoding="utf-8"))
    assert meta["strings_rev"] >= 2
    del meta["strings_rev"]
    (tdir / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    r2 = e.open_target(sample)
    assert r2.ok and not r2.cached and len(calls(log, "analyze")) == 2


def test_probe_refreshes_version_after_in_place_upgrade(tmp_path, ida_dir, log):
    """A long-lived engine must not keep the old version (and its cache dir) after IDA is upgraded in place."""
    notes = ida_dir / "release-notes.md"
    notes.write_text("# IDA 9.9\n", encoding="utf-8")
    worker = tmp_path / "version_worker.py"
    worker.write_text(r'''import json, os, re, sys
from pathlib import Path

req = json.load(open(sys.argv[1], encoding="utf-8"))
if os.environ.get("FAKE_LOG"):
    with open(os.environ["FAKE_LOG"], "a", encoding="utf-8") as f:
        f.write(json.dumps({"op": req["op"]}) + "\n")
notes = Path(os.environ["IDADIR"]) / "release-notes.md"
version = re.search(r"\d+(?:\.\d+)+", notes.read_text(encoding="utf-8")).group(0)
Path(req["result_path"]).write_text(json.dumps({"ok": True, "version": version}), encoding="utf-8")
''', encoding="utf-8")
    e = IdaEngine(Config.load(tmp_path / "data"), ida_dir=ida_dir, worker=worker)
    info = e.probe()
    assert info.available and info.version == "9.9"
    assert len(calls(log, "probe")) == 1
    assert e.probe().version == "9.9"  # unchanged install: cached, no second worker
    assert len(calls(log, "probe")) == 1
    notes.write_text("# IDA 9.10\n", encoding="utf-8")  # upgraded in place: same dir, new version file
    info = e.probe()
    assert info.available and info.version == "9.10"
    assert len(calls(log, "probe")) == 2


def _load_worker():
    import importlib.util
    from redharness.engines.ida import backend
    spec = importlib.util.spec_from_file_location("_ida_worker_under_test", Path(backend.__file__).parent / "_worker.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_utf16_runs_finds_wide_strings_with_terminator():
    w = _load_worker()
    data = b"\x00\x00" + ("\\Device\\sdrv").encode("utf-16le") + b"\x00\x00" + b"ab\x00\x00" + "xy".encode("utf-16le")
    runs = w.utf16_runs(data, 0x10000)
    assert runs == [(0x10002, 26, ("\\Device\\sdrv"))]  # 12 characters*2 + NUL(2); 'xy' is below minlen


def test_utf16_runs_ignores_odd_aligned_and_plain_ascii():
    w = _load_worker()
    assert w.utf16_runs(b"\x01" + "Device".encode("utf-16le"), 0x10000) == []  # odd address: misaligned
    assert w.utf16_runs(b"Device\x00 plain ascii", 0) == []


def test_collect_strings_raw_scan_replaces_truncated_ida_item():
    """IDA raw scan: if the leading backslash is defined separately IDA gives a short string; the raw run replaces it with the full string."""
    w = _load_worker()
    text = ("\\Device\\sdrv")
    data = b"\x00\x00" + text.encode("utf-16le") + b"\x00\x00"
    base = 0x10f54

    class Item:
        def __init__(s, ea, length, t, v):
            s.ea, s.length, s.strtype, s._v = ea, length, t, v

        def __str__(s):
            return s._v

    class Strings(list):
        def setup(self, **kw):
            Strings.kw = kw
            self[:] = [Item(base + 4, 24, 1, "Device\\sdrv"), Item(0x20000, 15, 0, "IoCreateDevice")]

    class Idautils:
        @staticmethod
        def Strings(default_setup=True):
            return Strings()

    class Nalt:
        STRTYPE_C, STRTYPE_C_16, STRTYPE_C_32 = 0, 1, 2

    class Seg:
        start_ea, end_ea, perm = base, base + len(data), 1  # an executable section is scanned too

    class Segment:
        SEGPERM_EXEC = 1

        @staticmethod
        def get_first_seg():
            return Seg()

        @staticmethod
        def get_next_seg(ea):
            return None

    class Bytes:
        @staticmethod
        def get_bytes(ea, n):
            return data

    rows = w.collect_strings(Idautils, Nalt, Bytes, Segment)
    values = {r["address"]: r["value"] for r in rows}
    assert values == {base + 2: text, 0x20000: "IoCreateDevice"}
    assert Strings.kw["strtypes"] == [0, 1, 2]
