"""Decompiler-timeout tests: the worker's IDA 9.5 path (fake ida_hexrays) and the backend's status mapping.

IDA 9.4 has no `set_decompiler_timeout`; the worker must not change anything there. IDA 9.5 gets the per-query budget
in milliseconds and MERR_TIMEOUT must surface as Status.TIMEOUT, never OK and never an empty result.
"""
import importlib.util
import json
import os
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

from redharness.config import Config
from redharness.core.result import Status
from redharness.engines.ida import IdaEngine

FAKE = Path(__file__).with_name("_fake_ida_worker.py")
WORKER_PATH = Path(__file__).resolve().parents[2] / "src" / "redharness" / "engines" / "ida" / "_worker.py"


@pytest.fixture
def ida_dir(tmp_path):
    d = tmp_path / "fake_ida"
    d.mkdir()
    (d / "idalib.dll").write_bytes(b"x")
    return d


@pytest.fixture
def sample(tmp_path):
    p = tmp_path / "target.exe"
    p.write_bytes(b"MZ" + os.urandom(2048))
    return p


def load_worker():
    spec = importlib.util.spec_from_file_location("ida_worker_under_test", WORKER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeCFunc:
    def __init__(self, text):
        self.text = text

    def __str__(self):
        return self.text


class FakeFailure:
    def __init__(self):
        self.code = 0


class FakeHexrays(types.ModuleType):
    MERR_TIMEOUT = -36

    class DecompilationFailure(Exception):
        pass

    def __init__(self, *, with_timeout_api, result="int f() { return 1; }", timeout_result=False):
        super().__init__("ida_hexrays")
        self.with_timeout_api = with_timeout_api
        self.result = result
        self.timeout_result = timeout_result
        self.timeout_calls = []
        self.decompile_calls = []
        if with_timeout_api:
            self.set_decompiler_timeout = self._set_decompiler_timeout

    def _set_decompiler_timeout(self, msecs):
        self.timeout_calls.append(msecs)
        return 0

    def init_hexrays_plugin(self):
        return True

    def hexrays_failure_t(self):
        return FakeFailure()

    def decompile(self, ea, hf=None):
        self.decompile_calls.append((ea, hf))
        if self.timeout_result:
            assert hf is not None
            hf.code = self.MERR_TIMEOUT
            return None
        if hf is not None:
            hf.code = 0
        return FakeCFunc(self.result)


class FakeIdapro(types.ModuleType):
    def __init__(self):
        super().__init__("idapro")

    def open_database(self, path, run_auto):
        return 0

    def close_database(self, *a):
        return None


class FakeIdc(types.ModuleType):
    def __init__(self):
        super().__init__("idc")

    def get_func_name(self, ea):
        return "sub_1000"


def run_worker(monkeypatch, fake, req):
    worker = load_worker()
    monkeypatch.setitem(sys.modules, "ida_hexrays", fake)
    monkeypatch.setitem(sys.modules, "idapro", FakeIdapro())
    monkeypatch.setitem(sys.modules, "idc", FakeIdc())
    monkeypatch.setattr(worker, "resolve_function", lambda fn: SimpleNamespace(start_ea=0x1000))
    return worker.op_decompile(dict({"target": "target.i64", "function": 0x1000}, **req))


def test_api_present_sets_budget_in_milliseconds_and_passes_failure_info(monkeypatch):
    fake = FakeHexrays(with_timeout_api=True)
    out = run_worker(monkeypatch, fake, {"decompile_timeout_ms": 150_000})
    assert fake.timeout_calls == [150_000]
    assert len(fake.decompile_calls) == 1 and fake.decompile_calls[0][1] is not None
    assert out["text"] == "int f() { return 1; }"


def test_merr_timeout_is_raised_as_timeout(monkeypatch):
    fake = FakeHexrays(with_timeout_api=True, timeout_result=True)
    try:
        run_worker(monkeypatch, fake, {"decompile_timeout_ms": 5})
    except RuntimeError as e:
        assert "DECOMPILE_TIMEOUT" in str(e) and "MERR_TIMEOUT" in str(e)
    else:
        raise AssertionError("a timed-out decompile must not return a result")
    assert fake.timeout_calls == [5]


def test_api_absent_is_unchanged(monkeypatch):
    fake = FakeHexrays(with_timeout_api=False)
    out = run_worker(monkeypatch, fake, {"decompile_timeout_ms": 5})
    assert not hasattr(fake, "set_decompiler_timeout")
    assert fake.decompile_calls == [(0x1000, None)]  # exactly the old call shape
    assert out["text"] == "int f() { return 1; }"


def test_api_absent_none_result_still_decompile_failed(monkeypatch):
    fake = FakeHexrays(with_timeout_api=False, result=None)
    fake.decompile = lambda ea, hf=None: (fake.decompile_calls.append((ea, hf)), None)[1]
    try:
        run_worker(monkeypatch, fake, {"decompile_timeout_ms": 5})
    except RuntimeError as e:
        assert "DECOMPILE_FAILED: empty result" in str(e)
    else:
        raise AssertionError("an empty result must not be OK")


def test_zero_budget_does_not_call_the_setter(monkeypatch):
    fake = FakeHexrays(with_timeout_api=True)
    run_worker(monkeypatch, fake, {"decompile_timeout_ms": 0})
    assert fake.timeout_calls == []
    assert fake.decompile_calls == [(0x1000, None)]


# ---------------------------------------------------------------- backend wiring
def make_engine(tmp_path, ida_dir, worker=FAKE, **kw):
    return IdaEngine(Config.load(tmp_path / "data"), ida_dir=ida_dir, worker=worker, **kw)


def test_engine_passes_budget_below_query_timeout(tmp_path, ida_dir):
    e = make_engine(tmp_path, ida_dir)  # query_timeout_s=180
    assert e._decompile_budget_ms() == 150_000


def test_env_forces_a_tiny_decompile_budget(tmp_path, ida_dir, monkeypatch):
    monkeypatch.setenv("RH_IDA_DECOMPILE_TIMEOUT", "0.005")
    e = make_engine(tmp_path, ida_dir)
    assert e._decompile_budget_ms() == 5


def _write_worker(path, body):
    path.write_text("import json, sys\n"
                    "req = json.load(open(sys.argv[1], encoding='utf-8'))\n" + body, encoding="utf-8")
    return path


def test_decompile_request_carries_the_budget(tmp_path, ida_dir, sample):
    e = make_engine(tmp_path, ida_dir)
    sha = e.open_target(sample).data.sha256
    w = _write_worker(tmp_path / "budget_worker.py",
                      "open(req['result_path'], 'w', encoding='utf-8').write(json.dumps("
                      "{'ok': True, 'address': 0x1000, 'name': 'f', "
                      "'text': 'budget=%s' % req.get('decompile_timeout_ms')}))\n")
    e.worker = w
    r = e.decompile(sha, 0x1000)
    assert r.ok and r.data.text == "budget=150000"


def test_worker_decompile_timeout_maps_to_status_timeout_and_is_not_cached(tmp_path, ida_dir, sample):
    e = make_engine(tmp_path, ida_dir)
    sha = e.open_target(sample).data.sha256
    w = _write_worker(tmp_path / "timeout_worker.py",
                      "open(req['result_path'], 'w', encoding='utf-8').write(json.dumps("
                      "{'ok': False, 'error': 'RuntimeError: DECOMPILE_TIMEOUT: MERR_TIMEOUT after 5 ms'}))\n"
                      "sys.exit(1)\n")
    e.worker = w
    r = e.decompile(sha, 0x1000)
    assert r.status is Status.TIMEOUT and not r.ok and r.data is None
    assert "MERR_TIMEOUT" in r.detail
    assert e.decompile(sha, 0x1000).status is Status.TIMEOUT  # the failure did not enter the cache
