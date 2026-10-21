"""Common engine contract test suite. IDA and (later) Ghidra must pass the same suite.

The subclass provides these fixtures: `engine` (Engine), `sample` (Path, the file to analyze),
`analysis_count` (callable: number of real analyses done so far).
"""
import hashlib
import re

from redharness.core.result import Status
from redharness.engines.base import EngineResult


def sha_of(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def pick_function(engine, sha):
    rows = engine.functions(sha, limit=5000).data.items
    mid = [f for f in rows if 64 <= f.size <= 400]
    assert mid, "no medium-size function"
    return mid[len(mid) // 2]


class EngineContract:
    def test_open_target_identity_and_cache(self, engine, sample, analysis_count):
        r = engine.open_target(sample)
        assert r.status is Status.OK and r.ok and not r.cached
        assert r.data.sha256 == sha_of(sample)
        assert r.data.function_count > 0
        n = analysis_count()
        r2 = engine.open_target(sample)
        assert r2.ok and r2.cached and r2.data == r.data
        assert analysis_count() == n  # no re-analysis

    def test_functions_pagination_consistent(self, engine, sample):
        sha = engine.open_target(sample).data.sha256
        p1 = engine.functions(sha, offset=0, limit=10)
        assert p1.ok and len(p1.data.items) == 10 and p1.data.has_more
        total = p1.data.total
        assert total == engine.open_target(sample).data.function_count
        last = engine.functions(sha, offset=total - 3, limit=10).data
        assert len(last.items) == 3 and not last.has_more
        p2 = engine.functions(sha, offset=10, limit=10).data
        assert p1.data.items[-1].address != p2.items[0].address
        assert p1.untrusted_content

    def test_strings_regex_and_untrusted(self, engine, sample):
        sha = engine.open_target(sample).data.sha256
        allp = engine.strings(sha, limit=10_000)
        assert allp.ok and allp.untrusted_content and allp.data.total > 0
        some = allp.data.items[0].value
        pat = re.escape(some[: max(3, len(some) // 2)])
        hit = engine.strings(sha, pattern=pat, limit=10_000)
        assert hit.ok and 1 <= hit.data.total <= allp.data.total
        assert all(re.search(pat, s.value) for s in hit.data.items)
        assert not engine.strings(sha, pattern="(").ok  # malformed regex -> error, not an exception

    def test_decompile_and_cache_and_truncation(self, engine, sample, analysis_count):
        sha = engine.open_target(sample).data.sha256
        fn = pick_function(engine, sha)
        d = engine.decompile(sha, fn.address)
        assert d.status is Status.OK and d.ok and d.untrusted_content
        assert d.data.text.strip() and d.data.total_chars == len(d.data.text)
        d2 = engine.decompile(sha, fn.address)
        assert d2.ok and d2.cached and d2.data.text == d.data.text
        cut = engine.decompile(sha, fn.address, max_chars=10)
        assert cut.status is Status.PARTIAL and not cut.ok  # truncated output is never OK
        assert len(cut.data.text) == 10 and cut.data.total_chars == d.data.total_chars

    def test_xrefs(self, engine, sample):
        sha = engine.open_target(sample).data.sha256
        fn = pick_function(engine, sha)
        x = engine.xrefs(sha, fn.address, direction="to")
        assert x.status in (Status.OK, Status.PARTIAL) and x.data is not None
        assert x.untrusted_content
        assert not engine.xrefs(sha, fn.address, direction="sideways").ok
        assert engine.xrefs(sha, fn.address, direction="from", limit=5).data is not None

    def test_unknown_target_is_not_ok(self, engine):
        bad = "0" * 64
        for res in (engine.functions(bad), engine.strings(bad), engine.decompile(bad, 0x1000),
                    engine.xrefs(bad, 0x1000)):
            assert isinstance(res, EngineResult) and not res.ok and res.status is not Status.OK
        assert not engine.functions("zz").ok
