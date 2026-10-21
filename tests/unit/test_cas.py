import hashlib

import pytest

from redharness.core.cas import Cas, CasCorrupt, CasError, CasMissing


def test_put_get_roundtrip_and_layout(tmp_path):
    cas = Cas(tmp_path / "cas")
    sha = cas.put(b"welcome")
    assert sha == hashlib.sha256(b"welcome").hexdigest()
    assert cas.path_for(sha) == tmp_path / "cas" / sha[:2] / sha
    assert cas.get(sha) == b"welcome" and cas.has(sha) and cas.size(sha) == 7


def test_put_is_idempotent(tmp_path):
    cas = Cas(tmp_path)
    assert cas.put(b"x") == cas.put(b"x")


def test_missing_and_corrupt(tmp_path):
    cas = Cas(tmp_path)
    with pytest.raises(CasMissing):
        cas.get("a" * 64)
    sha = cas.put(b"original")
    cas.path_for(sha).write_bytes(b"tampered")
    with pytest.raises(CasCorrupt):
        cas.get(sha)
    assert cas.put(b"original") == sha  # a corrupt blob is repaired by rewriting
    assert cas.get(sha) == b"original"


def test_rejects_path_traversal_shas(tmp_path):
    cas = Cas(tmp_path)
    for bad in ("../x", "A" * 64, "ab", "a" * 63, ""):
        with pytest.raises(CasError):
            cas.get(bad)


def test_put_file_streams_and_no_tmp_left(tmp_path):
    src = tmp_path / "t.bin"
    data = b"MZ" + bytes(range(256)) * 5000
    src.write_bytes(data)
    cas = Cas(tmp_path / "cas")
    sha = cas.put_file(src)
    assert sha == hashlib.sha256(data).hexdigest() and cas.get(sha) == data
    assert cas.put_file(src) == sha
    assert not list((tmp_path / "cas").rglob("*.tmp"))


def test_get_range(tmp_path):
    cas = Cas(tmp_path)
    sha = cas.put(b"0123456789")
    assert cas.get_range(sha, 2, 3) == b"234"
    assert cas.get_range(sha, 8) == b"89"
    with pytest.raises(CasError):
        cas.get_range(sha, -1)
