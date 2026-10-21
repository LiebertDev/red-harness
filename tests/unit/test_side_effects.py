"""Host-side side-effect observation: plain files only, links never followed, bounded listing."""
from __future__ import annotations

import os
import subprocess

import pytest

from redharness.sandbox.runner import _list_workdir_files


def _make_dir_link(link, target) -> bool:
    """Directory symlink, or (on Windows without the symlink privilege) a junction via mklink /J."""
    try:
        os.symlink(target, link, target_is_directory=True)
        return True
    except (OSError, NotImplementedError):
        pass
    if os.name == "nt":
        try:
            subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                           capture_output=True, check=True)
            return os.path.isdir(link)
        except (OSError, subprocess.CalledProcessError):
            return False
    return False


def _remove_link(link) -> None:
    for fn in (os.unlink, os.rmdir):
        try:
            fn(link)
            return
        except OSError:
            pass
    if os.name == "nt":
        subprocess.run(["cmd", "/c", "rmdir", str(link)], capture_output=True)


def test_plain_files_are_listed(tmp_path):
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    (root / "top.txt").write_text("x", encoding="utf-8")
    (root / "sub" / "nested.bin").write_bytes(b"x")
    got = _list_workdir_files(root)
    assert "top.txt" in got
    assert "sub/nested.bin" in got
    assert not any(item.startswith("<") for item in got)
    assert _list_workdir_files(tmp_path / "missing") == []


def test_directory_link_outside_is_skipped_and_reported(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "plain.txt").write_text("x", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret", encoding="utf-8")
    link = root / "linked"
    if not _make_dir_link(link, outside):
        pytest.skip("creating a directory symlink/junction is not permitted on this host")
    try:
        got = _list_workdir_files(root)
        assert "plain.txt" in got
        assert "linked/secret.txt" not in got
        assert not any(item.startswith("linked/") for item in got)
        assert any(item.startswith("<skipped link: linked") for item in got)
    finally:
        _remove_link(link)


def test_file_symlink_outside_is_skipped_and_reported(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "secret.txt"
    outside.write_text("secret", encoding="utf-8")
    link = root / "leak.txt"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        pytest.skip("creating a file symlink is not permitted on this host")
    try:
        got = _list_workdir_files(root)
        assert "leak.txt" not in got
        assert any(item.startswith("<skipped link: leak.txt") for item in got)
    finally:
        _remove_link(link)


def test_entry_cap_records_truncation(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    for i in range(8):
        (root / f"file{i}.txt").write_text(str(i), encoding="utf-8")
    got = _list_workdir_files(root, limit=3)
    listed = [item for item in got if not item.startswith("<")]
    assert len(listed) == 3
    assert any(item.startswith("<truncated:") for item in got)
    assert len(set(listed)) == len(listed)


def test_staged_modified_and_deleted_reported(tmp_path):
    from redharness.sandbox.runner import _new_workdir_files, _staged_baseline
    root = tmp_path / "w"
    (root / "in").mkdir(parents=True)
    (root / "out").mkdir()
    for n in ("a.bin", "b.bin", "c.bin"):
        (root / "in" / n).write_bytes(b"orig")
    (root / "in" / "nonce.txt").write_text("n", encoding="ascii")
    base = _staged_baseline(root)
    (root / "in" / "a.bin").write_bytes(b"diff")                    # same size, different content
    (root / "in" / "b.bin").unlink()
    (root / "in" / "nonce.txt").unlink()                            # harness deletes the nonce by design
    (root / "out" / "done.json").write_text("{}", encoding="utf-8")  # guest record: excluded
    (root / "out" / "dropped.txt").write_text("x", encoding="utf-8")
    got = _new_workdir_files(root, base)
    assert sorted(got) == ["deleted: in/b.bin", "modified: in/a.bin", "out/dropped.txt"]


def test_staged_untouched_not_reported(tmp_path):
    from redharness.sandbox.runner import _new_workdir_files, _staged_baseline
    root = tmp_path / "w"
    root.mkdir()
    (root / "t.exe").write_bytes(b"x")
    assert _new_workdir_files(root, _staged_baseline(root)) == []
    assert _new_workdir_files(root, {"t.exe"}) == []


def test_clipped_names_are_marked_in_reply_and_evidence():
    from types import SimpleNamespace
    from redharness.mcp.session import _side_effects_reply
    long = "x" * 300
    r = _side_effects_reply(SimpleNamespace(side_effects=[long, "ok.txt"]))
    assert r["side_effects"][0] == "x" * 200 + "…[clipped]"
    assert r["side_effects"][1] == "ok.txt" and r["side_effects_names_clipped"] == 1
    assert "side_effects_names_clipped" not in _side_effects_reply(SimpleNamespace(side_effects=["a"]))


def test_evidence_marks_clipped_names(tmp_path):
    from redharness.core.cas import Cas
    from redharness.core.result import Status
    from redharness.sandbox.evidence import build_run_evidence
    from redharness.sandbox.model import CaseResult, SandboxRun
    case = CaseResult(0, ("a",), None, "0" * 64, Status.OK, exit_code=0, integrity_verified=True)
    run = SandboxRun(run_id="r", target_sha256="1" * 64, status=Status.OK, cases=[case])
    run.sandbox_closed = True
    run.side_effects = ["y" * 250, "ok.txt"]
    ev = build_run_evidence(Cas(tmp_path / "cas"), run, case)
    p = ev["parameters"]
    assert p["side_effects"][0] == "y" * 200 + "\u2026[clipped]" and p["side_effects"][1] == "ok.txt"
    assert p["side_effects_names_clipped"] == 1
