"""scripts/check_wheel.py: the Core-only wheel gate run by the public CI. Synthetic wheels (zip files) only: nothing is
built, installed or imported."""
import importlib.util
import zipfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_wheel.py"


@pytest.fixture(scope="module")
def cw():
    spec = importlib.util.spec_from_file_location("check_wheel_under_test", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CORE = ["redharness/__init__.py", "redharness/core/proc.py", "redharness/dynamic/backend.py",
        "redharness-0.1.0.dist-info/METADATA", "redharness-0.1.0.dist-info/RECORD"]


def wheel(tmp_path: Path, names, name="redharness-0.1.0-py3-none-any.whl") -> Path:
    d = tmp_path / "dist"
    d.mkdir(exist_ok=True)
    w = d / name
    with zipfile.ZipFile(w, "w") as zf:
        for n in names:
            zf.writestr(n, "x")
    return w


def src_tree(tmp_path: Path, names) -> Path:
    src = tmp_path / "src"
    for n in names:
        if n.startswith("redharness/"):
            (src / n).parent.mkdir(parents=True, exist_ok=True)
            (src / n).write_text("x")
    return src


def test_core_wheel_passes(cw, tmp_path, capsys):
    w = wheel(tmp_path, CORE)
    assert cw.main([str(w.parent), "--src", str(src_tree(tmp_path, CORE))]) == 0
    assert "Core only" in capsys.readouterr().out


@pytest.mark.parametrize("pro", ["redharness/kernel/__init__.py", "redharness/dynamic/rhtrace/rhtrace.exe",
                                 "redharness/dynamic/rhtrace.py", "redharness/evals/runner.py",
                                 "redharness/studio/app.py", "redharness/jobs/bundle.py",
                                 "redharness/mcp/region_tool.py"])
def test_pro_module_in_the_wheel_fails(cw, tmp_path, capsys, pro):
    names = CORE + [pro]
    w = wheel(tmp_path, names)
    assert cw.main([str(w), "--src", str(src_tree(tmp_path, names))]) == 1   # even when it is in the source tree
    assert pro in capsys.readouterr().err


def test_extra_forbid_glob_and_core_lookalikes(cw, tmp_path):
    names = CORE + ["redharness/analysis/extra.py", "redharness/jobs/bundle_helpers.py", "redharness/kernelish.py"]
    w = wheel(tmp_path, names)
    assert cw.main([str(w)]) == 0                                   # *.py next to a Pro name is not Pro
    assert cw.main([str(w), "--forbid", "redharness/analysis/extra.py"]) == 1


def test_file_missing_from_the_source_tree_fails(cw, tmp_path, capsys):
    w = wheel(tmp_path, CORE + ["redharness/leftover.py"])
    assert cw.main([str(w), "--src", str(src_tree(tmp_path, CORE))]) == 1
    assert "not in the source tree: redharness/leftover.py" in capsys.readouterr().err


def test_usage_errors_are_not_a_pass(cw, tmp_path):
    (tmp_path / "empty").mkdir()
    assert cw.main([str(tmp_path / "empty")]) == 2                  # no wheel
    assert cw.main([str(wheel(tmp_path, ["other/x.py"], "other-1-py3-none-any.whl"))]) == 2   # no redharness package
    bad = tmp_path / "redharness-bad.whl"
    bad.write_bytes(b"not a zip")
    assert cw.main([str(bad)]) == 2
