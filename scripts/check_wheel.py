"""Core-only wheel gate: fails if a built redharness wheel carries an optional (Pro) module or a file that is not in
the source tree it was built from.

  python scripts/check_wheel.py <wheel file or directory holding exactly one .whl> [--src DIR] [--forbid GLOB ...]

Checks (exit 1 on any hit, 2 on a usage error, 0 when clean):
  1. no wheel entry matches PRO_PATHS (plus any --forbid glob; `**` crosses directories, `*` and `?` do not);
  2. with --src: every `redharness/...` entry of the wheel exists below DIR (e.g. `src`), so files that are not part of
     the source tree (untracked build outputs, leftovers) cannot ride along in package data.
Stdlib only; reads the wheel as a zip and never installs or imports it.
"""
from __future__ import annotations

import argparse
import re
import sys
import zipfile
from pathlib import Path

# Optional modules that only the extended build ships (the Core imports them lazily and degrades with a
# "premium feature not included in this build" message). Paths are relative to the wheel root.
PRO_PATHS = (
    "redharness/dynamic/rhtrace.py", "redharness/dynamic/rhtrace/**",
    "redharness/dynamic/region_view.py", "redharness/mcp/region_tool.py",
    "redharness/jobs/bundle.py",
    "redharness/evals/**",
    "redharness/analysis/driver.py", "redharness/analysis/ctl.py", "redharness/analysis/driver_profile.py",
    "redharness/analysis/bundle.py", "redharness/analysis/workspace.py", "redharness/analysis/service_audit.py",
    "redharness/mcp/driver_facts.py",
    "redharness/kernel/**", "redharness/models/**", "redharness/studio/**",
)


def glob_re(pattern: str) -> re.Pattern[str]:
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def wheel_entries(wheel: Path) -> list[str]:
    with zipfile.ZipFile(wheel) as zf:
        return [n for n in zf.namelist() if not n.endswith("/")]


def pro_entries(names: list[str], patterns: tuple[str, ...] | list[str] = PRO_PATHS) -> list[str]:
    res = [glob_re(p) for p in patterns]
    return sorted(n for n in names if any(r.match(n) for r in res))


def foreign_entries(names: list[str], src: Path) -> list[str]:
    """Package files in the wheel that do not exist in the source tree."""
    return sorted(n for n in names if n.startswith("redharness/") and not (src / n).is_file())


def find_wheel(path: Path) -> Path:
    if path.is_file():
        return path
    wheels = sorted(path.glob("redharness-*.whl"))
    if len(wheels) != 1:
        raise ValueError(f"expected exactly one redharness-*.whl in {path}, found {len(wheels)}")
    return wheels[0]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Core-only wheel gate")
    ap.add_argument("wheel", help="the .whl file, or a directory holding exactly one redharness-*.whl")
    ap.add_argument("--src", help="source root the wheel was built from (the directory that holds redharness/)")
    ap.add_argument("--forbid", action="append", default=[], metavar="GLOB", help="extra forbidden path glob")
    a = ap.parse_args(sys.argv[1:] if argv is None else argv)
    try:
        wheel = find_wheel(Path(a.wheel))
        names = wheel_entries(wheel)
    except (OSError, ValueError, zipfile.BadZipFile) as e:
        print(f"check_wheel: {e}", file=sys.stderr)
        return 2
    if not any(n.startswith("redharness/") for n in names):
        print(f"check_wheel: {wheel.name} holds no redharness package", file=sys.stderr)
        return 2
    pro = pro_entries(names, tuple(PRO_PATHS) + tuple(a.forbid))
    foreign = foreign_entries(names, Path(a.src)) if a.src else []
    for n in pro:
        print(f"check_wheel: optional (Pro) module in the Core wheel: {n}", file=sys.stderr)
    for n in foreign:
        print(f"check_wheel: not in the source tree: {n}", file=sys.stderr)
    if pro or foreign:
        print(f"check_wheel: FAILED ({wheel.name}: {len(pro)} Pro, {len(foreign)} foreign)", file=sys.stderr)
        return 1
    print(f"check_wheel: OK ({wheel.name}: {len(names)} entries, Core only)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
