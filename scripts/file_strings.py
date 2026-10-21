"""Raw file string scan CLI (static, no engine, no execution).

  python scripts/file_strings.py <file> [--pattern REGEX] [--min N] [--ascii-only] [--max N] [--json]

Includes overlay and section gaps; reports file offset, mapped RVA and section.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from redharness.analysis.file_strings import render_file_strings, scan_file_strings_file


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Raw file string scan (ASCII/UTF-16LE, overlay included)")
    ap.add_argument("file")
    ap.add_argument("--pattern", help="case-insensitive regular expression over the decoded value")
    ap.add_argument("--min", type=int, default=4, dest="min_length")
    ap.add_argument("--ascii-only", action="store_true")
    ap.add_argument("--max", type=int, default=10_000, dest="max_strings")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(sys.argv[1:] if argv is None else argv)
    encodings = ("ascii",) if a.ascii_only else ("ascii", "utf-16le")
    try:
        r = scan_file_strings_file(a.file, min_length=a.min_length, encodings=encodings,
                                   pattern=a.pattern, max_strings=a.max_strings)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(asdict(r), ensure_ascii=False, indent=2) if a.json else render_file_strings(r), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
