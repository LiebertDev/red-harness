r"""Leak guard: git-tracked text files must contain no personal information.

Caught: Windows user profile paths (C:\Users\<name>, C:/Users/<name>, /c/Users/<name>,
including JSON-escaped and URL-encoded forms), email addresses (allow list: users.noreply.github.com,
example.com) and the username read from the USERNAME environment variable at run time.
The same check is applied to staged files in .githooks/pre-commit (it uses this module).
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]

# C:\Users\name, C:\Users\name, C:/Users/name, /C:/Users/name, /c/Users/name, /mnt/c/Users/name
USER_PATH = re.compile(r"(?:[A-Za-z]:|/mnt/[A-Za-z]|/[A-Za-z])[\x5c/]+Users[\x5c/]+([^\x5c/\s\x22\x27`<>*:|?,;)\]}]+)", re.I)
# Claude scratch directory name: C--Users-<name>-Desktop-...
SCRATCH_NAME = re.compile(r"C--Users-([A-Za-z0-9_.]+?)-(?:Desktop|Documents|Downloads|AppData)", re.I)
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
# aquynh@gmail.com: the contact address printed in Capstone's own upstream licence text (licenses/capstone-*), kept unmodified
EMAIL_ALLOW = ("users.noreply.github.com", "example.com", "aquynh@gmail.com")
# non-personal profile directories and variable/placeholder forms
GENERIC_NAMES = {"public", "default", "default user", "all", "all users", "defaultuser0", "<name>", "name", "user", "username",
                 "runner", "runneradmin"}   # the GitHub-hosted CI runner accounts (an ordinary word, not a person)

BINARY_EXT = {".exe", ".dll", ".sys", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".zip", ".pdf", ".i64", ".pyc", ".bin"}


def _is_placeholder(name: str) -> bool:
    n = name.strip().lower()
    return (n in GENERIC_NAMES or n.startswith(("<", "{", "$", "%", "..."))
            or any(c in n for c in "<>{}$%*"))


def scan_text(text: str, username: str | None = None) -> list[str]:
    """Returns the violations in the text (list of short descriptions)."""
    found: list[str] = []
    for m in USER_PATH.finditer(text):
        if not _is_placeholder(m.group(1)):
            found.append("user profile path: " + m.group(0))
    for m in SCRATCH_NAME.finditer(text):
        found.append("scratch directory name: " + m.group(0))
    for m in EMAIL.finditer(text):
        if not m.group(0).lower().endswith(EMAIL_ALLOW):
            found.append("email: " + m.group(0))
    if username and len(username) >= 4 and username.lower() not in GENERIC_NAMES:
        if re.search(r"(?<![A-Za-z0-9])" + re.escape(username) + r"(?![A-Za-z0-9])", text, re.I):
            found.append("working-environment username appeared (USERNAME)")
    return found


def scan_file(path: Path, username: str | None = None) -> list[str]:
    if path.suffix.lower() in BINARY_EXT or not path.is_file():
        return []
    if path.resolve() == Path(__file__).resolve():  # the pattern documentation is in this file; do not scan itself
        return []
    data = path.read_bytes()
    if b"\0" in data[:8192]:
        return []
    return scan_text(data.decode("utf-8", errors="replace"), username)


def _git_lines(*args: str) -> list[str]:
    out = subprocess.run(["git", *args, "-z"], cwd=REPO, capture_output=True, check=True).stdout
    return [p for p in out.decode("utf-8", errors="replace").split("\0") if p]


def current_username() -> str | None:
    return os.environ.get("USERNAME") or os.environ.get("USER") or None


# --- the guard's own unit tests ----------------------------------------------------------------

def _u(prefix: str, sep: str, name: str) -> str:
    # built at run time so that no real pattern appears in the source
    return prefix + "Us" + "ers" + sep + name + sep + "x"


BS = chr(92)


def test_detects_path_variants():
    for s in (_u("C:" + BS, BS, "someone"), _u("C:" + BS * 2, BS * 2, "someone"), _u("C:/", "/", "someone"),
              _u("/c/", "/", "someone"), "[f](" + _u("/C:/", "/", "someone") + ")",
              "C--Us" + "ers-someone-Desktop-x"):
        assert scan_text(s), s


def test_allows_placeholders_and_system_profiles():
    for s in ("<HOME>/x", _u("C:" + BS, BS, "Public"), _u("C:" + BS, BS, "<name>"),
              _u("C:" + BS, BS, "%USERNAME%"), _u("C:/", "/", "$env:USERNAME"),
              "a@users.noreply.github.com", "x@example.com"):
        assert not scan_text(s), s


def test_detects_email_and_username():
    assert scan_text("write to foo.bar" + "@" + "mail.invalid")  # built at run time: no real address in the source
    assert scan_text("hello zekeriya here", username="zekeriya")
    assert not scan_text("hello", username="zekeriya")
    assert not scan_text("the test runner", username="runner")   # CI account name, not personal


def _staged_repo(tmp_path: Path, content: str) -> Path:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "f.txt").write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", "f.txt"], cwd=tmp_path, check=True)
    return tmp_path


def test_hook_main_rejects_forward_slash_profile_path(tmp_path):
    assert main([], repo=_staged_repo(tmp_path, "p = " + _u("C:/", "/", "x"))) == 1


def test_hook_main_rejects_staged_blob_even_if_worktree_clean(tmp_path):
    repo = _staged_repo(tmp_path, _u("C:" + BS, BS, "someone"))
    (repo / "f.txt").write_text("clean", encoding="utf-8")  # unstaged cleanup must not hide the staged leak
    assert main([], repo=repo) == 1


def test_hook_main_accepts_placeholder(tmp_path):
    assert main([], repo=_staged_repo(tmp_path, "p = " + _u("C:/", "/", "<name>"))) == 0


def test_hook_main_fails_closed_on_internal_error(tmp_path):
    assert main([], repo=tmp_path / "missing") == 2


# --- the real scan -----------------------------------------------------------------------------

def test_tracked_files_have_no_personal_info():
    user = current_username()
    problems: dict[str, list[str]] = {}
    if not (REPO / ".git").exists():
        pytest.skip("not a git work tree (e.g. an exported source tree): no tracked-file list to scan")
    try:
        tracked = _git_lines("ls-files")
    except (subprocess.CalledProcessError, OSError):
        pytest.skip("not a git work tree (e.g. an exported source tree): no tracked-file list to scan")
    for rel in tracked:
        hits = scan_file(REPO / rel, user)
        if hits:
            problems[rel] = sorted(set(hits))[:5]
    assert not problems, "personal information found:\n" + "\n".join(f"  {k}: {v}" for k, v in problems.items())


def scan_staged(repo: Path, username: str | None) -> dict[str, list[str]]:
    """Scans the staged (index) content, not the working-tree copy, with the same rules as the tracked-file test."""
    problems: dict[str, list[str]] = {}
    out = subprocess.run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"],
                         cwd=repo, capture_output=True, check=True).stdout
    for rel in (p for p in out.decode("utf-8", errors="replace").split("\0") if p):
        path = repo / rel
        if path.suffix.lower() in BINARY_EXT or path.resolve() == Path(__file__).resolve():
            continue
        data = subprocess.run(["git", "show", ":" + rel], cwd=repo, capture_output=True, check=True).stdout
        if b"\0" in data[:8192]:
            continue
        hits = scan_text(data.decode("utf-8", errors="replace"), username)
        if hits:
            problems[rel] = sorted(set(hits))[:5]
    return problems


def main(argv: list[str], repo: Path | None = None) -> int:
    """pre-commit entry point. Any internal error is fatal (non-zero): the guard never passes silently."""
    try:
        problems = scan_staged(repo or REPO, current_username())
    except BaseException as exc:  # noqa: BLE001 - fail closed
        print(f"[pre-commit] guard error, refusing to pass: {exc!r}", file=sys.stderr)
        return 2
    for rel, hits in problems.items():
        print(f"[pre-commit] {rel}: {hits}", file=sys.stderr)
    if problems:
        print("[pre-commit] personal information found; use placeholders (<HOME>, <REPO>, <REDACTED_EMAIL>).", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
