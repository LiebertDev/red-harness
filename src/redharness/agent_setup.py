"""`rh setup`: register the Red Harness MCP server in the user's AI coding clients and install the agent skill.

Rules (they hold for every client and for the skill file):
  - a file is backed up (timestamped copy next to it) before it is changed;
  - existing content is merged, never overwritten; only the `red-harness` entry is touched;
  - a second run changes nothing; `--dry-run` shows the plan and the diffs without writing anything;
  - a client's own CLI is used when it has one (Claude Code, Codex CLI); the others are JSON files edited in place;
  - `--print` only prints the snippets, `--uninstall` removes only our entry (and our skill file);
  - an entry or skill file that is not recognisably ours (an entry that does not run `rh mcp`, a SKILL.md whose content
    is not a version we shipped) is reported and left alone unless `--force` is given;
  - an update never leaves the client without the previous entry: it is replaced in place where the client CLI can,
    otherwise the previous entry is restored when the new one cannot be added;
  - a client CLI that is a batch shim (.cmd/.bat, run by cmd.exe, which re-parses its arguments) is resolved to the real
    program behind it; when that is not possible, only arguments free of cmd.exe metacharacters are passed to it, else
    the client is skipped with a pointer to `--print`.
"""

from __future__ import annotations

import argparse
import copy
import difflib
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Mapping

SERVER_NAME = "red-harness"
SKILL_NAME = "red-harness"
CLIENT_IDS = ("claude-code", "codex", "cursor", "gemini", "claude-desktop")
CLIENT_LABELS = {"claude-code": "Claude Code", "codex": "Codex CLI", "cursor": "Cursor", "gemini": "Gemini CLI",
                 "claude-desktop": "Claude Desktop"}
ENGINES = ("ghidra", "ida")
# Config files larger than this are refused (read nothing, write nothing).
MAX_CONFIG_BYTES = 8 * 1024 * 1024
# sha256 of every SKILL.md version that was shipped (LF line endings). `--uninstall` removes only a file with one of
# these contents; add the new hash here whenever skill/SKILL.md changes (a unit test enforces it).
SHIPPED_SKILL_SHA256 = frozenset({
    "b68a401b28c409fa36a8c9bba35817dfef0edfa1bbe46e9f4b229e42b7064bcf",
    "e09aafb13457906accbe0c408979fb29e5e45dddd84c1d4e280480cc6b65dad8",
    "5a746d5e3849fd271ba687ece06109da610e5ea9fb285981cb9611c0e4df6931",
    "3223f37b22e32f3f90234b20b559c5df2af5e9b892ec9d6d62065b07b3b600ab",
    "8a3a85c951c64f839cbcd4c5261172eefafcf7c0e95155d1e77295cfb93d1e71",
    "18035fdcb0ed3ed3a7cb6c5aa9cf148db806a442ada3b7a8ff3909cccd9fb702",   # control_pair rule (verifier 24)
})
# The program basenames of our own server entry (its args start with "mcp").
OUR_COMMANDS = ("rh", "rh.exe")
# Characters cmd.exe interprets when it parses the command line of a batch file: `"` toggles its quoting (so it can end
# the quoting Python adds), `%` and `!` expand variables, `^` escapes, `& | < >` chain or redirect commands, `( )` end
# the parenthesised blocks npm shims put `%*` in, and a line break ends the command. An argument with any of them could
# run something else; it is never passed to a .cmd/.bat.
BATCH_UNSAFE = frozenset('"%!^&|<>()\r\n\x00')
BATCH_SUFFIXES = (".cmd", ".bat")


class SetupError(Exception):
    """A user-actionable failure; the message is printed as is."""


def _is_batch(program: str) -> bool:
    return program.lower().endswith(BATCH_SUFFIXES)


def batch_unsafe_args(args: list[str]) -> list[str]:
    """The arguments that must not reach a batch file (see BATCH_UNSAFE)."""
    return [a for a in args if any(ch in BATCH_UNSAFE for ch in a)]


def _read_limited(path: Path) -> bytes:
    """The file's bytes; SetupError when it is larger than MAX_CONFIG_BYTES."""
    with open(path, "rb") as fh:
        size = os.fstat(fh.fileno()).st_size
        data = fh.read(MAX_CONFIG_BYTES + 1) if size <= MAX_CONFIG_BYTES else b""
    if size > MAX_CONFIG_BYTES or len(data) > MAX_CONFIG_BYTES:
        raise SetupError(f"{path} is larger than {MAX_CONFIG_BYTES // (1024 * 1024)} MiB; refusing to read it")
    return data


# --------------------------------------------------------------------------------------------------------------------
# environment (everything the code reads from the machine goes through here, so tests can use temp directories)
# --------------------------------------------------------------------------------------------------------------------
def _default_run(cmd: list[str]) -> subprocess.CompletedProcess:
    # Last line of defence: cmd.exe re-parses the arguments of a batch file, so nothing with its metacharacters goes there
    # (the planner already resolves shims or skips the client; this catches any other caller).
    if _is_batch(cmd[0]) and batch_unsafe_args(cmd[1:]):
        raise SetupError(f"refusing to pass arguments with cmd.exe metacharacters to the batch file {cmd[0]}")
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)


@dataclass
class SetupEnv:
    home: Path
    environ: Mapping[str, str]
    which: Callable[[str], str | None] = shutil.which
    run: Callable[[list[str]], Any] = _default_run
    now: Callable[[], datetime] = datetime.now

    @classmethod
    def system(cls) -> "SetupEnv":
        return cls(home=Path.home(), environ=os.environ)

    @property
    def appdata(self) -> Path:
        return Path(self.environ.get("APPDATA") or self.home / "AppData" / "Roaming")

    @property
    def localappdata(self) -> Path:
        return Path(self.environ.get("LOCALAPPDATA") or self.home / "AppData" / "Local")

    # Claude Code
    @property
    def claude_dir(self) -> Path:
        d = self.environ.get("CLAUDE_CONFIG_DIR")
        return Path(d) if d else self.home / ".claude"

    @property
    def claude_json(self) -> Path:
        d = self.environ.get("CLAUDE_CONFIG_DIR")
        return Path(d) / ".claude.json" if d else self.home / ".claude.json"

    # Codex CLI
    @property
    def codex_dir(self) -> Path:
        d = self.environ.get("CODEX_HOME")
        return Path(d) if d else self.home / ".codex"

    @property
    def codex_toml(self) -> Path:
        return self.codex_dir / "config.toml"

    # Cursor, Gemini CLI
    @property
    def cursor_dir(self) -> Path:
        return self.home / ".cursor"

    @property
    def gemini_dir(self) -> Path:
        return self.home / ".gemini"

    # Claude Desktop: the classic install keeps its config in %APPDATA%\Claude, the Microsoft Store (MSIX) build in the
    # package's virtualized copy of that folder.
    def desktop_config_candidates(self) -> list[Path]:
        out = [self.appdata / "Claude" / "claude_desktop_config.json"]
        pkgs = self.localappdata / "Packages"
        try:
            for p in sorted(pkgs.glob("Claude_*")):
                out.append(p / "LocalCache" / "Roaming" / "Claude" / "claude_desktop_config.json")
        except OSError:
            pass
        return out

    def desktop_config(self) -> tuple[Path, bool]:
        """(config path, detected). A config file wins, then an existing app folder (store build first)."""
        cands = self.desktop_config_candidates()
        for c in cands:
            if c.is_file():
                return c, True
        for c in reversed(cands):
            if c.parent.is_dir():
                return c, True
        return cands[0], False

    # shared skills folder read by Codex CLI and Gemini CLI
    @property
    def agents_skills_dir(self) -> Path:
        return self.home / ".agents" / "skills"


def detect_clients(env: SetupEnv) -> dict[str, bool]:
    return {
        "claude-code": bool(env.which("claude")) or env.claude_dir.is_dir() or env.claude_json.is_file(),
        "codex": bool(env.which("codex")) or env.codex_dir.is_dir(),
        "cursor": env.cursor_dir.is_dir() or bool(env.which("cursor")),
        "gemini": env.gemini_dir.is_dir() or bool(env.which("gemini")),
        "claude-desktop": env.desktop_config()[1],
    }


def skill_destinations(client: str, env: SetupEnv) -> Path | None:
    """SKILL.md path for a client that reads agent skills, else None."""
    if client == "claude-code":
        return env.claude_dir / "skills" / SKILL_NAME / "SKILL.md"
    if client in ("codex", "gemini"):
        return env.agents_skills_dir / SKILL_NAME / "SKILL.md"
    return None


# A path the shim starts, relative to its own folder: "%~dp0\node_modules\...\cli.js" or "%dp0%\...\bin\x.js".
_SHIM_TARGET = re.compile(r'"%(?:~dp0|dp0%)\\?([^"%\r\n]+)"', re.I)


def resolve_launcher(exe: str, env: SetupEnv) -> list[str]:
    """The argv prefix that runs the client CLI `exe` without a batch file in between.

    An npm-style shim (`claude.cmd`, `codex.cmd`) is replaced by what it starts: the native .exe it names, or node (the
    `node.exe` next to the shim, else a `node` .exe on PATH) plus the package script. A shim that cannot be read that way
    is returned as is; the caller then passes it only arguments free of cmd.exe metacharacters.
    """
    if not _is_batch(exe):
        return [exe]
    shim = Path(exe)
    try:
        text = _read_limited(shim).decode("utf-8", "replace")
    except (OSError, SetupError):
        return [exe]
    base = shim.parent
    for rel in _SHIM_TARGET.findall(text):
        parts = [p for p in rel.replace("/", "\\").split("\\") if p]
        if not parts or ".." in parts or parts[-1].lower() == "node.exe":
            continue
        target = base.joinpath(*parts)
        if not target.is_file():
            continue
        suffix = target.suffix.lower()
        if suffix == ".exe":
            return [str(target)]
        if suffix in (".js", ".cjs", ".mjs"):
            node = base / "node.exe"
            if not node.is_file():
                found = env.which("node")
                if not found or _is_batch(found):
                    return [exe]
                node = Path(found)
            return [str(node), str(target)]
    return [exe]


# --------------------------------------------------------------------------------------------------------------------
# the server entry
# --------------------------------------------------------------------------------------------------------------------
def build_entry(rh_exe: str, engine: str, engine_dir: str | None, environ: Mapping[str, str]) -> dict:
    env_vars: dict[str, str] = {}
    if engine_dir:
        env_vars["RH_GHIDRA_DIR" if engine == "ghidra" else "RH_IDA_DIR"] = engine_dir
    if environ.get("RH_DATA_ROOT"):
        env_vars["RH_DATA_ROOT"] = environ["RH_DATA_ROOT"]
    entry: dict[str, Any] = {"command": rh_exe, "args": ["mcp", "--engine", engine]}
    if env_vars:
        entry["env"] = env_vars
    return entry


def _norm(entry: Any) -> dict | None:
    """The three fields that define our entry (extra keys a client adds, such as `type`, are ignored)."""
    if not isinstance(entry, dict):
        return None
    return {"command": entry.get("command"), "args": list(entry.get("args") or []), "env": dict(entry.get("env") or {})}


def _same(current: Any, entry: dict) -> bool:
    return _norm(current) == _norm(entry)


def is_our_entry(entry: Any) -> bool:
    """True for an entry `rh setup` wrote: it runs an `rh` / `rh.exe` with arguments that start with `mcp`."""
    if not isinstance(entry, dict):
        return False
    command, args = entry.get("command"), entry.get("args")
    if not isinstance(command, str) or not isinstance(args, list) or not args or args[0] != "mcp":
        return False
    return command.replace("\\", "/").rsplit("/", 1)[-1].lower() in OUR_COMMANDS


_NOT_OURS = (f"an entry named {SERVER_NAME!r} that does not run `rh mcp` is there; left alone "
             f"(--force replaces or removes it anyway)")


def skill_digest(data: bytes) -> str:
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def read_skill() -> bytes:
    from importlib import resources
    data = resources.files("redharness.skill").joinpath("SKILL.md").read_bytes()
    return data.replace(b"\r\n", b"\n")


def _skill_path_in_package() -> str:
    from importlib import resources
    return str(resources.files("redharness.skill").joinpath("SKILL.md"))


# --------------------------------------------------------------------------------------------------------------------
# plan / apply
# --------------------------------------------------------------------------------------------------------------------
@dataclass
class Step:
    client: str
    kind: str                       # "mcp" | "skill"
    action: str                     # add | update | remove | create | unchanged | absent | skipped | error
    target: str                     # path (or the command) shown to the user
    note: str = ""
    diff: str = ""
    commands: list[list[str]] = field(default_factory=list)
    apply: Callable[[], None] | None = None
    backup: str | None = None
    error: str | None = None

    @property
    def changes(self) -> bool:
        return self.action in ("add", "update", "remove", "create")


def _udiff(before: str, after: str, path: str) -> str:
    lines = difflib.unified_diff(before.splitlines(), after.splitlines(), fromfile=path if before else "/dev/null",
                                 tofile=path, lineterm="", n=2)
    return "\n".join(lines)


def _backup(path: Path, env: SetupEnv) -> str | None:
    if not path.exists():
        return None
    stamp = env.now().strftime("%Y%m%d-%H%M%S")
    n = 1
    while True:
        dest = path.with_name(f"{path.name}.rh-backup-{stamp}" + (f"-{n}" if n > 1 else ""))
        try:
            out = open(dest, "xb")          # exclusive: never overwrites an existing file
        except FileExistsError:
            n += 1
            continue
        break
    try:
        with out, open(path, "rb") as src:
            shutil.copyfileobj(src, out)
        shutil.copystat(path, dest)
    except BaseException:
        dest.unlink(missing_ok=True)
        raise
    return str(dest)


def _atomic_write(path: Path, data: bytes) -> None:
    """Write `data` to `path` through a fresh, exclusively created temp file in the same folder, then os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".rh-tmp", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.chmod(tmp, stat.S_IMODE(os.stat(path).st_mode))     # keep the mode of the file it replaces
        except FileNotFoundError:
            pass
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _entry_json(entry: dict | None) -> str:
    return "" if entry is None else json.dumps(entry, indent=2, ensure_ascii=False)


# ---- JSON file clients (Cursor, Gemini CLI, Claude Desktop) --------------------------------------------------------
def _indent_of(text: str) -> Any:
    m = re.search(r'\n([ \t]+)"', text)
    return m.group(1) if m else 2


def plan_json_file(client: str, path: Path, entry: dict, uninstall: bool, env: SetupEnv, force: bool = False) -> Step:
    show = str(path)
    bom = False
    text = ""
    data: dict = {}
    if path.is_file():
        try:
            raw = _read_limited(path)
        except (OSError, SetupError) as e:
            return Step(client, "mcp", "error", show, f"{e}; left untouched")
        bom = raw.startswith(b"\xef\xbb\xbf")
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            return Step(client, "mcp", "error", show, "not valid UTF-8; left untouched")
        if text.strip():
            try:
                data = json.loads(text)
            except ValueError as e:
                return Step(client, "mcp", "error", show, f"not valid JSON ({e}); left untouched, fix or use --print")
            if not isinstance(data, dict):
                return Step(client, "mcp", "error", show, "top level is not an object; left untouched")
    servers = data.get("mcpServers", {})
    if not isinstance(servers, dict):
        return Step(client, "mcp", "error", show, '"mcpServers" is not an object; left untouched')
    current = servers.get(SERVER_NAME)
    new = copy.deepcopy(data)
    if SERVER_NAME in servers and not (force or is_our_entry(current) or _same(current, entry)):
        return Step(client, "mcp", "skipped", show, _NOT_OURS)
    if uninstall:
        if SERVER_NAME not in servers:
            return Step(client, "mcp", "absent", show)
        del new["mcpServers"][SERVER_NAME]
        action = "remove"
    else:
        if current is not None and _same(current, entry):
            return Step(client, "mcp", "unchanged", show)
        new.setdefault("mcpServers", {})
        new["mcpServers"][SERVER_NAME] = entry
        action = "add" if current is None else "update"
    new_text = json.dumps(new, indent=_indent_of(text), ensure_ascii=False)
    if text.endswith("\n") or not text:
        new_text += "\n"

    def apply() -> None:
        step.backup = _backup(path, env)
        _atomic_write(path, new_text.encode("utf-8-sig" if bom else "utf-8"))

    step = Step(client, "mcp", action, show, diff=_udiff(text, new_text, show), apply=apply)
    return step


# ---- CLI clients (Claude Code, Codex CLI) --------------------------------------------------------------------------
def _parse_json_config(raw: bytes) -> dict:
    data = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError("the top level is not an object")
    return data


def _parse_toml_config(raw: bytes) -> dict:
    return tomllib.loads(raw.decode("utf-8-sig"))


@dataclass(frozen=True)
class _CliClient:
    tool: str                           # the command on PATH
    config: Path                        # the file the command edits (read to verify, backed up before a change)
    parse: Callable[[bytes], dict]
    table: str                          # the key that holds the servers
    fmt: str                            # JSON | TOML (for messages)


def _cli_client(client: str, env: SetupEnv) -> _CliClient:
    if client == "claude-code":
        return _CliClient("claude", env.claude_json, _parse_json_config, "mcpServers", "JSON")
    return _CliClient("codex", env.codex_toml, _parse_toml_config, "mcp_servers", "TOML")


def _read_cli_entry(c: _CliClient) -> tuple[Any, str | None]:
    """(our entry or None, problem or None)."""
    if not c.config.is_file():
        return None, None
    try:
        data = c.parse(_read_limited(c.config))
    except SetupError as e:
        return None, str(e)
    except (ValueError, UnicodeDecodeError, OSError) as e:
        return None, f"{c.config} is not readable {c.fmt} ({e})"
    servers = data.get(c.table)
    return (servers.get(SERVER_NAME) if isinstance(servers, dict) else None), None


def _without_ours(c: _CliClient, path: Path) -> dict | None:
    """The parsed file without our entry (and without a servers table that is then empty); None if unreadable."""
    try:
        data = c.parse(_read_limited(path)) if path.is_file() else {}
    except (SetupError, ValueError, UnicodeDecodeError, OSError):
        return None
    servers = data.get(c.table)
    if isinstance(servers, dict):
        servers.pop(SERVER_NAME, None)
        if not servers:
            del data[c.table]
    return data


def _cli_commands(client: str, launcher: list[str], entry: dict, uninstall: bool, replace: bool) -> list[list[str]]:
    cmds: list[list[str]] = []
    if client == "claude-code":
        # `claude mcp add` refuses a name that exists, so an update is remove + add; a failed add restores the previous
        # entry (see plan_cli_client)
        if uninstall or replace:
            cmds.append([*launcher, "mcp", "remove", SERVER_NAME, "--scope", "user"])
        if not uninstall:
            add = [*launcher, "mcp", "add", "--scope", "user", SERVER_NAME]
            for k, v in (entry.get("env") or {}).items():
                add += ["-e", f"{k}={v}"]
            cmds.append(add + ["--", entry["command"], *entry["args"]])
    else:
        # `codex mcp add` replaces an existing entry in place, so an update is a single add with no gap
        if uninstall:
            cmds.append([*launcher, "mcp", "remove", SERVER_NAME])
        else:
            add = [*launcher, "mcp", "add", SERVER_NAME]
            for k, v in (entry.get("env") or {}).items():
                add += ["--env", f"{k}={v}"]
            cmds.append(add + ["--", entry["command"], *entry["args"]])
    return cmds


def _batch_problem(launcher: list[str], cmds: list[list[str]]) -> list[str]:
    """The arguments that cannot go through `launcher` (non-empty only when it is a batch file)."""
    if not _is_batch(launcher[0]):
        return []
    return batch_unsafe_args([a for cmd in cmds for a in cmd[len(launcher):]])


def _run_checked(env: SetupEnv, c: _CliClient, launcher: list[str], cmd: list[str]) -> None:
    r = env.run(cmd)
    if r.returncode != 0:
        msg = (r.stderr or r.stdout or "").strip().splitlines()
        verb = " ".join(cmd[len(launcher):len(launcher) + 2])
        raise SetupError(f"`{c.tool} {verb}` failed ({r.returncode})" + (": " + msg[0] if msg else ""))


def _restore_previous(client: str, c: _CliClient, launcher: list[str], old: dict, backup: str | None,
                      env: SetupEnv) -> str:
    """Put the entry that was there before a failed update back; returns what happened, for the error message."""
    after, _ = _read_cli_entry(c)
    if after is not None and _same(after, old):
        return "the previous entry is still in place"
    # 1. the client's own command, with the exact previous entry
    if client == "claude-code":
        cmds = ([[*launcher, "mcp", "remove", SERVER_NAME, "--scope", "user"]] if after is not None else []) + [
            [*launcher, "mcp", "add-json", "--scope", "user", SERVER_NAME, json.dumps(old, ensure_ascii=False)]]
        if not _batch_problem(launcher, cmds):
            try:
                for cmd in cmds:
                    _run_checked(env, c, launcher, cmd)
                after, _ = _read_cli_entry(c)
                if after is not None and _same(after, old):
                    return "the previous entry was restored with `claude mcp add-json`"
            except (SetupError, OSError, subprocess.SubprocessError):
                pass
    # 2. the backup, but only when nothing except our entry changed since it was taken
    if backup:
        bak = Path(backup)
        want = _without_ours(c, bak)
        if want is not None and want == _without_ours(c, c.config):
            try:
                _atomic_write(c.config, _read_limited(bak))
                after, _ = _read_cli_entry(c)
                if after is not None and _same(after, old):
                    return f"the previous entry was restored from the backup {backup}"
            except (SetupError, OSError):
                pass
    return (f"the previous entry could NOT be restored, re-add it by hand: {json.dumps(old, ensure_ascii=False)}"
            + (f" (backup: {backup})" if backup else ""))


def plan_cli_client(client: str, entry: dict, uninstall: bool, env: SetupEnv, force: bool = False) -> Step:
    c = _cli_client(client, env)
    show = str(c.config)
    current, problem = _read_cli_entry(c)
    if problem:
        return Step(client, "mcp", "error", show, problem + "; left untouched")
    if uninstall and current is None:
        return Step(client, "mcp", "absent", show)
    if not uninstall and current is not None and _same(current, entry):
        return Step(client, "mcp", "unchanged", show)
    if current is not None and not force and not is_our_entry(current):
        return Step(client, "mcp", "skipped", show, _NOT_OURS)
    exe = env.which(c.tool)
    if not exe:
        return Step(client, "mcp", "skipped", show, f"the `{c.tool}` command was not found on PATH; "
                    f"use `rh setup --print --client {client}` and register the server by hand")
    launcher = resolve_launcher(exe, env)
    action = "remove" if uninstall else ("add" if current is None else "update")
    cmds = _cli_commands(client, launcher, entry, uninstall, replace=current is not None and not uninstall)
    bad = _batch_problem(launcher, cmds)
    if bad:
        return Step(client, "mcp", "skipped", show,
                    f"`{exe}` is a batch file and cmd.exe would re-interpret the argument {bad[0]!r} (it contains one "
                    f"of \" % ! ^ & | < > ( ) or a line break); nothing was run: use `rh setup --print --client "
                    f"{client}` and register the server by hand")
    shown_old = _entry_json(_norm(current) if current is not None else None)
    shown_new = "" if uninstall else _entry_json(_norm(entry))
    diff = _udiff(shown_old, shown_new, show + " [" + SERVER_NAME + "]")

    def apply() -> None:
        step.backup = _backup(c.config, env)
        try:
            for cmd in cmds:
                _run_checked(env, c, launcher, cmd)
            after, problem2 = _read_cli_entry(c)
            ok = after is None if uninstall else (after is not None and _same(after, entry))
            if problem2 or not ok:
                raise SetupError(f"{c.tool} reported success but {c.config} does not show the expected state")
        except (SetupError, OSError, subprocess.SubprocessError) as e:
            if action != "update":
                raise
            raise SetupError(f"update failed: {e}; "
                             + _restore_previous(client, c, launcher, current, step.backup, env)) from e

    step = Step(client, "mcp", action, show, commands=cmds, diff=diff, apply=apply)
    return step


# ---- skill file ----------------------------------------------------------------------------------------------------
def plan_skill(client: str, path: Path, content: bytes, uninstall: bool, env: SetupEnv, force: bool = False) -> Step:
    show = str(path)
    try:
        existing = _read_limited(path) if path.is_file() else None
    except (OSError, SetupError) as e:
        return Step(client, "skill", "error", show, f"{e}; left untouched")
    if uninstall:
        if existing is None:
            return Step(client, "skill", "absent", show)
        if not re.search(rb"^name:\s*" + SKILL_NAME.encode() + rb"\s*$", existing, re.M):
            return Step(client, "skill", "skipped", show, "a skill file that is not ours is there; left alone")
        if skill_digest(existing) not in SHIPPED_SKILL_SHA256 and not force:
            return Step(client, "skill", "skipped", show, "the skill file differs from every version Red Harness "
                        "shipped (edited?); left alone (--force removes it anyway, after a backup)")

        def remove() -> None:
            step.backup = _backup(path, env)
            path.unlink()
            try:
                path.parent.rmdir()      # only if empty (the backup stays next to it, so normally it is kept)
            except OSError:
                pass

        step = Step(client, "skill", "remove", show, apply=remove)
        return step
    if existing == content:
        return Step(client, "skill", "unchanged", show)
    action = "create" if existing is None else "update"
    diff = (f"(new file, {len(content.decode().splitlines())} lines)" if existing is None
            else _udiff(existing.decode("utf-8", "replace"), content.decode(), show))

    def write() -> None:
        step.backup = _backup(path, env)
        _atomic_write(path, content)

    step = Step(client, "skill", action, show, diff=diff, apply=write)
    return step


# ---- the whole plan ------------------------------------------------------------------------------------------------
def build_plan(clients: list[str], entry: dict, uninstall: bool, with_skill: bool, env: SetupEnv,
               force: bool = False) -> list[Step]:
    steps: list[Step] = []
    content = read_skill() if (with_skill and not uninstall) else b""
    for c in clients:
        if c == "claude-code" or c == "codex":
            steps.append(plan_cli_client(c, entry, uninstall, env, force))
        elif c == "cursor":
            steps.append(plan_json_file(c, env.cursor_dir / "mcp.json", entry, uninstall, env, force))
        elif c == "gemini":
            steps.append(plan_json_file(c, env.gemini_dir / "settings.json", entry, uninstall, env, force))
        elif c == "claude-desktop":
            steps.append(plan_json_file(c, env.desktop_config()[0], entry, uninstall, env, force))
    if with_skill:
        seen: set[Path] = set()
        for c in clients:
            dest = skill_destinations(c, env)
            if dest is None or dest in seen:
                continue
            seen.add(dest)
            steps.append(plan_skill(c, dest, content, uninstall, env, force))
    return steps


def execute(steps: list[Step]) -> None:
    for s in steps:
        if s.apply is None or not s.changes:
            continue
        try:
            s.apply()
        except (SetupError, OSError, subprocess.SubprocessError) as e:
            s.action, s.error = "error", str(e)


# --------------------------------------------------------------------------------------------------------------------
# --print
# --------------------------------------------------------------------------------------------------------------------
def _toml_str(s: str) -> str:
    return json.dumps(s)    # a JSON string is a valid TOML basic string


def toml_block(entry: dict) -> str:
    lines = [f"[mcp_servers.{SERVER_NAME}]", f"command = {_toml_str(entry['command'])}",
             "args = [" + ", ".join(_toml_str(a) for a in entry["args"]) + "]"]
    if entry.get("env"):
        lines.append("env = { " + ", ".join(f"{k} = {_toml_str(v)}" for k, v in entry["env"].items()) + " }")
    return "\n".join(lines)


def print_snippets(clients: list[str], entry: dict, env: SetupEnv, out: Callable[[str], None]) -> None:
    for c in clients:
        out(f"== {CLIENT_LABELS[c]} ({c})")
        if c == "claude-code":
            cmd = _cli_commands(c, ["claude"], entry, False, False)[0]
            out("Run:")
            out("  " + subprocess.list2cmdline(cmd))
        elif c == "codex":
            cmd = _cli_commands(c, ["codex"], entry, False, False)[0]
            out("Run:")
            out("  " + subprocess.list2cmdline(cmd))
            out(f"or add to {env.codex_toml}:")
            out(toml_block(entry))
        else:
            path = {"cursor": env.cursor_dir / "mcp.json", "gemini": env.gemini_dir / "settings.json",
                    "claude-desktop": env.desktop_config()[0]}[c]
            out(f"Merge into {path} (restart the client afterwards):")
            out(json.dumps({"mcpServers": {SERVER_NAME: entry}}, indent=2))
        dest = skill_destinations(c, env)
        if dest:
            out(f"Skill: copy {_skill_path_in_package()} to {dest}")
        out("")


# --------------------------------------------------------------------------------------------------------------------
# engine and executable discovery
# --------------------------------------------------------------------------------------------------------------------
def resolve_engine(requested: str | None) -> tuple[str, str | None, list[str]]:
    """(engine name, install folder or None, notes). Without `requested` the first usable of Ghidra, IDA."""
    from .config import Config
    from .quickstart import QuickstartError, _engine_dir, select_engine
    try:
        engine, name, notes = select_engine(Config.load(), requested)
    except QuickstartError as e:
        raise SetupError(str(e)) from e
    if engine is None:
        name = requested or "ghidra"
        notes = notes + [f"no usable engine found; registering --engine {name} anyway (the server will say what is "
                         f"missing; `rh deps list` shows the status)"]
    return name, _engine_dir(name), notes


def find_rh_executable() -> str:
    from .quickstart import _rh_executable
    exe = _rh_executable()
    if not Path(exe).is_absolute():
        raise SetupError("could not locate the installed `rh` executable (expected next to the Python interpreter or on PATH)")
    return exe


# --------------------------------------------------------------------------------------------------------------------
# command line
# --------------------------------------------------------------------------------------------------------------------
HELP = f"""usage: rh setup [--client ID ...] [--engine ghidra|ida] [--dry-run | --print] [--uninstall] [--no-skill] [--force]

Registers the Red Harness MCP server (`rh mcp`, absolute path to this `rh`) in your AI coding clients and installs the
agent skill, so the client can use the harness without hand-written configuration.

  --client ID     limit to one client; repeatable or comma separated: {", ".join(CLIENT_IDS)}
                  (default: every client that is detected on this machine)
  --engine NAME   ghidra or ida (default: the first usable one)
  --dry-run       show what would change, with diffs; write nothing
  --print         only print the configuration snippets for the selected clients; touch nothing
  --uninstall     remove only the `{SERVER_NAME}` entry and the skill file this command installed
  --no-skill      do not install the skill (Claude Code: ~/.claude/skills; Codex CLI, Gemini CLI: ~/.agents/skills)
  --force         also replace or remove a `{SERVER_NAME}` entry that does not run `rh mcp`, and remove an edited
                  skill file on --uninstall (both are otherwise reported and left alone)

Claude Code and Codex CLI are configured through their own `claude mcp` / `codex mcp` commands; Cursor, Gemini CLI and
Claude Desktop through their JSON files (merged). Every changed file is first copied to <name>.rh-backup-<timestamp>.
Running the command again changes nothing. Restart the client afterwards.
"""


def _parse(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="rh setup", add_help=False)
    p.add_argument("--client", action="append", default=[])
    p.add_argument("--engine", default=None)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--print", dest="print_only", action="store_true")
    p.add_argument("--uninstall", action="store_true")
    p.add_argument("--no-skill", action="store_true")
    p.add_argument("--force", action="store_true")
    p.add_argument("-h", "--help", action="store_true")
    return p.parse_args(argv)


def _selected_clients(requested: list[str], env: SetupEnv, printing: bool) -> tuple[list[str], bool]:
    """(client ids, explicit). Unknown ids raise SetupError."""
    ids: list[str] = []
    for item in requested:
        for part in item.split(","):
            part = part.strip().lower()
            if part and part not in ids:
                if part not in CLIENT_IDS:
                    raise SetupError(f"unknown client {part!r}; choose from: {', '.join(CLIENT_IDS)}")
                ids.append(part)
    if ids:
        return ids, True
    if printing:
        return list(CLIENT_IDS), False
    found = detect_clients(env)
    return [c for c in CLIENT_IDS if found[c]], False


def main(argv: list[str], env: SetupEnv | None = None,
         engine_resolver: Callable[[str | None], tuple[str, str | None, list[str]]] | None = None,
         rh_exe: str | None = None, out: Callable[[str], None] | None = None) -> int:
    emit = out or print
    if out is None and hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(errors="replace")
        except Exception:  # noqa: BLE001
            pass
    try:
        try:
            ns = _parse(argv)
        except SystemExit:
            emit("rh setup: invalid arguments\n" + HELP)
            return 2
        if ns.help:
            emit(HELP)
            return 0
        if ns.print_only and (ns.dry_run or ns.uninstall):
            emit("rh setup: --print cannot be combined with --dry-run or --uninstall")
            return 2
        env = env or SetupEnv.system()
        clients, explicit = _selected_clients(ns.client, env, ns.print_only)
        if not clients:
            emit("rh setup: no supported AI client was detected on this machine "
                 f"({', '.join(CLIENT_IDS)}).\nUse --client ID to force one, or --print to get the snippets.")
            return 1
        engine, engine_dir, notes = (engine_resolver or resolve_engine)(ns.engine)
        exe = rh_exe or find_rh_executable()
        entry = build_entry(exe, engine, engine_dir, env.environ)
        for n in notes:
            emit("note: " + (n if len(n) <= 200 else n[:197] + "..."))
        if ns.print_only:
            print_snippets(clients, entry, env, emit)
            return 0
        steps = build_plan(clients, entry, ns.uninstall, not ns.no_skill, env, ns.force)
        mode = "uninstall" if ns.uninstall else "install"
        emit(f"rh setup ({mode}{', dry run' if ns.dry_run else ''}): engine {engine}"
             f"{' (' + engine_dir + ')' if engine_dir else ''}, rh {exe}")
        if not ns.dry_run:
            execute(steps)
        _report(steps, ns.dry_run, emit)
        if any(s.action == "error" for s in steps):
            return 1
        if explicit and any(s.action == "skipped" and s.kind == "mcp" for s in steps):
            return 1
        return 0
    except SetupError as e:
        emit(f"rh setup: {e}")
        return 1


_VERB_DRY = {"add": "would add", "update": "would update", "remove": "would remove", "create": "would create"}
_VERB_DONE = {"add": "added", "update": "updated", "remove": "removed", "create": "created"}


def _report(steps: list[Step], dry: bool, emit: Callable[[str], None]) -> None:
    for s in steps:
        verb = (_VERB_DRY if dry else _VERB_DONE).get(s.action, s.action)
        emit(f"[{s.client}] {s.kind:5} {verb}: {s.target}" + (f"  ({s.note})" if s.note else ""))
        if s.error:
            emit(f"    error: {s.error}")
        if dry and s.changes:
            for cmd in s.commands:
                emit("    run: " + subprocess.list2cmdline(cmd))
            if s.diff:
                emit("\n".join("    " + ln for ln in s.diff.splitlines()))
        elif s.backup:
            emit(f"    backup: {s.backup}")
    if not any(s.changes for s in steps):
        if all(s.action != "error" for s in steps):
            emit("nothing to change.")
    elif dry:
        emit("dry run: nothing was written. Run `rh setup` without --dry-run to apply.")
    else:
        emit("done. Restart the client(s) so they pick up the server and the skill.")
