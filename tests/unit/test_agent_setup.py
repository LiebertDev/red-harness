"""`rh setup`: client detection, merge/backup/idempotency, dry run, uninstall, the skill file. Every test works in a temp
HOME; the client CLIs are replaced by a fake runner that edits the temp config files the way the real commands do."""
from __future__ import annotations

import json
import tomllib
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from redharness import agent_setup as S

RH = r"C:\Tools\redharness\Scripts\rh.exe"
ENGINE = ("ghidra", r"C:\Tools\ghidra_12.1.3_PUBLIC", [])


class Clock:
    def __init__(self):
        self.n = 0

    def __call__(self):
        self.n += 1
        return datetime(2026, 1, 2, 3, 4, self.n % 60)


class Fake:
    """Temp HOME + fake `claude` / `codex` commands."""

    def __init__(self, tmp: Path, *, cli: bool = True, environ: dict | None = None):
        self.home = tmp / "home"
        self.home.mkdir()
        self.calls: list[list[str]] = []
        self.fail_next = False
        self.fail_verbs: set[str] = set()        # e.g. {"add"}: that subcommand fails, the others work
        self.touch_on_remove = False             # a running client writes the config while we update it
        self.environ = {"APPDATA": str(self.home / "AppData" / "Roaming"),
                        "LOCALAPPDATA": str(self.home / "AppData" / "Local"), **(environ or {})}
        tools = {"claude": r"C:\bin\claude.exe", "codex": r"C:\bin\codex.cmd"} if cli else {}
        self.env = S.SetupEnv(home=self.home, environ=self.environ, which=lambda n: tools.get(n), run=self.run,
                              now=Clock())

    # -- fake client CLIs ---------------------------------------------------------------------------------------------
    def run(self, cmd):
        self.calls.append(cmd)
        if self.fail_next:
            return SimpleNamespace(returncode=1, stdout="", stderr="boom\ndetails")
        if Path(cmd[0].replace("\\", "/")).stem.lower() == "node":     # a resolved npm shim: node <script> ...
            cmd = cmd[1:]
        tool = Path(cmd[0].replace("\\", "/")).stem.lower()
        assert cmd[1] == "mcp"
        verb, name = cmd[2], (cmd[3] if cmd[2] == "remove" else None)
        if verb in self.fail_verbs:
            return SimpleNamespace(returncode=1, stdout="", stderr=f"{verb} broke")
        if tool == "claude":
            p = self.env.claude_json
            data = json.loads(p.read_text("utf-8")) if p.exists() else {}
            servers = data.setdefault("mcpServers", {})
            if verb == "remove":
                if name not in servers:
                    return SimpleNamespace(returncode=1, stdout="", stderr="No MCP server found")
                del servers[name]
                if self.touch_on_remove:
                    data["numStartups"] = data.get("numStartups", 0) + 1
            elif verb == "add-json":
                rest = cmd[3:]
                assert rest[:2] == ["--scope", "user"] and len(rest) == 4
                if rest[2] in servers:
                    return SimpleNamespace(returncode=1, stdout="", stderr="already exists")
                servers[rest[2]] = json.loads(rest[3])
            else:
                rest = cmd[3:]
                assert rest[0] == "--scope" and rest[1] == "user"
                name = rest[2]
                if name in servers:                      # the real `claude mcp add` refuses an existing name
                    return SimpleNamespace(returncode=1, stdout="", stderr=f"MCP server {name} already exists")
                i, env = 3, {}
                while rest[i] == "-e":
                    k, v = rest[i + 1].split("=", 1)
                    env[k] = v
                    i += 2
                assert rest[i] == "--"
                servers[name] = {"type": "stdio", "command": rest[i + 1], "args": rest[i + 2:], "env": env}
            p.write_text(json.dumps(data, indent=2), "utf-8")
        else:
            p = self.env.codex_toml
            p.parent.mkdir(parents=True, exist_ok=True)
            data = tomllib.loads(p.read_text("utf-8")) if p.exists() else {}
            servers = data.setdefault("mcp_servers", {})
            if verb == "remove":
                del servers[name]
            else:
                rest = cmd[3:]
                name, i, env = rest[0], 1, {}           # the real `codex mcp add` replaces an existing name in place
                while rest[i] == "--env":
                    k, v = rest[i + 1].split("=", 1)
                    env[k] = v
                    i += 2
                assert rest[i] == "--"
                servers[name] = {"command": rest[i + 1], "args": rest[i + 2:], **({"env": env} if env else {})}
            others = {k: v for k, v in data.items() if k != "mcp_servers"}
            text = "".join(f"{k} = {json.dumps(v)}\n" for k, v in others.items())
            for n, e in servers.items():
                text += "\n" + S.toml_block({"command": e["command"], "args": e["args"], "env": e.get("env")}).replace(
                    S.SERVER_NAME, n, 1) + "\n"
            p.write_text(text, "utf-8")
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    def main(self, *argv, rh=RH, engine=ENGINE):
        lines: list[str] = []
        rc = S.main(list(argv), env=self.env, engine_resolver=lambda requested: engine, rh_exe=rh, out=lines.append)
        return rc, "\n".join(lines)

    def files(self) -> dict[str, bytes]:
        return {str(p.relative_to(self.home)): p.read_bytes() for p in sorted(self.home.rglob("*")) if p.is_file()}

    def backups(self) -> list[Path]:
        return sorted(self.home.rglob("*.rh-backup-*"))


@pytest.fixture
def fake(tmp_path):
    return Fake(tmp_path)


@pytest.fixture(autouse=True)
def never_real_home(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("a test touched the real user environment")
    monkeypatch.setattr(S.SetupEnv, "system", classmethod(boom))
    monkeypatch.setattr(S, "resolve_engine", boom)
    monkeypatch.setattr(S, "find_rh_executable", boom)


# --------------------------------------------------------------------------------------------------------------------
def test_detection_follows_what_is_installed(tmp_path):
    f = Fake(tmp_path, cli=False)
    assert not any(S.detect_clients(f.env).values())
    (f.home / ".cursor").mkdir()
    (f.home / ".gemini").mkdir()
    (f.home / ".codex").mkdir()
    d = S.detect_clients(f.env)
    assert d == {"claude-code": False, "codex": True, "cursor": True, "gemini": True, "claude-desktop": False}
    f.env.which = lambda n: r"C:\bin\claude.exe" if n == "claude" else None
    assert S.detect_clients(f.env)["claude-code"]


def test_nothing_detected_is_reported(fake):
    fake.env.which = lambda n: None
    rc, out = fake.main()
    assert rc == 1 and "no supported AI client" in out and "--print" in out
    assert fake.files() == {}


def test_json_client_creates_merges_and_is_idempotent(fake):
    cfg = fake.home / ".cursor" / "mcp.json"
    cfg.parent.mkdir()
    other = {"theme": "dark", "mcpServers": {"other": {"command": "x", "args": ["a"]}}}
    cfg.write_text(json.dumps(other, indent=4) + "\n", "utf-8")
    original = cfg.read_bytes()

    rc, out = fake.main("--client", "cursor", "--no-skill")
    assert rc == 0 and "added" in out
    data = json.loads(cfg.read_text("utf-8"))
    assert data["theme"] == "dark" and data["mcpServers"]["other"] == other["mcpServers"]["other"]
    assert data["mcpServers"]["red-harness"] == {
        "command": RH, "args": ["mcp", "--engine", "ghidra"], "env": {"RH_GHIDRA_DIR": ENGINE[1]}}
    assert cfg.read_text("utf-8").startswith('{\n    "theme"')       # indentation of the user's file is kept
    (bak,) = fake.backups()
    assert bak.read_bytes() == original and bak.name.startswith("mcp.json.rh-backup-20260102-0304")

    before = fake.files()
    rc, out = fake.main("--client", "cursor", "--no-skill")
    assert rc == 0 and "unchanged" in out and "nothing to change" in out
    assert fake.files() == before                                   # no write, no second backup


def test_json_client_new_file_has_no_backup_and_update_replaces_only_our_entry(fake):
    cfg = fake.home / ".gemini" / "settings.json"
    assert fake.main("--client", "gemini", "--no-skill")[0] == 0
    assert json.loads(cfg.read_text("utf-8"))["mcpServers"]["red-harness"]["args"][-1] == "ghidra"
    assert fake.backups() == []                                     # nothing existed to back up
    rc, out = fake.main("--client", "gemini", "--no-skill", engine=("ida", r"C:\IDA", []))
    assert rc == 0 and "updated" in out
    assert json.loads(cfg.read_text("utf-8"))["mcpServers"]["red-harness"]["env"] == {"RH_IDA_DIR": r"C:\IDA"}
    assert len(fake.backups()) == 1


def test_invalid_json_is_never_overwritten(fake):
    cfg = fake.home / ".cursor" / "mcp.json"
    cfg.parent.mkdir()
    cfg.write_text('{"mcpServers": {  // comment\n}', "utf-8")
    before = fake.files()
    rc, out = fake.main("--client", "cursor", "--no-skill")
    assert rc == 1 and "not valid JSON" in out
    assert fake.files() == before


def test_uninstall_json_removes_only_our_entry(fake):
    cfg = fake.home / ".cursor" / "mcp.json"
    cfg.parent.mkdir()
    cfg.write_text(json.dumps({"mcpServers": {"other": {"command": "x"}}}), "utf-8")
    fake.main("--client", "cursor", "--no-skill")
    rc, out = fake.main("--client", "cursor", "--no-skill", "--uninstall")
    assert rc == 0 and "removed" in out
    assert json.loads(cfg.read_text("utf-8")) == {"mcpServers": {"other": {"command": "x"}}}
    rc, out = fake.main("--client", "cursor", "--no-skill", "--uninstall")
    assert rc == 0 and "absent" in out


def test_claude_desktop_prefers_store_build_folder_and_existing_config(fake):
    std = fake.home / "AppData" / "Roaming" / "Claude"
    msix = fake.home / "AppData" / "Local" / "Packages" / "Claude_abc123" / "LocalCache" / "Roaming" / "Claude"
    assert fake.env.desktop_config()[1] is False
    msix.mkdir(parents=True)
    assert fake.env.desktop_config() == (msix / "claude_desktop_config.json", True)
    std.mkdir(parents=True)
    (std / "claude_desktop_config.json").write_text("{}", "utf-8")
    assert fake.env.desktop_config() == (std / "claude_desktop_config.json", True)       # a real config wins
    assert fake.main("--client", "claude-desktop")[0] == 0
    assert "red-harness" in json.loads((std / "claude_desktop_config.json").read_text("utf-8"))["mcpServers"]
    assert not (msix / "claude_desktop_config.json").exists()


def test_claude_code_uses_its_cli(fake):
    p = fake.env.claude_json
    p.write_text(json.dumps({"numStartups": 3, "mcpServers": {"other": {"command": "x"}}}), "utf-8")
    rc, out = fake.main("--client", "claude-code", "--no-skill")
    assert rc == 0 and "added" in out
    (cmd,) = fake.calls
    assert cmd[:6] == [r"C:\bin\claude.exe", "mcp", "add", "--scope", "user", "red-harness"]
    assert cmd[6:] == ["-e", f"RH_GHIDRA_DIR={ENGINE[1]}", "--", RH, "mcp", "--engine", "ghidra"]
    data = json.loads(p.read_text("utf-8"))
    assert data["numStartups"] == 3 and "other" in data["mcpServers"] and "red-harness" in data["mcpServers"]
    assert len(fake.backups()) == 1

    fake.calls.clear()
    before = fake.files()
    rc, out = fake.main("--client", "claude-code", "--no-skill")
    assert rc == 0 and "unchanged" in out and fake.calls == [] and fake.files() == before

    rc, out = fake.main("--client", "claude-code", "--no-skill", engine=("ida", r"C:\IDA", []))
    assert rc == 0 and "updated" in out
    assert [c[2] for c in fake.calls] == ["remove", "add"]
    assert json.loads(p.read_text("utf-8"))["mcpServers"]["red-harness"]["args"][-1] == "ida"

    fake.calls.clear()
    rc, out = fake.main("--client", "claude-code", "--no-skill", "--uninstall")
    assert rc == 0 and [c[2] for c in fake.calls] == ["remove"]
    assert list(json.loads(p.read_text("utf-8"))["mcpServers"]) == ["other"]


def test_codex_uses_its_cli_and_keeps_other_settings(fake):
    p = fake.env.codex_toml
    p.parent.mkdir()
    p.write_text('model = "x"\n', "utf-8")
    rc, out = fake.main("--client", "codex", "--no-skill")
    assert rc == 0 and fake.calls[0][:4] == [r"C:\bin\codex.cmd", "mcp", "add", "red-harness"]
    data = tomllib.loads(p.read_text("utf-8"))
    assert data["model"] == "x"
    assert data["mcp_servers"]["red-harness"] == {"command": RH, "args": ["mcp", "--engine", "ghidra"],
                                                  "env": {"RH_GHIDRA_DIR": ENGINE[1]}}
    fake.calls.clear()
    assert "unchanged" in fake.main("--client", "codex", "--no-skill")[1] and fake.calls == []
    rc, _ = fake.main("--client", "codex", "--no-skill", "--uninstall")
    assert rc == 0 and "red-harness" not in tomllib.loads(p.read_text("utf-8")).get("mcp_servers", {})


def test_cli_failure_is_reported_not_swallowed(fake):
    fake.env.claude_json.write_text("{}", "utf-8")
    fake.fail_next = True
    rc, out = fake.main("--client", "claude-code", "--no-skill")
    assert rc == 1 and "failed" in out and "boom" in out


def test_missing_cli_is_skipped_and_explicit_request_fails(tmp_path):
    f = Fake(tmp_path, cli=False)
    (f.home / ".codex").mkdir()
    rc, out = f.main("--client", "codex", "--no-skill")
    assert rc == 1 and "skipped" in out and "--print" in out
    assert not f.env.codex_toml.exists()
    rc, out = f.main("--no-skill")                                  # auto-detected only: not an error
    assert rc == 0 and "skipped" in out


def test_dry_run_writes_nothing_and_shows_the_diff(fake):
    cfg = fake.home / ".cursor" / "mcp.json"
    cfg.parent.mkdir()
    cfg.write_text(json.dumps({"mcpServers": {"other": {"command": "x"}}}, indent=2), "utf-8")
    fake.env.claude_json.write_text("{}", "utf-8")
    before = fake.files()
    rc, out = fake.main("--dry-run", "--client", "cursor,claude-code")
    assert rc == 0 and fake.files() == before and fake.calls == []
    assert "would add" in out and '+    "red-harness": {' in out and "claude.exe mcp add" in out
    assert "would create" in out and "SKILL.md" in out and "nothing was written" in out


def test_skill_install_update_uninstall(fake):
    rc, out = fake.main("--client", "claude-code,codex,gemini", "--dry-run")
    assert out.count("skill would create") == 2                      # codex and gemini share one folder
    fake.env.claude_json.write_text("{}", "utf-8")
    (fake.home / ".gemini").mkdir()
    assert fake.main("--client", "claude-code,codex,gemini")[0] == 0
    a = fake.home / ".claude" / "skills" / "red-harness" / "SKILL.md"
    b = fake.home / ".agents" / "skills" / "red-harness" / "SKILL.md"
    assert a.read_bytes() == b.read_bytes() == S.read_skill()

    b.write_bytes(S.read_skill().replace(b"Before you start", b"Edited by the user"))
    n = len(fake.backups())
    rc, out = fake.main("--client", "codex")
    assert rc == 0 and "updated" in out and b.read_bytes() == S.read_skill()
    assert len(fake.backups()) == n + 1
    assert b"Edited by the user" in [x for x in fake.backups() if "agents" in str(x)][0].read_bytes()

    fake.main("--client", "claude-code,codex", "--uninstall")
    assert not a.exists() and not b.exists()


def test_uninstall_leaves_a_foreign_skill_alone(fake):
    mine = fake.home / ".agents" / "skills" / "red-harness" / "SKILL.md"
    mine.parent.mkdir(parents=True)
    mine.write_text("---\nname: something-else\ndescription: x\n---\n", "utf-8")
    (fake.home / ".codex").mkdir()
    fake.env.which = lambda n: None
    rc, out = fake.main("--client", "codex", "--uninstall")
    assert mine.exists() and "not ours" in out


def test_print_only_touches_nothing(fake):
    before = fake.files()
    rc, out = fake.main("--print")
    assert rc == 0 and fake.files() == before and fake.calls == []
    for needle in ("claude mcp add", "codex mcp add", "[mcp_servers.red-harness]", "mcp.json", "settings.json",
                   "claude_desktop_config.json", '"mcpServers"', "Skill: copy"):
        assert needle in out, needle
    rc, out = fake.main("--print", "--client", "cursor")
    assert "claude mcp add" not in out and '"command"' in out


def test_print_toml_snippet_parses(fake):
    entry = S.build_entry(RH, "ghidra", r"C:\Tools\ghidra 12", {"RH_DATA_ROOT": r"D:\data"})
    parsed = tomllib.loads(S.toml_block(entry))["mcp_servers"]["red-harness"]
    assert parsed == entry


def test_argument_errors(fake):
    assert fake.main("--print", "--dry-run")[0] == 2
    assert fake.main("--print", "--uninstall")[0] == 2
    assert fake.main("--bogus")[0] == 2
    rc, out = fake.main("--client", "vscode")
    assert rc == 1 and "unknown client" in out
    assert fake.main("--help")[0] == 0


def test_entry_carries_data_root_only_when_set():
    assert "env" not in S.build_entry(RH, "ghidra", None, {})
    e = S.build_entry(RH, "ida", r"C:\IDA", {"RH_DATA_ROOT": r"D:\d"})
    assert e["env"] == {"RH_IDA_DIR": r"C:\IDA", "RH_DATA_ROOT": r"D:\d"}


def test_claude_config_dir_and_codex_home_are_honoured(tmp_path):
    f = Fake(tmp_path, environ={"CLAUDE_CONFIG_DIR": str(tmp_path / "cc"), "CODEX_HOME": str(tmp_path / "cx")})
    assert f.env.claude_json == tmp_path / "cc" / ".claude.json"
    assert S.skill_destinations("claude-code", f.env) == tmp_path / "cc" / "skills" / "red-harness" / "SKILL.md"
    assert f.env.codex_toml == tmp_path / "cx" / "config.toml"


# --------------------------------------------------------------------------------------------------------------------
# batch shims (.cmd/.bat run through cmd.exe, which re-parses the arguments)
# --------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("ch", list('"%!^&|<>()') + ["\n", "\r"])
def test_metacharacters_never_reach_an_unresolvable_batch_shim(fake, ch):
    # C:\bin\codex.cmd does not exist, so it cannot be resolved to the program behind it
    rc, out = fake.main("--client", "codex", "--no-skill", engine=("ghidra", rf"C:\Tools\gh{ch}idra", []))
    assert rc == 1 and "skipped" in out and "batch file" in out and "--print" in out
    assert fake.calls == [] and not fake.env.codex_toml.exists()
    rc, out = fake.main("--client", "codex", "--no-skill", rh=rf"C:\x{ch}y\rh.exe")
    assert rc == 1 and fake.calls == []


def test_default_runner_refuses_metacharacters_for_a_batch_file():
    with pytest.raises(S.SetupError, match="metacharacters"):
        S._default_run([r"C:\nowhere\codex.cmd", "mcp", "add", "x", "--", r"C:\a&b\rh.exe"])
    with pytest.raises(S.SetupError):
        S._default_run([r"C:\nowhere\claude.BAT", "mcp", "add", "100%"])


_NEW_SHIM = """@ECHO off\r\nGOTO start\r\n:find_dp0\r\nSET dp0=%~dp0\r\nEXIT /b\r\n:start\r\nSETLOCAL\r\nCALL :find_dp0\r\n
IF EXIST "%dp0%\\node.exe" (\r\n  SET "_prog=%dp0%\\node.exe"\r\n) ELSE (\r\n  SET "_prog=node"\r\n)\r\n
endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & "%_prog%"  "%dp0%\\node_modules\\@acme\\tool\\bin\\{name}.js" %*\r\n"""
_OLD_SHIM = """@IF EXIST "%~dp0\\node.exe" (\r\n  "%~dp0\\node.exe"  "%~dp0\\node_modules\\acme-tool\\cli.js" %*\r\n) ELSE (\r\n
  node  "%~dp0\\node_modules\\acme-tool\\cli.js" %*\r\n)\r\n"""
_EXE_SHIM = """@ECHO off\r\n"%~dp0\\node_modules\\acme-tool\\bin\\{name}.exe"   %*\r\n"""


def _shim(tmp: Path, name: str, body: str, files: list[str]) -> Path:
    d = tmp / "npm"
    d.mkdir(parents=True, exist_ok=True)
    for f in files:
        (d / f).parent.mkdir(parents=True, exist_ok=True)
        (d / f).write_bytes(b"")
    (d / f"{name}.cmd").write_text(body.replace("{name}", name), "utf-8")
    return d / f"{name}.cmd"


def test_npm_shim_is_resolved_to_node_and_its_script(tmp_path):
    shim = _shim(tmp_path, "codex", _NEW_SHIM, ["node.exe", "node_modules/@acme/tool/bin/codex.js"])
    f = Fake(tmp_path)
    assert S.resolve_launcher(str(shim), f.env) == [str(shim.parent / "node.exe"),
                                                    str(shim.parent / "node_modules" / "@acme" / "tool" / "bin" / "codex.js")]
    f.env.which = lambda n: str(shim) if n == "codex" else None
    hostile = r"C:\Tools\g&h %PATH% (x) ^!\"idra"
    rc, out = f.main("--client", "codex", "--no-skill", engine=("ghidra", hostile, []))
    assert rc == 0, out
    (cmd,) = f.calls
    assert not S._is_batch(cmd[0]) and cmd[0].endswith("node.exe") and cmd[1].endswith("codex.js")
    assert f"RH_GHIDRA_DIR={hostile}" in cmd                         # passed verbatim, never through cmd.exe
    assert tomllib.loads(f.env.codex_toml.read_text("utf-8"))["mcp_servers"]["red-harness"]["env"] == {
        "RH_GHIDRA_DIR": hostile}


def test_other_shim_layouts(tmp_path):
    f = Fake(tmp_path)
    old = _shim(tmp_path / "a", "claude", _OLD_SHIM, ["node_modules/acme-tool/cli.js"])
    node = tmp_path / "nodejs" / "node.exe"
    node.parent.mkdir()
    node.write_bytes(b"")
    f.env.which = lambda n: str(node) if n == "node" else None       # no node.exe next to the shim: node from PATH
    assert S.resolve_launcher(str(old), f.env) == [str(node), str(old.parent / "node_modules" / "acme-tool" / "cli.js")]
    f.env.which = lambda n: str(tmp_path / "nodejs" / "node.cmd") if n == "node" else None
    assert S.resolve_launcher(str(old), f.env) == [str(old)]          # node is itself a batch file: not resolved
    native = _shim(tmp_path / "b", "claude", _EXE_SHIM, ["node_modules/acme-tool/bin/claude.exe"])
    assert S.resolve_launcher(str(native), f.env) == [str(native.parent / "node_modules" / "acme-tool" / "bin" /
                                                          "claude.exe")]
    escape = _shim(tmp_path / "c", "claude", '"%~dp0\\..\\evil.exe" %*', [])
    (tmp_path / "c" / "evil.exe").write_bytes(b"")
    assert S.resolve_launcher(str(escape), f.env) == [str(escape)]    # never leaves the shim's folder
    assert S.resolve_launcher(r"C:\bin\claude.exe", f.env) == [r"C:\bin\claude.exe"]


# --------------------------------------------------------------------------------------------------------------------
# updates never lose the previous entry
# --------------------------------------------------------------------------------------------------------------------
def _claude_entry(fake):
    return json.loads(fake.env.claude_json.read_text("utf-8"))["mcpServers"].get("red-harness")


def test_claude_failed_add_restores_the_previous_entry_with_its_cli(fake):
    fake.env.claude_json.write_text(json.dumps({"numStartups": 1}), "utf-8")
    assert fake.main("--client", "claude-code", "--no-skill")[0] == 0
    before = _claude_entry(fake)
    fake.calls.clear()
    fake.fail_verbs = {"add"}
    rc, out = fake.main("--client", "claude-code", "--no-skill", engine=("ida", r"C:\IDA", []))
    assert rc == 1 and "update failed" in out and "add broke" in out and "restored with `claude mcp add-json`" in out
    assert [c[2] for c in fake.calls] == ["remove", "add", "add-json"]
    assert _claude_entry(fake) == before


def test_claude_failed_add_falls_back_to_the_backup(fake):
    fake.env.claude_json.write_text(json.dumps({"numStartups": 1, "mcpServers": {"other": {"command": "x"}}}), "utf-8")
    assert fake.main("--client", "claude-code", "--no-skill")[0] == 0
    before = fake.env.claude_json.read_bytes()
    fake.fail_verbs = {"add", "add-json"}
    rc, out = fake.main("--client", "claude-code", "--no-skill", engine=("ida", r"C:\IDA", []))
    assert rc == 1 and "restored from the backup" in out
    assert fake.env.claude_json.read_bytes() == before


def test_claude_failed_add_never_restores_a_backup_over_newer_changes(fake):
    fake.env.claude_json.write_text(json.dumps({"numStartups": 1}), "utf-8")
    assert fake.main("--client", "claude-code", "--no-skill")[0] == 0
    fake.fail_verbs = {"add", "add-json"}
    fake.touch_on_remove = True                                      # the client wrote the file in between
    rc, out = fake.main("--client", "claude-code", "--no-skill", engine=("ida", r"C:\IDA", []))
    assert rc == 1 and "could NOT be restored" in out and r"C:\\Tools\\redharness" in out and "backup:" in out
    data = json.loads(fake.env.claude_json.read_text("utf-8"))
    assert data["numStartups"] == 2 and "red-harness" not in data["mcpServers"]


def test_codex_update_is_a_single_add_and_a_failed_add_keeps_the_entry(fake):
    assert fake.main("--client", "codex", "--no-skill")[0] == 0
    fake.calls.clear()
    rc, out = fake.main("--client", "codex", "--no-skill", engine=("ida", r"C:\IDA", []))
    assert rc == 0 and [c[2] for c in fake.calls] == ["add"]
    before = fake.env.codex_toml.read_bytes()
    fake.fail_verbs = {"add"}
    rc, out = fake.main("--client", "codex", "--no-skill")
    assert rc == 1 and "update failed" in out and "still in place" in out
    assert fake.env.codex_toml.read_bytes() == before


# --------------------------------------------------------------------------------------------------------------------
# ownership: only entries and skill files that are ours are replaced or removed
# --------------------------------------------------------------------------------------------------------------------
FOREIGN = {"command": "node", "args": ["C:/elsewhere/server.js"]}


def test_foreign_json_entry_is_left_alone_unless_forced(fake):
    cfg = fake.home / ".cursor" / "mcp.json"
    cfg.parent.mkdir()
    cfg.write_text(json.dumps({"mcpServers": {"red-harness": FOREIGN}}), "utf-8")
    before = fake.files()
    for args in (("--client", "cursor", "--no-skill"), ("--client", "cursor", "--no-skill", "--uninstall")):
        rc, out = fake.main(*args)
        assert rc == 1 and "does not run `rh mcp`" in out and "--force" in out
        assert fake.files() == before
    assert fake.main("--client", "cursor", "--no-skill", "--force")[0] == 0
    assert json.loads(cfg.read_text("utf-8"))["mcpServers"]["red-harness"]["command"] == RH
    assert fake.main("--client", "cursor", "--no-skill", "--uninstall")[0] == 0     # now ours: no --force needed


def test_foreign_cli_entry_is_left_alone_unless_forced(fake):
    fake.env.claude_json.write_text(json.dumps({"mcpServers": {"red-harness": FOREIGN}}), "utf-8")
    rc, out = fake.main("--client", "claude-code", "--no-skill", "--uninstall")
    assert rc == 1 and "does not run `rh mcp`" in out and fake.calls == []
    rc, out = fake.main("--client", "claude-code", "--no-skill", "--uninstall", "--force")
    assert rc == 0 and [c[2] for c in fake.calls] == ["remove"]


def test_entry_ownership_rule():
    assert S.is_our_entry({"command": RH, "args": ["mcp", "--engine", "ida"]})
    assert S.is_our_entry({"command": "/opt/venv/bin/rh", "args": ["mcp"]})
    for other in (FOREIGN, {"command": RH, "args": ["studio"]}, {"command": RH}, {"command": "rhx.exe", "args": ["mcp"]},
                  "rh mcp", None):
        assert not S.is_our_entry(other), other


def test_uninstall_keeps_an_edited_skill_unless_forced(fake):
    (fake.home / ".gemini").mkdir()
    assert fake.main("--client", "gemini")[0] == 0
    skill = fake.home / ".agents" / "skills" / "red-harness" / "SKILL.md"
    skill.write_bytes(S.read_skill() + b"\nmy own notes\n")
    rc, out = fake.main("--client", "gemini", "--uninstall")
    assert skill.exists() and "differs from every version" in out
    rc, out = fake.main("--client", "gemini", "--uninstall", "--force")
    assert rc == 0 and not skill.exists()
    assert any(b"my own notes" in b.read_bytes() for b in fake.backups())


def test_shipped_skill_with_crlf_line_endings_is_still_ours(fake):
    (fake.home / ".gemini").mkdir()
    skill = fake.home / ".agents" / "skills" / "red-harness" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_bytes(S.read_skill().replace(b"\n", b"\r\n"))
    assert fake.main("--client", "gemini", "--uninstall")[0] == 0 and not skill.exists()


# --------------------------------------------------------------------------------------------------------------------
# writes and reads
# --------------------------------------------------------------------------------------------------------------------
def test_atomic_write_uses_a_fresh_temp_file(tmp_path):
    target = tmp_path / "mcp.json"
    stale = tmp_path / "mcp.json.rh-tmp"
    stale.write_bytes(b"someone else's file")
    S._atomic_write(target, b"{}\n")
    assert target.read_bytes() == b"{}\n" and stale.read_bytes() == b"someone else's file"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["mcp.json", "mcp.json.rh-tmp"]


def test_atomic_write_cleans_up_and_keeps_the_target_on_failure(tmp_path, monkeypatch):
    target = tmp_path / "mcp.json"
    target.write_bytes(b"original")

    def broken(src, dst):
        raise OSError("disk full")
    monkeypatch.setattr(S.os, "replace", broken)
    with pytest.raises(OSError):
        S._atomic_write(target, b"new")
    assert target.read_bytes() == b"original" and [p.name for p in tmp_path.iterdir()] == ["mcp.json"]


def test_backup_never_overwrites_an_existing_file(fake):
    cfg = fake.home / "c.json"
    cfg.write_bytes(b"v1")
    taken = cfg.with_name("c.json.rh-backup-20260102-030401")
    taken.write_bytes(b"older backup")
    fake.env.now = lambda: datetime(2026, 1, 2, 3, 4, 1)
    dest = Path(S._backup(cfg, fake.env))
    assert dest.name == "c.json.rh-backup-20260102-030401-2" and dest.read_bytes() == b"v1"
    assert taken.read_bytes() == b"older backup"


def test_oversized_config_files_are_refused(fake, monkeypatch):
    monkeypatch.setattr(S, "MAX_CONFIG_BYTES", 64)
    cfg = fake.home / ".cursor" / "mcp.json"
    cfg.parent.mkdir()
    cfg.write_text(json.dumps({"mcpServers": {}, "pad": "x" * 100}), "utf-8")
    fake.env.claude_json.write_text(json.dumps({"pad": "x" * 100}), "utf-8")
    before = fake.files()
    rc, out = fake.main("--client", "cursor,claude-code", "--no-skill")
    assert rc == 1 and out.count("larger than") == 2 and fake.calls == [] and fake.files() == before


def test_cli_dispatch_goes_through_setup(monkeypatch, capsys):
    from redharness.cli import main as cli_main
    assert cli_main(["setup", "--help"]) == 0
    assert "rh setup" in capsys.readouterr().out
    assert "setup" in cli_main.__globals__["HELP"]


# --------------------------------------------------------------------------------------------------------------------
# the packaged skill
# --------------------------------------------------------------------------------------------------------------------
def _frontmatter(text: str) -> dict:
    assert text.startswith("---\n")
    head = text.split("\n---\n", 1)[0].splitlines()[1:]
    return dict(line.split(": ", 1) for line in head)


def test_skill_is_packaged_and_well_formed():
    text = S.read_skill().decode("utf-8")
    fm = _frontmatter(text)
    assert fm["name"] == "red-harness"
    assert len(fm["description"]) < 1024 and "reverse engineer" in fm["description"]
    for needle in ("target_open", "SHA-256", "claim_add", "evidence", "unknown_record", "coverage", "report_build",
                   "run_controlled", "untrusted", "never \"clean\"", "scope manifest"):
        assert needle in text, needle


def test_skill_names_only_real_core_tools():
    from redharness.mcp.server import TOOL_NAMES
    import re
    text = S.read_skill().decode("utf-8")
    core = set(TOOL_NAMES) - {"captured_region"}
    named = set(re.findall(r"`([a-z_]+)(?:\(|`)", text)) & set(TOOL_NAMES)
    assert named <= core
    for banned in ("captured_region", "dynamic_observe", "dynamic_memory", "observe="):
        assert banned not in text
    assert {"target_open", "claim_add", "report_build", "coverage", "unknown_record"} <= named


def test_packaged_skill_hash_is_in_the_shipped_list():
    # changing skill/SKILL.md needs its new sha256 in SHIPPED_SKILL_SHA256, or --uninstall would keep it as "edited"
    assert S.skill_digest(S.read_skill()) in S.SHIPPED_SKILL_SHA256


def test_skill_file_is_declared_as_package_data():
    root = Path(__file__).resolve().parents[2]
    assert '"redharness.skill" = ["SKILL.md"]' in (root / "pyproject.toml").read_text("utf-8")
    assert (root / "src" / "redharness" / "skill" / "__init__.py").is_file()
