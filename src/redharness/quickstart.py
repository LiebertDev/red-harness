"""`rh quickstart <binary>`: a first evidence-backed result in a few minutes, with no model and no API key.

  rh quickstart <binary> [--engine ghidra|ida] [--data-root DIR] [--basis owner|authorized-test]

What it does, in order:
  1. checks the prerequisites (Python version, which engine is usable) and picks the engine: Ghidra if it works,
     else IDA (`--engine` forces one; there is no silent fallback in that case);
  2. writes a minimal scope manifest for the file (SHA-256 computed here; static analysis only; it states that the
     file is one the user owns or is authorized to analyse);
  3. runs a small fixed static pass through the SAME code path as the MCP tools (`Hub.call`, which the MCP server
     uses for every tool call): target_open (with the PE profile and protection diagnosis), functions_list,
     imports, strings;
  4. records two example observation claims that quote real evidence; the verifier sets their status;
  5. builds the report and prints where it is, a short summary and the next step (connecting an MCP client).

Nothing here executes the target, and the target is only read.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import __version__
from .config import Config
from .engines.base import Engine
from .scope.manifest import SCOPE_SCHEMA, sha256_file

MIN_PYTHON = (3, 12)
ENGINE_ORDER = ("ghidra", "ida")
DECLARED_BY = "rh quickstart (the user who ran this command)"
STATEMENT = ("Written automatically by `rh quickstart` for one file. By running the command the user declares that "
             "this file is theirs or that they are authorized to analyse it. Static analysis only: nothing is "
             "executed.")

_STRING_LINE = re.compile(r"^(0x[0-9a-fA-F]+) \S+ \S+ (.{6,60})$", re.M)
_IMPORT_LINE = re.compile(r"^(0x[0-9a-fA-F]+) ([^\s!]+![^\s]+)$", re.M)
_PLAIN_VALUE = re.compile(r"[A-Za-z0-9 ._:\\/()\-]{6,60}")


class QuickstartError(Exception):
    """A step failed in a way the user can act on; the message is printed as is."""


# --------------------------------------------------------------------------------------------------------------------
# prerequisites and engine selection
# --------------------------------------------------------------------------------------------------------------------
def write_manifest(target: Path, dest_dir: Path, *, basis: str = "authorized-test") -> tuple[Path, str]:
    """Writes `<dest_dir>/scope.json` for `target` (rh.scope/1, operations: static only). Returns (path, sha256)."""
    if basis not in ("owner", "authorized-test"):
        raise QuickstartError("--basis must be 'owner' or 'authorized-test'")
    if not target.is_file():
        raise QuickstartError(f"target file not found: {target}")
    sha = sha256_file(target)
    doc = {"schema": SCOPE_SCHEMA, "target_sha256": sha,
           "authorization": {"declared_by": DECLARED_BY, "basis": basis, "statement": STATEMENT},
           "allowed_operations": ["static"]}
    dest_dir.mkdir(parents=True, exist_ok=True)
    path = dest_dir / "scope.json"
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return path, sha


def select_engine(config: Config, requested: str | None,
                  make: Callable[[str, Config], Engine] | None = None) -> tuple[Engine | None, str, list[str]]:
    """(engine, name, notes). With `requested` only that engine is tried; otherwise Ghidra, then IDA. `notes` has one
    line per engine that was tried and failed (the reason a user needs)."""
    from .mcp.server import EngineSelectionError, make_engine, normalize_engine_name
    make = make or make_engine
    try:
        order = (normalize_engine_name(requested),) if requested else ENGINE_ORDER
    except EngineSelectionError as e:
        raise QuickstartError(str(e)) from e
    notes: list[str] = []
    for name in order:
        try:
            return make(name, config), name, notes
        except EngineSelectionError as e:
            notes.append(f"{name}: {e}")
        except Exception as e:  # noqa: BLE001 - a probe must never crash the prerequisite check
            notes.append(f"{name}: probe failed ({e!r})")
    return None, "", notes


def _engine_dir(name: str) -> str | None:
    """Install folder of the engine, for the MCP snippet. Best effort, never raises."""
    try:
        if name == "ghidra":
            from .engines.ghidra.backend import discover_ghidra_dir
            d = discover_ghidra_dir()
            return str(d) if d else None
        from .engines.ida.backend import discover_ida_install
        i = discover_ida_install()
        return str(i.path) if i else None
    except Exception:  # noqa: BLE001
        return None


def mcp_snippet(engine_name: str, data_root: Path, engine_dir: str | None, rh_exe: str | None = None) -> dict:
    """A ready-to-use `.mcp.json` (Claude Code / most MCP clients) with this machine's real paths."""
    exe = rh_exe or _rh_executable()
    env: dict[str, str] = {}
    if engine_dir:
        env["RH_GHIDRA_DIR" if engine_name == "ghidra" else "RH_IDA_DIR"] = engine_dir
    env["RH_DATA_ROOT"] = str(data_root)
    return {"mcpServers": {"red-harness": {"type": "stdio", "command": exe, "args": ["mcp", "--engine", engine_name],
                                           "env": env}}}


def _rh_executable() -> str:
    here = Path(sys.executable).parent
    for cand in (here / "rh.exe", here / "rh", here / "Scripts" / "rh.exe"):
        if cand.is_file():
            return str(cand)
    return shutil.which("rh") or "rh"


# --------------------------------------------------------------------------------------------------------------------
# the static pass
# --------------------------------------------------------------------------------------------------------------------
@dataclass
class Outcome:
    ok: bool
    report_path: str = ""
    summary: list[str] = field(default_factory=list)
    timings: dict[str, float] = field(default_factory=dict)
    claims: list[dict] = field(default_factory=list)
    counts: dict = field(default_factory=dict)
    job_id: str = ""
    sha256: str = ""


def _call(hub: Any, name: str, **args: Any) -> dict:
    """The MCP server's own dispatch (`Hub.call`: effect table, scope manifest, journal), minus the transport."""
    return hub.call(name, args, lambda: getattr(hub, name)(**args))


def _pick_import(content: str) -> tuple[str, str] | None:
    """The first import that has a name (an ordinal import `dll!#12` says little)."""
    for m in _IMPORT_LINE.finditer(content):
        if "!#" not in m.group(2):
            return m.group(1), m.group(2)
    return None


def _pe_profile_line(lines: list[str]) -> str:
    """One readable line from the `pe_profile ...` evidence lines (format, machine, subsystem, sections, mitigations)."""
    def field(rx: str) -> str:
        m = next((re.search(rx, ln) for ln in lines if re.search(rx, ln)), None)
        return m.group(1) if m else ""
    fmt, mach, sub = field(r"format=(\S+)"), field(r"machine=([^\s(]+)"), field(r"subsystem=([^\s(]+)")
    nsec = sum(1 for ln in lines if " section[" in ln)
    flags = " ".join(f"{k}={field(k + r'=(\w+)')}" for k in ("aslr", "dep", "cfg") if field(k + r"=(\w+)"))
    return " ".join(x for x in (fmt, mach, sub, f"{nsec} sections" if nsec else "", flags) if x) or "not available"


def _string_candidates(content: str) -> list[tuple[str, str]]:
    out = []
    for m in _STRING_LINE.finditer(content):
        value = m.group(2).strip()
        if _PLAIN_VALUE.fullmatch(value) and sum(c.isalpha() for c in value) >= 5:
            out.append((m.group(1), value))
    return out


def run_pass(target: Path, manifest: Path, hub: Any, say: Callable[[str], None]) -> Outcome:
    """The fixed static pass. `hub` is a `redharness.mcp.session.Hub` (a fake engine in tests). Raises ToolFailure."""
    t: dict[str, float] = {}

    def timed(label: str, fn: Callable[[], Any]) -> Any:
        t0 = time.monotonic()
        try:
            return fn()
        finally:
            t[label] = time.monotonic() - t0

    o = timed("target_open", lambda: _call(hub, "target_open", target_path=str(target), manifest_path=str(manifest)))
    tgt, prot = o["target"], o["target"]["protection"]
    say(f"  target_open     {tgt['arch']} {tgt['bits']}-bit, {tgt['function_count']} functions, "
        f"{tgt['string_count']} strings, protection {prot['diagnosis']} ({t['target_open']:.0f}s)")

    f = timed("functions_list", lambda: _call(hub, "functions_list", limit=200, detail="summary"))
    say(f"  functions_list  {f['result']['total']} functions, evidence {f['evidence_id'][:19]}")

    imp = timed("imports", lambda: _call(hub, "imports", limit=1000, detail="full"))
    imp_lines = _IMPORT_LINE.findall(imp.get("content", ""))
    dlls = sorted({sym.split("!", 1)[0].lower() for _, sym in imp_lines})
    say(f"  imports         {imp['result']['total']} symbols from {len(dlls)}{'+' if imp['result']['next_offset'] else ''} DLLs, "
        f"evidence {imp['evidence_id'][:19]}")

    s = timed("strings", lambda: _call(hub, "strings", limit=100, detail="full"))
    say(f"  strings         {s['result']['returned']} of {s['result']['total']} returned, evidence {s['evidence_id'][:19]}")

    claims: list[dict] = []

    def add(text: str, ev: str, quote: str, addr: str) -> dict:
        c = _call(hub, "claim_add", kind="observation", requested="SUPPORTED", text=text, evidence_ids=[ev],
                  atoms=[{"type": "quote", "evidence_id": ev, "text": quote},
                         {"type": "address", "evidence_id": ev, "value": addr}])
        return {"text": text, "status": c.get("status"), "claim_id": c.get("claim_id"), "evidence_id": ev}

    pick = _pick_import(imp.get("content", ""))
    if pick:
        addr, sym = pick
        claims.append(add(f"The target imports {sym} at {addr}.", imp["evidence_id"], sym, addr))
    for addr, value in _string_candidates(s.get("content", ""))[:3]:
        c = add(f"The target contains the string {value} at {addr}.", s["evidence_id"], value, addr)
        claims.append(c)
        if c["status"] in ("SUPPORTED", "PROVEN"):
            break
    for c in claims:
        say(f"  claim_add       {c['status']}: {c['text']}")
    if not claims:
        say("  claim_add       skipped (no import or string line to quote)")

    cov = timed("coverage", lambda: _call(hub, "coverage"))
    r = timed("report_build", lambda: _call(hub, "report_build"))
    counts = r["counts"]
    verified = sum(1 for c in claims if c["status"] in ("SUPPORTED", "PROVEN"))
    summary = [
        f"target     {target.name}, entry {tgt['entry']}, sha256 {o['target_sha256'][:16]}...",
        f"engine     {o['engine']['name']} {o['engine']['version']} (analysis {'reused from cache' if o['engine']['analysis_cached'] else 'run now'}, open took {t['target_open']:.0f}s)",
        f"pe profile {_pe_profile_line(prot.get('pe_profile', {}).get('lines', []))}",
        f"contents   {f['result']['total']} functions, {imp['result']['total']} import symbols from {len(dlls)}{'+' if imp['result']['next_offset'] else ''} DLLs, {s['result']['total']} strings",
        f"protection {prot['diagnosis']} (heuristic, a hint and not proof; nothing was unpacked or run)",
        f"claims     {len(claims)} recorded, {verified} verified by the claim verifier",
        f"report     {counts['findings']} findings, {counts['hypotheses']} hypotheses, "
        f"{counts['unsupported_claims']} unsupported claims in findings (must be 0)",
        f"coverage   {cov['assessment']}; not 'clean': functions listed {f['result']['returned']}/{f['result']['total']}, "
        f"strings {s['result']['returned']}/{s['result']['total']}, nothing decompiled",
        f"job        {o['job_id']}",
    ]
    return Outcome(True, r["report_path"], summary, t, claims, counts, o["job_id"], o["target_sha256"])


# --------------------------------------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------------------------------------
USAGE = """usage: rh quickstart <binary> [--engine ghidra|ida] [--data-root DIR] [--basis owner|authorized-test]

A first evidence-backed result in a few minutes, no model and no API key: checks the prerequisites, writes a scope
manifest for the file, opens it with the first usable engine (Ghidra, else IDA), runs a small static pass (target_open
with the PE profile, functions, imports, strings), records two example claims that quote real evidence, builds the report
and tells you how to connect an MCP client. Use a file you own or are authorized to analyse. The target is never run."""


def main(argv: list[str], *, make_engine_fn: Callable[[str, Config], Engine] | None = None,
         out: Callable[[str], None] | None = None) -> int:
    say = out or (lambda s: print(s, flush=True))
    ap = argparse.ArgumentParser(prog="rh quickstart", usage=USAGE, add_help=False)
    ap.add_argument("target", nargs="?")
    ap.add_argument("--engine", default=None)
    ap.add_argument("--data-root", default=None)
    ap.add_argument("--basis", default="authorized-test")
    ap.add_argument("-h", "--help", action="store_true")
    try:
        a, extra = ap.parse_known_args(argv)
    except SystemExit:
        print(USAGE, file=sys.stderr)
        return 2
    if a.help:
        print(USAGE)
        return 0
    if not a.target or extra:
        print(USAGE, file=sys.stderr)
        return 2
    t_start = time.monotonic()
    target = Path(a.target).expanduser()
    try:
        say(f"Red Harness {__version__} quickstart")
        say("Prerequisites")
        v = sys.version_info
        if (v.major, v.minor) < MIN_PYTHON:
            raise QuickstartError(f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer is required (this is {v.major}.{v.minor})")
        say(f"  python   {v.major}.{v.minor}.{v.micro} ok")
        config = Config.load(a.data_root)
        say(f"  data     {config.data_root}")
        engine, name, notes = select_engine(config, a.engine, make_engine_fn)
        for n in notes:
            say(f"  engine   not usable: {n}")
        if engine is None:
            raise QuickstartError(
                "no analysis engine is usable. Install Ghidra (free) and a JDK 21, then set RH_GHIDRA_DIR: "
                "`rh deps show ghidra` explains how. IDA Pro is the alternative (`rh deps show ida`).")
        info = engine.probe()
        say(f"  engine   {name} {info.version} selected")
        if not target.is_file():
            raise QuickstartError(f"target file not found: {target}")

        qdir = config.data_root / "quickstart"
        manifest, sha = write_manifest(target, qdir / sha256_file(target)[:16], basis=a.basis)
        say("Scope")
        say(f"  manifest {manifest}")
        say(f"  sha256   {sha}")
        say("  This manifest is for a file you own or are authorized to analyse; it allows static analysis only.")

        say(f"Static pass with {name} (the first open analyses the whole binary once; a cached result is reused later)")
        from .mcp.session import Hub, ToolFailure
        hub = Hub(config, engine)
        try:
            res = run_pass(target, manifest, hub, say)
        except ToolFailure as e:
            raise QuickstartError(f"{e.code}: {e.message}") from e
        finally:
            hub.close()
    except QuickstartError as e:
        print(f"rh quickstart: {e}", file=sys.stderr)
        return 1

    total = time.monotonic() - t_start
    say("")
    say("Summary")
    for line in res.summary:
        say(f"  {line}")
    say("")
    say(f"Report: {res.report_path}")
    say(f"Total time: {total:.0f}s")
    say("")
    snippet = mcp_snippet(name, config.data_root, _engine_dir(name))
    mcp_json = manifest.parent / "mcp.json"
    mcp_json.write_text(json.dumps(snippet, indent=2) + "\n", encoding="utf-8")
    say("Next step: let a model drive the same tools. Copy this file to .mcp.json in your project folder")
    say(f"  {mcp_json}")
    say("start Claude Code (or another MCP client) there and approve the red-harness server with /mcp.")
    say("The repository's .mcp.json.example and README section 'Connect an MCP client' show the same entry.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
