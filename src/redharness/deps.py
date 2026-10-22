"""`rh deps`: the optional third-party components, how to obtain them, and under which licence.

Nothing here is bundled with Red Harness. The registry below is the ONLY list of things `rh deps install` may install
(two pinned PyPI packages); every other component is bring-your-own and only gets instructions. The licence facts are
the same ones that THIRD_PARTY_NOTICES.md states; a test keeps the two in step.

  rh deps [list] [--json]          what each component is, whether it is present, its licence and upstream link
  rh deps show <id>                the full notice for one component
  rh deps install <id> [--yes] [--dry-run]
                                   pip components only: prints the notice, asks, then runs `pip install <pinned spec>`
"""

from __future__ import annotations

import importlib
import importlib.metadata
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence

NOT_OURS = "Not part of Red Harness and not covered by Red Harness's Apache-2.0 licence."


@dataclass(frozen=True)
class Component:
    id: str
    name: str
    kind: str                      # "pip" (installable here) | "byo" (you obtain it) | "runtime" | "os"
    purpose: str
    license: str                   # short SPDX-style label of the thing you would obtain
    license_note: str              # one or two sentences that matter for users
    license_url: str               # upstream licence text
    upstream_url: str
    obtain: str                    # how to get it (human text)
    aliases: tuple[str, ...] = ()
    pip_package: str = ""          # distribution name (pip kind)
    pip_spec: str = ""             # pinned requirement (pip kind); the only thing `install` will ever pass to pip
    extra: str = ""                # matching extra in pyproject.toml, if any
    env: tuple[str, ...] = field(default_factory=tuple)   # environment variables the harness reads for it


REGISTRY: tuple[Component, ...] = (
    Component(
        id="unicorn", name="Unicorn CPU emulator (Python package `unicorn`)", kind="pip", aliases=("emulate",),
        purpose="the `emulate` tool (bounded CPU emulation of target code, in a restricted host process)",
        license="GPL-2.0 (engine upstream); PyPI metadata of the Python package says BSD",
        license_note="The wheel from PyPI contains the compiled Unicorn engine, which upstream licenses under GPLv2. "
                     "Using it on your own machine is fine; the wheel has no licence file of its own, so read the "
                     "upstream text (link below) and, if you REDISTRIBUTE an environment that contains it, follow it.",
        license_url="https://github.com/unicorn-engine/unicorn/blob/2.1.4/COPYING",
        upstream_url="https://www.unicorn-engine.org/",
        obtain="`rh deps install emulate` (or `pip install \"red-harness-core[emulate]\"`): installs the pinned PyPI release.",
        pip_package="unicorn", pip_spec="unicorn==2.1.4", extra="emulate"),
    Component(
        id="capstone", name="Capstone disassembler (Python package `capstone`)", kind="pip", aliases=("disasm",),
        purpose="the Pro `captured_region` disassembly view and some optional tests; Core does not need it",
        license="BSD-3-Clause (Capstone; the PyPI package declares the BSD licence classifier)",
        license_note="Capstone's licence file asks that its text accompany any redistribution of the binary or source. "
                     "Red Harness redistributes nothing; the wheel carries LICENSE.TXT and pip stores it in the package's dist-info.",
        license_url="https://github.com/capstone-engine/capstone/blob/5.0.6/LICENSE.TXT",
        upstream_url="https://www.capstone-engine.org/",
        obtain="`rh deps install capstone`: installs the pinned PyPI release.",
        pip_package="capstone", pip_spec="capstone==5.0.6", extra="disasm"),
    Component(
        id="ghidra", name="Ghidra", kind="byo", aliases=("ghidra-engine",),
        purpose="analysis engine for every MCP tool (`rh mcp --engine ghidra`); tested with 12.1.3; needs a JDK 21",
        license="Apache-2.0 (with component notices inside the Ghidra distribution)",
        license_note="Released by the US National Security Agency; its NOTICE explains the government-work "
                     "qualifications. Red Harness is not affiliated with or endorsed by the NSA.",
        license_url="https://github.com/NationalSecurityAgency/ghidra/blob/master/LICENSE",
        upstream_url="https://github.com/NationalSecurityAgency/ghidra/releases",
        obtain="Download the release zip from upstream, extract it, and point Red Harness at the folder that contains "
               "support/analyzeHeadless.bat. A JDK 21 (for example Eclipse Temurin 21) must be on PATH or in JAVA_HOME.",
        env=("RH_GHIDRA_DIR", "GHIDRA_INSTALL_DIR", "JAVA_HOME")),
    Component(
        id="ida", name="IDA Pro / IDA Home (Hex-Rays)", kind="byo", aliases=("ida-pro", "idapro"),
        purpose="analysis engine for every MCP tool (`rh mcp --engine ida`), through the `idapro` (idalib) Python package",
        license="Proprietary (Hex-Rays EULA); not distributed by Red Harness",
        license_note="You must hold a valid IDA licence that covers your use. The `idapro` bridge is NOT installed "
                     "from PyPI by Red Harness (unverified publisher); install the wheel that ships inside your IDA "
                     "installation. Red Harness never runs IDA's licence activation script.",
        license_url="https://hex-rays.com/eula",
        upstream_url="https://hex-rays.com/ida-pro",
        obtain="Install IDA yourself. Point Red Harness at it with RH_IDA_DIR (the folder that contains idalib.dll) and, "
               "if the `idapro` package lives in a different Python, RH_IDA_PYTHON. Install the idalib wheel from the "
               "IDA folder: pip install \"<IDA>\\idalib\\python\\idapro-<version>-py3-none-any.whl\" (exact file name).",
        env=("RH_IDA_DIR", "IDADIR", "RH_IDA_PYTHON")),
    Component(
        id="python-embed", name="CPython embeddable package (compute runtime)", kind="runtime", aliases=("compute",),
        purpose="the interpreter that the `compute` tool runs inside Windows Sandbox (checked against pinned SHA-256 values)",
        license="PSF License Agreement (Python Software Foundation) and component licences",
        license_note="You download the zip from python.org yourself; Red Harness only verifies and unpacks it.",
        license_url="https://docs.python.org/3/license.html",
        upstream_url="https://www.python.org/downloads/release/python-31210/",
        obtain="Run `rh compute-runtime` for the exact download address and expected SHA-256, then "
               "`rh compute-runtime install python-3.12.10-embed-amd64.zip`."),
    Component(
        id="windows-sandbox", name="Windows Sandbox", kind="os", aliases=("sandbox",),
        purpose="isolation for the two tools that execute a target natively or run model code (`run_controlled`, `compute`)",
        license="Part of Windows (Microsoft licence terms for your Windows edition)",
        license_note="An optional Windows feature (Pro, Enterprise, Education; not Home). Red Harness does not install "
                     "or modify it. Without it those two tools report SANDBOX_UNAVAILABLE and the rest keeps working.",
        license_url="https://learn.microsoft.com/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview",
        upstream_url="https://learn.microsoft.com/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-install",
        obtain="Turn on the optional Windows feature \"Windows Sandbox\" (needs hardware virtualization in the firmware), "
               "then restart. Tune its memory with RH_SANDBOX_MEMORY_MB.",
        env=("RH_SANDBOX_MEMORY_MB",)),
)


def find(ident: str) -> Component | None:
    key = ident.strip().lower()
    for c in REGISTRY:
        if key == c.id or key in c.aliases:
            return c
    return None


# --------------------------------------------------------------------------------------------------------------------
# Detection: cheap, read-only, never raises.
# --------------------------------------------------------------------------------------------------------------------
def pip_version(package: str) -> str | None:
    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return None


def _detect_ghidra() -> tuple[bool, str]:
    from .engines.ghidra.backend import discover_ghidra_dir, ghidra_version
    d = discover_ghidra_dir()
    return (True, f"{ghidra_version(d) or 'unknown version'} at {d}") if d else (False, "")


def _detect_ida() -> tuple[bool, str]:
    from .engines.ida.backend import discover_ida_install
    i = discover_ida_install()
    return (True, f"{i.edition} at {i.path}") if i else (False, "")


def _detect_runtime() -> tuple[bool, str]:
    from .compute.runtime import PINNED, RuntimeMissing, load_runtime
    from .config import Config
    try:
        load_runtime(Config.load())
    except RuntimeMissing:
        return False, ""
    return True, PINNED.runtime_id


def _detect_sandbox() -> tuple[bool, str]:
    exe = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsSandbox.exe"
    return (True, "feature enabled") if exe.is_file() else (False, "")


_DETECTORS: dict[str, Callable[[], tuple[bool, str]]] = {
    "ghidra": _detect_ghidra, "ida": _detect_ida, "python-embed": _detect_runtime, "windows-sandbox": _detect_sandbox}


def status(c: Component) -> tuple[bool, str]:
    """(present, detail). Never raises: a failing probe counts as 'not found'."""
    try:
        if c.kind == "pip":
            v = pip_version(c.pip_package)
            return (True, v) if v else (False, "")
        return _DETECTORS[c.id]()
    except Exception:  # noqa: BLE001 - detection is advisory only
        return False, ""


# --------------------------------------------------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------------------------------------------------
_KIND_LABEL = {"pip": "optional pip package", "byo": "bring your own", "runtime": "you download it", "os": "OS feature"}


def notice_text(c: Component) -> str:
    lines = [f"{c.name}", f"  what it is for : {c.purpose}",
             f"  how obtained   : {_KIND_LABEL[c.kind]}; bundled with Red Harness: no",
             f"  licence        : {c.license}", f"  licence text   : {c.license_url}", f"  upstream       : {c.upstream_url}",
             f"  note           : {c.license_note}"]
    if c.env:
        lines.append(f"  environment    : {', '.join(c.env)}")
    lines.append(f"  {NOT_OURS}")
    return "\n".join(lines)


def list_text() -> str:
    rows = []
    for c in REGISTRY:
        present, detail = status(c)
        state = ("installed " + detail) if present and c.kind == "pip" else ("found " + detail if present else "not found")
        rows.append(f"{c.id:<16} {_KIND_LABEL[c.kind]:<21} {state}\n"
                    f"{'':<16} licence: {c.license}\n{'':<16} upstream: {c.upstream_url}")
    return ("\n".join(rows) + "\n\nNone of these is part of Red Harness or covered by its Apache-2.0 licence; nothing is bundled.\n"
            "See THIRD_PARTY_NOTICES.md. `rh deps show <id>` prints a full notice; `rh deps install <id>` installs "
            "the pip components (" + ", ".join(c.id for c in REGISTRY if c.kind == "pip") + ") after you confirm.")


def list_json() -> str:
    out = []
    for c in REGISTRY:
        present, detail = status(c)
        out.append({"id": c.id, "name": c.name, "kind": c.kind, "present": present, "detail": detail,
                    "license": c.license, "license_url": c.license_url, "upstream": c.upstream_url,
                    "bundled": False, "installable": c.kind == "pip", "pip_spec": c.pip_spec or None})
    return json.dumps(out, indent=2)


def pip_command(c: Component) -> list[str]:
    return [sys.executable, "-m", "pip", "install", c.pip_spec]


# --------------------------------------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------------------------------------
USAGE = """usage: rh deps [list [--json]]
       rh deps show <component>
       rh deps install <component> [--yes] [--dry-run]

Optional third-party components. None is bundled; each keeps its own licence (see THIRD_PARTY_NOTICES.md).
`install` works only for the pip components listed by `rh deps list` and installs the pinned version after showing
its licence notice and asking for confirmation (--yes skips the question; --dry-run only prints the pip command)."""


def _install(c: Component, *, yes: bool, dry_run: bool, run: Callable, ask: Callable[[str], str]) -> int:
    if c.kind != "pip":
        print(notice_text(c))
        print(f"\nRed Harness does not install '{c.id}'. How to get it:\n  {c.obtain}")
        return 1
    present, detail = status(c)
    print(notice_text(c))
    cmd = pip_command(c)
    print("\ncommand: " + " ".join(cmd))
    if dry_run:
        print("dry run: nothing was installed")
        return 0
    if present:
        print(f"already installed ({c.pip_package} {detail}); pip will make sure the pinned version {c.pip_spec} is present")
    if not yes:
        try:
            answer = ask(f"Install {c.pip_spec} under the licence above? [y/N] ")
        except EOFError:
            answer = ""
        if answer.strip().lower() not in ("y", "yes"):
            print("aborted: nothing was installed")
            return 1
    sys.stdout.flush()   # keep the notice ahead of pip's own output when stdout is a pipe
    rc = run(cmd).returncode
    if rc != 0:
        print(f"pip failed (exit {rc}); nothing else was changed")
        return rc
    importlib.invalidate_caches()
    v = pip_version(c.pip_package)
    print(f"installed: {c.pip_package} {v}" if v else f"pip finished but {c.pip_package} is not visible to this interpreter")
    return 0 if v else 1


def main(argv: Sequence[str], *, run: Callable = subprocess.run, ask: Callable[[str], str] = input) -> int:
    args = list(argv)
    if not args or args[0] == "list":
        rest = args[1:]
        if any(a not in ("--json",) for a in rest):
            print(USAGE, file=sys.stderr)
            return 2
        print(list_json() if "--json" in rest else list_text())
        return 0
    if args[0] in ("-h", "--help", "help"):
        print(USAGE)
        return 0
    if args[0] in ("show", "install"):
        flags = {a for a in args[1:] if a.startswith("-")}
        names = [a for a in args[1:] if not a.startswith("-")]
        allowed = {"--yes", "-y", "--dry-run"} if args[0] == "install" else set()
        if len(names) != 1 or flags - allowed:
            print(USAGE, file=sys.stderr)
            return 2
        c = find(names[0])
        if c is None:
            print(f"unknown component {names[0]!r}; known: {', '.join(x.id for x in REGISTRY)}. Nothing was installed.",
                  file=sys.stderr)
            return 2
        if args[0] == "show":
            print(notice_text(c))
            print(f"\nHow to get it:\n  {c.obtain}")
            return 0
        return _install(c, yes=bool(flags & {"--yes", "-y"}), dry_run="--dry-run" in flags, run=run, ask=ask)
    print(USAGE, file=sys.stderr)
    return 2
