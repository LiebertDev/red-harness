"""Minimal CLI: shows version/config; `rh mcp` starts the MCP stdio server."""

from __future__ import annotations

import sys

from . import __version__
from .config import Config
from .core.premium import NOT_INCLUDED, is_missing


HELP = f"""redharness {__version__}: evidence-bound static reverse-engineering harness (MCP server).

usage: rh <command> [options]

commands:
  mcp [--engine ida|ghidra]   start the MCP server on stdio (tools need an IDA or Ghidra engine; see docs/usage-mcp.md)
  studio [--engine ...] [--model ...]
                              local web UI on 127.0.0.1 over the same tools (`rh studio --help`)
  version                     print the version (also: -V, --version)
  export <job_id> <out.zip>   pack a finished job (evidence ledger, claims, report) into a portable bundle
  import <in.zip> [--overwrite]
                              unpack and verify a bundle made by `rh export` (imported claims are capped, see the docs)
  compute-runtime install <zip> | status
                              install or check the pinned Python interpreter that the `compute` tool runs in the sandbox
  deps [list|show <id>|install <id> [--yes]]
                              optional third-party components (Unicorn, Capstone, Ghidra, IDA, ...): licences, status,
                              and a confirmed pip install of the pinned pip components; nothing is bundled
  kernel status|inspect|probe ...
                              Phase 2 VM lab (premium): read-only status / inspect / guest probe (needs RH_PHASE2_VM)
  eval ...                    evaluation harness for model runs (development tool; needs benchmark material)
  bench import|verify ...     manage benchmark binaries used by `rh eval` (development tool)

environment:
  RH_DATA_ROOT      job store, cache and logs (default %USERPROFILE%\\RedHarnessData)
  RH_GHIDRA_DIR     Ghidra install directory (engine ghidra); a JDK 21 must be on PATH or in JAVA_HOME
  RH_IDA_DIR        IDA install directory (engine ida); the `idapro` Python package must be installed

`rh mcp --help` shows the server options. `rh` without arguments prints the version and data root.
"""

MCP_HELP = """usage: rh mcp [--engine ida|ghidra]

Starts the Red Harness MCP server on stdio (talk to it with an MCP client; do not run it by hand).
  --engine ida      IDA Pro through the `idapro` Python package (default when no flag is given)
  --engine ghidra   Ghidra headless (free): needs Ghidra 12.x (tested with 12.1.3) and a JDK 21 on PATH or JAVA_HOME
An engine that is requested but not usable ends the process with the reason on stderr and in the answer to the
client's `initialize` request; there is no silent fallback to the other engine. See docs/usage-mcp.md ("Engines").
"""


def _premium_missing(cmd: str) -> int:
    print(f"{cmd}: {NOT_INCLUDED}", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args and args[0] in ("-h", "--help", "help"):
        print(HELP)
        return 0
    if args and args[0] in ("-V", "--version", "version"):
        print(__version__)
        return 0
    if args and args[0] == "mcp":
        # stdout belongs to the MCP protocol; nothing is printed here.
        from .mcp.server import EngineSelectionError, normalize_engine_name, reply_initialize_error, serve_stdio
        if any(a in ("-h", "--help") for a in args[1:]):
            print(MCP_HELP)
            return 0
        engine_name, rest = None, args[1:]
        i = 0
        while i < len(rest):
            a = rest[i]
            if a == "--engine" or a.startswith("--engine="):
                if a == "--engine":
                    value = rest[i + 1] if i + 1 < len(rest) else ""
                    i += 2
                else:
                    value = a.split("=", 1)[1]
                    i += 1
                engine_name = value
                continue
            print(f"rh mcp: unknown argument {a!r}; usage: rh mcp [--engine ida|ghidra]", file=sys.stderr)
            return 2
        try:
            if engine_name is not None:
                engine_name = normalize_engine_name(engine_name)
            serve_stdio(Config.load(), engine_name=engine_name)
        except EngineSelectionError as e:
            print(f"rh mcp: {e}", file=sys.stderr)
            # An MCP client only sees "connection closed" when the server exits before `initialize`; answer that
            # request with a JSON-RPC error that carries the reason (skipped on a terminal).
            reply_initialize_error(f"rh mcp: {e}")
            return 2
        return 0
    if args and args[0] == "studio":
        try:
            from .studio.launch import main as studio_main
        except ImportError as e:   # Studio is a premium module
            if not is_missing(e, "redharness.studio.launch"):
                raise
            return _premium_missing("studio")
        return studio_main(args[1:])
    if args and args[0] == "eval":
        try:
            from .evals.runner import main as eval_main
        except ImportError as e:   # the evaluation harness is a premium module
            if not is_missing(e, "redharness.evals.runner"):
                raise
            return _premium_missing("eval")
        return eval_main(args[1:])
    if args and args[0] == "kernel":
        try:
            from .kernel.__main__ import main as kernel_main
        except ImportError as e:   # the Phase 2 kernel lab is a premium module
            if not is_missing(e, "redharness.kernel.__main__"):
                raise
            return _premium_missing("kernel")
        return kernel_main(args[1:])
    if args and args[0] == "deps":
        from .deps import main as deps_main
        return deps_main(args[1:])
    if args and args[0] == "compute-runtime":
        from .compute.runtime import main as runtime_main
        return runtime_main(args[1:])
    if args and args[0] == "bench":
        try:
            from .evals.bench import main as bench_main
        except ImportError as e:
            if not is_missing(e, "redharness.evals.bench"):
                raise
            return _premium_missing("bench")
        return bench_main(args[1:])
    if args and args[0] == "export":
        # rh export <job_id> <out.zip>  (portable evidence bundle)
        from pathlib import Path
        try:
            from .jobs.bundle import export_job
        except ImportError as e:   # job bundles are a premium module
            if not is_missing(e, "redharness.jobs.bundle"):
                raise
            return _premium_missing("export")
        if len(args) < 3:
            print("usage: rh export <job_id> <out.zip>")
            return 2
        try:
            p = export_job(Config.load().data_root, args[1], Path(args[2]))
            print(f"exported: {p}")
            return 0
        except Exception as e:  # noqa: BLE001
            print(f"export failed: {e}")
            return 1
    if args and args[0] == "import":
        # rh import <in.zip> [--overwrite]
        from pathlib import Path
        try:
            from .jobs.bundle import import_job
        except ImportError as e:
            if not is_missing(e, "redharness.jobs.bundle"):
                raise
            return _premium_missing("import")
        if len(args) < 2:
            print("usage: rh import <in.zip> [--overwrite]")
            return 2
        overwrite = "--overwrite" in args[2:]
        try:
            jid = import_job(Config.load().data_root, Path(args[1]), overwrite=overwrite)
            print(f"imported: {jid}")
            return 0
        except Exception as e:  # noqa: BLE001
            print(f"import failed: {e}")
            return 1
    print(f"redharness {__version__}\ndata_root: {Config.load().data_root}\ncommands: rh version | rh mcp [--engine ida|ghidra] | rh studio | rh eval | rh bench | rh deps | rh kernel | rh export | rh import | rh compute-runtime (rh --help for details)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
