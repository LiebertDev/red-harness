"""Quickstart client: drives `rh mcp` end to end with the official MCP SDK client (no model needed).

  python scripts/quickstart_client.py <target.exe> <scope.json> [--engine ghidra|ida] [--data-root DIR]

Steps (the same calls a model client makes): target_open -> strings -> claim_add (one observation, quoting the first
string that `strings` returned) -> coverage -> report_build. Prints a short summary of each reply and the report path.
Needs an analysis engine (Ghidra is free; see docs/usage-mcp.md, section Engines). The first open of a target runs the
engine's full analysis, which takes minutes for a large binary; later calls are served from the cache.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

STRING_LINE = re.compile(r"^(0x[0-9a-fA-F]+) \S+ (.{4,})$", re.M)


def _leaf_errors(exc: BaseException):
    if isinstance(exc, BaseExceptionGroup):
        for e in exc.exceptions:
            yield from _leaf_errors(e)
    else:
        yield exc


async def _call(session: ClientSession, name: str, **args) -> dict:
    res = await session.call_tool(name, args)
    if res.isError:
        text = "".join(getattr(c, "text", "") for c in res.content)
        raise SystemExit(f"{name} failed: {text}")
    if res.structuredContent is not None:
        sc = res.structuredContent
        return sc.get("result", sc) if set(sc) == {"result"} else sc
    return json.loads(res.content[0].text)


async def run(target: Path, manifest: Path, engine: str, data_root: str | None) -> int:
    env = dict(os.environ)
    if data_root:
        env["RH_DATA_ROOT"] = data_root
    params = StdioServerParameters(command=sys.executable, args=["-m", "redharness.cli", "mcp", "--engine", engine],
                                   env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = [t.name for t in (await session.list_tools()).tools]
            print(f"server up, {len(tools)} tools: {', '.join(tools)}")

            o = await _call(session, "target_open", target_path=str(target), manifest_path=str(manifest))
            t = o["target"]
            print(f"target_open: job {o['job_id']}, engine {o['engine']['name']} {o['engine']['version']}, "
                  f"{t['function_count']} functions, {t['string_count']} strings, "
                  f"protection {t['protection']['diagnosis']}")

            s = await _call(session, "strings", limit=20, detail="full")
            ev = s["evidence_id"]
            print(f"strings: {s['result']['returned']} of {s['result']['total']} returned, evidence {ev[:19]}...")

            m = STRING_LINE.search(s.get("content", ""))
            if m:
                addr, value = m.group(1), m.group(2).split("</")[0].strip()
                c = await _call(session, "claim_add", kind="observation", requested="SUPPORTED",
                                text=f"The target contains the string {value} at {addr}.",
                                evidence_ids=[ev],
                                atoms=[{"type": "quote", "evidence_id": ev, "text": value},
                                       {"type": "address", "evidence_id": ev, "value": addr}])
                print(f"claim_add: verifier status {c.get('status')} (the verifier sets it, not the caller)")
            else:
                print("claim_add: skipped (no string line to quote)")

            cov = await _call(session, "coverage")
            print(f"coverage: {cov['assessment']} (a missing examination is unknown, never 'clean')")

            r = await _call(session, "report_build")
            print(f"report_build: findings {r['counts']['findings']}, hypotheses {r['counts']['hypotheses']}, "
                  f"unsupported_claims {r['counts']['unsupported_claims']} (must be 0)")
            print(f"report: {r['report_path']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Drive rh mcp end to end with the MCP SDK client")
    ap.add_argument("target", type=Path)
    ap.add_argument("manifest", type=Path)
    ap.add_argument("--engine", choices=("ghidra", "ida"), default="ghidra")
    ap.add_argument("--data-root", default=None, help="RH_DATA_ROOT for this run (default: the usual data root)")
    a = ap.parse_args(sys.argv[1:] if argv is None else argv)
    try:
        return asyncio.run(run(a.target, a.manifest, a.engine, a.data_root))
    except BaseExceptionGroup as g:   # the SDK wraps errors raised while the server connection is open
        for e in _leaf_errors(g):
            print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
