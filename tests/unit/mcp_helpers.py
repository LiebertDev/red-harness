"""Helpers for a real MCP stdio client (SDK client): tests start the server as a separate process."""
import contextlib
import hashlib
import json
import os
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def make_manifest(path: Path, target: Path, **over) -> Path:
    doc = {"schema": "rh.scope/1", "target_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
           "authorization": {"declared_by": "test-owner", "basis": "owner",
                             "statement": "I own this test binary and authorize static analysis."},
           "allowed_operations": ["static"]}
    doc.update(over)
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


@contextlib.asynccontextmanager
async def mcp_session(args: list[str], data_root: Path, extra_env: dict | None = None):
    env = {**os.environ, "RH_DATA_ROOT": str(data_root), **(extra_env or {})}
    params = StdioServerParameters(command=sys.executable, args=args, env=env)
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
            yield session


async def call(session: ClientSession, name: str, **args):
    """(is_error, payload). On success the payload is a dict; on error it is the error text."""
    res = await session.call_tool(name, args)
    if res.isError:
        return True, "".join(getattr(c, "text", "") for c in res.content)
    if res.structuredContent is not None:
        sc = res.structuredContent
        return False, sc.get("result", sc) if set(sc) == {"result"} else sc
    return False, json.loads(res.content[0].text)
