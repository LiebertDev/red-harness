# Red Harness `compute` bootstrap: runs INSIDE Windows Sandbox with the pinned embeddable CPython
# (python.exe -I -B -X utf8 rh_boot.py). On the host only the unit tests' fake sandbox runs it.
#
# Contract: stdin = UTF-8 JSON {"code": str, "inputs": {name: {"b64": str} | {"int": int}}}.
# The model's code runs in a fresh module dict; an INPUTS dict (name -> bytes | int) is provided; the result is printed to stdout.
# The random module starts with a fixed seed (0). If the code raises, the interpreter writes the traceback to stderr and exits with code 1.
# This file is NOT a security boundary: the code can do whatever it wants; the boundary is the sandbox (network off, separate user, Low IL).
import base64
import json
import random
import sys


def _main() -> None:
    env = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    inputs = {}
    for name, v in env.get("inputs", {}).items():
        inputs[name] = base64.b64decode(v["b64"]) if "b64" in v else int(v["int"])
    code = compile(env["code"], "<compute>", "exec")
    random.seed(0)
    exec(code, {"__name__": "__main__", "__builtins__": __builtins__, "INPUTS": inputs})
    sys.stdout.flush()


_main()
