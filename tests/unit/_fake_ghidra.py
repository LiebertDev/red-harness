"""Fake `analyzeHeadless` (does NOT require Ghidra). Injected with `GhidraEngine(launcher=[python, this_file])`.

Mimics the real Ghidra argument layout: <project_dir> <project_name> (-import <file> | -process <name>)
[-noanalysis] [-readOnly] -scriptPath <dir> -postScript RHQuery.java <request.properties>.
Behavior is selected with FAKE_MODE. FAKE_LOG: one JSON line per call (op, flags, environment).
Mimics the real Ghidra observation: the process exits 0 even if the script fails ("Import succeeded").
"""
import json
import os
import sys
import time
from pathlib import Path

argv = sys.argv[1:]
proj_dir, proj_name = Path(argv[0]), argv[1]
req_path = argv[argv.index("-postScript") + 2]


def load_props(path):
    props = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            props[k] = v.replace("\n", "\n").replace("\\\\", "\\")
    return props


req = load_props(req_path)
op, nonce, result = req["op"], req["nonce"], req["result"]
mode = os.environ.get("FAKE_MODE", "ok")
DB = proj_dir / f"{proj_name}.rep" / "idata" / "00" / "~00000000.db" / "db.1.gbf"

if os.environ.get("FAKE_LOG"):
    with open(os.environ["FAKE_LOG"], "a", encoding="utf-8") as f:
        f.write(json.dumps({
            "op": op, "import": "-import" in argv, "process": "-process" in argv,
            "noanalysis": "-noanalysis" in argv, "readonly": "-readOnly" in argv,
            "analysis_timeout_flag": "-analysisTimeoutPerFile" in argv,
            "maxmem": os.environ.get("GHIDRA_HEADLESS_MAXMEM"), "ghidra_maxmem": os.environ.get("GHIDRA_MAXMEM"),
            "java_opts": os.environ.get("JAVA_TOOL_OPTIONS"), "xdg": os.environ.get("XDG_CONFIG_HOME"), "pythonpath": os.environ.get("PYTHONPATH"),
            "result_dir": str(Path(result).parent), "cwd": os.getcwd()}) + "\n")


def write(doc, path=result):
    Path(path).write_text(json.dumps(doc), encoding="utf-8")


def good_doc():
    if op == "analyze":
        funcs = [{"address": 0x140001000 + 0x100 * i, "name": f"FUN_{i}", "size": 0x40 + i, "thunk": i % 7 == 0,
                  "chunks": 1, "block": ".text", "source": "DEFAULT"} for i in range(25)]
        strs = [{"address": 0x140009000 + 0x20 * i, "length": 8, "kind": "string", "value": f"string-{i}"}
                for i in range(12)]
        info = {"arch": "x86", "bits": 64, "entry": 0x140001000, "decompiler": True, "imagebase": 0x140000000,
                "external_function_count": 300, "still_analyzing": False}
        return {"ok": True, "op": op, "nonce": nonce, "functions": funcs, "strings": strs, "info": info,
                "counts": {"functions": len(funcs), "strings": len(strs)}, "complete": True}
    if op == "decompile":
        return {"ok": True, "op": op, "nonce": nonce, "address": 0x140001000, "name": "FUN_0",
                "signature": "int FUN_0(void)", "text": "int FUN_0(void) { return 1; }" * 20, "complete": True}
    xs = [{"from": 0x140002000 + i, "to": int(req["address"]), "kind": "UNCONDITIONAL_CALL", "is_code": True,
           "from_function": "FUN_1"} for i in range(5)][: int(req["limit"])]
    return {"ok": True, "op": op, "nonce": nonce, "xrefs": xs, "total": 5, "counts": {"xrefs": len(xs)},
            "complete": True}


if "-process" in argv and not DB.is_file():
    sys.exit(0)  # real Ghidra: logs an error if the project is missing, may still exit 0; no result file

if op == "analyze" and "-import" in argv:
    DB.parent.mkdir(parents=True, exist_ok=True)
    DB.write_bytes(b"FAKE-GHIDRA-DB" * 100)
    (proj_dir / f"{proj_name}.rep" / "project.prp").write_text("x")

if mode == "timeout":
    time.sleep(120)
elif mode == "mem":
    blob = bytearray(600 * 1024 * 1024)
    for i in range(0, len(blob), 4096):
        blob[i] = 1
    time.sleep(30)
elif mode == "crash":  # a FULLY valid result was written but the process crashed -> must not be OK
    write(good_doc())
    os._exit(3)
elif mode == "timeout_after_result":  # result fully written, process hung on exit -> TIMEOUT
    write(good_doc())
    time.sleep(120)
elif mode == "noresult":  # script compile/run error: exit 0, no result file (real observation)
    sys.exit(0)
elif mode == "errdoc":
    write({"ok": False, "op": op, "nonce": nonce, "error": "RuntimeException: intentional", "complete": True})
elif mode == "decomp_timeout":
    write({"ok": False, "op": op, "nonce": nonce, "error": "RuntimeException: DECOMPILE_TIMEOUT: 120 s exceeded",
           "complete": True})
elif mode == "trunc_json":  # half-written JSON
    full = json.dumps(good_doc())
    Path(result).write_text(full[: len(full) // 2], encoding="utf-8")
elif mode == "nocomplete":
    d = good_doc()
    d.pop("complete")
    write(d)
elif mode == "wrongnonce":
    d = good_doc()
    d["nonce"] = "other-call"
    write(d)
elif mode == "badcount":  # array truncated but count intact
    d = good_doc()
    key = {"analyze": "functions", "xrefs": "xrefs"}.get(op)
    if key:
        d[key] = d[key][:-1]
    else:
        d.pop("text")
    write(d)
elif mode == "stillanalyzing":
    d = good_doc()
    if op == "analyze":
        d["info"]["still_analyzing"] = True
    write(d)
elif mode == "noisy":  # 12 MB of log noise: data does not pass through stdout, the result file is whole
    sys.stdout.write(("INFO  Searching 33 paths for library API-MS-WIN-CORE.DLL...\n" * 200_000))
    sys.stdout.flush()
    write(good_doc())
else:
    # Real Ghidra log lines mix into stdout; the result is still in the file
    print("INFO  REPORT: Execute script: RHQuery.java")
    print('{"ok": false, "mixed": "fake json in a log line"}')
    write(good_doc())
