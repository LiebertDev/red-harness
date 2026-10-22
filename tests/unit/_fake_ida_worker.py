"""Fake IDA worker (does not require IDA). Injected with `IdaEngine(worker=...)`.

Behavior is selected with the FAKE_MODE environment variable: ok | timeout | crash | noresult | errdoc | mem | importerr.
FAKE_LOG: one line per call (op, IDAUSR, IDADIR) is appended; used for counting calls.
"""
import json
import os
import sys
import time
from pathlib import Path


def write(path, doc):
    Path(path).write_text(json.dumps(doc), encoding="utf-8")


req = json.load(open(sys.argv[1], encoding="utf-8"))
op = req["op"]
mode = os.environ.get("FAKE_MODE", "ok")
if os.environ.get("FAKE_LOG"):
    with open(os.environ["FAKE_LOG"], "a", encoding="utf-8") as f:
        f.write(json.dumps({"op": op, "idausr": os.environ.get("IDAUSR"), "idadir": os.environ.get("IDADIR"),
                            "pythonpath": os.environ.get("PYTHONPATH")}) + "\n")

if op != "probe":
    if mode == "timeout":
        time.sleep(120)
    elif mode == "mem":
        blob = bytearray(600 * 1024 * 1024)
        for i in range(0, len(blob), 4096):
            blob[i] = 1
        time.sleep(30)
    elif mode == "crash":
        write(req["result_path"], {"ok": True, "functions": [], "strings": [], "info": {}, "text": "x",
                                   "address": 1, "name": "f", "xrefs": [], "total": 0})
        os._exit(3)  # result written but crashed: must still not be OK
    elif mode == "noresult":
        sys.exit(0)
    elif mode == "errdoc":
        write(req["result_path"], {"ok": False, "error": "RuntimeError: intentional"})
        sys.exit(1)
    elif mode == "importerr":
        write(req["result_path"], {"ok": False, "error": "ImportError: idapro missing"})
        sys.exit(1)
    elif mode in ("nofunc", "noname", "decomp_failed") and op != "analyze":  # the stable engine error codes
        write(req["result_path"], {"ok": False, "error": {
            "nofunc": "LookupError: NO_FUNCTION_AT_ADDRESS: no function at address: 0x401000",
            "noname": "LookupError: NAME_NOT_RESOLVED: name could not be resolved: nosuch",
            "decomp_failed": "RuntimeError: DECOMPILE_FAILED: empty result"}[mode]})
        sys.exit(1)

if op == "probe":
    if mode == "importerr":
        write(req["result_path"], {"ok": False, "error": "ImportError: idapro missing"})
        sys.exit(1)
    write(req["result_path"], {"ok": True, "version": "9.9.1"})
elif op == "analyze":
    Path(req["target"]).with_suffix(".i64").write_bytes(b"FAKE-IDB" * 64)
    funcs = [{"address": 0x1000 + 0x100 * i, "name": f"sub_{i}", "size": 0x40 + i} for i in range(25)]
    strs = [{"address": 0x9000 + 0x20 * i, "length": 8, "kind": "0", "value": f"string-{i}"} for i in range(12)]
    write(req["result_path"], {"ok": True, "functions": funcs, "strings": strs,
                               "info": {"arch": "metapc", "bits": 64, "entry": 0x1000, "decompiler": True}})
elif op == "decompile":
    write(req["result_path"], {"ok": True, "address": 0x1000, "name": "sub_0", "text": "int sub_0() { return 1; }" * 20})
elif op == "xrefs":
    xs = [{"from": 0x2000 + i, "to": req["address"], "kind": "Code_Near_Call", "is_code": True,
           "from_function": "sub_1"} for i in range(5)]
    write(req["result_path"], {"ok": True, "xrefs": xs[:req["limit"]], "total": 5})
else:
    write(req["result_path"], {"ok": False, "error": "unknown op"})
    sys.exit(1)
