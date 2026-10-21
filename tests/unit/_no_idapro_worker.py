"""Runs the REAL `engines/ida/_worker.py` as if the `idapro` package were not installed (sys.modules['idapro']=None
=> `import idapro` raises ImportError). Invoked as `python -I <this file> <request.json>`."""
import runpy
import sys
from pathlib import Path

sys.modules["idapro"] = None
WORKER = Path(__file__).resolve().parents[2] / "src" / "redharness" / "engines" / "ida" / "_worker.py"
runpy.run_path(str(WORKER), run_name="__main__")
