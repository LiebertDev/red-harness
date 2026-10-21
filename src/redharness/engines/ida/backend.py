"""IDA Pro idalib backend.

- idalib does NOT run in the main process: every operation runs in a separate Python process (`_worker.py`)
  under `core.proc.run_bounded` (Job Object: memory + time + tree kill). A crash/timeout/memory overrun is never OK.
- Cache: `cache/ida/<ida_version>/<target_sha256>/` (target copy, .i64, functions.json, strings.json,
  results/, meta.json). `meta.json` is written last = completion marker; if it is missing the directory is invalid
  and is re-analyzed. A failed result is not written to the cache.
- The user's global IDA settings are not touched: the worker is configured only in its own process through the
  `IDADIR` (install dir) and `IDAUSR` (`data_root/ida_user`) environment variables;
  `py-activate-idalib.py` is not run, `ida-config.json` is not written.
"""

from __future__ import annotations

import glob
import hashlib
import json
import logging
import os
import re
import shutil
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from ...config import Config
from ...core.journal import atomic_write_bytes, canonical, sha256_hex
from ...core.lock import JobLock, LockError
from ...core.proc import RunResult, run_bounded
from ...core.result import Status
from .._common import HEAVY, call_args_from_doc, disassembly_from_doc
from ..base import (DecompileInfo, Disassembly, Engine, EngineInfo, EngineResult, FunctionInfo, Page, StringInfo,
                    TargetInfo, XrefInfo)

ENV_IDA_DIR = "RH_IDA_DIR"
ENV_IDA_PYTHON = "RH_IDA_PYTHON"
WORKER = Path(__file__).with_name("_worker.py")
GB = 1024 ** 3
log = logging.getLogger(__name__)
# Install-directory names written by the IDA installers. 9.4 ships idalib with Home/Classroom too (9.3 docs said
# Home lacked it), so all editions are tried; dirs are still filtered by the presence of idalib.dll below.
IDA_DIR_PATTERNS = ("IDA Professional*", "IDA Home*", "IDA Classroom*", "IDA Essential*", "IDA Expert*", "IDA Ultimate*")
# Pro-tier dirs win over Classroom, and Classroom over Home, when several installs are present.
_EDITION_RANK = {"home": 0, "classroom": 1, "professional": 2, "essential": 2, "expert": 2, "ultimate": 2}
_EDITION_KEYWORDS = ("professional", "classroom", "essential", "expert", "ultimate", "home")
# String extraction revision: 2 with UTF-16LE support. An old cache (meta without the field) is re-analyzed.
STRINGS_REV = 2
# Query-result revision (part of the per-query cache key): 2 = operand text without IDA colour tags. Bump when the
# worker's output for the same query changes, so older cached results are not served.
RESULT_REV = 3   # 3: xrefs carry to_name / to_string / to_string_kind
_DROP_ENV = {"PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "IDAUSR", "IDADIR"}
# idalib/IDA open paths through the ANSI-limited Windows API: a database path of 260+ characters makes open_database fail
# (rc=4 or rc=1, "Can't open for read file", measured on 9.4 and 9.5: 259 chars work, 260+ fail), whatever LongPathsEnabled says.
MAX_IDB_PATH = 259
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
# An explicit beta release marker only: "IDA 9.5 Beta", "IDA Pro 9.5 beta 2", "9.5.261001 Beta". A mere mention of
# "beta" (e.g. "# IDA 9.5 SP1 — beta migration notes") says nothing about the build being a pre-release.
_BETA_HEADER_RE = re.compile(
    r"(?:\d+(?:\.\d+)+|\bIDA(?:\s+(?:Pro|Professional|Home|Classroom|Essential|Expert|Ultimate))?)\s+beta\b",
    re.IGNORECASE)
_BETA_DIR_RE = re.compile(r"\bbeta\b", re.IGNORECASE)
# The probe's version string becomes one path segment and is unknown before probing. This generous upper bound lets
# open_target refuse an obviously too-long data root without starting the probe worker; the exact check follows.
_PROBE_VERSION_BOUND = 32
_HEAVY = HEAVY  # Phase 1: one heavy engine operation per process (IDA and Ghidra SHARE the lock); a second one queues


GHIDRA_ALTERNATIVE = ("The free alternative is the Ghidra engine: start the server with `rh mcp --engine ghidra` "
                      "(docs/usage-mcp.md, section Engines).")


def idapro_missing_message(python: str) -> str:
    return ("IDA's Python package `idapro` is not installed in the Python that runs the server "
            f"({python}). Install it from the wheel in your IDA installation (IDA 9.x with an idalib licence): "
            "pip install \"<IDA install dir>\\idalib\\python\\idapro-<version>-py3-none-any.whl\" "
            "(the exact file name in that folder; pip does not accept a wildcard) into the same environment as `redharness` "
            "(or point RH_IDA_PYTHON at the Python that has it). " + GHIDRA_ALTERNATIVE)


def ida_dir_missing_message() -> str:
    return ("IDA unavailable: install directory not found (set RH_IDA_DIR or IDADIR to the folder that contains "
            "idalib.dll, e.g. C:\\Program Files\\IDA Professional 9.4). " + GHIDRA_ALTERNATIVE)


@dataclass(frozen=True)
class IdaInstall:
    """An IDA install directory that contains idalib.dll, plus the edition inferred from its directory name."""
    path: Path
    edition: str = ""  # "professional" | "home" | "classroom" | "essential" | "expert" | "ultimate" | ""
    beta: bool = False  # pre-release build: only chosen automatically when no stable install exists


@dataclass(frozen=True)
class IdaEngineInfo(EngineInfo):
    """EngineInfo with the IDA edition (e.g. edition="home") so reports can note a non-Pro install."""
    edition: str = ""
    install_dir: str = ""


def _edition_of(path: Path) -> str:
    name = path.name.lower()
    for keyword in _EDITION_KEYWORDS:
        if keyword in name:
            return keyword
    return ""


def _version_key(path: Path) -> tuple[int, ...]:
    m = re.search(r"\d+(?:\.\d+)*", path.name)
    return tuple(int(part) for part in m.group(0).split(".")) if m else ()


def _is_beta(path: Path) -> bool:
    """A beta install names it explicitly in its directory name or in the first line of `release-notes.md`
    ("# IDA 9.5 Beta", "IDA Professional 9.5 Beta"). Any other occurrence of "beta" (e.g. "SP1 — beta migration
    notes") is not a release marker."""
    if _BETA_DIR_RE.search(path.name):
        return True
    try:
        with open(path / "release-notes.md", encoding="utf-8", errors="replace") as f:
            header = f.readline()
    except OSError:
        return False
    return bool(_BETA_HEADER_RE.search(header))


def _install_at(candidate: str | os.PathLike) -> IdaInstall | None:
    p = Path(candidate)
    if not (p / "idalib.dll").is_file():
        log.debug("%s: idalib.dll not found — this IDA edition may not ship idalib", p)
        return None
    return IdaInstall(p, _edition_of(p), _is_beta(p))


def discover_ida_install(explicit: str | os.PathLike | None = None) -> IdaInstall | None:
    """Best IDA install directory containing idalib.dll. The explicit override (argument, then RH_IDA_DIR, then
    IDADIR) wins; otherwise Program Files is scanned for every known edition. A stable release always beats a beta
    (default analysis must not silently run on a pre-release); then Pro tier, then the newest version."""
    overrides: list[str] = []
    if explicit:
        overrides.append(str(explicit))
    for var in (ENV_IDA_DIR, "IDADIR"):
        if os.environ.get(var):
            overrides.append(os.environ[var])
    for c in overrides:
        install = _install_at(c)
        if install is not None:
            return install
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    found: list[IdaInstall] = []
    for pattern in IDA_DIR_PATTERNS:
        for c in glob.glob(os.path.join(pf, pattern)):
            install = _install_at(c)
            if install is not None:
                found.append(install)
    if not found:
        return None
    found.sort(key=lambda i: (not i.beta, _EDITION_RANK.get(i.edition, -1), _version_key(i.path)), reverse=True)
    if found[0].beta:
        log.warning("only a beta IDA install was found (%s); set RH_IDA_DIR to pin a stable release", found[0].path)
    return found[0]


def discover_ida_dir(explicit: str | os.PathLike | None = None) -> Path | None:
    install = discover_ida_install(explicit)
    return install.path if install is not None else None


def idb_path_problem(tdir: Path, suffix: str) -> str:
    """Empty string if IDA can open the database that analysis will create in `tdir`, else a PATH_TOO_LONG explanation
    (fail-closed up front instead of an opaque open_database rc=4 from the worker)."""
    idb = str(tdir / ("target" + suffix.lower() + ".i64"))
    if len(idb) <= MAX_IDB_PATH:
        return ""
    return (f"PATH_TOO_LONG: the IDA database path would be {len(idb)} characters (limit {MAX_IDB_PATH}; IDA cannot open "
            f"longer paths, open_database fails with rc=4). Use a shorter data root (RH_DATA_ROOT or --data-root) "
            f"by at least {len(idb) - MAX_IDB_PATH} characters.")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _fail(status: Status, detail: str, t0: float, **kw) -> EngineResult:
    return EngineResult(status, None, detail, duration_s=time.monotonic() - t0, **kw)


class IdaEngine(Engine):
    name = "ida"

    def __init__(self, config: Config | None = None, *, python: str | os.PathLike | None = None,
                 ida_dir: str | os.PathLike | None = None, memory_limit_bytes: int = 6 * GB,
                 analyze_timeout_s: float = 900, query_timeout_s: float = 180,
                 probe_timeout_s: float = 90, lock_wait_s: float = 120,
                 worker: str | os.PathLike | None = None):
        self.config = config or Config.load()
        self.python = str(python or os.environ.get(ENV_IDA_PYTHON) or sys.executable)
        self._ida_dir_arg = ida_dir
        self.memory_limit = memory_limit_bytes
        self.analyze_timeout_s = analyze_timeout_s
        self.query_timeout_s = query_timeout_s
        self.probe_timeout_s = probe_timeout_s
        self.lock_wait_s = lock_wait_s
        self.worker = Path(worker) if worker else WORKER  # a fake worker can be injected in tests
        self._info: EngineInfo | None = None
        self._info_key: tuple | None = None  # identity of the install the cached probe belongs to

    # ------------------------------------------------------------------ process
    @property
    def ida_user_dir(self) -> Path:
        return self.config.data_root / "ida_user"

    def _env(self, ida_dir: Path) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if k.upper() not in _DROP_ENV}
        self.ida_user_dir.mkdir(parents=True, exist_ok=True)
        env.update(IDADIR=str(ida_dir), IDAUSR=str(self.ida_user_dir), PYTHONUTF8="1",
                   PYTHONIOENCODING="utf-8")
        return env

    def _run(self, op: str, req: dict, timeout_s: float) -> tuple[Status, dict | None, str, RunResult | None]:
        """Runs the worker bounded. (status, result_document, detail, run). The document is returned only for OK + ok:true."""
        install = discover_ida_install(self._ida_dir_arg)
        if install is None:
            return Status.TOOL_MISSING, None, ida_dir_missing_message(), None
        ida_dir = install.path
        work = self.config.work_dir / f"ida-{uuid.uuid4().hex}"
        work.mkdir(parents=True, exist_ok=True)
        try:
            result_path = work / "result.json"
            req = dict(req, op=op, result_path=str(result_path))
            (work / "req.json").write_text(json.dumps(req), encoding="utf-8")
            rr = run_bounded([self.python, "-I", str(self.worker), str(work / "req.json")], timeout_s=timeout_s,
                             memory_limit_bytes=self.memory_limit, env=self._env(ida_dir),
                             cwd=str(work), head_bytes=8192, tail_bytes=8192)
            if rr.status in (Status.TIMEOUT, Status.MEMORY_LIMIT, Status.TOOL_MISSING):
                return rr.status, None, rr.detail, rr
            # stdout is diagnostic only (the result is in the file); so only truncation (PARTIAL) does not count as a failure.
            clean_exit = rr.exit_code == 0 and rr.status in (Status.OK, Status.PARTIAL)
            doc = None
            if result_path.is_file():
                try:
                    doc = json.loads(result_path.read_text(encoding="utf-8"))
                except ValueError:
                    doc = None
            tail = rr.stderr[-400:].decode("utf-8", "replace") + rr.stdout[-400:].decode("utf-8", "replace")
            if isinstance(doc, dict) and doc.get("ok") is False:
                err = str(doc.get("error", ""))
                st = Status.TOOL_MISSING if ("ImportError" in err.split(":")[0] or "ModuleNotFoundError" in err
                                             or "DECOMPILER_UNAVAILABLE" in err) else Status.ERROR
                if st is Status.TOOL_MISSING and "idapro" in err:
                    return st, None, f"worker error: {err}. {idapro_missing_message(self.python)}", rr
                return st, None, f"worker error: {err}", rr
            if not clean_exit:
                return Status.ERROR, None, f"worker did not exit cleanly ({rr.status.value}: {rr.detail}) {tail}".strip(), rr
            if not isinstance(doc, dict) or doc.get("ok") is not True:
                return Status.ERROR, None, f"worker result file missing/corrupt {tail}".strip(), rr
            return Status.OK, doc, "", rr
        finally:
            shutil.rmtree(work, ignore_errors=True)

    # ------------------------------------------------------------------ probe
    @property
    def edition(self) -> str:
        """Edition of the install discovery would use ("home", "classroom", "professional", ... or "")."""
        install = discover_ida_install(self._ida_dir_arg)
        return install.edition if install is not None else ""

    def probe(self) -> EngineInfo:
        install = discover_ida_install(self._ida_dir_arg)
        key = self._install_key(install)
        if self._info is not None and self._info.available:
            if key == self._info_key:
                return self._info
            # The resolved install changed since the probe (e.g. an in-place upgrade): the cached version, and with
            # it the version-specific cache directory, is stale. Re-probe instead of serving the old engine info.
            log.info("IDA install changed (%s); refreshing probe", install.path if install is not None else "missing")
            self._info = None
        st, doc, detail, _ = self._run("probe", {}, self.probe_timeout_s)
        if st is Status.OK and doc and doc.get("version"):
            install = discover_ida_install(self._ida_dir_arg)
            edition = install.edition if install is not None else ""
            note = f"idalib working; edition={edition}" if edition else "idalib working"
            if install is not None and install.beta:
                note += "; BETA build"
            self._info = IdaEngineInfo("ida", True, doc["version"], note, edition=edition,
                                       install_dir=str(install.path) if install is not None else "")
            self._info_key = self._install_key(install)
        else:
            msg = detail if detail.startswith("IDA unavailable") else f"IDA unavailable: {st.value}: {detail}"
            self._info = EngineInfo("ida", False, "", msg)
            self._info_key = key
        return self._info

    @staticmethod
    def _install_key(install: IdaInstall | None) -> tuple:
        """Identity of a resolved install: its directory plus mtime/size of the IDA library and version/notes file.
        A long-lived engine re-probes when this changes (in-place upgrade), so the cache dir follows the new version."""
        if install is None:
            return ("",)
        key: list = [str(install.path)]
        for name in ("idalib.dll", "release-notes.md"):
            try:
                s = (install.path / name).stat()
                key.append((name, s.st_mtime_ns, s.st_size))
            except OSError:
                key.append((name, None, None))
        return tuple(key)

    def _tdir(self, version: str, sha: str) -> Path:
        return self.config.cache_dir / "ida" / version / sha

    def _unavailable(self, info: EngineInfo, t0: float) -> EngineResult:
        return _fail(Status.TOOL_MISSING, info.detail or "IDA unavailable", t0)

    # ------------------------------------------------------------------ cache
    def _meta(self, tdir: Path, sha: str) -> dict | None:
        try:
            meta = json.loads((tdir / "meta.json").read_text(encoding="utf-8"))
            if (meta.get("sha256") == sha and meta.get("strings_rev") == STRINGS_REV
                    and (tdir / meta["idb"]).is_file()
                    and (tdir / "functions.json").is_file() and (tdir / "strings.json").is_file()):
                return meta
        except (OSError, ValueError, KeyError):
            pass
        return None

    def _target_info(self, meta: dict) -> TargetInfo:
        i = meta["info"]
        return TargetInfo(meta["sha256"], meta["source_path"], i.get("arch", ""), i.get("bits", 0),
                          i.get("entry"), meta["function_count"], meta["string_count"],
                          bool(i.get("decompiler")), i.get("imagebase"))

    def _lock(self, tdir: Path) -> JobLock:
        lock = JobLock(tdir.with_name(tdir.name + ".lock"))
        deadline = time.monotonic() + self.lock_wait_s
        while True:
            try:
                lock.acquire()
                return lock
            except LockError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.5)

    # ------------------------------------------------------------------ open_target
    def open_target(self, path: str | Path) -> EngineResult[TargetInfo]:
        t0 = time.monotonic()
        src = Path(path)
        # The SHA is always 64 hex chars, so the database path length is already exact except for the version segment
        # (only known after probing). Check a conservative upper bound first: a too-long data root must not start a
        # probe worker just to be refused.
        version_guess = (self._info.version if self._info is not None and self._info.available and self._info.version
                         else "0" * _PROBE_VERSION_BOUND)
        problem = idb_path_problem(self._tdir(version_guess, "0" * 64), src.suffix)
        if problem:
            return _fail(Status.ERROR, problem, t0)
        info = self.probe()
        if not info.available:
            return self._unavailable(info, t0)
        if not src.is_file():
            return _fail(Status.ERROR, f"target file does not exist: {src}", t0)
        try:
            sha = _sha256_file(src)
        except OSError as e:
            return _fail(Status.ERROR, f"could not read target: {e}", t0)
        tdir = self._tdir(info.version, sha)
        problem = idb_path_problem(tdir, src.suffix)
        if problem:
            return _fail(Status.ERROR, problem, t0)
        with _HEAVY:
            try:
                tdir.parent.mkdir(parents=True, exist_ok=True)
                lock = self._lock(tdir)
            except (LockError, OSError) as e:
                return _fail(Status.ERROR, f"could not acquire cache lock: {e}", t0)
            try:
                meta = self._meta(tdir, sha)
                if meta:
                    return EngineResult(Status.OK, self._target_info(meta), cached=True,
                                        duration_s=time.monotonic() - t0)
                return self._analyze(src, sha, tdir, info.version, t0)
            finally:
                lock.release()

    def _analyze(self, src: Path, sha: str, tdir: Path, version: str, t0: float) -> EngineResult[TargetInfo]:
        shutil.rmtree(tdir, ignore_errors=True)  # half-finished/corrupt previous attempt
        tdir.mkdir(parents=True)
        copy = tdir / ("target" + src.suffix.lower())
        try:
            shutil.copyfile(src, copy)
            if _sha256_file(copy) != sha:  # identity pinning: the copy must be identical to the target
                shutil.rmtree(tdir, ignore_errors=True)
                return _fail(Status.ERROR, "ARTIFACT_CHANGED: copy SHA-256 mismatch (target changed during analysis)", t0)
        except OSError as e:
            shutil.rmtree(tdir, ignore_errors=True)
            return _fail(Status.ERROR, f"could not copy target: {e}", t0)
        ta = time.monotonic()
        st, doc, detail, rr = self._run("analyze", {"target": str(copy)}, self.analyze_timeout_s)
        analysis_s = time.monotonic() - ta
        if st is not Status.OK or doc is None:
            shutil.rmtree(tdir, ignore_errors=True)  # no partial database is left behind
            return _fail(st, f"analysis failed: {detail}", t0)
        idbs = sorted(p.name for p in tdir.glob("*.i64"))
        if len(idbs) != 1:
            shutil.rmtree(tdir, ignore_errors=True)
            return _fail(Status.ERROR, f"expected exactly one .i64, got: {idbs}", t0)
        try:
            atomic_write_bytes(tdir / "functions.json", canonical(doc["functions"]))
            atomic_write_bytes(tdir / "strings.json", canonical(doc["strings"]))
            meta = {"sha256": sha, "source_path": str(src), "idb": idbs[0],
                    "idb_sha256": _sha256_file(tdir / idbs[0]), "ida_version": version,
                    "info": doc["info"], "function_count": len(doc["functions"]),
                    "string_count": len(doc["strings"]), "strings_rev": STRINGS_REV, "analysis_s": round(analysis_s, 2),
                    "peak_job_memory": rr.peak_job_memory if rr else None}
            atomic_write_bytes(tdir / "meta.json", canonical(meta))  # completion marker: written last
        except (OSError, KeyError) as e:
            shutil.rmtree(tdir, ignore_errors=True)
            return _fail(Status.ERROR, f"could not write cache: {e}", t0)
        return EngineResult(Status.OK, self._target_info(meta), cached=False, duration_s=time.monotonic() - t0,
                            extra={"analysis_s": meta["analysis_s"], "peak_job_memory": meta["peak_job_memory"]})

    # ------------------------------------------------------------------ queries
    def _prepare(self, sha: str, t0: float):
        """(tdir, meta) or an EngineResult (error)."""
        if not _SHA_RE.match(sha or ""):
            return _fail(Status.ERROR, "invalid sha256", t0)
        info = self.probe()
        if not info.available:
            return self._unavailable(info, t0)
        tdir = self._tdir(info.version, sha)
        meta = self._meta(tdir, sha)
        if meta is None:
            return _fail(Status.ERROR, "target not analyzed/cache invalid (run open_target first)", t0)
        return tdir, meta

    @staticmethod
    def _page(rows: list, offset: int, limit: int, make) -> Page:
        offset, limit = max(offset, 0), max(limit, 0)
        items = [make(r) for r in rows[offset:offset + limit]]
        return Page(items, len(rows), offset, offset + len(items) < len(rows))

    def functions(self, sha256: str, *, offset: int = 0, limit: int = 100) -> EngineResult[Page[FunctionInfo]]:
        t0 = time.monotonic()
        prep = self._prepare(sha256, t0)
        if isinstance(prep, EngineResult):
            return prep
        tdir, _ = prep
        try:
            rows = json.loads((tdir / "functions.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            return _fail(Status.ERROR, f"could not read functions.json: {e}", t0)
        page = self._page(rows, offset, limit, lambda r: FunctionInfo(r["address"], r["name"], r["size"]))
        return EngineResult(Status.OK, page, cached=True, duration_s=time.monotonic() - t0, untrusted_content=True)

    def strings(self, sha256: str, *, pattern: str | None = None, offset: int = 0,
                limit: int = 100) -> EngineResult[Page[StringInfo]]:
        t0 = time.monotonic()
        if pattern and len(pattern) > 512:
            return _fail(Status.ERROR, "regex too long (>512)", t0)
        try:
            rx = re.compile(pattern) if pattern else None
        except re.error as e:
            return _fail(Status.ERROR, f"invalid regex: {e}", t0)
        prep = self._prepare(sha256, t0)
        if isinstance(prep, EngineResult):
            return prep
        tdir, _ = prep
        try:
            rows = json.loads((tdir / "strings.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            return _fail(Status.ERROR, f"could not read strings.json: {e}", t0)
        if rx:
            rows = [r for r in rows if rx.search(r["value"])]
        page = self._page(rows, offset, limit,
                          lambda r: StringInfo(r["address"], r["length"], r["kind"], r["value"]))
        return EngineResult(Status.OK, page, cached=True, duration_s=time.monotonic() - t0, untrusted_content=True)

    def _query(self, sha: str, op: str, args: dict, t0: float) -> tuple[dict | None, EngineResult | None, bool]:
        """Result document (from cache or from the worker) or an error result. (doc, err, cached)."""
        prep = self._prepare(sha, t0)
        if isinstance(prep, EngineResult):
            return None, prep, False
        tdir, meta = prep
        key = sha256_hex(canonical({"op": op, "args": args, "rev": RESULT_REV}))
        rpath = tdir / "results" / f"{key}.json"
        try:
            cached = json.loads(rpath.read_text(encoding="utf-8"))
            if cached.get("key") == key:
                return cached["result"], None, True
        except (OSError, ValueError, KeyError):
            pass
        with _HEAVY:
            idb = tdir / meta["idb"]
            try:
                if _sha256_file(idb) != meta["idb_sha256"]:
                    (tdir / "meta.json").unlink(missing_ok=True)  # the next open_target re-analyzes
                    return None, _fail(Status.ERROR, "cached .i64 has changed (corrupt); invalidated", t0), False
            except OSError as e:
                return None, _fail(Status.ERROR, f"could not read .i64: {e}", t0), False
            st, doc, detail, _ = self._run(op, dict(args, target=str(idb)), self.query_timeout_s)
            if st is not Status.OK or doc is None:
                return None, _fail(st, f"{op} failed: {detail}", t0), False
            doc.pop("ok", None)
            atomic_write_bytes(rpath, canonical({"key": key, "result": doc}))
            return doc, None, False

    def decompile(self, sha256: str, function: int | str, *, max_chars: int = 200_000) -> EngineResult[DecompileInfo]:
        t0 = time.monotonic()
        doc, err, cached = self._query(sha256, "decompile", {"function": function}, t0)
        if err is not None:
            return err
        text = doc["text"]
        total = len(text)
        if total > max_chars:
            return EngineResult(Status.PARTIAL, DecompileInfo(doc["address"], doc["name"], text[:max_chars], total),
                                f"output truncated to {max_chars} characters (total {total})", cached,
                                time.monotonic() - t0, True)
        return EngineResult(Status.OK, DecompileInfo(doc["address"], doc["name"], text, total), "", cached,
                            time.monotonic() - t0, True)

    def xrefs(self, sha256: str, address: int, *, direction: str = "to", limit: int = 200) -> EngineResult[list[XrefInfo]]:
        t0 = time.monotonic()
        if direction not in ("to", "from"):
            return _fail(Status.ERROR, "direction must be 'to' or 'from'", t0)
        doc, err, cached = self._query(sha256, "xrefs", {"address": address, "direction": direction,
                                                         "limit": limit}, t0)
        if err is not None:
            return err
        items = [XrefInfo(x["from"], x["to"], x["kind"], x["is_code"], x["from_function"], x.get("to_name") or "",
                          x.get("to_string"), x.get("to_string_kind") or "") for x in doc["xrefs"]]
        if doc["total"] > len(items):
            return EngineResult(Status.PARTIAL, items, f"returned {len(items)} of {doc['total']} xrefs", cached,
                                time.monotonic() - t0, True)
        return EngineResult(Status.OK, items, "", cached, time.monotonic() - t0, True)

    def call_args(self, sha256: str, address: int) -> EngineResult[dict[int, int | None]]:
        t0 = time.monotonic()
        doc, err, cached = self._query(sha256, "callargs", {"address": int(address)}, t0)
        if err is not None:
            return err
        out, bad = call_args_from_doc(doc)
        if out is None:
            return _fail(Status.ERROR, f"call_args result inconsistent: {bad}", t0)
        return EngineResult(Status.OK, out, "", cached, time.monotonic() - t0, True)

    def disassemble(self, sha256: str, address: int, *, count: int = 200,
                    whole_function: bool = False) -> EngineResult[Disassembly]:
        t0 = time.monotonic()
        count = max(1, min(int(count), 20_000))
        doc, err, cached = self._query(sha256, "disassemble", {"address": int(address), "count": count,
                                                               "whole_function": bool(whole_function)}, t0)
        if err is not None:
            return err
        dis, bad = disassembly_from_doc(doc)
        if dis is None:
            return _fail(Status.ERROR, f"disassemble result inconsistent: {bad}", t0)
        st = Status.OK if dis.complete else Status.PARTIAL
        return EngineResult(st, dis, dis.stop_reason if not dis.complete else "", cached,
                            time.monotonic() - t0, True)
