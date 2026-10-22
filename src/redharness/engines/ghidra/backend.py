"""Ghidra headless backend (Java GhidraScript; does NOT depend on PyGhidra).

Each operation runs via `analyzeHeadless.bat` in a separate process tree under `core.proc.run_bounded` (Job Object:
memory + time + tree kill); JVM `-Xmx4g` (GHIDRA_HEADLESS_MAXMEM=4G), Job limit 6 GB (the heavy-engine memory budget).

Cache: `cache/ghidra/<ghidra_version>/<target_sha256>/` = {proj/ (Ghidra project), target.<extension>,
functions.json, strings.json, results/, meta.json}. On the FIRST open, import + full analysis (+ export) runs once;
all later queries open the SAME project with `-process -noanalysis -readOnly` (NO re-analysis). The project is built
in a temporary directory, `meta.json` is written last and the directory is moved into place atomically with
`os.replace`; a half-finished/failed analysis never enters the cache. The SHA-256 of the project data files is kept
in meta and verified on every query.

Result channel: the script writes its result NOT to stdout but to a separate JSON file (Ghidra log lines do not mix in).

--- Failure modes that are PREVENTED here ---
1. A result recovered after a timeout must not stay `ok:true`. The process status
   (`run_bounded`) is evaluated BEFORE the result file; on TIMEOUT/MEMORY_LIMIT/TOOL_MISSING/ERROR the result
   file is never read and `data=None` is returned. So "file complete but process killed" is never OK.
2. An existing output file must not count as clean success: file
   existence proves nothing. Every call uses a fresh working directory + a single-use `nonce`; the document is
   verified by `complete:true` (the field the script writes LAST), `op`, `nonce` and content counts (functions == len(...)).
   If the script crashes and Ghidra still says "Import succeeded" with exit code 0 (this really happens)
   there is no result file -> ERROR.
3. Truncated output (`output_truncated`) must not be ignored: DATA does not pass
   through stdout, so the stdout cap cannot truncate data; the data is in the file and verified with counts. stdout/stderr
   are diagnostics only (`extra["log_truncated"]` is flagged). If the decompile text exceeds `max_chars`, `Status.PARTIAL` is returned.
Additionally: `-analysisTimeoutPerFile` is NOT USED: the internal timeout may abort the analysis midway and say
"Save succeeded" with exit code 0 (silent partial analysis). The only timeout is the outer `run_bounded`; if exceeded,
the whole tree is killed and the cache is not written.
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
import re
import shutil
import time
import uuid
from pathlib import Path

from ...config import Config
from ...core.journal import atomic_write_bytes, canonical, sha256_hex
from ...core.lock import LockError
from ...core.proc import RunResult, run_bounded
from ...core.result import Status
from .._common import (HEAVY, SHA_RE, acquire_dir_lock, bodies_from_doc, call_args_from_doc, disassembly_from_doc, fail, make_page,
                       sha256_file)
from ..base import (DecompileInfo, Disassembly, Engine, EngineInfo, EngineResult, FunctionBodies, FunctionInfo, Page, StringInfo,
                    TargetInfo, XrefInfo)

ENV_GHIDRA_DIR = "RH_GHIDRA_DIR"
SCRIPTS_DIR = Path(__file__).with_name("scripts")
SCRIPT = "RHQuery.java"
PROJECT_NAME = "rh"
GB = 1024 ** 3
LOG_CAP = 2 * 1024 * 1024  # stdout/stderr diagnostic cap (head and tail separately); data does not pass through stdout
_DROP_ENV = {"GHIDRA_MAXMEM", "GHIDRA_HEADLESS_MAXMEM", "GHIDRA_JAVA_OPTIONS", "GHIDRA_HEADLESS_JAVA_OPTIONS",
             "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH", "PYTHONPATH", "PYTHONHOME"}
_VERSION_RE = re.compile(r"^application\.version=(\S+)\s*$", re.M)


def _is_ghidra_dir(p: Path) -> bool:
    return (p / "support" / "analyzeHeadless.bat").is_file() and (p / "Ghidra" / "application.properties").is_file()


def discover_ghidra_dir(explicit: str | os.PathLike | None = None) -> Path | None:
    cands: list[str] = []
    if explicit:
        cands.append(str(explicit))
    for var in (ENV_GHIDRA_DIR, "GHIDRA_INSTALL_DIR"):
        if os.environ.get(var):
            cands.append(os.environ[var])
    home = Path.home()
    for pat in (home / "Desktop" / "ghidra_*", home / "ghidra*", Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "ghidra*",
                Path("C:/ghidra*")):
        cands += sorted(glob.glob(str(pat)), reverse=True)
    for c in cands:
        p = Path(c)
        if _is_ghidra_dir(p):
            return p
    return None


GHIDRA_INSTALL_HELP = (
    "Download Ghidra 12.1.3 (the tested version) from https://github.com/NationalSecurityAgency/ghidra/releases, "
    "extract the zip and set RH_GHIDRA_DIR to the extracted folder (the one that contains support/analyzeHeadless.bat). "
    "Without RH_GHIDRA_DIR the folder is also found as ~/Desktop/ghidra_*, ~/ghidra*, %ProgramFiles%/ghidra* or C:/ghidra*. "
    "Ghidra needs a JDK 21 (for example Eclipse Temurin 21) on PATH or in JAVA_HOME. See docs/usage-mcp.md, section Engines.")
JDK_HELP = ("Ghidra needs a JDK 21 (for example Eclipse Temurin 21): install it and make sure `java -version` works in a "
            "new terminal, or set JAVA_HOME to the JDK folder.")


def _java_exe() -> str:
    """`java` from PATH, else JAVA_HOME/bin/java.exe, else plain `java` (the probe then reports it missing)."""
    if shutil.which("java"):
        return "java"
    home = os.environ.get("JAVA_HOME")
    if home:
        cand = Path(home) / "bin" / "java.exe"
        if cand.is_file():
            return str(cand)
    return "java"


def ghidra_version(ghidra_dir: Path) -> str:
    m = _VERSION_RE.search((ghidra_dir / "Ghidra" / "application.properties").read_text(encoding="utf-8", errors="replace"))
    return m.group(1) if m else ""


def _prop_escape(v) -> str:
    s = str(v).replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return ("\\" + s) if s.startswith(" ") else s


def project_digest(proj: Path) -> str:
    """Combined SHA-256 of the program's data files (idata/**/*.gbf, *.prp). Read-only queries do not
    modify them (only ~index.dat/.bak are rewritten)."""
    h = hashlib.sha256()
    for p in sorted(proj.rglob("*")):
        if p.is_file() and p.suffix in (".gbf", ".prp") and p.relative_to(proj).parts[:2] == (f"{PROJECT_NAME}.rep", "idata"):
            h.update(p.relative_to(proj).as_posix().encode() + b"\0")
            h.update(sha256_file(p).encode())
    return h.hexdigest()


class GhidraEngine(Engine):
    name = "ghidra"

    def __init__(self, config: Config | None = None, *, ghidra_dir: str | os.PathLike | None = None,
                 heap: str = "4G", memory_limit_bytes: int = 6 * GB, analyze_timeout_s: float = 1200,
                 query_timeout_s: float = 300, probe_timeout_s: float = 60, lock_wait_s: float = 120,
                 decompile_timeout_s: int = 120, scripts_dir: str | os.PathLike | None = None,
                 launcher: list[str] | None = None, probe_argv: list[str] | None = None):
        self.config = config or Config.load()
        self._dir_arg = ghidra_dir
        self.heap = heap
        self.memory_limit = memory_limit_bytes
        self.analyze_timeout_s = analyze_timeout_s
        self.query_timeout_s = query_timeout_s
        self.probe_timeout_s = probe_timeout_s
        self.lock_wait_s = lock_wait_s
        self.decompile_timeout_s = decompile_timeout_s
        self.scripts_dir = Path(scripts_dir) if scripts_dir else SCRIPTS_DIR
        self._launcher = launcher        # a fake process is injected in tests
        self._probe_argv = probe_argv
        self._info: EngineInfo | None = None

    # ------------------------------------------------------------------ environment
    @property
    def user_dir(self) -> Path:
        return self.config.data_root / "ghidra_user"

    def _env(self) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if k.upper() not in _DROP_ENV}
        settings, cache = self.user_dir / "settings", self.user_dir / "cache"
        settings.mkdir(parents=True, exist_ok=True)
        cache.mkdir(parents=True, exist_ok=True)
        # The user's global Ghidra settings (%APPDATA%\ghidra) are not used. JAVA_TOOL_OPTIONS supports quoted paths
        # with spaces (launch.bat's VMARG_LIST does not), so a directory with spaces works.
        env["JAVA_TOOL_OPTIONS"] = (f'-Dapplication.settingsdir="{settings.as_posix()}" '
                                    f'-Dapplication.cachedir="{cache.as_posix()}"')
        # To find the JVM, launch.bat calls LaunchSupport with `-save` and writes java_home.save to the USER's global
        # settings directory; LaunchSupport does not see settingsdir in JAVA_TOOL_OPTIONS, it does see XDG_CONFIG_HOME.
        env["XDG_CONFIG_HOME"] = (self.user_dir / "xdg").as_posix()
        env["GHIDRA_HEADLESS_MAXMEM"] = self.heap  # -> -Xmx4G
        env["PYTHONUTF8"] = "1"
        return env

    def _headless(self, ghidra_dir: Path | None) -> list[str] | None:
        if self._launcher is not None:
            return list(self._launcher)
        return [str(ghidra_dir / "support" / "analyzeHeadless.bat")] if ghidra_dir else None

    # ------------------------------------------------------------------ probe
    def probe(self) -> EngineInfo:
        if self._info is not None and self._info.available:
            return self._info
        d = discover_ghidra_dir(self._dir_arg)
        if d is None:
            self._info = EngineInfo("ghidra", False, "", "Ghidra unavailable: install directory not found. " + GHIDRA_INSTALL_HELP)
            return self._info
        ver = ghidra_version(d)
        if not ver:
            self._info = EngineInfo("ghidra", False, "", f"Ghidra unavailable: could not read version ({d})")
            return self._info
        # Real probe: Ghidra's own LaunchSupport tells which JDK it will use (fails if there is no JDK 21).
        argv = self._probe_argv or [_java_exe(), "-cp", str(d / "support" / "LaunchSupport.jar"), "LaunchSupport",
                                    str(d), "-jdk_home"]
        rr = run_bounded(argv, timeout_s=self.probe_timeout_s, memory_limit_bytes=1 * GB, env=self._env(),
                         head_bytes=8192, tail_bytes=8192)
        jdk = [ln.strip() for ln in rr.stdout.decode("utf-8", "replace").splitlines()
               if ln.strip() and not ln.startswith("Picked up")]
        if rr.status is not Status.OK or rr.exit_code != 0 or not jdk or not Path(jdk[-1]).exists():
            self._info = EngineInfo("ghidra", False, ver, f"Ghidra unavailable: JDK not found/did not run "
                                    f"({rr.status.value}: {rr.detail}) {rr.stderr[-200:].decode('utf-8', 'replace')}. {JDK_HELP}".strip())
            return self._info
        self._info = EngineInfo("ghidra", True, ver, f"JDK: {jdk[-1]}; dir: {d}")
        return self._info

    def _tdir(self, version: str, sha: str) -> Path:
        return self.config.cache_dir / "ghidra" / version / sha

    # ------------------------------------------------------------------ process
    def _run(self, op: str, req: dict, proj_parent: Path, mode: list[str], timeout_s: float, *,
             validate) -> tuple[Status, dict | None, str, RunResult | None]:
        """Runs the script bounded. Only (OK, document) is success. The process status is checked BEFORE the result file."""
        launcher = self._headless(discover_ghidra_dir(self._dir_arg))
        if launcher is None:
            return Status.TOOL_MISSING, None, "Ghidra unavailable: install directory not found. " + GHIDRA_INSTALL_HELP, None
        work = self.config.work_dir / f"ghidra-{uuid.uuid4().hex}"
        work.mkdir(parents=True, exist_ok=True)
        try:
            nonce = uuid.uuid4().hex
            result_path = work / "result.json"
            req = dict(req, op=op, nonce=nonce, result=result_path.as_posix())
            req_path = work / "req.properties"
            req_path.write_text("".join(f"{k}={_prop_escape(v)}\n" for k, v in req.items()), encoding="utf-8")
            argv = launcher + [proj_parent.as_posix(), PROJECT_NAME, *mode, "-scriptPath", str(self.scripts_dir),
                               "-postScript", SCRIPT, req_path.as_posix()]
            rr = run_bounded(argv, timeout_s=timeout_s, memory_limit_bytes=self.memory_limit, env=self._env(),
                             cwd=str(work), head_bytes=LOG_CAP, tail_bytes=LOG_CAP)
            # Process status FIRST: on timeout/memory/crash the result file is NOT read, whatever it
            # contains (even if fully written).
            if rr.status in (Status.TIMEOUT, Status.MEMORY_LIMIT, Status.TOOL_MISSING):
                return rr.status, None, rr.detail, rr
            if rr.exit_code != 0 or rr.status not in (Status.OK, Status.PARTIAL):
                return Status.ERROR, None, f"Ghidra did not exit cleanly ({rr.status.value}: {rr.detail}) {self._tail(rr)}".strip(), rr
            # rr.status PARTIAL = only the stdout/stderr diagnostic output was truncated (data does not pass through this channel).
            doc = None
            if result_path.is_file():
                try:
                    doc = json.loads(result_path.read_text(encoding="utf-8"))
                except ValueError:
                    doc = None
            if not isinstance(doc, dict):
                # On a script error Ghidra also says exit code 0 + "Import succeeded"; hence the file is mandatory.
                return Status.ERROR, None, f"script result file missing/corrupt {self._tail(rr)}".strip(), rr
            if doc.get("complete") is not True or doc.get("op") != op or doc.get("nonce") != nonce:
                return Status.ERROR, None, "result document incomplete/foreign (complete/op/nonce mismatch)", rr
            if doc.get("ok") is False:
                err = str(doc.get("error", ""))
                st = (Status.TIMEOUT if "DECOMPILE_TIMEOUT" in err else
                      Status.TOOL_MISSING if "DECOMPILER_UNAVAILABLE" in err else Status.ERROR)
                return st, None, f"script error: {err}", rr
            if doc.get("ok") is not True:
                return Status.ERROR, None, "no ok in result document", rr
            bad = validate(doc)
            if bad:
                return Status.ERROR, None, f"result document inconsistent (truncated/partial): {bad}", rr
            return Status.OK, doc, "", rr
        finally:
            shutil.rmtree(work, ignore_errors=True)

    @staticmethod
    def _tail(rr: RunResult) -> str:
        return (rr.stderr[-300:].decode("utf-8", "replace") + rr.stdout[-300:].decode("utf-8", "replace"))

    @staticmethod
    def _valid_analyze(doc: dict) -> str:
        try:
            c = doc["counts"]
            if c["functions"] != len(doc["functions"]) or c["strings"] != len(doc["strings"]):
                return "counts mismatch"
            if doc["info"].get("still_analyzing") is not False:
                return "analysis appears to be still running"
            if not doc["functions"]:
                return "function list empty"
        except (KeyError, TypeError):
            return "field missing"
        return ""

    @staticmethod
    def _valid_decompile(doc: dict) -> str:
        return "" if all(k in doc for k in ("address", "name", "text")) and isinstance(doc["text"], str) else "field missing"

    @staticmethod
    def _valid_xrefs(doc: dict) -> str:
        try:
            if doc["counts"]["xrefs"] != len(doc["xrefs"]) or doc["total"] < len(doc["xrefs"]):
                return "counts mismatch"
        except (KeyError, TypeError):
            return "field missing"
        return ""

    @staticmethod
    def _valid_disassemble(doc: dict) -> str:
        try:
            if doc["counts"]["insns"] != len(doc["insns"]):
                return "counts mismatch"
        except (KeyError, TypeError):
            return "field missing"
        return ""

    # ------------------------------------------------------------------ cache
    def _meta(self, tdir: Path, sha: str) -> dict | None:
        try:
            meta = json.loads((tdir / "meta.json").read_text(encoding="utf-8"))
            if (meta.get("sha256") == sha and (tdir / "proj" / f"{PROJECT_NAME}.rep").is_dir()
                    and (tdir / "functions.json").is_file() and (tdir / "strings.json").is_file()):
                return meta
        except (OSError, ValueError, KeyError):
            pass
        return None

    @staticmethod
    def _target_info(meta: dict) -> TargetInfo:
        i = meta["info"]
        return TargetInfo(meta["sha256"], meta["source_path"], i.get("arch", ""), i.get("bits", 0),
                          i.get("entry"), meta["function_count"], meta["string_count"], bool(i.get("decompiler")),
                          i.get("imagebase"))

    # ------------------------------------------------------------------ open_target
    def open_target(self, path: str | Path) -> EngineResult[TargetInfo]:
        t0 = time.monotonic()
        info = self.probe()
        if not info.available:
            return fail(Status.TOOL_MISSING, info.detail or "Ghidra unavailable", t0)
        src = Path(path)
        if not src.is_file():
            return fail(Status.ERROR, f"target file does not exist: {src}", t0)
        try:
            sha = sha256_file(src)
        except OSError as e:
            return fail(Status.ERROR, f"could not read target: {e}", t0)
        tdir = self._tdir(info.version, sha)
        with HEAVY:
            try:
                tdir.parent.mkdir(parents=True, exist_ok=True)
                lock = acquire_dir_lock(tdir, self.lock_wait_s)
            except (LockError, OSError) as e:
                return fail(Status.ERROR, f"could not acquire cache lock: {e}", t0)
            try:
                meta = self._meta(tdir, sha)
                if meta:
                    return EngineResult(Status.OK, self._target_info(meta), cached=True,
                                        duration_s=time.monotonic() - t0,
                                        extra={"external_function_count": meta["info"].get("external_function_count")})
                return self._analyze(src, sha, tdir, info.version, t0)
            finally:
                lock.release()

    def _analyze(self, src: Path, sha: str, tdir: Path, version: str, t0: float) -> EngineResult[TargetInfo]:
        shutil.rmtree(tdir, ignore_errors=True)  # half-finished/corrupt previous attempt
        for stale in tdir.parent.glob(tdir.name + ".partial-*"):  # left by an analysis whose server was killed (we hold the cache lock)
            shutil.rmtree(stale, ignore_errors=True)
        tmp = tdir.with_name(f"{tdir.name}.partial-{uuid.uuid4().hex[:8]}")
        tmp.mkdir(parents=True)
        suffix = src.suffix.lower() if re.fullmatch(r"\.[a-z0-9]{1,8}", src.suffix.lower()) else ""
        program = "target" + suffix
        copy = tmp / program
        try:
            shutil.copyfile(src, copy)
            if sha256_file(copy) != sha:  # identity pinning: the copy must be identical to the target
                shutil.rmtree(tmp, ignore_errors=True)
                return fail(Status.ERROR, "ARTIFACT_CHANGED: copy SHA-256 mismatch (target changed during analysis)", t0)
            (tmp / "proj").mkdir()
        except OSError as e:
            shutil.rmtree(tmp, ignore_errors=True)
            return fail(Status.ERROR, f"could not copy target: {e}", t0)
        ta = time.monotonic()
        st, doc, detail, rr = self._run("analyze", {}, tmp / "proj", ["-import", copy.as_posix()],
                                        self.analyze_timeout_s, validate=self._valid_analyze)
        analysis_s = time.monotonic() - ta
        if st is not Status.OK or doc is None:
            shutil.rmtree(tmp, ignore_errors=True)  # no partial project is left behind
            return fail(st, f"analysis failed: {detail}", t0)
        try:
            if not (tmp / "proj" / f"{PROJECT_NAME}.rep").is_dir():
                raise OSError("Ghidra project was not created")
            atomic_write_bytes(tmp / "functions.json", canonical(doc["functions"]))
            atomic_write_bytes(tmp / "strings.json", canonical(doc["strings"]))
            meta = {"sha256": sha, "source_path": str(src), "program": program, "ghidra_version": version,
                    "project_digest": project_digest(tmp / "proj"), "info": doc["info"],
                    "function_count": len(doc["functions"]), "string_count": len(doc["strings"]),
                    "analysis_s": round(analysis_s, 2), "peak_job_memory": rr.peak_job_memory if rr else None}
            atomic_write_bytes(tmp / "meta.json", canonical(meta))  # completion marker: written last
            os.replace(tmp, tdir)  # atomic placement
        except OSError as e:
            shutil.rmtree(tmp, ignore_errors=True)
            return fail(Status.ERROR, f"could not write cache: {e}", t0)
        return EngineResult(Status.OK, self._target_info(meta), cached=False, duration_s=time.monotonic() - t0,
                            extra={"analysis_s": meta["analysis_s"], "peak_job_memory": meta["peak_job_memory"],
                                   "external_function_count": doc["info"].get("external_function_count"),
                                   "log_truncated": bool(rr and rr.truncated)})

    # ------------------------------------------------------------------ queries
    def _prepare(self, sha: str, t0: float):
        if not SHA_RE.match(sha or ""):
            return fail(Status.ERROR, "invalid sha256", t0)
        info = self.probe()
        if not info.available:
            return fail(Status.TOOL_MISSING, info.detail or "Ghidra unavailable", t0)
        tdir = self._tdir(info.version, sha)
        meta = self._meta(tdir, sha)
        if meta is None:
            return fail(Status.ERROR, "target not analyzed/cache invalid (run open_target first)", t0)
        return tdir, meta

    def _rows(self, sha: str, fname: str, t0: float):
        prep = self._prepare(sha, t0)
        if isinstance(prep, EngineResult):
            return prep
        tdir, _ = prep
        try:
            return json.loads((tdir / fname).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            return fail(Status.ERROR, f"could not read {fname}: {e}", t0)

    def functions(self, sha256: str, *, offset: int = 0, limit: int = 100) -> EngineResult[Page[FunctionInfo]]:
        t0 = time.monotonic()
        rows = self._rows(sha256, "functions.json", t0)
        if isinstance(rows, EngineResult):
            return rows
        page = make_page(rows, offset, limit, lambda r: FunctionInfo(r["address"], r["name"], r["size"]))
        return EngineResult(Status.OK, page, cached=True, duration_s=time.monotonic() - t0, untrusted_content=True)

    def strings(self, sha256: str, *, pattern: str | None = None, offset: int = 0,
                limit: int = 100) -> EngineResult[Page[StringInfo]]:
        t0 = time.monotonic()
        if pattern and len(pattern) > 512:
            return fail(Status.ERROR, "regex too long (>512)", t0)
        try:
            rx = re.compile(pattern) if pattern else None
        except re.error as e:
            return fail(Status.ERROR, f"invalid regex: {e}", t0)
        rows = self._rows(sha256, "strings.json", t0)
        if isinstance(rows, EngineResult):
            return rows
        if rx:
            rows = [r for r in rows if rx.search(r["value"])]
        page = make_page(rows, offset, limit, lambda r: StringInfo(r["address"], r["length"], r["kind"], r["value"]))
        return EngineResult(Status.OK, page, cached=True, duration_s=time.monotonic() - t0, untrusted_content=True)

    def _query(self, sha: str, op: str, args: dict, req: dict, validate, t0: float):
        """(doc, error_result, cached). Result cache: the same query does not start a new JVM."""
        prep = self._prepare(sha, t0)
        if isinstance(prep, EngineResult):
            return None, prep, False
        tdir, meta = prep
        key = sha256_hex(canonical({"op": op, "args": args}))
        rpath = tdir / "results" / f"{key}.json"
        try:
            cached = json.loads(rpath.read_text(encoding="utf-8"))
            if cached.get("key") == key:
                return cached["result"], None, True
        except (OSError, ValueError, KeyError):
            pass
        with HEAVY:
            try:
                lock = acquire_dir_lock(tdir, self.lock_wait_s)  # two JVMs must not open the same project at once
            except (LockError, OSError) as e:
                return None, fail(Status.ERROR, f"could not acquire cache lock: {e}", t0), False
            try:
                if project_digest(tdir / "proj") != meta["project_digest"]:
                    (tdir / "meta.json").unlink(missing_ok=True)  # the next open_target re-analyzes
                    return None, fail(Status.ERROR, "cached Ghidra project has changed (corrupt); invalidated", t0), False
                st, doc, detail, _ = self._run(op, req, tdir / "proj",
                                               ["-process", meta["program"], "-noanalysis", "-readOnly"],
                                               self.query_timeout_s, validate=validate)
                if st is not Status.OK or doc is None:
                    return None, fail(st, f"{op} failed: {detail}", t0), False
                for k in ("ok", "complete", "nonce", "op"):
                    doc.pop(k, None)
                atomic_write_bytes(rpath, canonical({"key": key, "result": doc}))
                return doc, None, False
            finally:
                lock.release()

    def decompile(self, sha256: str, function: int | str, *, max_chars: int = 200_000) -> EngineResult[DecompileInfo]:
        t0 = time.monotonic()
        req = {"function_name": function} if isinstance(function, str) else {"function_addr": int(function)}
        req["decompile_timeout"] = self.decompile_timeout_s
        doc, err, cached = self._query(sha256, "decompile", {"function": function}, req, self._valid_decompile, t0)
        if err is not None:
            return err
        text = doc["text"]
        total = len(text)
        if total > max_chars:  # truncated output is never OK
            return EngineResult(Status.PARTIAL, DecompileInfo(doc["address"], doc["name"], text[:max_chars], total),
                                f"output truncated to {max_chars} characters (total {total})", cached,
                                time.monotonic() - t0, True)
        return EngineResult(Status.OK, DecompileInfo(doc["address"], doc["name"], text, total), "", cached,
                            time.monotonic() - t0, True)

    def xrefs(self, sha256: str, address: int, *, direction: str = "to", limit: int = 200) -> EngineResult[list[XrefInfo]]:
        t0 = time.monotonic()
        if direction not in ("to", "from"):
            return fail(Status.ERROR, "direction must be 'to' or 'from'", t0)
        args = {"address": int(address), "direction": direction, "limit": int(limit), "rev": 2}   # rev 2: to_name/to_string
        doc, err, cached = self._query(sha256, "xrefs", args, args, self._valid_xrefs, t0)
        if err is not None:
            return err
        items = [XrefInfo(x["from"], x["to"], x["kind"], x["is_code"], x["from_function"], x.get("to_name") or "",
                          x.get("to_string"), x.get("to_string_kind") or "") for x in doc["xrefs"]]
        if doc["total"] > len(items):
            return EngineResult(Status.PARTIAL, items, f"returned {len(items)} of {doc['total']} xrefs", cached,
                                time.monotonic() - t0, True)
        return EngineResult(Status.OK, items, "", cached, time.monotonic() - t0, True)

    @staticmethod
    def _valid_callargs(doc: dict) -> str:
        try:
            if doc["counts"]["calls"] != len(doc["calls"]):
                return "counts mismatch"
        except (KeyError, TypeError):
            return "field missing"
        return ""

    def decode(self, sha256: str, address: int, *, count: int = 64) -> EngineResult[Disassembly]:
        t0 = time.monotonic()
        count = max(1, min(int(count), 512))
        args = {"address": int(address), "count": count, "rev": 1}
        doc, err, cached = self._query(sha256, "decode", args, {"address": int(address), "count": count},
                                       self._valid_disassemble, t0)
        if err is not None:
            return err
        dis, bad = disassembly_from_doc(doc)
        if dis is None:
            return fail(Status.ERROR, f"decode result inconsistent: {bad}", t0)
        return EngineResult(Status.OK if dis.complete else Status.PARTIAL, dis, dis.stop_reason, cached,
                            time.monotonic() - t0, True)

    def call_args(self, sha256: str, address: int) -> EngineResult[dict[int, int | None]]:
        t0 = time.monotonic()
        args = {"address": int(address), "rev": 1}
        doc, err, cached = self._query(sha256, "callargs", args, {"address": int(address)}, self._valid_callargs, t0)
        if err is not None:
            return err
        out, bad = call_args_from_doc(doc)
        if out is None:
            return fail(Status.ERROR, f"call_args result inconsistent: {bad}", t0)
        return EngineResult(Status.OK, out, "", cached, time.monotonic() - t0, True)

    @staticmethod
    def _valid_bodies(doc: dict) -> str:
        try:
            if doc["counts"]["functions"] != len(doc["functions"]):
                return "counts mismatch"
            if any(f["counts"]["insns"] != len(f["insns"]) for f in doc["functions"]):
                return "instruction counts mismatch"
        except (KeyError, TypeError):
            return "field missing"
        return ""

    def disassemble_functions(self, sha256: str, *, first: int = 0,
                              max_insns: int = 60_000) -> EngineResult[FunctionBodies]:
        t0 = time.monotonic()
        args = {"first": max(0, int(first)), "max_insns": max(1, min(int(max_insns), 200_000)), "rev": 1}
        doc, err, cached = self._query(sha256, "disasm_funcs", args, {k: v for k, v in args.items() if k != "rev"},
                                       self._valid_bodies, t0)
        if err is not None:
            return err
        bodies, bad = bodies_from_doc(doc)
        if bodies is None:
            return fail(Status.ERROR, f"disassemble_functions result inconsistent: {bad}", t0)
        return EngineResult(Status.OK, bodies, "", cached, time.monotonic() - t0, True)

    def disassemble(self, sha256: str, address: int, *, count: int = 200,
                    whole_function: bool = False) -> EngineResult[Disassembly]:
        t0 = time.monotonic()
        count = max(1, min(int(count), 20_000))
        args = {"address": int(address), "count": count, "whole_function": bool(whole_function)}
        req = dict(args, whole_function="true" if whole_function else "false")
        doc, err, cached = self._query(sha256, "disassemble", args, req, self._valid_disassemble, t0)
        if err is not None:
            return err
        dis, bad = disassembly_from_doc(doc)
        if dis is None:
            return fail(Status.ERROR, f"disassemble result inconsistent: {bad}", t0)
        st = Status.OK if dis.complete else Status.PARTIAL
        return EngineResult(st, dis, dis.stop_reason if not dis.complete else "", cached,
                            time.monotonic() - t0, True)
