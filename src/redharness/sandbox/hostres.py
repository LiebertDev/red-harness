"""Host-side guards around starting Windows Sandbox: memory headroom pre-check, persisted retry backoff and
detection/closing of the sandbox error dialog that WE launched.

Why: the Hyper-V worker can refuse to create the VM partition ("Failed to create partition: not enough system
resources", HRESULT 0x800705AA), and consecutive starts then tend to fail together. `WindowsSandbox.exe` does NOT exit on
this error: it stays alive showing a Yes/No dialog ("failed to start ... send feedback?"), so without detection the
dialog stays on screen and the runner only notices after its full timeout. Nothing here touches processes or windows
the caller did not name explicitly.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

DEFAULT_MIN_HEADROOM_MB = 1024     # available RAM / commit that must remain ABOVE the sandbox's own memory request
ENV_MIN_HEADROOM_MB = "RH_SANDBOX_MIN_HEADROOM_MB"
ENV_STATE_DIR = "RH_STATE_DIR"     # machine-wide state dir override (tests)
BACKOFF_FILE = "sandbox_resource_backoff.json"
COOLDOWN_AFTER_FAILURES = 3        # consecutive failed launches before the runner stops launching altogether
COOLDOWN_S = 600.0                 # ... for this long
DIALOG_CLASS = "#32770"            # standard Win32 dialog / MessageBox
IDNO = 7                           # MessageBox "No" button id (locale independent)
_WM_COMMAND = 0x0111
_HEX_ERROR = re.compile(r"0x[0-9a-fA-F]{6,8}")   # the error text carries a hex HRESULT in every locale


def min_headroom_mb() -> int:
    raw = os.environ.get(ENV_MIN_HEADROOM_MB)
    try:
        v = int(raw) if raw else DEFAULT_MIN_HEADROOM_MB
    except ValueError:
        return DEFAULT_MIN_HEADROOM_MB
    return v if 0 <= v <= 65536 else DEFAULT_MIN_HEADROOM_MB


def state_dir() -> Path:
    """Machine-wide state directory (NOT the per-run data root: eval runs use one data root each, which would reset
    every counter kept there). RH_STATE_DIR, else %LOCALAPPDATA%/RedHarness, else ~/.redharness."""
    env = os.environ.get(ENV_STATE_DIR)
    if env:
        return Path(env)
    base = os.environ.get("LOCALAPPDATA")
    return Path(base) / "RedHarness" if base else Path.home() / ".redharness"


def default_backoff(base_s: float, cap_mult: float = 6.0) -> "Backoff":
    return Backoff(state_dir() / BACKOFF_FILE, base_s, cap_mult)


def describe_memory(status: dict | None) -> str:
    """One line with every measured memory figure, for failure details (diagnosis only; no figure predicts the failure)."""
    if not status:
        return "memory unknown"
    keys = (("avail_phys_mb", "available"), ("free_zero_mb", "free+zeroed"), ("standby_mb", "standby"),
            ("avail_commit_mb", "commit available"))
    return ", ".join(f"{label} {status[k]} MB" for k, label in keys if isinstance(status.get(k), int))


# ---------------------------------------------------------------- memory

def _page_lists_mb() -> dict:
    """Free + zeroed and standby page lists in MB (NtQuerySystemInformation SystemMemoryListInformation); {} if the
    call is refused. 'Available' = free + zeroed + STANDBY: standby pages are cache that must first be repurposed,
    so 'available' overstates what a new VM partition can take immediately."""
    import ctypes
    sz = ctypes.c_size_t

    class SMLI(ctypes.Structure):
        _fields_ = [("zero", sz), ("free", sz), ("modified", sz), ("modified_nowrite", sz), ("bad", sz),
                    ("standby_by_prio", sz * 8), ("repurposed_by_prio", sz * 8), ("modified_pagefile", sz)]
    st = SMLI()
    try:
        if ctypes.windll.ntdll.NtQuerySystemInformation(80, ctypes.byref(st), ctypes.sizeof(st), None) != 0:
            return {}
    except (OSError, AttributeError):
        return {}
    page_mb = 4096 / (1 << 20)
    return {"free_zero_mb": int((st.zero + st.free) * page_mb), "standby_mb": int(sum(st.standby_by_prio) * page_mb)}

def memory_status() -> dict | None:
    """{'avail_phys_mb', 'total_phys_mb', 'avail_commit_mb'} via GlobalMemoryStatusEx (+ 'free_zero_mb', 'standby_mb'
    when the page-list query works); None if unavailable."""
    if sys.platform != "win32":
        return None
    import ctypes

    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [("dwLength", ctypes.c_uint32), ("dwMemoryLoad", ctypes.c_uint32),
                    ("ullTotalPhys", ctypes.c_uint64), ("ullAvailPhys", ctypes.c_uint64),
                    ("ullTotalPageFile", ctypes.c_uint64), ("ullAvailPageFile", ctypes.c_uint64),
                    ("ullTotalVirtual", ctypes.c_uint64), ("ullAvailVirtual", ctypes.c_uint64),
                    ("ullAvailExtendedVirtual", ctypes.c_uint64)]
    st = MEMORYSTATUSEX()
    st.dwLength = ctypes.sizeof(st)
    try:
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
            return None
    except (OSError, AttributeError):
        return None
    mb = 1 << 20
    return {"avail_phys_mb": st.ullAvailPhys // mb, "total_phys_mb": st.ullTotalPhys // mb,
            "avail_commit_mb": st.ullAvailPageFile // mb, **_page_lists_mb()}


def headroom_problem(status: dict | None, need_mb: int, headroom_mb: int | None = None) -> str | None:
    """Text if available RAM or commit is below need_mb + headroom_mb (a start would almost certainly fail), else None.
    Unknown status (None / missing keys) is never a reason to refuse: the check only blocks on a measured shortfall."""
    if not status:
        return None
    headroom = min_headroom_mb() if headroom_mb is None else headroom_mb
    need = int(need_mb) + int(headroom)
    for key, label in (("avail_phys_mb", "available RAM"), ("avail_commit_mb", "available commit (RAM + pagefile)")):
        have = status.get(key)
        if isinstance(have, int) and have < need:
            return (f"{label} {have} MB is below the {need} MB needed ({need_mb} MB sandbox + {headroom} MB headroom); "
                    "sandbox not started")
    return None


# ---------------------------------------------------------------- persisted backoff

@dataclass
class Backoff:
    """Consecutive failed-start counter persisted in the MACHINE-WIDE state dir (see state_dir), shared by every run,
    data root and process. Delay = base * 2**(failures-1), capped at base * cap_mult. After `cooldown_after`
    consecutive failures the delay becomes `cooldown_s`: callers must then refuse to launch at all (`cooling_down`)."""
    path: Path
    base_s: float
    cap_mult: float = 6.0
    cooldown_after: int = COOLDOWN_AFTER_FAILURES
    cooldown_s: float = COOLDOWN_S
    clock: Callable[[], float] = time.time

    def _load(self) -> dict:
        try:
            d = json.loads(self.path.read_text(encoding="ascii"))
            return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def remaining(self) -> float:
        until = self._load().get("until")
        return max(0.0, float(until) - self.clock()) if isinstance(until, (int, float)) else 0.0

    def failures(self) -> int:
        n = self._load().get("failures")
        return n if isinstance(n, int) and n > 0 else 0

    def cooling_down(self) -> bool:
        """True while the long cool-down after repeated failures is running (no launch may be attempted)."""
        return self.failures() >= self.cooldown_after and self.remaining() > 0

    def record_failure(self) -> float:
        n = self.failures() + 1
        if n >= self.cooldown_after:
            delay = self.cooldown_s
        else:
            delay = min(self.base_s * (2 ** (n - 1)), self.base_s * self.cap_mult)
        self._save({"failures": n, "until": self.clock() + delay})
        return delay

    def record_success(self) -> None:
        if self.failures():
            self._save({"failures": 0, "until": 0})

    def _save(self, doc: dict) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_name(self.path.name + f".{os.getpid()}.tmp")
            tmp.write_text(json.dumps(doc), encoding="ascii")
            os.replace(tmp, self.path)
        except OSError:
            pass   # backoff is best effort; it must never fail a run


# ---------------------------------------------------------------- error dialog (owned PIDs only)

@dataclass(frozen=True)
class Dialog:
    hwnd: int
    pid: int
    text: str


def _real_windows() -> list[tuple[int, int, str, str, str]]:
    """Visible top-level windows as (hwnd, pid, class, title, all child static text)."""
    import ctypes
    from ctypes import wintypes
    user32 = ctypes.windll.user32
    cb_t = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    out: list[tuple[int, int, str, str, str]] = []

    def text_of(h) -> str:
        buf = ctypes.create_unicode_buffer(1024)
        user32.GetWindowTextW(h, buf, 1024)
        return buf.value

    def class_of(h) -> str:
        buf = ctypes.create_unicode_buffer(256)
        user32.GetClassNameW(h, buf, 256)
        return buf.value

    def top(h, _l):
        if user32.IsWindowVisible(h):
            pid = wintypes.DWORD(0)
            user32.GetWindowThreadProcessId(h, ctypes.byref(pid))
            kids: list[str] = []
            user32.EnumChildWindows(h, cb_t(lambda c, _x: (kids.append(text_of(c)), True)[1]), 0)
            out.append((int(h), pid.value, class_of(h), text_of(h), " ".join(k for k in kids if k)))
        return True

    user32.EnumWindows(cb_t(top), 0)
    return out


def find_error_dialogs(pids: set[int], windows: Callable[[], list] | None = None) -> list[Dialog]:
    """Standard dialogs owned by one of `pids` whose text carries a hex error code. Windows of other processes are
    never returned, whatever they show."""
    if not pids:
        return []
    try:
        wins = (windows or _real_windows)()
    except Exception:  # noqa: BLE001 - window enumeration trouble means 'unknown', not 'failed start'
        return []
    found = []
    for hwnd, pid, cls, title, body in wins:
        if pid in pids and cls == DIALOG_CLASS and _HEX_ERROR.search(body or ""):
            found.append(Dialog(hwnd, pid, " ".join(body.split())[:300]))
    return found


def press_no(hwnd: int) -> bool:
    """Answers the dialog's 'No' (do not send feedback) button without touching its process."""
    try:
        import ctypes
        return bool(ctypes.windll.user32.PostMessageW(hwnd, _WM_COMMAND, IDNO, 0))
    except (OSError, AttributeError):
        return False
