"""Keeps the Windows Sandbox window from stealing focus (best effort, Windows only, ctypes only).

RH_SANDBOX_WINDOW=minimized (default) | normal. In `minimized` mode the launcher starts WindowsSandbox.exe with
SW_SHOWMINNOACTIVE and a bounded background watcher minimizes (without activating) every new top-level window of the
sandbox processes and gives the focus back to the previous foreground window if a sandbox window took it. Windows 10
may still flash the window briefly. Pure ctypes (EnumWindows, Toolhelp snapshot): the watcher spawns no subprocess. Nothing here ever raises into the run path."""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
from typing import Callable

log = logging.getLogger(__name__)

ENV_WINDOW = "RH_SANDBOX_WINDOW"
SW_SHOWMINNOACTIVE = 7
POLL_S = 0.2
WATCH_S = 60.0
TH32CS_SNAPPROCESS = 0x2


def expand_pids(roots: set[int], table: list[tuple[int, int, str]], name_prefix: str = "",
                exclude: frozenset[int] | set[int] = frozenset()) -> set[int]:
    """roots + all their descendants (parent-PID walk) + processes whose exe name starts with name_prefix
    (case-insensitive) that were not running before launch (`exclude`)."""
    own = set(roots)
    pref = name_prefix.lower()
    if pref:
        own |= {p for p, _pp, n in table if n.lower().startswith(pref) and p not in exclude}
    kids: dict[int, list[int]] = {}
    for p, pp, _n in table:
        kids.setdefault(pp, []).append(p)
    todo = list(own)
    while todo:
        for k in kids.get(todo.pop(), ()):
            if k not in own and k not in exclude:
                own.add(k)
                todo.append(k)
    return own


def mode() -> str:
    v = (os.environ.get(ENV_WINDOW) or "minimized").strip().lower()
    return "normal" if v == "normal" else "minimized"


def enabled() -> bool:
    return sys.platform == "win32" and mode() == "minimized"


def startupinfo():
    """subprocess STARTUPINFO that starts the process minimized and not activated; None when not applicable."""
    if not enabled():
        return None
    try:
        import subprocess
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = SW_SHOWMINNOACTIVE
        return si
    except Exception:  # noqa: BLE001
        return None


class _Win32:
    """Thin ctypes wrapper; replaceable in tests."""

    def __init__(self):
        import ctypes
        from ctypes import wintypes
        self._c, self._w = ctypes, wintypes
        self.user32 = ctypes.windll.user32

    def top_windows(self) -> list[tuple[int, int]]:
        c, w = self._c, self._w
        out: list[tuple[int, int]] = []
        cb_t = c.WINFUNCTYPE(w.BOOL, w.HWND, w.LPARAM)

        def cb(h, _l):
            pid = w.DWORD()
            self.user32.GetWindowThreadProcessId(h, c.byref(pid))
            if self.user32.IsWindowVisible(h):
                out.append((int(h), int(pid.value)))
            return True
        self.user32.EnumWindows(cb_t(cb), 0)
        return out

    def process_table(self) -> list[tuple[int, int, str]]:
        """(pid, parent pid, exe name) of all processes via CreateToolhelp32Snapshot; no subprocess."""
        c, w = self._c, self._w

        class PROCESSENTRY32W(c.Structure):
            _fields_ = [("dwSize", w.DWORD), ("cntUsage", w.DWORD), ("th32ProcessID", w.DWORD),
                        ("th32DefaultHeapID", c.c_size_t), ("th32ModuleID", w.DWORD), ("cntThreads", w.DWORD),
                        ("th32ParentProcessID", w.DWORD), ("pcPriClassBase", c.c_long), ("dwFlags", w.DWORD),
                        ("szExeFile", c.c_wchar * 260)]
        k32 = c.windll.kernel32
        k32.CreateToolhelp32Snapshot.restype = w.HANDLE
        k32.CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]
        k32.Process32FirstW.argtypes = k32.Process32NextW.argtypes = [w.HANDLE, c.POINTER(PROCESSENTRY32W)]
        k32.CloseHandle.argtypes = [w.HANDLE]
        snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if not snap or int(snap) == -1:
            return []
        out: list[tuple[int, int, str]] = []
        try:
            e = PROCESSENTRY32W()
            e.dwSize = c.sizeof(e)
            ok = k32.Process32FirstW(snap, c.byref(e))
            while ok:
                out.append((int(e.th32ProcessID), int(e.th32ParentProcessID), e.szExeFile))
                ok = k32.Process32NextW(snap, c.byref(e))
        finally:
            k32.CloseHandle(snap)
        return out

    def foreground(self) -> int:
        return int(self.user32.GetForegroundWindow() or 0)

    def window_pid(self, hwnd: int) -> int:
        pid = self._w.DWORD()
        self.user32.GetWindowThreadProcessId(hwnd, self._c.byref(pid))
        return int(pid.value)

    def minimize(self, hwnd: int) -> None:
        self.user32.ShowWindowAsync(hwnd, SW_SHOWMINNOACTIVE)

    def set_foreground(self, hwnd: int) -> None:
        """SetForegroundWindow is ignored when the caller is not the foreground process, which is exactly the case
        once a sandbox window has taken the foreground (the sandbox host is also elevated, so attaching input queues
        does not help). Escalation: plain call, then a synthetic Alt key press (makes this process the last input
        owner), then SwitchToThisWindow."""
        c, w = self._c, self._w
        u = self.user32
        cur = c.windll.kernel32.GetCurrentThreadId()
        fg = u.GetForegroundWindow()
        fg_tid = u.GetWindowThreadProcessId(fg, None) if fg else 0
        attached = False
        try:
            if fg_tid and fg_tid != cur:
                attached = bool(u.AttachThreadInput(w.DWORD(cur), w.DWORD(fg_tid), True))
            u.SetForegroundWindow(hwnd)
            if self.foreground() != hwnd:
                u.keybd_event(0x12, 0, 0, 0)          # VK_MENU down
                u.keybd_event(0x12, 0, 0x2, 0)        # VK_MENU up (KEYEVENTF_KEYUP)
                u.SetForegroundWindow(hwnd)
            if self.foreground() != hwnd:
                u.SwitchToThisWindow(hwnd, True)
        finally:
            if attached:
                u.AttachThreadInput(w.DWORD(cur), w.DWORD(fg_tid), False)


def foreground_now() -> int:
    """Foreground window handle right now (0 = unknown / not Windows). Taken BEFORE the sandbox is launched, so the
    watcher knows which window to give focus back to even if a sandbox window grabs it within milliseconds."""
    try:
        return _Win32().foreground() if sys.platform == "win32" else 0
    except Exception:  # noqa: BLE001
        return 0


def watch(pids: Callable[[], set[int]], api=None, duration_s: float = WATCH_S, poll_s: float = POLL_S,
          clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep,
          stop: threading.Event | None = None, name_prefix: str = "",
          exclude: frozenset[int] | set[int] = frozenset(), prev0: int = 0) -> None:
    """Synchronous loop (run it in a thread): minimizes each new window of `pids()` once and restores the previous
    foreground window if a sandbox window took it. Bounded by duration_s; swallows every error."""
    try:
        api = api or _Win32()
        deadline = clock() + duration_s
        seen: set[int] = set()
        prev = prev0 or api.foreground()   # last foreground window that is not a sandbox window
        while clock() < deadline and not (stop and stop.is_set()):
            try:
                own = set(pids())
                table_fn = getattr(api, "process_table", None)
                alive: set[int] | None = None
                if table_fn is not None:
                    table = table_fn()
                    alive = {p for p, _pp, _n in table}
                    if own or name_prefix:
                        own = expand_pids(own, table, name_prefix, exclude)
                mine = {h for h, p in api.top_windows() if p in own}
                for h in sorted(mine - seen):
                    seen.add(h)
                    api.minimize(h)
                    log.debug("sandbox window %#x minimized", h)
                fg = api.foreground()
                pid_fn = getattr(api, "window_pid", None)
                fg_own = bool(fg) and (fg in mine or (pid_fn is not None and pid_fn(fg) in own))
                if fg and fg_own:
                    if prev and prev not in mine and not (pid_fn is not None and pid_fn(prev) in own):
                        try:
                            api.set_foreground(prev)
                            log.debug("foreground restored to %#x", prev)
                        except Exception:  # noqa: BLE001
                            pass
                elif fg and not (pid_fn is not None and alive is not None and pid_fn(fg) not in alive):
                    prev = fg   # (a window of an already exited process, e.g. the launcher stub, is no restore target)
            except Exception as e:  # noqa: BLE001
                log.debug("window guard poll failed: %s", e)
            sleep(poll_s)
    except Exception as e:  # noqa: BLE001
        log.debug("window guard stopped: %s", e)


def start_watcher(pids: Callable[[], set[int]], **kw) -> threading.Thread | None:
    """Starts the daemon watcher thread; None when disabled/non-Windows or on any failure. Tests inject `api=`."""
    try:
        if mode() != "minimized" or ("api" not in kw and sys.platform != "win32"):
            return None
        t = threading.Thread(target=watch, args=(pids,), kwargs=kw, name="rh-sandbox-window", daemon=True)
        t.start()
        return t
    except Exception as e:  # noqa: BLE001
        log.debug("window guard not started: %s", e)
        return None
