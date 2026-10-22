"""Windows Sandbox backend: .wsb generation, launch, process listing and shutdown.

The backend interface (SandboxBackend) is small so tests can plug in a fake sandbox. The real backend
manages `WindowsSandbox*` processes via `tasklist`/`taskkill` (only one
instance runs at a time; processes force-close in about a second).
"""

from __future__ import annotations

import csv
import io
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Protocol
from xml.sax.saxutils import escape

from ..config import sandbox_memory_mb
from ..core.procinfo import process_start_time
from . import hostres, windowguard

_SANDBOX_PROC = re.compile(r"windowssandbox[a-z]*\.exe", re.I)
HCS_RELEASE_WAIT_S = 15.0   # max wait after shutdown for the sandbox VM to leave HCS (partition/memory release)
HCS_POLL_S = 0.2


class SandboxBackend(Protocol):
    def available(self) -> tuple[bool, str]: ...

    def running_processes(self) -> list[int]:
        """PIDs of running WindowsSandbox* processes (empty = no sandbox)."""

    def start(self, wsb_path: Path) -> None: ...

    def kill_all(self, wait_s: float = 20.0) -> list[int]:
        """Force-kills all sandbox processes and waits for them to end. Returns the PIDs still alive
        (empty list = closed)."""

    # Ownership (power-loss recovery): a record is {"pid": int, "start": int | None} (start = process creation time).
    # A backend without these methods cannot prove ownership, so recovery leaves its processes alone.
    def owned_processes(self) -> list[dict]:
        """Sandbox processes that appeared after OUR start() (not present before it)."""

    def alive_owned(self, procs: list[dict]) -> list[int]:
        """PIDs of the recorded processes that are still the same live process."""

    def kill_owned(self, procs: list[dict], wait_s: float = 20.0) -> list[int]:
        """Force-kills ONLY the recorded processes (a foreign Windows Sandbox is never touched). Returns the PIDs of
        recorded processes still alive (empty list = closed)."""


def render_wsb(in_dir: Path, out_dir: Path, *, memory_mb: int | None = None) -> str:
    """Isolation: network, GPU, audio, video, printer and clipboard disabled; input read-only; output a separate writable folder."""
    if memory_mb is None:
        memory_mb = sandbox_memory_mb()
    return (
        "<Configuration>\n"
        "  <VGpu>Disable</VGpu>\n"
        "  <Networking>Disable</Networking>\n"
        "  <AudioInput>Disable</AudioInput>\n"
        "  <VideoInput>Disable</VideoInput>\n"
        "  <PrinterRedirection>Disable</PrinterRedirection>\n"
        "  <ClipboardRedirection>Disable</ClipboardRedirection>\n"
        f"  <MemoryInMB>{int(memory_mb)}</MemoryInMB>\n"
        "  <MappedFolders>\n"
        f"    <MappedFolder><HostFolder>{escape(str(in_dir))}</HostFolder><SandboxFolder>C:\\in</SandboxFolder>"
        "<ReadOnly>true</ReadOnly></MappedFolder>\n"
        f"    <MappedFolder><HostFolder>{escape(str(out_dir))}</HostFolder><SandboxFolder>C:\\out</SandboxFolder>"
        "<ReadOnly>false</ReadOnly></MappedFolder>\n"
        "  </MappedFolders>\n"
        "  <LogonCommand><Command>cmd.exe /c C:\\in\\run.cmd</Command></LogonCommand>\n"
        "</Configuration>\n")


def parse_hcsdiag(text: str) -> list[str]:
    """Keys of NON-TEMPLATE VMs from `hcsdiag list` output (GUID; state name for transient rows without a GUID).
    Output: an id line, then a 'VM,  <State>, <GUID>, <Owner>' line. 'SavedAsTemplate' is the persistent Sandbox
    template (CmService), not part of our session."""
    out: list[str] = []
    for line in text.splitlines():
        if "," not in line:
            continue
        parts = [p.strip() for p in line.split(",")]
        if parts[0] != "VM" or len(parts) < 2 or parts[1] == "SavedAsTemplate":
            continue
        out.append(parts[2].lower() if len(parts) > 2 and parts[2] else parts[1])
    return out


def parse_tasklist(csv_text: str) -> list[int]:
    """WindowsSandbox* PIDs from `tasklist /FO CSV /NH` output."""
    pids: list[int] = []
    for row in csv.reader(io.StringIO(csv_text)):
        if len(row) >= 2 and _SANDBOX_PROC.fullmatch(row[0].strip()):
            try:
                pids.append(int(row[1]))
            except ValueError:
                continue
    return pids


class WindowsSandboxBackend:
    def __init__(self, exe: str | os.PathLike | None = None):
        root = os.environ.get("SystemRoot", r"C:\Windows")
        self.exe = Path(exe) if exe else Path(root) / "System32" / "WindowsSandbox.exe"
        self._tasklist = Path(root) / "System32" / "tasklist.exe"
        self._taskkill = Path(root) / "System32" / "taskkill.exe"
        self._hcsdiag = Path(root) / "System32" / "hcsdiag.exe"
        self._vms_before: set[str] | None = None   # non-template VMs before start() (other people's VMs are not ours)
        self._pids_before: set[int] = set()        # sandbox PIDs before start(): anything new afterwards is ours
        self._launched: int | None = None          # PID of the WindowsSandbox.exe we spawned

    def available(self) -> tuple[bool, str]:
        if sys.platform != "win32":
            return False, f"Windows Sandbox exists only on Windows (this host: {sys.platform})"
        if not self.exe.is_file():
            return False, f"WindowsSandbox.exe missing ({self.exe}); the Containers-DisposableClientVM feature may be off"
        return True, ""

    def running_processes(self) -> list[int]:
        r = subprocess.run([str(self._tasklist), "/FO", "CSV", "/NH"], capture_output=True, timeout=30)
        if r.returncode != 0:
            raise OSError(f"tasklist failed (code {r.returncode})")
        return parse_tasklist(r.stdout.decode("mbcs", "replace"))

    def compute_systems(self) -> list[str] | None:
        """Non-template HCS VMs (`hcsdiag list`); None if the tool is missing or fails (unknown)."""
        if not self._hcsdiag.is_file():
            return None
        try:
            r = subprocess.run([str(self._hcsdiag), "list"], capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            return None
        if r.returncode != 0:
            return None
        return parse_hcsdiag(r.stdout.decode("mbcs", "replace"))

    def wait_vm_released(self, wait_s: float) -> bool:
        """Waits (up to wait_s) until the VM we started is gone from HCS. Even after the processes die the VM stays
        'Running' for ~1-2 s more and does not return its partition memory; starting a new VM immediately risks
        0x800705AA (insufficient system resources).
        True = gone or unknown (no hcsdiag / start() not called), False = timed out."""
        if self._vms_before is None:
            return True
        deadline = time.monotonic() + wait_s
        while True:
            vms = self.compute_systems()
            if vms is None:
                return True
            ours = [v for v in vms if v not in self._vms_before]
            if not ours:
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(HCS_POLL_S)

    def start(self, wsb_path: Path) -> None:
        # VMs present before launch (WSL, other VMs): on shutdown we only wait for OUR new VM to go away
        self._vms_before = set(self.compute_systems() or [])
        try:
            self._pids_before = set(self.running_processes())
        except (OSError, subprocess.SubprocessError):
            self._pids_before = set()
        extra = {}
        fg0 = windowguard.foreground_now()   # before the launch: the window to give focus back to
        si = windowguard.startupinfo()
        if si is not None:
            extra["startupinfo"] = si
        proc = subprocess.Popen([str(self.exe), str(wsb_path)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, close_fds=True, **extra)
        self._launched = proc.pid
        # pure ctypes (no tasklist per poll): the launched PID, its descendants and new WindowsSandbox* processes
        windowguard.start_watcher(lambda: {proc.pid}, name_prefix="windowssandbox",
                                  exclude=frozenset(self._pids_before), prev0=fg0)   # best effort, bounded, never raises

    # ---- host pressure / start error dialog (only for processes WE launched)
    def memory_status(self) -> dict | None:
        """Host available RAM/commit in MB (None = unknown); the runner refuses to start below the headroom."""
        return hostres.memory_status()

    def _own_pids(self) -> set[int]:
        pids = {r["pid"] for r in self.owned_processes()}
        if self._launched is not None and self._launched not in self._pids_before:
            pids.add(self._launched)
        return pids

    def start_error(self) -> str | None:
        """Text of the start-failure dialog ("... failed to start. Error 0x800705aa") shown by a sandbox process WE
        started, else None. WindowsSandbox.exe does not exit on this error; it waits for the user."""
        found = hostres.find_error_dialogs(self._own_pids())
        return found[0].text if found else None

    def dismiss_start_error(self) -> list[int]:
        """Closes ONLY the error dialog(s) of our own sandbox processes: answers 'No', then force-closes our recorded
        processes if they are still alive. A foreign Windows Sandbox is never touched. Returns the PIDs handled."""
        own = self._own_pids()
        dialogs = hostres.find_error_dialogs(own)
        for d in dialogs:
            hostres.press_no(d.hwnd)
        if dialogs:
            time.sleep(1.0)
            recs = [r for r in self.owned_processes() if r["pid"] in own]
            if recs:
                self.kill_owned(recs, 5.0)
        return sorted({d.pid for d in dialogs})

    # ---- ownership (recorded in the sandbox journal so a later process can clean up only what we started)
    def owned_processes(self) -> list[dict]:
        try:
            listed = self.running_processes()
        except (OSError, subprocess.SubprocessError):
            listed = []
        pids = [p for p in listed if p not in self._pids_before]
        if self._launched is not None and self._launched not in pids and self._launched not in self._pids_before                 and process_start_time(self._launched) is not None:
            pids.append(self._launched)   # just spawned, not yet visible to tasklist
        return [{"pid": p, "start": process_start_time(p)} for p in pids]

    @staticmethod
    def _same_process(rec: dict, listed: set[int]) -> bool:
        pid, start = rec.get("pid"), rec.get("start")
        if not isinstance(pid, int) or pid <= 0:
            return False
        now = process_start_time(pid)
        if start is None:
            return pid in listed          # identity unknown: only if it is still a WindowsSandbox* image
        return now == start               # creation time pins the identity (PID reuse after a reboot)

    def alive_owned(self, procs: list[dict]) -> list[int]:
        try:
            listed = set(self.running_processes())
        except (OSError, subprocess.SubprocessError):
            listed = set()
        return [r["pid"] for r in procs if self._same_process(r, listed)]

    def kill_owned(self, procs: list[dict], wait_s: float = 20.0) -> list[int]:
        deadline = time.monotonic() + wait_s
        while True:
            alive = self.alive_owned(procs)
            if not alive or time.monotonic() >= deadline:
                return alive
            for pid in alive:
                subprocess.run([str(self._taskkill), "/F", "/T", "/PID", str(pid)], capture_output=True, timeout=30)
            time.sleep(0.5)

    def kill_all(self, wait_s: float = 20.0) -> list[int]:
        deadline = time.monotonic() + wait_s
        pids: list[int] = []
        while True:
            try:
                pids = self.running_processes()
            except (OSError, subprocess.SubprocessError):
                pids = [-1]  # could not list: closure UNVERIFIED -> count as not closed
            if not pids:
                # processes gone; wait for the VM to actually be released (within the remaining time, at most HCS_RELEASE_WAIT_S)
                self.wait_vm_released(max(0.0, min(HCS_RELEASE_WAIT_S, deadline - time.monotonic())))
                return pids
            if time.monotonic() >= deadline:
                return pids
            for pid in pids:
                if pid > 0:
                    subprocess.run([str(self._taskkill), "/F", "/T", "/PID", str(pid)],
                                   capture_output=True, timeout=30)
            time.sleep(0.5)
