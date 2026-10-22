"""Windows API bindings (ctypes). Windows only."""

from __future__ import annotations

import sys

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("redharness.core._win (Win32 API bindings) is available on Windows only; "
                      "other platforms use core.procinfo and the POSIX runner in core.proc")

import ctypes
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000
WAIT_TIMEOUT = 0x102
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_PARAMETER = 87
CREATE_SUSPENDED = 0x00000004

JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
JobObjectBasicAccountingInformation = 1
JobObjectAssociateCompletionPortInformation = 7
JobObjectExtendedLimitInformation = 9
JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT = 9
JOB_OBJECT_MSG_JOB_MEMORY_LIMIT = 10

ULONG_PTR = ctypes.c_size_t
SIZE_T = ctypes.c_size_t


class BASIC_LIMIT(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", SIZE_T),
        ("MaximumWorkingSetSize", SIZE_T),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ULONG_PTR),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [(n, ctypes.c_uint64) for n in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class EXTENDED_LIMIT(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", BASIC_LIMIT),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", SIZE_T),
        ("JobMemoryLimit", SIZE_T),
        ("PeakProcessMemoryUsed", SIZE_T),
        ("PeakJobMemoryUsed", SIZE_T),
    ]


class BASIC_ACCOUNTING(ctypes.Structure):
    _fields_ = [
        ("TotalUserTime", ctypes.c_int64),
        ("TotalKernelTime", ctypes.c_int64),
        ("ThisPeriodTotalUserTime", ctypes.c_int64),
        ("ThisPeriodTotalKernelTime", ctypes.c_int64),
        ("TotalPageFaultCount", wintypes.DWORD),
        ("TotalProcesses", wintypes.DWORD),
        ("ActiveProcesses", wintypes.DWORD),
        ("TotalTerminatedProcesses", wintypes.DWORD),
    ]


class ASSOC_PORT(ctypes.Structure):
    _fields_ = [("CompletionKey", wintypes.LPVOID), ("CompletionPort", wintypes.HANDLE)]


def _sig(fn, res, *args):
    fn.restype = res
    fn.argtypes = list(args)


H = wintypes.HANDLE
_sig(k32.OpenProcess, H, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
_sig(k32.CloseHandle, wintypes.BOOL, H)
_sig(k32.GetProcessTimes, wintypes.BOOL, H, *[ctypes.POINTER(ctypes.c_uint64)] * 4)
_sig(k32.WaitForSingleObject, wintypes.DWORD, H, wintypes.DWORD)
_sig(k32.CreateJobObjectW, H, wintypes.LPVOID, wintypes.LPCWSTR)
_sig(k32.SetInformationJobObject, wintypes.BOOL, H, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
_sig(k32.QueryInformationJobObject, wintypes.BOOL, H, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
     ctypes.POINTER(wintypes.DWORD))
_sig(k32.AssignProcessToJobObject, wintypes.BOOL, H, H)
_sig(k32.TerminateJobObject, wintypes.BOOL, H, wintypes.UINT)
_sig(k32.CreateIoCompletionPort, H, H, H, ULONG_PTR, wintypes.DWORD)
_sig(k32.GetQueuedCompletionStatus, wintypes.BOOL, H, ctypes.POINTER(wintypes.DWORD),
     ctypes.POINTER(ULONG_PTR), ctypes.POINTER(wintypes.LPVOID), wintypes.DWORD)
_sig(ntdll.NtResumeProcess, wintypes.LONG, H)

INVALID_HANDLE = wintypes.HANDLE(-1).value


def process_start_time(pid: int) -> int | None:
    """Process creation time (FILETIME, 100ns). None if the process does not exist or has exited."""
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, False, pid)
    if not h:
        return None
    try:
        if k32.WaitForSingleObject(h, 0) != WAIT_TIMEOUT:
            return None  # exited (the handle can still be opened)
        c, e, k, u = (ctypes.c_uint64() for _ in range(4))
        if not k32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(k), ctypes.byref(u)):
            return None
        return int(c.value)
    finally:
        k32.CloseHandle(h)


def pid_alive(pid: int) -> bool:
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, False, pid)
    if not h:
        return ctypes.get_last_error() == ERROR_ACCESS_DENIED  # exists but access denied
    try:
        return k32.WaitForSingleObject(h, 0) == WAIT_TIMEOUT
    finally:
        k32.CloseHandle(h)
