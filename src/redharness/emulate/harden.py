"""Hardening of the emulation worker process (Windows): Low integrity level, applied by the worker to its own primary
token BEFORE it reads the target or loads the emulator. A process may lower (never raise) its own integrity level.

At Low integrity the mandatory integrity policy (no-write-up) denies writes to objects labelled Medium, which is the
default for the user profile, the repository and the job store; the Job Object (host.py) additionally limits the job to
ONE active process, so the worker cannot start a child. Not covered (stated in docs/design/emulation.md): reads (no
read-up is not the default policy), network access, and the short bootstrap that runs before the lowering (harness
code only, no target bytes).
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes

LOW_RID = 0x1000                 # SECURITY_MANDATORY_LOW_RID
TOKEN_INTEGRITY_LEVEL = 25       # TOKEN_INFORMATION_CLASS.TokenIntegrityLevel
TOKEN_QUERY, TOKEN_ADJUST_DEFAULT = 0x0008, 0x0080
SE_GROUP_INTEGRITY = 0x20


class HardeningError(OSError):
    pass


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


def _apis():
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    adv.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    adv.GetLengthSid.argtypes = [ctypes.c_void_p]
    adv.GetLengthSid.restype = wintypes.DWORD
    adv.SetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    adv.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                        ctypes.POINTER(wintypes.DWORD)]
    adv.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
    adv.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
    adv.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    adv.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.LocalFree.argtypes = [ctypes.c_void_p]
    return adv, k32


def integrity_rid() -> int:
    """The integrity RID of this process's token (0x1000 Low, 0x2000 Medium, 0x3000 High)."""
    adv, k32 = _apis()
    tok = wintypes.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(tok)):
        raise HardeningError(f"OpenProcessToken failed ({ctypes.get_last_error()})")
    try:
        need = wintypes.DWORD()
        adv.GetTokenInformation(tok, TOKEN_INTEGRITY_LEVEL, None, 0, ctypes.byref(need))
        buf = ctypes.create_string_buffer(need.value)
        if not adv.GetTokenInformation(tok, TOKEN_INTEGRITY_LEVEL, buf, need, ctypes.byref(need)):
            raise HardeningError(f"GetTokenInformation failed ({ctypes.get_last_error()})")
        sid = _SidAndAttributes.from_buffer(buf).Sid
        count = adv.GetSidSubAuthorityCount(sid)[0]
        return int(adv.GetSidSubAuthority(sid, count - 1)[0])
    finally:
        k32.CloseHandle(tok)


def lower_to_low_integrity() -> None:
    """Sets this process's token to Low integrity and checks the result; HardeningError if it did not take effect."""
    adv, k32 = _apis()
    tok = wintypes.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, ctypes.byref(tok)):
        raise HardeningError(f"OpenProcessToken failed ({ctypes.get_last_error()})")
    sid = ctypes.c_void_p()
    try:
        if not adv.ConvertStringSidToSidW("S-1-16-4096", ctypes.byref(sid)):
            raise HardeningError(f"ConvertStringSidToSid failed ({ctypes.get_last_error()})")
        tml = _SidAndAttributes(sid, SE_GROUP_INTEGRITY)
        size = ctypes.sizeof(tml) + adv.GetLengthSid(sid)
        if not adv.SetTokenInformation(tok, TOKEN_INTEGRITY_LEVEL, ctypes.byref(tml), size):
            raise HardeningError(f"SetTokenInformation(TokenIntegrityLevel) failed ({ctypes.get_last_error()})")
    finally:
        if sid:
            k32.LocalFree(sid)
        k32.CloseHandle(tok)
    if integrity_rid() != LOW_RID:
        raise HardeningError("the token is not at Low integrity after lowering")
