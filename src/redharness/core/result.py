"""Fail-closed result statuses. Only OK is success."""

from __future__ import annotations

from enum import Enum


class Status(str, Enum):
    OK = "OK"
    PARTIAL = "PARTIAL"  # output truncated / partial coverage
    LIMIT_REACHED = "LIMIT_REACHED"
    TIMEOUT = "TIMEOUT"
    MEMORY_LIMIT = "MEMORY_LIMIT"
    TOOL_MISSING = "TOOL_MISSING"
    ERROR = "ERROR"

    @property
    def is_success(self) -> bool:
        return self is Status.OK
