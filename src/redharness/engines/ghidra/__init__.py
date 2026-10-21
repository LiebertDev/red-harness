"""Ghidra headless backend (Java GhidraScript, separate process, under a Job Object)."""

from .backend import GhidraEngine

__all__ = ["GhidraEngine"]
