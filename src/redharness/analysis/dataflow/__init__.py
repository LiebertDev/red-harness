"""Bounded data-flow slice inside one function (docs/design/dataflow-slice.md). Engine-independent: it consumes the
common `Disassembly` contract and a PE image view; nothing is executed."""

from .image import ImageLoad, PeImageView
from .seh import ExceptEdge, scope_edges
from .slicer import (MAX_BUFFER, MAX_FUNCTION_INSNS, MAX_STEPS_DEFAULT, MAX_STEPS_MAX, SLICER_REV, SliceError,
                     SliceResult, slice_function)

__all__ = ["ExceptEdge", "scope_edges", "ImageLoad", "PeImageView", "MAX_BUFFER", "MAX_FUNCTION_INSNS", "MAX_STEPS_DEFAULT", "MAX_STEPS_MAX",
           "SLICER_REV", "SliceError", "SliceResult", "slice_function"]
