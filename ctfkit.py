"""Backward-compatible CTFKit entry point."""

from __future__ import annotations

import sys
from importlib import import_module
from pathlib import Path

_SOURCE_ROOT = Path(__file__).resolve().parent / "src"
_SOURCE_PACKAGE = _SOURCE_ROOT / "ctfkit"

if __name__ == "ctfkit" and _SOURCE_PACKAGE.is_dir():
    # A source checkout contains both this legacy script and the src-layout package. Make
    # the shim package-like so imports from the repository root do not shadow src/ctfkit.
    __path__ = [str(_SOURCE_PACKAGE)]
    __version__ = "1.0.0"

    from ctfkit.config import (
        PortSelection,
        ScanConfig,
        Target,
        parse_port_selection,
        parse_target,
    )
    from ctfkit.decoders import DecodeCandidate, decode_candidates
    from ctfkit.file_analysis import FileAnalysis, analyze_file
    from ctfkit.scanner import NmapScanner, ScanReport

    __all__ = [
        "DecodeCandidate",
        "FileAnalysis",
        "NmapScanner",
        "PortSelection",
        "ScanConfig",
        "ScanReport",
        "Target",
        "analyze_file",
        "decode_candidates",
        "parse_port_selection",
        "parse_target",
    ]
elif _SOURCE_ROOT.is_dir():
    sys.path.insert(0, str(_SOURCE_ROOT))

main = import_module("ctfkit.cli").main

if __name__ == "__main__":
    raise SystemExit(main())
