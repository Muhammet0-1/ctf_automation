"""Read-only, bounded local file metadata and string analysis."""

from __future__ import annotations

import hashlib
import math
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import AnalysisError, ConfigurationError

DEFAULT_MAX_FILE_BYTES = 67_108_864
ABSOLUTE_MAX_FILE_BYTES = 268_435_456
SAMPLE_BYTES = 1_048_576
MAX_STRINGS = 100

SIGNATURES = (
    (b"\x7fELF", "ELF executable or object"),
    (b"MZ", "PE/DOS executable"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"%PDF-", "PDF document"),
    (b"PK\x03\x04", "ZIP-compatible archive"),
    (b"\x1f\x8b", "Gzip stream"),
    (b"SQLite format 3\x00", "SQLite database"),
)


@dataclass(frozen=True, slots=True)
class FileAnalysis:
    path: str
    size_bytes: int
    sha256: str
    detected_type: str
    sample_bytes: int
    sample_entropy: float
    strings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "command": "analyze",
            "path": self.path,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "detected_type": self.detected_type,
            "sample_bytes": self.sample_bytes,
            "sample_entropy": round(self.sample_entropy, 4),
            "strings": list(self.strings),
        }


def analyze_file(
    path_value: str | Path,
    *,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    minimum_string_length: int = 4,
    max_strings: int = 20,
) -> FileAnalysis:
    _validate_limits(max_file_bytes, minimum_string_length, max_strings)
    try:
        path = Path(path_value).expanduser()
    except RuntimeError as exc:
        raise ConfigurationError("file path could not be expanded") from exc
    try:
        initial_metadata = os.lstat(path)
    except OSError as exc:
        raise AnalysisError(f"file could not be inspected safely ({type(exc).__name__})") from exc
    if not stat.S_ISREG(initial_metadata.st_mode):
        raise AnalysisError("analysis target must be a regular file, not a symlink or special file")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    if not hasattr(os, "O_NOFOLLOW"):
        raise AnalysisError("safe no-follow file opening is unavailable on this platform")
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AnalysisError(f"file could not be opened safely ({type(exc).__name__})") from exc

    digest = hashlib.sha256()
    sample = bytearray()
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise AnalysisError("analysis target must be a regular file")
        if metadata.st_size > max_file_bytes:
            raise AnalysisError(f"file exceeds the configured {max_file_bytes}-byte analysis limit")
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, max_file_bytes - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > max_file_bytes:
                raise AnalysisError("file grew beyond the configured limit during analysis")
            digest.update(chunk)
            if len(sample) < SAMPLE_BYTES:
                sample.extend(chunk[: SAMPLE_BYTES - len(sample)])
        if total != metadata.st_size:
            raise AnalysisError("file changed size during analysis")
    finally:
        os.close(descriptor)

    sample_bytes = bytes(sample)
    return FileAnalysis(
        path=str(path),
        size_bytes=total,
        sha256=digest.hexdigest(),
        detected_type=_detect_type(sample_bytes),
        sample_bytes=len(sample_bytes),
        sample_entropy=_entropy(sample_bytes),
        strings=_extract_strings(sample_bytes, minimum_string_length, max_strings),
    )


def _validate_limits(max_file_bytes: int, minimum_length: int, max_strings: int) -> None:
    if (
        isinstance(max_file_bytes, bool)
        or not isinstance(max_file_bytes, int)
        or not 1 <= max_file_bytes <= ABSOLUTE_MAX_FILE_BYTES
    ):
        raise ConfigurationError(
            f"maximum file bytes must be between 1 and {ABSOLUTE_MAX_FILE_BYTES}"
        )
    if (
        isinstance(minimum_length, bool)
        or not isinstance(minimum_length, int)
        or not 4 <= minimum_length <= 64
    ):
        raise ConfigurationError("minimum string length must be between 4 and 64")
    if (
        isinstance(max_strings, bool)
        or not isinstance(max_strings, int)
        or not 0 <= max_strings <= MAX_STRINGS
    ):
        raise ConfigurationError(f"maximum strings must be between 0 and {MAX_STRINGS}")


def _detect_type(sample: bytes) -> str:
    for signature, description in SIGNATURES:
        if sample.startswith(signature):
            return description
    if not sample:
        return "empty file"
    if b"\x00" not in sample:
        try:
            sample.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            pass
        else:
            return "UTF-8 text"
    return "unknown binary data"


def _extract_strings(sample: bytes, minimum_length: int, limit: int) -> tuple[str, ...]:
    if limit == 0:
        return ()
    values: list[str] = []
    current = bytearray()
    for byte in sample + b"\x00":
        if 32 <= byte <= 126:
            current.append(byte)
            continue
        if len(current) >= minimum_length:
            values.append(current.decode("ascii")[:512])
            if len(values) >= limit:
                break
        current.clear()
    return tuple(values)


def _entropy(sample: bytes) -> float:
    if not sample:
        return 0.0
    counts = [0] * 256
    for byte in sample:
        counts[byte] += 1
    length = len(sample)
    return -sum((count / length) * math.log2(count / length) for count in counts if count)
