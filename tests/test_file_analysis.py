from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from ctfkit import file_analysis
from ctfkit.errors import AnalysisError, ConfigurationError
from ctfkit.file_analysis import analyze_file


def test_analyze_text_file_reports_hash_type_and_bounded_strings(tmp_path: Path) -> None:
    path = tmp_path / "sample.txt"
    content = b"Hello CTF\nflag{example}\n"
    path.write_bytes(content)
    report = analyze_file(path, max_strings=1)
    assert report.size_bytes == len(content)
    assert report.sha256 == hashlib.sha256(content).hexdigest()
    assert report.detected_type == "UTF-8 text"
    assert report.strings == ("Hello CTF",)
    assert report.sample_entropy > 0


@pytest.mark.parametrize(
    ("prefix", "expected"),
    [
        (b"\x7fELFrest", "ELF executable or object"),
        (b"MZrest", "PE/DOS executable"),
        (b"\x89PNG\r\n\x1a\nrest", "PNG image"),
        (b"%PDF-1.7", "PDF document"),
        (b"PK\x03\x04rest", "ZIP-compatible archive"),
    ],
)
def test_analyze_recognizes_bounded_magic_signatures(
    tmp_path: Path, prefix: bytes, expected: str
) -> None:
    path = tmp_path / "sample.bin"
    path.write_bytes(prefix)
    assert analyze_file(path).detected_type == expected


def test_analyze_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "empty"
    path.write_bytes(b"")
    report = analyze_file(path)
    assert report.detected_type == "empty file"
    assert report.sample_entropy == 0


def test_analyze_rejects_final_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("safe")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(AnalysisError, match="regular file"):
        analyze_file(link)


def test_analyze_rejects_fifo_before_opening(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "pipe"
    os.mkfifo(path)

    def fail_open(*_args: object, **_kwargs: object) -> int:
        raise AssertionError("special files must be rejected before open")

    monkeypatch.setattr(file_analysis.os, "open", fail_open)
    with pytest.raises(AnalysisError, match="special file"):
        analyze_file(path)


def test_analyze_rejects_directory_and_size_limit(tmp_path: Path) -> None:
    with pytest.raises(AnalysisError, match="regular file"):
        analyze_file(tmp_path)
    path = tmp_path / "large"
    path.write_bytes(b"12345")
    with pytest.raises(AnalysisError, match="exceeds"):
        analyze_file(path, max_file_bytes=4)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_file_bytes": True},
        {"max_file_bytes": 0},
        {"minimum_string_length": 3},
        {"minimum_string_length": 65},
        {"max_strings": -1},
        {"max_strings": 101},
    ],
)
def test_analyze_rejects_invalid_limits(tmp_path: Path, kwargs: dict[str, object]) -> None:
    path = tmp_path / "sample"
    path.write_bytes(b"sample")
    with pytest.raises(ConfigurationError):
        analyze_file(path, **kwargs)  # type: ignore[arg-type]


def test_analysis_never_changes_file_contents_or_permissions(tmp_path: Path) -> None:
    path = tmp_path / "immutable"
    path.write_bytes(b"unchanged")
    path.chmod(0o640)
    before = (path.read_bytes(), path.stat().st_mode)
    analyze_file(path)
    after = (path.read_bytes(), path.stat().st_mode)
    assert after == before
