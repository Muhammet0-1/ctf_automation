from __future__ import annotations

import json
import runpy
import socket
import sys
from io import StringIO
from pathlib import Path

import pytest

from ctfkit import cli
from ctfkit.decoders import DecodeCandidate
from ctfkit.file_analysis import FileAnalysis
from ctfkit.models import OpenPort, ResolvedEndpoint
from ctfkit.reporting import render_analysis, render_decode, render_scan
from ctfkit.scanner import ScanReport

ENDPOINT = ResolvedEndpoint(socket.AddressFamily.AF_INET, "10.10.10.10")


def scan_report(*ports: OpenPort) -> ScanReport:
    return ScanReport(
        target="lab.test",
        selected_endpoint=ENDPOINT,
        resolved_endpoints=(ENDPOINT,),
        port_specification="80,443",
        duration_seconds=float("nan"),
        host_up=True,
        open_ports=ports,
    )


def test_scan_json_never_emits_nan() -> None:
    output = render_scan(scan_report(OpenPort(80, "tcp", "http")), "json")
    assert "NaN" not in output
    assert json.loads(output)["open_ports"][0]["port"] == 80


def test_jsonl_outputs_typed_records() -> None:
    scan_records = [
        json.loads(line)
        for line in render_scan(scan_report(OpenPort(80, "tcp")), "jsonl").splitlines()
    ]
    assert [record["type"] for record in scan_records] == ["scan", "open_port", "summary"]
    decode_records = [
        json.loads(line)
        for line in render_decode((DecodeCandidate("rot13", "hello"),), "jsonl").splitlines()
    ]
    assert [record["type"] for record in decode_records] == ["decode", "candidate"]


def test_text_output_escapes_terminal_control_characters() -> None:
    report = scan_report(OpenPort(80, "tcp", "http\x1b[31m", "server\nname"))
    output = render_scan(report, "text")
    assert "\x1b" not in output
    assert "\\x1b" in output
    assert "server\\x0aname" in output


def test_analysis_renderers_include_hash_and_strings() -> None:
    report = FileAnalysis("sample", 4, "a" * 64, "UTF-8 text", 4, 1.0, ("test",))
    assert "SHA-256" in render_analysis(report, "text")
    assert json.loads(render_analysis(report, "json"))["strings"] == ["test"]


class FakeScanner:
    current = scan_report()

    def scan(self, _config: object) -> ScanReport:
        return self.current


def test_cli_scan_requires_authorization() -> None:
    with pytest.raises(SystemExit) as error:
        cli.main(["scan", "10.10.10.10"])
    assert error.value.code == 2


def test_cli_scan_output_and_fail_on_open(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "NmapScanner", FakeScanner)
    FakeScanner.current = scan_report(OpenPort(80, "tcp"))
    try:
        result = cli.main(
            [
                "scan",
                "10.10.10.10",
                "--acknowledge-authorization",
                "--fail-on-open",
                "--format",
                "json",
            ]
        )
        assert result == 3
        assert json.loads(capsys.readouterr().out)["open_ports"][0]["port"] == 80
    finally:
        FakeScanner.current = scan_report()


def test_cli_decode_argument_and_stdin(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["decode", "SGVsbG8=", "--format", "json"]) == 0
    assert any(
        item["value"] == "Hello" for item in json.loads(capsys.readouterr().out)["candidates"]
    )
    monkeypatch.setattr(cli.sys, "stdin", StringIO("48656c6c6f"))
    assert cli.main(["decode", "--stdin", "--format", "json"]) == 0
    assert any(
        item["transformation"] == "hex"
        for item in json.loads(capsys.readouterr().out)["candidates"]
    )


def test_cli_decode_rejects_conflicting_sources() -> None:
    with pytest.raises(SystemExit) as error:
        cli.main(["decode", "value", "--stdin"])
    assert error.value.code == 2


def test_cli_errors_escape_terminal_controls(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as error:
        cli.main(["decode", "value", "\x1b[31m"])
    assert error.value.code == 2
    stderr = capsys.readouterr().err
    assert "\x1b" not in stderr
    assert "\\x1b" in stderr


def test_legacy_script_entry_point_remains_compatible(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    script = Path(__file__).parents[1] / "ctfkit.py"
    monkeypatch.setattr(sys, "argv", [str(script), "--version"])
    with pytest.raises(SystemExit) as error:
        runpy.run_path(str(script), run_name="__main__")
    assert error.value.code == 0
    assert capsys.readouterr().out.strip() == "ctfkit 1.0.0"


def test_cli_analyzes_a_local_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "sample"
    path.write_text("Hello CTF")
    assert cli.main(["analyze", str(path), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["sha256"]


@pytest.mark.parametrize("renderer", [render_scan, render_decode, render_analysis])
def test_renderers_reject_unknown_formats(renderer: object) -> None:
    with pytest.raises(ValueError):
        if renderer is render_scan:
            render_scan(scan_report(), "xml")
        elif renderer is render_decode:
            render_decode((), "xml")
        else:
            render_analysis(FileAnalysis("x", 0, "a" * 64, "empty", 0, 0.0, ()), "xml")
