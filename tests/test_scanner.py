from __future__ import annotations

import io
import os
import socket
import subprocess
from pathlib import Path
from typing import Any

import pytest

from ctfkit import scanner as scanner_module
from ctfkit.config import ScanConfig, parse_port_selection, parse_target
from ctfkit.errors import ScanError, ToolUnavailableError
from ctfkit.models import ResolvedEndpoint
from ctfkit.scanner import MAX_XML_BYTES, NmapScanner

ENDPOINT = ResolvedEndpoint(socket.AddressFamily.AF_INET, "10.10.10.10")

XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="Example Server" version="1.2"/>
      </port>
      <port protocol="tcp" portid="22"><state state="closed"/></port>
      <port protocol="tcp" portid="80"><state state="open"/></port>
    </ports>
  </host>
</nmaprun>
"""


class FakeResolver:
    def resolve(self, _config: ScanConfig) -> tuple[ResolvedEndpoint, ...]:
        return (ENDPOINT,)


class RecordingRunner:
    def __init__(self, completed: subprocess.CompletedProcess[str] | None = None) -> None:
        self.completed = completed or subprocess.CompletedProcess([], 0, XML, "")
        self.args: list[str] = []
        self.kwargs: dict[str, Any] = {}

    def __call__(self, args: object, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.args = list(args)  # type: ignore[arg-type]
        self.kwargs = kwargs
        return self.completed


def config(**kwargs: object) -> ScanConfig:
    values: dict[str, object] = {
        "target": parse_target("lab.test"),
        "ports": parse_port_selection("22,80,443"),
        "acknowledge_authorization": True,
    }
    values.update(kwargs)
    return ScanConfig(**values)  # type: ignore[arg-type]


def executable(tmp_path: Path) -> str:
    path = tmp_path / "nmap"
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(0o700)
    return str(path)


def test_scan_uses_pinned_ip_fixed_flags_and_parses_open_ports(tmp_path: Path) -> None:
    runner = RecordingRunner()
    times = iter((10.0, 10.25))
    scanner = NmapScanner(
        resolver=FakeResolver(),  # type: ignore[arg-type]
        which=lambda _name: executable(tmp_path),
        run_process=runner,  # type: ignore[arg-type]
        monotonic=lambda: next(times),
    )
    report = scanner.scan(config())
    assert runner.args[-1] == "10.10.10.10"
    assert runner.args[:4] == [str(Path(runner.args[0]).resolve()), "-n", "-sT", "-T3"]
    assert "-A" not in runner.args
    assert "-sC" not in runner.args
    assert "-sV" not in runner.args
    assert "--script" not in runner.args
    assert runner.kwargs["timeout"] == 305.0
    assert runner.kwargs["env"] == {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
    assert report.duration_seconds == 0.25
    assert [(item.port, item.service) for item in report.open_ports] == [(80, None), (443, "https")]


def test_ipv6_endpoint_enables_nmap_ipv6_mode(tmp_path: Path) -> None:
    endpoint = ResolvedEndpoint(socket.AddressFamily.AF_INET6, "fd00::10")

    class IPv6Resolver:
        def resolve(self, _config: ScanConfig) -> tuple[ResolvedEndpoint, ...]:
            return (endpoint,)

    runner = RecordingRunner()
    scanner = NmapScanner(
        resolver=IPv6Resolver(),  # type: ignore[arg-type]
        which=lambda _name: executable(tmp_path),
        run_process=runner,  # type: ignore[arg-type]
    )
    scanner.scan(config())
    assert "-6" in runner.args
    assert runner.args[-1] == "fd00::10"


def test_full_scan_uses_p_dash_only_after_config_confirmation(tmp_path: Path) -> None:
    runner = RecordingRunner()
    scanner = NmapScanner(
        resolver=FakeResolver(),  # type: ignore[arg-type]
        which=lambda _name: executable(tmp_path),
        run_process=runner,  # type: ignore[arg-type]
    )
    scanner.scan(config(ports=parse_port_selection("all"), acknowledge_full_scan=True))
    assert "-p-" in runner.args


def test_missing_or_non_executable_nmap_is_reported(tmp_path: Path) -> None:
    scanner = NmapScanner(resolver=FakeResolver(), which=lambda _name: None)  # type: ignore[arg-type]
    with pytest.raises(ToolUnavailableError):
        scanner.scan(config())
    path = tmp_path / "nmap"
    path.write_text("not executable")
    scanner = NmapScanner(resolver=FakeResolver(), which=lambda _name: str(path))  # type: ignore[arg-type]
    with pytest.raises(ToolUnavailableError):
        scanner.scan(config())


def test_timeout_and_nonzero_exit_are_wrapped(tmp_path: Path) -> None:
    def timeout(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired("nmap", 1)

    scanner = NmapScanner(
        resolver=FakeResolver(),  # type: ignore[arg-type]
        which=lambda _name: executable(tmp_path),
        run_process=timeout,  # type: ignore[arg-type]
    )
    with pytest.raises(ScanError, match="timeout"):
        scanner.scan(config())

    runner = RecordingRunner(subprocess.CompletedProcess([], 2, "", "bad\x1b[31m input"))
    scanner = NmapScanner(
        resolver=FakeResolver(),  # type: ignore[arg-type]
        which=lambda _name: executable(tmp_path),
        run_process=runner,  # type: ignore[arg-type]
    )
    with pytest.raises(ScanError, match="status 2"):
        scanner.scan(config())


@pytest.mark.parametrize(
    "xml",
    [
        "not xml",
        (
            "<nmaprun><host><ports><port portid='bad'><state state='open'/>"
            "</port></ports></host></nmaprun>"
        ),
    ],
)
def test_malformed_xml_is_rejected(tmp_path: Path, xml: str) -> None:
    runner = RecordingRunner(subprocess.CompletedProcess([], 0, xml, ""))
    scanner = NmapScanner(
        resolver=FakeResolver(),  # type: ignore[arg-type]
        which=lambda _name: executable(tmp_path),
        run_process=runner,  # type: ignore[arg-type]
    )
    with pytest.raises(ScanError):
        scanner.scan(config())


def test_oversized_xml_is_rejected(tmp_path: Path) -> None:
    runner = RecordingRunner(subprocess.CompletedProcess([], 0, "x" * (MAX_XML_BYTES + 1), ""))
    scanner = NmapScanner(
        resolver=FakeResolver(),  # type: ignore[arg-type]
        which=lambda _name: executable(tmp_path),
        run_process=runner,  # type: ignore[arg-type]
    )
    with pytest.raises(ScanError, match="5 MiB"):
        scanner.scan(config())


def test_process_runner_stops_oversized_output_before_returning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeProcess:
        def __init__(self) -> None:
            self.stdout = io.BytesIO(b"x" * (MAX_XML_BYTES + 1))
            self.stderr = io.BytesIO()
            self.killed = False

        def wait(self, timeout: float | None = None) -> int:
            return 0

        def kill(self) -> None:
            self.killed = True

    process = FakeProcess()
    monkeypatch.setattr(scanner_module.subprocess, "Popen", lambda *_args, **_kwargs: process)
    with pytest.raises(ScanError, match="safety limit"):
        scanner_module._run_process(
            ["nmap"],
            capture_output=True,
            text=True,
            timeout=1.0,
            check=False,
            env={},
        )
    assert process.killed


def test_scanner_does_not_modify_fake_nmap_executable(tmp_path: Path) -> None:
    path = Path(executable(tmp_path))
    before = (path.read_bytes(), os.stat(path).st_mode)
    scanner = NmapScanner(
        resolver=FakeResolver(),  # type: ignore[arg-type]
        which=lambda _name: str(path),
        run_process=RecordingRunner(),  # type: ignore[arg-type]
    )
    scanner.scan(config())
    assert (path.read_bytes(), os.stat(path).st_mode) == before
