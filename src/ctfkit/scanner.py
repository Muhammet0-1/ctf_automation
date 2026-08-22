"""Conservative Nmap orchestration for explicitly authorized CTF targets."""

from __future__ import annotations

import math
import os
import shutil
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Protocol

from .config import ScanConfig
from .errors import ScanError, ToolUnavailableError
from .models import OpenPort, ResolvedEndpoint
from .resolution import TargetResolver

MAX_XML_BYTES = 5_242_880
MAX_ERROR_BYTES = 65_536


class ProcessRunner(Protocol):
    def __call__(
        self,
        args: Sequence[str],
        *,
        capture_output: bool,
        text: bool,
        timeout: float,
        check: bool,
        env: Mapping[str, str],
    ) -> subprocess.CompletedProcess[str]: ...


@dataclass(frozen=True, slots=True)
class ScanReport:
    target: str
    selected_endpoint: ResolvedEndpoint
    resolved_endpoints: tuple[ResolvedEndpoint, ...]
    port_specification: str
    duration_seconds: float
    host_up: bool
    open_ports: tuple[OpenPort, ...]

    def to_dict(self) -> dict[str, Any]:
        duration = self.duration_seconds
        if not math.isfinite(duration):
            duration = 0.0
        return {
            "schema_version": 1,
            "command": "scan",
            "target": self.target,
            "selected_endpoint": self.selected_endpoint.to_dict(),
            "resolved_endpoints": [item.to_dict() for item in self.resolved_endpoints],
            "port_specification": self.port_specification,
            "duration_seconds": round(duration, 3),
            "host_up": self.host_up,
            "open_ports": [item.to_dict() for item in self.open_ports],
        }


class NmapScanner:
    def __init__(
        self,
        *,
        resolver: TargetResolver | None = None,
        which: Callable[[str], str | None] = shutil.which,
        run_process: ProcessRunner | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._resolver = resolver or TargetResolver()
        self._which = which
        self._run_process = run_process or _run_process
        self._monotonic = monotonic

    def scan(self, config: ScanConfig) -> ScanReport:
        endpoints = self._resolver.resolve(config)
        selected = endpoints[0]
        nmap_path = self._which("nmap")
        if not nmap_path:
            raise ToolUnavailableError("nmap is required for the scan command")
        executable = str(Path(nmap_path).resolve())
        if not Path(executable).is_file() or not os.access(executable, os.X_OK):
            raise ToolUnavailableError("resolved nmap path is not an executable file")

        command = self._build_command(executable, selected, config)
        started = self._monotonic()
        try:
            completed = self._run_process(
                command,
                capture_output=True,
                text=True,
                timeout=float(config.timeout) + 5.0,
                check=False,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            )
        except subprocess.TimeoutExpired as exc:
            raise ScanError("nmap exceeded the configured absolute timeout") from exc
        except OSError as exc:
            raise ScanError(f"nmap could not be started ({type(exc).__name__})") from exc

        if completed.returncode != 0:
            detail = _clean(completed.stderr or completed.stdout, limit=300)
            suffix = f": {detail}" if detail else ""
            raise ScanError(f"nmap exited with status {completed.returncode}{suffix}")
        xml_output = completed.stdout
        if len(xml_output.encode("utf-8")) > MAX_XML_BYTES:
            raise ScanError("nmap XML output exceeded the 5 MiB safety limit")
        host_up, open_ports = _parse_nmap_xml(xml_output)
        return ScanReport(
            target=config.target.hostname,
            selected_endpoint=selected,
            resolved_endpoints=endpoints,
            port_specification=config.ports.specification,
            duration_seconds=max(0.0, self._monotonic() - started),
            host_up=host_up,
            open_ports=open_ports,
        )

    @staticmethod
    def _build_command(
        executable: str,
        endpoint: ResolvedEndpoint,
        config: ScanConfig,
    ) -> list[str]:
        command = [
            executable,
            "-n",
            "-sT",
            "-T3",
            "--max-retries",
            "2",
            "--max-rate",
            str(config.max_rate),
            "--host-timeout",
            f"{math.ceil(float(config.timeout))}s",
        ]
        if endpoint.ip_version == 6:
            command.append("-6")
        if config.ports.full_scan:
            command.append("-p-")
        else:
            command.extend(("-p", config.ports.specification))
        command.extend(("-oX", "-", endpoint.address))
        return command


def _run_process(
    args: Sequence[str],
    *,
    capture_output: bool,
    text: bool,
    timeout: float,
    check: bool,
    env: Mapping[str, str],
) -> subprocess.CompletedProcess[str]:
    if not capture_output or not text:
        raise ValueError("the bounded process runner requires captured text output")
    process = subprocess.Popen(
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        raise ScanError("nmap output pipes could not be created")

    stdout = bytearray()
    stderr = bytearray()
    exceeded = threading.Event()
    readers = (
        threading.Thread(
            target=_read_bounded,
            args=(process.stdout, stdout, MAX_XML_BYTES, exceeded, process),
            daemon=True,
        ),
        threading.Thread(
            target=_read_bounded,
            args=(process.stderr, stderr, MAX_ERROR_BYTES, exceeded, process),
            daemon=True,
        ),
    )
    for reader in readers:
        reader.start()
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise
    finally:
        for reader in readers:
            reader.join()

    if exceeded.is_set():
        raise ScanError("nmap output exceeded the configured safety limit")
    completed = subprocess.CompletedProcess(
        args,
        returncode,
        stdout.decode("utf-8", errors="replace"),
        stderr.decode("utf-8", errors="replace"),
    )
    if check and returncode != 0:
        raise subprocess.CalledProcessError(
            returncode,
            args,
            output=completed.stdout,
            stderr=completed.stderr,
        )
    return completed


def _read_bounded(
    stream: BinaryIO,
    output: bytearray,
    limit: int,
    exceeded: threading.Event,
    process: subprocess.Popen[bytes],
) -> None:
    try:
        while chunk := stream.read(65_536):
            remaining = limit + 1 - len(output)
            if remaining > 0:
                output.extend(chunk[:remaining])
            if len(output) > limit or len(chunk) > remaining:
                exceeded.set()
                process.kill()
                return
    finally:
        stream.close()


def _parse_nmap_xml(xml_output: str) -> tuple[bool, tuple[OpenPort, ...]]:
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        raise ScanError("nmap returned malformed XML") from exc

    host = root.find("host")
    if host is None:
        return False, ()
    status = host.find("status")
    host_up = status is not None and status.get("state") == "up"
    open_ports: list[OpenPort] = []
    for port_element in host.findall("./ports/port"):
        state = port_element.find("state")
        if state is None or state.get("state") != "open":
            continue
        try:
            port = int(port_element.get("portid", ""))
        except ValueError as exc:
            raise ScanError("nmap XML contained an invalid port number") from exc
        if not 1 <= port <= 65_535:
            raise ScanError("nmap XML contained an out-of-range port number")
        service_element = port_element.find("service")
        open_ports.append(
            OpenPort(
                port=port,
                protocol=_clean(port_element.get("protocol", "tcp"), limit=16),
                service=_attribute(service_element, "name"),
                product=_attribute(service_element, "product"),
                version=_attribute(service_element, "version"),
            )
        )
    return host_up, tuple(sorted(open_ports, key=lambda item: (item.protocol, item.port)))


def _attribute(element: ET.Element | None, name: str) -> str | None:
    if element is None:
        return None
    value = element.get(name)
    return _clean(value, limit=120) if value else None


def _clean(value: str, *, limit: int) -> str:
    printable = "".join(character if character.isprintable() else " " for character in value)
    return " ".join(printable.split())[:limit]
