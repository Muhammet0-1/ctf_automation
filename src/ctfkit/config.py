"""Strict parsing and resource limits for CTFKit commands."""

from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass

from .errors import ConfigurationError

MAX_TARGET_LENGTH = 253
MAX_EXPLICIT_PORTS = 4_096
DEFAULT_PORTS = "1-1024"


@dataclass(frozen=True, slots=True)
class Target:
    hostname: str


def parse_target(value: str) -> Target:
    if not value or value != value.strip():
        raise ConfigurationError("target must not be empty or surrounded by whitespace")
    if len(value) > MAX_TARGET_LENGTH:
        raise ConfigurationError(f"target exceeds the {MAX_TARGET_LENGTH}-character limit")
    if any(ord(character) < 33 or ord(character) == 127 for character in value):
        raise ConfigurationError("target must not contain whitespace or control characters")
    if any(marker in value for marker in ("/", "\\", "?", "#", "@", "*", "[", "]")):
        raise ConfigurationError("target must be one hostname or unbracketed IP address")
    if ":" in value:
        try:
            return Target(str(ipaddress.IPv6Address(value)))
        except ipaddress.AddressValueError as exc:
            raise ConfigurationError("target is not a valid IPv6 address") from exc

    lowered = value.rstrip(".").lower()
    try:
        return Target(str(ipaddress.IPv4Address(lowered)))
    except ipaddress.AddressValueError:
        try:
            ascii_hostname = lowered.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ConfigurationError("target hostname is not valid IDNA") from exc
    labels = ascii_hostname.split(".")
    if not ascii_hostname or len(ascii_hostname) > MAX_TARGET_LENGTH:
        raise ConfigurationError("target hostname is too long")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not all(character.isalnum() or character == "-" for character in label)
        for label in labels
    ):
        raise ConfigurationError("target hostname is invalid")
    return Target(ascii_hostname)


@dataclass(frozen=True, slots=True)
class PortSelection:
    specification: str
    count: int
    full_scan: bool = False


def parse_port_selection(value: str) -> PortSelection:
    if value == "all":
        return PortSelection("1-65535", 65_535, full_scan=True)
    if not value or value != value.strip() or any(character.isspace() for character in value):
        raise ConfigurationError("port specification must not be empty or contain whitespace")

    ports: set[int] = set()
    for segment in value.split(","):
        if not segment:
            raise ConfigurationError("port specification contains an empty segment")
        if "-" in segment:
            start_text, separator, end_text = segment.partition("-")
            if not separator or not start_text.isdecimal() or not end_text.isdecimal():
                raise ConfigurationError("port ranges must use START-END integers")
            start, end = int(start_text), int(end_text)
            if start > end:
                raise ConfigurationError("port range start must not exceed its end")
            if not 1 <= start <= end <= 65_535:
                raise ConfigurationError("ports must be between 1 and 65535")
            ports.update(range(start, end + 1))
        else:
            if not segment.isdecimal():
                raise ConfigurationError("ports must be decimal integers or ranges")
            port = int(segment)
            if not 1 <= port <= 65_535:
                raise ConfigurationError("ports must be between 1 and 65535")
            ports.add(port)
        if len(ports) > MAX_EXPLICIT_PORTS:
            raise ConfigurationError(
                f"explicit selections are limited to {MAX_EXPLICIT_PORTS} unique ports"
            )
    return PortSelection(_compress_ports(ports), len(ports))


def _compress_ports(ports: set[int]) -> str:
    ordered = sorted(ports)
    ranges: list[str] = []
    start = previous = ordered[0]
    for port in ordered[1:]:
        if port == previous + 1:
            previous = port
            continue
        ranges.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = port
    ranges.append(str(start) if start == previous else f"{start}-{previous}")
    return ",".join(ranges)


@dataclass(frozen=True, slots=True)
class ScanConfig:
    target: Target
    ports: PortSelection
    acknowledge_authorization: bool
    allow_public_target: bool = False
    acknowledge_full_scan: bool = False
    timeout: float = 300.0
    max_rate: int = 100

    def __post_init__(self) -> None:
        if not isinstance(self.target, Target):
            raise ConfigurationError("target must be parsed with parse_target")
        if parse_target(self.target.hostname) != self.target:
            raise ConfigurationError("target must use the canonical parsed representation")
        if not isinstance(self.ports, PortSelection):
            raise ConfigurationError("ports must be parsed with parse_port_selection")
        if not isinstance(self.ports.full_scan, bool):
            raise ConfigurationError("full_scan must be a boolean")
        if self.ports.full_scan:
            if self.ports.specification != "1-65535" or self.ports.count != 65_535:
                raise ConfigurationError("full port selection is malformed")
        else:
            parsed_ports = parse_port_selection(self.ports.specification)
            if parsed_ports != self.ports:
                raise ConfigurationError("ports must use the canonical parsed representation")
        for name in (
            "acknowledge_authorization",
            "allow_public_target",
            "acknowledge_full_scan",
        ):
            if not isinstance(getattr(self, name), bool):
                raise ConfigurationError(f"{name} must be a boolean")
        if not self.acknowledge_authorization:
            raise ConfigurationError("explicit authorization acknowledgement is required")
        if self.ports.full_scan and not self.acknowledge_full_scan:
            raise ConfigurationError("full port scans require --acknowledge-full-scan")
        if not _bounded_float(self.timeout, 1.0, 600.0):
            raise ConfigurationError("scan timeout must be between 1 and 600 seconds")
        if (
            isinstance(self.max_rate, bool)
            or not isinstance(self.max_rate, int)
            or not 1 <= self.max_rate <= 1_000
        ):
            raise ConfigurationError("maximum packet rate must be between 1 and 1000")


def _bounded_float(value: object, minimum: float, maximum: float) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    numeric = float(value)
    return math.isfinite(numeric) and minimum <= numeric <= maximum
