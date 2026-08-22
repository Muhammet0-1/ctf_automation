from __future__ import annotations

import socket

import pytest

from ctfkit.config import PortSelection, ScanConfig, Target, parse_port_selection, parse_target
from ctfkit.errors import ConfigurationError, ResolutionError
from ctfkit.resolution import TargetResolver


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Example.COM.", "example.com"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("10.10.10.10", "10.10.10.10"),
        ("fd00::1", "fd00::1"),
    ],
)
def test_target_parser_normalizes_supported_targets(raw: str, expected: str) -> None:
    assert parse_target(raw).hostname == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        " example.com",
        "example.com/path",
        "https://example.com",
        "user@example.com",
        "*.example.com",
        "[::1]",
        "bad_label.example",
        "-bad.example",
        "example.com:80",
    ],
)
def test_target_parser_rejects_ambiguous_targets(raw: str) -> None:
    with pytest.raises(ConfigurationError):
        parse_target(raw)


@pytest.mark.parametrize(
    ("raw", "canonical", "count", "full"),
    [
        ("80", "80", 1, False),
        ("80,443,8000-8002", "80,443,8000-8002", 5, False),
        ("80,80,79-81", "79-81", 3, False),
        ("all", "1-65535", 65_535, True),
    ],
)
def test_port_parser_canonicalizes_valid_selections(
    raw: str, canonical: str, count: int, full: bool
) -> None:
    selection = parse_port_selection(raw)
    assert selection.specification == canonical
    assert selection.count == count
    assert selection.full_scan is full


@pytest.mark.parametrize(
    "raw",
    ["", "80, 443", "0", "65536", "100-99", "x", "80,", "1-4097"],
)
def test_port_parser_rejects_invalid_or_excessive_selections(raw: str) -> None:
    with pytest.raises(ConfigurationError):
        parse_port_selection(raw)


def make_config(target_value: str = "lab.test", **kwargs: object) -> ScanConfig:
    values: dict[str, object] = {
        "target": parse_target(target_value),
        "ports": parse_port_selection("80"),
        "acknowledge_authorization": True,
    }
    values.update(kwargs)
    return ScanConfig(**values)  # type: ignore[arg-type]


def test_scan_config_requires_authorization_and_full_scan_confirmation() -> None:
    with pytest.raises(ConfigurationError, match="authorization"):
        make_config(acknowledge_authorization=False)
    with pytest.raises(ConfigurationError, match="full port"):
        make_config(ports=parse_port_selection("all"))
    assert make_config(
        ports=parse_port_selection("all"), acknowledge_full_scan=True
    ).ports.full_scan


@pytest.mark.parametrize(
    "kwargs",
    [
        {"timeout": float("nan")},
        {"timeout": 0.5},
        {"timeout": 601},
        {"max_rate": True},
        {"max_rate": 0},
        {"max_rate": 1001},
        {"allow_public_target": "yes"},
    ],
)
def test_scan_config_rejects_invalid_bounds_and_truthy_non_booleans(
    kwargs: dict[str, object],
) -> None:
    with pytest.raises(ConfigurationError):
        make_config(**kwargs)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"target": Target("LAB.test")},
        {"ports": PortSelection("80,80", 1)},
        {"ports": PortSelection("-A", 1)},
        {"ports": PortSelection("1-65535", 65_535, full_scan="yes")},
        {"ports": PortSelection("1-65534", 65_535, full_scan=True)},
    ],
)
def test_scan_config_rejects_directly_constructed_noncanonical_values(
    kwargs: dict[str, object],
) -> None:
    with pytest.raises(ConfigurationError):
        make_config(**kwargs)


def fake_resolver(*addresses: str) -> TargetResolver:
    records = []
    for address in addresses:
        if ":" in address:
            records.append(
                (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 0, 0, 0))
            )
        else:
            records.append(
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 0))
            )
    return TargetResolver(lambda *_args, **_kwargs: records)


@pytest.mark.parametrize(
    "address", ["127.0.0.1", "10.10.10.10", "172.16.1.1", "192.168.1.1", "fd00::1", "::1"]
)
def test_resolver_accepts_explicit_local_ranges(address: str) -> None:
    endpoints = fake_resolver(address).resolve(make_config())
    assert endpoints[0].address == address


def test_resolver_requires_flag_for_public_addresses() -> None:
    resolver = fake_resolver("8.8.8.8")
    with pytest.raises(ResolutionError, match="public"):
        resolver.resolve(make_config())
    assert resolver.resolve(make_config(allow_public_target=True))[0].address == "8.8.8.8"


@pytest.mark.parametrize(
    "address",
    [
        "0.0.0.0",
        "100.64.0.1",
        "169.254.1.1",
        "192.0.2.1",
        "224.0.0.1",
        "fe80::1",
        "2001:db8::1",
        "::ffff:10.0.0.1",
        "2002:0808:0808::1",
    ],
)
def test_resolver_rejects_reserved_transition_and_mapped_addresses(address: str) -> None:
    with pytest.raises(ResolutionError):
        fake_resolver(address).resolve(make_config(allow_public_target=True))


def test_resolver_rejects_mixed_and_oversized_answers() -> None:
    with pytest.raises(ResolutionError, match="mixed"):
        fake_resolver("10.0.0.1", "8.8.8.8").resolve(make_config(allow_public_target=True))
    with pytest.raises(ResolutionError, match="exceeding"):
        fake_resolver(*(f"10.0.0.{index}" for index in range(1, 10))).resolve(make_config())


def test_resolver_deduplicates_and_sorts_answers() -> None:
    endpoints = fake_resolver("10.0.0.2", "10.0.0.1", "10.0.0.1").resolve(make_config())
    assert [item.address for item in endpoints] == ["10.0.0.1", "10.0.0.2"]
