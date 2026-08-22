"""Resolve one authorized scan target into a bounded, approved address set."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Iterable
from enum import Enum
from typing import Any

from .config import ScanConfig
from .errors import ResolutionError
from .models import ResolvedEndpoint

MAX_RESOLVED_ENDPOINTS = 8
GetAddrInfo = Callable[..., Iterable[tuple[Any, Any, Any, Any, tuple[Any, ...]]]]

IPV4_LOCAL_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")
)
IPV6_LOCAL_NETWORKS = tuple(ipaddress.ip_network(network) for network in ("fc00::/7", "::1/128"))


class AddressScope(str, Enum):
    LOCAL = "local"
    PUBLIC = "public"


class TargetResolver:
    def __init__(self, getaddrinfo: GetAddrInfo | None = None) -> None:
        self._getaddrinfo = getaddrinfo or socket.getaddrinfo

    def resolve(self, config: ScanConfig) -> tuple[ResolvedEndpoint, ...]:
        try:
            records = self._getaddrinfo(
                config.target.hostname,
                None,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
        except (socket.gaierror, UnicodeError, ValueError) as exc:
            raise ResolutionError(
                f"target hostname could not be resolved: {config.target.hostname}"
            ) from exc

        endpoints: dict[tuple[int, str], ResolvedEndpoint] = {}
        scopes: set[AddressScope] = set()
        for family_raw, _socktype, _protocol, _canonical, sockaddr in records:
            try:
                family = socket.AddressFamily(family_raw)
            except ValueError:
                continue
            if family not in (socket.AddressFamily.AF_INET, socket.AddressFamily.AF_INET6):
                continue
            address = str(sockaddr[0])
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError as exc:
                raise ResolutionError("resolver returned an invalid IP address") from exc
            scope = _classify_address(parsed)
            scopes.add(scope)
            endpoints[(int(family), str(parsed))] = ResolvedEndpoint(family, str(parsed))

        if not endpoints:
            raise ResolutionError("target has no usable IPv4 or IPv6 address")
        if len(endpoints) > MAX_RESOLVED_ENDPOINTS:
            raise ResolutionError(
                f"target resolved to {len(endpoints)} addresses, exceeding the limit of "
                f"{MAX_RESOLVED_ENDPOINTS}"
            )
        if len(scopes) != 1:
            raise ResolutionError("target resolves to a mixed local/public address set")
        if AddressScope.PUBLIC in scopes and not config.allow_public_target:
            raise ResolutionError(
                "target resolves to a public address; use --allow-public-target only with "
                "explicit scope authorization"
            )
        return tuple(sorted(endpoints.values(), key=lambda item: (item.ip_version, item.address)))


def _classify_address(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> AddressScope:
    if isinstance(address, ipaddress.IPv6Address):
        if (
            address.ipv4_mapped is not None
            or address.sixtofour is not None
            or address.teredo is not None
        ):
            raise ResolutionError(f"transition or mapped IPv6 address is prohibited: {address}")
        if any(address in network for network in IPV6_LOCAL_NETWORKS):
            return AddressScope.LOCAL
    elif any(address in network for network in IPV4_LOCAL_NETWORKS):
        return AddressScope.LOCAL

    if address.is_global and not address.is_multicast:
        return AddressScope.PUBLIC
    raise ResolutionError(
        f"reserved, link-local, multicast, or unspecified address is prohibited: {address}"
    )
