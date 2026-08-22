"""Immutable result models shared by command handlers and reporters."""

from __future__ import annotations

from dataclasses import dataclass
from socket import AddressFamily
from typing import Any


@dataclass(frozen=True, slots=True)
class ResolvedEndpoint:
    family: AddressFamily
    address: str

    @property
    def ip_version(self) -> int:
        return 6 if self.family is AddressFamily.AF_INET6 else 4

    def to_dict(self) -> dict[str, Any]:
        return {"address": self.address, "ip_version": self.ip_version}


@dataclass(frozen=True, slots=True)
class OpenPort:
    port: int
    protocol: str
    service: str | None = None
    product: str | None = None
    version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"port": self.port, "protocol": self.protocol}
        if self.service:
            data["service"] = self.service
        if self.product:
            data["product"] = self.product
        if self.version:
            data["version"] = self.version
        return data
