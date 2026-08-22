"""Bounded, single-pass text decoding helpers."""

from __future__ import annotations

import base64
import binascii
import codecs
from contextlib import suppress
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote_to_bytes

from .errors import ConfigurationError

MAX_INPUT_CHARACTERS = 65_536
MAX_DECODED_BYTES = 262_144


@dataclass(frozen=True, slots=True)
class DecodeCandidate:
    transformation: str
    value: str

    def to_dict(self) -> dict[str, Any]:
        return {"transformation": self.transformation, "value": self.value}


def decode_candidates(value: str) -> tuple[DecodeCandidate, ...]:
    if not value:
        raise ConfigurationError("decode input must not be empty")
    if len(value) > MAX_INPUT_CHARACTERS:
        raise ConfigurationError(f"decode input exceeds the {MAX_INPUT_CHARACTERS}-character limit")

    candidates: list[DecodeCandidate] = []
    seen: set[str] = set()

    def add(name: str, decoded: bytes | str) -> None:
        if isinstance(decoded, bytes):
            if len(decoded) > MAX_DECODED_BYTES:
                return
            try:
                text = decoded.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                return
        else:
            text = decoded
        if not text or text == value or text in seen:
            return
        seen.add(text)
        candidates.append(DecodeCandidate(name, text))

    compact = value.strip()
    if compact and not any(character.isspace() for character in compact):
        padded = compact + "=" * (-len(compact) % 4)
        with suppress(binascii.Error, ValueError):
            add("base64", base64.b64decode(padded, validate=True))
        with suppress(binascii.Error, ValueError):
            add("base64url", base64.b64decode(padded, altchars=b"-_", validate=True))
        base32_padded = compact.upper() + "=" * (-len(compact) % 8)
        with suppress(binascii.Error, ValueError):
            add("base32", base64.b32decode(base32_padded, casefold=False))
        if len(compact) % 2 == 0:
            with suppress(ValueError):
                add("hex", bytes.fromhex(compact))

    if _contains_percent_escape(value):
        with suppress(ValueError):
            add("url-percent", unquote_to_bytes(value))
    if any(character.isalpha() and character.isascii() for character in value):
        add("rot13", codecs.decode(value, "rot_13"))
    add("reverse", value[::-1])
    return tuple(candidates)


def _contains_percent_escape(value: str) -> bool:
    for index in range(len(value) - 2):
        if value[index] == "%" and all(
            character in "0123456789abcdefABCDEF" for character in value[index + 1 : index + 3]
        ):
            return True
    return False
