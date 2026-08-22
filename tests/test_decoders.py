from __future__ import annotations

import pytest

from ctfkit.decoders import decode_candidates
from ctfkit.errors import ConfigurationError


def values(raw: str) -> dict[str, str]:
    return {item.transformation: item.value for item in decode_candidates(raw)}


def test_base64_hex_url_and_rot13_candidates() -> None:
    assert values("SGVsbG8gQ1RG")["base64"] == "Hello CTF"
    assert values("48656c6c6f")["hex"] == "Hello"
    assert values("hello%20ctf")["url-percent"] == "hello ctf"
    assert values("uryyb")["rot13"] == "hello"


def test_base64url_and_reverse_are_single_pass() -> None:
    result = values("SGVsbG8td29ybGQ_")
    assert result["base64url"] == "Hello-world?"
    assert result["reverse"] == "_QGby92dt8GbsVGS"


def test_binary_decode_output_is_not_rendered_as_text() -> None:
    result = values("//79")
    assert "base64" not in result


def test_candidates_are_deduplicated() -> None:
    candidates = decode_candidates("4141")
    assert len({item.value for item in candidates}) == len(candidates)


@pytest.mark.parametrize("raw", ["", "x" * 65_537])
def test_decoder_rejects_empty_and_oversized_input(raw: str) -> None:
    with pytest.raises(ConfigurationError):
        decode_candidates(raw)
