from __future__ import annotations

import shutil
import socket
import subprocess
from typing import NoReturn

import pytest


def _blocked(*_args: object, **_kwargs: object) -> NoReturn:
    raise AssertionError("real network and subprocess access is blocked in tests")


@pytest.fixture(autouse=True)
def block_external_effects(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("getaddrinfo", "gethostbyaddr", "gethostbyname", "gethostbyname_ex"):
        monkeypatch.setattr(socket, name, _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "socket", _blocked)
    for name in ("Popen", "call", "check_call", "check_output", "run"):
        monkeypatch.setattr(subprocess, name, _blocked)
    monkeypatch.setattr(shutil, "which", _blocked)
