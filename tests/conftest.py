"""Shared pytest fixtures: build small in-memory emails on the fly so the
tests need no external sample files and run fully offline."""

from __future__ import annotations

from email.message import EmailMessage
from email.utils import formatdate
from pathlib import Path

import pytest


def _eml(headers: dict[str, str], body: str = "hello") -> bytes:
    m = EmailMessage()
    for k, v in headers.items():
        m[k] = v
    if "Date" not in headers:
        m["Date"] = formatdate()
    m.set_content(body)
    return m.as_bytes()


@pytest.fixture
def write_eml(tmp_path: Path):
    def _factory(name: str, headers: dict[str, str], body: str = "hello") -> Path:
        p = tmp_path / name
        p.write_bytes(_eml(headers, body))
        return p

    return _factory
