"""Unit tests for :mod:`sssd_test_framework.utils.tools`."""

from __future__ import annotations

import pytest

from sssd_test_framework.utils.tools import AHostSv4Entry


@pytest.mark.parametrize(
    "stdout, expected_ip",
    [
        ("192.168.1.1 STREAM hostname.example\n", "192.168.1.1"),
        ("10.0.0.5       STREAM foo\n10.0.0.6       STREAM foo\n", "10.0.0.5"),
        ("", None),
        ("\n\n", None),
    ],
)
def test_ahostsv4_entry_from_output(stdout: str, expected_ip: str | None) -> None:
    entry = AHostSv4Entry.FromOutput(stdout)
    if expected_ip is None:
        assert entry is None
    else:
        assert entry is not None
        assert entry.ip == expected_ip
