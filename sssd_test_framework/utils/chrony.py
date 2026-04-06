"""
Chrony Utilities

"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Generator

import pytest
from pytest_mh import MultihostHost, MultihostUtility

__all__ = ["ChronyUtils"]


class ChronyUtils(MultihostUtility[MultihostHost]):
    """
    Interface for manipulating system time via chrony.

    :meth:`time_skew` takes **seconds** (signed): forward if non-negative, backward
    if negative (e.g. ``86400`` for one day forward, ``-3600`` for one hour back).
    It is a context manager: skew applies for the ``with`` body, then the clock is
    restored. If chronyd cannot enter manual mode, the current test is skipped
    via :func:`pytest.skip`. If ``settime`` fails after that, :exc:`RuntimeError`
    is raised.

    .. code-block:: python
        :caption: Example usage

        @pytest.mark.topology(KnownTopology.LDAP)
        def test_clock_skew(client: Client, provider: GenericProvider, kdc: KDC):
            # ... setup ...
            if not client.chrony.is_available():
                pytest.skip("chronyc not available")

            with client.chrony.time_skew(24 * 60 * 60):  # +1 day
                auth_ok = client.auth.ssh.password("user", "Secret123")
                assert not auth_ok, "Auth should fail due to clock skew!"
    """

    def __init__(self, host: MultihostHost) -> None:
        """
        :param host: Multihost host.
        :type host: MultihostHost
        """
        super().__init__(host)

    def is_available(self) -> bool:
        """
        Check if ``chronyc`` is available on the host.

        :return: True if chronyc is found, False otherwise.
        :rtype: bool
        """
        result = self.host.conn.run("which chronyc", raise_on_error=False)
        return result.rc == 0

    @staticmethod
    def _offset_from_seconds(seconds: int) -> str:
        """
        Build a chrony ``settime`` relative offset from a signed second count.

        :param seconds: Signed offset in seconds (forward if non-negative, backward if negative).
        :type seconds: int
        :return: Chrony relative time string (e.g. ``"+ 3600 seconds"``, ``"- 60 seconds"``).
        :rtype: str
        """
        if seconds >= 0:
            return f"+ {seconds} seconds"
        return f"- {-seconds} seconds"

    @contextmanager
    def time_skew(self, seconds: int) -> Generator[None, None, None]:
        """
        Context manager that skews the system clock and restores it afterward.

        Restarts ``chronyd``, enables manual mode, applies the offset via
        ``chronyc settime``, then yields for the ``with`` body. On exit (normal or
        exception), the saved time is restored and NTP is re-synced.

        :param seconds: Signed offset in seconds (forward if non-negative, backward
            if negative; e.g. ``86400`` for one day forward, ``-3600`` for one hour back).
        :type seconds: int
        :yields: ``None`` — run assertions or steps while the clock is skewed.

        If ``chronyd`` restart or ``chronyc manual on`` fails, the current test is
        skipped via :func:`pytest.skip`.

        :raises RuntimeError: If the ``settime`` batch fails once manual mode is on.
        """
        offset = self._offset_from_seconds(seconds)
        result = self.host.conn.run("date '+%a %b %d %H:%M:%S'")
        saved_time = result.stdout.strip()

        result = self.host.conn.run(
            "systemctl restart chronyd && chronyc -a 'manual on' 2>&1",
            raise_on_error=False,
        )
        if result.rc != 0:
            pytest.skip(f"chronyd not running or manual mode failed: {result.stdout}")

        try:
            result = self.host.conn.run(
                f"chronyc -a -m 'offline' 'settime {offset}' 'makestep' 'manual reset' 2>&1",
                raise_on_error=False,
            )
            if "200 OK" not in result.stdout and result.rc != 0:
                detail = result.stderr.strip() or result.stdout.strip() or f"rc={result.rc}"
                raise RuntimeError(f"chrony settime failed: {detail}")

            yield
        finally:
            self.host.conn.run(
                f"chronyc -a -m 'settime {saved_time} + 10 seconds'" " 'makestep' 'manual reset' 'online' 2>&1",
                raise_on_error=False,
            )
            self.host.conn.run(
                "systemctl stop chronyd 2>/dev/null;"
                " chronyd -q 'server clock.redhat.com iburst' 2>/dev/null;"
                " systemctl start chronyd 2>/dev/null || true",
                raise_on_error=False,
            )
