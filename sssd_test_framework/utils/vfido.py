"""Manage GDM interface from SCAutolib."""

from __future__ import annotations

from pytest_mh import MultihostHost, MultihostUtility

__all__ = [
    "Vfido",
]


class Vfido(MultihostUtility[MultihostHost]):
    """
    Manage virtual passkey device and service
    """

    def __init__(self, host):
        super().__init__(host)

    def teardown(self):
        pass

    def stop(self) -> None:
        """Stop vfido service"""
        self.host.conn.exec(["systemctl", "stop", "vfido"])

    def start(self) -> None:
        """Start vfido service"""
        self.host.conn.exec(["systemctl", "start", "vfido"])

    def reset(self) -> None:
        """reset state of vfido service back to clean"""
        self.stop()
        self.host.conn.exec(["/opt/test_venv/bin/vfido_reset"])

    def touch(self) -> bool:
        """
        send touch signal to vitrual passkey
        """
        result = self.host.conn.exec(["/opt/test_venv/bin/vfido_touch"])
        return result.rc == 0

    def pin_set(self, pin: str | int) -> None:
        """Set pin on virtual passkey"""
        self.host.conn.exec(["/opt/test_venv/bin/vfido_pin_set", pin])

    def pin_enable(self) -> None:
        """Set pin on virtual passkey"""
        self.host.conn.exec(["/opt/test_venv/bin/vfido_pin_enable"])

    def pin_disable(self) -> None:
        """Set pin on virtual passkey"""
        self.host.conn.exec(["/opt/test_venv/bin/vfido_pin_enable"])
