"""Manage virtual FIDO device."""

from __future__ import annotations

from pytest_mh import MultihostHost, MultihostUtility

from ..misc.globals import test_venv_bin

__all__ = [
    "Vfido",
]


class Vfido(MultihostUtility[MultihostHost]):
    """
    Manage virtual passkey device and service
    """

    def __init__(self, host: MultihostHost):
        super().__init__(host)

    def stop(self) -> bool:
        """
        Stop vfido service

        :return: True if service stop succeeds, else False
        :rtype: bool
        """
        result = self.host.conn.exec(["systemctl", "stop", "vfido"])
        return result.rc == 0

    def start(self) -> bool:
        """
        Start vfido service

        :return: True if service start succeeds, else False
        :rtype: bool
        """
        result = self.host.conn.exec(["systemctl", "start", "vfido"])
        return result.rc == 0

    def reset(self) -> bool:
        """
        reset state of vfido service back to clean

        :return: True if vfido_reset succeeds, else False
        :rtype: bool
        """
        self.stop()
        result = self.host.conn.exec([f"{test_venv_bin}/vfido_reset"])
        return result.rc == 0

    def touch(self) -> bool:
        """
        send touch signal to virtual passkey

        :return: True if the touch signal was sent successfully, else False
        :rtype: bool
        """
        result = self.host.conn.exec([f"{test_venv_bin}/vfido_touch"])
        return result.rc == 0

    def pin_set(self, pin: str | int) -> bool:
        """
        Set pin on virtual passkey

        :return: Trun if setting pin succeeds, else False
        :rtype: bool
        """
        result = self.host.conn.exec([f"{test_venv_bin}/vfido_pin_set", str(pin)])
        return result.rc == 0

    def pin_enable(self) -> bool:
        """
        Enable pin on virtual passkey

        :return: True if enabling pin succeeds, else False
        :rtype: bool
        """
        result = self.host.conn.exec([f"{test_venv_bin}/vfido_pin_enable"])
        return result.rc == 0

    def pin_disable(self) -> bool:
        """
        Disable pin on virtual passkey

        :return: Trun if disabling pin succeeds, else False
        :rtype: bool
        """
        result = self.host.conn.exec([f"{test_venv_bin}/vfido_pin_disable"])
        return result.rc == 0
