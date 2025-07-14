"""Manage socket-activated responders in SSSD for testing purposes."""

from __future__ import annotations

import re
from typing import Final, Optional

from pytest_mh import MultihostHost, MultihostUtility

__all__ = [
    "SSSDSocketResponder",
    "SSSDSocketUtils",
    "ResponderType",
]


class ResponderType(str):
    """
    Well-known SSSD responders that support socket activation.
    """

    NSS: Final = "nss"
    """Name Service Switch responder"""

    PAM: Final = "pam"
    """Pluggable Authentication Module responder"""

    SUDO: Final = "sudo"
    """Sudo responder"""

    SSH: Final = "ssh"
    """SSH responder"""

    PAC: Final = "pac"
    """Privilege Attribute Certificate responder"""

    AUTOFS: Final = "autofs"
    """Automount responder"""


class SSSDSocketResponder:
    """
    Represents an SSSD socket-activated responder (e.g., nss, pam).
    Provides methods to manage its socket and service units, and
    record/restore their systemd state for test teardown.
    """

    def __init__(
        self,
        host: MultihostHost,
        responder: str,
    ) -> None:
        """
        Initialize a socket-activated responder object.

        :param host: The host where SSSD services run.
        :type host: MultihostHost
        :param responder: The responder type (e.g., 'nss', 'pam').
        :type responder: str
        """
        self.host = host
        self.responder = responder
        self.socket_unit = f"sssd-{responder}.socket"
        self.service_unit = f"sssd-{responder}.service"

        self._was_socket_enabled: Optional[bool] = None
        self._was_socket_active: Optional[bool] = None
        self._was_service_active: Optional[bool] = None

    def snapshot(self) -> None:
        """
        Capture and remember the current systemd state of the responder.

        This method stores:
        - Whether the socket is enabled
        - Whether the socket is active
        - Whether the responder service is active

        These are later used by `restore()` to revert the system to its original state.
        """
        self._was_socket_enabled = self._is_enabled(self.socket_unit)
        self._was_socket_active = self._is_active(self.socket_unit)
        self._was_service_active = self._is_active(self.service_unit)

    def restore(self) -> None:
        """
        Restore the responder to the original systemd state as remembered by `snapshot()`.

        If no snapshot was taken, this method does nothing.
        """
        if self._was_socket_enabled is not None:
            if self._was_socket_enabled:
                self.enable()
            else:
                self.disable()

        if self._was_socket_active is not None:
            if self._was_socket_active:
                self.start()
            else:
                self.stop()

        if self._was_service_active is not None:
            cmd = "start" if self._was_service_active else "stop"
            self.host.conn.exec(["systemctl", cmd, self.service_unit])

    def _is_enabled(self, unit: str) -> bool:
        """Return True if the given systemd unit is enabled."""
        result = self.host.conn.exec(["systemctl", "is-enabled", unit], raise_on_error=False)
        return result.stdout.strip() == "enabled"

    def _is_active(self, unit: str) -> bool:
        """Return True if the given systemd unit is active."""
        result = self.host.conn.exec(["systemctl", "is-active", unit], raise_on_error=False)
        return result.stdout.strip() == "active"

    def enable(self) -> None:
        """
        Enable the responder's socket unit.
        """
        result = self.host.conn.exec(["systemctl", "enable", self.socket_unit], raise_on_error=False)
        if result.rc != 0:
            raise RuntimeError(f"Failed to enable {self.socket_unit}: {result.stderr}")

    def disable(self) -> None:
        """
        Disable the responder's socket unit.
        """
        result = self.host.conn.exec(["systemctl", "disable", self.socket_unit], raise_on_error=False)
        if result.rc != 0:
            raise RuntimeError(f"Failed to disable {self.socket_unit}: {result.stderr}")

    def start(self) -> None:
        """
        Start the responder's socket unit.
        """
        result = self.host.conn.exec(["systemctl", "start", self.socket_unit], raise_on_error=False)
        if result.rc != 0:
            raise RuntimeError(f"Failed to start {self.socket_unit}: {result.stderr}")

    def stop(self) -> None:
        """
        Stop the responder's socket unit.
        """
        result = self.host.conn.exec(["systemctl", "stop", self.socket_unit], raise_on_error=False)
        if result.rc != 0:
            raise RuntimeError(f"Failed to stop {self.socket_unit}: {result.stderr}")

    def is_socket_active(self) -> bool:
        """
        Check if the responder's socket unit is active.

        :return: True if active, False otherwise.
        :rtype: bool
        """
        result = self.host.conn.exec(["systemctl", "is-active", self.socket_unit], raise_on_error=False)
        return result.stdout.strip() == "active"

    def is_service_active(self) -> bool:
        """
        Check if the responder's service unit is active.

        :return: True if active, False otherwise.
        :rtype: bool
        """
        result = self.host.conn.exec(["systemctl", "is-active", self.service_unit], raise_on_error=False)
        return result.stdout.strip() == "active"

    def get_socket_path(self) -> Optional[str]:
        """
        Get the UNIX socket path for the responder.

        :return: Socket path if found, None otherwise.
        :rtype: Optional[str]
        """
        result = self.host.conn.exec(
            ["systemctl", "show", self.socket_unit, "--property=Listen"], raise_on_error=False
        )
        if result.rc != 0:
            raise RuntimeError(f"Failed to get socket path for {self.socket_unit}: {result.stderr}")

        match = re.search(r"Listen=([^\s]+)", result.stdout)
        return match.group(1) if match else None


class SSSDSocketUtils(MultihostUtility[MultihostHost]):
    def __init__(self, host: MultihostHost) -> None:
        super().__init__(host)

    @property
    def nss(self) -> SSSDSocketResponder:
        return SSSDSocketResponder(self.host, ResponderType.NSS)

    @property
    def pam(self) -> SSSDSocketResponder:
        return SSSDSocketResponder(self.host, ResponderType.PAM)

    @property
    def sudo(self) -> SSSDSocketResponder:
        return SSSDSocketResponder(self.host, ResponderType.SUDO)

    @property
    def ssh(self) -> SSSDSocketResponder:
        return SSSDSocketResponder(self.host, ResponderType.SSH)

    @property
    def pac(self) -> SSSDSocketResponder:
        return SSSDSocketResponder(self.host, ResponderType.PAC)

    @property
    def autofs(self) -> SSSDSocketResponder:
        return SSSDSocketResponder(self.host, ResponderType.AUTOFS)

    def remove_services_from_sssd_conf(
        self,
        socket_responders: Optional[list[str]] = None,
        conf_path: str = "/etc/sssd/sssd.conf",
    ) -> None:
        """
        Remove only the socket-activated responders from the 'services' line in sssd.conf.
        Remove the entire line if it becomes empty after removal.

        :param socket_responders: List of responders to remove (default: all known).
        :param conf_path: str(default: "/etc/sssd/sssd.conf").
        """
        socket_responders = socket_responders or [
            ResponderType.NSS,
            ResponderType.PAM,
            ResponderType.SUDO,
            ResponderType.SSH,
            ResponderType.PAC,
            ResponderType.AUTOFS,
        ]

        # Extract current services line
        result = self.host.conn.exec(["grep", "^services[[:space:]]*=", conf_path], raise_on_error=False)
        if result.rc != 0:
            # No services line found — nothing to do
            return

        match = re.search(r"^services\s*=\s*(.*)", result.stdout.strip())
        if not match:
            return

        current_services = [s.strip() for s in match.group(1).split(",")]
        updated_services = [s for s in current_services if s not in socket_responders]

        if not updated_services:
            # Remove the line entirely
            self.host.conn.exec(["sed", "-i", "/^services[[:space:]]*=.*$/d", conf_path])
        else:
            new_line = f"services = {','.join(updated_services)}"
            self.host.conn.exec(["sed", "-i", f"s/^services[[:space:]]*=.*/{new_line}/", conf_path])

        # Restart SSSD to apply changes
        self.host.conn.exec(["systemctl", "restart", "sssd.service"])

    def socket_teardown(self) -> None:
        """
        Teardown socket-activated SSSD responders and restore systemd state.

        This method performs the following:

        - Stops all socket and service units associated with known responders.
        - If a responder was snapshot (via ``snapshot()``), restores the
          original enabled/active state of its socket and service units.

        Note:
            This method does **not** revert changes to ``sssd.conf``.
            It assumes that configuration cleanup is handled elsewhere
            in the test framework.
        """
        responders = [self.nss, self.pam, self.sudo, self.ssh, self.pac, self.autofs]

        for responder in responders:
            responder.stop()
            self.host.conn.exec(["systemctl", "stop", responder.service_unit])

            # Restore original state if known
            if responder._was_socket_enabled is not None:
                responder.restore()

        super().teardown()
