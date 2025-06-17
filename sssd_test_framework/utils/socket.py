"""Manage socket-activated responders in SSSD for testing purposes."""

from __future__ import annotations

import re
from typing import Final, Optional

from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.conn import ProcessResult

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
    Provides methods to manage its socket and service units.
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
        if responder not in [
            ResponderType.NSS,
            ResponderType.PAM,
            ResponderType.SUDO,
            ResponderType.SSH,
            ResponderType.PAC,
            ResponderType.AUTOFS,
        ]:
            raise ValueError(f"Unknown responder: {responder}")

        self.host = host
        self.responder = responder
        self.socket_unit = f"sssd-{responder}.socket"
        self.service_unit = f"sssd-{responder}.service"

    def enable_socket(self) -> None:
        """
        Enable the responder's socket unit.
        """
        result = self.host.conn.exec(["systemctl", "enable", self.socket_unit], raise_on_error=False)
        if result.rc != 0:
            raise RuntimeError(f"Failed to enable {self.socket_unit}: {result.stderr}")

    def disable_socket(self) -> None:
        """
        Disable the responder's socket unit.
        """
        result = self.host.conn.exec(["systemctl", "disable", self.socket_unit], raise_on_error=False)
        if result.rc != 0:
            raise RuntimeError(f"Failed to disable {self.socket_unit}: {result.stderr}")

    def start_socket(self) -> None:
        """
        Start the responder's socket unit.
        """
        result = self.host.conn.exec(["systemctl", "start", self.socket_unit], raise_on_error=False)
        if result.rc != 0:
            raise RuntimeError(f"Failed to start {self.socket_unit}: {result.stderr}")

    def stop_socket(self) -> None:
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

    def trigger_socket(self, command: str, args: list[str] = []) -> ProcessResult:
        """
        Trigger the responder by running a command that activates the socket.

        :param command: Command to trigger the responder (e.g., 'getent', 'sssctl').
        :type command: str
        :param args: Arguments for the command.
        :type args: list[str]
        :return: Process result of the command.
        :rtype: ProcessResult
        """
        result = self.host.conn.exec([command, *args], raise_on_error=False)
        if result.rc != 0 and "Connection refused" in result.stderr:
            raise RuntimeError(f"Socket activation failed for {self.responder}: {result.stderr}")
        return result


class SSSDSocketUtils(MultihostUtility[MultihostHost]):
    """
    Utility class to manage SSSD socket-activated responders in tests.
    """

    def __init__(self, host: MultihostHost) -> None:
        """
        Initialize the socket utilities for SSSD responders.

        :param host: Remote host.
        :type host: MultihostHost
        """
        super().__init__(host)
        self.responders: dict[str, SSSDSocketResponder] = {}

    def get_responder(self, responder: str) -> SSSDSocketResponder:
        """
        Get or create an SSSDSocketResponder object for the given responder.

        :param responder: Responder type (e.g., 'nss', 'pam').
        :type responder: str
        :return: Responder object.
        :rtype: SSSDSocketResponder
        """
        if responder not in self.responders:
            self.responders[responder] = SSSDSocketResponder(self.host, responder)
        return self.responders[responder]

    def remove_services_from_sssd_conf(self) -> None:
        """
        Remove the 'services' line from sssd.conf to test socket activation.
        """
        result = self.host.conn.exec(
            ["sed", "-i", "/^services[[:space:]]*=.*$/d", "/etc/sssd/sssd.conf"], raise_on_error=False
        )
        if result.rc != 0:
            raise RuntimeError(f"Failed to remove services line from sssd.conf: {result.stderr}")

        # Restart SSSD to apply changes
        self.host.conn.exec(["systemctl", "restart", "sssd.service"])

    def restore_services_to_sssd_conf(self, services: str = "nss,pam,sudo,ssh,pac,autofs") -> None:
        """
        Restore the 'services' line in sssd.conf.

        :param services: Comma-separated list of services to restore.
        :type services: str
        """
        result = self.host.conn.exec(
            ["sed", "-i", f"/\\[sssd\\]/a services = {services}", "/etc/sssd/sssd.conf"], raise_on_error=False
        )
        if result.rc != 0:
            raise RuntimeError(f"Failed to restore services line to sssd.conf: {result.stderr}")

        # Restart SSSD to apply changes
        self.host.conn.exec(["systemctl", "restart", "sssd.service"])

    def verify_socket_activation(self, responder: str, test_command: str, test_args: list[str] = []) -> bool:
        """
        Verify socket activation by triggering the responder and checking service activation.

        :param responder: Responder type (e.g., 'nss', 'pam').
        :type responder: str
        :param test_command: Command to trigger the socket (e.g., 'getent', 'sssctl').
        :type test_command: str
        :param test_args: Arguments for the test command.
        :type test_args: list[str]
        :return: True if socket activation succeeds, False otherwise.
        :rtype: bool
        """
        resp = self.get_responder(responder)
        resp.stop_socket()
        resp.start_socket()

        # Ensure service is not running initially
        if resp.is_service_active():
            resp.host.conn.exec(["systemctl", "stop", resp.service_unit])

        # Trigger socket with test command
        result = resp.trigger_socket(test_command, test_args)
        if result.rc != 0:
            return False

        # Check if service is now active
        return resp.is_service_active()
