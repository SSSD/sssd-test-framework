"""Keycloak multihost host."""

from __future__ import annotations

import time

from pytest_mh.ssh import SSHProcessError

from .base import BaseDomainHost

__all__ = [
    "KeycloakHost",
]


class KeycloakHost(BaseDomainHost):
    """
    Keycloak host object.

    Provides features specific for Keycloak server.

    This class adds ``config.adminpw`` multihost configuration option to set
    password of the Keycloak admin user so we run kcadm.sh commands to set
    options in Keycloak.

    .. code-block:: yaml
        :caption: Example multihost configuration
        :emphasize-lines: 4

        - hostname: master.keycloak.test
          role: keycloak
          config:
            adminpw: Secret123

    .. note::

        Full backup and restore is supported. However, the operation relies on
        ``kc.sh export`` and ``kc.sh import`` commands which can take several
        seconds to finish.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.adminpw = self.config.get("adminpw", "Secret123")

        # Backup of original data
        self.__backup: str | None = None

    def kclogin(self) -> None:
        """
        Obtain ``admin`` user credentials for Keycloak.
        """
        for x in range(0, 5):
            try:
                str_error = None
                self.ssh.exec(
                    [
                        "/opt/keycloak/bin/kcadm.sh",
                        "config",
                        "credentials",
                        "--server",
                        f"https://{self.hostname}:8443/auth/",
                        "--realm",
                        "master",
                        "--user",
                        "admin",
                        "--password",
                        self.adminpw,
                    ]
                )
            except SSHProcessError as err:
                str_error = str(err)

            if str_error:
                time.sleep(30)
            else:
                break

    def backup(self) -> None:
        """
        Backup all Keycloak server data.

        This is done by calling ``kc.sh export`` on the server
        and can take several seconds to finish.
        """
        if self.__backup is not None:
            return

        cmd = self.ssh.run(
            "set -e; systemctl stop keycloak;"
            "/opt/keycloak/bin/kc.sh export --dir /tmp/kcbackup"
            "> /tmp/kcbackup.log;"
            "systemctl start keycloak;"
            "ls -1 /tmp/kcbackup| tail -n 1"
        )
        self.__backup = cmd.stdout.strip()

    def restore(self) -> None:
        """
        Restore all Keycloak server data to its original state.

        This is done by calling ``kc.sh import`` on the server
        and can take several seconds to finish.
        """
        if self.__backup is None:
            return

        self.ssh.run(
            "systemctl stop keycloak; /opt/keycloak/bin/kc.sh import --dir /tmp/kcbackup; systemctl start keycloak"
        )
