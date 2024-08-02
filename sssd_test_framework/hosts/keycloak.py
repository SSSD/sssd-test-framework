"""Keycloak multihost host."""

from __future__ import annotations

import time
from pathlib import PurePosixPath
from typing import Any

from pytest_mh.conn import ProcessError, ProcessLogLevel

from .base import BaseDomainHost, BaseLinuxHost

__all__ = [
    "KeycloakHost",
]


class KeycloakHost(BaseDomainHost, BaseLinuxHost):
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

    def kclogin(self) -> None:
        """
        Obtain ``admin`` user credentials for Keycloak.
        """
        for x in range(0, 5):
            try:
                str_error = None
                self.conn.exec(
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
            except ProcessError as err:
                str_error = str(err)

            if str_error:
                time.sleep(30)
            else:
                break

    def start(self) -> None:
        self.svc.start("keycloak.service")

    def stop(self) -> None:
        self.svc.stop("keycloak.service")

    def backup(self) -> Any:
        """
        Backup all Keycloak server data.

        This is done by calling ``kc.sh export`` on the server
        and can take several seconds to finish.

        :return: Backup data.
        :rtype: Any
        """
        self.logger.info("Creating backup of Keycloak")

        self.stop()
        cmd = self.conn.run(
            """
            set -e
            path=`mktemp -d`
            /opt/keycloak/bin/kc.sh export --dir "$path"
            echo $path
            """,
            log_level=ProcessLogLevel.Error,
        )
        self.start()

        return PurePosixPath(cmd.stdout_lines[-1].strip())

    def restore(self, backup_data: Any | None) -> None:
        """
        Restore all Keycloak server data to its original state.

        This is done by calling ``kc.sh import`` on the server
        and can take several seconds to finish.

        :return: Backup data.
        :rtype: Any
        """
        if backup_data is None:
            return

        if not isinstance(backup_data, PurePosixPath):
            raise TypeError(f"Expected PurePosixPath, got {type(backup_data)}")

        backup_path = str(backup_data)
        self.logger.info(f"Restoring Keycloak from {backup_path}")

        self.stop()
        self.conn.run(
            f"""
            set -e
            /opt/keycloak/bin/kc.sh import --dir '{backup_path}'
            """,
            log_level=ProcessLogLevel.Error,
        )
        self.start()
