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

        self.client.setdefault("id_provider", "idp")
        self.client.setdefault("idp_type", f"keycloak:https://{self.hostname}:8443/auth/admin/realms/master/")
        self.client.setdefault("idp_client_id", "myclient")
        self.client.setdefault("idp_client_secret", "ClientSecret123")
        self.client.setdefault(
            "idp_token_endpoint", f"https://{self.hostname}:8443/auth/realms/master/protocol/openid-connect/token"
        )
        self.client.setdefault(
            "idp_userinfo_endpoint",
            f"https://{self.hostname}:8443/auth/realms/master/protocol/openid-connect/userinfo",
        )
        self.client.setdefault(
            "idp_device_auth_endpoint",
            "https://{self.hostname}:8443/auth/realms/master/protocol/openid-connect/auth/device",
        )
        self.client.setdefault("idp_id_scope", "profile")
        self.client.setdefault("idp_auth_scope", "openid profile email")

    def kclogin(self) -> None:
        """
        Obtain ``admin`` user credentials for Keycloak.
        """
        for x in range(0, 20):
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
                time.sleep(2)
            else:
                break

    def start(self) -> None:
        self.svc.start("keycloak.service")

    def stop(self) -> None:
        self.svc.stop("keycloak.service")

    def backup(self) -> Any:
        """
        Backup all Keycloak server data.

        :return: Backup data.
        :rtype: Any
        """
        self.logger.info("Creating backup of Keycloak")

        cmd = self.conn.run(
            """
            set -ex

            function backup {
                if [ -d "$1" ] || [ -f "$1" ]; then
                    cp --force --archive "$1" "$2"
                fi
            }

            path=`mktemp -d`

            systemctl stop keycloak.service
            backup /opt/keycloak/conf "$path/keycloak-conf"
            backup /opt/keycloak/data "$path/keycloak-data"
            systemctl start keycloak.service

            echo $path
            """,
            log_level=ProcessLogLevel.Error,
        )

        return PurePosixPath(cmd.stdout_lines[-1].strip())

    def restore(self, backup_data: Any | None) -> None:
        """
        Restore all Keycloak server data to its original state.

        :return: Backup data.
        :rtype: Any
        """
        if backup_data is None:
            return

        if not isinstance(backup_data, PurePosixPath):
            raise TypeError(f"Expected PurePosixPath, got {type(backup_data)}")

        backup_path = str(backup_data)
        self.logger.info(f"Restoring Keycloak from {backup_path}")

        self.conn.run(
            f"""
            set -ex

            function restore {{
                rm --force --recursive "$2"
                if [ -d "$1" ] || [ -f "$1" ]; then
                    cp --force --archive "$1" "$2"
                fi
            }}

            systemctl stop keycloak.service
            restore "{backup_path}/keycloak-conf" /opt/keycloak/conf
            restore "{backup_path}/keycloak-data" /opt/keycloak/data
            systemctl start keycloak.service
            """,
            log_level=ProcessLogLevel.Error,
        )
