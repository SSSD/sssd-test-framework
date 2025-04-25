"""Samba multihost host."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

from pytest_mh.conn import ProcessLogLevel

from .base import BaseLDAPDomainHost, BaseLinuxHost

__all__ = [
    "SambaHost",
]


class SambaHost(BaseLDAPDomainHost, BaseLinuxHost):
    """
    Samba host object.

    Provides features specific to Samba server.

    .. note::

        Full backup and restore is supported.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._features: dict[str, bool] | None = None

        self.adminuser: str = self.config.get("username", "Administrator")
        """Username of the admin user, defaults to value of ``Administrator``."""

        self.adminpw: str = self.config.get("adminpw", self.bindpw)
        """Password of the admin user, defaults to value of ``bindpw``."""

        # Additional client configuration
        self.client.setdefault("id_provider", "ad")
        self.client.setdefault("access_provider", "ad")
        self.client.setdefault("ad_server", self.hostname)
        self.client.setdefault("dyndns_update", False)

        # Use different default for domain
        if "domain" not in self.config and "ad_domain" in self.client:
            self.domain = self.client["ad_domain"]

        # Use different default for realm
        if "realm" not in self.config:
            self.realm = self.domain.upper()

    @property
    def features(self) -> dict[str, bool]:
        """
        Features supported by the host.
        """
        if self._features is not None:
            return self._features

        self.logger.info(f"Detecting features on {self.hostname}")

        # Set default values
        self._features = {
            "passkey": True,
        }

        self.logger.info("Detected features:", extra={"data": {"Features": self._features}})

        return self._features

    def start(self) -> None:
        self.svc.start("samba.service")

        # systemctl finishes before Samba is really listening, we need to wait
        self.conn.run(
            """
            timeout 60s bash -c 'until netstat -ltp 2> /dev/null | grep :ldap &> /dev/null; do :; done'
            timeout 60s bash -c 'until netstat -ltp 2> /dev/null | grep :kerberos &> /dev/null; do :; done'
            """
        )

    def stop(self) -> None:
        self.svc.stop("samba.service")

    def backup(self) -> Any:
        """
        Backup all Samba server data.

        This is done by creating a backup of Samba database. This operation
        is usually very fast.

        :return: Backup data.
        :rtype: Any
        """
        self.logger.info("Creating backup of Samba DC")

        self.stop()
        result = self.conn.run(
            """
            set -e
            path=`mktemp -d`
            rm -fr "$path" && cp -r /var/lib/samba "$path"
            echo $path
            """,
            log_level=ProcessLogLevel.Error,
        )
        self.start()

        return PurePosixPath(result.stdout_lines[-1].strip())

    def restore(self, backup_data: Any | None) -> None:
        """
        Restore all Samba server data to its original value.

        This is done by overriding current database with the backup created
        by :func:`backup`. This operation is usually very fast.

        :return: Backup data.
        :rtype: Any
        """
        if backup_data is None:
            return

        if not isinstance(backup_data, PurePosixPath):
            raise TypeError(f"Expected PurePosixPath, got {type(backup_data)}")

        backup_path = str(backup_data)
        self.logger.info(f"Restoring Samba DC from {backup_path}")

        self.disconnect()
        self.stop()
        self.conn.run(
            f"""
            set -e
            rm -fr /var/lib/samba
            cp -r "{backup_path}" /var/lib/samba
            samba-tool ntacl sysvolreset
            """,
            log_level=ProcessLogLevel.Error,
        )
        self.start()
