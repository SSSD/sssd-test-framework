"""LDAP multihost host."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

from pytest_mh.conn import ProcessLogLevel

from .base import BaseLDAPDomainHost, BaseLinuxHost

__all__ = [
    "LDAPHost",
]


class LDAPHost(BaseLDAPDomainHost, BaseLinuxHost):
    """
    LDAP host object.

    Provides features specific to native directory server like 389ds.

    .. note::

        Full backup and restore is supported by copying ``/etc/dirsrv`` and
        ``/var/lib/dirsrv`` (same approach as IPA in PR #288).
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._features: dict[str, bool] | None = None
        self._ldap_service_name = self.config.get("ldap_service_name", "dirsrv@localhost.service")

        # Additional client configuration
        self.client.setdefault("id_provider", "ldap")
        self.client.setdefault("ldap_uri", f"ldap://{self.hostname}")

        # Use different default for domain
        if "domain" not in self.config and "dns_discovery_domain" in self.client:
            self.domain = self.client["dns_discovery_domain"]

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

        result = self.conn.run(
            """
            set -ex

            grep -r "passkey" /etc/dirsrv/ &> /dev/null && echo "passkey" || :
            """,
            log_level=ProcessLogLevel.Error,
        )

        # Set default values
        self._features = {
            "passkey": False,
        }

        self._features.update({k: True for k in result.stdout_lines})
        self.logger.info("Detected features:", extra={"data": {"Features": self._features}})

        return self._features

    def start(self) -> None:
        self.svc.start(self._ldap_service_name)

    def stop(self) -> None:
        self.svc.stop(self._ldap_service_name)

    def backup(self) -> Any:
        """
        Backup all directory server data.

        Stop 389-ds and copy ``/etc/dirsrv`` and ``/var/lib/dirsrv``, then start
        it again. This avoids LDAP modify-based restore failures such as
        ``ldap.UNWILLING_TO_PERFORM`` (``'Server is unwilling to perform'``)
        that left users behind and caused later ``ldap.ALREADY_EXISTS``.

        :return: Backup data.
        :rtype: Any
        """
        self.logger.info("Creating backup of LDAP server")

        result = self.conn.run(
            """
            set -x

            function backup {
                if [ -d "$1" ] || [ -f "$1" ]; then
                    cp --force --archive "$1" "$2"
                fi
            }

            set -e

            path=`mktemp -d`

            systemctl stop dirsrv.target
            backup /etc/dirsrv "$path/dirsrv-etc"
            backup /var/lib/dirsrv "$path/dirsrv-lib"
            systemctl start dirsrv.target

            echo $path
            """,
            log_level=ProcessLogLevel.Error,
        )

        return PurePosixPath(result.stdout_lines[-1].strip())

    def restore(self, backup_data: Any | None) -> None:
        """
        Restore directory server data.

        Stop 389-ds, replace ``/etc/dirsrv`` and ``/var/lib/dirsrv`` from the
        backup created by :meth:`backup`, then start it again. File copy restores
        the full database state (including test users), so teardown cannot leave
        leftovers that fail later with ``ldap.ALREADY_EXISTS``.

        :return: Backup data.
        :rtype: Any
        """
        if backup_data is None:
            return

        if not isinstance(backup_data, PurePosixPath):
            raise TypeError(f"Expected PurePosixPath, got {type(backup_data)}")

        backup_path = str(backup_data)
        self.logger.info(f"Restoring LDAP server from {backup_path}")

        self.disconnect()
        self.conn.run(
            f"""
            set -x

            function restore {{
                rm --force --recursive "$2"
                if [ -d "$1" ] || [ -f "$1" ]; then
                    cp --force --archive "$1" "$2"
                fi
            }}

            set -e

            systemctl stop dirsrv.target
            restore "{backup_path}/dirsrv-etc" /etc/dirsrv
            restore "{backup_path}/dirsrv-lib" /var/lib/dirsrv
            systemctl start dirsrv.target
            """,
            log_level=ProcessLogLevel.Error,
        )
