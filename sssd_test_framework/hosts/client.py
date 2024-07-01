"""IPA multihost host."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

from pytest_mh.ssh import SSHLog

from .base import BaseBackupHost, BaseLinuxHost

__all__ = [
    "ClientHost",
]


class ClientHost(BaseBackupHost, BaseLinuxHost):
    """
    SSSD client host object.

    Provides features specific to SSSD client.

    .. note::

        Full backup and restore of SSSD state is supported.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._features: dict[str, bool] | None = None

    @property
    def features(self) -> dict[str, bool]:
        """
        Features supported by the host.
        """
        if self._features is not None:
            return self._features

        self.logger.info(f"Detecting SSSD's features on {self.hostname}")

        result = self.ssh.run(
            """
            set -ex

            [ -f "/usr/lib64/sssd/libsss_files.so" ] && echo "files-provider" || :
            [ -f "/usr/libexec/sssd/passkey_child" ] && echo "passkey" || :
            [ -f "/usr/bin/sss_ssh_knownhostsproxy" ] && echo "knownhostsproxy" || :
            man sssd.conf | grep -q "user (string)" && echo "non-privileged" || :
            man sssd-ldap | grep -q "ldap_use_ppolicy (boolean)" && echo "ldap_use_ppolicy" || :
            """,
            log_level=SSHLog.Error,
        )

        # Set default values
        self._features = {
            "files-provider": False,
            "passkey": False,
            "non-privileged": False,
            "ldap_use_ppolicy": False,
            "knownhostsproxy": False,
        }

        self._features.update({k: True for k in result.stdout_lines})
        self.logger.info("Detected features:", extra={"data": {"Features": self._features}})

        return self._features

    def start(self) -> None:
        """
        Not supported.

        :raises NotImplementedError: _description_
        """
        # SSSD might not be configured properly at this time. We start and stop SSSD in tests.
        raise NotImplementedError("Starting Active Directory service is not implemented.")

    def stop(self) -> None:
        self.svc.stop("sssd.service")

    def backup(self) -> Any:
        """
        Backup all SSSD data.

        :return: Backup data.
        :rtype: Any
        """
        self.logger.info("Creating backup of SSSD client")

        result = self.ssh.run(
            """
            set -ex

            function backup {
                if [ -d "$1" ] || [ -f "$1" ]; then
                    cp --force --archive "$1" "$2"
                fi
            }

            path=`mktemp -d`
            backup /etc/krb5.conf "$path/krb5.conf"
            backup /etc/krb5.keytab "$path/krb5.keytab"
            backup /etc/sssd "$path/config"
            backup /var/log/sssd "$path/logs"
            backup /var/lib/sss "$path/lib"

            echo $path
            """,
            log_level=SSHLog.Error,
        )

        return PurePosixPath(result.stdout_lines[-1].strip())

    def restore(self, backup_data: Any | None) -> None:
        """
        Restore all SSSD data.

        :return: Backup data.
        :rtype: Any
        """
        if backup_data is None:
            return

        if not isinstance(backup_data, PurePosixPath):
            raise TypeError(f"Expected PurePosixPath, got {type(backup_data)}")

        backup_path = str(backup_data)

        self.logger.info(f"Restoring SSSD data from {backup_path}")
        self.ssh.run(
            f"""
            set -ex

            function restore {{
                rm --force --recursive "$2"
                if [ -d "$1" ] || [ -f "$1" ]; then
                    cp --force --archive "$1" "$2"
                fi
            }}

            rm --force --recursive /etc/sssd /var/lib/sss /var/log/sssd
            restore "{backup_path}/krb5.conf" /etc/krb5.conf
            restore "{backup_path}/krb5.keytab" /etc/krb5.keytab
            restore "{backup_path}/config" /etc/sssd
            restore "{backup_path}/logs" /var/log/sssd
            restore "{backup_path}/lib" /var/lib/sss
            """,
            log_level=SSHLog.Error,
        )
