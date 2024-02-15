"""IPA multihost host."""

from __future__ import annotations

from pytest_mh.ssh import SSHLog

from .base import BaseBackupHost

__all__ = [
    "ClientHost",
]


class ClientHost(BaseBackupHost):
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
            man sssd.conf | grep -q "user (string)" && echo "non-privileged" || :
            """,
            log_level=SSHLog.Error,
        )

        # Set default values
        self._features = {
            "files-provider": False,
            "passkey": False,
            "non-privileged": False,
        }

        self._features.update({k: True for k in result.stdout_lines})
        self.logger.info("Detected features:", extra={"data": {"Features": self._features}})

        return self._features

    def backup(self) -> None:
        """
        Backup all SSSD data.
        """
        location = "/tmp/mh.client.sssd.backup"
        self.logger.info(f"Creating backup of SSSD client at {location}")

        self.ssh.run(
            f"""
            set -ex

            function backup {{
                if [ -d "$1" ] || [ -f "$1" ]; then
                    cp --force --archive "$1" "$2"
                fi
            }}

            mkdir -p "{location}"
            backup /etc/sssd "{location}/config"
            backup /var/log/sssd "{location}/logs"
            backup /var/lib/sss "{location}/lib"
            """,
            log_level=SSHLog.Error,
        )

        self._backup_location = location

    def restore(self) -> None:
        """
        Restore all SSSD data.
        """
        if not self._backup_location:
            return

        self.logger.info(f"Restoring SSSD data from {self._backup_location}")
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
            restore "{self._backup_location}/config" /etc/sssd
            restore "{self._backup_location}/logs" /var/log/sssd
            restore "{self._backup_location}/lib" /var/lib/sss
            """,
            log_level=SSHLog.Error,
        )
