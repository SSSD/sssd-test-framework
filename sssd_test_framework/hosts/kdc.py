"""KDC multihost host."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

from .base import BaseDomainHost, BaseLinuxHost

__all__ = [
    "KDCHost",
]


class KDCHost(BaseDomainHost, BaseLinuxHost):
    """
    Kerberos KDC server host object.

    Provides features specific to Kerberos KDC.

    This class adds ``config.realm`` and ``config.domain`` multihost
    configuration options to set the default kerberos realm and domain.

    .. code-block:: yaml
        :caption: Example multihost configuration
        :emphasize-lines: 6-7

        - hostname: kdc.test
          role: kdc
          config:
            realm: TEST
            domain: test
            client:
              krb5_server: kdc.test
              krb5_kpasswd: kdc.test
              krb5_realm: TEST

    .. note::

        Full backup and restore is supported.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.client["auth_provider"] = "krb5"

    def backup(self) -> Any:
        """
        Backup KDC server.

        :return: Backup data.
        :rtype: Any
        """
        result = self.ssh.run(
            """
            set -e
            path=`mktemp`
            kdb5_util dump $path && rm -f "$path.dump_ok"
            echo $path
            """
        )
        return PurePosixPath(result.stdout_lines[-1].strip())

    def restore(self, backup_data: Any | None) -> None:
        """
        Restore KDC server to its initial contents.

        :return: Backup data.
        :rtype: Any
        """
        if backup_data is None:
            return

        if not isinstance(backup_data, PurePosixPath):
            raise TypeError(f"Expected PurePosixPath, got {type(backup_data)}")

        backup_path = str(backup_data)

        self.ssh.run(f'kdb5_util load "{backup_path}"')
