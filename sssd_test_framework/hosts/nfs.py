"""NFS multihost host."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

from .base import BaseBackupHost

__all__ = [
    "NFSHost",
]


class NFSHost(BaseBackupHost):
    """
    NFS server host object.

    Provides features specific to NFS server.

    This class adds ``config.exports_dir`` multihost configuration option to set
    the top level NFS exports directory where additional shares are created by
    individual test cases.

    .. code-block:: yaml
        :caption: Example multihost configuration
        :emphasize-lines: 4

        - hostname: nfs.test
          role: nfs
          config:
            exports_dir: /dev/shm/exports

    .. note::

        Full backup and restore is supported.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.exports_dir: str = self.config.get("exports_dir", "/exports").rstrip("/")
        """Top level NFS exports directory, defaults to ``/exports``."""

    def backup(self) -> Any:
        """
        Backup NFS server.

        :return: Backup data.
        :rtype: Any
        """
        self.ssh.run(
            rf"""
            tar --ignore-failed-read -czvf /tmp/mh.nfs.backup.tgz "{self.exports_dir}" /etc/exports /etc/exports.d
            """
        )
        return PurePosixPath("/tmp/mh.nfs.backup.tgz")

    def restore(self, backup_data: Any | None) -> None:
        """
        Restore NFS server to its initial contents.

        :return: Backup data.
        :rtype: Any
        """
        if backup_data is None:
            return

        if not isinstance(backup_data, PurePosixPath):
            raise TypeError(f"Expected PurePosixPath, got {type(backup_data)}")

        backup_path = str(backup_data)

        self.ssh.run(
            rf"""
            rm -fr "{self.exports_dir}/*"
            rm -fr /etc/exports.d/*
            tar -xf "{backup_path}" -C /
            exportfs -r
            """
        )
