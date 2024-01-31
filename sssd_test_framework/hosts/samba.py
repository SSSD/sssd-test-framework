"""Samba multihost host."""

from __future__ import annotations

from .base import BaseLDAPDomainHost

__all__ = [
    "SambaHost",
]


class SambaHost(BaseLDAPDomainHost):
    """
    Samba host object.

    Provides features specific to Samba server.

    .. note::

        Full backup and restore is supported.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._features: dict[str, bool] | None = None

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

    def backup(self) -> None:
        """
        Backup all Samba server data.

        This is done by creating a backup of Samba database. This operation
        is usually very fast.
        """
        self.ssh.run(
            """
            set -e
            systemctl stop samba
            rm -fr /var/lib/samba.bak
            cp -r /var/lib/samba /var/lib/samba.bak
            systemctl start samba

            # systemctl finishes before samba is fully started, wait for it to start listening on ldap port
            timeout 60s bash -c 'until netstat -ltp 2> /dev/null | grep :ldap &> /dev/null; do :; done'
        """
        )
        self._backup_location = "/var/lib/samba.bak"

    def restore(self) -> None:
        """
        Restore all Samba server data to its original value.

        This is done by overriding current database with the backup created
        by :func:`backup`. This operation is usually very fast.
        """
        if not self._backup_location:
            return

        self.disconnect()
        self.ssh.run(
            f"""
            set -e
            systemctl stop samba
            rm -fr /var/lib/samba
            cp -r "{self._backup_location}" /var/lib/samba
            systemctl start samba
            samba-tool ntacl sysvolreset

            # systemctl finishes before samba is fully started, wait for it to start listening on ldap port
            timeout 60s bash -c 'until netstat -ltp 2> /dev/null | grep :ldap &> /dev/null; do :; done'
        """
        )
        self.disconnect()
