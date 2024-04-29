"""LDAP multihost host."""

from __future__ import annotations

from typing import Any

import ldap
from pytest_mh.ssh import SSHLog

from .base import BaseLDAPDomainHost, BaseLinuxHost

__all__ = [
    "LDAPHost",
]


class LDAPHost(BaseLDAPDomainHost, BaseLinuxHost):
    """
    LDAP host object.

    Provides features specific to native directory server like 389ds.

    .. note::

        Full backup and restore is supported.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._features: dict[str, bool] | None = None
        self._ldap_service_name = self.config.get("ldap_service_name", "dirsrv@localhost.service")

        # Additional client configuration
        self.client.setdefault("id_provider", "ldap")
        self.client.setdefault("ldap_uri", f"ldap://{self.hostname}")

    @property
    def features(self) -> dict[str, bool]:
        """
        Features supported by the host.
        """
        if self._features is not None:
            return self._features

        self.logger.info(f"Detecting features on {self.hostname}")

        result = self.ssh.run(
            """
            set -ex

            grep -r "passkey" /etc/dirsrv/ &> /dev/null && echo "passkey" || :
            """,
            log_level=SSHLog.Error,
        )

        # Set default values
        self._features = {
            "passkey": False,
        }

        self._features.update({k: True for k in result.stdout_lines})
        self.logger.info("Detected features:", extra={"data": {"Features": self._features}})

        return self._features

    def remove_backup(self, backup_data: Any | None) -> None:
        """
        Remove backup data from the host.

        :param backup_data: Backup data.
        :type backup_data: Any | None
        """
        # Nothing to do since we store backup in memory
        pass

    def start(self) -> None:
        self.svc.start(self._ldap_service_name)

    def stop(self) -> None:
        self.svc.stop(self._ldap_service_name)

    def backup(self) -> Any:
        """
        Backup all directory server data.

        Full backup of ``cn=config`` and default naming context is performed.
        This is done by simple LDAP search on given base dn and remembering the
        contents. The operation is usually very fast.

        :return: Backup data.
        :rtype: Any
        """
        data = self.conn.search_s(self.naming_context, ldap.SCOPE_SUBTREE)
        config = self.conn.search_s("cn=config", ldap.SCOPE_BASE)
        nc = self.conn.search_s(self.naming_context, ldap.SCOPE_BASE, attrlist=["aci"])

        dct = self.ldap_result_to_dict(data)
        dct.update(self.ldap_result_to_dict(config))
        dct.update(self.ldap_result_to_dict(nc))

        return dct

    def restore(self, backup_data: Any | None) -> None:
        """
        Restore directory server data.

        Current directory server content in ``cn=config`` and default naming
        context is modified to its original data. This is done by computing a
        difference between original data obtained by :func:`backup` and then
        calling add, delete and modify operations to convert current state to
        the original state. This operation is usually very fast.

        :return: Backup data.
        :rtype: Any
        """
        if backup_data is None:
            return

        if not isinstance(backup_data, dict):
            raise TypeError(f"Expected dict, got {type(backup_data)}")

        data = self.conn.search_s(self.naming_context, ldap.SCOPE_SUBTREE)
        config = self.conn.search_s("cn=config", ldap.SCOPE_BASE)
        nc = self.conn.search_s(self.naming_context, ldap.SCOPE_BASE, attrlist=["aci"])

        # Convert list of tuples to dictionary for better lookup
        data = self.ldap_result_to_dict(data)
        data.update(self.ldap_result_to_dict(config))
        data.update(self.ldap_result_to_dict(nc))

        for dn, attrs in reversed(data.items()):
            # Restore records that were modified
            if dn in backup_data:
                original_attrs = backup_data[dn]
                modlist = ldap.modlist.modifyModlist(attrs, original_attrs)
                modlist = self.__filter_modlist(dn, modlist)
                if modlist:
                    self.conn.modify_s(dn, modlist)

        for dn, attrs in reversed(data.items()):
            # Delete records that were added
            if dn not in backup_data:
                self.conn.delete_s(dn)
                continue

        for dn, attrs in backup_data.items():
            # Add back records that were deleted
            if dn not in data:
                self.conn.add_s(dn, list(attrs.items()))

    def __filter_modlist(self, dn: str, modlist: list) -> list:
        """
        Remove special items that can not be modified from ``modlist``.

        :param dn: Object's DN.
        :type dn: str
        :param modlist: LDAP modlist.
        :type modlist: list
        :return: Filtered modlist.
        :rtype: list
        """
        if dn != "cn=config":
            return modlist

        result = []
        for op, attr, value in modlist:
            # We are not allowed to touch these
            if attr.startswith("nsslapd"):
                continue

            result.append((op, attr, value))

        return result
