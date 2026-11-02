"""LDAP multihost host."""

from __future__ import annotations

from typing import Any

import ldap
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

        Full backup and restore is supported.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._features: dict[str, bool] | None = None
        self._ldap_service_name = self.config.get("ldap_service_name", "dirsrv@localhost.service")
        self.extra_naming_contexts: set[str] = set()
        """Additional naming contexts created for tests (multi-suffix rootDSE)."""

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

        Full backup of ``cn=config``, every naming context (including any extra
        suffixes), mapping-tree entries, and backend instances is performed.
        This is done by simple LDAP search on given base dns and remembering the
        contents. The operation is usually very fast.

        :return: Backup data.
        :rtype: Any
        """
        self.logger.info("Creating backup of LDAP server")
        return self._ldap_state()

    def restore(self, backup_data: Any | None) -> None:
        """
        Restore directory server data.

        Current directory server content in ``cn=config``, naming contexts,
        mapping trees, and backends is modified to its original data. This is
        done by computing a difference between original data obtained by
        :func:`backup` and then calling add, delete and modify operations to
        convert current state to the original state. Extra naming contexts
        created during a test are removed because they are absent from the
        backup. This operation is usually very fast.

        :return: Backup data.
        :rtype: Any
        """
        if backup_data is None:
            return

        self.logger.info("Restoring LDAP server from memory")

        if not isinstance(backup_data, dict):
            raise TypeError(f"Expected dict, got {type(backup_data)}")

        data = self._ldap_state()

        for dn, attrs in reversed(data.items()):
            # Restore records that were modified
            if dn in backup_data:
                original_attrs = backup_data[dn]
                modlist = ldap.modlist.modifyModlist(attrs, original_attrs)
                modlist = self.__filter_modlist(dn, modlist)
                if modlist:
                    self.ldap_conn.modify_s(dn, modlist)

        # Delete records that were added (deepest entries first; drop suffix
        # data before mapping-tree/backend config that references it).
        to_delete = [dn for dn in data if dn not in backup_data]
        to_delete.sort(key=self._restore_delete_key)
        for dn in to_delete:
            try:
                self.ldap_conn.delete_s(dn)
            except ldap.NO_SUCH_OBJECT:
                continue

        for dn, attrs in backup_data.items():
            # Add back records that were deleted
            if dn not in data:
                self.ldap_conn.add_s(dn, list(attrs.items()))

        self.extra_naming_contexts.clear()

    def _backup_naming_contexts(self) -> set[str]:
        """Naming contexts included in backup/restore (default, tracked, rootDSE)."""
        contexts = {self.naming_context, *self.extra_naming_contexts}
        try:
            result = self.ldap_conn.search_s("", ldap.SCOPE_BASE, attrlist=["namingContexts"])
        except ldap.LDAPError:
            return contexts

        if not result:
            return contexts

        _, attrs = result[0]
        for key, values in attrs.items():
            if key.lower() == "namingcontexts":
                contexts.update(v.decode("utf-8") for v in values)
        return contexts

    def _ldap_state(self) -> dict[str, dict[str, list[bytes]]]:
        """
        Snapshot LDAP entries covered by backup/restore.

        Includes every naming context, ``cn=config``, mapping-tree children, and
        backend instances so extra suffixes created during a test are visible to
        restore and removed when absent from the backup.
        """
        dct: dict[str, dict[str, list[bytes]]] = {}

        for nc in self._backup_naming_contexts():
            try:
                data = self.ldap_conn.search_s(nc, ldap.SCOPE_SUBTREE)
                dct.update(self.ldap_result_to_dict(data))
                nc_aci = self.ldap_conn.search_s(nc, ldap.SCOPE_BASE, attrlist=["aci"])
                dct.update(self.ldap_result_to_dict(nc_aci))
            except ldap.NO_SUCH_OBJECT:
                continue

        config = self.ldap_conn.search_s("cn=config", ldap.SCOPE_BASE)
        dct.update(self.ldap_result_to_dict(config))

        for base, scope in (
            ("cn=mapping tree,cn=config", ldap.SCOPE_ONELEVEL),
            ("cn=ldbm database,cn=plugins,cn=config", ldap.SCOPE_SUBTREE),
        ):
            try:
                entries = self.ldap_conn.search_s(base, scope)
                dct.update(self.ldap_result_to_dict(entries))
            except ldap.NO_SUCH_OBJECT:
                continue

        return dct

    @staticmethod
    def _restore_delete_key(dn: str) -> tuple[int, int, str]:
        """Sort key: suffix data, then mapping tree, then backends; deeper first."""
        dn_l = dn.lower()
        if "cn=mapping tree,cn=config" in dn_l:
            phase = 1
        elif "cn=ldbm database,cn=plugins,cn=config" in dn_l:
            phase = 2
        elif dn_l == "cn=config" or dn_l.endswith(",cn=config"):
            phase = 3
        else:
            phase = 0
        return (phase, -dn.count(","), dn)

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
