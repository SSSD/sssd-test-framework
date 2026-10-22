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
        self.saved_default_naming_context: str | None = None
        """Original nsslapd-defaultnamingcontext, restored when extra NCs are removed."""

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

        Full backup of ``cn=config`` and default naming context is performed.
        This is done by simple LDAP search on given base dn and remembering the
        contents. The operation is usually very fast.

        :return: Backup data.
        :rtype: Any
        """
        self.logger.info("Creating backup of LDAP server")

        data = self.ldap_conn.search_s(self.naming_context, ldap.SCOPE_SUBTREE)
        config = self.ldap_conn.search_s("cn=config", ldap.SCOPE_BASE)
        nc = self.ldap_conn.search_s(self.naming_context, ldap.SCOPE_BASE, attrlist=["aci"])

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

        self.logger.info("Restoring LDAP server from memory")

        if not isinstance(backup_data, dict):
            raise TypeError(f"Expected dict, got {type(backup_data)}")

        # Extra backends/suffixes are outside the default naming-context backup
        # scope, and nsslapd-* changes are filtered from cn=config restore.
        # Tear them down explicitly so later tests are not polluted.
        self._cleanup_extra_naming_contexts()

        data = self.ldap_conn.search_s(self.naming_context, ldap.SCOPE_SUBTREE)
        config = self.ldap_conn.search_s("cn=config", ldap.SCOPE_BASE)
        nc = self.ldap_conn.search_s(self.naming_context, ldap.SCOPE_BASE, attrlist=["aci"])

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
                    self.ldap_conn.modify_s(dn, modlist)

        for dn, attrs in reversed(data.items()):
            # Delete records that were added
            if dn not in backup_data:
                self.ldap_conn.delete_s(dn)
                continue

        for dn, attrs in backup_data.items():
            # Add back records that were deleted
            if dn not in data:
                self.ldap_conn.add_s(dn, list(attrs.items()))

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

    def _cleanup_extra_naming_contexts(self) -> None:
        """
        Remove extra backends/suffixes and restore defaultNamingContext.

        Backup/restore only covers the primary naming context and ``cn=config``
        base, so leftover ``dc=other,dc=test`` mapping trees otherwise survive
        between tests and break the next ``backend create``.
        """
        bind = f'-D "{self.binddn}" -w "{self.bindpw}"'
        # Always attempt the well-known multi-NC helper suffix, plus any tracked ones.
        suffixes = set(self.extra_naming_contexts) | {"dc=other,dc=test"}
        be_names = {"otherRoot"}

        for suffix in suffixes:
            mapping_dn = f'cn="{suffix}",cn=mapping tree,cn=config'
            self.conn.run(
                f"ldapdelete -x {bind} -H ldap://localhost -r '{suffix}' || true\n"
                f"ldapdelete -x {bind} -H ldap://localhost '{mapping_dn}' || true\n",
                raise_on_error=False,
            )

        for be_name in be_names:
            backend_dn = f"cn={be_name},cn=ldbm database,cn=plugins,cn=config"
            self.conn.run(
                f"ldapdelete -x {bind} -H ldap://localhost '{backend_dn}' || true\n"
                f'dsconf -j -D "{self.binddn}" -w "{self.bindpw}" ldap://localhost '
                f'backend delete "{be_name}" --do-it || true\n',
                raise_on_error=False,
            )

        saved = self.saved_default_naming_context
        if saved is not None:
            try:
                self.ldap_conn.modify_s(
                    "cn=config",
                    [(ldap.MOD_REPLACE, "nsslapd-defaultnamingcontext", [saved.encode("utf-8")])],
                )
            except ldap.LDAPError:
                try:
                    self.ldap_conn.modify_s(
                        "cn=config",
                        [(ldap.MOD_ADD, "nsslapd-defaultnamingcontext", [saved.encode("utf-8")])],
                    )
                except ldap.LDAPError:
                    self.logger.warning("Unable to restore nsslapd-defaultnamingcontext=%s", saved)

        self.extra_naming_contexts.clear()
        self.saved_default_naming_context = None
