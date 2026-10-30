"""LDAP multihost host."""

from __future__ import annotations

import textwrap
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
        self._ldap_cert_dir = self.config.get("ldap_cert_dir", "/var/data/certs")

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

    def create_additional_instance(
        self,
        name: str,
        *,
        hostname: str,
        port: int,
        secure_port: int,
        suffix: str | None = None,
    ) -> None:
        """
        Create, configure and start an additional 389ds instance on this host.

        The primary instance is provisioned when the host image is built, this
        only ever adds further instances alongside it.

        The instance shares the host's bind credentials and TLS certificate, so
        it can be used as a second, distinct LDAP server in failover topologies.
        SSSD keys its failover server list on the hostname, therefore ``hostname``
        must differ from the primary instance's name for the two to be treated
        as separate servers, even though they share an address.

        The operation is idempotent, an existing instance of the same name is
        left untouched.

        .. code-block:: python
            :caption: Example usage in a topology controller

            class MultiLDAPTopologyController(ProvisionedBackupTopologyController):
                def topology_setup(self, client: ClientHost, ldap: LDAPHost) -> None:
                    ldap.create_additional_instance(
                        "master2", hostname="master2.ldap.test", port=2389, secure_port=2636
                    )
                    super().topology_setup()

                def topology_teardown(self, client: ClientHost, ldap: LDAPHost) -> None:
                    ldap.remove_additional_instance("master2")
                    super().topology_teardown()

        The second server is then addressable from a test as
        ``ldap://master2.ldap.test:2389``, for example as ``ldap_backup_uri``.

        :param name: Instance name, the resulting unit is ``dirsrv@<name>.service``.
        :type name: str
        :param hostname: Fully qualified name the instance is reachable under.
        :type hostname: str
        :param port: LDAP port.
        :type port: int
        :param secure_port: LDAPS port.
        :type secure_port: int
        :param suffix: Naming context, defaults to the primary instance's suffix.
        :type suffix: str | None, optional
        """
        if suffix is None:
            suffix = self.naming_context

        self.logger.info(f"Creating 389ds instance '{name}' on {self.hostname} as {hostname}:{port}")

        self.conn.run(
            textwrap.dedent(f"""
            set -ex

            # Nothing to do if the instance already exists.
            if dsctl -l | grep -qx 'slapd-{name}'; then
                exit 0
            fi

            cat > '/root/{name}.inf' <<EOF
            [general]
            config_version = 2
            full_machine_name = {hostname}

            [slapd]
            instance_name = {name}
            port = {port}
            secure_port = {secure_port}
            root_dn = {self.binddn}
            root_password = {self.bindpw}

            [backend-userroot]
            suffix = {suffix}
            create_suffix_entry = True
            EOF

            dscreate from-file '/root/{name}.inf'

            # Share the primary instance's certificate. It carries the alias as a
            # subjectAltName, so TLS to the second name passes hostname validation.
            dsconf '{name}' security ca-certificate add --file '{self._ldap_cert_dir}/ca.crt' --name 'sssd-ca'
            dsconf '{name}' security ca-certificate set-trust-flags 'sssd-ca' --flags 'CT,,'

            ARGS=
            # Workaround for https://github.com/389ds/389-ds-base/issues/7470
            if dsctl '{name}' tls import-server-key-cert --help 2>&1 | grep -q -- '--nickname'; then
                ARGS='--nickname Server-Cert'
            fi
            dsctl '{name}' tls import-server-key-cert $ARGS \
                '{self._ldap_cert_dir}/{self.hostname}.crt' '{self._ldap_cert_dir}/{self.hostname}.key'

            systemctl restart 'dirsrv@{name}.service'
            """),
            log_level=ProcessLogLevel.Error,
        )

        # Match the primary instance, which grants anonymous read access.
        self.conn.run(
            f"""ldapmodify -D '{self.binddn}' -w '{self.bindpw}' -H 'ldap://localhost:{port}' -x""",
            input=(
                f"dn: {suffix}\n"
                "changetype: modify\n"
                "add: aci\n"
                'aci: (targetattr=*)(version 3.0; acl "Enable anyone read"; '
                'allow (read, search, compare)(userdn="ldap:///anyone");)\n'
            ),
            log_level=ProcessLogLevel.Error,
            raise_on_error=False,
        )

    def remove_additional_instance(self, name: str) -> None:
        """
        Stop and remove an instance created by :func:`create_additional_instance`.

        The operation is idempotent, removing a non existent instance is a no-op.

        .. code-block:: python
            :caption: Example usage

            ldap.remove_additional_instance("master2")

        :param name: Instance name.
        :type name: str
        """
        self.logger.info(f"Removing 389ds instance '{name}' from {self.hostname}")

        self.conn.run(
            f"""
            set -ex

            if dsctl -l | grep -qx 'slapd-{name}'; then
                dsctl '{name}' remove --do-it
            fi

            rm --force '/root/{name}.inf'
            """,
            log_level=ProcessLogLevel.Error,
        )

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
