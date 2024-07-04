from __future__ import annotations

from functools import partial, wraps
from typing import Any

from pytest_mh import TopologyController
from pytest_mh.conn import ProcessResult

from .config import SSSDMultihostConfig
from .hosts.ad import ADHost
from .hosts.base import BaseBackupHost
from .hosts.client import ClientHost
from .hosts.ipa import IPAHost
from .hosts.nfs import NFSHost
from .hosts.samba import SambaHost
from .misc.ssh import retry_command

__all__ = [
    "LDAPTopologyController",
    "IPATopologyController",
    "ADTopologyController",
    "SambaTopologyController",
    "IPATrustADTopologyController",
    "IPATrustSambaTopologyController",
]


def restore_vanilla_on_error(method):
    """
    Restore or hosts to its original state if an exception occurs
    during method execution.

    :param method: Method to decorate.
    :type method: _type_
    :return: _description_
    :rtype: _type_
    """

    @wraps(method)
    def wrapper(self: BackupTopologyController, *args, **kwargs):
        try:
            return self._invoke_with_args(partial(method, self))
        except Exception:
            self.restore_vanilla()
            raise

    return wrapper


class BackupTopologyController(TopologyController[SSSDMultihostConfig]):
    """
    Provide basic restore functionality for topologies.
    """

    def __init__(self) -> None:
        super().__init__()

        self.backup_data: dict[BaseBackupHost, Any | None] = {}
        self.provisioned: bool = False

    def _init(self, *args, **kwargs):
        super()._init(*args, **kwargs)
        self.provisioned = self.name in self.multihost.provisioned_topologies

    def restore(self, hosts: dict[BaseBackupHost, Any | None]) -> None:
        errors = []
        for host, backup_data in hosts.items():
            if not isinstance(host, BaseBackupHost):
                continue

            try:
                host.restore(backup_data)
            except Exception as e:
                errors.append(e)

        if errors:
            raise ExceptionGroup("Some hosts failed to restore to original state", errors)

    def restore_vanilla(self) -> None:
        restore_data: dict[BaseBackupHost, Any | None] = {}

        for host in self.hosts:
            if not isinstance(host, BaseBackupHost):
                continue

            restore_data[host] = host.backup_data

        self.restore(restore_data)

    def topology_teardown(self) -> None:
        if self.provisioned:
            return

        try:
            for host, backup_data in self.backup_data.items():
                if not isinstance(host, BaseBackupHost):
                    continue

                host.remove_backup(backup_data)
        except Exception:
            # This is not that important, we can just ignore
            pass

        self.restore_vanilla()

    def teardown(self) -> None:
        if self.provisioned:
            self.restore_vanilla()
            return

        self.restore(self.backup_data)


class ClientTopologyController(BackupTopologyController):
    """
    Client Topology Controller.
    """

    def topology_teardown(self) -> None:
        pass

    def teardown(self) -> None:
        self.restore_vanilla()


class LDAPTopologyController(BackupTopologyController):
    """
    LDAP Topology Controller.
    """

    def topology_teardown(self) -> None:
        pass

    def teardown(self) -> None:
        self.restore_vanilla()


class IPATopologyController(BackupTopologyController):
    """
    IPA Topology Controller.
    """

    @restore_vanilla_on_error
    def topology_setup(self, client: ClientHost, ipa: IPAHost, nfs: NFSHost) -> None:
        if self.provisioned:
            self.logger.info(f"Topology '{self.name}' is already provisioned")
            return

        self.logger.info(f"Enrolling {client.hostname} into {ipa.domain}")

        # Remove any existing Kerberos configuration and keytab
        client.fs.rm("/etc/krb5.conf")
        client.fs.rm("/etc/krb5.keytab")

        # Backup ipa-client-install files
        client.fs.backup("/etc/ipa")
        client.fs.backup("/var/lib/ipa-client")

        # Join ipa domain
        client.conn.exec(["realm", "join", ipa.domain], input=ipa.adminpw)

        # Backup so we can restore to this state after each test
        self.backup_data[ipa] = ipa.backup()
        self.backup_data[client] = client.backup()
        self.backup_data[nfs] = nfs.backup()


class ADTopologyController(BackupTopologyController):
    """
    AD Topology Controller.
    """

    @restore_vanilla_on_error
    def topology_setup(self, client: ClientHost, provider: ADHost | SambaHost, nfs: NFSHost) -> None:
        if self.provisioned:
            self.logger.info(f"Topology '{self.name}' is already provisioned")
            return

        self.logger.info(f"Enrolling {client.hostname} into {provider.domain}")

        # Remove any existing Kerberos configuration and keytab
        client.fs.rm("/etc/krb5.conf")
        client.fs.rm("/etc/krb5.keytab")

        # Join AD domain
        client.conn.exec(["realm", "join", provider.domain], input=provider.adminpw)

        # Backup so we can restore to this state after each test
        self.backup_data[provider] = provider.backup()
        self.backup_data[client] = client.backup()
        self.backup_data[nfs] = nfs.backup()


class SambaTopologyController(ADTopologyController):
    """
    Samba Topology Controller.
    """

    pass


class IPATrustADTopologyController(BackupTopologyController):
    """
    IPA trust AD Topology Controller.
    """

    @restore_vanilla_on_error
    def topology_setup(self, client: ClientHost, ipa: IPAHost, trusted: ADHost | SambaHost) -> None:
        if self.provisioned:
            self.logger.info(f"Topology '{self.name}' is already provisioned")
            return

        # Create trust
        self.logger.info(f"Establishing trust between {ipa.domain} and {trusted.domain}")
        ipa.kinit()
        self.trust_add(ipa, trusted)

        # Do not enroll client into IPA domain if it is already joined
        if "ipa" not in self.multihost.provisioned_topologies:
            self.logger.info(f"Enrolling {client.hostname} into {ipa.domain}")

            # Remove any existing Kerberos configuration and keytab
            client.fs.rm("/etc/krb5.conf")
            client.fs.rm("/etc/krb5.keytab")

            # Backup ipa-client-install files
            client.fs.backup("/etc/ipa")
            client.fs.backup("/var/lib/ipa-client")

            # Join IPA domain)
            client.conn.exec(["realm", "join", ipa.domain], input=ipa.adminpw)

        # Backup so we can restore to this state after each test
        self.backup_data[ipa] = ipa.backup()
        self.backup_data[trusted] = trusted.backup()
        self.backup_data[client] = client.backup()

    # If this command is run on freshly started containers, it is possible the IPA is not yet
    # fully ready to create the trust. It takes a while for it to start working.
    @retry_command(max_retries=20, delay=5, match_stderr='CIFS server communication error: code "3221225581"')
    def trust_add(self, ipa: IPAHost, trusted: ADHost | SambaHost) -> ProcessResult:
        return ipa.conn.exec(
            ["ipa", "trust-add", trusted.domain, "--admin", "Administrator", "--password"], input=trusted.adminpw
        )


class IPATrustSambaTopologyController(IPATrustADTopologyController):
    """
    IPA trust Samba Topology Controller.
    """

    pass
