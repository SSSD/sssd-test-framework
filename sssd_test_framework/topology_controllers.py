from __future__ import annotations

from pytest_mh import BackupTopologyController
from pytest_mh.conn import ProcessResult

from .config import SSSDMultihostConfig
from .hosts.ad import ADHost
from .hosts.client import ClientHost
from .hosts.ipa import IPAHost
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


class ProvisionedBackupTopologyController(BackupTopologyController[SSSDMultihostConfig]):
    """
    Provide basic restore functionality for topologies.
    """

    def __init__(self) -> None:
        super().__init__()

        self.provisioned: bool = False

    def init(self, *args, **kwargs):
        super().init(*args, **kwargs)
        self.provisioned = self.name in self.multihost.provisioned_topologies

    def topology_teardown(self) -> None:
        if self.provisioned:
            return

        super().topology_teardown()

    def teardown(self) -> None:
        if self.provisioned:
            self.restore_vanilla()
            return

        super().teardown()


class ClientTopologyController(ProvisionedBackupTopologyController):
    """
    Client Topology Controller.
    """

    pass


class LDAPTopologyController(ProvisionedBackupTopologyController):
    """
    LDAP Topology Controller.
    """

    pass


class IPATopologyController(ProvisionedBackupTopologyController):
    """
    IPA Topology Controller.
    """

    @BackupTopologyController.restore_vanilla_on_error
    def topology_setup(self, client: ClientHost, ipa: IPAHost) -> None:
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
        super().topology_setup()


class ADTopologyController(ProvisionedBackupTopologyController):
    """
    AD Topology Controller.
    """

    @BackupTopologyController.restore_vanilla_on_error
    def topology_setup(self, client: ClientHost, provider: ADHost | SambaHost) -> None:
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
        super().topology_setup()


class SambaTopologyController(ADTopologyController):
    """
    Samba Topology Controller.
    """

    pass


class IPATrustADTopologyController(ProvisionedBackupTopologyController):
    """
    IPA trust AD Topology Controller.
    """

    @BackupTopologyController.restore_vanilla_on_error
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
        super().topology_setup()

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
