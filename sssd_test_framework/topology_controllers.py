from __future__ import annotations

import socket

from pytest_mh import BackupTopologyController
from pytest_mh.conn import ProcessResult

from .config import SSSDMultihostConfig
from .hosts.ad import ADHost
from .hosts.client import ClientHost
from .hosts.ipa import IPAHost
from .hosts.keycloak import KeycloakHost
from .hosts.samba import SambaHost
from .misc.ssh import retry_command

__all__ = [
    "LDAPTopologyController",
    "IPATopologyController",
    "ADTopologyController",
    "SambaTopologyController",
    "IPATrustADTopologyController",
    "IPATrustSambaTopologyController",
    "IPATrustIPATopologyController",
    "KeycloakTopologyController",
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

    def topology_setup(self, *args, **kwargs) -> None:
        if self.provisioned:
            self.logger.info(f"Topology '{self.name}' is already provisioned")
            return

        super().topology_setup(*args, **kwargs)

    def topology_teardown(self, *args, **kwargs) -> None:
        if self.provisioned:
            return

        super().topology_teardown(*args, **kwargs)

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

        # Configure DNS forwarder for AD domain on IPA server
        self.setup_dns_forwarder(ipa, trusted)

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

    def setup_dns_forwarder(self, ipa: IPAHost, trusted: ADHost | SambaHost) -> None:
        """
        Configure DNS forwarder on IPA server for the trusted AD domain.

        This ensures IPA can resolve the AD domain for trust establishment.
        """
        self.logger.info(f"Configuring DNS forwarder for {trusted.domain} on {ipa.hostname}")
        ipa.kinit()

        # Check if forwarder already exists
        result = ipa.conn.exec(
            ["ipa", "dnsforwardzone-show", trusted.domain],
            raise_on_error=False,
        )

        if result.rc == 0:
            self.logger.info(f"DNS forwarder for {trusted.domain} already exists, skipping")
            return

        # Resolve AD server hostname to IP address (forwarder requires IP)
        # Use getattr to safely access the host attribute from the connection
        ad_hostname = getattr(trusted.conn, "host", trusted.hostname)
        try:
            ad_ip = socket.gethostbyname(ad_hostname)
        except socket.gaierror:
            self.logger.error(
                f"Could not resolve hostname '{ad_hostname}'. "
                "Please ensure it is resolvable from the test controller."
            )
            raise

        # Add DNS forward zone pointing to the AD server IP
        ipa.conn.exec(
            [
                "ipa",
                "dnsforwardzone-add",
                trusted.domain,
                f"--forwarder={ad_ip}",
                "--forward-policy=only",
            ]
        )

        # Restart named to ensure it picks up the new forwarder zone
        ipa.conn.exec(["systemctl", "restart", "named"])
        self.logger.info(f"DNS forwarder for {trusted.domain} configured successfully")

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


class KeycloakTopologyController(ProvisionedBackupTopologyController):
    """
    Keycloak Topology Controller.
    """

    @BackupTopologyController.restore_vanilla_on_error
    def topology_setup(self, client: ClientHost, keycloak: KeycloakHost) -> None:
        if self.provisioned:
            self.logger.info(f"Topology '{self.name}' is already provisioned")
            return

        self.logger.info(f"Enrolling {client.hostname} into {keycloak.hostname} by creating an IdP client")

        # Create an IdP client
        keycloak.kclogin()
        keycloak.conn.run(
            "/opt/keycloak/bin/kcadm.sh create clients -r master "
            '-b \'{"clientId": "myclient", "clientAuthenticatorType": "client-secret", '
            '"secret": "ClientSecret123", "serviceAccountsEnabled": true, '
            '"attributes": {"oauth2.device.authorization.grant.enabled": "true"}}\' '
        )
        keycloak.conn.run(
            "/opt/keycloak/bin/kcadm.sh add-roles -r master "
            "--cclientid account --rolename view-groups --uusername service-account-myclient"
        )
        keycloak.conn.run(
            "/opt/keycloak/bin/kcadm.sh add-roles -r master "
            "--cclientid master-realm --rolename view-users --uusername service-account-myclient"
        )
        keycloak.conn.run(
            "/opt/keycloak/bin/kcadm.sh add-roles -r master "
            "--cclientid master-realm --rolename query-users --uusername service-account-myclient"
        )
        keycloak.conn.run(
            "/opt/keycloak/bin/kcadm.sh add-roles -r master "
            "--cclientid master-realm --rolename query-groups --uusername service-account-myclient"
        )

        # Backup so we can restore to this state after each test
        super().topology_setup()


class GDMTopologyController(ProvisionedBackupTopologyController):
    """
    GDM EIdP Topology Controller.
    """

    @BackupTopologyController.restore_vanilla_on_error
    def topology_setup(self, client: ClientHost, ipa: IPAHost, keycloak: KeycloakHost) -> None:
        if self.provisioned:
            self.logger.info(f"Topology '{self.name}' is already provisioned")
            return

        self.logger.info(f"Enrolling IPA server {ipa.hostname} into {keycloak.hostname} by creating an IdP client")

        # Create an IdP client
        keycloak.kclogin()
        keycloak.conn.run(
            "/opt/keycloak/bin/kcadm.sh create clients -r master "
            '-b \'{"clientId": "ipa_oidc_client", "clientAuthenticatorType": "client-secret", '
            '"secret": "IPA_Secret123", "serviceAccountsEnabled": true, '
            '"redirectUris" : [ "https://ipa-ca.ipa.test/ipa/idp/*" ], '
            '"webOrigins" : [ "https://ipa-ca.ipa.test" ],'
            '"attributes": {"oauth2.device.authorization.grant.enabled": "true"}}\' '
        )

        ipa.kinit()
        ipa.conn.run(
            f"ipa idp-add keycloak --provider keycloak --base-url {keycloak.hostname}:8443/auth "
            "--org master --client-id ipa_oidc_client --secret",
            input="IPA_Secret123",
        )

        # Backup so we can restore to this state after each test
        super().topology_setup()

    def topology_teardown(self, ipa: IPAHost, keycloak: KeycloakHost) -> None:
        self.logger.info(f"Un-enrolling IPA server {ipa.hostname} from {keycloak.hostname} by deleting the IdP client")
        keycloak.kclogin()
        keycloak.conn.run(
            "ID=$(/opt/keycloak/bin/kcadm.sh get clients -q clientId=ipa_oidc_client --fields=id|jq -r '.[0].id'); "
            "/opt/keycloak/bin/kcadm.sh delete clients/$ID"
        )
        ipa.kinit()
        ipa.conn.run("ipa idp-del keycloak")
        super().topology_teardown()


class IPATrustIPATopologyController(ProvisionedBackupTopologyController):
    """
    IPA trust IPA Topology Controller.
    """

    @BackupTopologyController.restore_vanilla_on_error
    def topology_setup(self, client: ClientHost, ipa: IPAHost, trusted: IPAHost) -> None:
        if self.provisioned:
            self.logger.info(f"Topology '{self.name}' is already provisioned")
            return

        # Add ipa-ipa trust COPR and update packages
        self.logger.info("Adding COPR and updating packages")
        ipa.conn.exec(["dnf", "copr", "enable", "abbra/wip-ipa-trust", "-y"])
        client.conn.exec(["dnf", "copr", "enable", "abbra/wip-ipa-trust", "-y"])
        trusted.conn.exec(["dnf", "copr", "enable", "abbra/wip-ipa-trust", "-y"])

        ipa.conn.exec(["dnf", "update", "freeipa-server", "sssd-client", "-y"])
        trusted.conn.exec(["dnf", "update", "freeipa-server", "sssd-client", "-y"])
        client.conn.exec(["dnf", "update", "sssd-client", "-y"])

        # F40 sssd-kcm fails to start with 'Invalid option --genconf-section=kcm:'
        ipa.conn.exec(["systemctl", "restart", "sssd-kcm"])
        trusted.conn.exec(["systemctl", "restart", "sssd-kcm"])

        # upgraded ipa from a version not supporting the IPA id override templates commands,
        # may need to refresh IPA schema:
        ipa.conn.exec(["rm", "-rf", "~/.cache/ipa/schema"])
        trusted.conn.exec(["rm", "-rf", "~/.cache/ipa/schema"])

        # IPA server and the remote domain cannot share the same NetBIOS name: MASTER
        trusted.kinit()
        trusted.conn.exec(["ipa-adtrust-install", "--netbios-name", "MASTER2", "-U"])

        # Create trust
        self.logger.info(f"Establishing trust between {ipa.domain} and {trusted.domain}")

        ipa.kinit()
        ipa.conn.exec(
            [
                "ipa",
                "trust-add",
                trusted.domain,
                "--admin",
                "admin",
                "--password",
                "--range-type=ipa-ad-trust-posix",
                "--type=ipa",
                "--two-way=true",
            ],
            input=trusted.adminpw,
        )

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
