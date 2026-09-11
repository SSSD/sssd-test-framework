"""Client multihost role."""

from __future__ import annotations

import os

from pytest_mh.conn import ProcessResult

from ..hosts.client import ClientHost
from ..topology import SSSDTopologyMark
from ..utils.adcli import AdcliUtils
from ..utils.automount import AutomountUtils
from ..utils.gdm import GDM
from ..utils.ldb import LDBUtils
from ..utils.local_users import (
    LocalGroup,
    LocalNetgroup,
    LocalSudoAlias,
    LocalSudoAliasKind,
    LocalSudoRule,
    LocalUser,
    LocalUsersUtils,
)
from ..utils.realmd import RealmUtils
from ..utils.sbus import DBUSDestination, DBUSKnownBus
from ..utils.smartcard import SmartCardUtils
from ..utils.sss_override import SSSOverrideUtils
from ..utils.sssctl import SSSCTLUtils
from ..utils.sssd import SSSDUtils
from ..utils.vfido import Vfido
from .base import BaseLinuxRole
from .generic import GenericProvider

__all__ = [
    "Client",
]


class Client(BaseLinuxRole[ClientHost]):
    """
    SSSD Client role.

    Provides unified Python API for managing and testing SSSD.

    .. code-block:: python
        :caption: Starting SSSD

        @pytest.mark.topology(KnownTopology.Client)
        def test_example(client: Client):
            client.sssd.start()

    .. note::

        The role object is instantiated automatically as a dynamic pytest
        fixture by the multihost plugin. You should not create the object
        manually.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.sssd: SSSDUtils = SSSDUtils(self.host, self.fs, self.svc, self.authselect, load_config=False)
        """
        Managing and configuring SSSD.
        """

        self.sssctl: SSSCTLUtils = SSSCTLUtils(self.host, self.fs)
        """
        Call commands from sssctl.
        """

        self.realm: RealmUtils = RealmUtils(self.host)
        """
        Call commands from realm.
        """

        self.adcli: AdcliUtils = AdcliUtils(self.host)
        """
        Call commands from adcli.
        """

        self.ldb: LDBUtils = LDBUtils(self.host)
        """
        Utility for ldb functions.
        """

        self.automount: AutomountUtils = AutomountUtils(self.host, self.svc)
        """
        Methods for testing automount.
        """

        self.local: LocalUsersUtils = LocalUsersUtils(self.host, self.fs, client=self)
        """
        Managing local users and groups.
        """

        self.sss_override: SSSOverrideUtils = SSSOverrideUtils(self.host, self.fs)
        """
        Managing local overrides users and groups.
        """

        self.ifp: DBUSDestination = DBUSDestination(
            self.host, dest="org.freedesktop.sssd.infopipe", bus=DBUSKnownBus.SYSTEM
        )
        """
        The D-bus destination for infopipe.
        """

        self.smartcard: SmartCardUtils = SmartCardUtils(self.host, self.fs, self.svc)
        """
        Utility class for managing smart card operations using SoftHSM and PKCS#11.
        """

        self.gdm: GDM = GDM(self.host)
        """
        Managing GDM interface from SCAutolib
        """

        self.vfido: Vfido = Vfido(self.host)
        """
        Managing virtual passkey device and service
        """

    def setup(self) -> None:
        """
        Called before execution of each test.

        Setup client host:

        #. stop sssd
        #. clear sssd cache, logs and configuration
        #. import implicit domains from topology marker
        """
        super().setup()
        self.sssd.stop()
        self.sssd.clear(db=True, memcache=True, logs=True, config=True)

        if self.mh.data.topology_mark is not None:
            if not isinstance(self.mh.data.topology_mark, SSSDTopologyMark):
                raise ValueError("Multihost data does not have SSSDTopologyMark")

            for domain, path in self.mh.data.topology_mark.domains.items():
                role = self.mh._lookup(path)
                if isinstance(role, list):
                    raise ValueError("List is not expected")

                self.sssd.import_domain(domain, role)

    def sss_ssh_knownhosts(self, *args: str) -> ProcessResult:
        """
        Execute sss_ssh_knownhosts.

        :param `*args`: Command arguments.
        :type `*args`: str
        :return: Command result.
        :rtype: ProcessResult
        """
        return self.host.conn.exec(["sss_ssh_knownhosts", *args])

    def sss_ssh_authorizedkeys(self, *args: str) -> ProcessResult:
        """
        Execute sss_ssh_authorizedkeys.

        :param `*args`: Command arguments.
        :type `*args`: str
        :return: Command result.
        :rtype: ProcessResult
        """
        return self.host.conn.exec(["sss_ssh_authorizedkeys", *args], raise_on_error=False)

    def user(self, name: str) -> LocalUser:
        """
        Get user object.

        :param name: User name.
        :type name: str
        :return: New user object.
        :rtype: LocalUser
        """

        return LocalUser(self.local, name)

    def group(self, name: str) -> LocalGroup:
        """
        Get group object.
        :param name: Group name.
        :type name: str
        :return: New group object.
        :rtype: LocalGroup
        """

        return LocalGroup(self.local, name)

    def sudoalias(self, name: str, kind: LocalSudoAliasKind) -> LocalSudoAlias:
        """
        Get sudo alias object.
        :param name: Sudo alias name.
        :type name: str
        :param kind: Alias kind.
        :type kind: LocalSudoAliasKind
        :return: New sudo alias object.
        :rtype: LocalSudoAlias
        """

        return self.local.sudoalias(name, kind)

    def netgroup(self, name: str) -> LocalNetgroup:
        """
        Get netgroup object.
        :param name: Netgroup name.
        :type name: str
        :return: New netgroup object.
        :rtype: LocalNetgroup
        """

        return self.local.netgroup(name)

    def sudorule(self, name: str) -> LocalSudoRule:
        """
        Get sudo rule object.
        :param name: Sudo rule name.
        :type name: str
        :return: New sudo rule object.
        :rtype: LocalSudoRule
        """

        return self.local.sudorule(name)

    def install_ca_cert(
        self,
        provider: GenericProvider,
        name: str = "test-ca.crt",
        cert_path: str | None = None,
    ) -> str:
        """
        Install a CA certificate into the system trust store.

        Fetches the root CA certificate from ``provider``, writes it to the system
        trust anchor directory (``/etc/pki/ca-trust/source/anchors/<name>``),
        runs ``update-ca-trust``, and configures ``/etc/openldap/ldap.conf``
        so that OpenLDAP clients (adcli, realmd, ldapsearch, etc.) use the
        system trust store.

        All changes are tracked by the test framework and restored automatically
        after the test.

        :param provider: Provider role to fetch the root CA certificate from.
        :type provider: ~sssd_test_framework.roles.generic.GenericProvider
        :param name: Certificate filename under ``/etc/pki/ca-trust/source/anchors/``.
            Ignored when ``cert_path`` is set.
        :type name: str
        :param cert_path: Full destination path on the client, overrides the default.
        :type cert_path: str | None
        :return: Path where the certificate was written on the client.
        :rtype: str
        """
        ca_cert = provider.export_root_ca_certificate()

        if cert_path is None:
            cert_path = f"/etc/pki/ca-trust/source/anchors/{name}"

        parent = os.path.dirname(cert_path)
        if parent and len(parent.split("/")) > 2:
            self.fs.mkdir_p(parent)

        self.fs.write(cert_path, ca_cert)
        self.host.conn.run("update-ca-trust")
        self._configure_tls_cacert()

        return cert_path

    def install_ca_cert_from_server(
        self,
        hostname: str,
        port: int = 636,
        name: str = "test-ca.crt",
        cert_path: str | None = None,
    ) -> str:
        """
        Install a CA certificate by fetching it directly from a TLS server.

        Connects to ``hostname:port`` with ``openssl s_client``, captures the
        certificate the server presents, writes it to the system trust anchor
        directory, runs ``update-ca-trust``, and points ``TLS_CACERT`` in
        ``/etc/openldap/ldap.conf`` at the updated system bundle. Useful when
        the server uses a self-signed certificate that is difficult to export
        from the host (e.g. AD DC with no AD CS).

        All changes are tracked by the test framework and restored automatically
        after the test.

        :param hostname: Hostname or IP of the TLS server.
        :type hostname: str
        :param port: TLS port, defaults to 636.
        :type port: int
        :param name: Certificate filename under ``/etc/pki/ca-trust/source/anchors/``.
            Ignored when ``cert_path`` is set.
        :type name: str
        :param cert_path: Full destination path on the client, overrides the default.
        :type cert_path: str | None
        :return: Path where the certificate was written on the client.
        :rtype: str
        :raises RuntimeError: If the certificate cannot be fetched from the server.
        """
        result = self.host.conn.run(
            f"openssl s_client -connect {hostname}:{port} -showcerts </dev/null 2>/dev/null",
            raise_on_error=False,
        )

        certs = []
        current: list[str] = []
        for line in result.stdout.splitlines():
            if "-----BEGIN CERTIFICATE-----" in line:
                current = [line]
            elif "-----END CERTIFICATE-----" in line:
                current.append(line)
                certs.append("\n".join(current))
                current = []
            elif current:
                current.append(line)

        if not certs:
            raise RuntimeError(f"Failed to fetch certificate from {hostname}:{port}: {result.stderr}")

        pem = certs[-1]

        if cert_path is None:
            cert_path = f"/etc/pki/ca-trust/source/anchors/{name}"

        parent = os.path.dirname(cert_path)
        if parent and len(parent.split("/")) > 2:
            self.fs.mkdir_p(parent)

        self.fs.write(cert_path, pem)
        self.host.conn.run("update-ca-trust")
        self._configure_tls_cacert()

        return cert_path

    def _configure_tls_cacert(self) -> None:
        """
        Configure ``/etc/openldap/ldap.conf`` for system CA trust and channel binding.

        Removes any explicit ``TLS_CACERT`` and ``TLS_CACERTDIR`` directives so
        libldap falls back to its compiled-in defaults (the system trust store).
        Sets ``SASL_CBINDING tls-endpoint`` for channel binding support.
        """
        ldap_conf = "/etc/openldap/ldap.conf"

        result = self.host.conn.run(f"cat {ldap_conf}", raise_on_error=False)
        current = result.stdout if result.rc == 0 else ""

        lines = [
            line
            for line in current.splitlines()
            if not line.startswith("TLS_CACERT")
            and not line.startswith("TLS_CACERTDIR")
            and not line.startswith("SASL_CBINDING")
        ]
        lines.append("SASL_CBINDING tls-endpoint")

        self.fs.write(ldap_conf, "\n".join(lines) + "\n")
