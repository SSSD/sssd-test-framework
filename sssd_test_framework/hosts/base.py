"""Base classes and objects for SSSD specific multihost hosts."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import PurePath
from typing import Any

import ldap
from ldap.ldapobject import ReconnectLDAPObject
from pytest_mh import MultihostHost
from pytest_mh.ssh import SSHPowerShellProcess
from pytest_mh.utils.fs import LinuxFileSystem
from pytest_mh.utils.services import SystemdServices

from ..config import SSSDMultihostDomain

__all__ = [
    "BaseHost",
    "BaseBackupHost",
    "BaseDomainHost",
    "BaseLDAPDomainHost",
]


class BaseHost(MultihostHost[SSSDMultihostDomain]):
    """
    Base class for all SSSD hosts.
    """

    @property
    def features(self) -> dict[str, bool]:
        """
        Features supported by the host.
        """
        return {}


class BaseBackupHost(BaseHost, ABC):
    """
    Base class for all hosts that supports automatic backup and restore.

    A backup of the host is created before starting a test case and all changes
    done in the test case to the host are automatically reverted when the test
    run is finished.

    .. warning::

        There might be some limitations on what data can and can not be restored
        that depends on particular host. See the documentation of each host
        class to learn if a full or partial restoration is done.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.backup_data: Any | None = None
        """Backup data of vanilla state of this host."""

    def pytest_setup(self) -> None:
        # Make sure required services are running
        try:
            self.start()
        except NotImplementedError:
            pass

        # Create backup of initial state
        self.backup_data = self.backup()

    def pytest_teardown(self) -> None:
        self.remove_backup(self.backup_data)

    def remove_backup(self, backup_data: Any | None) -> None:
        """
        Remove backup data from the host.

        :param backup_data: Backup data.
        :type backup_data: Any | None
        """
        if backup_data is None:
            return

        if isinstance(backup_data, PurePath):
            path = str(backup_data)
        else:
            raise TypeError(f"Only PurePath is supported as backup_data, got {type(backup_data)}")

        if self.ssh.shell is SSHPowerShellProcess:
            self.ssh.exec(["Remove-Item", "-Force", "-Recurse", path])
        else:
            self.ssh.exec(["rm", "-fr", path])

    @abstractmethod
    def start(self) -> None:
        """
        Start required services.

        :raises NotImplementedError: If start operation is not supported.
        """
        pass

    @abstractmethod
    def stop(self) -> None:
        """
        Stop required services.

        :raises NotImplementedError: If stop operation is not supported.
        """
        pass

    @abstractmethod
    def backup(self) -> Any:
        """
        Backup backend data.

        Returns directory or file path where the backup is stored (as PurePath)
        or any Python data relevant for the backup. This data is passed to
        :meth:`restore` which will use this information to restore the host to
        its original state.

        :return: Backup data.
        :rtype: Any
        """
        pass

    @abstractmethod
    def restore(self, backup_data: Any | None) -> None:
        """
        Restore backend data.

        :param backup_data: Backup data.
        :type backup_data: Any | None
        """
        pass


class BaseDomainHost(BaseBackupHost):
    """
    Base class for all domain (backend) hosts.

    This class extends the multihost configuration with ``config.client``
    section that can contain additional SSSD configuration for the domain to
    allow connection to the domain (like keytab and certificate locations,
    domain name, etc.).

    .. code-block:: yaml
        :caption: Example multihost configuration
        :emphasize-lines: 4-7

        - hostname: master.ipa.test
          role: ipa
          config:
            client:
              ipa_domain: ipa.test
              krb5_keytab: /enrollment/ipa.keytab
              ldap_krb5_keytab: /enrollment/ipa.keytab
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.client: dict[str, Any] = self.config.get("client", {})

        self.domain: str = self.config.get("domain", "test")
        """Identity domain name."""

        self.realm: str = self.config.get("realm", self.domain.upper())
        """Kerberos realm."""


class BaseLDAPDomainHost(BaseDomainHost):
    """
    Base class for all domain (backend) hosts that require direct LDAP access to
    manipulate data (like 389ds or SambaDC).

    Extends :class:`BaseDomainHost` to manage LDAP connection and adds
    ``config.binddn`` and ``config.bindpw`` multihost configuration options.

    .. code-block:: yaml
        :caption: Example multihost configuration
        :emphasize-lines: 6-7

        - hostname: master.ldap.test
          role: ldap
          config:
            binddn: cn=Directory Manager
            bindpw: Secret123
            client:
              ldap_tls_reqcert: demand
              ldap_tls_cacert: /data/certs/ca.crt
              dns_discovery_domain: ldap.test

    .. note::

        The LDAP connection is not opened immediately, but only when
        :attr:`conn` is accessed for the first time.
    """

    def __init__(self, *args, tls: bool = True, **kwargs) -> None:
        """
        :param tls: Require TLS connection, defaults to True
        :type tls: bool, optional
        """
        super().__init__(*args, **kwargs)

        self.tls: bool = tls
        """Use TLS when establishing connection or no?"""

        self.binddn: str = self.config.get("binddn", "cn=Directory Manager")
        """Bind DN ``config.binddn``, defaults to ``cn=Directory Manager``"""

        self.bindpw: str = self.config.get("bindpw", "Secret123")
        """Bind password ``config.bindpw``, defaults to ``Secret123``"""

        # Lazy properties.
        self.__conn: ReconnectLDAPObject | None = None
        self.__naming_context: str | None = None

    @property
    def conn(self) -> ReconnectLDAPObject:
        """
        LDAP connection (``python-ldap`` library).

        :rtype: ReconnectLDAPObject
        """
        if not self.__conn:
            newconn = ReconnectLDAPObject(f"ldap://{self.ssh_host}")
            newconn.protocol_version = ldap.VERSION3
            newconn.set_option(ldap.OPT_REFERRALS, 0)

            if self.tls:
                newconn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
                newconn.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
                newconn.start_tls_s()

            newconn.simple_bind_s(self.binddn, self.bindpw)
            self.__conn = newconn

        return self.__conn

    @property
    def naming_context(self) -> str:
        """
        Default naming context.

        :raises ValueError: If default naming context can not be obtained.
        :rtype: str
        """
        if not self.__naming_context:
            attr = "defaultNamingContext"
            result = self.conn.search_s("", ldap.SCOPE_BASE, attrlist=[attr])
            if len(result) != 1:
                raise ValueError(f"Unexpected number of results for rootDSE query: {len(result)}")

            (_, values) = result[0]
            if attr not in values:
                raise ValueError(f"Unable to find {attr}")

            self.__naming_context = str(values[attr][0].decode("utf-8"))

        return self.__naming_context

    def disconnect(self) -> None:
        """
        Disconnect LDAP connection.
        """
        if self.__conn is not None:
            self.__conn.unbind()
            self.__conn = None

    def ldap_result_to_dict(
        self, result: list[tuple[str, dict[str, list[bytes]]]]
    ) -> dict[str, dict[str, list[bytes]]]:
        """
        Convert result from python-ldap library from tuple into a dictionary
        to simplify lookup by distinguished name.

        :param result: Search result from python-ldap.
        :type result: tuple[str, dict[str, list[bytes]]]
        :return: Dictionary with distinguished name as key and attributes as value.
        :rtype: dict[str, dict[str, list[bytes]]]
        """
        return dict((dn, attrs) for dn, attrs in result if dn is not None)


class BaseLinuxHost(MultihostHost[SSSDMultihostDomain]):
    """
    Base Linux host.

    Adds linux specific reentrant utilities.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.fs: LinuxFileSystem = LinuxFileSystem(self)
        self.svc: SystemdServices = SystemdServices(self)
