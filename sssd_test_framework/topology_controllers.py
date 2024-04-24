from __future__ import annotations

from pytest_mh import TopologyController

from .hosts.base import BaseBackupHost

__all__ = [
    "LDAPTopologyController",
    "IPATopologyController",
    "ADTopologyController",
    "SambaTopologyController",
    "IPATrustADTopologyController",
    "IPATrustSambaTopologyController",
]


class BackupTopologyController(TopologyController):
    """
    Run "restore" method on all hosts that inherit from BaseBackupHost.
    """

    def teardown(self, **kwargs) -> None:
        errors = []
        for host in set(kwargs.values()):
            if not isinstance(host, BaseBackupHost):
                continue

            try:
                host.restore(host.backup_data)
            except Exception as e:
                errors.append(e)

        if errors:
            raise ExceptionGroup("Some hosts failed to restore to original state", errors)


class ClientTopologyController(BackupTopologyController):
    """
    Client Topology Controller.
    """

    pass


class LDAPTopologyController(BackupTopologyController):
    """
    LDAP Topology Controller.
    """

    pass


class IPATopologyController(BackupTopologyController):
    """
    IPA Topology Controller.
    """

    pass


class ADTopologyController(BackupTopologyController):
    """
    AD Topology Controller.
    """

    pass


class SambaTopologyController(BackupTopologyController):
    """
    Samba Topology Controller.
    """

    pass


class IPATrustADTopologyController(BackupTopologyController):
    """
    IPA trust AD Topology Controller.
    """

    pass


class IPATrustSambaTopologyController(BackupTopologyController):
    """
    IPA trust Samba Topology Controller.
    """

    pass
