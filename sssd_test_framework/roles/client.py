"""Client multihost role."""

from __future__ import annotations

from pytest_mh.conn import ProcessResult

from ..hosts.client import ClientHost
from ..topology import SSSDTopologyMark
from ..utils.adcli import AdcliUtils
from ..utils.automount import AutomountUtils
from ..utils.ldb import LDBUtils
from ..utils.local_users import LocalUsersUtils
from ..utils.sbus import DBUSDestination, DBUSKnownBus
from ..utils.sss_override import SSSOverrideUtils
from ..utils.sssctl import SSSCTLUtils
from ..utils.sssd import SSSDUtils
from .base import BaseLinuxRole

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

        self.local: LocalUsersUtils = LocalUsersUtils(self.host, self.fs)
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
