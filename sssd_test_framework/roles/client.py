"""Client multihost role."""

from __future__ import annotations

from pytest_mh.conn import ProcessResult

from ..hosts.client import ClientHost
from ..topology import SSSDTopologyMark
from ..utils.automount import AutomountUtils
from ..utils.ldb import LDBUtils
from ..utils.local_users import LocalUsersUtils
from ..utils.sbus import DBUSDestination, DBUSKnownBus
from ..utils.sss_override import SSSOverrideUtils
from ..utils.sssctl import SSSCTLUtils
from ..utils.sssd import SSSDUtils
from .base import BaseLinuxRole
from ..utils.virtual_smartcard import SmartCardUtils

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

        self.smart_card: SmartCardUtils = SmartCardUtils(self.host)
        """
        Utility class for managing smart card operations using SoftHSM and PKCS#11.
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
    
     
    def setup_smart_card(self, label: str, so_pin: str, user_pin: str) -> None:
        """
        Initializes the smart card with a given label and PINs.
        
        :param label: Label for the smart card token.
        :param so_pin: Security Officer PIN for the token.
        :param user_pin: User PIN for accessing the smart card.
        """
        self.smart_card.init(label, so_pin, user_pin)
    
    def upload_key(self, key_path: str, key_id: str, pin: str) -> None:
        """
        Adds a private key to the smart card.
        
        :param key_path: Path to the private key file.
        :param key_id: ID to associate with the key.
        :param pin: User PIN for authentication.
        """
        self.smart_card.add_key(key_path, key_id, pin)
    
    def upload_certificate(self, cert_path: str, cert_id: str, pin: str) -> None:
        """
        Adds a certificate to the smart card.
        
        :param cert_path: Path to the certificate file.
        :param cert_id: ID to associate with the certificate.
        :param pin: User PIN for authentication.
        """
        self.smart_card.add_cert(cert_path, cert_id, pin)
    
    def restart_smart_card_service(self) -> None:
        """
        Restarts the virtual smart card service.
        """
        self.smart_card.reset_service()
    
    def insert_smart_card(self) -> None:
        """
        Starts the virtual smart card service, simulating card insertion.
        """
        self.smart_card.insert_card()
    
    def remove_smart_card(self) -> None:
        """
        Stops the virtual smart card service, simulating card removal.
        """
        self.smart_card.remove_card()
    
    def generate_and_upload_ca(self, key_id: str, cert_id: str, pin: str, subj: str = "/CN=Test CA") -> tuple[str, str]:
        """
        Generates a CA key and self-signed certificate, then uploads both to the smart card.

        :param key_id: ID to associate with the private key.
        :param cert_id: ID to associate with the certificate.
        :param pin: User PIN for smart card authentication.
        :param subj: Subject DN for the certificate.
        :return: Tuple of paths (key_path, cert_path) on the remote host.
        """
        key_path, cert_path = self.smart_card.generate_ca_cert(subj=subj)
        self.smart_card.add_key(key_path, key_id, pin)
        self.smart_card.add_cert(cert_path, cert_id, pin)
        return key_path, cert_path