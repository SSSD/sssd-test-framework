from __future__ import annotations

from typing import TYPE_CHECKING

from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.cli import CLIBuilder, CLIBuilderArgs
from pytest_mh.utils.fs import LinuxFileSystem
from pytest_mh.utils.services import SystemdServices

if TYPE_CHECKING:
    from ..roles.client import Client

__all__ = [
    "SmartCardUtils",
]


class SmartCardUtils(MultihostUtility[MultihostHost]):
    """
    Utility class for managing smart card operations using SoftHSM and PKCS#11.
    """

    SOFTHSM2_CONF_PATH = "/opt/test_ca/softhsm2.conf"
    TOKEN_STORAGE_PATH = "/opt/test_ca/tokens"
    OPENSC_CACHE_PATHS = [
        "$HOME/.cache/opensc/",
        "/run/sssd/.cache/opensc/",
    ]

    def __init__(self, host: MultihostHost, fs: LinuxFileSystem, svc: SystemdServices) -> None:
        """
        :param host: Multihost object.
        :type host: MultihostHost
        :param fs: Filesystem utility object.
        :type fs: LinuxFileSystem
        :param svc: Systemd svc utility object.
        :type svc: SystemdServices
        """
        super().__init__(host)

        self.cli: CLIBuilder = host.cli
        """CLI builder utility for command construction."""

        self.fs: LinuxFileSystem = fs
        """Filesystem utility used to handle file operations."""

        self.svc: SystemdServices = svc
        """Systemd utility to manage and interact with svc."""

    def initialize_card(self, label: str = "sc_test", so_pin: str = "12345678", user_pin: str = "123456") -> None:
        """
        Initializes a SoftHSM token with the given label and PINs.

        Cleans cache directories and prepares the token directory.

        :param label: Token label, defaults to "sc_test"
        :type label: str, optional
        :param so_pin: Security Officer PIN, defaults to "12345678"
        :type so_pin: str, optional
        :param user_pin: User PIN, defaults to "123456"
        :type user_pin: str, optional
        """
        for path in self.OPENSC_CACHE_PATHS:
            self.fs.rm(path)

        self.fs.rm(self.TOKEN_STORAGE_PATH)
        self.fs.mkdir_p(self.TOKEN_STORAGE_PATH)

        args: CLIBuilderArgs = {
            "label": (self.cli.option.VALUE, label),
            "free": (self.cli.option.SWITCH, True),
            "so-pin": (self.cli.option.VALUE, so_pin),
            "pin": (self.cli.option.VALUE, user_pin),
        }
        self.host.conn.run(
            self.cli.command("softhsm2-util --init-token", args), env={"SOFTHSM2_CONF": self.SOFTHSM2_CONF_PATH}
        )

    def add_cert(
        self,
        cert_path: str,
        cert_id: str = "01",
        pin: str = "123456",
        private: bool | None = False,
    ) -> None:
        """
        Adds a certificate or private key to the smart card.

        :param cert_path: Path to the certificate or key file.
        :type cert_path: str
        :param cert_id: Object ID, defaults to "01"
        :type cert_id: str, optional
        :param pin: User PIN, defaults to "123456"
        :type pin: str, optional
        :param private: Whether the object is a private key. Defaults to False.
        :type private: bool, optional
        """
        obj_type = "privkey" if private else "cert"
        args: CLIBuilderArgs = {
            "module": (self.cli.option.VALUE, "/usr/lib64/pkcs11/libsofthsm2.so"),
            "login": (self.cli.option.SWITCH, True),
            "pin": (self.cli.option.VALUE, pin),
            "write-object": (self.cli.option.VALUE, cert_path),
            "type": (self.cli.option.VALUE, obj_type),
            "id": (self.cli.option.VALUE, cert_id),
        }
        self.host.conn.run(self.cli.command("pkcs11-tool", args), env={"SOFTHSM2_CONF": self.SOFTHSM2_CONF_PATH})

    def add_key(self, key_path: str, key_id: str = "01", pin: str = "123456") -> None:
        """
        Adds a private key to the smart card.

        :param key_path: Path to the private key.
        :type key_path: str
        :param key_id: Key ID, defaults to "01"
        :type key_id: str, optional
        :param pin: User PIN, defaults to "123456"
        :type pin: str, optional
        """
        self.add_cert(cert_path=key_path, cert_id=key_id, pin=pin, private=True)

    def generate_cert(
        self,
        key_path: str = "/tmp/selfsigned.key",
        cert_path: str = "/tmp/selfsigned.crt",
        subj: str = "/CN=Test Cert",
    ) -> tuple[str, str]:
        """
        Generates a self-signed certificate and private key.

        :param key_path: Output path for the private key, defaults to "/tmp/selfsigned.key"
        :type key_path: str, optional
        :param cert_path: Output path for the certificate, defaults to "/tmp/selfsigned.crt"
        :type cert_path: str, optional
        :param subj: Subject for the certificate, defaults to "/CN=Test Cert"
        :type subj: str, optional
        :return: Tuple of (key_path, cert_path)
        :rtype: tuple
        """
        args: CLIBuilderArgs = {
            "x509": (self.cli.option.SWITCH, True),
            "nodes": (self.cli.option.SWITCH, True),
            "sha256": (self.cli.option.SWITCH, True),
            "days": (self.cli.option.VALUE, "365"),
            "newkey": (self.cli.option.VALUE, "rsa:2048"),
            "keyout": (self.cli.option.VALUE, key_path),
            "out": (self.cli.option.VALUE, cert_path),
            "subj": (self.cli.option.VALUE, subj),
        }
        self.host.conn.run(self.cli.command("openssl req", args))
        return key_path, cert_path

    def insert_card(self) -> None:
        """
        Simulates card insertion by starting the smart card service.
        """
        self.svc.start("virt_cacard.service")

    def remove_card(self) -> None:
        """
        Simulates card removal by stopping the smart card service.
        """
        self.svc.stop("virt_cacard.service")

    def setup_local_card(self, client: Client, username: str) -> None:
        """
        Setup local system for smart card authentication.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.Client)
            def test_example(client: Client):
                client.smartcard.setup_local_card(client, 'localuser1')

                result = client.host.conn.run("su - localuser1 -c 'su - localuser1 -c whoami'", input="123456")
                assert "PIN" in result.stderr
                assert "localuser1" in result.stdout
        """
        client.host.fs.rm("/etc/sssd/pki/sssd_auth_ca_db.pem")
        key, cert = self.generate_cert()
        self.initialize_card()
        self.add_key(key)
        self.add_cert(cert)
        client.authselect.select("sssd", ["with-smartcard"])
        self.svc.restart("virt_cacard.service")
        client.sssd.common.local()
        client.sssd.dom("local")["local_auth_policy"] = "only"
        client.sssd.section(f"certmap/local/{username}")["matchrule"] = "<SUBJECT>.*CN=Test Cert.*"
        client.sssd.pam["pam_cert_auth"] = "True"

        data = client.host.fs.read(cert)
        client.host.fs.append("/etc/sssd/pki/sssd_auth_ca_db.pem", data)
        client.sssd.start()
