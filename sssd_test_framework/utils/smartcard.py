from __future__ import annotations

from typing import TYPE_CHECKING

from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.cli import CLIBuilder, CLIBuilderArgs
from pytest_mh.utils.fs import LinuxFileSystem
from pytest_mh.utils.services import SystemdServices

if TYPE_CHECKING:
    from ..roles.client import Client
    from ..roles.ipa import IPA

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

    def initialize_card(
        self,
        label: str = "sc_test",
        so_pin: str = "12345678",
        user_pin: str = "123456",
        reset: bool = True,
    ) -> None:
        """
        Initialize a SoftHSM token with the given label and PINs.

        When *reset* is ``True`` (default), existing token storage and OpenSC
        caches are removed first.  Pass ``False`` to add a token alongside
        existing ones (multi-token / multi-card setup).

        :param label: Token label, defaults to "sc_test"
        :type label: str, optional
        :param so_pin: Security Officer PIN, defaults to "12345678"
        :type so_pin: str, optional
        :param user_pin: User PIN, defaults to "123456"
        :type user_pin: str, optional
        :param reset: Remove existing tokens before initializing, defaults to True
        :type reset: bool, optional
        """
        if reset:
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
        token_label: str | None = None,
        label: str | None = None,
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
        :param token_label: Label of the target token. When ``None`` (the
            default) ``pkcs11-tool`` writes to the first available token.
            Set this when multiple tokens exist to target a specific one.
        :type token_label: str | None, optional
        :param label: Label for the PKCS#11 object being written.  Required
            when ``p11_child`` accesses the token directly (i.e. without
            ``virt_cacard``), because the response parser expects a
            non-empty label.
        :type label: str | None, optional
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
        if token_label is not None:
            args["token-label"] = (self.cli.option.VALUE, token_label)
        if label is not None:
            args["label"] = (self.cli.option.VALUE, label)
        self.host.conn.run(self.cli.command("pkcs11-tool", args), env={"SOFTHSM2_CONF": self.SOFTHSM2_CONF_PATH})

    def add_key(
        self,
        key_path: str,
        key_id: str = "01",
        pin: str = "123456",
        token_label: str | None = None,
        label: str | None = None,
    ) -> None:
        """
        Adds a private key to the smart card.

        :param key_path: Path to the private key.
        :type key_path: str
        :param key_id: Key ID, defaults to "01"
        :type key_id: str, optional
        :param pin: User PIN, defaults to "123456"
        :type pin: str, optional
        :param token_label: Label of the target token (see :meth:`add_cert`).
        :type token_label: str | None, optional
        :param label: Label for the PKCS#11 object (see :meth:`add_cert`).
        :type label: str | None, optional
        """
        self.add_cert(cert_path=key_path, cert_id=key_id, pin=pin, private=True, token_label=token_label, label=label)

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

    def enroll_to_token(
        self,
        client: Client,
        ipa: IPA,
        username: str,
        *,
        token_label: str = "sc_test",
        cert_id: str = "01",
        pin: str = "123456",
        init: bool = False,
    ) -> None:
        """
        Request an IPA-signed certificate for *username* and store it on *token_label*.

        When *init* is ``True``, the token is first initialized via
        :meth:`initialize_card` (resetting any existing token storage).
        Pass ``False`` when the card has already been initialized or when
        adding a second certificate to an existing token.

        :param client: Client role object.
        :type client: Client
        :param ipa: IPA role object whose CA issues the certificate.
        :type ipa: IPA
        :param username: IPA principal to issue the certificate for.
        :type username: str
        :param token_label: SoftHSM token label to write the objects to,
            defaults to "sc_test".
        :type token_label: str, optional
        :param cert_id: PKCS#11 object ID, defaults to "01".
        :type cert_id: str, optional
        :param pin: User PIN for the token, defaults to "123456".
        :type pin: str, optional
        :param init: Initialize (and reset) the token before enrolling,
            defaults to False.
        :type init: bool, optional
        """
        if init:
            self.initialize_card(label=token_label, user_pin=pin)

        cert, key, _ = ipa.ca.request(username)
        cert_content = ipa.fs.read(cert)
        key_content = ipa.fs.read(key)

        name_suffix = token_label
        cert_path = f"/opt/test_ca/{username}_{name_suffix}.crt"
        key_path = f"/opt/test_ca/{username}_{name_suffix}.key"

        client.fs.write(cert_path, cert_content)
        client.fs.write(key_path, key_content)

        self.add_key(key_path, key_id=cert_id, pin=pin, token_label=token_label, label=username)
        self.add_cert(cert_path, cert_id=cert_id, pin=pin, token_label=token_label, label=username)
