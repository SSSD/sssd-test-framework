from __future__ import annotations

from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.utils.fs import LinuxFileSystem
from pytest_mh.cli import CLIBuilder

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

    def __init__(self, host: MultihostHost) -> None:
        super().__init__(host)

    def init(self, label: str, so_pin: str, user_pin: str) -> None:
        """
        Initializes a SoftHSM token with the given label and PINs.

        Cleans cache directories and prepares the token directory.

        :param label: Token label.
        :param so_pin: Security Officer PIN.
        :param user_pin: User PIN.
        """
        for path in self.OPENSC_CACHE_PATHS:
            self.host.conn.run(f"rm -rf {path}")

        self.host.conn.run(f"rm -rf {self.TOKEN_STORAGE_PATH}")
        self.host.conn.run(f"mkdir -p {self.TOKEN_STORAGE_PATH}")

        self.host.conn.exec(
            [
                "softhsm2-util", "--init-token",
                "--label", label,
                "--free",
                "--so-pin", so_pin,
                "--pin", user_pin
            ],
            env={"SOFTHSM2_CONF": self.SOFTHSM2_CONF_PATH}
        )

    def add_key(self, key_path: str, key_id: str = "01", pin: str = "123456") -> None:
        """
        Adds a private key to the smart card.

        :param key_path: Path to the private key.
        :param key_id: Key ID (default '01').
        :param pin: User PIN (default '123456').
        """
        self.host.conn.exec(
            [
                "pkcs11-tool", "--module", "/usr/lib64/pkcs11/libsofthsm2.so",
                "-l", "--pin", pin,
                "--write-object", key_path,
                "--type", "privkey",
                "--id", key_id
            ],
            env={"SOFTHSM2_CONF": self.SOFTHSM2_CONF_PATH}
        )

    def add_cert(self, cert_path: str, cert_id: str = "01", pin: str = "123456") -> None:
        """
        Adds a certificate to the smart card.

        :param cert_path: Path to the certificate.
        :param cert_id: Certificate ID (default '01').
        :param pin: User PIN (default '123456').
        """
        self.host.conn.exec(
            [
                "pkcs11-tool", "--module", "/usr/lib64/pkcs11/libsofthsm2.so",
                "-l", "--pin", pin,
                "--write-object", cert_path,
                "--type", "cert",
                "--id", cert_id
            ],
            env={"SOFTHSM2_CONF": self.SOFTHSM2_CONF_PATH}
        )

    def reset_service(self) -> None:
        """
        Restarts the virtual smart card service.
        """
        self.host.svc.restart("virt_cacard.service")

    def insert_card(self) -> None:
        """
        Simulates card insertion by starting the smart card service.
        """
        self.host.conn.exec(["systemctl", "start", "virt_cacard.service"])

    def remove_card(self) -> None:
        """
        Simulates card removal by stopping the smart card service.
        """
        self.host.conn.exec(["systemctl", "stop", "virt_cacard.service"])

    def generate_self_signed_cert(
        self,
        key_path: str = "/tmp/selfsigned.key",
        cert_path: str = "/tmp/selfsigned.crt",
        subj: str = "/CN=Test Cert"
    ) -> tuple[str, str]:
        """
        Generates a self-signed certificate and private key.

        :param key_path: Output path for the private key.
        :param cert_path: Output path for the certificate.
        :param subj: Subject for the certificate.
        :return: Tuple of (key_path, cert_path)
        """
        self.host.conn.exec(
            [
                "openssl", "req", "-x509", "-nodes",
                "-sha256", "-days", "365",
                "-newkey", "rsa:2048",
                "-keyout", key_path,
                "-out", cert_path,
                "-subj", subj
            ]
        )
        return key_path, cert_path