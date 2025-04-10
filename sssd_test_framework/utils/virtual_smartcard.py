from pytest_mh import MultihostHost
from pytest_mh.utils.fs import LinuxFileSystem

__all__ = [
    "SmartCardUtils",
]
class SmartCardUtils:
    """
    Utility class for managing smart card operations using SoftHSM and PKCS#11.
    """
    
    def __init__(self, host: MultihostHost):
        """
        Initializes the SmartCardUtils with a given host.
        
        :param host: The remote host where smart card operations will be executed.
        """
        self.host = host
        self.fs = LinuxFileSystem(host.conn)
    
    def init(self, label: str, so_pin: str, user_pin: str) -> None:
        """
        Initializes a SoftHSM token with the given label and PINs.
        
        :param label: The label for the new token.
        :param so_pin: Security Officer PIN.
        :param user_pin: User PIN.
        """
        self.host.conn.exec([
            "softhsm2-util", "--init-token",
            "--label", label,
            "--free",
            "--so-pin", so_pin,
            "--pin", user_pin
        ])
    
    def add_key(self, key_path: str, key_id: str, pin: str) -> None:
        """
        Adds a private key to the smart card.
        
        :param key_path: Path to the private key file.
        :param key_id: ID for the key in the smart card.
        :param pin: User PIN for authentication.
        """
        self.fs.copy(key_path, "/tmp/key.pem")
        self.host.conn.exec([
            "pkcs11-tool", "--module", "/usr/lib64/pkcs11/libsofthsm2.so",
            "-l", "--pin", pin,
            "--write-object", "/tmp/key.pem",
            "--type", "privkey",
            "--id", key_id
        ])
    
    def add_cert(self, cert_path: str, cert_id: str, pin: str) -> None:
        """
        Adds a certificate to the smart card.
        
        :param cert_path: Path to the certificate file.
        :param cert_id: ID for the certificate in the smart card.
        :param pin: User PIN for authentication.
        """
        self.fs.copy(cert_path, "/tmp/cert.pem")
        self.host.conn.exec([
            "pkcs11-tool", "--module", "/usr/lib64/pkcs11/libsofthsm2.so",
            "-l", "--pin", pin,
            "--write-object", "/tmp/cert.pem",
            "--type", "cert",
            "--id", cert_id
        ])
    
    def reset_service(self) -> None:
        """
        Restarts the virtual smart card service.
        """
        self.host.svc.restart("virt_cacard.service")
    
    def insert_card(self) -> None:
        """
        Starts the virtual smart card service to simulate card insertion.
        """
        self.host.conn.exec(["systemctl", "start", "virt_cacard.service"])
    
    def remove_card(self) -> None:
        """
        Stops the virtual smart card service to simulate card removal.
        """
        self.host.conn.exec(["systemctl", "stop", "virt_cacard.service"])

    def generate_ca_cert(self, key_path: str = "/tmp/ca.key", cert_path: str = "/tmp/ca.crt", subj: str = "/CN=Test CA") -> tuple[str, str]:
        """
        Generates a self-signed CA certificate and key using OpenSSL on the remote host.

        :param key_path: Path where the private key will be stored.
        :param cert_path: Path where the certificate will be stored.
        :param subj: The subject line for the certificate.
        :return: Tuple of (key_path, cert_path)
        """
        self.host.conn.exec([
            "openssl", "genrsa", "-out", key_path, "2048"
        ])
        self.host.conn.exec([
            "openssl", "req", "-x509", "-new", "-nodes",
            "-key", key_path,
            "-sha256", "-days", "365",
            "-out", cert_path,
            "-subj", subj
        ])
        return key_path, cert_path