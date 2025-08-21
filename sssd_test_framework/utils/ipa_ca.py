from __future__ import annotations

import os
import re
import shlex
import uuid
from typing import Dict, Literal, Optional, Tuple

from pytest_mh import MultihostHost
from pytest_mh.cli import CLIBuilder, CLIBuilderArgs
from pytest_mh.utils.fs import LinuxFileSystem

RevocationReason = Literal[
    "unspecified",
    "key_compromise",
    "ca_compromise",
    "affiliation_changed",
    "superseded",
    "cessation_of_operation",
    "certificate_hold",
    "remove_from_crl",
    "privilege_withdrawn",
    "aa_compromise",
]


class IPACertificateAuthority:
    """
    Provides helper methods for FreeIPA Certificate Authority operations.

    This class allows requesting, revoking, placing/removing certificate holds,
    and retrieving certificate information via the ipa CLI.

    .. code-block:: python
       :caption: Example usage

       cert, key, csr = ipa.ca.request(principal="HTTP/client.ipa.test")
       ipa.ca.revoke_hold(cert)
       ipa.ca.revoke(cert, reason="key_compromise")
    """

    def __init__(self, host: MultihostHost, fs: LinuxFileSystem) -> None:
        """
        Initialize the IPA Certificate Authority helper.

        :param host: Remote test host.
        :type host: MultihostHost
        :param fs: Filesystem helper for remote file operations.
        :type fs: LinuxFileSystem
        """
        self.host = host
        self.fs = fs
        self.cli: CLIBuilder = host.cli
        self.temp_dir = f"/tmp/ipa_test_certs_{os.getpid()}_{uuid.uuid4().hex}"
        self.fs.mkdir_p(self.temp_dir, mode="700")

    def teardown(self) -> None:
        """
        Remove the temporary directory used for storing CSR, keys, and certificates.

        Logs a warning if cleanup fails.
        """
        try:
            self.fs.rm(self.temp_dir)
        except Exception as e:
            self.host.logger.warning(f"Failed to remove temporary directory {self.temp_dir}: {e}")

    def request(
        self,
        principal: str,
        subject: Optional[str] = None,
        add_service: bool = False,
        key_size: int = 2048,
    ) -> Tuple[str, str, str]:
        """
        Request a certificate from the IPA CA.

        :param principal: The principal (user or service) name.
        :type principal: str
        :param subject: Optional OpenSSL subject (e.g., /CN=example). If omitted, derived from principal.
        :type subject: str | None
        :param add_service: Whether to add the principal as an IPA service.
        :type add_service: bool
        :param key_size: RSA key size in bits.
        :type key_size: int
        :returns: A tuple of (certificate_path, key_path, csr_path).
        :rtype: tuple[str, str, str]
        :raises ValueError: If subject cannot be derived from principal.
        :raises RuntimeError: If CSR generation fails.
        """
        base = re.sub(r"[^a-zA-Z0-9.\_-]", "_", principal)
        key_path = os.path.join(self.temp_dir, f"{base}.key")
        csr_path = os.path.join(self.temp_dir, f"{base}.csr")
        cert_path = os.path.join(self.temp_dir, f"{base}.crt")

        if subject is None:
            hostname = principal.split("@")[0].split("/")[-1] if "@" in principal else principal.split("/")[-1]
            if not hostname:
                raise ValueError(f"Cannot derive subject from principal '{principal}'")
            subject = f"/CN={hostname}"

        self._generate_csr(key_path, csr_path, subject, key_size)

        if add_service:
            self.host.conn.run(f"ipa service-add {shlex.quote(principal)}", raise_on_error=False)

        args: CLIBuilderArgs = {
            "principal": (self.cli.option.VALUE, principal),
            "certificate-out": (self.cli.option.VALUE, cert_path),
        }

        self.host.conn.run(
            self.cli.command(f"ipa cert-request {shlex.quote(csr_path)}", args),
            raise_on_error=True,
        )

        return cert_path, key_path, csr_path

    def revoke(self, cert_path: str, reason: RevocationReason = "unspecified") -> None:
        """
        Revoke a certificate in IPA.

        :param cert_path: Path to the certificate file.
        :type cert_path: str
        :param reason: Reason for revocation.
        :type reason: RevocationReason
        :raises RuntimeError: If revocation fails.
        """
        serial = self._get_cert_serial(cert_path)
        reason_code = self._revocation_reason_to_code(reason)
        args: CLIBuilderArgs = {
            "serial": (self.cli.option.VALUE, serial),
            "revocation-reason": (self.cli.option.VALUE, str(reason_code)),
        }
        result = self.host.conn.run(self.cli.command("ipa cert-revoke", args), raise_on_error=False)
        if result.rc != 0:
            raise RuntimeError(f"IPA cert-revoke failed: {result.stderr}")

    def revoke_hold(self, cert_path: str) -> None:
        """
        Place a certificate on hold.

        :param cert_path: Path to the certificate file.
        :type cert_path: str
        """
        self.revoke(cert_path, reason="certificate_hold")

    def revoke_hold_remove(self, cert_path: str) -> None:
        """
        Remove hold from a certificate.

        :param cert_path: Path to the certificate file.
        :type cert_path: str
        :raises RuntimeError: If hold removal fails.
        """
        serial = self._get_cert_serial(cert_path)
        args: CLIBuilderArgs = {"serial": (self.cli.option.VALUE, serial)}
        result = self.host.conn.run(self.cli.command("ipa cert-remove-hold", args), raise_on_error=False)
        if result.rc != 0:
            raise RuntimeError(f"ipa cert-remove-hold failed: {result.stderr}")

    def get(self, cert_path: str) -> Dict[str, str]:
        """
        Retrieve certificate details from IPA.

        :param cert_path: Path to the certificate file.
        :type cert_path: str
        :returns: A dictionary of certificate attributes.
        :rtype: dict[str, str]
        :raises ValueError: If the certificate is not found in IPA.
        """
        serial = self._get_cert_serial(cert_path)
        args: CLIBuilderArgs = {
            "serial": (self.cli.option.VALUE, serial),
            "all": (self.cli.option.SWITCH, True),
        }
        result = self.host.conn.run(self.cli.command("ipa cert-show", args), raise_on_error=False)
        if result.rc != 0:
            raise ValueError(f"Certificate with serial '{serial}' not found in IPA: {result.stderr}")
        return self._parse_cert_info(result.stdout)

    def _generate_csr(self, key_path: str, csr_path: str, subject: str, key_size: int = 2048) -> None:
        """
        Generate a CSR and key using OpenSSL.

        :param key_path: Path to save the private key.
        :type key_path: str
        :param csr_path: Path to save the CSR file.
        :type csr_path: str
        :param subject: Subject for the CSR (e.g., /CN=example).
        :type subject: str
        :param key_size: RSA key size in bits.
        :type key_size: int
        :raises RuntimeError: If CSR generation fails.
        """
        args: CLIBuilderArgs = {
            "newkey": (self.cli.option.VALUE, f"rsa:{key_size}"),
            "nodes": (self.cli.option.SWITCH, True),
            "keyout": (self.cli.option.VALUE, key_path),
            "out": (self.cli.option.VALUE, csr_path),
            "subj": (self.cli.option.VALUE, subject),
        }
        result = self.host.conn.run(self.cli.command("openssl req", args), raise_on_error=False)
        if result.rc != 0:
            raise RuntimeError(f"OpenSSL CSR generation failed: {result.stderr}")

    def _get_cert_serial(self, cert_path: str) -> str:
        """
        Extract the certificate serial number using OpenSSL.

        :param cert_path: Path to the certificate file.
        :type cert_path: str
        :returns: The certificate serial number as a lowercase hex string.
        :rtype: str
        :raises RuntimeError: If serial extraction fails.
        """
        cmd = ["openssl", "x509", "-in", cert_path, "-noout", "-serial"]
        cmdline = " ".join(shlex.quote(p) for p in cmd)
        result = self.host.conn.run(cmdline, raise_on_error=False)
        if result.rc != 0:
            raise RuntimeError(f"Failed to get serial from certificate: {result.stderr}")
        out = (result.stdout or "").strip()
        if "=" in out:
            return out.split("=", 1)[1].lower()
        return out.lower()

    def _revocation_reason_to_code(self, reason: RevocationReason) -> int:
        """
        Map a revocation reason string to its corresponding numeric code.

        :param reason: Revocation reason string.
        :type reason: RevocationReason
        :returns: Numeric reason code.
        :rtype: int
        """
        reason_map = {
            "unspecified": 0,
            "key_compromise": 1,
            "ca_compromise": 2,
            "affiliation_changed": 3,
            "superseded": 4,
            "cessation_of_operation": 5,
            "certificate_hold": 6,
            "remove_from_crl": 8,
            "privilege_withdrawn": 9,
            "aa_compromise": 10,
        }
        return reason_map[reason]

    def _parse_cert_info(self, output: str) -> Dict[str, str]:
        """
        Parse ipa cert-show output into a dictionary.

        :param output: Raw command output from ipa cert-show.
        :type output: str
        :returns: Dictionary of certificate attributes.
        :rtype: dict[str, str]
        """
        info: Dict[str, str] = {}
        for line in (output or "").splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                info[key.strip()] = value.strip()
        return info
