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
    and retrieving certificate information via the `ipa` CLI.
    """

    def __init__(self, host: MultihostHost, fs: LinuxFileSystem) -> None:
        """
        Initialize the IPA Certificate Authority helper.

        Args:
            host: A connected `MultihostHost` instance for running commands.
            fs: A `LinuxFileSystem` instance for file operations.
        """
        self.host = host
        self.fs = fs
        self.cli: CLIBuilder = host.cli
        self.temp_dir = f"/tmp/ipa_test_certs_{os.getpid()}_{uuid.uuid4().hex}"
        self.fs.mkdir_p(self.temp_dir, mode="700")

    def __del__(self) -> None:
        """Clean up temporary files on object destruction."""
        self.teardown()

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

        Args:
            principal: The principal (user or service) name.
            subject: Optional OpenSSL subject (e.g., `/CN=example`). If omitted, derived from principal.
            add_service: Whether to add the principal as an IPA service.
            key_size: RSA key size in bits.

        Returns:
            A tuple of (certificate_path, key_path, csr_path).

        Raises:
            ValueError: If subject cannot be derived from principal.
            RuntimeError: If CSR generation fails.
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

        self.host.conn.run(self.cli.command(f"ipa cert-request {shlex.quote(csr_path)}", args), raise_on_error=True)

        return cert_path, key_path, csr_path

    def revoke(self, cert_path: str, reason: RevocationReason = "unspecified") -> None:
        """
        Revoke a certificate in IPA.

        Args:
            cert_path: Path to the certificate file.
            reason: Reason for revocation.

        Raises:
            RuntimeError: If revocation fails.
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

        Args:
            cert_path: Path to the certificate file.
        """
        self.revoke(cert_path, reason="certificate_hold")

    def revoke_hold_remove(self, cert_path: str) -> None:
        """
        Remove hold from a certificate.

        Args:
            cert_path: Path to the certificate file.

        Raises:
            RuntimeError: If hold removal fails.
        """
        serial = self._get_cert_serial(cert_path)
        args: CLIBuilderArgs = {"serial": (self.cli.option.VALUE, serial)}
        result = self.host.conn.run(self.cli.command("ipa cert-remove-hold", args), raise_on_error=False)
        if result.rc != 0:
            raise RuntimeError(f"ipa cert-remove-hold failed: {result.stderr}")

    def get(self, cert_path: str) -> Dict[str, str]:
        """
        Retrieve certificate details from IPA.

        Args:
            cert_path: Path to the certificate file.

        Returns:
            A dictionary of certificate attributes.

        Raises:
            ValueError: If the certificate is not found in IPA.
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
        """Generate a CSR and key using OpenSSL."""
        cmd = [
            "openssl",
            "req",
            "-newkey",
            f"rsa:{key_size}",
            "-nodes",
            "-keyout",
            key_path,
            "-out",
            csr_path,
            "-subj",
            subject,
        ]
        cmdline = " ".join(shlex.quote(p) for p in cmd)
        result = self.host.conn.run(cmdline, raise_on_error=False)
        if result.rc != 0:
            raise RuntimeError(f"OpenSSL CSR generation failed: {result.stderr}")

    def _get_cert_serial(self, cert_path: str) -> str:
        """Extract the certificate serial number using OpenSSL."""
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
        """Map a revocation reason string to its corresponding numeric code."""
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
        """Parse `ipa cert-show` output into a dictionary."""
        info = {}
        for line in (output or "").splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                info[key.strip()] = value.strip()
        return info
