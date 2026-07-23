"""TLS and certificate management utilities."""

from __future__ import annotations

import shlex

from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.conn import ProcessResult

__all__ = [
    "TLSUtils",
]


class TLSUtils(MultihostUtility[MultihostHost]):
    """
    Interface for TLS/SSL certificate operations.

    .. code-block:: python
        :caption: Example usage

        @pytest.mark.topology(KnownTopology.AD)
        def test_ldaps(client: Client, ad: AD):
            # Export and trust AD's root CA certificate
            ca_cert = ad.host.export_root_ca_certificate()
            client.tls.trust_ca_certificate(ca_cert, "ad-root-ca")

            # Now LDAPS operations work
            r = client.adcli.join(
                domain=ad.host.domain,
                login_user=ad.host.adminuser,
                password=ad.host.adminpw,
                args=["--use-ldaps"]
            )
            assert r.rc == 0
    """

    def _detect_ca_trust_system(self) -> tuple[str, str, str]:
        """
        Detect the CA trust system (RHEL vs Debian-based).

        :return: Tuple of (cert_dir, update_command, config_file)
        :rtype: tuple[str, str, str]
        """
        # Check for RHEL/Fedora CA trust system
        result = self.host.conn.run("test -d /etc/pki/ca-trust/source/anchors", raise_on_error=False)
        if result.rc == 0:
            return (
                "/etc/pki/ca-trust/source/anchors",
                "update-ca-trust",
                "/etc/openldap/ldap.conf",
            )

        # Check for Debian/Ubuntu CA trust system
        result = self.host.conn.run("test -d /usr/local/share/ca-certificates", raise_on_error=False)
        if result.rc == 0:
            return (
                "/usr/local/share/ca-certificates",
                "update-ca-certificates",
                "/etc/ldap/ldap.conf",
            )

        # Fallback to RHEL paths
        return (
            "/etc/pki/ca-trust/source/anchors",
            "update-ca-trust",
            "/etc/openldap/ldap.conf",
        )

    def trust_ca_certificate(
        self,
        certificate_content: str,
        certificate_name: str | None = None,
    ) -> ProcessResult:
        """
        Trust a CA certificate by installing it to system trust store.

        Automatically detects the distribution and uses appropriate paths:
        - RHEL/Fedora: /etc/pki/ca-trust/source/anchors/ + update-ca-trust
        - Debian/Ubuntu: /usr/local/share/ca-certificates/ + update-ca-certificates

        :param certificate_content: PEM-formatted certificate content.
        :type certificate_content: str
        :param certificate_name: Optional certificate filename (without extension).
        :type certificate_name: str | None
        :return: Result of update-ca-trust/update-ca-certificates command.
        :rtype: ProcessResult
        """
        if certificate_name is None:
            certificate_name = "custom-ca"

        # Detect CA trust system
        cert_dir, update_cmd, _ = self._detect_ca_trust_system()

        # Build certificate path with proper quoting
        cert_path = f"{cert_dir}/{certificate_name}.crt"
        quoted_path = shlex.quote(cert_path)

        # Write certificate to trust anchors
        self.host.conn.run(
            f"cat > {quoted_path}",
            input=certificate_content,
        )

        # Update system trust store
        return self.host.conn.run(update_cmd)

    def trust_ca_certificate_file(
        self,
        certificate_path: str,
        certificate_name: str | None = None,
    ) -> ProcessResult:
        """
        Trust a CA certificate from file path.

        :param certificate_path: Path to certificate file on local machine.
        :type certificate_path: str
        :param certificate_name: Optional certificate filename (without extension).
        :type certificate_name: str | None
        :return: Result of update-ca-trust/update-ca-certificates command.
        :rtype: ProcessResult
        """
        with open(certificate_path) as f:
            cert_content = f.read()

        return self.trust_ca_certificate(cert_content, certificate_name)

    def configure_ldap_tls(
        self,
        *,
        tls_reqcert: str = "demand",
        tls_cacertdir: str | None = None,
        tls_cacert: str | None = None,
    ) -> None:
        """
        Configure LDAP client TLS settings in /etc/openldap/ldap.conf or /etc/ldap/ldap.conf.

        This method non-destructively updates or appends TLS settings to the LDAP
        configuration file. Existing settings are preserved.

        :param tls_reqcert: Certificate verification level (never, allow, try, demand, hard).
        :type tls_reqcert: str
        :param tls_cacertdir: Path to CA certificate directory.
        :type tls_cacertdir: str | None
        :param tls_cacert: Path to specific CA certificate file.
        :type tls_cacert: str | None
        """
        # Detect distribution-specific LDAP config path
        _, _, ldap_conf = self._detect_ca_trust_system()
        quoted_conf = shlex.quote(ldap_conf)

        # Create config file if it doesn't exist
        self.host.conn.run(f"touch {quoted_conf}")

        # Update or append TLS_REQCERT
        self.host.conn.run(
            f"grep -q '^TLS_REQCERT' {quoted_conf} && "
            f"sed -i 's/^TLS_REQCERT.*/TLS_REQCERT {tls_reqcert}/' {quoted_conf} || "
            f"echo 'TLS_REQCERT {tls_reqcert}' >> {quoted_conf}"
        )

        # Update or append TLS_CACERTDIR if specified
        if tls_cacertdir:
            self.host.conn.run(
                f"grep -q '^TLS_CACERTDIR' {quoted_conf} && "
                f"sed -i 's|^TLS_CACERTDIR.*|TLS_CACERTDIR {tls_cacertdir}|' {quoted_conf} || "
                f"echo 'TLS_CACERTDIR {tls_cacertdir}' >> {quoted_conf}"
            )

        # Update or append TLS_CACERT if specified
        if tls_cacert:
            self.host.conn.run(
                f"grep -q '^TLS_CACERT' {quoted_conf} && "
                f"sed -i 's|^TLS_CACERT.*|TLS_CACERT {tls_cacert}|' {quoted_conf} || "
                f"echo 'TLS_CACERT {tls_cacert}' >> {quoted_conf}"
            )

    def disable_certificate_verification(self) -> None:
        """
        Disable TLS certificate verification (for testing only).

        .. warning::
            This is insecure and should only be used for development/testing.
        """
        self.configure_ldap_tls(tls_reqcert="never")
