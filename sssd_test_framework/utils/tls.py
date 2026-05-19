"""TLS and certificate management utilities."""

from __future__ import annotations

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

    def trust_ca_certificate(
        self,
        certificate_content: str,
        certificate_name: str | None = None,
    ) -> ProcessResult:
        """
        Trust a CA certificate by installing it to system trust store.

        :param certificate_content: PEM-formatted certificate content.
        :type certificate_content: str
        :param certificate_name: Optional certificate filename (without extension).
        :type certificate_name: str | None
        :return: Result of update-ca-trust command.
        :rtype: ProcessResult
        """
        if certificate_name is None:
            certificate_name = "custom-ca"

        cert_path = f"/etc/pki/ca-trust/source/anchors/{certificate_name}.crt"

        # Write certificate to trust anchors
        self.host.conn.run(
            f"cat > {cert_path}",
            input=certificate_content,
        )

        # Update system trust store
        return self.host.conn.run("update-ca-trust")

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
        :return: Result of update-ca-trust command.
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
        Configure LDAP client TLS settings in /etc/openldap/ldap.conf.

        :param tls_reqcert: Certificate verification level (never, allow, try, demand, hard).
        :type tls_reqcert: str
        :param tls_cacertdir: Path to CA certificate directory.
        :type tls_cacertdir: str | None
        :param tls_cacert: Path to specific CA certificate file.
        :type tls_cacert: str | None
        """
        config_lines = [f"TLS_REQCERT {tls_reqcert}"]

        if tls_cacertdir:
            config_lines.append(f"TLS_CACERTDIR {tls_cacertdir}")

        if tls_cacert:
            config_lines.append(f"TLS_CACERT {tls_cacert}")

        config_content = "\n".join(config_lines) + "\n"
        self.host.conn.run(
            "cat > /etc/openldap/ldap.conf",
            input=config_content,
        )

    def disable_certificate_verification(self) -> None:
        """
        Disable TLS certificate verification (for testing only).

        .. warning::
            This is insecure and should only be used for development/testing.
        """
        self.configure_ldap_tls(tls_reqcert="never")
