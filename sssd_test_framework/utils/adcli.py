"""Perform actions on Active Directory."""

from __future__ import annotations

from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.conn import ProcessResult

__all__ = [
    "AdcliUtils",
]


class AdcliUtils(MultihostUtility[MultihostHost]):
    """
    Interface to adcli utility.

    .. code-block:: python
        :caption: Example usage

        @pytest.mark.topology(KnownTopologyGroup.AnyAD)
        def test_adcli_join(client: Client, provider: GenericADProvider):
            cred = provider.host.adminpw
            r = client.adcli.join(provider.host.domain, ["--domain-controller", provider.host.hostname], password=cred)
            assert provider.host.domain in r.stdout, "adcli failed to join the client"

    This utility will not revert any changes. It relies on AD host topology
    for clean up.
    """

    def info(self, domain: str, *, args: list[str] | None = None) -> ProcessResult:
        """
        Discover AD domain.

        :param domain: domain.
        :type domain: str,
        :param args: additional arguments, defaults to None
        :type args: list[str] | None, optional
        """
        if args is None:
            args = []

        return self.host.conn.exec(["adcli", "info", *args, "--verbose", f"{domain}"])

    def testjoin(self, *, args: list[str] | None = None) -> ProcessResult:
        """
        Validate join.

        :param args: additional arguments, defaults to None
        :type args: list[str] | None, optional
        """
        if args is None:
            args = []

        return self.host.conn.exec(["adcli", *args, "--verbose", "testjoin"])

    def delete_computer(
        self,
        host: str,
        *,
        args: list[str] | None = None,
        password: str | None = None,
    ) -> ProcessResult:
        """
        Delete computer account.

        :param host: client hostname
        :type host: str | None,
        :param args: additional arguments, defaults to None.
        :type args: list[str] | None, optional
        :param password: password, defaults to None.
        :type password: str | None, optional
        """
        if args is None:
            args = []

        return self.host.conn.exec(["adcli", "delete-computer", *args, host], input=password)

    def join(
        self,
        domain: str,
        *,
        args: list[str] | None = None,
        password: str | None = None,
        user: str | None = None,
        krb: bool | None = False,
        prompt_password: bool | None = False,
        stdin: bool | None = False,
    ) -> ProcessResult:
        """
        Create a computer account.

        :param domain: domain.
        :type domain: str,
        :param args: additional arguments, defaults to None
        :type args: list[str] | None, optional
        :param password: password, defaults to None
        :type password: str | None, optional
        :param user: Authenticating User, defaults to None
        :type user: str | None, optional
        :param krb: Use kerberos credentials.
        :type krb: bool | False, optional
        """
        if args is None:
            args = []

        if krb:
            self.host.conn.exec(["kinit", user], input=password)
            command = self.host.conn.exec(["adcli", "join", "--verbose", "--login-ccache", *args, domain])
        elif prompt_password:
            command = self.host.conn.exec(["adcli", "join", "-W", "--verbose", *args, domain], input=password)
        elif stdin:
            command = self.host.conn.exec(
                ["echo", password, "|", "adcli", "join", "--stdin-password", "--verbose", *args, domain]
            )

        return command

    def create_user(
        self,
        username: str,
        domain: str | None = None,
        *,
        args: list[str] | None = None,
    ) -> ProcessResult:
        """
        Create user.

        :param user: Username.
        :type user: str
        :param domain: Domain.
        :type domain: str,
        :param args: additional arguments, defaults to None
        :type args: list[str] | None, optional
        :param password: Password.
        :type password: str | None, optional
        :param krb: Use kerberos credentials.
        :type krb: bool | False, optional
        """
        if args is None:
            args = []

        command = self.host.conn.exec(["adcli", "create-user", username, domain, "--verbose", *args])

        return command

    def delete_user(
        self,
        username: str,
        domain: str | None = None,
        *,
        args: list[str] | None = None,
    ) -> ProcessResult:
        """
        Delete user.

        :param username: Username.
        :type username: str,
        :param domain: Domain.
        :type domain: str,
        :param args: additional arguments, defaults to None
        :type args: list[str] | None, optional
        """
        if args is None:
            args = []

        command = self.host.conn.exec(["adcli", "create-user", username, domain, "--verbose", *args])

        return command
