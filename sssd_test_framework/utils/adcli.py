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
            assert provider.host.domain in r.stdout, "adcli failed to join the client!"

    .. note::

       This utility will not revert any changes. It relies on AD host topology for clean up.
       For methods requiring an authentication, --stdin-password(-W) is a default. Setting krb=True will enable
       kerberos based authentication.
    """

    def info(self, domain: str, *, args: list[str] | None = None) -> ProcessResult:
        """
        Discover AD domain.

        :param domain: domain.
        :type domain: str
        :param args: additional arguments, defaults to None
        :type args: list[str] | None, optional
        :return: Result of called command.
        :rtype: ProcessResult
        """
        if args is None:
            args = []

        command = self.host.conn.exec(["adcli", "info", *args, "--verbose", f"{domain}"], raise_on_error=False)

        return command

    def testjoin(
        self,
        domain: str,
        *,
        args: list[str] | None = None,
    ) -> ProcessResult:
        """
        Validate join.

        :param domain: Domain.
        :type domain: str
        :param args: Additional arguments, defaults to None
        :type args: list[str] | None, optional
        :return: Result of called command.
        :rtype: ProcessResult
        """
        if args is None:
            args = []

        return self.host.conn.exec(["adcli", "testjoin", "--verbose", domain, *args], raise_on_error=False)

    def join(
        self,
        domain: str,
        *,
        args: list[str] | None = None,
        password: str,
        login_user: str,
        krb: bool = False,
    ) -> ProcessResult:
        """
        Create a computer account.

        :param domain: Domain.
        :type domain: str
        :param args: Additional arguments, defaults to None
        :type args: list[str] | None, optional
        :param password: Password
        :type password: str
        :param login_user: Authenticating User
        :type login_user: str
        :param krb: Use Kerberos credentials, defaults to False
        :type krb: bool, optional
        :return: Result of called command.
        :rtype: ProcessResult
        """
        if args is None:
            args = []

        if krb:
            self.host.conn.exec(["kinit", f"{login_user}@{domain.upper()}"], input=password)
            command = self.host.conn.exec(["adcli", "join", "--verbose", "-C", *args, domain], raise_on_error=False)
        else:
            command = self.host.conn.exec(
                ["adcli", "join", "--stdin-password", "--verbose", f"--login-user={login_user}", *args, domain],
                input=password,
                raise_on_error=False,
            )

        return command

    def delete_computer(
        self,
        domain: str,
        *,
        args: list[str] | None = None,
        password: str,
        login_user: str,
        krb: bool = False,
    ) -> ProcessResult:
        """
        Delete computer account.

        :param domain: Domain.
        :type domain: str
        :param args: additional arguments, defaults to None.
        :type args: list[str] | None, optional
        :param password: Password
        :type password: str
        :param login_user: Authenticating User
        :type login_user: str
        :param krb: Use Kerberos credentials, defaults to False
        :type krb: bool, optional
        :return: Result of called command.
        :rtype: ProcessResult
        """
        if args is None:
            args = []

        if krb:
            self.host.conn.exec(["kinit", f"{login_user}@{domain.upper()}"], input=password)
            command = self.host.conn.exec(["adcli", "delete-computer", "--verbose", "-C", *args], raise_on_error=False)
        else:
            command = self.host.conn.exec(
                ["adcli", "delete-computer", "--stdin-password", "--verbose", *args],
                input=password,
                raise_on_error=False,
            )

        return command

    def show_computer(
        self,
        domain: str,
        *,
        password: str,
        args: list[str] | None = None,
        login_user: str,
        krb: bool = False,
    ) -> ProcessResult:
        """
        Show computer.

        :param domain: Domain.
        :type domain: str
        :param args: additional arguments, defaults to None
        :type args: list[str] | None, optional
        :param password: Password
        :type password: str
        :param login_user: Authenticating User
        :type login_user: str
        :param krb: Use Kerberos credentials, defaults to False
        :type krb: bool, optional
        :return: Result of called command.
        :rtype: ProcessResult
        """
        if args is None:
            args = []

        if krb:
            self.host.conn.exec(["kinit", f"{login_user}@{domain.upper()}"], input=password)
            command = self.host.conn.exec(
                ["adcli", "show-computer", f"--domain={domain}", "--verbose", "-C", *args], raise_on_error=False
            )
        else:
            command = self.host.conn.exec(
                [
                    "adcli",
                    "show-computer",
                    "--stdin-password",
                    "-U",
                    login_user,
                    f"--domain={domain}",
                    "--verbose",
                    *args,
                ],
                input=password,
                raise_on_error=False,
            )
        return command

    def preset_computer(
        self,
        domain: str,
        *,
        password: str,
        args: list[str] | None = None,
        login_user: str,
        krb: bool = False,
    ) -> ProcessResult:
        """
        Preset computer.

        :param domain: Domain.
        :type domain: str
        :param args: additional arguments, defaults to None
        :type args: list[str] | None, optional
        :param password: Password
        :type password: str
        :param login_user: Authenticating User
        :type login_user: str
        :param krb: Use Kerberos credentials, defaults to False
        :type krb: bool, optional
        :return: Result of called command.
        :rtype: ProcessResult
        """
        if args is None:
            args = []

        if krb:
            self.host.conn.exec(["kinit", f"{login_user}@{domain.upper()}"], input=password)
            command = self.host.conn.exec(
                ["adcli", "preset-computer", f"--domain={domain}", "--verbose", "-C", *args], raise_on_error=False
            )
        else:
            command = self.host.conn.exec(
                [
                    "adcli",
                    "preset-computer",
                    "--stdin-password",
                    "-U",
                    login_user,
                    f"--domain={domain}",
                    "--verbose",
                    *args,
                ],
                input=password,
                raise_on_error=False,
            )
        return command

    def reset_computer(
        self,
        domain: str,
        *,
        password: str,
        args: list[str] | None = None,
        login_user: str,
        krb: bool = False,
    ) -> ProcessResult:
        """
        Reset computer.

        :param domain: Domain.
        :type domain: str
        :param args: additional arguments, defaults to None
        :type args: list[str] | None, optional
        :param password: Password
        :type password: str
        :param login_user: Authenticating User
        :type login_user: str
        :param krb: Use Kerberos credentials, defaults to False
        :type krb: bool, optional
        :return: Result of called command.
        :rtype: ProcessResult
        """
        if args is None:
            args = []

        if krb:
            self.host.conn.exec(["kinit", f"{login_user}@{domain.upper()}"], input=password)
            command = self.host.conn.exec(
                ["adcli", "reset-computer", f"--domain={domain}", "--verbose", "-C", *args], raise_on_error=False
            )
        else:
            command = self.host.conn.exec(
                [
                    "adcli",
                    "reset-computer",
                    "--stdin-password",
                    "-U",
                    login_user,
                    f"--domain={domain}",
                    "--verbose",
                    *args,
                ],
                input=password,
                raise_on_error=False,
            )
        return command
