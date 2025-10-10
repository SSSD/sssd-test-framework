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

    def _exec_adcli(
        self,
        subcommand: str,
        positional_args: list[str],
        *,
        domain: str,
        password: str,  # Required
        login_user: str,  # Required
        krb: bool,
        args: list[str] | None = None,
    ) -> ProcessResult:
        """Helper to execute adcli commands with common authentication logic."""
        if args is None:
            args = []
        base_cmd = ["adcli", subcommand]
        if krb:
            # Bug: Missing newline for kinit input
            self.host.conn.exec(["kinit", f"{login_user}@{domain.upper()}"], input=password)
            command_args = [*base_cmd, f"--domain={domain}", "-C", *args, *positional_args]
            # Hardcoded raise_on_error=False
            return self.host.conn.exec(command_args, raise_on_error=False)
        else:
            command_args = [
                *base_cmd,
                "--stdin-password",
                f"--domain={domain}",
                *args,
                "-U",
                login_user,
                *positional_args,
            ]
            # Hardcoded raise_on_error=False
            return self.host.conn.exec(command_args, input=password, raise_on_error=False)

    def info(self, *, domain: str, args: list[str] | None = None) -> ProcessResult:
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

        command = self.host.conn.exec(["adcli", "info", *args, domain], raise_on_error=False)

        return command

    def testjoin(
        self,
        *,
        domain: str,
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

        return self.host.conn.exec(["adcli", "testjoin", domain, *args], raise_on_error=False)

    def join(
        self,
        *,
        domain: str,
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

        command = self._exec_adcli(
            subcommand="join",
            positional_args=[],
            domain=domain,
            password=password,
            login_user=login_user,
            krb=krb,
            args=args,
        )

        return command

    def delete_computer(
        self,
        *,
        domain: str,
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

        command = self._exec_adcli(
            subcommand="delete-computer",
            positional_args=[],
            domain=domain,
            password=password,
            login_user=login_user,
            krb=krb,
            args=args,
        )
        return command

    def show_computer(
        self,
        *,
        domain: str,
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

        command = self._exec_adcli(
            subcommand="show-computer",
            positional_args=[],
            domain=domain,
            password=password,
            login_user=login_user,
            krb=krb,
            args=args,
        )

        return command

    def preset_computer(
        self,
        *,
        domain: str,
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

        command = self._exec_adcli(
            subcommand="preset-computer",
            positional_args=[],
            domain=domain,
            password=password,
            login_user=login_user,
            krb=krb,
            args=args,
        )
        return command

    def reset_computer(
        self,
        *,
        domain: str,
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

        command = self._exec_adcli(
            subcommand="reset-computer",
            positional_args=[],
            domain=domain,
            password=password,
            login_user=login_user,
            krb=krb,
            args=args,
        )
        return command

    def create_user(
        self,
        user,
        *,
        domain: str,
        password: str,
        args: list[str] | None = None,
        login_user: str,
        krb: bool = False,
    ) -> ProcessResult:
        """
        Create user.

        :param domain: Domain.
        :type domain: str
        :param user: User.
        :type user: str
        :param args: additional arguments, defaults to None
        :type args: list[str] | None, optional
        :param password: Password.
        :type password: str
        :param login_user: Authenticating User.
        :type login_user: str
        :param krb: Use Kerberos credentials, defaults to False
        :type krb: bool, optional
        :return: Result of called command.
        :rtype: ProcessResult
        """
        if args is None:
            args = []

        command = self._exec_adcli(
            subcommand="create-user",
            positional_args=[user],
            domain=domain,
            password=password,
            login_user=login_user,
            krb=krb,
            args=args,
        )
        return command

    def delete_user(
        self,
        user,
        *,
        domain: str,
        password: str,
        args: list[str] | None = None,
        login_user: str,
        krb: bool = False,
    ) -> ProcessResult:
        """
        Delete user.

        :param domain: Domain.
        :type domain: str
        :param user: User.
        :type user: str
        :param args: additional arguments, defaults to None
        :type args: list[str] | None, optional
        :param password: Password.
        :type password: str
        :param login_user: Authenticating User.
        :type login_user: str
        :param krb: Use Kerberos credentials, defaults to False
        :type krb: bool, optional
        :return: Result of called command.
        :rtype: ProcessResult
        """
        if args is None:
            args = []

        command = self._exec_adcli(
            subcommand="delete-user",
            positional_args=[user],
            domain=domain,
            password=password,
            login_user=login_user,
            krb=krb,
            args=args,
        )
        return command

    def delete_group(
        self,
        group,
        *,
        domain: str,
        password: str,
        args: list[str] | None = None,
        login_user: str,
        krb: bool = False,
    ) -> ProcessResult:
        """
        Delete group.

        :param domain: Domain.
        :type domain: str
        :param group: Group.
        :type group: str
        :param args: additional arguments, defaults to None
        :type args: list[str] | None, optional
        :param password: Password.
        :type password: str
        :param login_user: Authenticating User.
        :type login_user: str
        :param krb: Use Kerberos credentials, defaults to False
        :type krb: bool, optional
        :return: Result of called command.
        :rtype: ProcessResult
        """
        if args is None:
            args = []

        command = self._exec_adcli(
            subcommand="delete-group",
            positional_args=[group],
            domain=domain,
            password=password,
            login_user=login_user,
            krb=krb,
            args=args,
        )
        return command

    def create_group(
        self,
        group,
        *,
        domain: str,
        password: str,
        args: list[str] | None = None,
        login_user: str,
        krb: bool = False,
    ) -> ProcessResult:
        """
        Create group.

        :param domain: Domain.
        :type domain: str
        :param group: Group.
        :type group: str
        :param args: additional arguments, defaults to None
        :type args: list[str] | None, optional
        :param password: Password.
        :type password: str
        :param login_user: Authenticating User.
        :type login_user: str
        :param krb: Use Kerberos credentials, defaults to False
        :type krb: bool, optional
        :return: Result of called command.
        :rtype: ProcessResult
        """
        if args is None:
            args = []

        command = self._exec_adcli(
            subcommand="create-group",
            positional_args=[group],
            domain=domain,
            password=password,
            login_user=login_user,
            krb=krb,
            args=args,
        )

        return command

    def add_member(
        self,
        group,
        member,
        *,
        domain: str,
        password: str,
        args: list[str] | None = None,
        login_user: str,
        krb: bool = False,
    ) -> ProcessResult:
        """
        Add member.

        :param domain: Domain.
        :type domain: str
        :param group: Group.
        :type group: str
        :param member: member, user or computer.
        :type member: str
        :param args: additional arguments, defaults to None
        :type args: list[str] | None, optional
        :param password: Password.
        :type password: str
        :param login_user: Authenticating User.
        :type login_user: str
        :param krb: Use Kerberos credentials, defaults to False
        :type krb: bool, optional
        :return: Result of called command.
        :rtype: ProcessResult
        """
        if args is None:
            args = []

        command = self._exec_adcli(
            subcommand="add-member",
            positional_args=[group, member],
            domain=domain,
            password=password,
            login_user=login_user,
            krb=krb,
            args=args,
        )

        return command

    def remove_member(
        self,
        group,
        member,
        *,
        domain: str,
        password: str,
        args: list[str] | None = None,
        login_user: str,
        krb: bool = False,
    ) -> ProcessResult:
        """
        Remove member.

        :param domain: Domain.
        :type domain: str
        :param group: Group.
        :type group: str
        :param member: member, user or computer.
        :type member: str
        :param args: additional arguments, defaults to None
        :type args: list[str] | None, optional
        :param password: Password.
        :type password: str
        :param login_user: Authenticating User.
        :type login_user: str
        :param krb: Use Kerberos credentials, defaults to False
        :type krb: bool, optional
        :return: Result of called command.
        :rtype: ProcessResult
        """
        if args is None:
            args = []

        command = self._exec_adcli(
            subcommand="remove-member",
            positional_args=[group, member],
            domain=domain,
            password=password,
            login_user=login_user,
            krb=krb,
            args=args,
        )

        return command

    def create_msa(
        self,
        *,
        domain: str,
        password: str,
        args: list[str] | None = None,
        login_user: str,
        krb: bool = False,
    ) -> ProcessResult:
        """
        Create Managed Service Account.

        :param domain: Domain.
        :type domain: str
        :param args: Additional arguments, defaults to None
        :type args: list[str] | None, optional
        :param password: Password.
        :type password: str
        :param login_user: Authenticating User.
        :type login_user: str
        :param krb: Kerberos credentials, defaults to False
        :type krb: bool, optional
        :return: Result of called command.
        :rtype: ProcessResult
        """
        if args is None:
            args = []

        command = self._exec_adcli(
            subcommand="create-msa",
            positional_args=[],
            domain=domain,
            password=password,
            login_user=login_user,
            krb=krb,
            args=args,
        )

        return command

    def passwd_user(
        self,
        *,
        user: str,
        new_password: str,
        domain: str,
        login_user: str,
        password: str,
        args: list[str] | None = None,
    ) -> bool:
        """
        (Re)Set Password.

        :param user: User.
        :type user: str
        :param new_password: New password.
        :type new_password: str
        :param domain: Domain.
        :type domain: str
        :param login_user: Authenticating User.
        :type login_user: str
        :param password: Password of Authenticating user.
        :type password: str
        :param args: Additional arguments, defaults to None.
        :type args: list[str] | None, optional
        :return: True on success, False otherwise
        :rtype: bool
        """

        if args is None:
            args = []

        # The command needs to be interactive, so we use an expect script
        command_str = f"adcli passwd-user {user} --domain={domain} {' '.join(args)}"

        # Use password authentication for the admin user
        command_str += f" -U {login_user}"
        expect_script = f"""
            spawn {command_str}
            expect "Password for {login_user}@{domain.upper()}:"
            send -- "{password}\\r"
            expect "Password for {user}:"
            send -- "{new_password}\\r"
            expect eof
        """

        result = self.host.conn.expect(expect_script, raise_on_error=True)
        return result.rc == 0
