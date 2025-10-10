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

        if krb:
            self.host.conn.exec(["kinit", f"{login_user}@{domain.upper()}"], input=password)
            command = self.host.conn.exec(["adcli", "join", "-C", *args, domain], raise_on_error=False)
        else:
            command = self.host.conn.exec(
                ["adcli", "join", "--stdin-password", f"--login-user={login_user}", *args, domain],
                input=password,
                raise_on_error=False,
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

        if krb:
            self.host.conn.exec(["kinit", f"{login_user}@{domain.upper()}"], input=password)
            command = self.host.conn.exec(
                [
                    "adcli",
                    "delete-computer",
                    "-C",
                    f"--domain={domain}",
                    *args,
                ],
                raise_on_error=False,
            )
        else:
            command = self.host.conn.exec(
                [
                    "adcli",
                    "delete-computer",
                    "--stdin-password",
                    f"--domain={domain}",
                    *args,
                ],
                input=password,
                raise_on_error=False,
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

        if krb:
            self.host.conn.exec(["kinit", f"{login_user}@{domain.upper()}"], input=password)
            command = self.host.conn.exec(
                ["adcli", "show-computer", f"--domain={domain}", "-C", *args], raise_on_error=False
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
                    *args,
                ],
                input=password,
                raise_on_error=False,
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

        if krb:
            self.host.conn.exec(["kinit", f"{login_user}@{domain.upper()}"], input=password)
            command = self.host.conn.exec(
                ["adcli", "preset-computer", f"--domain={domain}", "-C", *args], raise_on_error=False
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
                    *args,
                ],
                input=password,
                raise_on_error=False,
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

        if krb:
            self.host.conn.exec(["kinit", f"{login_user}@{domain.upper()}"], input=password)
            command = self.host.conn.exec(
                ["adcli", "reset-computer", f"--domain={domain}", "-C", *args], raise_on_error=False
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
                    *args,
                ],
                input=password,
                raise_on_error=False,
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
        if krb:
            self.host.conn.exec(["kinit", f"{login_user}@{domain.upper()}"], input=password)
            command = self.host.conn.exec(
                ["adcli", "create-user", user, f"--domain={domain}", "-C", *args], raise_on_error=False
            )
        else:
            command = self.host.conn.exec(
                [
                    "adcli",
                    "create-user",
                    user,
                    "--stdin-password",
                    f"--domain={domain}",
                    *args,
                    "-U",
                    login_user,
                ],
                input=password,
                raise_on_error=False,
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
        if krb:
            self.host.conn.exec(["kinit", f"{login_user}@{domain.upper()}"], input=password)
            command = self.host.conn.exec(
                ["adcli", "delete-user", user, f"--domain={domain}", "-C", *args], raise_on_error=False
            )
        else:
            command = self.host.conn.exec(
                [
                    "adcli",
                    "delete-user",
                    user,
                    "--stdin-password",
                    f"--domain={domain}",
                    *args,
                    "-U",
                    login_user,
                ],
                input=password,
                raise_on_error=False,
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
        if krb:
            self.host.conn.exec(["kinit", f"{login_user}@{domain.upper()}"], input=password)
            command = self.host.conn.exec(
                ["adcli", "delete-group", group, f"--domain={domain}", "-C", *args], raise_on_error=False
            )
        else:
            command = self.host.conn.exec(
                [
                    "adcli",
                    "delete-group",
                    group,
                    "--stdin-password",
                    f"--domain={domain}",
                    *args,
                    "-U",
                    login_user,
                ],
                input=password,
                raise_on_error=False,
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
        if krb:
            self.host.conn.exec(["kinit", f"{login_user}@{domain.upper()}"], input=password)
            command = self.host.conn.exec(
                ["adcli", "create-group", group, f"--domain={domain}", "-C", *args], raise_on_error=False
            )
        else:
            command = self.host.conn.exec(
                [
                    "adcli",
                    "create-group",
                    group,
                    "--stdin-password",
                    f"--domain={domain}",
                    *args,
                    "-U",
                    login_user,
                ],
                input=password,
                raise_on_error=False,
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

        if krb:
            self.host.conn.exec(["kinit", f"{login_user}@{domain.upper()}"], input=password)
            command = self.host.conn.exec(
                ["adcli", "add-member", f"--domain={domain}", "-C", *args, group, member], raise_on_error=False
            )
        else:
            command = self.host.conn.exec(
                [
                    "adcli",
                    "add-member",
                    "--stdin-password",
                    f"--domain={domain}",
                    *args,
                    "-U",
                    login_user,
                    group,
                    member,
                ],
                input=password,
                raise_on_error=False,
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

        if krb:
            self.host.conn.exec(["kinit", f"{login_user}@{domain.upper()}"], input=password)
            command = self.host.conn.exec(
                ["adcli", "remove-member", f"--domain={domain}", "-C", *args, group, member], raise_on_error=False
            )
        else:
            command = self.host.conn.exec(
                [
                    "adcli",
                    "remove-member",
                    "--stdin-password",
                    f"--domain={domain}",
                    *args,
                    "-U",
                    login_user,
                    group,
                    member,
                ],
                input=password,
                raise_on_error=False,
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

        if krb:
            self.host.conn.exec(["kinit", f"{login_user}@{domain.upper()}"], input=password)
            command = self.host.conn.exec(
                ["adcli", "create-msa", f"--domain={domain}", "-C", *args], raise_on_error=False
            )
        else:
            command = self.host.conn.exec(
                [
                    "adcli",
                    "create-msa",
                    "--stdin-password",
                    f"--domain={domain}",
                    *args,
                    "-U",
                    login_user,
                ],
                input=password,
                raise_on_error=False,
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
        (Re)Set password

        :param user: User.
        :type user: str
        :param new_password: New password.
        :type new_password: str
        :param domain:Domain.
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

        result =  self.host.conn.expect(expect_script, raise_on_error=True)
        return result.rc == 0
