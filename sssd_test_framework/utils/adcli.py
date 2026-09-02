"""Perform actions on Active Directory."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.conn import ProcessResult

if TYPE_CHECKING:
    from sssd_test_framework.roles.generic import GenericADProvider

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

    def _resolve_provider_params(
        self,
        *,
        provider: GenericADProvider | None = None,
        domain: str | None = None,
        login_user: str | None = None,
        password: str | None = None,
    ) -> tuple[str, str, str]:
        """
        Resolve domain, login_user, and password from either provider object or explicit parameters.

        :param provider: Provider object (optional)
        :type provider: GenericADProvider | None
        :param domain: Domain string (optional if provider given)
        :type domain: str | None
        :param login_user: Login user (optional if provider given)
        :type login_user: str | None
        :param password: Password (optional if provider given)
        :type password: str | None
        :return: Tuple of (domain, login_user, password)
        :rtype: tuple[str, str, str]
        :raises ValueError: If neither provider nor domain is provided, or if credentials are missing
        """
        if provider is not None:
            # Provider mode - use provider's attributes, allow overrides
            resolved_domain = domain if domain is not None else provider.domain
            resolved_user = login_user if login_user is not None else provider.host.adminuser  # type: ignore[attr-defined]
            resolved_password = password if password is not None else provider.host.adminpw  # type: ignore[attr-defined]
            return resolved_domain, resolved_user, resolved_password
        elif domain is not None:
            # Domain string mode - require explicit credentials
            if not login_user or not password:
                raise ValueError(
                    "When using domain string mode, both 'login_user' and 'password' are required. "
                    "Consider passing a 'provider' parameter instead."
                )
            return domain, login_user, password
        else:
            raise ValueError("Either 'provider' or 'domain' parameter must be provided.")

    def _exec_adcli(
        self,
        subcommand: str,
        positional_args: list[str],
        *,
        domain: str,
        password: str | None = None,
        login_user: str | None = None,
        krb: bool,
        args: list[str] | None = None,
    ) -> ProcessResult:
        """
        Helper to execute adcli commands with flexible authentication logic.

        If login_user and password are not provided, it assumes machine-based authentication
        (using the system keytab) regardless of the krb flag.
        """
        if args is None:
            args = []
        base_cmd = ["adcli", subcommand]

        # Machine Authentication (Host Keytab)
        if login_user is None and password is None:
            command_args = [*base_cmd, f"--domain={domain}", *args, *positional_args]
            return self.host.conn.exec(command_args, raise_on_error=False)

        # Validation: Enforce credentials for explicit authentication
        if not login_user or not password:
            raise ValueError("Both 'login_user' and 'password' are required for explicit user authentication.")

        # Kerberos User Authentication
        if krb:
            self.host.conn.exec(["kinit", f"{login_user}@{domain.upper()}"], input=password)
            command_args = [*base_cmd, f"--domain={domain}", "-C", *args, *positional_args]
            return self.host.conn.exec(command_args, raise_on_error=False)

        # Explicit User/Password Authentication (Standard Admin Task)
        command_args = [
            *base_cmd,
            "--stdin-password",
            f"--domain={domain}",
            *args,
            "-U",
            login_user,
            *positional_args,
        ]
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

    def update(
        self,
        *,
        domain: str,
        password: str | None = None,
        login_user: str | None = None,
        args: list[str] | None = None,
    ) -> ProcessResult:
        """
        Update a computer account's password, and other attributes.

        Can be run in two modes:

        1. **Machine Auth:** (Default) Call without `password` or `login_user`.
           Uses the machine's local keytab (self-update).
        2. **User Auth:** Call with `password` and `login_user`.
           Uses admin credentials via Kerberos to force an update.

        :param domain: Domain.
        :type domain: str
        :param password: Password (optional, for Admin auth).
        :type password: str | None
        :param login_user: Authenticating User (optional, for Admin auth).
        :type login_user: str | None
        :param args: Additional arguments, defaults to None
        :type args: list[str] | None, optional
        :return: Result of called command.
        :rtype: ProcessResult
        """
        if args is None:
            args = []

        command = self._exec_adcli(
            subcommand="update",
            positional_args=[],
            domain=domain,
            password=password,
            login_user=login_user,
            krb=True,
            args=args,
        )
        return command

    def join(
        self,
        provider: GenericADProvider | None = None,
        *,
        domain: str | None = None,
        login_user: str | None = None,
        password: str | None = None,
        krb: bool = False,
        args: list[str] | None = None,
        # Convenience parameters for common adcli options
        host_keytab: str | None = None,
        computer_name: str | None = None,
        domain_ou: str | None = None,
        verbose: bool = False,
        show_details: bool = False,
    ) -> ProcessResult:
        """
        Create a computer account.

        Can be called with either a Provider object (recommended) or a domain string.

        **Provider mode** (recommended):
        Uses provider's domain and admin credentials by default. Override with optional parameters.

        **Domain string mode** (backward compatibility):
        Requires explicit login_user and password.

        :param provider: Provider object (optional, recommended)
        :type provider: GenericADProvider | None
        :param domain: Domain string (optional if provider given, required otherwise)
        :type domain: str | None
        :param login_user: Authenticating user (optional if provider given), defaults to provider.host.adminuser
        :type login_user: str | None
        :param password: Password (optional if provider given), defaults to provider.host.adminpw
        :type password: str | None
        :param krb: Use Kerberos credentials, defaults to False
        :type krb: bool
        :param args: Additional custom arguments, defaults to None
        :type args: list[str] | None
        :param host_keytab: Custom keytab location (--host-keytab)
        :type host_keytab: str | None
        :param computer_name: Custom computer name (--computer-name)
        :type computer_name: str | None
        :param domain_ou: Organizational Unit (--domain-ou)
        :type domain_ou: str | None
        :param verbose: Enable verbose output (--verbose)
        :type verbose: bool
        :param show_details: Show details (--show-details)
        :type show_details: bool
        :return: Result of called command.
        :rtype: ProcessResult

        .. code-block:: python
            :caption: Provider mode example

            # Simple join using provider defaults (positional)
            client.adcli.join(provider)

            # Join with custom keytab (positional provider)
            client.adcli.join(provider, host_keytab="/tmp/custom.keytab")

            # Override credentials (keyword provider also works)
            client.adcli.join(provider=provider, login_user="special-admin", password="Secret123")

        .. code-block:: python
            :caption: Domain string mode (backward compatibility)

            client.adcli.join(domain="ad.test", login_user="admin", password="Secret123")
        """
        # Resolve domain, login_user, and password
        resolved_domain, resolved_user, resolved_password = self._resolve_provider_params(
            provider=provider, domain=domain, login_user=login_user, password=password
        )

        # Build args list from convenience parameters
        if args is None:
            args = []

        extra_args = []
        if verbose:
            extra_args.append("--verbose")
        if show_details:
            extra_args.append("--show-details")
        if host_keytab:
            extra_args.append(f"--host-keytab={host_keytab}")
        if computer_name:
            extra_args.append(f"--computer-name={computer_name}")
        if domain_ou:
            extra_args.append(f"--domain-ou={domain_ou}")

        # Combine custom args with convenience args
        all_args = [*extra_args, *args]

        command = self._exec_adcli(
            subcommand="join",
            positional_args=[],
            domain=resolved_domain,
            password=resolved_password,
            login_user=resolved_user,
            krb=krb,
            args=all_args,
        )

        return command

    def delete_computer(
        self,
        provider: GenericADProvider | None = None,
        *,
        domain: str | None = None,
        login_user: str | None = None,
        password: str | None = None,
        krb: bool = False,
        args: list[str] | None = None,
    ) -> ProcessResult:
        """
        Delete computer account.

        Can be called with either a Provider object (recommended) or a domain string.

        :param provider: Provider object (optional, recommended)
        :type provider: GenericADProvider | None
        :param domain: Domain string (optional if provider given, required otherwise)
        :type domain: str | None
        :param login_user: Authenticating user (optional if provider given), defaults to provider.host.adminuser
        :type login_user: str | None
        :param password: Password (optional if provider given), defaults to provider.host.adminpw
        :type password: str | None
        :param krb: Use Kerberos credentials, defaults to False
        :type krb: bool
        :param args: Additional arguments, defaults to None
        :type args: list[str] | None
        :return: Result of called command.
        :rtype: ProcessResult
        """
        # Resolve domain, login_user, and password
        resolved_domain, resolved_user, resolved_password = self._resolve_provider_params(
            provider=provider, domain=domain, login_user=login_user, password=password
        )

        if args is None:
            args = []

        command = self._exec_adcli(
            subcommand="delete-computer",
            positional_args=[],
            domain=resolved_domain,
            password=resolved_password,
            login_user=resolved_user,
            krb=krb,
            args=args,
        )
        return command

    def show_computer(
        self,
        provider: GenericADProvider | None = None,
        *,
        domain: str | None = None,
        login_user: str | None = None,
        password: str | None = None,
        krb: bool = False,
        args: list[str] | None = None,
    ) -> ProcessResult:
        """
        Show computer account information.

        Can be called with either a Provider object (recommended) or a domain string.

        :param provider: Provider object (optional, recommended)
        :type provider: GenericADProvider | None
        :param domain: Domain string (optional if provider given, required otherwise)
        :type domain: str | None
        :param login_user: Authenticating user (optional if provider given), defaults to provider.host.adminuser
        :type login_user: str | None
        :param password: Password (optional if provider given), defaults to provider.host.adminpw
        :type password: str | None
        :param krb: Use Kerberos credentials, defaults to False
        :type krb: bool
        :param args: Additional arguments, defaults to None
        :type args: list[str] | None
        :return: Result of called command.
        :rtype: ProcessResult
        """
        # Resolve domain, login_user, and password
        resolved_domain, resolved_user, resolved_password = self._resolve_provider_params(
            provider=provider, domain=domain, login_user=login_user, password=password
        )

        if args is None:
            args = []

        command = self._exec_adcli(
            subcommand="show-computer",
            positional_args=[],
            domain=resolved_domain,
            password=resolved_password,
            login_user=resolved_user,
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
