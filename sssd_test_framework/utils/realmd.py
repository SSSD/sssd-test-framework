"""Manage realm operations."""

from __future__ import annotations

from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.cli import CLIBuilder, CLIBuilderArgs
from pytest_mh.conn import ProcessResult

__all__ = [
    "RealmUtils",
]


class RealmUtils(MultihostUtility[MultihostHost]):
    """
    Interface to the realm utility.

    .. code-block:: python
        :caption: Example usage

        @pytest.mark.topology(KnownTopology.AD)
        def test_realm_discover(client: Client, provider: ADProvider):
            r = client.realm.discover(provider.host.domain, args=["--use-ldaps"])
            assert provider.host.domain in r.stdout, "realm failed to discover domain info!"

    """

    def __init__(self, host: MultihostHost) -> None:
        """
        Initialize the RealmUtils.

        :param host: The multihost host instance.
        :type host: MultihostHost
        """
        super().__init__(host)
        self.cli: CLIBuilder = self.host.cli
        """Command line builder."""

    def _exec_realm(
        self,
        subcommand: str,
        *,
        password: str | None = None,
        user: str | None = None,
        domain: str | None = None,
        args: list[str] | None = None,
        krb: bool = False,
    ) -> ProcessResult:
        """
        Execute realm commands.

        :param subcommand: Subcommand (e.g., "join", "leave").
        :type subcommand: str
        :param password: Password, defaults to None.
        :type password: str
        :param user: User, defaults to None.
        :type user: str
        :param domain: domain.
        :type domain: str, optional
        :param args: Additional arguments.
        :type args: list[str] | None, optional
        :param krb: Use Kerberos.
        :type krb: bool
        :return: ProcessResult
        :rtype: ProcessResult
        """
        if args is None:
            args = []

        # Base command
        command = ["realm", subcommand, "--verbose", *args]

        if krb:
            c = self.host.conn.exec(["kinit", f"{user}"], input=password)
            if c.rc == 0 and domain:
                command.append(domain)
            return self.host.conn.exec(command)
        else:
            # execute with password as input
            if user:
                command.extend(["-U", user])
            if domain:
                command.append(domain)
            return self.host.conn.exec(command, input=password)

    def discover(self, domain: str | None = None, *, args: list[str] | None = None) -> ProcessResult:
        """
        Discover a realm and it's capabilities.

        :param domain: domain, defaults to None
        :type domain: str, optional
        :param args: Additional arguments, defaults to None
        :type args: list[str] | None, optional
        :return: Result of called command.
        :rtype: ProcessResult
        """
        if args is None:
            args = []
        if domain is None:
            domain = ""

        return self.host.conn.exec(["realm", "discover", domain, *args])

    def leave(
        self,
        domain: str | None = None,
        *,
        args: list[str] | None = None,
        password: str,
        user: str,
        krb: bool = False,
    ) -> ProcessResult:
        """
        Deconfigure and remove a client from realm.

        :param domain: domain.
        :type domain: str
        :param args: Additional arguments, defaults to None.
        :type args: list[str] | None, optional
        :param password: Password to run the operation.
        :type password: str
        :param user: Authenticating user.
        :type user: str
        :param krb: kerberos authentication, defaults to False.
        :type krb: bool
        :return: Result of called command.
        :rtype: ProcessResult
        """
        return self._exec_realm(
            "leave",
            domain=domain,  # Pass None to helper if empty string
            args=args,
            password=password,
            user=user,
            krb=krb,
        )

    def join(
        self,
        domain: str,
        *,
        args: list[str] | None = None,
        password: str,
        user: str,
        krb: bool = False,
    ) -> ProcessResult:
        """
        Join and configure a client to realm.

        :param domain: Domain.
        :type domain: str
        :param args: Additional arguments, defaults to None
        :type args: list[str] | None, optional
        :param password: Password.
        :type password: str
        :param user: Authenticating user.
        :type user: str
        :param krb: Kerberos authentication, defaults to False
        :type krb: bool
        :return: Result of called command.
        :rtype: ProcessResult
        """
        return self._exec_realm(
            "join",
            domain=domain,
            args=args,
            password=password,
            user=user,
            krb=krb,
        )

    def renew(
        self,
        domain: str,
        *,
        args: list[str] | None = None,
    ) -> ProcessResult:
        """
        Renew host keytab.

        :param domain: domain.
        :type domain: str
        :param args: Additional arguments, defaults to None
        :type args: list[str] | None, optional
        :return: Result of called command.
        :rtype: ProcessResult
        """
        if args is None:
            args = []

        command = ["realm", "renew", domain, "--verbose", *args]
        return self.host.conn.exec(command)

    def permit(self, user: str, *, withdraw: bool = False, args: list[str] | None = None) -> ProcessResult:
        """
        Permit users log in.

        :param user: User to permit.
        :type user: str
        :param withdraw: Withdraw permission, defaults to False
        :type withdraw: bool, optional
        :param args: Additional arguments, defaults to None
        :type args: list[str] | None, optional
        :return: Result of called command.
        :rtype: ProcessResult
        """
        cli_args: CLIBuilderArgs = {"withdraw": (self.cli.option.SWITCH, withdraw)}
        if args is None:
            args = []

        return self.host.conn.exec(["realm", "permit", *self.cli.args(cli_args), *args, user])

    def deny(self, user: str, *, args: list[str] | None = None) -> ProcessResult:
        """
        Deny users log in.

        :param user: User.
        :type user: str
        :param args: Additional arguments, defaults to None
        :type args: list[str] | None, optional
        :return: Result of called command.
        :rtype: ProcessResult
        """
        return self.permit(user, withdraw=True, args=args)

    def list(self, *, args: list[str] | None = None) -> ProcessResult:
        """
        List discovered, and configured realms.

        :param args: Additional arguments, defaults to None
        :type args: list[str] | None, optional
        :return: Result of called command.
        :rtype: ProcessResult
        """
        if args is None:
            args = []

        return self.host.conn.exec(["realm", "list", "--verbose", *args])
