"""Manage realm operations."""

from __future__ import annotations

from pytest_mh import MultihostHost, MultihostUtility
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
            r = client.realm.discover(["--use-ldaps"])
            assert provider.host.domain in r.stdout, "realm failed to discover domain info!"

    """

    def discover(self, domain: str | None = None, *, args: list[str] | None = None) -> ProcessResult:
        """
        Discover a realm and it's capabilities.

        :param domain: domain, defaults to None
        :type domain: str, optional
        :param args: Additional arguments, defaults to None
        :type args: list[str] | None, optional
        """
        if args is None:
            args = []
        if domain is None:
            domain = ""

        return self.host.conn.exec(["realm", "discover", domain, *args])

    def leave(
        self,
        domain: str = "",
        *,
        args: list[str] | None = None,
        password: str,
        user: str,
        krb: bool = False,
    ) -> ProcessResult:
        """
        Deconfigure and remove a client from realm.

        :param domain: domain to leave.
        :type domain: str,
        :param args: Additional arguments, defaults to None.
        :type args: list[str] | None, optional
        :param password: Password to run the operation.
        :type password: str
        :param user: Authenticating user.
        :type user: str
        :param krb: Enable kerberos authentication, defaults to False.
        :type krb: bool
        """
        if args is None:
            args = []

        if krb:
            self.host.conn.exec(["kinit", user], input=password)
            result = self.host.conn.exec(["realm", "leave", "--verbose", *args, domain])
        else:
            result = self.host.conn.exec(["realm", "leave", "--verbose", *args, "-U", user, domain], input=password)

        return result

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

        :param domain: Domain to join.
        :type domain: str
        :param args: Additional arguments, defaults to None
        :type args: list[str] | None, optional
        :param password: Password to run the operation.
        :type password: str
        :param user: Authenticating user.
        :type user: str
        :param krb: Enable kerberos authentication, defaults to False
        :type krb: bool
        """
        if args is None:
            args = []

        if krb:
            self.host.conn.exec(["kinit", user], input=password)
            result = self.host.conn.exec(["realm", "join", "--verbose", *args, domain])
        else:
            result = self.host.conn.exec(["realm", "join", "--verbose", *args, "-U", user, domain], input=password)

        return result

    def list(self, *, args: list[str] | None = None) -> ProcessResult:
        """
        List discovered, and configured realms.

        :param args: Additional arguments, defaults to None
        :type args: list[str] | None, optional
        """
        if args is None:
            args = []

        return self.host.conn.exec(["realm", "list", "--verbose", *args])
