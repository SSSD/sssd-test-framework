"""Manage enrollment in realms."""

from __future__ import annotations

from typing import Any

from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.conn import ProcessResult

__all__ = [
    "RealmdUtils",
]


class RealmdUtils(MultihostUtility[MultihostHost]):
    """
    Call commands from realmd
    """

    def discover(self, domain: str, args: list[Any] | None = None) -> ProcessResult:
        """
        Call ``realm discover``  with given arguments.

        :param domain: Discover information about domains
        :type domain: str,
        :param args: additional arguments to the discover operation, defaults to None
        :type args: list[Any] | None, optional
        """
        if args is None:
            args = []

        return self.host.conn.exec(["realm", "discover", *args])

    def leave(self, args: list[Any] | None = None) -> ProcessResult:
        """
        Call ``realm leave`` with given arguments.

        :param args: additional arguments to pass to the leave operation, defaults to None
        :type args: list[Any] | None, optional
        """
        if args is None:
            args = []

        return self.host.conn.exec(["realm", "leave", *args])

    def join(
        self,
        domain: str,
        *,
        args: list[Any] | None = None,
        password: str | None = None,
        user: str | None = None,
        krb: bool = False,
    ) -> ProcessResult:
        """
        Call ``realm join`` with given arguments.

        :param domain: domain to join
        :type domain: str,
        :param args: additional arguments to pass to the join operation, defaults to None
        :type args: list[Any] | None, optional
        :param password: user-credentials to run the operation
        :type password: str,
        :param krb: to enable kerberos authentication, defaults to False
        :type krb: bool
        """
        if args is None:
            args = []

        if krb is True:
            self.host.conn.exec(["kinit", user], input=password)
            return self.host.conn.exec(["realm", "join", "--verbose", *args, domain])
        else:
            return self.host.conn.exec(["realm", "join", "--verbose", *args, "-U", user, domain], input=password)

    def rlist(self, args: list[Any] | None = None) -> ProcessResult:
        """
        Call ``realm list`` with given arguments.
        List all discovered, and configured realms

        :param args: additional arguments to pass to the list operation, defaults to None
        :type args: list[Any] | None, optional
        """
        if args is None:
            args = []

        return self.host.conn.exec(["realm", "list", *args])

    def permit(self, args: list[Any] | None = None) -> ProcessResult:
        """
        Call ``realm permit`` with given arguments.
        Permit local login by users of the realm

        :param args: permit information about domain, defaults to None
        :type args: list[Any] | None, optional
        """
        if args is None:
            args = []

        return self.host.conn.exec(["realm", "permit", *args])
