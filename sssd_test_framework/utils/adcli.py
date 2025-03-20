"""Perform actions on Active Directory."""

from __future__ import annotations

from typing import Any

from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.conn import ProcessResult

__all__ = [
    "AdcliUtils",
]


class AdcliUtils(MultihostUtility[MultihostHost]):
    """
    Call commands from adcli
    This utility will not revert any changes. It relies on AD host topology
    for clean up.
    """

    def __init__(self, host: MultihostHost) -> None:
        """
        :param host: Remote host instance.
        :type host: MultihostHost
        """
        super().__init__(host)

    def info(self, domain: str, args: list[Any] | None = None) -> ProcessResult:
        """
        Call ``adcli info`` with given arguments.

        :param domain: Active Directory domain to discover
        :type domain: str,
        :param args: A list of additional arguments, flags used with adcli
        :type args: list | Any, optional
        """
        if args is None:
            args = []

        return self.host.conn.exec(["adcli", "info", *args, "--verbose", f"{domain}"])

    def testjoin(self, args: list[Any] | None = None) -> ProcessResult:
        """
        call ``adcli testjoin`` with given arguments.

        This method will return if the machine account password and the join are still valid in AD

        :param args: A list of additional arguments, flags used with adcli
        :type args: list | Any, optional
        """
        if args is None:
            args = []
        return self.host.conn.exec(["adcli", *args, "--verbose", "testjoin"])

    def del_com(
        self,
        host: str,
        args: list[Any] | None = None,
        passwd: str | None = None,
    ) -> ProcessResult:
        """
        call ``adcli delete computer`` with given arguments.

        This method deletes a computer account in the domain

        :param host: client host account
        :type host: str | None,
        :param args: A list of additional arguments, flags to use with adcli
        :type args: list | Any, optional
        :type domain: list | None, optional
        :param passwd: credentials to carry out the operations
        :type passwd: str | None, optional
        """
        if args is None:
            args = []
        return self.host.conn.exec(["adcli", "delete-computer", *args, host], input=passwd)

    def join(
        self,
        domain: str,
        args: list[Any] | None = None,
        *,
        passwd: str | None = None,
        user: str | None = "Administrator",
        krb: bool | None = False,
    ) -> ProcessResult:
        """
        call ``adcli join`` with given arguments.

        :type domain: list | None, optional
        :param args: A list of additional arguments, flags with adcli
        :type args: list | Any, optional
        :param passwd: credential to carry out the operations
        :type passwd: str | None, optional
        :param user: Username to carry out the operations
        :type user: str | None, optional
        :param krb: Use kerberos credentials
        :type krb: bool | False, optional
        """
        if args is None:
            args = []
        if krb is True:
            self.host.conn.exec(["kinit", user], input=passwd)
            return self.host.conn.exec(["adcli", "join", "--login-ccache", *args, domain])
        else:
            return self.host.conn.exec(
                ["echo", passwd, "|", "adcli", "join", "--stdin-password", "--verbose", *args, domain]
            )
