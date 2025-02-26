"""Perform actions on Active Directory."""

from __future__ import annotations

from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.cli import CLIBuilder, CLIBuilderArgs
from pytest_mh.conn import ProcessResult
from pytest_mh.utils.fs import LinuxFileSystem

__all__ = [
    "ADCLIUtils",
]


class ADCLI(MultihostUtility[MultihostHost]):
    """
    Call commands from adcli
    """

    def __init__(self, host: MultihostHost, fs: LinuxFileSystem) -> None:
        super().__init__(host)

        self.cli: CLIBuilder = self.host.cli
        """Command line builder."""

        self.fs: LinuxFileSystem = fs
        """Filesystem utils."""

    def info(
        self,
        domain: str,
        args: list[Any] | None = None
    ) -> ProcessResult:
        """
        Call ``adcli info `` with given arguments.

        :param domain: Displays discovered information about an Active Directory domain, defaults to None
        :type domain: str,
        :param domain_controller: Domain controller to connect, defaults to None
        :type domain_controller: str, optional
        """
        if args is None:
            args = []

        return self.host.conn.exec(["adcli", "info", f"{domain}", *args])

    def testjoin(
        self,
        args: list[Any] | None = None
    ) -> ProcessResult:
        """
        call ``adcli testjoin `` with given arguments.

        :param domain: Target Active Directory domain, defaults to None
        :type domain: str | None, optional
        :param domain_controller: Domain controller to connect
        :type domain_controller: str | None, optional
        """
        if args is None:
            args = []
        return self.host.conn.exec(["adcli", "testjoin", *args])

    def del_com(
        self,
        host: str,
        args: list[Any] | None = None,
        passwd: str| None = None,
    ) -> ProcessResult:
        """
        call ``adcli delete computer `` with given arguments.

        :param domain: Target Active Directory domain, defaults to None
        :type domain: str | None, optional
        :param domain_controller: Domain controller to connect
        :type domain_controller: str | None, optional
        """
        if args is None:
            args = []
        return self.host.conn.exec(["adcli", "delete-computer", f"{self.host.hostname}", *args], input=passwd)

    def join(
        self,
        domain: str,
        args: list[Any] | None = None
    ) -> str:
        """
        call ``adcli join`` with given arguments.

        """
        args: CLIBuilderArgs = {
        }
        self.host.conn.exec(["adcli", "join"] + self.cli.args(args))
