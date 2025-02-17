"""Manage enrollment in realms"""

from __future__ import annotations

from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.cli import CLIBuilder, CLIBuilderArgs
from pytest_mh.conn import ProcessResult
from pytest_mh.utils.fs import LinuxFileSystem

__all__ = [
    "realmdUtils",
]


class Realmd(MultihostUtility[MultihostHost]):
    """
    Call commands from realmd
    """

    def __init__(self, host: MultihostHost, fs: LinuxFileSystem) -> None:
        super().__init__(host)

        self.cli: CLIBuilder = self.host.cli
        """Command line builder."""

        self.fs: LinuxFileSystem = fs
        """Filesystem utils."""

    def discover(
        self,
        args: list[Any]| None = None,
    ) -> ProcessResult:
        """
        Call ``realm discover `` with given arguments.

        :param domain: Discover information about domains
        :type domain: str,
        :param args: additional arguments to pass to the discover operation
        :type args: list,
        """
        if args is None:
            args = []

        return self.host.conn.exec(["realm", "discover", *args])

    def leave(
        self,
        args: list[Any] | None = None
    ) -> ProcessResult:
        """
        Call ``realm leave `` with given arguments.

        :param args: additional arguments to pass to the leave operation
        :type args: list,
        """
        if args is None:
            args = []

        return self.host.conn.exec(["realm", "leave", *args])

    def join(
        self,
        domain: str,
        args: list[Any] | None = None,
        passwd: str | None = None,
    ) -> ProcessResult:
        """
        Call ``realm join `` with given arguments.

        :param domain: join information about domains
        :type domain: str,
        :param args: additional arguments to pass to the join operation
        :type args: list,
        """
        if args is None:
            args = []

        return self.host.conn.exec(["realm", "join", "--verbose", *args, domain], input=passwd)

    def list(
        self,
        args: list[Any] | None = None,
    ) -> ProcessResult:
        """
        Call ``realm list `` with given arguments.
        List all discovered, and configured realms

        :param args: additional arguments to pass to the list operation
        :type args: list,
        """
        if args is None:
            args = []

        return self.host.conn.exec(["realm", "list", *args])

    def permit(
        self,
        args: list[Any] | None = None,
    ) -> ProcessResult:
        """
        Call ``realm permit `` with given arguments.
        Permit local login by users of the realm

        :param args: permit information about domains
        :type args: list,
        """
        if args is None:
            args = []

        return self.host.conn.exec(["realm", "permit", *args])
