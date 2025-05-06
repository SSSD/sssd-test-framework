"""Manage GDM interface from SCAutolib."""

from __future__ import annotations

from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.cli import CLIBuilder, CLIBuilderArgs
from pytest_mh.conn import ProcessResult
from pytest_mh.utils.fs import LinuxFileSystem

__all__ = [
    "GDM",
]


class GDM(MultihostUtility[MultihostHost]):
    """
    Call commands from scautolib.
    """

    def init(self) -> None:
        """
        Initialize GDM for testing
        """
        self.host.conn.exec(["/opt/test_venv/bin/scauto", "gui", "init"])

    def assert_text(self, word: str) -> bool:
        """
        Run scauto gui assert-text

        :param word: Single word in string format to search for in screen capture.
        :type word: str
        :return: Result of searching for string.
        :rtype: bool
        """
        result = self.host.conn.exec(["/opt/test_venv/bin/scauto", "gui", "assert-text", word])
        return result == 0

    def click_on(self, word: str) -> bool:
        """
        Run scauto gui click-on

        :param word: Click on object containing word
        :type word: str
        :return: Result of clicking on object
        :rtype: bool
        """
        result = self.host.conn.exec(["/opt/test_venv/bin/scauto", "gui", "click-on", word])
        return result == 0

    def kb_write(self, word: str) -> bool:
        """
        Run scauto gui kb-write

        :param word: type word on keyboard
        :type word: str
        :return: Result of typing work and pressing enter
        :rtype: bool
        """
        result = self.host.conn.exec(["/opt/test_venv/bin/scauto", "gui", "kb-write", word])
        return result == 0

    def check_home_screen(self) -> bool:
        """
        Run scauto gui check-home-screen

        :return: Result of checking if current screenshot is of the home screen
        :rtype: bool
        """
        result = self.host.conn.exec(["/opt/test_venv/bin/scauto", "gui", "check-home-screen"])
        return result == 0

    def done(self) -> bool:
        """
        Run scauto gui done

        :return: run cleanup after gui tests
        :rtype: bool
        """
        result = self.host.conn.exec(["/opt/test_venv/bin/scauto", "gui", "done"])
        return result == 0
