"""Manage GDM interface from SCAutolib."""

from __future__ import annotations

import json
import re
import time
from typing import TYPE_CHECKING

from pytest_mh import MultihostHost, MultihostUtility

from ..misc import retry
from ..misc.globals import scauto_path

if TYPE_CHECKING:
    from ..roles.client import Client


__all__ = [
    "GDM",
]


class GDM(MultihostUtility[MultihostHost]):
    """
    Call commands from scautolib.
    """

    def __init__(self, host):
        super().__init__(host)
        self.init_completed = False

        self.cmd = [scauto_path, "gui", "--wait-time", "1", "--no-screenshot"]

    def teardown(self):
        if self.init_completed:
            self.done()

    def init(self) -> None:
        """
        Initialize GDM for testing
        """
        if not self.init_completed:
            self.host.conn.exec([*self.cmd, "init"])
            self.init_completed = True

    def assert_text(self, word: str) -> bool:
        """
        Run scauto gui assert-text

        :param word: Single word in string format to search for in screen capture.
        :type word: str
        :return: Result of searching for string.
        :rtype: bool
        """
        if not self.init_completed:
            self.init()

        result = self.host.conn.exec([*self.cmd, "assert-text", word])
        return result.rc == 0

    def click_on(self, word: str) -> bool:
        """
        Run scauto gui click-on

        :param word: Click on object containing word
        :type word: str
        :return: Result of clicking on object
        :rtype: bool
        """
        if not self.init_completed:
            self.init()

        result = self.host.conn.exec([*self.cmd, "click-on", word])
        return result.rc == 0

    def kb_write(self, word: str) -> bool:
        """
        Run scauto gui kb-write

        :param word: type word on keyboard
        :type word: str
        :return: Result of typing work and pressing enter
        :rtype: bool
        """
        if not self.init_completed:
            self.init()

        result = self.host.conn.exec([*self.cmd, "kb-write", word])
        time.sleep(0.3)
        return result.rc == 0

    def kb_send(self, word: str) -> bool:
        """
        Run scauto gui kb-send

        :param word: key or key-combination string
        :type word: str
        :return: Result of sending key press
        :rtype: bool
        """
        if not self.init_completed:
            self.init()

        result = self.host.conn.exec([*self.cmd, "kb-send", word])
        return result.rc == 0

    @retry(max_retries=60, delay=1, on=AssertionError)
    def wait_for_login(self, client: Client) -> None:
        """
        Watch journald log for login message.

        :param client: Client role object to read log
        :type client: Client role
        """
        result = client.journald.journalctl(
            grep="Opening and taking control of.*card", unit=None, since="5 seconds ago"
        )
        if result.rc != 0:
            raise AssertionError("Unable to see gnome-shell take control of video card")

    def check_home_screen(self) -> bool:
        """
        Run scauto gui check-home-screen

        :return: Result of checking if current screenshot is of the home screen
        :rtype: bool
        """
        if not self.init_completed:
            self.init()

        cmd = [scauto_path, "-v", "debug", "gui", "--wait-time", "2", "--no-screenshot"]
        result = self.host.conn.exec([*cmd, "check-home-screen"], raise_on_error=False)
        return result.rc == 0

    def done(self) -> bool:
        """
        Run scauto gui done

        :return: run cleanup after gui tests
        :rtype: bool
        """
        # Do nothing and return True if init was not already run
        if not self.init_completed:
            return True

        result = self.host.conn.exec([*self.cmd, "done"])
        self.host.conn.exec(["systemctl", "stop", "gdm"], raise_on_error=False)
        self.init_completed = False
        return result.rc == 0

    def login_idp(self, client: Client, username: str, password: str) -> bool:
        """
        Helper function to facilitate GDM login process for IdP

        :param client: client machine role object
        :type client: Client role
        :param username: Username to use for login
        :type username: str
        :param password: Password for login to IdP
        :type password: str
        :return: login URL to use to IdP login
        :rtype: str
        """

        client.journald.clear()

        self.click_on("listed?")
        self.kb_write(username)
        self.click_on("Log")

        log = client.journald.journalctl(grep="auth-mechanisms.*eidp.*code", args=["_COMM=gdm"])
        match = re.search(r"\{.*\}", log.stdout_lines[-1])
        if match:
            json_string = match.group()
        else:
            self.logger.error("Unable to find IdP URI in journal")
            return False

        data = json.loads(json_string)
        uri = data["authSelection"]["mechanisms"]["eidp"]["uri"]
        code = data["authSelection"]["mechanisms"]["eidp"]["code"]

        test_uri = f"{uri}?user_code={code}"

        # Attemp login and capture return value
        client.auth.idp.keycloak(test_uri, username, password)

        self.kb_send("enter")

        # Sleeping to wait for login process to prevent race condition with ffmpeg
        time.sleep(5)

        retval = self.check_home_screen()

        return retval
