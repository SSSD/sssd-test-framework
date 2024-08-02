"""Selecting authselect profiles."""

from __future__ import annotations

from pytest_mh import MultihostHost, MultihostUtility

__all__ = [
    "AuthselectUtils",
]


class AuthselectUtils(MultihostUtility[MultihostHost]):
    """
    Use authselect to configure nsswitch and PAM.

    .. code-block:: python
        :caption: Example usage

        @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
        def test_example(client: Client, provider: GenericProvider):
            client.authselect.select('sssd', ['with-mkhomedir'])

    .. note::

        All changes are automatically reverted when a test is finished.
    """

    def __init__(self, host: MultihostHost) -> None:
        """
        :param host: Remote host instance.
        :type host: MultihostHost
        """
        super().__init__(host)
        self.__backup: str | None = None

    def teardown(self):
        """
        Revert to original state.

        :meta private:
        """
        if self.__backup is not None:
            self.host.conn.exec(["authselect", "backup-restore", self.__backup])
            self.host.conn.exec(["rm", "-fr", f"/var/lib/authselect/backups/{self.__backup}"])
            self.__backup = None

        super().teardown()

    def select(self, profile: str, features: list[str] = []) -> None:
        """
        Select an authselect profile.

        :param profile: Authselect profile name.
        :type profile: str
        :param features: Authselect features to enable, defaults to []
        :type features: list[str], optional
        """
        backup = []
        if self.__backup is None:
            self.__backup = "multihost.backup"
            backup = [f"--backup={self.__backup}"]

        self.host.conn.exec(["authselect", "select", profile, *features, "--force", *backup])

    def current(self) -> str:
        """
        List current Authselect configuration.
        :return: Authselect configuration
        :rtype: str
        """
        result = self.host.conn.exec(["authselect", "current"]).stdout

        return result

    def disable_feature(self, features: list[str]) -> None:
        """
        Disable Authselect feature.
        :param features: Authselect features to disable
        :type: list[str], required
        """
        backup = []
        if self.__backup is None:
            self.__backup = "multihost.backup"
            backup = [f"--backup={self.__backup}"]
        self.host.conn.exec(["authselect", "disable-feature", *features, *backup])

    def enable_feature(self, features: list[str]) -> None:
        """
        Enable Authselect feature.
        :param features:  Authselect features to enable
        :type: list[str], required
        """
        backup = []
        if self.__backup is None:
            self.__backup = "multihost.backup"
            backup = [f"--backup={self.__backup}"]

        self.host.conn.exec(["authselect", "enable-feature", *features, *backup])
