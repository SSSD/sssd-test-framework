from __future__ import annotations

from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.cli import CLIBuilder, CLIBuilderArgs
from pytest_mh.utils.fs import LinuxFileSystem

__all__ = [
    "SSSOverrideUtils",
    "SSSOverrideUser",
    "SSSOverrideGroup",
]


class SSSOverrideUtils(MultihostUtility[MultihostHost]):
    """
    Management of local override users and groups, using sss_override.
    """

    def __init__(self, host: MultihostHost, fs: LinuxFileSystem) -> None:
        """
        :param host: Remote host instance.
        :type host: MultihostHost
        :param fs: Linux file system
        :type fs: LinuxFileSystem
        """
        super().__init__(host)

        self.cli: CLIBuilder = CLIBuilder(host.ssh)
        self.fs: LinuxFileSystem = fs

    def user(self, name: str) -> SSSOverrideUser:
        """
        Get local override user object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.LDAP)
            def test_example(client: Client, ldap: LDAP):
                # Add user
                ldap.user("user-1").add(uid=10001, gid=10001, gecos="gecos")

                # SSSD must be running for sss_override to work
                client.sssd.start()

                # Create local override for the user
                client.sss_override.user("user-1").add(name="o-user-1", uid=20001, gid=20001, gecos="o-gecos")

                # SSSD must be restarted so newly created view can be applied
                client.sssd.restart()

                # Check the result
                result = client.tools.getent.passwd("o-user-1")
                assert result is not None
                assert result.name == "o-user-1"
                assert result.uid == 20001
                assert result.gid == 20001
                assert result.gecos == "o-gecos"

        :param name: User.
        :type name: str
        :return: New user local override object.
        :rtype: SSSOverrideUser
        """
        return SSSOverrideUser(self, name)

    def group(self, group: str) -> SSSOverrideGroup:
        """
        Get local override group object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.LDAP)
            def test_example(client: Client, ldap: LDAP):
                # Add group
                ldap.group("group-1").add(gid=10001)

                # SSSD must be running for sss_override to work
                client.sssd.start()

                # Create local override for the user
                client.sss_override.group("group-1").add(name="o-group-1", gid=20001)

                # SSSD must be restarted so newly created view can be applied
                client.sssd.restart()

                # Check the result
                result = client.tools.getent.group("o-group-1")
                assert result is not None
                assert result.name == "o-group-1"
                assert result.gid == 20001


        :param group: Group name.
        :type group: str
        :return: New group object.
        :rtype: SSSOverrideGroup
        """
        return SSSOverrideGroup(self, group)

    def export_data(
        self,
        *,
        users: str | None = "/tmp/sss_override_users.bak",
        groups: str | None = "/tmp/sss_override_groups.bak",
    ) -> None:
        """
        Exports local override data for **all** users and groups.

        :param users: File location where users will be exported, if ``None``
            then user export is omitted. Defaults to
            ``/tmp/sss_override_users.bak``.
        :type users: str | None
        :param groups: File location where groups will be exported, if ``None``
            then group export is omitted. Defaults to
            ``/tmp/sss_override_groups.bak``.
        :type groups: str | None
        """
        if users:
            self.logger.info(f"Exporting user local overrides data to {users} on {self.host.hostname}")
            self.fs.backup(users)
            self.host.ssh.exec(["sss_override", "user-export", users])

        if groups:
            self.logger.info(f"Exporting group local overrides data to {groups} on {self.host.hostname}")
            self.fs.backup(groups)
            self.host.ssh.exec(["sss_override", "group-export", groups])

    def import_data(
        self,
        *,
        users: str | None = "/tmp/sss_override_users.bak",
        groups: str | None = "/tmp/sss_override_groups.bak",
    ) -> None:
        """
        Import users and groups local override data.

        :param users: File location with user overrides that will be imported,
            if ``None`` then user import is omitted. Defaults to
            ``/tmp/sss_override_users.bak``.
        :type users: str | None
        :param groups: File location with group overrides that will be imported,
            if ``None`` then group import is omitted. Defaults to
            ``/tmp/sss_override_groups.bak``.
        :type groups: str | None
        """
        if users:
            self.logger.info(f"Importing user local overrides data from {users} on {self.host.hostname}")
            self.fs.backup(users)
            self.host.ssh.exec(["sss_override", "user-import", users])

        if groups:
            self.logger.info(f"Importing group local overrides data from {groups} on {self.host.hostname}")
            self.fs.backup(groups)
            self.host.ssh.exec(["sss_override", "group-import", groups])


class SSSOverrideUser:
    """
    Management of local override for users using sss_override.
    """

    def __init__(self, util: SSSOverrideUtils, user: str) -> None:
        """
        :param util: OverrideUser object.
        :type util: SSSOverrideUser
        :param user: User name.
        :type user: str
        """
        self.util: SSSOverrideUtils = util
        self.user: str = user

    def add(
        self,
        *,
        uid: int | None = None,
        gid: int | None = None,
        name: str | None = None,
        home: str | None = None,
        gecos: str | None = None,
        shell: str | None = None,
        certificate: str | None = None,
    ) -> SSSOverrideUser:
        """
        Create new local override for user.

        :param uid: User id, defaults to None
        :type uid: int | None, optional
        :param gid: Primary group id, defaults to None
        :type gid: int | None, optional
        :param name: | None, optional
        :type name: str | None, optional
        :param home: Home directory, defaults to None
        :type home: str | None, optional
        :param gecos: GECOS, defaults to None
        :type gecos: str | None, optional
        :param shell: Login shell, defaults to None
        :type shell: str | None, optional
        :param certificate: PKI certificate defaults to None
        :type certificate: str | None, optional
        :return: Self.
        :rtype: SSSOverrideUser
        """
        args: CLIBuilderArgs = {
            "name": (self.util.cli.option.VALUE, name),
            "uid": (self.util.cli.option.VALUE, uid),
            "gid": (self.util.cli.option.VALUE, gid),
            "home": (self.util.cli.option.VALUE, home),
            "gecos": (self.util.cli.option.VALUE, gecos),
            "shell": (self.util.cli.option.VALUE, shell),
            "certificate": (self.util.cli.option.VALUE, certificate),
        }

        self.util.logger.info(f"Creating local override for user {self.user} on {self.util.host.hostname}")
        self.util.host.ssh.exec(["sss_override", "user-add", self.user] + self.util.cli.args(args))

        return self

    def delete(self) -> SSSOverrideUser:
        """
        Delete the local override for user.
        """
        self.util.logger.info(f"Deleting local override for user {self.user} on {self.util.host.hostname}")
        self.util.host.ssh.exec(["sss_override", "user-del", self.user])

        return self

    def get(self, attrs: list[str] | None = None) -> dict[str, list[str]] | None:
        """
        Get local override data for user.

        :param attrs: If set, only requested attributes are returned, defaults to None, returning all attributes
        :type attrs: list[str] | None, optional
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]]
        """

        self.util.logger.info(f"Fetching local override data for user {self.user} on {self.util.host.hostname}")
        output = self.util.host.ssh.exec(["sss_override", "user-show", self.user])
        if not output.stdout:
            return None

        lst = output.stdout.split(":")
        if len(lst) != 8:
            raise ValueError(f"Unexpected output: {output.stdout}")

        result = [
            {
                "user": lst[0],
                "name": lst[1],
                "uid": lst[2],
                "gid": lst[3],
                "gecos": lst[4],
                "home": lst[5],
                "shell": lst[6],
                "certificate": lst[7],
            }
        ]

        return {k: [str(v)] for k, v in result[0].items() if not attrs or k in attrs}


class SSSOverrideGroup:
    """
    Management of local override for group.
    """

    def __init__(self, util: SSSOverrideUtils, group: str) -> None:
        """
        :param util: SSSOverrideUtils utility object.
        :type util: SSSOverrideUtils
        :param group: Group name.
        :type group: str
        """
        self.util: SSSOverrideUtils = util
        self.group: str = group

    def add(
        self,
        *,
        name: str | None = None,
        gid: int | None = None,
    ) -> SSSOverrideGroup:
        """
        Create new local override for group.

        :param name: Group local override name, defaults to None
        :type name: str | None, required
        :param gid: Group id, defaults to None
        :type gid: int | None, optional
        :return: Self.
        :rtype: SSSOverrideGroup
        """
        args: CLIBuilderArgs = {
            "name": (self.util.cli.option.VALUE, name),
            "gid": (self.util.cli.option.VALUE, gid),
        }

        self.util.logger.info(f"Creating local override for group {self.group} on {self.util.host.hostname}")
        self.util.host.ssh.exec(["sss_override", "group-add", self.group] + self.util.cli.args(args))

        return self

    def delete(self) -> SSSOverrideGroup:
        """
        Delete the local override for group.
        """
        self.util.logger.info(f"Deleting local override for group {self.group} on {self.util.host.hostname}")
        self.util.host.ssh.exec(["sss_override", "group-del", self.group])

        return self

    def get(self, attrs: list[str] | None = None) -> dict[str, list[str]] | None:
        """
        Get local override attributes for group.

        :param attrs: If set, only requested attributes are returned, defaults to None, returning all attributes
        :type attrs: list[str] | None, optional
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]]
        """
        self.util.logger.info(f"Fetching local override group {self.group} on {self.util.host.hostname}")
        output = self.util.host.ssh.exec(["sss_override", "group-show", self.group])
        if not output.stdout:
            return None

        lst = output.stdout.split(":")
        if len(lst) != 3:
            raise ValueError(f"Unexpected output: {output.stdout}")

        result = [
            {
                "group": lst[0],
                "name": lst[1],
                "gid": lst[2],
            }
        ]

        return {k: [str(v)] for k, v in result[0].items() if not attrs or k in attrs}
