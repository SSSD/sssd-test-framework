"Managing local users and groups."

from __future__ import annotations

import jc
from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.cli import CLIBuilder, CLIBuilderArgs
from pytest_mh.ssh import SSHLog

__all__ = [
    "OverrideUtils",
    "OverrideUser",
    "OverrideGroup",
]


class OverrideUtils(MultihostUtility[MultihostHost]):
    """
    Management of override users and groups.

    .. note::

        All changes are automatically reverted when a test is finished.
    """

    def __init__(self, host: MultihostHost) -> None:
        """
        :rtype: object
        :param host: Remote host instance.
        :type host: MultihostHost
        """
        super().__init__(host)

        self.cli: CLIBuilder = CLIBuilder(host.ssh)
        self._users: list[str] = []
        self._groups: list[str] = []

    def teardown(self) -> None:
        """
        Teardown
        """
        super().teardown()

    def user(self, name: str) -> OverrideUser:
        """
        Get override user object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.Client)
            def test_example(client: Client):
                # Create user
                client.overrides.user('user-1', o-user-1).add(uid=10001)

                # Call `id o-user-1` and assert the result
                result = client.tools.id('o-user-1')
                assert result is not None
                assert result.user.name == 'o-user-1'
                assert result.user.id == 10001

        :param name: User name.
        :type name: str
        :return: New user override object.
        :rtype: OverrideUser
        """
        return OverrideUser(self, name)

    def group(self, name: str) -> OverrideGroup:
        """
        Get override group object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.Client)
            def test_example(client: Client):
                # Create override
                group = client.override.group('users').add(uid=10001)

                # Create secondary group and add user as a member

                # Call `id user-1` and assert the result
                result = client.tools.id('o-users-1')
                assert result is not None
                assert result.group.name == 'o-user-1'
                assert result.group.id == 10001

        :param name: Group name.
        :type name: str
        :return: New group object.
        :rtype: OverrideGroup
        """
        return OverrideGroup(self, name)


class OverrideUser(object):
    """
    Management of override users.
    """

    def __init__(self, util: OverrideUtils, name: str) -> None:
        """
        :param util: OverrideUser object.
        :type util: OverrideUser
        :param name: User name.
        :type name: str
        """
        self.util = util
        self.name = name

    def add(
        self,
        *,
        uid: int | None = None,
        gid: int | None = None,
        name: str | None = None,
        password: str | None = "Secret123",
        home: str | None = None,
        gecos: str | None = None,
        shell: str | None = None,
        certificate: str | None = None,
    ) -> OverrideUser:
        """
        Create new override user.

        :param uid: User id, defaults to None
        :type uid: int | None, optional
        :param gid: Primary group id, defaults to None
        :type gid: int | None, optional
        :param home: Home directory, defaults to None
        :type home: str | None, optional
        :param gecos: GECOS, defaults to None
        :type gecos: str | None, optional
        :param shell: Login shell, defaults to None
        :type shell: str | None, optional
        :param certificate: PKI certificate defaults to None
        type: str | None, optional
        :return: Self.
        :rtype: OverrideUser
        """
        args: CLIBuilderArgs = {
            "name": (self.util.cli.option.VALUE, name),
            "uid": (self.util.cli.option.VALUE, uid),
            "gid": (self.util.cli.option.VALUE, gid),
            "home": (self.util.cli.option.VALUE, home),
            "gecos": (self.util.cli.option.VALUE, gecos),
            "shell": (self.util.cli.option.VALUE, shell),
            "certificate": (self.util.cli.option.VALUE, certificate), }

        self.util.logger.info(f'Creating override user "{self.name}" on {self.util.host.hostname}')
        self.util.host.ssh.run(self.util.cli.command(
            f'sss_override user-add {self.name}', args), input=password, log_level=SSHLog.Error)
        self.util._users.append(self.name)

        return self

    def modify(
        self,
        *,
        uid: int | None = None,
        gid: int | None = None,
        name: str | None = None,
        password: str | None = "Secret123",
        home: str | None = None,
        gecos: str | None = None,
        shell: str | None = None,
        certificate: str | None = None,
    ) -> OverrideUser:
        """
        Modify existing override user.

        Parameters that are not set are ignored.

        :param uid: User id, defaults to None
        :type uid: int | None, optional
        :param gid: Primary group id, defaults to None
        :type gid: int | None, optional
        :param home: Home directory, defaults to None
        :type home: str | None, optional
        :param gecos: GECOS, defaults to None
        :type gecos: str | None, optional
        :param shell: Login shell, defaults to None
        :type shell: str | None, optional
        :param certificate: certificate, defaults to None
        :type certificate: str | None, optional
        :return: Self.
        :rtype: OverrideUser
        """

        args: CLIBuilderArgs = {
            "name": (self.util.cli.option.VALUE, name),
            "uid": (self.util.cli.option.VALUE, uid),
            "gid": (self.util.cli.option.VALUE, gid),
            "home": (self.util.cli.option.VALUE, home),
            "gecos": (self.util.cli.option.VALUE, gecos),
            "shell": (self.util.cli.option.VALUE, shell),
            "certificate": (self.util.cli.option.VALUE, certificate), }

        self.util.logger.info(f'Modifying override user "{self.name}" on {self.util.host.hostname}')
        self.util.host.ssh.run(self.util.cli.command(f'sss_override user-add {self.name}', args), input=password, log_level=SSHLog.Error)

        return self

    def backup(self, *, file: str | None = "backup",) -> None:
        """
        :param file: File name.
        :type file: str | None, defaults to backup
        :return: Self.
        :rtype: OverrideUser
        """
        self.util.logger.info(f'Exporting override user "{self.name}" on {self.util.host.hostname}')
        self.util.host.ssh.run(f'sss_override user-export "{self.name}" "{file}"', log_level=SSHLog.Error)

    def restore(self, *, file: str | None = "backup",) -> None:
        """
        :param file: File name.
        :type file: str | None, defaults to backup
        :return: Self.
        :rtype: OverrideUser
        """
        self.util.logger.info(f'Importing override user "{self.name}" on {self.util.host.hostname}')
        self.util.host.ssh.run(f'sss_override user-import "{self.name}" "{file}"', log_level=SSHLog.Error)

    def delete(self) -> None:
        """
        Delete the override user.
        """
        self.util.logger.info(f'Deleting override user "{self.name}" on {self.util.host.hostname}')
        self.util.host.ssh.run(f"sss_override user-del '{self.name}'", log_level=SSHLog.Error)

    def get(self, attrs: list[str] | None = None) -> dict[str, list[str]]:
        """
        Get override attributes.

        :param attrs: If set, only requested attributes are returned, defaults to None
        :type attrs: list[str] | None, optional
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]]
        """

        self.util.logger.info(f'Fetching override user "{self.name}" on {self.util.host.hostname}')
        result = self.util.host.ssh.exec(["sss_override", "user-show", self.name],
                                         raise_on_error=False, log_level=SSHLog.Error)
        if result.rc != 0:
            return {}

        lst = result.stdout.split(":")
        if len(lst) < 7:
            return {}

        result = [{"userid": lst[0], "override": lst[1], "uid": lst[2], "gid": lst[3],
            "gecos": lst[4], "home": lst[5], "shell": lst[6], "certificate": lst[7]}]

        return {k: [str(v)] for k, v in result[0].items() if not attrs or k in attrs}


class OverrideGroup(object):
    """
    Management of override groups.
    """

    def __init__(self, util: OverrideUtils, name: str) -> None:
        """
        :param util: OverrideUtils utility object.
        :type util: OverrideUtils
        :param name: Group name.
        :type name: str
        :param override_name: Override name.
        :type override_name: str
        """
        self.util = util
        self.name = name

    def add(
        self,
        *,
        name: str | None = None,
        gid: int | None = None,
    ) -> OverrideGroup:
        """
        Create new override group.

        :param name: Group override name, defaults to None
        :type name: str | None, required
        :param gid: Group id, defaults to None
        :type gid: int | None, optional
        :return: Self.
        :rtype: OverrideGroup
        """
        args: CLIBuilderArgs = {
            "name": (self.util.cli.option.VALUE, name),
            "gid": (self.util.cli.option.VALUE, gid),
        }

        self.util.logger.info(f'Creating override group "{self.name}" on {self.util.host.hostname}')
        self.util.host.ssh.run(self.util.cli.command(f'sss_override group-add {self.name}', args),
                               log_level=SSHLog.Silent)
        self.util._groups.append(self.name)

        return self

    def modify(
        self,
        *,
        name: str | None = None,
        gid: int | None = None,
    ) -> OverrideGroup:
        """
        Modify existing override group.

        Parameters that are not set are ignored.

        :param name: Override name, defaults to None
        :type name: str | None, optional
        :param gid: Group id, defaults to None
        :type gid: int | None, optional
        :return: Self.
        :rtype: OverrideGroup
        """

        args: CLIBuilderArgs = {
            "name": (self.util.cli.option.VALUE, name),
            "gid": (self.util.cli.option.VALUE, gid),
        }

        self.util.logger.info(f'Modifying override group "{self.name}" on {self.util.host.hostname}')
        self.util.host.ssh.run(self.util.cli.command(f'sss_override group-add "{self.name}"', args),
                               log_level=SSHLog.Error)

        return self

    def delete(self) -> None:
        """
        Delete the group.
        """
        self.util.logger.info(f'Deleting override group "{self.name}" on {self.util.host.hostname}')
        self.util.host.ssh.run(f'sss_override group-del "{self.name}"', log_level=SSHLog.Error)
        self.util._groups.remove(self.name)

    def backup(self, *, file: str | None = "backup", ) -> None:
        """
        :param file: File name.
        :type file: str | None, defaults to backup
        :return: Self.
        :rtype: OverrideUser
        """
        self.util.logger.info(f'Exporting override group "{self.name}" on {self.util.host.hostname}')
        self.util.host.ssh.run(f"sss_override group-export '{self.name}' '{file}'", log_level=SSHLog.Error)

    def restore(self, *, file: str | None = "backup", ) -> None:
        """
        :param file: File name.
        :type file: str | None, defaults to backup
        :return: Self.
        :rtype: OverrideUser
        """
        self.util.logger.info(f'Importing override group "{self.name}" on {self.util.host.hostname}')
        self.util.host.ssh.run(f"sss_override group-import '{self.name}' '{file}'", log_level=SSHLog.Error)

    def get(self, attrs: list[str] | None = None) -> dict[str, list[str]]:
        """
        Get group attributes.

        :param attrs: If set, only requested attributes are returned, defaults to None
        :type attrs: list[str] | None, optional
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]]
        """
        self.util.logger.info(f'Fetching override group "{self.name}" on {self.util.host.hostname}')
        result = self.util.host.ssh.exec(["sss_override", "group-show", self.name], raise_on_error=False, log_level=SSHLog.Silent)
        if result.rc != 0:
            return {}

        lst = result.stdout.split(":")
        if len(lst) < 2:
            return {}

        result = [{"groupname": lst[0], "name": lst[1], "gid": lst[2], "members": lst[3]}]

        return {k: [str(v)] for k, v in result[0].items() if not attrs or k in attrs}
