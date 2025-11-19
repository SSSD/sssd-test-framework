"Managing local users and groups."

from __future__ import annotations

from typing import Any

import jc
from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.cli import CLIBuilder, CLIBuilderArgs
from pytest_mh.conn import ProcessLogLevel
from pytest_mh.utils.fs import LinuxFileSystem

__all__ = [
    "LocalGroup",
    "LocalUser",
    "LocalUsersUtils",
    "LocalSudoRule",
]


class LocalUsersUtils(MultihostUtility[MultihostHost]):
    """
    Management of local users and groups.

    .. note::

        All changes are automatically reverted when a test is finished.
    """

    def __init__(self, host: MultihostHost, fs: LinuxFileSystem) -> None:
        """
        :param host: Remote host instance.
        :type host: MultihostHost
        """
        super().__init__(host)

        self.cli: CLIBuilder = host.cli
        self.fs: LinuxFileSystem = fs
        self._users: list[str] = []
        self._groups: list[str] = []
        self._sudorules: list[LocalSudoRule] = []

    def teardown(self) -> None:
        """
        Delete any added user and group.
        """
        cmd = ""

        if self._users:
            cmd += "\n".join([f"userdel '{x}' --force --remove" for x in self._users])
            cmd += "\n"

        if self._groups:
            cmd += "\n".join([f"groupdel '{x}' -f" for x in self._groups])
            cmd += "\n"

        if cmd:
            self.host.conn.run("set -e\n\n" + cmd)

        for rule in self._sudorules[:]:
            rule.delete()

        super().teardown()

    def user(self, name: str) -> LocalUser:
        """
        Get user object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.Client)
            def test_example(client: Client):
                # Create user
                client.local.user('user-1').add(uid=10001)

                # Call `id user-1` and assert the result
                result = client.tools.id('user-1')
                assert result is not None
                assert result.user.name == 'user-1'
                assert result.user.id == 10001
                assert result.group.name == 'user-1'
                assert result.group.id == 10001

        :param name: User name.
        :type name: str
        :return: New user object.
        :rtype: LocalUser
        """
        return LocalUser(self, name)

    def group(self, name: str) -> LocalGroup:
        """
        Get group object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.Client)
            def test_example(client: Client):
                # Create user
                user = client.local.user('user-1').add(uid=10001)

                # Create secondary group and add user as a member
                client.local.group('group-1').add().add_member(user)

                # Call `id user-1` and assert the result
                result = client.tools.id('user-1')
                assert result is not None
                assert result.user.name == 'user-1'
                assert result.user.id == 10001
                assert result.group.name == 'user-1'
                assert result.group.id == 10001
                assert result.memberof('group-1')

        :param name: Group name.
        :type name: str
        :return: New group object.
        :rtype: LocalGroup
        """
        return LocalGroup(self, name)


class LocalUser(object):
    """
    Management of local users.
    """

    def __init__(self, util: LocalUsersUtils, name: str) -> None:
        """
        :param util: LocalUsersUtils utility object.
        :type util: LocalUsersUtils
        :param name: User name.
        :type name: str
        """
        self.util = util
        self.name = name

    def __str__(self):
        """
        Returns a string representation of the LocalUser.
        """
        return self.name

    def add(
        self,
        *,
        uid: int | None = None,
        gid: int | None = None,
        password: str | None = "Secret123",
        home: str | None = None,
        gecos: str | None = None,
        shell: str | None = None,
    ) -> LocalUser:
        """
        Create new local user.

        :param uid: User id, defaults to None
        :type uid: int | None, optional
        :param gid: Primary group id, defaults to None
        :type gid: int | None, optional
        :param password: Password, defaults to 'Secret123'
        :type password: str, optional
        :param home: Home directory, defaults to None
        :type home: str | None, optional
        :param gecos: GECOS, defaults to None
        :type gecos: str | None, optional
        :param shell: Login shell, defaults to None
        :type shell: str | None, optional
        :return: Self.
        :rtype: LocalUser
        """
        if home is not None:
            self.util.fs.backup(home)

        args: CLIBuilderArgs = {
            "name": (self.util.cli.option.POSITIONAL, self.name),
            "uid": (self.util.cli.option.VALUE, uid),
            "gid": (self.util.cli.option.VALUE, gid),
            "home": (self.util.cli.option.VALUE, home),
            "gecos": (self.util.cli.option.VALUE, gecos),
            "shell": (self.util.cli.option.VALUE, shell),
        }

        passwd = f" && passwd --stdin '{self.name}'" if password else ""
        self.util.logger.info(f'Creating local user "{self.name}" on {self.util.host.hostname}')
        self.util.host.conn.run(
            self.util.cli.command("useradd", args) + passwd, input=password, log_level=ProcessLogLevel.Error
        )

        self.util._users.append(self.name)
        return self

    def modify(
        self,
        *,
        uid: int | None = None,
        gid: int | None = None,
        password: str | None = None,
        home: str | None = None,
        gecos: str | None = None,
        shell: str | None = None,
    ) -> LocalUser:
        """
        Modify existing local user.

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
        :return: Self.
        :rtype: LocalUser
        """

        args: CLIBuilderArgs = {
            "name": (self.util.cli.option.POSITIONAL, self.name),
            "uid": (self.util.cli.option.VALUE, uid),
            "gid": (self.util.cli.option.VALUE, gid),
            "home": (self.util.cli.option.VALUE, home),
            "gecos": (self.util.cli.option.VALUE, gecos),
            "shell": (self.util.cli.option.VALUE, shell),
        }

        passwd = f" && passwd --stdin '{self.name}'" if password else ""
        self.util.logger.info(f'Modifying local user "{self.name}" on {self.util.host.hostname}')
        self.util.host.conn.run(
            self.util.cli.command("usermod", args) + passwd, input=password, log_level=ProcessLogLevel.Error
        )

        return self

    def delete(self) -> None:
        """
        Delete the user.
        """
        self.util.logger.info(f'Deleting local user "{self.name}" on {self.util.host.hostname}')
        self.util.host.conn.run(f"userdel '{self.name}' --force --remove", log_level=ProcessLogLevel.Error)
        self.util._users.remove(self.name)

    def get(self, attrs: list[str] | None = None) -> dict[str, list[str]]:
        """
        Get user attributes.

        :param attrs: If set, only requested attributes are returned, defaults to None
        :type attrs: list[str] | None, optional
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]]
        """
        self.util.logger.info(f'Fetching local user "{self.name}" on {self.util.host.hostname}')
        result = self.util.host.conn.exec(
            ["getent", "passwd", self.name], raise_on_error=False, log_level=ProcessLogLevel.Error
        )
        if result.rc != 0:
            return {}

        jcresult = jc.parse("passwd", result.stdout)
        if not jcresult:
            return {}

        if not isinstance(jcresult, list):
            raise TypeError(f"Unexpected type: {type(jcresult)}, expecting list")

        if not isinstance(jcresult[0], dict):
            raise TypeError(f"Unexpected type: {type(jcresult[0])}, expecting dict")

        return {k: [str(v)] for k, v in jcresult[0].items() if not attrs or k in attrs}


class LocalGroup(object):
    """
    Management of local groups.
    """

    def __init__(self, util: LocalUsersUtils, name: str) -> None:
        """
        :param util: LocalUsersUtils utility object.
        :type util: LocalUsersUtils
        :param name: Group name.
        :type name: str
        """
        self.util = util
        self.name = name

    def __str__(self):
        """
        Returns a string representation of the LocalGroup.
        """
        return self.name

    def add(
        self,
        *,
        gid: int | None = None,
    ) -> LocalGroup:
        """
        Create new local group.

        :param gid: Group id, defaults to None
        :type gid: int | None, optional
        :return: Self.
        :rtype: LocalGroup
        """
        args: CLIBuilderArgs = {
            "name": (self.util.cli.option.POSITIONAL, self.name),
            "gid": (self.util.cli.option.VALUE, gid),
        }

        self.util.logger.info(f'Creating local group "{self.name}" on {self.util.host.hostname}')
        self.util.host.conn.run(self.util.cli.command("groupadd", args), log_level=ProcessLogLevel.Silent)
        self.util._groups.append(self.name)

        return self

    def modify(
        self,
        *,
        gid: int | None = None,
    ) -> LocalGroup:
        """
        Modify existing local group.

        Parameters that are not set are ignored.

        :param gid: Group id, defaults to None
        :type gid: int | None, optional
        :return: Self.
        :rtype: LocalGroup
        """

        args: CLIBuilderArgs = {
            "name": (self.util.cli.option.POSITIONAL, self.name),
            "gid": (self.util.cli.option.VALUE, gid),
        }

        self.util.logger.info(f'Modifying local group "{self.name}" on {self.util.host.hostname}')
        self.util.host.conn.run(self.util.cli.command("groupmod", args), log_level=ProcessLogLevel.Error)

        return self

    def delete(self) -> None:
        """
        Delete the group.
        """
        self.util.logger.info(f'Deleting local group "{self.name}" on {self.util.host.hostname}')
        self.util.host.conn.run(f"groupdel '{self.name}' -f", log_level=ProcessLogLevel.Error)
        self.util._groups.remove(self.name)

    def get(self, attrs: list[str] | None = None) -> dict[str, list[str]]:
        """
        Get group attributes.

        :param attrs: If set, only requested attributes are returned, defaults to None
        :type attrs: list[str] | None, optional
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]]
        """
        self.util.logger.info(f'Fetching local group "{self.name}" on {self.util.host.hostname}')
        result = self.util.host.conn.exec(
            ["getent", "group", self.name], raise_on_error=False, log_level=ProcessLogLevel.Silent
        )
        if result.rc != 0:
            return {}

        jcresult = jc.parse("group", result.stdout)
        if not jcresult:
            return {}

        if not isinstance(jcresult, list):
            raise TypeError(f"Unexpected type: {type(jcresult)}, expecting list")

        if not isinstance(jcresult[0], dict):
            raise TypeError(f"Unexpected type: {type(jcresult[0])}, expecting dict")

        return {k: [str(v)] for k, v in jcresult[0].items() if not attrs or k in attrs}

    def add_member(self, member: LocalUser) -> LocalGroup:
        """
        Add group member.

        :param member: User or group to add as a member.
        :type member: LocalUser
        :return: Self.
        :rtype: LocalGroup
        """
        return self.add_members([member])

    def add_members(self, members: list[LocalUser]) -> LocalGroup:
        """
        Add multiple group members.

        :param member: List of users or groups to add as members.
        :type member: list[LocalUser]
        :return: Self.
        :rtype: LocalGroup
        """
        self.util.logger.info(f'Adding members to group "{self.name}" on {self.util.host.hostname}')

        if not members:
            return self

        cmd = "\n".join([f"groupmems --group '{self.name}' --add '{x.name}'" for x in members])
        self.util.host.conn.run("set -ex\n" + cmd, log_level=ProcessLogLevel.Error)

        return self

    def remove_member(self, member: LocalUser) -> LocalGroup:
        """
        Remove group member.

        :param member: User or group to remove from the group.
        :type member: LocalUser
        :return: Self.
        :rtype: LocalGroup
        """
        return self.remove_members([member])

    def remove_members(self, members: list[LocalUser]) -> LocalGroup:
        """
        Remove multiple group members.

        :param member: List of users or groups to remove from the group.
        :type member: list[LocalUser]
        :return: Self.
        :rtype: LocalGroup
        """
        self.util.logger.info(f'Removing members from group "{self.name}" on {self.util.host.hostname}')

        if not members:
            return self

        cmd = "\n".join([f"groupmems --group '{self.name}' --delete '{x.name}'" for x in members])
        self.util.host.conn.run("set -ex\n" + cmd, log_level=ProcessLogLevel.Error)

        return self


class LocalSudoRule(object):
    """
    Local sudo rule management.
    """

    default_user: str = "ALL"
    default_host: str = "ALL"
    default_command: str = "ALL"

    def __init__(self, util: LocalUsersUtils, name: str) -> None:
        """
        :param util: LocalUsersUtils util object.
        :param name: Sudo rule name.
        :type name: str
        """
        self.name = name
        self.util = util
        self.__rule: dict[str, Any] = dict()
        self.filename: str | None = None
        self.rule_str: str | None = None

    def __str__(self):
        """
        Returns a string representation of the LocalSudoRule.
        """
        if self.rule_str:
            return self.rule_str
        else:
            return self.name

    @staticmethod
    def _format_list(item: str | Any | list[str | Any], add_percent: bool = False) -> str:
        """
        Format the item as a string.

        :param item: object to be formatted
        :type item: str | Any| list[str | Any]
        :param add_percent: If true, prepend % to the item, defaults to False
        :type add_percent: bool, optional
        :return: Formatted string.
        :rtype: str
        """
        if isinstance(item, list):
            result = ", ".join(f"%{str(x)}" if isinstance(x, LocalGroup) and add_percent else str(x) for x in item)
        else:
            if isinstance(item, LocalGroup) and add_percent:
                result = f"%{str(item)}"
            else:
                result = str(item)
        return result

    def add(
        self,
        *,
        user: str | LocalUser | LocalGroup | list[str | LocalUser | LocalGroup] | Any | None = default_user,
        host: str | list[str] | Any | None = default_host,
        command: str | list[str] | Any | None = default_command,
        option: str | list[str] | None = None,
        runasuser: str | LocalUser | list[str | LocalUser] | None = None,
        runasgroup: str | LocalGroup | list[str | LocalGroup] | None = None,
        order: int | None = None,
        nopasswd: bool | None = None,
    ) -> LocalSudoRule:
        """
        Create new sudo rule.

        :param user: sudoUser attribute, defaults to ALL
        :type user: str | LocalUser | LocalGroup | list[str | LocalUser | LocalGroup]
        :param host: sudoHost attribute, defaults to ALL
        :type host: str | list[str],
        :param command: sudoCommand attribute, defaults to ALL
        :type command: str | list[str],
        :param option: sudoOption attribute, defaults to None
        :type option: str | list[str] | None, optional
        :param runasuser: sudoRunAsUser attribute, defaults to None
        :type runasuser: str | LocalUser | list[str | LocalUser] | None, optional
        :param runasgroup: sudoRunAsGroup attribute, defaults to None
        :type runasgroup: str | LocalGroup | list[str | LocalGroup] | None, optional
        :param order: sudoOrder attribute, defaults to None
        :type order: int | None, optional
        :param nopasswd: If true, no authentication is required (NOPASSWD), defaults to None (no change)
        :type nopasswd: bool | None, optional
        :return: New sudo rule object.
        :rtype: LocalSudoRule
        """
        orderstr = f"{order:02d}" if order is not None else str(len(self.util._sudorules))
        if self.filename is None:
            self.filename = f"{orderstr}_{self.name}"

        # Remember arguments so we can use them in modify if needed
        self.__rule = dict[str, Any](
            user=user,
            host=host,
            command=command,
            option=option,
            runasuser=runasuser,
            runasgroup=runasgroup,
            order=order,
            nopasswd=nopasswd,
        )
        run_as_str = ""
        if runasuser or runasgroup:
            run_as_str += "("
            if runasuser:
                run_as_str += LocalSudoRule._format_list(runasuser)
            if runasgroup:
                run_as_str += f":{LocalSudoRule._format_list(runasgroup)}"
            run_as_str += ")"
        user_str = LocalSudoRule._format_list(user, add_percent=True)
        host_str = LocalSudoRule._format_list(host)
        tagspec_str = "NOPASSWD:" if nopasswd else ""
        command_str = LocalSudoRule._format_list(command)
        rule_str = f"{user_str} {host_str}={run_as_str} {tagspec_str} {command_str}\n"
        self.rule_str = rule_str
        self.util.fs.write(f"/etc/sudoers.d/{self.filename}", self.rule_str)
        self.util._sudorules.append(self)
        return self

    def modify(
        self,
        *,
        user: str | LocalUser | LocalGroup | list[str | LocalUser | LocalGroup] | None = None,
        host: str | list[str] | None = None,
        command: str | list[str] | None = None,
        option: str | list[str] | None = None,
        runasuser: str | LocalUser | list[str | LocalUser] | None = None,
        runasgroup: str | LocalGroup | list[str | LocalGroup] | None = None,
        order: int | None = None,
        nopasswd: bool | None = None,
    ) -> LocalSudoRule:
        """
        Modify existing Local sudo rule.

        :param user: sudoUser attribute, defaults to None
        :type user: str | LocalUser | LocalGroup | list[str | LocalUser | LocalGroup] | None, optional
        :param host: sudoHost attribute, defaults to None
        :type host: str | list[str] | None, optional
        :param command: sudoCommand attribute defaults to None
        :type command: str | list[str] | None, optional
        :param option: sudoOption attribute, defaults to None
        :type option: str | list[str] | None, optional
        :param runasuser: sudoRunAsUser attribute, defaults to None
        :type runasuser: str | LocalUser | list[str | LocalUser] | None, optional
        :param runasgroup: sudoRunAsGroup attribute, defaults to None
        :type runasgroup: str | LocalGroup | list[str | LocalGroup] | None, optional
        :param order: sudoOrder attribute, defaults to None
        :type order: int | None, optional
        :param nopasswd: If true, no authentication is required (NOPASSWD), defaults to None (no change)
        :type nopasswd: bool | None, optional
        :return:  New sudo rule object.
        :rtype: LocalSudoRule
        """
        self.delete()
        self.add(
            user=user if user is not None else self.__rule.get("user"),
            host=host if host is not None else self.__rule.get("host"),
            command=command if command is not None else self.__rule.get("command"),
            option=option if option is not None else self.__rule.get("option"),
            runasuser=runasuser if runasuser is not None else self.__rule.get("runasuser"),
            runasgroup=runasgroup if runasgroup is not None else self.__rule.get("runasgroup"),
            order=order if order is not None else self.__rule.get("order"),
            nopasswd=nopasswd if nopasswd is not None else self.__rule.get("nopasswd"),
        )
        return self

    def delete(self) -> None:
        """
        Delete local sudo rule.
        """
        if self.filename:
            self.util.fs.rm(f"/etc/sudoers.d/{self.filename}")
        if self in self.util._sudorules:
            self.util._sudorules.remove(self)
