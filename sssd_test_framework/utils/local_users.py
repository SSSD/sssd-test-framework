"Managing local users and groups."

from __future__ import annotations

import re
from typing import Any, Literal

import jc
from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.cli import CLIBuilder, CLIBuilderArgs
from pytest_mh.conn import ProcessLogLevel
from pytest_mh.utils.fs import LinuxFileSystem

from ..roles.generic import GenericNetgroupMember

__all__ = [
    "LocalGroup",
    "LocalUser",
    "LocalUsersUtils",
    "LocalNetgroup",
    "LocalNetgroupMember",
    "LocalSudoAlias",
    "LocalSudoAliasKind",
    "LocalSudoRule",
]

_SUDO_ALIAS_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")

LocalSudoAliasKind = Literal["user", "runas", "host", "command"]


class LocalUsersUtils(MultihostUtility[MultihostHost]):
    """
    Management of local users and groups.

    .. note::

        All changes are automatically reverted when a test is finished.
    """

    def __init__(self, host: MultihostHost, fs: LinuxFileSystem) -> None:
        """
        :param host: Remote host instance.
        :type host: MultihostHost.
        """
        super().__init__(host)

        self.cli: CLIBuilder = host.cli
        self.fs: LinuxFileSystem = fs
        self._users: list[str] = []
        self._groups: list[str] = []
        self._netgroup_baseline: str | None = None
        self._netgroup_initialized: bool = False
        self._netgroup_names_touched: set[str] = set()
        self._netgroups: dict[str, LocalNetgroup] = {}
        self._sudoaliases: list[LocalSudoAlias] = []
        self._sudorules: list[LocalSudoRule] = []

    def teardown(self) -> None:
        """
        Remove local changes made through this utility.

        Deletes added users and groups, removes sudo rules and sudoers aliases
        created under ``/etc/sudoers.d/``, and relies on the filesystem helper's
        backup/restore for ``/etc/netgroup`` and other backed-up paths.
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

        for alias in self._sudoaliases[:]:
            alias.delete()

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
        :type name: str.
        :return: New user object.
        :rtype: LocalUser.
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
        :type name: str.
        :return: New group object.
        :rtype: LocalGroup.
        """
        return LocalGroup(self, name)

    def netgroup(self, name: str) -> LocalNetgroup:
        """
        Get a local netgroup object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.Client)
            def test_example(client: Client):
                ng = client.local.netgroup("ng-1").add()
                ng.add_member(user=client.local.user("u1"))

                result = client.tools.getent.netgroup("ng-1")
                assert result is not None

        :param name: Netgroup name.
        :type name: str.
        :return: Netgroup helper.
        :rtype: LocalNetgroup.
        """
        return LocalNetgroup(self, name)

    def _netgroup_ensure_initialized(self) -> None:
        """
        Ensure ``/etc/netgroup`` is backed up and the pre-test baseline content is cached once.

        No-op if initialization already ran for this utility instance.
        """
        if self._netgroup_initialized:
            return
        self.fs.backup("/etc/netgroup")
        result = self.host.conn.exec(["cat", "/etc/netgroup"], raise_on_error=False)
        self._netgroup_baseline = result.stdout if result.rc == 0 else ""
        self._netgroup_initialized = True

    def _rewrite_netgroup_file(self) -> None:
        """
        Write ``/etc/netgroup`` from the cached baseline, dropping lines for netgroup names this
        utility manages, then appending formatted lines for every registered :class:`LocalNetgroup`.
        """
        self._netgroup_ensure_initialized()
        baseline = self._netgroup_baseline or ""
        lines_out: list[str] = []
        for line in baseline.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                lines_out.append(line)
                continue
            first = stripped.split()[0]
            if first in self._netgroup_names_touched:
                continue
            lines_out.append(line)
        body = "\n".join(lines_out)
        if body and not body.endswith("\n"):
            body += "\n"
        additions: list[str] = []
        for ng in sorted(self._netgroups.values(), key=lambda x: x.name):
            additions.append(ng._format_line())
        addition_str = "\n".join(additions)
        if addition_str:
            addition_str += "\n"
        self.fs.write("/etc/netgroup", body + addition_str)

    def sudoalias(self, name: str, kind: LocalSudoAliasKind) -> LocalSudoAlias:
        """
        Get a sudoers alias object.

        Alias names must match sudoers rules: start with an uppercase letter and contain only
        uppercase letters, digits, and underscores. Define aliases before rules that reference
        them (e.g. write alias files first, or use lower ``order`` values than dependent rules).

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.Client)
            def test_example(client: Client):
                admins = client.local.sudoalias("ADMINS", "user")
                admins.add([client.local.user("u1"), client.local.group("g1")])

                client.local.sudorule("r1").add(user=admins, host="ALL", command="/bin/ls")

        :param name: Alias name (e.g. ``ADMINS``).
        :type name: str.
        :param kind: ``user`` → ``User_Alias``, ``runas`` → ``Runas_Alias``, ``host`` → ``Host_Alias``,
            ``command`` → ``Cmnd_Alias``.
        :type kind: LocalSudoAliasKind.
        :return: Sudo alias helper.
        :rtype: LocalSudoAlias.
        """
        return LocalSudoAlias(self, name, kind)

    def sudorule(self, name: str) -> LocalSudoRule:
        """
        Get a local sudoers rule object.

        :param name: Rule basename (used in the generated filename under ``/etc/sudoers.d/``).
        :type name: str.
        :return: Sudo rule helper.
        :rtype: LocalSudoRule.
        """
        return LocalSudoRule(self, name)


class LocalUser(object):
    """
    Management of local users.
    """

    def __init__(self, util: LocalUsersUtils, name: str) -> None:
        """
        :param util: LocalUsersUtils utility object.
        :type util: LocalUsersUtils.
        :param name: User name.
        :type name: str.
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

        :param uid: User id, defaults to None.
        :type uid: int | None, optional.
        :param gid: Primary group id, defaults to None.
        :type gid: int | None, optional.
        :param password: Password, defaults to 'Secret123'.
        :type password: str, optional.
        :param home: Home directory, defaults to None.
        :type home: str | None, optional.
        :param gecos: GECOS, defaults to None.
        :type gecos: str | None, optional.
        :param shell: Login shell, defaults to None.
        :type shell: str | None, optional.
        :return: Self.
        :rtype: LocalUser.
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

        :param uid: User id, defaults to None.
        :type uid: int | None, optional.
        :param gid: Primary group id, defaults to None.
        :type gid: int | None, optional.
        :param home: Home directory, defaults to None.
        :type home: str | None, optional.
        :param gecos: GECOS, defaults to None.
        :type gecos: str | None, optional.
        :param shell: Login shell, defaults to None.
        :type shell: str | None, optional.
        :return: Self.
        :rtype: LocalUser.
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

        :param attrs: If set, only requested attributes are returned, defaults to None.
        :type attrs: list[str] | None, optional.
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]].
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
        :type util: LocalUsersUtils.
        :param name: Group name.
        :type name: str.
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

        :param gid: Group id, defaults to None.
        :type gid: int | None, optional.
        :return: Self.
        :rtype: LocalGroup.
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

        :param gid: Group id, defaults to None.
        :type gid: int | None, optional.
        :return: Self.
        :rtype: LocalGroup.
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

        :param attrs: If set, only requested attributes are returned, defaults to None.
        :type attrs: list[str] | None, optional.
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]].
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
        :type member: LocalUser.
        :return: Self.
        :rtype: LocalGroup.
        """
        return self.add_members([member])

    def add_members(self, members: list[LocalUser]) -> LocalGroup:
        """
        Add multiple group members.

        :param member: List of users or groups to add as members.
        :type member: list[LocalUser].
        :return: Self.
        :rtype: LocalGroup.
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
        :type member: LocalUser.
        :return: Self.
        :rtype: LocalGroup.
        """
        return self.remove_members([member])

    def remove_members(self, members: list[LocalUser]) -> LocalGroup:
        """
        Remove multiple group members.

        :param member: List of users or groups to remove from the group.
        :type member: list[LocalUser].
        :return: Self.
        :rtype: LocalGroup.
        """
        self.util.logger.info(f'Removing members from group "{self.name}" on {self.util.host.hostname}')

        if not members:
            return self

        cmd = "\n".join([f"groupmems --group '{self.name}' --delete '{x.name}'" for x in members])
        self.util.host.conn.run("set -ex\n" + cmd, log_level=ProcessLogLevel.Error)

        return self


class LocalNetgroupMember(GenericNetgroupMember):
    """
    Local netgroup member (NIS triple and/or nested netgroup).
    """

    def __init__(
        self,
        *,
        host: str | None = None,
        user: LocalUser | str | None = None,
        group: LocalGroup | str | None = None,
        hostgroup: str | None = None,
        ng: LocalNetgroup | str | None = None,
    ) -> None:
        """
        :param host: Host part of the triple, defaults to None.
        :type host: str | None, optional.
        :param user: User part of the triple, defaults to None.
        :type user: LocalUser | str | None, optional.
        :param group: Not supported for local netgroups.
        :type group: LocalGroup | str | None, optional.
        :param hostgroup: Not supported for local netgroups.
        :type hostgroup: str | None, optional.
        :param ng: Nested netgroup, defaults to None.
        :type ng: LocalNetgroup | str | None, optional.

        :raises :class:`ValueError` for unsupported member kinds.
        """
        if group is not None or hostgroup is not None:
            raise ValueError("Local /etc/netgroup netgroups do not support group or hostgroup members.")

        super().__init__(host=host, user=user, ng=ng)

        self.group: str | None = self._get_name(group)
        """Netgroup group (not supported locally)."""

        self.hostgroup: str | None = hostgroup
        """Netgroup hostgroup (not supported locally)."""

    def to_member_string(self) -> str:
        """
        Format this member for ``/etc/netgroup``.

        :return: Triple or nested netgroup name.
        :rtype: str.
        """
        if self.netgroup is not None:
            return self.netgroup

        if self.host is None and self.user is None:
            raise ValueError("Netgroup member must specify host, user, and/or nested netgroup (ng)")

        h = self.host if self.host is not None else "-"
        u = self.user if self.user is not None else "-"
        return f"({h},{u},)"


class LocalNetgroup(object):
    """
    Local netgroup management via.
    """

    def __init__(self, util: LocalUsersUtils, name: str) -> None:
        """
        :param util: LocalUsersUtils utility object.
        :type util: LocalUsersUtils.
        :param name: Netgroup name.
        :type name: str.
        """
        self.util = util
        self.name = name
        self._members: list[str] = []

    def __str__(self) -> str:
        """
        Return the netgroup name.
        """
        return self.name

    def _format_line(self) -> str:
        """
        Build one ``/etc/netgroup`` line: netgroup name, tab, then member tokens (or ``(,,)`` if empty).

        :return: Line without trailing newline.
        :rtype: str.
        """
        if not self._members:
            # Empty triple (,,) — valid NIS form with empty host, user, and domain fields.
            return f"{self.name}\t(,,)"
        return f"{self.name}\t" + " ".join(self._members)

    def add(self) -> LocalNetgroup:
        """
        Create a new netgroup entry.

        :return: Self.
        :rtype: LocalNetgroup.
        :raises: :class:`ValueError` for duplicate names.
        """
        self.util.logger.info(f'Creating local netgroup "{self.name}" on {self.util.host.hostname}')
        existing = self.util._netgroups.get(self.name)
        if existing is not None and existing is not self:
            raise ValueError(
                f'Local netgroup "{self.name}" is already managed by another LocalNetgroup instance; '
                "reuse the object returned from the first client.local.netgroup() call."
            )
        self.util._netgroup_names_touched.add(self.name)
        self.util._netgroups[self.name] = self
        self.util._rewrite_netgroup_file()
        return self

    def add_member(
        self,
        *,
        host: str | None = None,
        user: LocalUser | str | None = None,
        group: LocalGroup | str | None = None,
        hostgroup: str | None = None,
        ng: LocalNetgroup | str | None = None,
    ) -> LocalNetgroup:
        """
        Add a netgroup member.

        :return: Self.
        :rtype: LocalNetgroup.
        """
        return self.add_members([LocalNetgroupMember(host=host, user=user, group=group, hostgroup=hostgroup, ng=ng)])

    def add_members(self, members: list[LocalNetgroupMember]) -> LocalNetgroup:
        """
        Add multiple netgroup members.

        Duplicate member strings are not allowed in ``/etc/netgroup``: each line must be unique.
        Members are compared by :meth:`LocalNetgroupMember.to_member_string`; if that string is
        already in this netgroup or appears more than once in ``members``, later duplicates are
        skipped (nothing is appended for them).

        :param members: Netgroup members.
        :type members: list[LocalNetgroupMember].
        :return: Self.
        :rtype: LocalNetgroup.
        """
        self.util.logger.info(f'Adding members to local netgroup "{self.name}" on {self.util.host.hostname}')

        if not members:
            return self

        if self.name not in self.util._netgroups:
            raise RuntimeError(f'Netgroup "{self.name}" was not created; call add() first')

        for m in members:
            line = m.to_member_string()
            if line in self._members:
                continue
            self._members.append(line)
        self.util._rewrite_netgroup_file()
        return self

    def remove_member(
        self,
        *,
        host: str | None = None,
        user: LocalUser | str | None = None,
        group: LocalGroup | str | None = None,
        hostgroup: str | None = None,
        ng: "LocalNetgroup | str | None" = None,
    ) -> LocalNetgroup:
        """
        Remove a netgroup member.

        :return: Self.
        :rtype: LocalNetgroup.
        """
        return self.remove_members(
            [LocalNetgroupMember(host=host, user=user, group=group, hostgroup=hostgroup, ng=ng)]
        )

    def remove_members(self, members: list[LocalNetgroupMember]) -> LocalNetgroup:
        """
        Remove netgroup members.

        :param members: Members to remove.
        :type members: list[LocalNetgroupMember].
        :return: Self.
        :rtype: LocalNetgroup.
        """
        self.util.logger.info(f'Removing members from local netgroup "{self.name}" on {self.util.host.hostname}')

        if not members:
            return self

        if self.name not in self.util._netgroups:
            raise RuntimeError(f'Netgroup "{self.name}" was not  created; call add() first')

        remove_strings = {m.to_member_string() for m in members}
        self._members = [x for x in self._members if x not in remove_strings]
        self.util._rewrite_netgroup_file()
        return self

    def delete(self) -> None:
        """
        Remove this netgroup from ``/etc/netgroup``.
        """
        self.util.logger.info(f'Deleting local netgroup "{self.name}" on {self.util.host.hostname}')
        self.util._netgroup_names_touched.add(self.name)
        if self.name in self.util._netgroups:
            del self.util._netgroups[self.name]
        self._members.clear()
        self.util._rewrite_netgroup_file()


class LocalSudoAlias(object):
    """
    Local sudoers alias (``User_Alias``, ``Runas_Alias``, ``Host_Alias``, or ``Cmnd_Alias``).
    """

    _KEYWORD: dict[LocalSudoAliasKind, str] = {
        "user": "User_Alias",
        "runas": "Runas_Alias",
        "host": "Host_Alias",
        "command": "Cmnd_Alias",
    }

    def __init__(self, util: LocalUsersUtils, name: str, kind: LocalSudoAliasKind) -> None:
        """
        :param util: LocalUsersUtils utility object.
        :type util: LocalUsersUtils.
        :param name: Alias name (uppercase; see sudoers(5)).
        :type name: str.
        :param kind: Which alias type to write.
        :type kind: LocalSudoAliasKind.
        """
        if not _SUDO_ALIAS_NAME.match(name):
            raise ValueError(f'Invalid sudoers alias name "{name}": must match ^[A-Z][A-Z0-9_]*$ (see sudoers(5))')
        self.util = util
        self.name = name
        self.kind = kind
        self.filename: str | None = None
        self.alias_str: str | None = None
        self.__members: Any = None
        self._order: int | None = None

    def __str__(self) -> str:
        """
        Return the alias name.
        """
        return self.name

    @staticmethod
    def _format_member(kind: LocalSudoAliasKind, item: str | LocalUser | LocalGroup) -> str:
        """
        Format one sudoers alias member for the RHS of ``Alias = …``.

        For ``user`` and ``runas`` aliases, a :class:`LocalGroup` is written as ``%groupname``;
        users and raw strings are written with :func:`str`. For ``host`` and ``command`` aliases,
        ``item`` is stringified as-is (callers pass hostnames or command paths as appropriate).

        :param kind: Which alias type is being built.
        :type kind: LocalSudoAliasKind.
        :param item: Single member value.
        :type item: str | LocalUser | LocalGroup.
        :return: Fragment suitable inside the comma-separated member list.
        :rtype: str.
        """
        if kind in ("user", "runas"):
            if isinstance(item, LocalGroup):
                return f"%{item.name}"
            return str(item)
        return str(item)

    @classmethod
    def _format_members(
        cls,
        kind: LocalSudoAliasKind,
        members: str | LocalUser | LocalGroup | list[str | LocalUser | LocalGroup],
    ) -> str:
        """
        Format ``members`` for the RHS of a sudoers alias line.

        A single value is passed through :meth:`_format_member`. A list must be non-empty; entries
        are formatted and joined into a comma-separated list.

        :param kind: Alias type (controls how users vs. groups are written).
        :type kind: LocalSudoAliasKind.
        :param members: One member or a non-empty list of members.
        :type members: str | LocalUser | LocalGroup | list[str | LocalUser | LocalGroup].
        :return: Comma-separated sudoers fragment.
        :rtype: str.
        :raises: :class:`ValueError` if ``members`` is an empty list.
        """
        if isinstance(members, list):
            if not members:
                raise ValueError("sudoers alias member list must not be empty")
            return ", ".join(cls._format_member(kind, x) for x in members)
        return cls._format_member(kind, members)

    def add(
        self,
        members: str | LocalUser | LocalGroup | list[str | LocalUser | LocalGroup],
        *,
        order: int | None = None,
    ) -> LocalSudoAlias:
        """
        Write the alias line to ``/etc/sudoers.d/``.

        :param members: One or more users/groups (for ``user`` / ``runas``), hostnames (for ``host``),
            or commands (for ``command``).
        :type members: str | LocalUser | LocalGroup | list[str | LocalUser | LocalGroup].
        :param order: Optional ordering prefix for the drop-in file name (lower sorts first).
        :type order: int | None, optional.
        :return: Self.
        :rtype: LocalSudoAlias.

        After :meth:`delete`, ``filename`` is unset and a **new** name is chosen here; see the class
        docstring.
        """
        self._order = order
        orderstr = f"{order:02d}" if order is not None else f"{len(self.util._sudoaliases):02d}"
        if self.filename is None:
            self.filename = f"{orderstr}_alias_{self.kind}_{self.name}"

        self.__members = members
        keyword = self._KEYWORD[self.kind]
        body = self._format_members(self.kind, members)
        self.alias_str = f"{keyword} {self.name} = {body}\n"
        self.util.fs.write(f"/etc/sudoers.d/{self.filename}", self.alias_str)
        if self not in self.util._sudoaliases:
            self.util._sudoaliases.append(self)
        return self

    def modify(
        self,
        members: str | LocalUser | LocalGroup | list[str | LocalUser | LocalGroup] | None = None,
        *,
        order: int | None = None,
    ) -> LocalSudoAlias:
        """
        Replace alias members (and optionally the file order prefix).

        :param members: New member list, defaults to None (keep previous).
        :type members: str | LocalUser | LocalGroup | list[str | LocalUser | LocalGroup] | None, optional.
        :param order: Optional ordering prefix for the drop-in file name.
        :type order: int | None, optional
        :return: Self.
        :rtype: LocalSudoAlias.
        """
        prev_order = self._order
        self.delete()
        return self.add(
            members if members is not None else self.__members,
            order=order if order is not None else prev_order,
        )

    def delete(self) -> None:
        """
        Remove this alias drop-in file.

        Clears the stored file name so a later :meth:`add` picks a new path; see the class
        docstring.
        """
        if self.filename:
            self.util.fs.rm(f"/etc/sudoers.d/{self.filename}")
        self.filename = None
        self.alias_str = None
        self._order = None
        if self in self.util._sudoaliases:
            self.util._sudoaliases.remove(self)


LocalSudoRuleUserPiece = str | LocalUser | LocalGroup | LocalSudoAlias
LocalSudoRuleUserArg = LocalSudoRuleUserPiece | list[LocalSudoRuleUserPiece]
LocalSudoRuleHostArg = str | LocalSudoAlias | list[str | LocalSudoAlias]
LocalSudoRuleCommandArg = str | LocalSudoAlias | list[str | LocalSudoAlias]
LocalSudoRuleRunAsUserArg = str | LocalUser | LocalSudoAlias | list[str | LocalUser | LocalSudoAlias]
LocalSudoRuleRunAsGroupArg = str | LocalGroup | LocalSudoAlias | list[str | LocalGroup | LocalSudoAlias]


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
        :type name: str.
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
    def _format_list_item(item: str | Any, add_percent: bool = False) -> str:
        """
        Format a single sudoers list element.

        :param item: String, :class:`LocalUser`, :class:`LocalGroup`, or :class:`LocalSudoAlias`.
        :type item: str | Any.
        :param add_percent: If true, prepend ``%`` to :class:`LocalGroup` entries.
        :type add_percent: bool, optional.
        :return: Formatted fragment.
        :rtype: str.
        """
        if isinstance(item, LocalSudoAlias):
            return item.name
        if isinstance(item, LocalGroup) and add_percent:
            return f"%{str(item)}"
        return str(item)

    @staticmethod
    def _format_list(item: str | Any | list[str | Any], add_percent: bool = False) -> str:
        """
        Format the item as a comma-separated sudoers list.

        :param item: A single value or list of values to format.
        :type item: str | Any | list[str | Any].
        :param add_percent: If true, prepend ``%`` to :class:`LocalGroup` entries (sudo user field).
        :type add_percent: bool, optional.
        :return: Formatted string.
        :rtype: str.
        """
        if isinstance(item, list):
            return ", ".join(LocalSudoRule._format_list_item(x, add_percent) for x in item)
        return LocalSudoRule._format_list_item(item, add_percent)

    def add(
        self,
        *,
        user: LocalSudoRuleUserArg | None = default_user,
        host: LocalSudoRuleHostArg | None = default_host,
        command: LocalSudoRuleCommandArg | None = default_command,
        option: str | list[str] | None = None,
        runasuser: LocalSudoRuleRunAsUserArg | None = None,
        runasgroup: LocalSudoRuleRunAsGroupArg | None = None,
        order: int | None = None,
        nopasswd: bool | None = None,
    ) -> LocalSudoRule:
        """
        Create new sudo rule.

        :param user: sudoUser attribute, defaults to ALL.
        :type user: LocalSudoRuleUserArg | None.
        :param host: sudoHost attribute, defaults to ALL.
        :type host: LocalSudoRuleHostArg | None.
        :param command: sudoCommand attribute, defaults to ALL.
        :type command: LocalSudoRuleCommandArg | None.
        :param option: sudoOption attribute, defaults to None.
        :type option: str | list[str] | None, optional.
        :param runasuser: sudoRunAsUser attribute, defaults to None.
        :type runasuser: LocalSudoRuleRunAsUserArg | None, optional.
        :param runasgroup: sudoRunAsGroup attribute, defaults to None.
        :type runasgroup: LocalSudoRuleRunAsGroupArg | None, optional.
        :param order: sudoOrder attribute, defaults to None.
        :type order: int | None, optional.
        :param nopasswd: If true, no authentication is required (NOPASSWD), defaults to None (no change)
        :type nopasswd: bool | None, optional.
        :return: New sudo rule object.
        :rtype: LocalSudoRule.
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
        user: LocalSudoRuleUserArg | None = None,
        host: LocalSudoRuleHostArg | None = None,
        command: LocalSudoRuleCommandArg | None = None,
        option: str | list[str] | None = None,
        runasuser: LocalSudoRuleRunAsUserArg | None = None,
        runasgroup: LocalSudoRuleRunAsGroupArg | None = None,
        order: int | None = None,
        nopasswd: bool | None = None,
    ) -> LocalSudoRule:
        """
        Modify existing Local sudo rule.

        :param user: sudoUser attribute, defaults to None.
        :type user: LocalSudoRuleUserArg | None, optional.
        :param host: sudoHost attribute, defaults to None.
        :type host: LocalSudoRuleHostArg | None, optional.
        :param command: sudoCommand attribute defaults to None.
        :type command: LocalSudoRuleCommandArg | None, optional.
        :param option: sudoOption attribute, defaults to None.
        :type option: str | list[str] | None, optional.
        :param runasuser: sudoRunAsUser attribute, defaults to None.
        :type runasuser: LocalSudoRuleRunAsUserArg | None, optional.
        :param runasgroup: sudoRunAsGroup attribute, defaults to None.
        :type runasgroup: LocalSudoRuleRunAsGroupArg | None, optional.
        :param order: sudoOrder attribute, defaults to None.
        :type order: int | None, optional.
        :param nopasswd: If true, no authentication is required (NOPASSWD), defaults to None (no change).
        :type nopasswd: bool | None, optional.
        :return:  New sudo rule object.
        :rtype: LocalSudoRule.
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
