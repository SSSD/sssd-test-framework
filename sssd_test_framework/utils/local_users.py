"Managing local users and groups."

from __future__ import annotations

import re
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal

import jc
from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.cli import CLIBuilder, CLIBuilderArgs
from pytest_mh.conn import ProcessLogLevel
from pytest_mh.utils.fs import LinuxFileSystem

from ..roles.generic import (
    GenericGroup,
    GenericNetgroup,
    GenericNetgroupMember,
    GenericSudoRule,
    GenericUser,
    SudoRuleCommandField,
    SudoRuleHostField,
    SudoRuleRunAsGroupField,
    SudoRuleRunAsUserField,
    SudoRuleUserField,
)

if TYPE_CHECKING:
    from ..roles.client import Client

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

    def __init__(self, host: MultihostHost, fs: LinuxFileSystem, client: Client | None = None) -> None:
        """
        :param host: Remote host instance.
        :type host: MultihostHost
        :param client: Client role that owns this utility.
        :type client: Client | None
        """
        super().__init__(host)

        self._client: Client | None = client
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
        :type name: str
        :return: Netgroup helper.
        :rtype: LocalNetgroup
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
        :type name: str
        :param kind: ``user`` → ``User_Alias``, ``runas`` → ``Runas_Alias``, ``host`` → ``Host_Alias``,
            ``command`` → ``Cmnd_Alias``.
        :type kind: LocalSudoAliasKind
        :return: Sudo alias helper.
        :rtype: LocalSudoAlias
        """
        return LocalSudoAlias(self, name, kind)

    def sudorule(self, name: str) -> LocalSudoRule:
        """
        Get a local sudoers rule object.

        :param name: Rule basename (used in the generated filename under ``/etc/sudoers.d/``).
        :type name: str
        :return: Sudo rule helper.
        :rtype: LocalSudoRule
        """
        return LocalSudoRule(self, name)


class LocalUser(GenericUser):
    """
    Management of local users.

    :class:`LocalUser` is a :class:`GenericUser` for static typing; passkey-related
    methods are not supported on local ``/etc/passwd`` users.
    """

    def __init__(self, util: LocalUsersUtils, name: str) -> None:
        """
        :param util: LocalUsersUtils utility object.
        :type util: LocalUsersUtils
        :param name: User name.
        :type name: str
        """
        if util._client is None:
            raise RuntimeError("LocalUser requires LocalUsersUtils to be bound to a Client (client= in constructor).")
        super().__init__(util._client)
        self.util: LocalUsersUtils = util
        self._name: str = name

    @property
    def name(self) -> str:
        return self._name

    def __str__(self) -> str:
        """
        Returns a string representation of the LocalUser.
        """
        return self._name

    def add(
        self,
        *,
        uid: int | None = None,
        gid: int | None = None,
        password: str = "Secret123",
        home: str | None = None,
        gecos: str | None = None,
        shell: str | None = None,
        email: str | None = None,
    ) -> LocalUser:
        """
        Create new local user.

        :param uid: User id, defaults to None.
        :type uid: int | None, optional
        :param gid: Primary group id, defaults to None.
        :type gid: int | None, optional
        :param password: Password, defaults to 'Secret123' (use empty string to skip ``passwd``).
        :type password: str, optional
        :param home: Home directory, defaults to None.
        :type home: str | None, optional
        :param gecos: GECOS, defaults to None.
        :type gecos: str | None, optional
        :param shell: Login shell, defaults to None.
        :type shell: str | None, optional
        :param email: Not applied to local users (present for :class:`GenericUser` API compatibility).
        :type email: str | None, optional
        :return: Self.
        :rtype: LocalUser
        """
        del email  # Local /etc/passwd user management does not set a mail attribute here.
        if home is not None:
            self.util.fs.backup(home)

        args: CLIBuilderArgs = {
            "name": (self.util.cli.option.POSITIONAL, self._name),
            "uid": (self.util.cli.option.VALUE, uid),
            "gid": (self.util.cli.option.VALUE, gid),
            "home": (self.util.cli.option.VALUE, home),
            "gecos": (self.util.cli.option.VALUE, gecos),
            "shell": (self.util.cli.option.VALUE, shell),
        }

        passwd = f" && passwd --stdin '{self._name}'" if password else ""
        self.util.logger.info(f'Creating local user "{self._name}" on {self.util.host.hostname}')
        self.util.host.conn.run(
            self.util.cli.command("useradd", args) + passwd, input=password, log_level=ProcessLogLevel.Error
        )

        self.util._users.append(self._name)
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
        email: str | None = None,
    ) -> LocalUser:
        """
        Modify existing local user.

        Parameters that are not set are ignored.

        :param uid: User id, defaults to None.
        :type uid: int | None, optional
        :param gid: Primary group id, defaults to None.
        :type gid: int | None, optional
        :param home: Home directory, defaults to None.
        :type home: str | None, optional
        :param gecos: GECOS, defaults to None.
        :type gecos: str | None, optional
        :param shell: Login shell, defaults to None.
        :type shell: str | None, optional
        :param email: Not applied to local users (present for :class:`GenericUser` API compatibility).
        :type email: str | None, optional
        :return: Self.
        :rtype: LocalUser
        """
        del email  # Local /etc/passwd user management does not set a mail attribute here.

        args: CLIBuilderArgs = {
            "name": (self.util.cli.option.POSITIONAL, self._name),
            "uid": (self.util.cli.option.VALUE, uid),
            "gid": (self.util.cli.option.VALUE, gid),
            "home": (self.util.cli.option.VALUE, home),
            "gecos": (self.util.cli.option.VALUE, gecos),
            "shell": (self.util.cli.option.VALUE, shell),
        }

        passwd = f" && passwd --stdin '{self._name}'" if password else ""
        self.util.logger.info(f'Modifying local user "{self._name}" on {self.util.host.hostname}')
        self.util.host.conn.run(
            self.util.cli.command("usermod", args) + passwd, input=password, log_level=ProcessLogLevel.Error
        )

        return self

    def reset(self, password: str | None = "Secret123") -> LocalUser:
        """
        Reset user password.

        :param password: Password, defaults to 'Secret123'
        :type password: str, optional
        :return: Self.
        :rtype: LocalUser
        """
        return self.modify(password=password)

    def expire(self, expiration: str | None = "19700101000000") -> LocalUser:
        """
        Set user password expiration date and time (via ``chage -E``).

        :param expiration: Date and time for user password expiration, defaults to 19700101000000
        :type expiration: str | None, optional
        :return: Self.
        :rtype: LocalUser
        """
        exp = expiration if expiration is not None else "19700101000000"
        end = datetime.strptime(exp, "%Y%m%d%H%M%S")
        date_str = end.strftime("%Y-%m-%d")
        self.util.logger.info(
            f'Setting password expiration for local user "{self._name}" on {self.util.host.hostname}'
        )
        self.util.host.conn.run(f"chage -E '{date_str}' '{self._name}'", log_level=ProcessLogLevel.Error)
        return self

    def password_change_at_logon(self, **kwargs) -> LocalUser:
        """
        Force user to change password next logon (``chage -d 0`` and password reset).

        :return: Self.
        :rtype: LocalUser
        """
        if "password" not in kwargs:
            raise TypeError("Missing argument 'password'!")
        self.modify(password=kwargs["password"])
        self.util.logger.info(
            f'Requiring password change at next logon for local user "{self._name}" on {self.util.host.hostname}'
        )
        self.util.host.conn.run(f"chage -d 0 '{self._name}'", log_level=ProcessLogLevel.Error)
        return self

    def passkey_add(self, passkey_mapping: str) -> LocalUser:
        """
        Add passkey mapping to the user.

        :raises NotImplementedError: Not supported for local users.
        """
        raise NotImplementedError("LocalUser does not support passkey_add; use a directory-backed user.")

    def passkey_remove(self, passkey_mapping: str) -> LocalUser:
        """
        Remove passkey mapping from the user.

        :raises NotImplementedError: Not supported for local users.
        """
        raise NotImplementedError("LocalUser does not support passkey_remove; use a directory-backed user.")

    def delete(self) -> None:
        """
        Delete the user.
        """
        self.util.logger.info(f'Deleting local user "{self._name}" on {self.util.host.hostname}')
        self.util.host.conn.run(f"userdel '{self._name}' --force --remove", log_level=ProcessLogLevel.Error)
        self.util._users.remove(self._name)

    def get(self, attrs: list[str] | None = None) -> dict[str, list[str]]:
        """
        Get user attributes.

        :param attrs: If set, only requested attributes are returned, defaults to None.
        :type attrs: list[str] | None, optional
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]]
        """
        self.util.logger.info(f'Fetching local user "{self._name}" on {self.util.host.hostname}')
        result = self.util.host.conn.exec(
            ["getent", "passwd", self._name], raise_on_error=False, log_level=ProcessLogLevel.Error
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


class LocalGroup(GenericGroup):
    """
    Management of local groups.

    :class:`LocalGroup` is a :class:`GenericGroup` for static typing. Membership
    changes only accept :class:`LocalUser` and :class:`LocalGroup`; directory
    principals are not valid members of ``/etc/group``.
    """

    def __init__(self, util: LocalUsersUtils, name: str) -> None:
        """
        :param util: LocalUsersUtils utility object.
        :type util: LocalUsersUtils
        :param name: Group name.
        :type name: str
        """
        if util._client is None:
            raise RuntimeError("LocalGroup requires LocalUsersUtils to be bound to a Client (client= in constructor).")
        super().__init__(util._client)
        self.util: LocalUsersUtils = util
        self._name: str = name

    @property
    def name(self) -> str:
        return self._name

    def __str__(self) -> str:
        """
        Returns a string representation of the LocalGroup.
        """
        return self._name

    @staticmethod
    def _member_principal_name(member: GenericUser | GenericGroup) -> str:
        """
        Resolve a member to a local ``passwd``/``group`` name.

        :raises NotImplementedError: if ``member`` is not a local user or local group.
        """
        if isinstance(member, (LocalUser, LocalGroup)):
            return member.name
        raise NotImplementedError(
            "LocalGroup membership only supports LocalUser and LocalGroup; use directory-specific APIs otherwise."
        )

    def add(
        self,
        *,
        gid: int | None = None,
        description: str | None = None,
    ) -> LocalGroup:
        """
        Create new local group.

        :param gid: Group id, defaults to None.
        :type gid: int | None, optional
        :param description: Not stored for pure local groups (present for :class:`GenericGroup` API compatibility).
        :type description: str | None, optional
        :return: Self.
        :rtype: LocalGroup
        """
        del description  # No description field in /etc/group via this API.
        args: CLIBuilderArgs = {
            "name": (self.util.cli.option.POSITIONAL, self._name),
            "gid": (self.util.cli.option.VALUE, gid),
        }

        self.util.logger.info(f'Creating local group "{self._name}" on {self.util.host.hostname}')
        self.util.host.conn.run(self.util.cli.command("groupadd", args), log_level=ProcessLogLevel.Silent)
        self.util._groups.append(self._name)

        return self

    def modify(
        self,
        *,
        gid: int | None = None,
        description: str | None = None,
    ) -> LocalGroup:
        """
        Modify existing local group.

        Parameters that are not set are ignored.

        :param gid: Group id, defaults to None.
        :type gid: int | None, optional
        :param description: Not stored for pure local groups (present for :class:`GenericGroup` API compatibility).
        :type description: str | None, optional
        :return: Self.
        :rtype: LocalGroup
        """
        del description  # No description field in /etc/group via this API.

        args: CLIBuilderArgs = {
            "name": (self.util.cli.option.POSITIONAL, self._name),
            "gid": (self.util.cli.option.VALUE, gid),
        }

        self.util.logger.info(f'Modifying local group "{self._name}" on {self.util.host.hostname}')
        self.util.host.conn.run(self.util.cli.command("groupmod", args), log_level=ProcessLogLevel.Error)

        return self

    def delete(self) -> None:
        """
        Delete the group.
        """
        self.util.logger.info(f'Deleting local group "{self._name}" on {self.util.host.hostname}')
        self.util.host.conn.run(f"groupdel '{self._name}' -f", log_level=ProcessLogLevel.Error)
        self.util._groups.remove(self._name)

    def get(self, attrs: list[str] | None = None) -> dict[str, list[str]]:
        """
        Get group attributes.

        :param attrs: If set, only requested attributes are returned, defaults to None.
        :type attrs: list[str] | None, optional
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]]
        """
        self.util.logger.info(f'Fetching local group "{self._name}" on {self.util.host.hostname}')
        result = self.util.host.conn.exec(
            ["getent", "group", self._name], raise_on_error=False, log_level=ProcessLogLevel.Silent
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

    def add_member(self, member: GenericUser | GenericGroup) -> LocalGroup:
        """
        Add group member.

        :param member: User or group to add as a member.
        :type member: GenericUser | GenericGroup
        :return: Self.
        :rtype: LocalGroup
        """
        return self.add_members([member])

    def add_members(self, members: list[GenericUser | GenericGroup]) -> LocalGroup:
        """
        Add multiple group members.

        :param members: List of users or groups to add as members.
        :type members: list[GenericUser | GenericGroup]
        :return: Self.
        :rtype: LocalGroup
        """
        self.util.logger.info(f'Adding members to group "{self._name}" on {self.util.host.hostname}')

        if not members:
            return self

        cmd = "\n".join(
            [f"groupmems --group '{self._name}' --add '{self._member_principal_name(x)}'" for x in members]
        )
        self.util.host.conn.run("set -ex\n" + cmd, log_level=ProcessLogLevel.Error)

        return self

    def remove_member(self, member: GenericUser | GenericGroup) -> LocalGroup:
        """
        Remove group member.

        :param member: User or group to remove from the group.
        :type member: GenericUser | GenericGroup
        :return: Self.
        :rtype: LocalGroup
        """
        return self.remove_members([member])

    def remove_members(self, members: list[GenericUser | GenericGroup]) -> LocalGroup:
        """
        Remove multiple group members.

        :param members: List of users or groups to remove from the group.
        :type members: list[GenericUser | GenericGroup]
        :return: Self.
        :rtype: LocalGroup
        """
        self.util.logger.info(f'Removing members from group "{self._name}" on {self.util.host.hostname}')

        if not members:
            return self

        cmd = "\n".join(
            [f"groupmems --group '{self._name}' --delete '{self._member_principal_name(x)}'" for x in members]
        )
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
        user: GenericUser | str | None = None,
        group: LocalGroup | str | None = None,
        hostgroup: str | None = None,
        ng: GenericNetgroup | str | None = None,
    ) -> None:
        """
        :param host: Host part of the triple, defaults to None.
        :type host: str | None, optional
        :param user: User part of the triple, defaults to None.
        :type user: GenericUser | str | None, optional
        :param group: Not supported for local netgroups.
        :type group: LocalGroup | str | None, optional
        :param hostgroup: Not supported for local netgroups.
        :type hostgroup: str | None, optional
        :param ng: Nested netgroup, defaults to None.
        :type ng: GenericNetgroup | str | None, optional

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
        :rtype: str
        """
        if self.netgroup is not None:
            return self.netgroup

        if self.host is None and self.user is None:
            raise ValueError("Netgroup member must specify host, user, and/or nested netgroup (ng)")

        h = self.host if self.host is not None else "-"
        u = self.user if self.user is not None else "-"
        return f"({h},{u},)"


class LocalNetgroup(GenericNetgroup):
    """
    Local netgroup management via ``/etc/netgroup``.

    :class:`LocalNetgroup` is a :class:`GenericNetgroup` for static typing. Only
    :class:`LocalNetgroupMember` instances are supported in :meth:`add_members`
    and :meth:`remove_members` (not arbitrary :class:`GenericNetgroupMember`
    subclasses from other backends).
    """

    def __init__(self, util: LocalUsersUtils, name: str) -> None:
        """
        :param util: LocalUsersUtils utility object.
        :type util: LocalUsersUtils
        :param name: Netgroup name.
        :type name: str
        """
        if util._client is None:
            raise RuntimeError(
                "LocalNetgroup requires LocalUsersUtils to be bound to a Client (client= in constructor)."
            )
        super().__init__(util._client)
        self.util: LocalUsersUtils = util
        self._name: str = name
        self._members: list[str] = []

    @property
    def name(self) -> str:
        return self._name

    def __str__(self) -> str:
        """
        Return the netgroup name.
        """
        return self._name

    def _format_line(self) -> str:
        """
        Build one ``/etc/netgroup`` line: netgroup name, tab, then member tokens (or ``(,,)`` if empty).

        :return: Line without trailing newline.
        :rtype: str
        """
        if not self._members:
            # Empty triple (,,) — valid NIS form with empty host, user, and domain fields.
            return f"{self._name}\t(,,)"
        return f"{self._name}\t" + " ".join(self._members)

    def add(self) -> LocalNetgroup:
        """
        Create a new netgroup entry.

        :return: Self.
        :rtype: LocalNetgroup
        :raises: :class:`ValueError` for duplicate names.
        """
        self.util.logger.info(f'Creating local netgroup "{self._name}" on {self.util.host.hostname}')
        existing = self.util._netgroups.get(self._name)
        if existing is not None and existing is not self:
            raise ValueError(
                f'Local netgroup "{self._name}" is already managed by another LocalNetgroup instance; '
                "reuse the object returned from the first client.local.netgroup() call."
            )
        self.util._netgroup_names_touched.add(self._name)
        self.util._netgroups[self._name] = self
        self.util._rewrite_netgroup_file()
        return self

    def get(self, attrs: list[str] | None = None) -> dict[str, list[str]]:
        """
        Get netgroup data from ``getent netgroup`` (reflecting ``/etc/netgroup``).

        Keys include ``cn`` (netgroup name) and ``nisNetgroupTriple`` (member tokens).
        """
        self.util.logger.info(f'Fetching local netgroup "{self._name}" on {self.util.host.hostname}')
        result = self.util.host.conn.exec(
            ["getent", "netgroup", self._name], raise_on_error=False, log_level=ProcessLogLevel.Silent
        )
        if result.rc != 0:
            return {}

        line = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
        if not line:
            return {}

        tokens = line.split()
        if not tokens or tokens[0] != self._name:
            return {}

        triples = tokens[1:]
        out: dict[str, list[str]] = {"cn": [self._name], "nisNetgroupTriple": triples}
        if attrs is None:
            return out
        return {k: v for k, v in out.items() if k in attrs}

    def add_member(
        self,
        *,
        host: str | None = None,
        user: GenericUser | str | None = None,
        ng: GenericNetgroup | str | None = None,
    ) -> LocalNetgroup:
        """
        Add a netgroup member.

        :return: Self.
        :rtype: LocalNetgroup
        """
        return self.add_members([LocalNetgroupMember(host=host, user=user, ng=ng)])

    def add_members(self, members: list[GenericNetgroupMember]) -> LocalNetgroup:
        """
        Add multiple netgroup members.

        Duplicate member strings are not allowed in ``/etc/netgroup``: each line must be unique.
        Members are compared by :meth:`LocalNetgroupMember.to_member_string`; if that string is
        already in this netgroup or appears more than once in ``members``, later duplicates are
        skipped (nothing is appended for them).

        :param members: Netgroup members (must be :class:`LocalNetgroupMember`).
        :type members: list[GenericNetgroupMember]
        :return: Self.
        :rtype: LocalNetgroup
        """
        self.util.logger.info(f'Adding members to local netgroup "{self._name}" on {self.util.host.hostname}')

        if not members:
            return self

        if self._name not in self.util._netgroups:
            raise RuntimeError(f'Netgroup "{self._name}" was not created; call add() first')

        for m in members:
            if not isinstance(m, LocalNetgroupMember):
                raise TypeError("Local netgroups only accept LocalNetgroupMember entries.")
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
        user: GenericUser | str | None = None,
        ng: GenericNetgroup | str | None = None,
    ) -> LocalNetgroup:
        """
        Remove a netgroup member.

        :return: Self.
        :rtype: LocalNetgroup
        """
        return self.remove_members([LocalNetgroupMember(host=host, user=user, ng=ng)])

    def remove_members(self, members: list[GenericNetgroupMember]) -> LocalNetgroup:
        """
        Remove netgroup members.

        :param members: Members to remove (must be :class:`LocalNetgroupMember`).
        :type members: list[GenericNetgroupMember]
        :return: Self.
        :rtype: LocalNetgroup
        """
        self.util.logger.info(f'Removing members from local netgroup "{self._name}" on {self.util.host.hostname}')

        if not members:
            return self

        if self._name not in self.util._netgroups:
            raise RuntimeError(f'Netgroup "{self._name}" was not created; call add() first')

        local_members: list[LocalNetgroupMember] = []
        for m in members:
            if not isinstance(m, LocalNetgroupMember):
                raise TypeError("Local netgroups only accept LocalNetgroupMember entries.")
            local_members.append(m)

        remove_strings = {m.to_member_string() for m in local_members}
        self._members = [x for x in self._members if x not in remove_strings]
        self.util._rewrite_netgroup_file()
        return self

    def delete(self) -> None:
        """
        Remove this netgroup from ``/etc/netgroup``.
        """
        self.util.logger.info(f'Deleting local netgroup "{self._name}" on {self.util.host.hostname}')
        self.util._netgroup_names_touched.add(self._name)
        if self._name in self.util._netgroups:
            del self.util._netgroups[self._name]
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
        :type util: LocalUsersUtils
        :param name: Alias name (uppercase; see sudoers(5)).
        :type name: str
        :param kind: Which alias type to write.
        :type kind: LocalSudoAliasKind
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
        :type kind: LocalSudoAliasKind
        :param item: Single member value.
        :type item: str | LocalUser | LocalGroup
        :return: Fragment suitable inside the comma-separated member list.
        :rtype: str
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
        :type kind: LocalSudoAliasKind
        :param members: One member or a non-empty list of members.
        :type members: str | LocalUser | LocalGroup | list[str | LocalUser | LocalGroup]
        :return: Comma-separated sudoers fragment.
        :rtype: str
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
        :type members: str | LocalUser | LocalGroup | list[str | LocalUser | LocalGroup]
        :param order: Optional ordering prefix for the drop-in file name (lower sorts first).
        :type order: int | None, optional
        :return: Self.
        :rtype: LocalSudoAlias

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
        :type members: str | LocalUser | LocalGroup | list[str | LocalUser | LocalGroup] | None, optional
        :param order: Optional ordering prefix for the drop-in file name.
        :type order: int | None, optional
        :return: Self.
        :rtype: LocalSudoAlias
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


class LocalSudoRule(GenericSudoRule):
    """
    Local sudo rule management (``/etc/sudoers.d/`` drop-ins).

    See :class:`GenericSudoRule` for parameter meanings. ``ProtocolName`` values
    (including :class:`LocalSudoAlias`) are emitted as bare sudoers names.
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
        if util._client is None:
            raise RuntimeError(
                "LocalSudoRule requires LocalUsersUtils to be bound to a Client (client= in constructor)."
            )
        super().__init__(util._client)
        self._name: str = name
        self.util: LocalUsersUtils = util
        self.__rule: dict[str, Any] = dict()
        self.filename: str | None = None
        self.rule_str: str | None = None

    @property
    def name(self) -> str:
        return self._name

    def __str__(self) -> str:
        """
        Returns a string representation of the LocalSudoRule.
        """
        if self.rule_str:
            return self.rule_str
        return self._name

    @staticmethod
    def _format_list_item(item: str | Any, add_percent: bool = False) -> str:
        """
        Format a single sudoers list element.

        :param item: String, user/group, or name reference (e.g. :class:`LocalSudoAlias`).
        :type item: str | Any
        :param add_percent: If true, prepend ``%`` to :class:`GenericGroup` entries.
        :type add_percent: bool, optional
        :return: Formatted fragment.
        :rtype: str
        """
        if isinstance(item, LocalSudoAlias):
            return item.name
        if isinstance(item, GenericGroup) and add_percent:
            return f"%{item.name}"
        return str(item)

    @staticmethod
    def _format_list(item: str | Any | list[str | Any], add_percent: bool = False) -> str:
        """
        Format the item as a comma-separated sudoers list.

        :param item: A single value or list of values to format.
        :type item: str | Any | list[str | Any]
        :param add_percent: If true, prepend ``%`` to :class:`GenericGroup` entries (sudo user field).
        :type add_percent: bool, optional
        :return: Formatted string.
        :rtype: str
        """
        if isinstance(item, list):
            return ", ".join(LocalSudoRule._format_list_item(x, add_percent) for x in item)
        return LocalSudoRule._format_list_item(item, add_percent)

    def get(self, attrs: list[str] | None = None) -> dict[str, list[str]]:
        """
        Return rule text as attributes (``cn``, ``sudoRule``).

        If ``rule_str`` is unset, reads the drop-in file when ``filename`` is set.
        """
        line = self.rule_str.strip() if self.rule_str else ""
        if not line and self.filename:
            result = self.util.host.conn.exec(
                ["cat", f"/etc/sudoers.d/{self.filename}"],
                raise_on_error=False,
                log_level=ProcessLogLevel.Silent,
            )
            if result.rc == 0:
                line = result.stdout.strip()
        if not line:
            return {}
        data: dict[str, list[str]] = {"cn": [self._name], "sudoRule": [line]}
        if attrs is None:
            return data
        return {k: v for k, v in data.items() if k in attrs}

    def add(
        self,
        *,
        user: SudoRuleUserField = default_user,
        host: SudoRuleHostField = default_host,
        command: SudoRuleCommandField = default_command,
        option: str | list[str] | None = None,
        runasuser: SudoRuleRunAsUserField = None,
        runasgroup: SudoRuleRunAsGroupField = None,
        order: int | None = None,
        nopasswd: bool | None = None,
    ) -> LocalSudoRule:
        """
        Create new sudo rule.

        :param user: sudoUser attribute, defaults to ALL.
        :type user: SudoRuleUserField, optional
        :param host: sudoHost attribute, defaults to ALL.
        :type host: SudoRuleHostField, optional
        :param command: sudoCommand attribute, defaults to ALL.
        :type command: SudoRuleCommandField, optional
        :param option: sudoOption attribute, defaults to None.
        :type option: str | list[str] | None, optional
        :param runasuser: sudoRunAsUser attribute, defaults to None.
        :type runasuser: SudoRuleRunAsUserField, optional
        :param runasgroup: sudoRunAsGroup attribute, defaults to None.
        :type runasgroup: SudoRuleRunAsGroupField, optional
        :param order: sudoOrder attribute, defaults to None.
        :type order: int | None, optional
        :param nopasswd: If true, no authentication is required (NOPASSWD), defaults to None (no change)
        :type nopasswd: bool | None, optional
        :return: New sudo rule object.
        :rtype: LocalSudoRule
        """
        orderstr = f"{order:02d}" if order is not None else str(len(self.util._sudorules))
        if self.filename is None:
            self.filename = f"{orderstr}_{self._name}"

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
        user: SudoRuleUserField = None,
        host: SudoRuleHostField = None,
        command: SudoRuleCommandField = None,
        option: str | list[str] | None = None,
        runasuser: SudoRuleRunAsUserField = None,
        runasgroup: SudoRuleRunAsGroupField = None,
        order: int | None = None,
        nopasswd: bool | None = None,
    ) -> LocalSudoRule:
        """
        Modify existing local sudo rule.

        Parameters set to ``None`` keep the previous values.

        :param user: sudoUser attribute, defaults to None.
        :type user: SudoRuleUserField, optional
        :param host: sudoHost attribute, defaults to None.
        :type host: SudoRuleHostField, optional
        :param command: sudoCommand attribute, defaults to None.
        :type command: SudoRuleCommandField, optional
        :param option: sudoOption attribute, defaults to None.
        :type option: str | list[str] | None, optional
        :param runasuser: sudoRunAsUser attribute, defaults to None.
        :type runasuser: SudoRuleRunAsUserField, optional
        :param runasgroup: sudoRunAsGroup attribute, defaults to None.
        :type runasgroup: SudoRuleRunAsGroupField, optional
        :param order: sudoOrder attribute, defaults to None.
        :type order: int | None, optional
        :param nopasswd: If true, no authentication is required (NOPASSWD), defaults to None (no change).
        :type nopasswd: bool | None, optional
        :return: Self.
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
