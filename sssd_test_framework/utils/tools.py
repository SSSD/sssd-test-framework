"""Run various standard Linux commands on remote host."""

from __future__ import annotations

from typing import Any, Sequence

import jc
from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.conn import Process, ProcessResult
from pytest_mh.utils.fs import LinuxFileSystem

__all__ = [
    "GetentUtils",
    "GroupEntry",
    "IdEntry",
    "LinuxToolsUtils",
    "PasswdEntry",
    "UnixGroup",
    "UnixObject",
    "UnixUser",
]


class UnixObject(object):
    """
    Generic Unix object.
    """

    def __init__(self, id: int | None, name: str | None) -> None:
        """
        :param id: Object ID.
        :type id: int | None
        :param name: Object name.
        :type name: str | None
        """
        self.id: int | None = id
        """
        ID.
        """

        self.name: str | None = name
        """
        Name.
        """

    def __str__(self) -> str:
        return f'({self.id},"{self.name}")'

    def __repr__(self) -> str:
        return str(self)

    def __eq__(self, o: object) -> bool:
        if isinstance(o, str):
            return o == self.name
        elif isinstance(o, int):
            return o == self.id
        elif isinstance(o, tuple):
            if len(o) != 2 or not isinstance(o[0], int) or not isinstance(o[1], str):
                raise NotImplementedError(f"Unable to compare {type(o)} with {self.__class__}")

            id, name = o
            return id == self.id and name == self.name
        elif isinstance(o, UnixObject):
            # Fallback to identity comparison
            return NotImplemented

        raise NotImplementedError(f"Unable to compare {type(o)} with {self.__class__}")


class UnixUser(UnixObject):
    """
    Unix user.
    """

    pass


class UnixGroup(UnixObject):
    """
    Unix group.
    """

    pass


class IdEntry(object):
    """
    Result of ``id``
    """

    def __init__(self, user: UnixUser, group: UnixGroup, groups: list[UnixGroup]) -> None:
        self.user: UnixUser = user
        """
        User information.
        """

        self.group: UnixGroup = group
        """
        Primary group.
        """

        self.groups: list[UnixGroup] = groups
        """
        Secondary groups.
        """

    def memberof(self, groups: int | str | tuple[int, str] | list[int | str | tuple[int, str]]) -> bool:
        """
        Check if the user is member of give group(s).

        Group specification can be either a single gid or group name. But it can
        be also a tuple of (gid, name) where both gid and name must match or list
        of groups where the user must be member of all given groups.

        :param groups: _description_
        :type groups: int | str | tuple
        :return: _description_
        :rtype: bool
        """
        if isinstance(groups, (int, str, tuple)):
            return groups in self.groups

        return all(x in self.groups for x in groups)

    def __str__(self) -> str:
        return f"{{user={str(self.user)},group={str(self.group)},groups={str(self.groups)}}}"

    def __repr__(self) -> str:
        return str(self)

    @classmethod
    def FromDict(cls, d: dict[str, Any]) -> IdEntry:
        user = UnixUser(d["uid"]["id"], d["uid"].get("name", None))
        group = UnixGroup(d["gid"]["id"], d["gid"].get("name", None))
        groups = []

        for secondary_group in d["groups"]:
            groups.append(UnixGroup(secondary_group["id"], secondary_group.get("name", None)))

        return cls(user, group, groups)

    @classmethod
    def FromOutput(cls, stdout: str) -> IdEntry:
        jcresult = jc.parse("id", stdout)

        if not isinstance(jcresult, dict):
            raise TypeError(f"Unexpected type: {type(jcresult)}, expecting dict")

        return cls.FromDict(jcresult)


class PasswdEntry(object):
    """
    Result of ``getent passwd``
    """

    def __init__(
        self,
        name: str | None,
        password: str | None,
        uid: int | None,
        gid: int | None,
        gecos: str | None,
        home: str | None,
        shell: str | None,
    ) -> None:
        self.name: str | None = name
        """
        User name.
        """

        self.password: str | None = password
        """
        User password.
        """

        self.uid: int | None = uid
        """
        User id.
        """

        self.gid: int | None = gid
        """
        Group id.
        """

        self.gecos: str | None = gecos
        """
        GECOS.
        """

        self.home: str | None = home
        """
        Home directory.
        """

        self.shell: str | None = shell
        """
        Login shell.
        """

    def __str__(self) -> str:
        return f"({self.name}:{self.password}:{self.uid}:{self.gid}:{self.gecos}:{self.home}:{self.shell})"

    def __repr__(self) -> str:
        return str(self)

    @classmethod
    def FromDict(cls, d: dict[str, str | int | None]) -> PasswdEntry:
        username = d.get("username", None)
        password = d.get("password", None)
        uid = d.get("uid", None)
        gid = d.get("gid", None)
        comment = d.get("comment", None)
        home = d.get("home", None)
        shell = d.get("shell", None)

        if username is not None and not isinstance(username, str):
            raise ValueError("username is not instance of str")

        if password is not None and not isinstance(password, str):
            raise ValueError("password is not instance of str")

        if uid is not None and not isinstance(uid, int):
            raise ValueError("uid is not instance of int")

        if gid is not None and not isinstance(gid, int):
            raise ValueError("gid is not instance of int")

        if comment is not None and not isinstance(comment, str):
            raise ValueError("comment is not instance of str")

        if home is not None and not isinstance(home, str):
            raise ValueError("home is not instance of str")

        if shell is not None and not isinstance(shell, str):
            raise ValueError("shell is not instance of str")

        return cls(
            name=username,
            password=password,
            uid=uid,
            gid=gid,
            gecos=comment,
            home=home,
            shell=shell,
        )

    @classmethod
    def FromOutput(cls, stdout: str) -> PasswdEntry:
        result = jc.parse("passwd", stdout)

        if not isinstance(result, list):
            raise TypeError(f"Unexpected type: {type(result)}, expecting list")

        if len(result) != 1:
            raise ValueError("More then one entry was returned")

        return cls.FromDict(result[0])


class GroupEntry(object):
    """
    Result of ``getent group``
    """

    def __init__(self, name: str | None, password: str | None, gid: int | None, members: list[str]) -> None:
        self.name: str | None = name
        """
        Group name.
        """

        self.password: str | None = password
        """
        Group password.
        """

        self.gid: int | None = gid
        """
        Group id.
        """

        self.members: list[str] = members
        """
        Group members.
        """

    def __str__(self) -> str:
        return f'({self.name}:{self.password}:{self.gid}:{",".join(self.members)})'

    def __repr__(self) -> str:
        return str(self)

    @classmethod
    def FromDict(cls, d: dict[str, str | int | list[str] | None]) -> GroupEntry:
        group_name = d.get("group_name", None)
        password = d.get("password", None)
        gid = d.get("gid", None)
        members = d.get("members", [])

        if group_name is not None and not isinstance(group_name, str):
            raise ValueError("group_name is not instance of str")

        if password is not None and not isinstance(password, str):
            raise ValueError("password is not instance of str")

        if gid is not None and not isinstance(gid, int):
            raise ValueError("gid is not instance of int")

        if not isinstance(members, list):
            raise ValueError("members is not instance of list")

        return cls(
            name=group_name,
            password=password,
            gid=gid,
            members=members,
        )

    @classmethod
    def FromOutput(cls, stdout: str) -> GroupEntry:
        result = jc.parse("group", stdout)

        if not isinstance(result, list):
            raise TypeError(f"Unexpected type: {type(result)}, expecting list")

        if len(result) != 1:
            raise ValueError("More then one entry was returned")

        return cls.FromDict(result[0])


class InitgroupsEntry(object):
    """
    Result of ``getent initgroups``

    If user does not exist or does not have any supplementary groups then ``self.groups`` is empty.
    """

    def __init__(self, name: str, groups: list[int]) -> None:
        self.name: str = name
        """
        Exact username for which ``initgroups`` was called
        """

        self.groups: list[int] = groups
        """
        Group ids that ``name`` is member of.
        """

    def __str__(self) -> str:
        return f'({self.name}:{",".join([str(i) for i in self.groups])})'

    def __repr__(self) -> str:
        return str(self)

    def memberof(self, groups: list[int]) -> bool:
        """
        Check if the user is member of given groups.

        This method checks only supplementary groups not the primary group.

        :param groups: List of group ids
        :type groups: list[int]
        :return: If user is member of all given groups True, otherwise False.
        :rtype: bool
        """

        return all(x in self.groups for x in groups)

    @classmethod
    def FromDict(cls, d: dict[str, Any]) -> InitgroupsEntry:
        return cls(
            name=d["name"],
            groups=d.get("groups", []),
        )

    @classmethod
    def FromOutput(cls, stdout: str) -> InitgroupsEntry:
        result: list[str] = stdout.split()

        dictionary: dict[str, str | list[int]] = {}
        dictionary["name"] = result[0]

        if len(result) > 1:
            dictionary["groups"] = [int(x) for x in result[1:]]

        return cls.FromDict(dictionary)


class NetgroupEntry(object):
    """
    Result of ``getent netgroup``

    You can use string or tuple to assert netgroups members. Optionally, you
    can omit the domain part in which case the domain is not checked at all.
    This is useful for topology parametrization due to differences in the IPA
    provider which automatically adds IPA domain and it can not be set manually.

    .. code-block:: python
        :caption: Example usage

        result = client.tools.getent.netgroup("ng-1")
        assert result is not None
        assert result.name == "ng-1"
        assert len(result.members) == 1

        # The following line two lines means: assert "(host,user,domain)" in result.members
        assert "(-,user-1,)" in result.members
        assert ("-", "user-1", "") in  result.members

        # The following line two lines ignore the domain part: assert "(host,user)" in result.members
        assert "(-,user-1)" in result.members
        assert ("-", "user-1") in  result.members

    You probably want to use plain string in most scenarios as it is more
    readable and easier to write. But it may be nicer to use tuples if you use
    variables for the values instead of hard coded string.
    """

    class NetgroupTriple(object):
        def __init__(self, host: str, user: str, domain: str) -> None:
            self.host: str = host
            self.user: str = user
            self.domain: str = domain

        def __str__(self) -> str:
            return f"({self.host},{self.user},{self.domain})"

        def __eq__(self, other: object) -> bool:
            if isinstance(other, type(self)):
                return self.host == other.host and self.user == other.user and self.domain == other.domain

            if isinstance(other, str):
                host, user, domain = self.Parse(other)
                if domain is None:
                    return self.host == host and self.user == user

                return self.host == host and self.user == user and self.domain == domain

            if isinstance(other, tuple):
                if list(map(type, other)) == [str, str]:
                    return self.host == other[0] and self.user == other[1]

                if list(map(type, other)) == [str, str, str]:
                    return self.host == other[0] and self.user == other[1] and self.domain == other[2]

                raise TypeError(f"Unable to compare NetgroupTriple with tuple{list(map(type, other))}")

            return NotImplemented

        def __ne__(self, other: object) -> bool:
            return not self == other

        @staticmethod
        def Parse(triple: str) -> tuple[str, str, str | None]:
            if not triple.startswith("(") or not triple.endswith(")"):
                raise ValueError(f"Not a valid netgroup triple: {triple}")

            parsed = [x.strip() for x in triple[1:-1].split(",")]
            if len(parsed) not in [2, 3]:
                raise ValueError(f"Not a valid netgroup triple: {triple}")

            return (parsed[0], parsed[1], parsed[2] if len(parsed) == 3 else None)

    def __init__(self, name: str, members: list[NetgroupEntry.NetgroupTriple]) -> None:
        self.name: str = name
        """
        Netgroup name.
        """

        self.members: list[NetgroupEntry.NetgroupTriple] = members
        """
        Netgroup members.
        """

    def __str__(self) -> str:
        return f'{self.name} {" ".join(map(str, self.members))})'

    def __repr__(self) -> str:
        return str(self)

    @classmethod
    def FromDict(cls, d: dict[str, Any]) -> NetgroupEntry:
        members: list[NetgroupEntry.NetgroupTriple] = []
        for m in d.get("members", []):
            members.append(NetgroupEntry.NetgroupTriple(**m))

        return cls(
            name=d["name"],
            members=members,
        )

    @classmethod
    def FromOutput(cls, stdout: str) -> NetgroupEntry:
        # jc does not support netgroups output
        result = [x.strip() for x in stdout.split(" ") if x]

        if not result:
            raise ValueError("No entry was returned")

        members: list[dict[str, str]] = []
        for m in result[1:]:
            host, user, domain = NetgroupEntry.NetgroupTriple.Parse(m)

            # None is not allowed in constructor
            if domain is None:
                domain = ""

            members.append({"host": host, "user": user, "domain": domain})

        return cls.FromDict({"name": result[0], "members": members})


class HostsEntry(object):
    """
    Result of ``getent hosts``

    .. code-block:: python
        :caption: Example usage

            ldap.hosts("host0").add(ip_address="192.168.1.1", aliases=[])
            client.sssd.common.resolver(ldap)
            client.sssd.start()

            result = client.tools.getent.hosts("host0", service="sss")
            if result is not None:
                assert "host0" == result.name, f"Host 'host0' was not found!"
                assert "192.168.1.1"  in result.ip, f"IP addresses '192.168.1.1' was not found!"
    """

    def __init__(self, name: str | None, ip: list[str] | None, aliases: list[str] | None) -> None:

        self.name: str | None = name
        """Hostname."""

        self.ip: list[str] | None = ip
        """IP address."""

        self.aliases: list[str] | None = aliases
        """Host aliases."""

    def __str__(self) -> str:
        return f"({self.ip}: {self.name}, {self.aliases})"

    def __repr__(self) -> str:
        return str(self)

    @classmethod
    def FromDict(cls, d: dict[str, Any]) -> HostsEntry:
        if isinstance(d, dict):
            ip = d.get("ip", None)
            name = d.get("name", None)
            aliases = d.get("aliases", None)

            if name is not None and not isinstance(name, str):
                raise ValueError("name is not an instance of str")

            if ip is not None and not isinstance(ip, list):
                raise ValueError("ip is not an instance of  list")

            if aliases is not None and not isinstance(aliases, list):
                raise ValueError("aliases is not an instance of  list")

        return cls(name=name, ip=ip, aliases=aliases)

    @classmethod
    def FromList(cls, d: list[dict[str, Any]]) -> HostsEntry:
        name: str | None = None
        ip: list[str] = []
        aliases: list[str] = []

        for i in d:
            if isinstance(i, dict):
                ip_value = i.get("ip")
                if isinstance(ip_value, str) and ip_value:
                    ip.append(ip_value)
                elif isinstance(ip_value, list):
                    ip.extend([v for v in ip_value if isinstance(v, str)])

                hostname = i.get("hostname")
                if isinstance(hostname, list) and hostname:
                    if name is None and isinstance(hostname[0], str):
                        name = hostname[0]
                    if len(hostname) > 1:
                        for host in hostname[1:]:
                            if isinstance(host, str) and host not in aliases:
                                aliases.append(host)

        return cls.FromDict({"name": name, "ip": ip if ip else None, "aliases": aliases if aliases else None})

    @classmethod
    def FromOutput(cls, stdout: str) -> HostsEntry:
        result = jc.parse("hosts", stdout)

        if not isinstance(result, list):
            raise TypeError(f"Unexpected type: {type(result)}, expecting list")

        if not result:
            raise ValueError("No hosts data found in output")

        return cls.FromList(result)


class NetworksEntry(object):
    """
    Result of ``getent networks``

    If networks does not exist or does not have any supplementary networks then ``self.networks`` is empty.

    .. code-block:: python
        :caption: Example usage

            ldap.networks("net0").add(ip_address ="192.168.1.1", aliases = [])
            client.sssd.common.resolver(ldap)
            client.sssd.start()

            result = client.tools.getent.networks("net0", service="sss")
            if result is not None:
                assert "net0"  in  result.name, f"Network 'net0' was not found!"
    """

    def __init__(self, name: str | None | None, ip: str | None, aliases: Sequence[str] | None) -> None:

        self.name: str | None = name
        """Network name. """

        self.ip: str | None = ip
        """Exact network name which ``network`` was called."""

        self.aliases: Sequence[str] | None = aliases
        """Network aliases."""

    def __str__(self) -> str:
        return f"({self.ip}: {self.name} {self.aliases})"

    def __repr__(self) -> str:
        return str(self)

    @classmethod
    def FromDict(cls, d: dict[str, Sequence[str]]) -> NetworksEntry:
        if isinstance(d, dict):
            ip = d.get("ip", None)
            name = d.get("name", None)
            aliases = d.get("aliases", None)

            if ip is not None and not isinstance(ip, str):
                raise ValueError("ip is not an instance of  str")

            if name is not None and not isinstance(name, str):
                raise ValueError("hostname is not an instance of str")

        return cls(ip=ip, name=name, aliases=aliases)

    @classmethod
    def FromOutput(cls, stdout: str) -> NetworksEntry:
        parts = [part for part in stdout.split() if part]
        if len(parts) < 2:
            raise ValueError(f"Two few values {len(parts)}: {parts}")

        aliases = []
        if len(parts) > 2:
            for host in parts[2:]:
                if isinstance(host, str) and host not in aliases:
                    aliases.append(host)
        result = {"name": parts[0].strip(), "ip": parts[1].strip(), "aliases": aliases}

        return cls.FromDict(result)


class ServicesEntry(object):
    """
    Result of ``getent services``

    If services does not exist or does not have any supplementary services then ``self.services`` is empty.

    .. code-block:: python
        :caption: Example usage

            ldap.services("service0").add(port=12345, protocol="tcp", aliases = [])
            client.sssd.common.resolver(ldap)
            client.sssd.start()

            result = client.tools.getent.services("service0", service="sss")
            if result is not None:
                assert "service0" == result.name, f"Service 'service0' was not found!"
    """

    def __init__(self, name: str | None, protocol: str | None = None, port: int | None = None) -> None:

        self.name: str | None = name
        """Service name. """

        self.protocol: str | None = protocol
        """Protocol."""

        self.port: int | None = port
        """Port."""

    def __str__(self) -> str:
        return f"({self.name} {self.port}/{self.protocol})"

    def __repr__(self) -> str:
        return str(self)

    @classmethod
    def FromDict(cls, d: dict[str, Any | None]) -> ServicesEntry:
        if isinstance(d, dict):
            name = d.get("name", None)
            protocol = d.get("protocol", None)
            port = d.get("port", None)

            if name is not None and not isinstance(name, str):
                raise ValueError("name is not an instance of  str")

            if protocol is not None and not isinstance(protocol, str):
                raise ValueError("protocol is not an instance of str")

            if port is not None and not isinstance(port, int):
                raise ValueError("port is not an instance of int")

            return cls(name=name, protocol=protocol, port=port)

    @classmethod
    def FromOutput(cls, stdout: str) -> ServicesEntry:
        name: str = ""
        port: int = 0
        protocol: str = ""

        parts: list[str] = [part for part in stdout.split() if part]
        if len(parts) < 2:
            raise ValueError(f"Two few values {len(parts)}: {parts}")

        name = parts[0].strip()

        if "/" in parts[1]:
            port = int(parts[1].split("/")[0].strip())
            protocol = parts[1].split("/")[1].strip()

        result = {"name": name, "port": port, "protocol": protocol}

        return cls.FromDict(result)


class SubIDEntry(object):
    """
    Result of 'getsubids'.
    """

    def __init__(self, name: str, range_start: int, range_size: int) -> None:

        self.name: str = name
        """ User name"""

        self.range_start: int = range_start
        """ SubID range start """

        self.range_size: int = range_size
        """  SubID range size """

    def __str__(self) -> str:
        return f"owner:{self.name}, start:{self.range_start}, size:{self.range_size})"

    def __repr__(self) -> str:
        return str(self)

    @classmethod
    def FromDict(cls, d: dict[str, Any]) -> SubIDEntry:
        return cls(
            name=d.get("name", ""),
            range_start=d.get("range_start", 0),
            range_size=d.get("range_size", 0),
        )

    @classmethod
    def FromOutput(cls, stdout: str) -> SubIDEntry:
        line = stdout.strip()
        if ":" in line:
            parts = line.split(":", 1)
            if len(parts) == 2:
                rest = parts[1].strip().split()
                if len(rest) == 3:
                    return cls(
                        name=rest[0],
                        range_start=int(rest[1]),
                        range_size=int(rest[2]),
                    )
        return cls(name="", range_start=0, range_size=0)


class LinuxToolsUtils(MultihostUtility[MultihostHost]):
    """
    Run various standard commands on remote host.
    """

    def __init__(self, host: MultihostHost, fs: LinuxFileSystem) -> None:
        """
        :param host: Remote host.
        :type host: MultihostHost
        """
        super().__init__(host)

        self.getent: GetentUtils = GetentUtils(host)
        """
        Run ``getent`` command.
        """

        self.__fs: LinuxFileSystem = fs
        self.__rollback: list[str] = []

    def getsubid(self, name: str, group: bool = False) -> SubIDEntry | None:
        """
        Call ``getsubids $name``

        :param name: User name.
        :type name: str
        :param group: Get group range switch, optional
        :type group: bool, defaults to False
        :return: SubIDEntry data, None if not found
        :type: SubIDEntry | None
        """
        args = ""
        if group:
            args = "-g"

        command = self.host.conn.run(f"getsubids {args} {name}", raise_on_error=False)
        if command.rc != 0:
            return None

        return SubIDEntry.FromOutput(command.stdout)

    def id(self, name: str | int) -> IdEntry | None:
        """
        Run ``id`` command.

        :param name: User name or id.
        :type name: str | int
        :return: id data, None if not found
        :rtype: IdEntry | None
        """
        command = self.host.conn.exec(["id", name], raise_on_error=False)
        if command.rc != 0:
            return None

        return IdEntry.FromOutput(command.stdout)

    def grep(self, pattern: str, paths: str | list[str], args: list[str] | None = None) -> bool:
        """
        Run ``grep`` command.

        :param pattern: Pattern to match.
        :type pattern: str
        :param paths: Paths to search.
        :type paths: str | list[str]
        :param args: Additional arguments to ``grep`` command, defaults to None.
        :type args: list[str] | None, optional
        :return: True if grep returned 0, False otherwise.
        :rtype: bool
        """
        if args is None:
            args = []

        paths = [paths] if isinstance(paths, str) else paths
        command = self.host.conn.exec(["grep", *args, pattern, *paths], raise_on_error=False)

        return command.rc == 0

    def dnf(self, args: list[Any] | None = None) -> ProcessResult:
        """
        Execute dnf commands with given arguments.

        :param args: Arguments to ``dnf``, defaults to None
        :type args: list[Any] | None, optional
        :return: SSH Process result
        :rtype: ProcessResult
        """
        if args is None:
            args = []

        dnf_id_before = self.host.conn.exec(["dnf", "history"]).stdout.split("\n")[2].split("|")[0].strip()

        command = self.host.conn.exec(["dnf", "-y", *args])
        dnf_id_after = self.host.conn.exec(["dnf", "history"]).stdout.split("\n")[2].split("|")[0].strip()

        if int(dnf_id_before) < int(dnf_id_after):
            self.__rollback.append(f"dnf history -y undo {dnf_id_after}")

        return command

    def faillock(self, args: list[Any]) -> ProcessResult:
        """
        Execute faillock command.
        :param args: Arguments to ``faillock``
        :type args: list[Any]
        :return: SSH Process result
        :rtype: ProcessResult
        """
        if args is None:
            args = []

        return self.host.conn.exec(["faillock", *args])

    @property
    def sshkey(self) -> SSHKeyUtils:
        """
        Execute ssh-keygen command.
        :return: SSHKeyUtils object.
        :rtype: SSHKeyUtils
        """

        return SSHKeyUtils(self.host, self.__fs)

    def teardown(self):
        """
        Revert all changes.

        :meta private:
        """
        cmd = "\n".join(reversed(self.__rollback))
        if cmd:
            self.host.conn.run(cmd)

        super().teardown()

    def wait_for_condition(self, condition: str, body: str = "", timeout: int = 60) -> ProcessResult:
        """
        Wait at maximum ``timeout`` seconds until the ``condition`` is true. Execute ``body`` after each attempt.
        The condition is a bash expression, usually it is a single bash command that must succeed before a test
        can continue.

        .. note::

            Internally, this expands to ``timeout {time}s bash -c 'until {condition}; do : {body}; done'``.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.LDAP)
            def test_just_condition(client: Client):
                client.sssd.domain["ldap_uri"] = "ldap://typo"
                client.sssd.start(debug_level=None, raise_on_error=False)

                assert client.sssd.default_domain
                r = client.tools.wait_for_condition(condition=f"sssctl domain-status {client.sssd.default_domain}")
                assert r.rc == 0
                assert "LDAP: not connected" in r.stdout

        :param condition: Command that is awaited
        :type condition: str
        :param body: Body to be executed while waiting for condition, defaults to ""
        :type body: str, optional
        :param timeout: How long should we try the command in seconds, defaults to 60
        :type timeout: int, optional
        :return: Proccess result
        :rtype: ProcessResult
        """

        return self.host.conn.run(f"timeout {timeout}s bash -c 'until {condition}; do : {body}; done'")


class KillCommand(object):
    def __init__(self, host: MultihostHost, process: Process, pid: int) -> None:
        self.host = host
        self.process = process
        self.pid = pid
        self.__killed: bool = False

    def kill(self) -> None:
        if self.__killed:
            return

        self.host.conn.exec(["kill", self.pid])
        self.__killed = True

    def __enter__(self) -> KillCommand:
        return self

    def __exit__(self, exception_type, exception_value, traceback) -> None:
        self.kill()
        self.process.wait()


class GetentUtils(MultihostUtility[MultihostHost]):
    """
    Interface to getent command.
    """

    def __init__(self, host: MultihostHost) -> None:
        """
        :param host: Remote host.
        :type host: MultihostHost
        """
        super().__init__(host)

    def passwd(self, name: str | int, *, service: str | None = None) -> PasswdEntry | None:
        """
        Call ``getent passwd $name``

        :param name: User name or id.
        :type name: str | int
        :param service: Service used, defaults to None
        :type service: str | None
        :return: passwd data, None if not found
        :rtype: PasswdEntry | None
        """
        return self.__exec(PasswdEntry, "passwd", name, service)

    def group(self, name: str | int, *, service: str | None = None) -> GroupEntry | None:
        """
        Call ``getent group $name``

        :param name: Group name or id.
        :type name: str | int
        :param service: Service used, defaults to None
        :type service: str | None
        :return: group data, None if not found
        :rtype: PasswdEntry | None
        """
        return self.__exec(GroupEntry, "group", name, service)

    def initgroups(self, name: str, *, service: str | None = None) -> InitgroupsEntry:
        """
        Call ``getent initgroups $name``

        If ``name`` does not exist, group list is empty. This is standard behavior of ``getent initgroups``

        :param name: User name.
        :type name: str
        :param service: Service used, defaults to None
        :type service: str | None
        :return: Initgroups data
        :rtype: InitgroupsEntry
        """
        return self.__exec(InitgroupsEntry, "initgroups", name, service)

    def netgroup(self, name: str, *, service: str | None = None) -> NetgroupEntry | None:
        """
        Call ``getent netgroup $name``

        :param name: Netgroup name.
        :type name: str
        :param service: Service used, defaults to None
        :type service: str | None
        :return: Netgroup data, None if not found
        :rtype: NetgroupEntry | None
        """
        return self.__exec(NetgroupEntry, "netgroup", name, service)

    def hosts(self, name: str, *, service: str | None = None) -> HostsEntry:
        """
        Call ``getent hosts $name``

        :param name: Hostname.
        :type name: str
        :param service: Service used, defaults to None
        :type service: str | None
        :return: Hosts data, None if not found
        :rtype: HostsEntry | None
        """
        return self.__exec(HostsEntry, "hosts", name, service)

    def networks(self, name: str, *, service: str | None = None) -> NetworksEntry:
        """
        Call ``getent networks $name``

        :param name: Network.
        :type name: str
        :param service: Service used, defaults to None
        :type service: str | None
        :return: Network data, None if not found
        :rtype: NetworksEntry | None
        """
        return self.__exec(NetworksEntry, "networks", name, service)

    def services(self, name: str, *, service: str | None = None) -> ServicesEntry:
        """
        Call ``getent services $name``

        :param name: Service.
        :type name: str
        :param service: Service used, defaults to None
        :type service: str | None
        :return: Service data, None if not found
        :rtype: ServicesEntry | None
        """
        return self.__exec(ServicesEntry, "services", name, service)

    def __exec(self, cls, cmd: str, name: str | int, service: str | None = None) -> Any:
        args = []
        if service is not None:
            args = ["-s", service]

        command = self.host.conn.exec(["getent", *args, cmd, name], raise_on_error=False)
        if command.rc != 0:
            return None

        return cls.FromOutput(command.stdout)


class SSHKeyUtils:
    """
    Interface to ssh-keygen command.
    """

    def __init__(self, host: MultihostHost, fs: LinuxFileSystem) -> None:
        """
        :param host:
        :type host: MultihostHost
        :param fs:
        :type fs: LinuxFileSystem
        """
        self.host: MultihostHost = host
        self.fs: LinuxFileSystem = fs

    def generate(
        self,
        user: str,
        homedir: str,
        group: str | None = None,
        file: str = "id_rsa",
        cipher: str = "rsa",
        args: list[Any] | None = None,
    ) -> tuple[str, str]:
        """
        Creates user's home directory and SSH key pair.

        :param user: Username.
        :type user: str
        :param homedir: Home directory.
        :type homedir: str
        :param group: User group, defaults to None
        :type group: str, optional
        :param file: SSH key file, defaults to "id_rsa"
        :type file: str, optional
        :param cipher: Encryption algorithm, defaults to "rsa"
        :type cipher: str, optional
        :param args: Additional arguments to pass to ssh-keygen, defaults to None
        :type args: list[Any] | None
        :return: Public key, private key
        :rtype: tuple[str, str]
        """
        self.fs.backup("/home")

        if group is None:
            group = user

        if args is None:
            args = []

        if not self.fs.exists(homedir):
            self.fs.copy("/etc/skel", homedir, mode="0700")

        if self.fs.exists(f"{homedir}/.ssh/{file}"):
            raise FileExistsError("SSH Keypair already exits!")
        else:
            self.fs.mkdir_p(f"{homedir}/.ssh", mode="0700")
            self.host.conn.exec(
                ["ssh-keygen", "-t", cipher, "-N", " ", *args, "-f", f"{homedir}/.ssh/{file}", "-C", file]
            )
            self.fs.chown(homedir, user=user, group=group, args=["-R"])

            return self.fs.read(f"{homedir}/.ssh/{file}.pub"), self.fs.read(f"{homedir}/.ssh/{file}")
