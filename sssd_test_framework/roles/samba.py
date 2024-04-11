"""Samba multihost role."""

from __future__ import annotations

from typing import Any, TypeAlias

import ldap.modlist
import configparser
import os.path
from pytest_mh.cli import CLIBuilderArgs
from pytest_mh.ssh import SSHProcessResult

from sssd_test_framework.utils.ldap import LDAPRecordAttributes

from ..hosts.samba import SambaHost
from ..misc import attrs_parse, to_list_of_strings
from .base import BaseLinuxLDAPRole, BaseObject, DeleteAttribute
from .ldap import LDAPAutomount, LDAPNetgroup, LDAPNetgroupMember, LDAPObject, LDAPOrganizationalUnit, LDAPSudoRule

__all__ = [
    "Samba",
    "SambaObject",
    "SambaComputer",
    "SambaUser",
    "SambaGroup",
    "SambaOrganizationalUnit",
    "SambaAutomount",
    "SambaSudoRule",
    "GPO",
]


class Samba(BaseLinuxLDAPRole[SambaHost]):
    """
    Samba role.

    Provides unified Python API for managing objects in the Samba domain controller.

    .. code-block:: python
        :caption: Creating user and group

        @pytest.mark.topology(KnownTopology.Samba)
        def test_example(samba: Samba):
            u = samba.user('tuser').add()
            g = samba.group('tgroup').add()
            g.add_member(u)

    .. note::

        The role object is instantiated automatically as a dynamic pytest
        fixture by the multihost plugin. You should not create the object
        manually.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.domain: str = self.host.domain
        """
        Samba domain name.
        """

        self.realm: str = self.host.realm
        """
        Kerberos realm.
        """

        self.automount: SambaAutomount = SambaAutomount(self)
        """
        Manage automount maps and keys.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.Samba)
            def test_example_autofs(client: Client, samba: Samba, nfs: NFS):
                nfs_export1 = nfs.export('export1').add()
                nfs_export2 = nfs.export('export2').add()
                nfs_export3 = nfs.export('sub/export3').add()

                # Create automount maps
                auto_master = samba.automount.map('auto.master').add()
                auto_home = samba.automount.map('auto.home').add()
                auto_sub = samba.automount.map('auto.sub').add()

                # Create mount points
                auto_master.key('/ehome').add(info=auto_home)
                auto_master.key('/esub/sub1/sub2').add(info=auto_sub)

                # Create mount keys
                key1 = auto_home.key('export1').add(info=nfs_export1)
                key2 = auto_home.key('export2').add(info=nfs_export2)
                key3 = auto_sub.key('export3').add(info=nfs_export3)

                # Start SSSD
                client.sssd.common.autofs()
                client.sssd.start()

                # Reload automounter in order to fetch updated maps
                client.automount.reload()

                # Check that we can mount all directories on correct locations
                assert client.automount.mount('/ehome/export1', nfs_export1)
                assert client.automount.mount('/ehome/export2', nfs_export2)
                assert client.automount.mount('/esub/sub1/sub2/export3', nfs_export3)

                # Check that the maps are correctly fetched
                assert client.automount.dumpmaps() == {
                    '/ehome': {
                        'map': 'auto.home',
                        'keys': [str(key1), str(key2)]
                    },
                    '/esub/sub1/sub2': {
                        'map': 'auto.sub',
                        'keys': [str(key3)]
                    },
                }
        """

        # Set AD schema for automount
        self.automount.set_schema(self.automount.Schema.AD)

    def fqn(self, name: str) -> str:
        """
        Return fully qualified name in form name@domain.
        """
        return f"{name}@{self.domain}"

    def user(self, name: str) -> SambaUser:
        """
        Get user object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.Samba)
            def test_example(client: Client, samba: Samba):
                # Create user
                samba.user('user-1').add()

                # Start SSSD
                client.sssd.start()

                # Call `id user-1` and assert the result
                result = client.tools.id('user-1')
                assert result is not None
                assert result.user.name == 'user-1'
                assert result.group.name == 'domain users'

        :param name: User name.
        :type name: str
        :return: New user object.
        :rtype: SambaUser
        """
        return SambaUser(self, name)

    def group(self, name: str) -> SambaGroup:
        """
        Get group object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.Samba)
            def test_example(client: Client, samba: Samba):
                # Create user
                user = samba.user('user-1').add()

                # Create secondary group and add user as a member
                samba.group('group-1').add().add_member(user)

                # Start SSSD
                client.sssd.start()

                # Call `id user-1` and assert the result
                result = client.tools.id('user-1')
                assert result is not None
                assert result.user.name == 'user-1'
                assert result.group.name == 'domain users'
                assert result.memberof('group-1')

        :param name: Group name.
        :type name: str
        :return: New group object.
        :rtype: SambaGroup
        """
        return SambaGroup(self, name)

    def netgroup(self, name: str, basedn: LDAPObject | str | None = "ou=netgroups") -> SambaNetgroup:
        """
        Get netgroup object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.Samba)
            def test_example_netgroup(client: Client, samba: Samba):
                # Create user
                user = samba.user("user-1").add()

                # Create two netgroups
                ng1 = samba.netgroup("ng-1").add()
                ng2 = samba.netgroup("ng-2").add()

                # Add user and ng2 as members to ng1
                ng1.add_member(user=user)
                ng1.add_member(ng=ng2)

                # Add host as member to ng2
                ng2.add_member(host="client")

                # Start SSSD
                client.sssd.start()

                # Call `getent netgroup ng-1` and assert the results
                result = client.tools.getent.netgroup("ng-1")
                assert result is not None
                assert result.name == "ng-1"
                assert len(result.members) == 2
                assert "(-,user-1,)" in result.members
                assert "(client,-,)" in result.members

        :param name: Netgroup name.
        :type name: str
        :param basedn: Base dn, defaults to ``ou=netgroups``
        :type basedn: LDAPObject | str | None, optional
        :return: New netgroup object.
        :rtype: SambaNetgroup
        """
        return SambaNetgroup(self, name, basedn)

    def computer(self, name: str) -> SambaComputer:
        """
        Get computer object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.AD)
            def test_example(client: Client, samba: Samba):
                # Create OU
                ou = ad.ou("test").add().dn
                # Move computer object
                ad.computer(client.host.hostname.split(".")[0]).move(ou)

                client.sssd.start()

        :param name: Computer name.
        :type name: str
        :return: New computer object.
        :rtype: ADComputer
        """
        return SambaComputer(self, name)

    def gpo(self, name: str) -> GPO:
        """
        Get group policy object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.AD)
            def test_ad__gpo_is_set_to_enforcing(client: Client, samba: Samba):
                user = ad.user("user").add()
                allow_user = ad.user("allow_user").add()
                deny_user = ad.user("deny_user").add()

                ad.gpo("test policy").add().policy(
                    {
                    "SeInteractiveLogonRight": [allow_user, ad.group("Domain Admins")],
                    "SeRemoteInteractiveLogonRight": [allow_user, ad.group("Domain Admins")],
                    "SeDenyInteractiveLogonRight": [deny_user],
                    "SeDenyRemoteInteractiveLogonRight": [deny_user],
                    }
                ).link()

                client.sssd.domain["ad_gpo_access_control"] = "enforcing"
                client.sssd.start()

                assert client.auth.ssh.password(username="allow_user", password="Secret123")
                assert not client.auth.ssh.password(username="user", password="Secret123")
                assert not client.auth.ssh.password(username="deny_user", password="Secret123")

        :param name: Name of the GPO.
        :type name: str
        """
        return GPO(self, name)

    def ou(self, name: str, basedn: LDAPObject | str | None = None) -> SambaOrganizationalUnit:
        """
        Get organizational unit object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.Samba)
            def test_example(client: Client, samba: Samba):
                # Create organizational unit for sudo rules
                ou = samba.ou('mysudoers').add()

                # Create user
                samba.user('user-1').add()

                # Create sudo rule
                samba.sudorule('testrule', basedn=ou).add(user='ALL', host='ALL', command='/bin/ls')

                client.sssd.common.sudo()
                client.sssd.start()

                # Test that user can run /bin/ls
                assert client.auth.sudo.run('user-1', 'Secret123', command='/bin/ls')

        :param name: Unit name.
        :type name: str
        :param basedn: Base dn, defaults to None
        :type basedn: LDAPObject | str | None, optional
        :return: New organizational unit object.
        :rtype: SambaOrganizationalUnit
        """
        return SambaOrganizationalUnit(self, name, basedn)

    def sudorule(self, name: str, basedn: LDAPObject | str | None = "ou=sudoers") -> SambaSudoRule:
        """
        Get sudo rule object.

        .. code-blocK:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.Samba)
            def test_example(client: Client, samba: Samba):
                user = samba.user('user-1').add(password="Secret123")
                samba.sudorule('testrule').add(user=user, host='ALL', command='/bin/ls')

                client.sssd.common.sudo()
                client.sssd.start()

                # Test that user can run /bin/ls
                assert client.auth.sudo.run('user-1', 'Secret123', command='/bin/ls')

        :param name: Rule name.
        :type name: str
        :param basedn: Base dn, defaults to ``ou=sudoers``
        :type basedn: LDAPObject | str | None, optional
        :return: New sudo rule object.
        :rtype: SambaSudoRule
        """
        return SambaSudoRule(self, SambaUser, SambaGroup, name, basedn)


class SambaObject(BaseObject):
    """
    Base class for Samba DC object management.

    Provides shortcuts for command execution and implementation of :meth:`get`
    and :meth:`delete` methods.
    """

    def __init__(self, role: Samba, command: str, name: str) -> None:
        """
        :param role: Samba role object.
        :type role: Samba
        :param command: Samba command group.
        :type command: str
        :param name: Object name.
        :type name: str
        """
        super().__init__(role)

        self.command: str = command
        """Samba-tool command."""

        self.name: str = name
        """Object name."""

        self.__dn: str | None = None

        self.__sid: str | None = None

    def _exec(self, op: str, args: list[str] | None = None, **kwargs) -> SSHProcessResult:
        """
        Execute samba-tool command.

        .. code-block:: console

            $ samba-tool $command $ op $name $args
            for example >>> samba-tool user add tuser

        :param op: Command group operation (usually add, delete, show)
        :type op: str
        :param args: List of additional command arguments, defaults to None
        :type args: list[str] | None, optional
        :return: SSH process result.
        :rtype: SSHProcessResult
        """
        if args is None:
            args = []

        return self.role.host.ssh.exec(["samba-tool", self.command, op, self.name, *args], **kwargs)

    def _add(self, attrs: CLIBuilderArgs) -> None:
        """
        Add Samba object.

        :param attrs: Object attributes in :class:`pytest_mh.cli.CLIBuilder` format, defaults to dict()
        :type attrs: pytest_mh.cli.CLIBuilderArgs, optional
        """
        self._exec("add", self.cli.args(attrs))

    def _modify(self, attrs: dict[str, Any | list[Any] | DeleteAttribute | None]) -> None:
        """
        Modify Samba object.

        :param attrs: Attributes to modify.
        :type attrs: dict[str, Any  |  list[Any]  |  DeleteAttribute  |  None]
        """
        obj = self.get()

        # Remove dn and distinguishedName attributes
        dn = obj.pop("dn")[0]
        del obj["distinguishedName"]

        # Build old attrs
        old_attrs = {k: [str(i).encode("utf-8") for i in v] for k, v in obj.items()}

        # Update object
        for attr, value in attrs.items():
            if value is None:
                continue

            if isinstance(value, DeleteAttribute):
                del obj[attr]
                continue

            if not isinstance(value, list):
                obj[attr] = [str(value)]
                continue

            obj[attr] = to_list_of_strings(value)

        # Build new attrs
        new_attrs = {k: [str(i).encode("utf-8") for i in v] for k, v in obj.items()}

        # Build diff
        modlist = ldap.modlist.modifyModlist(old_attrs, new_attrs)
        if modlist:
            self.role.host.conn.modify_s(dn, modlist)

    def delete(self) -> None:
        """
        Delete Samba object.
        """
        self._exec("delete")

    def get(self, attrs: list[str] | None = None) -> dict[str, list[str]]:
        """
        Get Samba object attributes.

        :param attrs: If set, only requested attributes are returned, defaults to None
        :type attrs: list[str] | None, optional
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]]
        """
        cmd = self._exec("show")
        return attrs_parse(cmd.stdout_lines, attrs)

    @property
    def dn(self) -> str:
        """
        Object's distinguished name.
        """
        if self.__dn is not None:
            return self.__dn

        obj = self.get(["dn"])
        self.__dn = obj.pop("dn")[0]
        return self.__dn

    @property
    def sid(self) -> str:
        """
        Object's security identifier.
        """
        if self.__sid is not None:
            return self.__sid

        obj = self.get(["objectSid"])
        self.__sid = obj.pop("objectSid")[0]
        return self.__sid


class SambaUser(SambaObject):
    """
    Samba user management.
    """

    def __init__(self, role: Samba, name: str) -> None:
        """
        :param role: Samba role object.
        :type role: Samba
        :param name: User name.
        :type name: str
        """
        super().__init__(role, "user", name)

    def add(
        self,
        *,
        uid: int | None = None,
        gid: int | None = None,
        password: str | None = "Secret123",
        home: str | None = None,
        gecos: str | None = None,
        shell: str | None = None,
        email: str | None = None,
    ) -> SambaUser:
        """
        Create new Samba user.

        Parameters that are not set are ignored.

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
        :param email: Email, defaults to None (= user@domain)
        :type email:  str | None, optional
        :return: Self.
        :rtype: SambaUser
        """
        if email is None:
            email = f"{self.name}@{self.host.domain}"

        attrs: CLIBuilderArgs = {
            "password": (self.cli.option.POSITIONAL, password),
            "given-name": (self.cli.option.VALUE, self.name),
            "surname": (self.cli.option.VALUE, self.name),
            "uid-number": (self.cli.option.VALUE, uid),
            "gid-number": (self.cli.option.VALUE, gid),
            "unix-home": (self.cli.option.VALUE, home),
            "gecos": (self.cli.option.VALUE, gecos),
            "login-shell": (self.cli.option.VALUE, shell),
            "mail-address": (self.cli.option.VALUE, email),
        }

        self._add(attrs)
        return self

    def modify(
        self,
        *,
        uid: int | DeleteAttribute | None = None,
        gid: int | DeleteAttribute | None = None,
        home: str | DeleteAttribute | None = None,
        gecos: str | DeleteAttribute | None = None,
        shell: str | DeleteAttribute | None = None,
        email: str | DeleteAttribute | None = None,
    ) -> SambaUser:
        """
        Modify existing Samba user.

        Parameters that are not set are ignored. If needed, you can delete an
        attribute by setting the value to :attr:`Delete`.

        :param uid: User id, defaults to None
        :type uid: int | DeleteAttribute | None, optional
        :param gid: Primary group id, defaults to None
        :type gid: int | DeleteAttribute | None, optional
        :param home: Home directory, defaults to None
        :type home: str | DeleteAttribute | None, optional
        :param gecos: GECOS, defaults to None
        :type gecos: str | DeleteAttribute | None, optional
        :param shell: Login shell, defaults to None
        :type shell: str | DeleteAttribute | None, optional
        :param email: Email, defaults to None
        :type email: str | DeleteAttribute | None, optional
        :return: Self.
        :rtype: SambaUser
        """
        unix_attrs: dict[str, Any] = {
            "uidNumber": uid,
            "gidNumber": gid,
            "unixHomeDirectory": home,
            "gecos": gecos,
            "loginShell": shell,
        }

        samba_attrs: dict[str, Any] = {"emailAddress": email}
        attrs = {**unix_attrs, **samba_attrs}

        self._modify(attrs)
        return self

    def passkey_add(self, passkey_mapping: str) -> SambaUser:
        """
        Add passkey mapping to the user.

        :param passkey_mapping: Passkey mapping generated by ``sssctl passkey-register``
        :type passkey_mapping: str
        :return: Self.
        :rtype: SambaUser
        """
        attrs: LDAPRecordAttributes = {"altSecurityIdentities": passkey_mapping}
        self.role.ldap.modify(self.dn, add=attrs)
        return self

    def passkey_remove(self, passkey_mapping: str) -> SambaUser:
        """
        Remove passkey mapping from the user.

        :param passkey_mapping: Passkey mapping generated by ``sssctl passkey-register``
        :type passkey_mapping: str
        :return: Self.
        :rtype: SambaUser.
        """
        attrs: LDAPRecordAttributes = {"altSecurityIdentities": passkey_mapping}
        self.role.ldap.modify(self.dn, delete=attrs)
        return self


class SambaGroup(SambaObject):
    """
    Samba group management.
    """

    def __init__(self, role: Samba, name: str) -> None:
        """
        :param role: Samba role object.
        :type role: Samba
        :param name: Group name.
        :type name: str
        """
        super().__init__(role, "group", name)

    def add(
        self,
        *,
        gid: int | None = None,
        description: str | None = None,
        scope: str = "Global",
        category: str = "Security",
    ) -> SambaGroup:
        """
        Create new Samba group.

        :param gid: Group id, defaults to None
        :type gid: int | None, optional
        :param description: Description, defaults to None
        :type description: str | None, optional
        :param scope: Scope ('Global', 'Universal', 'DomainLocal'), defaults to 'Global'
        :type scope: str, optional
        :param category: Category ('Distribution', 'Security'), defaults to 'Security'
        :type category: str, optional
        :return: Self.
        :rtype: SambaGroup
        """
        attrs: CLIBuilderArgs = {
            "gid-number": (self.cli.option.VALUE, gid),
            "description": (self.cli.option.VALUE, description),
            "group-scope": (self.cli.option.VALUE, scope),
            "group-type": (self.cli.option.VALUE, category),
        }

        # NIS Domain is required by samba-tool if gid number is set.
        # It is stored in msSFU30NisDomain attribute of the group which is not
        # used by SSSD so we can just provide hard coded value.
        if gid is not None:
            attrs["nis-domain"] = (self.cli.option.VALUE, "samba")

        self._add(attrs)
        return self

    def modify(
        self,
        *,
        gid: int | DeleteAttribute | None = None,
        description: str | DeleteAttribute | None = None,
    ) -> SambaGroup:
        """
        Modify existing Samba group.

        Parameters that are not set are ignored. If needed, you can delete an
        attribute by setting the value to :attr:`Delete`.

        :param gid: Group id, defaults to None
        :type gid: int | DeleteAttribute | None, optional
        :param description: Description, defaults to None
        :type description: str | DeleteAttribute | None, optional
        :return: Self.
        :rtype: SambaUser
        """
        attrs: dict[str, Any] = {
            "gidNumber": gid,
            "description": description,
        }

        self._modify(attrs)
        return self

    def add_member(self, member: SambaUser | SambaGroup) -> SambaGroup:
        """
        Add group member.

        :param member: User or group to add as a member.
        :type member: SambaUser | SambaGroup
        :return: Self.
        :rtype: SambaGroup
        """
        return self.add_members([member])

    def add_members(self, members: list[SambaUser | SambaGroup]) -> SambaGroup:
        """
        Add multiple group members.

        :param members: List of users or groups to add as members.
        :type members: list[SambaUser | SambaGroup]
        :return: Self.
        :rtype: SambaGroup
        """
        self._exec("addmembers", self.__get_member_args(members))
        return self

    def remove_member(self, member: SambaUser | SambaGroup) -> SambaGroup:
        """
        Remove group member.

        :param member: User or group to remove from the group.
        :type member: SambaUser | SambaGroup
        :return: Self.
        :rtype: SambaGroup
        """
        return self.remove_members([member])

    def remove_members(self, members: list[SambaUser | SambaGroup]) -> SambaGroup:
        """
        Remove multiple group members.

        :param members: List of users or groups to remove from the group.
        :type members: list[SambaUser | SambaGroup]
        :return: Self.
        :rtype: SambaGroup
        """
        self._exec("removemembers", self.__get_member_args(members))
        return self

    def __get_member_args(self, members: list[SambaUser | SambaGroup]) -> list[str]:
        return [",".join([x.name for x in members])]


class SambaComputer(SambaObject):
    """
    AD computer management.
    """

    def __init__(self, role: Samba, name: str) -> None:
        """
        :param role: AD role object.
        :type role: AD
        :param name: Computer name.
        :type name: str
        """
        super().__init__(role, "Computer", name)

    def move(self, target: str) -> SambaComputer:
        """
        Move a computer object.
        :param target: Target path.
        :type target: str

        :return: Self.
        :rtype: SambaComputer
        """
        if self.name.startswith("cn"):
            _name = self.name.split(",")[0].split("=")[1]
            self._exec("Move", [self.name, target])

        return self


class GPO(BaseObject[SambaHost, Samba]):
    """
    Group policy object management.
    """

    def __init__(self, role: Samba, name: str) -> None:
        """
        :param name: GPO name, defaults to 'Domain Test Policy'
        :type name: str, optional
        """
        super().__init__(role)

        self.name: str = name
        """Group policy display name."""

        self.target: str | None = None
        """Group policy target."""

        self._search_base: str = f"cn=policies,cn=system,{self.role.host.naming_context}"
        """Group policy search base."""

        self._dn = self.get("dn")
        """Group policy dn."""

        self._cn = self.get("GPO")
        """Group policy cn."""

    def get(self, key: str) -> str | None:
        """
        Get group policy attributes.

        :param key: Attribute to get.
        :type key: str
        :return: Key value.
        :rtype: str
        """
        result = []
        if self.name is not None:
            for i in self.role.host.ssh.run("samba-tool gpo listall").stdout_lines:
                if "GENSEC" not in i:
                    result.append(i)

        result = attrs_parse(result, [key])

        for k, v in result.items():
            if k == self.name:
                return v[0]

        return None

    def delete(self) -> None:
        """
        Delete group policy object.
        """
        self.role.host.ssh.run(f"samba-tool gpo del {self._cn}")

    def add(self) -> GPO:
        """
        Add a group policy object.

        :return: Group policy object
        :rtype: GPO
        """
        self.role.host.ssh.run(f"samba-tool gpo create {self.name}")

        self._cn = self.get("GPO")
        self._dn = self.get("dn")

        return self

    def link(
            self,
            target: str | None = "Default-First-Site-Name",
            args: list[str] | str | None = None,
    ) -> GPO:
        """
        Link the group policy to the target object inside the directory, a site, domain or an ou.

        ..Note::
            The New and Set cmdlets are identical. To modify an existing link,
            change the $op parameter to "Set", i.e. to disable 'Enforced'

            ou_policy.link("Set", args=["-Enforced No"])

        :param target: Group policy target, defaults to 'Default-First-Site-Name'
        :type target: str, optional
        :param args: Additional arguments
        :type args: list[str] | None, optional
        :return: Group policy object
        :rtype: GPO
        :TODO: Need to check args and map them to samba args
        """
        if args is None:
            args = []

        if isinstance(args, list):
            args = " ".join(args)
        elif args is None:
            args = ""

        self.target = target

        self.role.host.ssh.run(f"samba-tool gpo setlink {self.target} {self._cn}")
        # -UAdministrator --enforce --disable

        return self

    def unlink(self) -> GPO:
        """
        Unlink the group policy from the target.

        :return: Group policy object
        :rtype: GPO
        """
        self.role.host.ssh.run(f"samba-tool gpo dellink {self.target} {self._cn}")

        return self

    def permissions(self, level: str, target_type: str | None = "User") -> GPO:
        """
        Configure group policy object permissions.

        :param level: Permission level
        :type level: str, values should be 'GpoRead | GpoApply | GpoEdit | GpoEditDeleteModifySecurity | None'
        :param target_type: Target type, defaults to 'user'
        :type target_type: str, optional, values should be 'user | group | computer'
        :return: Group policy object
        :rtype: GPO
        :TODO: Figure out dsacl and what permissions can we set on the GPO object
        """
        self.role.host.ssh.run(
            #f'Set-GPPermission -Guid "{self._cn}" -PermissionLevel {level} -Type "{target_type}" -Replace $True'
            f"samba-tool dsacl"
        )

        return self

    def policy(self, logon_rights: dict[str, list[SambaObject]]) -> GPO:
        """
        Group policy configuration.

        This method does the remaining configuration of the group policy. It updates
        'GptTmpl.inf' with security logon right keys with the SIDs of users and groups
        objects. The *Remote* keys can be omitted, in which the corresponding keys values
        will then be used.

        To add users and groups to the policy, the SID must be used for the values. The
        values need to be prefixed with an '*' and use a comma for a de-limiter, i.e.
        `*SID1-2-3-4,*SID-5-6-7-8`

        Additionally, gPCMachineExtensionNames need to be updated in the directory so
        the GPO is readable to the client. The value is a list of Client Side
        Extensions (CSEs), that is an index of what part of the policy is pushed and
        processed by the client.

        :param logon_rights: List of logon rights.
        :type logon_rights: dict[str, list[SambaObject]]
        :return: Group policy object
        :rtype: GPO
        """
        _path: str = os.path.join("/var/lib/samba/sysvol/samba.test/Policies/",
                                  self._cn,
                                  "\{MACHINE/Microsoft/Windows\ NT/SecEdit/GptTmpl.inf")

        _keys: list[str] = [
            "SeInteractiveLogonRight",
            "SeRemoteInteractiveLogonRight",
            "SeDenyInteractiveLogonRight",
            "SeDenyRemoteInteractiveLogonRight",
        ]

        for i in _keys:
            if i not in logon_rights.keys() and i == "SeRemoteInteractiveLogonRight":
                logon_rights[i] = logon_rights["SeInteractiveLogonRight"]
            if i not in logon_rights.keys() and i == "SeDenyRemoteInteractiveLogonRight":
                logon_rights[i] = logon_rights["SeDenyInteractiveLogonRight"]

        for i in _keys:
            if i not in logon_rights.keys():
                raise KeyError(f"Expected {i} but got {logon_rights.keys()}")

        _logon_rights: dict[str, Any] = {}
        for k, v in logon_rights.items():
            sids: list[str] = []
            for j in v:
                sids.append(f"*{j.sid}")
                _logon_rights = {**_logon_rights, **{k: ",".join(sids)}}

        config = configparser.ConfigParser = configparser.ConfigParser(interpolation=None)
        config.add_section("Unicode")
        config.set("Unicode", "Unicode", "yes")
        config.add_section("Version")
        config.set("Version", "signature", "\"$CHICAGO$\"")
        config.set("Version", "Revision", "1")

        for k, v in logon_rights.items():
            _value = ""
            for i in enumerate(v):
                if i != len(v) - 1:
                    _value = _value + str(i) + ";"
                else:
                    _value = _value + str(i)
            config.set("Privilege Rights", _value)

        self.host.fs.write(_path, config)

        return self


SambaOrganizationalUnit: TypeAlias = LDAPOrganizationalUnit[SambaHost, Samba]
SambaAutomount: TypeAlias = LDAPAutomount[SambaHost, Samba]
SambaSudoRule: TypeAlias = LDAPSudoRule[SambaHost, Samba, SambaUser, SambaGroup]
SambaNetgroup: TypeAlias = LDAPNetgroup[SambaHost, Samba, SambaUser]
SambaNetgroupMember: TypeAlias = LDAPNetgroupMember[SambaUser, SambaNetgroup]
