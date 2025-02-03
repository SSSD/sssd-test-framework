"""Samba multihost role."""

from __future__ import annotations

import base64
import configparser
from typing import Any, TypeAlias

import ldap.modlist
from pytest_mh.cli import CLIBuilderArgs
from pytest_mh.conn import ProcessResult

from ..hosts.samba import SambaHost
from ..misc import attrs_parse, to_list_of_strings
from ..utils.ldap import LDAPRecordAttributes
from .base import BaseLinuxLDAPRole, BaseObject, DeleteAttribute
from .generic import GenericPasswordPolicy
from .ldap import LDAPAutomount, LDAPNetgroup, LDAPNetgroupMember, LDAPObject, LDAPOrganizationalUnit, LDAPSudoRule

__all__ = [
    "Samba",
    "SambaObject",
    "SambaComputer",
    "SambaPasswordPolicy",
    "SambaUser",
    "SambaGroup",
    "SambaOrganizationalUnit",
    "SambaAutomount",
    "SambaSudoRule",
    "SambaGPO",
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

    @property
    def naming_context(self) -> str:
        """
        Samba naming context.

        :rtype: str
        """
        return self.host.naming_context

    def fqn(self, name: str) -> str:
        """
        Return fully qualified name in form name@domain.
        """
        return f"{name}@{self.domain}"

    @property
    def password(self) -> SambaPasswordPolicy:
        """
        Domain password policy management.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.Samba)
            def test_example(client: Client, samba: Samba):
                # Enable password complexity
                samba.password.complexity(enable=True)

                # Set 3 login attempts and 30 lockout duration
                samba.password.lockout(attempts=3, duration=30)

                # Set password length requirement to 12 characters
                samba.password.requirement(length=12)

                # Set password max age to 30 seconds
                samba.password.age(maximum=30)
        """
        return SambaPasswordPolicy(self)

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

        :param name: Username.
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

            @pytest.mark.topology(KnownTopology.Samba)
            def test_example(client: Client, samba: Samba):
                # Create OU
                ou = samba.ou("test").add().dn
                # Move computer object
                samba.computer(client.host.hostname.split(".")[0]).move(ou)

                client.sssd.start()

        :param name: Computer name.
        :type name: str
        :return: New computer object.
        :rtype: ADComputer
        """
        return SambaComputer(self, name)

    def gpo(self, name: str) -> SambaGPO:
        """
        Get group policy object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.AD)
            def test_ad__gpo_is_set_to_enforcing(client: Client, samba: Samba):
                user = ad.user("user").add()
                allow_user = ad.user("allow_user").add()
                deny_user = ad.user("deny_user").add()

                provider.gpo("test policy").add().policy(
                    {
                    "SeInteractiveLogonRight": [allow_user, provider.group("Domain Admins")],
                    "SeRemoteInteractiveLogonRight": [allow_user, provider.group("Domain Admins")],
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
        :return: New GPO object.
        :rtype: SambaGPO
        """
        return SambaGPO(self, name)

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

    def site(self, name: str) -> SambaSite:
        """
        Get site object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.Samba)
            def test_example(client: Client, samba: Samba):
                # Create New Site, this name cannot contain spaces
                site = samba.site('New-Site').add()

        :param name: Site name.
        :type name: str, cannot contain spaces
        :return: New site object.
        :rtype: SambaSite
        """
        return SambaSite(self, name)

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

        self.naming_context: str = role.ldap.naming_context
        """Domain naming context."""

        self.__dn: str | None = None

        self.__sid: str | None = None

        self.__cn: str | None = None

    def _exec(self, op: str, args: list[str] | None = None, **kwargs) -> ProcessResult:
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
        :rtype: ProcessResult
        """
        if args is None:
            args = []

        if self.command == "gpo":
            return self.role.host.conn.exec(["samba-tool", self.command, op, self.__cn, *args], **kwargs)

        return self.role.host.conn.exec(["samba-tool", self.command, op, self.name, *args], **kwargs)

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
            self.role.host.ldap_conn.modify_s(dn, modlist)

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

        # The samba-tool gpo show command returns a limited list of attributes, so we use LDAP instead
        # The LDAP output is formatted to be like samba-tool
        if self.command == "gpo":
            result = self.role.host.ldap_conn.search_s(
                f"cn=system,{self.naming_context}",
                ldap.SCOPE_SUBTREE,
                f"(&(objectClass=groupPolicyContainer)(displayName={self.name}))",
                attrlist=attrs,
            )

            (_, result_attrs) = result[0]
            out: list[str] = []
            for key, values in result_attrs.items():
                for value in values:
                    try:
                        decoded = value.decode("utf-8")
                    except UnicodeDecodeError:
                        decoded = base64.b64encode(value).decode("utf-8")
                    # The dn is missing from the output
                    if key == "distinguishedName":
                        out.insert(0, f"dn: {decoded}")
                    out.append(f"{key}: {decoded}")
            cmd = out
        else:
            cmd = self._exec("show").stdout_lines

        return attrs_parse(cmd, attrs)

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
    def cn(self) -> str:
        """
        Object's distinguished name.
        """
        if self.__cn is not None:
            return self.__cn

        obj = self.get(["cn"])
        self.__cn = obj.pop("cn")[0]
        return self.__cn

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

    def password_change_at_logon(self) -> SambaUser:
        """
        Force user to change password next logon.

        :return: Self.
        :rtype: SambaUser
        """
        self._modify({"pwdLastSet": "0"})
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
        super().__init__(role, "computer", name)

    def move(self, target: str) -> SambaComputer:
        """
        Move a computer object.

        :param target: Target path.
        :type target: str
        :return: Self.
        :rtype: SambaComputer
        """
        self._exec("move", [target])

        return self


class SambaSite(SambaObject):
    """
    AD Sites management.
    """

    def __init__(self, role: Samba, name: str) -> None:
        """
        :param role: Samba role object.
        :type role: Samba
        :param name: Site name, cannot contain spaces.
        :type name: str
        """
        super().__init__(role, "sites", name)

    def add(self) -> SambaSite:
        """
        Create new Samba site.

        :return: Self.
        :rtype: SambaSite
        """
        self._exec("create")

        return self


class SambaGPO(SambaObject):
    """
    Group policy object management.
    """

    def __init__(self, role: Samba, name: str) -> None:
        """
        :param name: GPO name, defaults to 'Domain Test Policy'
        :type name: str, optional
        """
        super().__init__(role, "gpo", name)

        self.target: str | None = None
        """Group policy target."""

        self.search_base: str = f"cn=policies,cn=system,{self.role.host.naming_context}"
        """Group policy search base."""

        # samba-tool gpo commands edit the database files directly and need to be authenticated.
        self.credentials: str = f" --username={self.role.host.admin} --password={self.role.host.adminpw}"
        """Credentials to manage GPOs."""

    def add(self) -> SambaGPO:
        """
        Add a group policy object.

        :return: Samba group policy object
        :rtype: SambaGPO
        """
        self.host.conn.run(f'samba-tool gpo create "{self.name}" {self.credentials}')

        return self

    def delete(self) -> None:
        """
        Delete group policy object.
        """
        self.role.host.conn.run(f'samba-tool gpo del "{self.cn}" {self.credentials}')

    def link(
        self,
        target: str | None = None,
        enforced: bool | None = False,
        disabled: bool | None = False,
    ) -> SambaGPO:
        """
        Link the group policy to the target object inside the directory, a site, domain or an ou.

        :param target: Group policy target, defaults to 'Default-First-Site-Name'
        :type target: str, optional
        :param enforced: Enforced the policy
        :type enforced: bool, optional
        :param disabled: Disable the policy
        :type disabled: bool, optional
        :return: Samba group policy object
        :rtype: SambaGPO
        """
        if target is None and self.target is None:
            self.target = f"CN=Default-First-Site-Name,CN=Sites,CN=Configuration,{self.role.host.naming_context}"

        if target is not None and self.target is None:
            self.target = target

        args: CLIBuilderArgs = {
            "Target": (self.cli.option.POSITIONAL, self.target),
            "Guid": (self.cli.option.POSITIONAL, self.cn),
            "enforce": (self.cli.option.SWITCH, enforced),
            "disable": (self.cli.option.SWITCH, disabled),
            "username": (self.cli.option.VALUE, self.role.host.admin),
            "password": (self.cli.option.VALUE, self.role.host.adminpw),
        }

        self.host.conn.run(self.cli.command("samba-tool gpo setlink", args))

        return self

    def unlink(self) -> SambaGPO:
        """
        Unlink the group policy from the target.

        :return: Samba group policy object
        :rtype: SambaGPO
        """
        self.host.conn.run(f'samba-tool gpo dellink "{self.target}" "{self.cn}" {self.credentials}')

        return self

    def policy(self, logon_rights: dict[str, list[SambaObject]], cfg: dict[str, Any] | None = None) -> SambaGPO:
        """
        Group policy configuration.

        This method does the remaining configuration of the group policy. It updates
        'GptTmpl.inf' with security logon right keys with the SIDs of users and groups
        objects. The *Remote* keys can be omitted, in which the interactive key's value
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
        :param cfg: Extra configuration for GptTmpl.inf file, defaults to None
        :type cfg: dict[str, Any] | None, optional
        :return: Samba Group policy object
        :rtype: SambaGPO
        """
        _path: str = (
            f"/var/lib/samba/sysvol/"
            f"{self.role.domain}/"
            f"Policies/{self.cn}"
            f"/MACHINE/Microsoft/Windows "
            f"NT/SecEdit/"
        )
        _full_path: str = f"{_path}GptTmpl.inf"

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

        config = configparser.ConfigParser(interpolation=None)
        config.optionxform = str  # type: ignore
        config["Unicode"] = {}
        config["Unicode"]["Unicode"] = "yes"
        config["Version"] = {}
        config["Version"]["signature"] = '"$CHICAGO$"'
        config["Version"]["Revision"] = "1"
        config["Privilege Rights"] = {}

        for k, v in _logon_rights.items():
            config["Privilege Rights"][k] = v  # type: ignore

        if cfg is not None:
            for _k, _v in cfg.items():
                config[_k] = {}
                for __k, __v in _v.items():
                    config[_k][__k] = __v

        config.write(open("/tmp/GptTmpl.inf", "w"))

        # The enable the GPO the gPCMachineExtensionNames attributes needs to be updated with the proper CSEs
        attrs: LDAPRecordAttributes = {
            "gPCMachineExtensionNames": "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}"
            "{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"
        }
        self._modify(attrs)

        self.role.fs.mkdir_p(_path, mode="750", user="BUILTIN\\administrators", group="users")
        self.role.fs.upload("/tmp/GptTmpl.inf", _full_path, mode="750", user="BUILTIN\\administrators", group="users")

        return self


class SambaPasswordPolicy(GenericPasswordPolicy):
    """
    Password policy management.
    """

    def __init__(self, role: Samba):
        """
        :param role: Samba host object.
        :type role: SambaHost
        """
        super().__init__(role)

    def complexity(self, enable: bool) -> SambaPasswordPolicy:
        """
        Enable or disable password complexity.

        :param enable: Enable or disable password complexity.
        :type enable: bool
        :return: SambaPasswordPolicy object.
        :rtype: SambaPasswordPolicy
        """
        complexity: str = "on" if enable else "off"

        args: CLIBuilderArgs = {
            "complexity": (self.cli.option.VALUE, complexity),
        }

        self.host.conn.run(self.cli.command("samba-tool domain passwordsettings set", args))

        return self

    def lockout(self, duration: int, attempts: int) -> SambaPasswordPolicy:
        """
        Set lockout duration and login attempts.

        :param duration: Duration of lockout in seconds, converted to minutes.
        :type duration: int
        :param attempts: Number of login attempts.
        :type attempts: int
        :return: SambaPasswordPolicy object.
        :rtype: SambaPasswordPolicy
        """
        minutes = divmod(duration, 60)[0]

        args: CLIBuilderArgs = {
            "account-lockout-duration": (self.cli.option.VALUE, str(minutes)),
            "account-lockout-threshold": (self.cli.option.VALUE, str(attempts)),
        }
        self.host.conn.run(self.cli.command("samba-tool domain passwordsettings set", args))

        return self

    def age(self, minimum: int, maximum: int) -> SambaPasswordPolicy:
        """
        Set maximum and minimum password age.

        :param minimum: Minimum password age in seconds, converted to days.
        :type minimum: int
        :param maximum: Maximum password age in seconds, converted to days.
        :type maximum: int
        :return: SambaPasswordPolicy object.
        :rtype: SambaPasswordPolicy
        """
        _minimum: int = divmod(minimum, 3600)[0]
        _maximum: int = divmod(maximum, 3600)[0]

        args: CLIBuilderArgs = {
            "min-pwd-age": (self.cli.option.VALUE, str(_minimum)),
            "max-pwd-age": (self.cli.option.VALUE, str(_maximum)),
        }
        self.host.conn.run(self.cli.command("samba-tool domain passwordsettings set", args))

        return self

    def requirements(self, length: int) -> SambaPasswordPolicy:
        """
        Set password requirements, like length.

        :param length: Required password character count.
        :type length: int
        :return: SambaPasswordPolicy object.
        :rtype: SambaPasswordPolicy
        """
        args: CLIBuilderArgs = {
            "min-pwd-length": (self.cli.option.VALUE, str(length)),
        }
        self.host.conn.run(self.cli.command("samba-tool domain passwordsettings set", args))

        return self


SambaOrganizationalUnit: TypeAlias = LDAPOrganizationalUnit[SambaHost, Samba]
SambaAutomount: TypeAlias = LDAPAutomount[SambaHost, Samba]
SambaSudoRule: TypeAlias = LDAPSudoRule[SambaHost, Samba, SambaUser, SambaGroup]
SambaNetgroup: TypeAlias = LDAPNetgroup[SambaHost, Samba, SambaUser]
SambaNetgroupMember: TypeAlias = LDAPNetgroupMember[SambaUser, SambaNetgroup]
