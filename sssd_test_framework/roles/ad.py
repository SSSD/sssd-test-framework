"""Active Directory multihost role."""

from __future__ import annotations

from typing import Any, TypeAlias

from pytest_mh.cli import CLIBuilderArgs
from pytest_mh.ssh import SSHClient, SSHPowerShellProcess, SSHProcessResult

from ..hosts.ad import ADHost
from ..misc import attrs_include_value, attrs_parse, attrs_to_hash
from .base import BaseObject, BaseWindowsRole, DeleteAttribute
from .ldap import LDAPNetgroupMember
from .nfs import NFSExport

__all__ = [
    "AD",
    "ADAutomount",
    "ADAutomountMap",
    "ADGroup",
    "ADObject",
    "ADOrganizationalUnit",
    "ADComputer",
    "ADSudoRule",
    "ADUser",
    "GPO",
]


class AD(BaseWindowsRole[ADHost]):
    """
    AD service management.
    """

    """
    Active Directory role.

    Provides unified Python API for managing objects in the Active Directory
    domain controller.

    .. code-block:: python
        :caption: Creating user and group

        @pytest.mark.topology(KnownTopology.AD)
        def test_example(ad: AD):
            u = ad.user('tuser').add()
            g = ad.group('tgroup').add()
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
        Active Directory domain name.
        """

        self.realm: str = self.host.realm
        """
        Kerberos realm.
        """

        self.auto_ou: dict[str, bool] = {}
        """Organizational units that were automatically created."""

        self.automount: ADAutomount = ADAutomount(self)
        """
        Manage automount maps and keys.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.AD)
            def test_example_autofs(client: Client, ad: AD, nfs: NFS):
                nfs_export1 = nfs.export('export1').add()
                nfs_export2 = nfs.export('export2').add()
                nfs_export3 = nfs.export('sub/export3').add()

                # Create automount maps
                auto_master = ad.automount.map('auto.master').add()
                auto_home = ad.automount.map('auto.home').add()
                auto_sub = ad.automount.map('auto.sub').add()

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

    def ssh(self, user: str, password: str, *, shell=SSHPowerShellProcess) -> SSHClient:
        """
        Open SSH connection to the host as given user.

        :param user: Username.
        :type user: str
        :param password: User password.
        :type password: str
        :param shell: Shell that will run the commands, defaults to SSHPowerShellProcess
        :type shell: str, optional
        :return: SSH client connection.
        :rtype: SSHClient
        """
        return super().ssh(user, password, shell=shell)

    def fqn(self, name: str) -> str:
        """
        Return fully qualified name in form name@domain.
        """
        return f"{name}@{self.domain}"

    def user(self, name: str, basedn: ADObject | str | None = "cn=users") -> ADUser:
        """
        Get user object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.AD)
            def test_example(client: Client, ad: AD):
                # Create user
                ad.user('user-1').add()

                # Start SSSD
                client.sssd.start()

                # Call `id user-1` and assert the result
                result = client.tools.id('user-1')
                assert result is not None
                assert result.user.name == 'user-1'
                assert result.group.name == 'domain users'

        :param name: User name.
        :type name: str
        :param basedn: Base dn, defaults to ``cn=users``
        :type basedn: ADObject | str | None, optional
        :return: New user object.
        :rtype: ADUser
        """
        return ADUser(self, name, basedn)

    def group(self, name: str, basedn: ADObject | str | None = "cn=users") -> ADGroup:
        """
        Get group object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.AD)
            def test_example_group(client: Client, ad: AD):
                # Create user
                user = ad.user('user-1').add()

                # Create secondary group and add user as a member
                ad.group('group-1').add().add_member(user)

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
        :param basedn: Base dn, defaults to ``cn=users``
        :type basedn: ADObject | str | None, optional
        :return: New group object.
        :rtype: ADGroup
        """
        return ADGroup(self, name, basedn)

    def netgroup(self, name: str, basedn: ADObject | str | None = "ou=netgroups") -> ADNetgroup:
        """
        Get netgroup object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.AD)
            def test_example_netgroup(client: Client, ad: AD):
                # Create user
                user = ad.user("user-1").add()

                # Create two netgroups
                ng1 = ad.netgroup("ng-1").add()
                ng2 = ad.netgroup("ng-2").add()

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
        :type basedn: ADObject | str | None, optional
        :return: New netgroup object.
        :rtype: ADNetgroup
        """
        return ADNetgroup(self, name, basedn)

    def ou(self, name: str, basedn: ADObject | str | None = None) -> ADOrganizationalUnit:
        """
        Get organizational unit object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.AD)
            def test_example(client: Client, ad: AD):
                # Create organizational unit for sudo rules
                ou = ad.ou('mysudoers').add()

                # Create user
                ad.user('user-1').add()

                # Create sudo rule
                ad.sudorule('testrule', basedn=ou).add(user='ALL', host='ALL', command='/bin/ls')

                client.sssd.common.sudo()
                client.sssd.start()

                # Test that user can run /bin/ls
                assert client.auth.sudo.run('user-1', 'Secret123', command='/bin/ls')

        :param name: Unit name.
        :type name: str
        :param basedn: Base dn, defaults to None
        :type basedn: ADObject | str | None, optional
        :return: New organizational unit object.
        :rtype: ADOrganizationalUnit
        """
        return ADOrganizationalUnit(self, name, basedn)

    def computer(self, name: str, basedn: ADObject | str | None = "cn=computers") -> ADComputer:
        """
        Get computer object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.AD)
            def test_example(client: Client, ad: AD):
                # Create OU
                ou = ad.ou("test").add().dn
                # Move computer object
                ad.computer(client.host.hostname.split(".")[0]).move(ou)

                client.sssd.start()

        :param name: Computer name.
        :type name: str
        :param basedn: Base dn, defaults to "cn=computers"
        :type basedn: ADObject | str | None,
        :return: New computer object.
        :rtype: ADComputer
        """
        return ADComputer(self, name, basedn)

    def gpo(self, name: str) -> GPO:
        """
        Get group policy object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.AD)
            def test_ad__gpo_is_set_to_enforcing(client: Client, ad: AD):
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

    def sudorule(self, name: str, basedn: ADObject | str | None = "ou=sudoers") -> ADSudoRule:
        """
        Get sudo rule object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.AD)
            def test_example(client: Client, ad: AD):
                user = ad.user('user-1').add(password="Secret123")
                ad.sudorule('testrule').add(user=user, host='ALL', command='/bin/ls')

                client.sssd.common.sudo()
                client.sssd.start()

                # Test that user can run /bin/ls
                assert client.auth.sudo.run('user-1', 'Secret123', command='/bin/ls')

        :param name: Rule name.
        :type name: str
        :param basedn: Base dn, defaults to ``ou=sudoers``
        :type basedn: ADObject | str | None, optional
        :return: New sudo rule object.
        :rtype: ADSudoRule
        """

        return ADSudoRule(self, name, basedn)


class ADObject(BaseObject[ADHost, AD]):
    """
    Base class for Active Directory object management.

    Provides shortcuts for command execution and implementation of :meth:`get`
    and :meth:`delete` methods.
    """

    def __init__(
        self,
        role: AD,
        command_group: str,
        name: str,
        rdn: str,
        basedn: ADObject | str | None = None,
        default_ou: str | None = None,
    ) -> None:
        """
        :param role: AD role object.
        :type role: AD
        :param command_group: AD command group.
        :type command_group: str
        :param name: Object name.
        :type name: str
        :param rdn: Relative distinguished name.
        :type rdn: str
        :param basedn: Base dn, defaults to None
        :type basedn: ADObject | str | None, optional
        :param default_ou: Name of default organizational unit that is automatically
                           created if basedn is set to ou=$default_ou, defaults to None.
        :type default_ou: str | None, optional
        """
        super().__init__(role)

        self.command_group: str = command_group
        """Active Directory Powershell module command group."""

        self.name: str = name
        """Object name."""

        self.rdn: str = rdn
        """Object relative DN."""

        self.basedn: ADObject | str | None = basedn
        """Object base DN."""

        self.dn: str = self._dn(rdn, basedn)
        """Object DN."""

        self.path: str = self._path(basedn)
        """Object path (DN of the parent container)."""

        self.default_ou: str | None = default_ou
        """Default organizational unit that usually holds this object."""

        self._identity: CLIBuilderArgs = {"Identity": (self.cli.option.VALUE, self.dn)}
        """Identity parameter used in powershell commands."""

        self.__sid: str | None = None

        self.__create_default_ou(basedn, self.default_ou)

    def __create_default_ou(self, basedn: ADObject | str | None, default_ou: str | None) -> None:
        """
        If default base dn is used we want to make sure that the container
        (usually an organizational unit) exit. This is to allow nicely working
        topology parametrization when the base dn is not specified and created
        inside the test because not all backends supports base dn (e.g. IPA).

        :param basedn: Selected base DN.
        :type basedn: ADObject | str | None
        :param default_ou: Default name of organizational unit.
        :type default_ou: str | None
        """
        if default_ou is None:
            return

        if basedn is None or not isinstance(basedn, str):
            return

        if basedn.lower() != f"ou={default_ou}" or default_ou in self.role.auto_ou:
            return

        self.role.ou(default_ou).add()
        self.role.auto_ou[default_ou] = True

    def _dn(self, rdn: str, basedn: ADObject | str | None = None) -> str:
        """
        Get distinguished name of an object.

        :param rdn: Relative DN.
        :type rdn: str
        :param basedn: Base DN, defaults to None
        :type basedn: ADObject | str | None, optional
        :return: Distinguished name combined from rdn+dn+naming-context.
        :rtype: str
        """
        if isinstance(basedn, ADObject):
            return f"{rdn},{basedn.dn}"

        if not basedn:
            return f"{rdn},{self.role.host.naming_context}"

        return f"{rdn},{basedn},{self.role.host.naming_context}"

    def _path(self, basedn: ADObject | str | None = None) -> str:
        """
        Get object LDAP path.

        :param basedn: Base DN, defaults to None
        :type basedn: ADObject | str | None, optional
        :return: Distinguished name of the parent container combined from basedn+naming-context.
        :rtype: str
        """
        if isinstance(basedn, ADObject):
            return basedn.dn

        if not basedn:
            return self.role.host.naming_context

        return f"{basedn},{self.role.host.naming_context}"

    def _exec(
        self, op: str, args: list[str] | str | None = None, *, format_with: str | None = None, **kwargs
    ) -> SSHProcessResult:
        """
        Execute AD command.

        .. code-block:: console

            $ $op-AD$command_group $args
            for example >>> New-ADUser tuser

        :param op: Command group operation (usually New, Set, Remove, Get)
        :type op: str
        :param args: List of additional command arguments, defaults to None
        :type args: list[str] | None, optional
        :param format_with: Command that will be used to format the output (e.g.
            Format-List), defaults to None (default format of executed command)
        :type format_with: str | None
        :return: SSH process result.
        :rtype: SSHProcessResult
        """
        if args is None:
            args = []

        if isinstance(args, list):
            args = " ".join(args)
        elif args is None:
            args = ""

        format = "" if format_with is None else f"| {format_with}"

        return self.role.host.ssh.run(
            f"""
            Import-Module ActiveDirectory
            {op}-AD{self.command_group} {args} {format}
        """,
            **kwargs,
        )

    def _add(self, attrs: CLIBuilderArgs) -> None:
        """
        Add Active Directory object.

        :param attrs: Object attributes in :class:`pytest_mh.cli.CLIBuilder` format, defaults to dict()
        :type attrs: pytest_mh.cli.CLIBuilderArgs, optional
        """
        self._exec("New", self.cli.args(attrs, quote_value=True))

    def _modify(self, attrs: CLIBuilderArgs) -> None:
        """
        Modifiy Active Directory object.

        :param attrs: Object attributes in :class:`pytest_mh.cli.CLIBuilder` format, defaults to dict()
        :type attrs: pytest_mh.cli.CLIBuilderArgs, optional
        """
        self._exec("Set", self.cli.args(attrs, quote_value=True))

    def delete(self) -> None:
        """
        Delete Active Directory object.
        """
        args: CLIBuilderArgs = {
            "Confirm": (self.cli.option.SWITCH, False),
            **self._identity,
        }
        self._exec("Remove", self.cli.args(args, quote_value=True))

    def get(self, attrs: list[str] | None = None) -> dict[str, list[str]]:
        """
        Get AD object attributes.

        :param attrs: If set, only requested attributes are returned, defaults to None
        :type attrs: list[str] | None, optional
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]]
        """
        cmd = self._exec("Get", self.cli.args(self._identity, quote_value=True), format_with="Format-List")
        return attrs_parse(cmd.stdout_lines, attrs)

    @property
    def sid(self) -> str | None:
        """
        Gets AD Object's SID.

        :return: SID
        :rtype: str
        """
        if self.__sid is None:
            for i in self.get(["SID"]).values():
                if len(i) == 1:
                    self.__sid = i[0]

        return self.__sid


class ADOrganizationalUnit(ADObject):
    """
    AD organizational unit management.
    """

    def __init__(self, role: AD, name: str, basedn: ADObject | str | None = None) -> None:
        """
        :param role: AD role object.
        :type role: AD
        :param name: Unit name.
        :type name: str
        :param basedn: Base dn, defaults to None
        :type basedn: ADObject | str | None, optional
        """
        super().__init__(role, "OrganizationalUnit", name, f"ou={name}", basedn)

    def add(self) -> ADOrganizationalUnit:
        """
        Create new AD organizational unit.

        :return: Self.
        :rtype: ADOrganizationalUnit
        """
        attrs: CLIBuilderArgs = {
            "Name": (self.cli.option.VALUE, self.name),
            "Path": (self.cli.option.VALUE, self.path),
            "ProtectedFromAccidentalDeletion": (self.cli.option.PLAIN, "$False"),
        }

        self._add(attrs)
        return self


class ADComputer(ADObject):
    """
    AD computer management.
    """

    def __init__(self, role: AD, name: str, basedn: ADObject | str | None = "cn=computers") -> None:
        """
        :param role: AD role object.
        :type role: AD
        :param name: Computer name.
        :type name: str
        :param basedn: Base dn, defaults to 'cn=computers'
        :type basedn: ADObject | str | None, optional
        """
        super().__init__(role, "Object", name.upper(), f"cn={name.upper()}", basedn, default_ou=None)

    def move(self, target: str) -> ADComputer:
        """
        Move a computer object.
        :param target: Target path.
        :type target: str

        :return: Self.
        :rtype: ADComputer
        """
        attrs: CLIBuilderArgs = {
            **self._identity,
            "TargetPath": (self.cli.option.VALUE, target),
        }

        self._exec("Move", self.cli.args(attrs, quote_value=True))
        self.basedn = target
        self._identity = {"Identity": (self.cli.option.VALUE, f"{self.rdn},{target}")}

        return self


class ADUser(ADObject):
    """
    AD user management.
    """

    def __init__(self, role: AD, name: str, basedn: ADObject | str | None = "cn=users") -> None:
        """
        :param role: AD role object.
        :type role: AD
        :param name: User name.
        :type name: str
        :param basedn: Base dn, defaults to 'cn=users'
        :type basedn: ADObject | str | None, optional
        """
        # There is no automatically created default ou because cn=users already exists
        super().__init__(role, "User", name, f"cn={name}", basedn, default_ou=None)

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
    ) -> ADUser:
        """
        Create new AD user.

        Parameters that are not set are ignored.

        :param uid: User id, defaults to None
        :type uid: int | None, optional
        :param gid: Primary group id, defaults to None
        :type gid: int | None, optional
        :param password: Password (cannot be None), defaults to 'Secret123'
        :type password: str, optional
        :param home: Home directory, defaults to None
        :type home: str | None, optional
        :param gecos: GECOS, defaults to None
        :type gecos: str | None, optional
        :param shell: Login shell, defaults to None
        :type shell: str | None, optional
        :param email: Email, defaults to None (= user@domain)
        :type email: str | None, optional
        :return: Self.
        :rtype: ADUser
        """
        if email is None:
            email = f"{self.name}@{self.host.domain}"

        unix_attrs = {
            "uid": self.name,
            "uidNumber": uid,
            "gidNumber": gid,
            "unixHomeDirectory": home,
            "gecos": gecos,
            "loginShell": shell,
        }

        attrs: CLIBuilderArgs = {
            "Name": (self.cli.option.VALUE, self.name),
            "AccountPassword": (self.cli.option.PLAIN, f'(ConvertTo-SecureString "{password}" -AsPlainText -force)'),
            "OtherAttributes": (self.cli.option.PLAIN, attrs_to_hash(unix_attrs)),
            "Enabled": (self.cli.option.PLAIN, "$True"),
            "Path": (self.cli.option.VALUE, self.path),
            "EmailAddress": (self.cli.option.PLAIN, email),
            "GivenName": (self.cli.option.PLAIN, "dummyfirstname"),
            "Surname": (self.cli.option.PLAIN, "dummylastname"),
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
    ) -> ADUser:
        """
        Modify existing AD user.

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
        :param email: Email address, defaults to None
        :type email: str | DeleteAttribute | None, optional
        :return: Self.
        :rtype: ADUser
        """
        unix_attrs = {
            "uidNumber": uid,
            "gidNumber": gid,
            "unixHomeDirectory": home,
            "gecos": gecos,
            "loginShell": shell,
        }

        ad_attrs = {"emailAddress": email}
        all_attrs = {**unix_attrs, **ad_attrs}

        clear = [key for key, value in all_attrs.items() if isinstance(value, DeleteAttribute)]
        replace = {
            key: value
            for key, value in all_attrs.items()
            if value is not None and not isinstance(value, DeleteAttribute)
        }

        attrs: CLIBuilderArgs = {
            **self._identity,
            "Replace": (self.cli.option.PLAIN, attrs_to_hash(replace)),
            "Clear": (self.cli.option.PLAIN, ",".join(clear) if clear else None),
        }

        self._modify(attrs)
        return self

    def passkey_add(self, passkey_mapping: str) -> ADUser:
        """
        Add passkey mapping to the user.

        :param passkey_mapping: Passkey mapping generated by ``sssctl passkey-register``
        :type passkey_mapping: str
        :return: Self.
        :rtype: ADUser
        """
        attrs: CLIBuilderArgs = {
            **self._identity,
            "Add": (self.cli.option.PLAIN, attrs_to_hash({"altSecurityIdentities": passkey_mapping})),
        }
        self._modify(attrs)
        return self

    def passkey_remove(self, passkey_mapping: str) -> ADUser:
        """
        Remove passkey mapping from the user.

        :param passkey_mapping: Passkey mapping generated by ``sssctl passkey-register``
        :type passkey_mapping: str
        :return: Self.
        :rtype: ADUser.
        """
        attrs: CLIBuilderArgs = {
            **self._identity,
            "Remove": (self.cli.option.PLAIN, attrs_to_hash({"altSecurityIdentities": passkey_mapping})),
        }
        self._modify(attrs)
        return self


class ADGroup(ADObject):
    """
    AD group management.
    """

    def __init__(self, role: AD, name: str, basedn: ADObject | str | None = "cn=users") -> None:
        """
        :param role: AD role object.
        :type role: AD
        :param name: Group name.
        :type name: str
        :param basedn: Base dn, defaults to 'cn=users'
        :type basedn: ADObject | str | None, optional
        """
        # There is no automatically created default ou because cn=users already exists
        super().__init__(role, "Group", name, f"cn={name}", basedn, default_ou=None)

    def add(
        self,
        *,
        gid: int | None = None,
        description: str | None = None,
        scope: str = "Global",
        category: str = "Security",
    ) -> ADGroup:
        """
        Create new AD group.

        :param gid: Group id, defaults to None
        :type gid: int | None, optional
        :param description: Description, defaults to None
        :type description: str | None, optional
        :param scope: Scope ('Global', 'Universal', 'DomainLocal'), defaults to 'Global'
        :type scope: str, optional
        :param category: Category ('Distribution', 'Security'), defaults to 'Security'
        :type category: str, optional
        :return: Self.
        :rtype: ADGroup
        """
        unix_attrs = {
            "gidNumber": gid,
            "description": description,
        }

        attrs: CLIBuilderArgs = {
            "Name": (self.cli.option.VALUE, self.name),
            "GroupScope": (self.cli.option.VALUE, scope),
            "GroupCategory": (self.cli.option.VALUE, category),
            "OtherAttributes": (self.cli.option.PLAIN, attrs_to_hash(unix_attrs)),
            "Path": (self.cli.option.VALUE, self.path),
        }

        self._add(attrs)
        return self

    def modify(
        self,
        *,
        gid: int | DeleteAttribute | None = None,
        description: str | DeleteAttribute | None = None,
    ) -> ADGroup:
        """
        Modify existing AD group.

        Parameters that are not set are ignored. If needed, you can delete an
        attribute by setting the value to :attr:`Delete`.

        :param gid: Group id, defaults to None
        :type gid: int | DeleteAttribute | None, optional
        :param description: Description, defaults to None
        :type description: str | DeleteAttribute | None, optional
        :return: Self.
        :rtype: ADUser
        """
        unix_attrs = {
            "gidNumber": gid,
            "description": description,
        }

        clear = [key for key, value in unix_attrs.items() if isinstance(value, DeleteAttribute)]
        replace = {
            key: value
            for key, value in unix_attrs.items()
            if value is not None and not isinstance(value, DeleteAttribute)
        }

        attrs: CLIBuilderArgs = {
            **self._identity,
            "Replace": (self.cli.option.PLAIN, attrs_to_hash(replace)),
            "Clear": (self.cli.option.PLAIN, ",".join(clear) if clear else None),
        }

        self._modify(attrs)
        return self

    def add_member(self, member: ADUser | ADGroup) -> ADGroup:
        """
        Add group member.

        :param member: User or group to add as a member.
        :type member: ADUser | ADGroup
        :return: Self.
        :rtype: ADGroup
        """
        return self.add_members([member])

    def add_members(self, members: list[ADUser | ADGroup]) -> ADGroup:
        """
        Add multiple group members.

        :param member: List of users or groups to add as members.
        :type member: list[ADUser | ADGroup]
        :return: Self.
        :rtype: ADGroup
        """
        self.role.host.ssh.run(
            f"""
            Import-Module ActiveDirectory
            Add-ADGroupMember -Identity '{self.dn}' -Members {self.__get_members(members)}
        """
        )
        return self

    def remove_member(self, member: ADUser | ADGroup) -> ADGroup:
        """
        Remove group member.

        :param member: User or group to remove from the group.
        :type member: ADUser | ADGroup
        :return: Self.
        :rtype: ADGroup
        """
        return self.remove_members([member])

    def remove_members(self, members: list[ADUser | ADGroup]) -> ADGroup:
        """
        Remove multiple group members.

        :param member: List of users or groups to remove from the group.
        :type member: list[ADUser | ADGroup]
        :return: Self.
        :rtype: ADGroup
        """
        self.role.host.ssh.run(
            f"""
            Import-Module ActiveDirectory
            Remove-ADGroupMember -Confirm:$False -Identity '{self.dn}' -Members {self.__get_members(members)}
        """
        )
        return self

    def __get_members(self, members: list[ADUser | ADGroup]) -> str:
        return ",".join([f'"{x.dn}"' for x in members])


class ADNetgroup(ADObject):
    """
    AD netgroup management.
    """

    def __init__(self, role: AD, name: str, basedn: ADObject | str | None = "ou=netgroups") -> None:
        """
        :param role: AD role object.
        :type role: AD
        :param name: Netgroup name.
        :type name: str
        :param basedn: Base dn, defaults to ``ou=netgroups``
        :type basedn: ADObject | str | None, optional
        """
        super().__init__(role, "Object", name, f"cn={name}", basedn, default_ou="netgroups")

    def add(self) -> ADNetgroup:
        """
        Create new AD netgroup.

        :return: Self.
        :rtype: ADNetgroup
        """
        attrs = {
            "objectClass": "nisNetgroup",
            "cn": self.name,
        }

        args: CLIBuilderArgs = {
            "Name": (self.cli.option.VALUE, self.name),
            "Type": (self.cli.option.VALUE, "nisNetgroup"),
            "OtherAttributes": (self.cli.option.PLAIN, attrs_to_hash(attrs)),
            "Path": (self.cli.option.VALUE, self.path),
        }

        self._add(args)
        return self

    def add_member(
        self,
        *,
        host: str | None = None,
        user: ADUser | str | None = None,
        domain: str | None = None,
        ng: ADNetgroup | str | None = None,
    ) -> ADNetgroup:
        """
        Add netgroup member.

        :param host: Host, defaults to None
        :type host: str | None, optional
        :param user: User, defaults to None
        :type user: ADUser | str | None, optional
        :param domain: Domain, defaults to None
        :type domain: str | None, optional
        :param ng: Netgroup, defaults to None
        :type ng: ADNetgroup | str | None, optional
        :return: Self.
        :rtype: ADNetgroup
        """
        return self.add_members([ADNetgroupMember(host=host, user=user, domain=domain, ng=ng)])

    def add_members(self, members: list[ADNetgroupMember]) -> ADNetgroup:
        """
        Add multiple netgroup members.

        :param members: Netgroup members.
        :type members: list[ADNetgroupMember]
        :return: Self.
        :rtype: ADNetgroup
        """
        triples, netgroups = self.__members(members)

        attrs = {}
        if triples:
            attrs["nisNetgroupTriple"] = triples

        if netgroups:
            attrs["memberNisNetgroup"] = netgroups

        args: CLIBuilderArgs = {
            **self._identity,
            "Add": (self.cli.option.PLAIN, attrs_to_hash(attrs)),
        }

        self._modify(args)
        return self

    def remove_member(
        self,
        *,
        host: str | None = None,
        user: ADUser | str | None = None,
        domain: str | None = None,
        ng: ADNetgroup | str | None = None,
    ) -> ADNetgroup:
        """
        Remove netgroup member.

        :param host: Host, defaults to None
        :type host: str | None, optional
        :param user: User, defaults to None
        :type user: ADUser | str | None, optional
        :param domain: Domain, defaults to None
        :type domain: str | None, optional
        :param ng: Netgroup, defaults to None
        :type ng: ADNetgroup | str | None, optional
        :return: Self.
        :rtype: ADNetgroup
        """
        return self.remove_members([ADNetgroupMember(host=host, user=user, domain=domain, ng=ng)])

    def remove_members(self, members: list[ADNetgroupMember]) -> ADNetgroup:
        """
        Remove multiple netgroup members.

        :param members: Netgroup members.
        :type members: list[LDAPNetgroupMember]
        :return: Self.
        :rtype: LDAPNetgroup[HostType, LDAPRoleType, LDAPUserType]
        """
        triples, netgroups = self.__members(members)

        attrs = {}
        if triples:
            attrs["nisNetgroupTriple"] = triples

        if netgroups:
            attrs["memberNisNetgroup"] = netgroups

        args: CLIBuilderArgs = {
            **self._identity,
            "Remove": (self.cli.option.PLAIN, attrs_to_hash(attrs)),
        }

        self._modify(args)
        return self

    def __members(self, members: list[ADNetgroupMember]) -> tuple[list[str], list[str]]:
        """
        Split members into triples and netgroups

        :param members: Netgroup members.
        :type members: list[LDAPNetgroupMember]
        :return: (triples, netgroups)
        :rtype: tuple[list[str], list[str]]
        """
        triples = []
        netgroups = []

        for member in members:
            if member.netgroup is not None:
                netgroups.append(member.netgroup)

            triple = member.triple()
            if triple is not None:
                triples.append(triple)

        return (triples, netgroups)


class ADSudoRule(ADObject):
    """
    AD sudo rule management.
    """

    def __init__(
        self,
        role: AD,
        name: str,
        basedn: ADObject | str | None = "ou=sudoers",
    ) -> None:
        """
        :param role: AD role object.
        :type role: AD
        :param name: Sudo rule name.
        :type name: str
        :param basedn: Base dn, defaults to None
        :type basedn: ADObject | str | None, optional
        """
        super().__init__(role, "Object", name, f"cn={name}", basedn, default_ou="sudoers")

    def add(
        self,
        *,
        user: int | str | ADUser | ADGroup | list[int | str | ADUser | ADGroup] | None = None,
        host: str | list[str] | None = None,
        command: str | list[str] | None = None,
        option: str | list[str] | None = None,
        runasuser: int | str | ADUser | ADGroup | list[int | str | ADUser | ADGroup] | None = None,
        runasgroup: int | str | ADGroup | list[int | str | ADGroup] | None = None,
        notbefore: str | list[str] | None = None,
        notafter: str | list[str] | None = None,
        order: int | list[int] | None = None,
        nopasswd: bool | None = None,
    ) -> ADSudoRule:
        """
        Create new sudo rule.

        :param user: sudoUser attribute, defaults to None
        :type user: int | str | ADUser | ADGroup | list[int | str | ADUser | ADGroup], optional
        :param host: sudoHost attribute, defaults to None
        :type host: str | list[str], optional
        :param command: sudoCommand attribute, defaults to None
        :type command: str | list[str], optional
        :param option: sudoOption attribute, defaults to None
        :type option: str | list[str] | None, optional
        :param runasuser: sudoRunAsUser attribute, defaults to None
        :type runasuser: int | str | ADUser | ADGroup | list[int | str | ADUser | ADGroup] | None, optional
        :param runasgroup: sudoRunAsGroup attribute, defaults to None
        :type runasgroup: int | str | ADGroup | list[int | str | ADGroup] | None, optional
        :param notbefore: sudoNotBefore attribute, defaults to None
        :type notbefore: str | list[str] | None, optional
        :param notafter: sudoNotAfter attribute, defaults to None
        :type notafter: str | list[str] | None, optional
        :param order: sudoOrder attribute, defaults to None
        :type order: int | list[int] | None, optional
        :param nopasswd: If true, no authentication is required (NOPASSWD), defaults to None (no change)
        :type nopasswd: bool | None, optional
        :return: Self.
        :rtype: ADSudoRule
        """
        attrs = {
            "objectClass": "sudoRole",
            "sudoUser": self.__sudo_user(user),
            "sudoHost": host,
            "sudoCommand": command,
            "sudoOption": option,
            "sudoRunAsUser": self.__sudo_user(runasuser),
            "sudoRunAsGroup": self.__sudo_group(runasgroup),
            "sudoNotBefore": notbefore,
            "sudoNotAfter": notafter,
            "sudoOrder": order,
        }

        if nopasswd is True:
            attrs["sudoOption"] = attrs_include_value(attrs["sudoOption"], "!authenticate")
        elif nopasswd is False:
            attrs["sudoOption"] = attrs_include_value(attrs["sudoOption"], "authenticate")

        args: CLIBuilderArgs = {
            "Name": (self.cli.option.VALUE, self.name),
            "Type": (self.cli.option.VALUE, "sudoRole"),
            "OtherAttributes": (self.cli.option.PLAIN, attrs_to_hash(attrs)),
            "Path": (self.cli.option.VALUE, self.path),
        }

        self._add(args)
        return self

    def modify(
        self,
        *,
        user: int | str | ADUser | ADGroup | list[int | str | ADUser | ADGroup] | DeleteAttribute | None = None,
        host: str | list[str] | DeleteAttribute | None = None,
        command: str | list[str] | DeleteAttribute | None = None,
        option: str | list[str] | DeleteAttribute | None = None,
        runasuser: int | str | ADUser | ADGroup | list[int | str | ADUser | ADGroup] | DeleteAttribute | None = None,
        runasgroup: int | str | ADGroup | list[int | str | ADGroup] | DeleteAttribute | None = None,
        notbefore: str | list[str] | DeleteAttribute | None = None,
        notafter: str | list[str] | DeleteAttribute | None = None,
        order: int | list[int] | DeleteAttribute | None = None,
        nopasswd: bool | None = None,
    ) -> ADSudoRule:
        """
        Modify existing sudo rule.

        Parameters that are not set are ignored. If needed, you can delete an
        attribute by setting the value to :attr:`Delete`.

        :param user: sudoUser attribute, defaults to None
        :type user: int | str | ADUser | ADGroup | list[int | str | ADUser | ADGroup]
          | DeleteAttribute | None, optional
        :param host: sudoHost attribute, defaults to None
        :type host: str | list[str] | DeleteAttribute | None, optional
        :param command: sudoCommand attribute, defaults to None
        :type command: str | list[str] | DeleteAttribute | None, optional
        :param option: sudoOption attribute, defaults to None
        :type option: str | list[str] | DeleteAttribute | None, optional
        :param runasuser: sudoRunAsUsere attribute, defaults to None
        :type runasuser: int | str | ADUser | ADGroup | list[int | str | ADUser | ADGroup]
          | DeleteAttribute | None, optional
        :param runasgroup: sudoRunAsGroup attribute, defaults to None
        :type runasgroup: int | str | ADGroup | list[int | str | ADGroup] | DeleteAttribute | None, optional
        :param notbefore: sudoNotBefore attribute, defaults to None
        :type notbefore: str | list[str] | DeleteAttribute | None, optional
        :param notafter: sudoNotAfter attribute, defaults to None
        :type notafter: str | list[str] | DeleteAttribute | None, optional
        :param order: sudoOrder attribute, defaults to None
        :type order: int | list[int] | DeleteAttribute | None, optional
        :param nopasswd: If true, no authentication is required (NOPASSWD), defaults to None (no change)
        :type nopasswd: bool | None, optional
        :return: Self.
        :rtype: ADSudoRule
        """
        attrs = {
            "sudoUser": self.__sudo_user(user),
            "sudoHost": host,
            "sudoCommand": command,
            "sudoOption": option,
            "sudoRunAsUser": self.__sudo_user(runasuser),
            "sudoRunAsGroup": self.__sudo_group(runasgroup),
            "sudoNotBefore": notbefore,
            "sudoNotAfter": notafter,
            "sudoOrder": order,
        }

        if nopasswd is True:
            attrs["sudoOption"] = attrs_include_value(attrs["sudoOption"], "!authenticate")
        elif nopasswd is False:
            attrs["sudoOption"] = attrs_include_value(attrs["sudoOption"], "authenticate")

        clear = [key for key, value in attrs.items() if isinstance(value, DeleteAttribute)]
        replace = {
            key: value for key, value in attrs.items() if value is not None and not isinstance(value, DeleteAttribute)
        }

        args: CLIBuilderArgs = {
            **self._identity,
            "Replace": (self.cli.option.PLAIN, attrs_to_hash(replace)),
            "Clear": (self.cli.option.PLAIN, ",".join(clear) if clear else None),
        }

        self._modify(args)
        return self

    def __sudo_user(
        self, sudo_user: None | DeleteAttribute | int | str | ADUser | ADGroup | list[int | str | ADUser | ADGroup]
    ) -> list[str] | DeleteAttribute | None:
        def _get_value(value: int | str | ADUser | ADGroup) -> str:
            if isinstance(value, ADUser):
                return value.name

            if isinstance(value, ADGroup):
                return "%" + value.name

            if isinstance(value, str):
                return value

            if isinstance(value, int):
                return "#" + str(value)

            raise ValueError(f"Unsupported type: {type(value)}")

        if sudo_user is None:
            return None

        if isinstance(sudo_user, DeleteAttribute):
            return sudo_user

        if not isinstance(sudo_user, list):
            return [_get_value(sudo_user)]

        out = []
        for value in sudo_user:
            out.append(_get_value(value))

        return out

    def __sudo_group(
        self, sudo_group: None | DeleteAttribute | int | str | ADGroup | list[int | str | ADGroup]
    ) -> list[str] | DeleteAttribute | None:
        def _get_value(value: int | str | ADGroup):
            if isinstance(value, ADGroup):
                return value.name

            if isinstance(value, str):
                return value

            if isinstance(value, int):
                return "#" + str(value)

            raise ValueError(f"Unsupported type: {type(value)}")

        if sudo_group is None:
            return None

        if isinstance(sudo_group, DeleteAttribute):
            return sudo_group

        if not isinstance(sudo_group, list):
            return [_get_value(sudo_group)]

        out = []
        for value in sudo_group:
            out.append(_get_value(value))

        return out


class ADAutomount(object):
    """
    AD automount management.
    """

    def __init__(self, role: AD) -> None:
        """
        :param role: AD role object.
        :type role: AD
        """
        self.__role = role

    def map(self, name: str, basedn: ADObject | str | None = "ou=autofs") -> ADAutomountMap:
        """
        Get automount map object.

        :param name: Automount map name.
        :type name: str
        :param basedn: Base dn, defaults to ``ou=autofs``
        :type basedn: ADObject | str | None, optional
        :return: New automount map object.
        :rtype: ADAutomountMap
        """
        return ADAutomountMap(self.__role, name, basedn)

    def key(self, name: str, map: ADAutomountMap) -> ADAutomountKey:
        """
        Get automount key object.

        :param name: Automount key name.
        :type name: str
        :param map: Automount map that is a parent to this key.
        :type map: ADAutomountMap
        :return: New automount key object.
        :rtype: ADAutomountKey
        """
        return ADAutomountKey(self.__role, name, map)


class ADAutomountMap(ADObject):
    """
    AD automount map management.
    """

    def __init__(
        self,
        role: AD,
        name: str,
        basedn: ADObject | str | None = "ou=autofs",
    ) -> None:
        """
        :param role: AD role object.
        :type role: AD
        :param name: Automount map name.
        :type name: str
        :param basedn: Base dn, defaults to ``ou=autofs``
        :type basedn: ADObject | str | None, optional
        """
        super().__init__(role, "Object", name, f"cn={name}", basedn, default_ou="autofs")

    def add(
        self,
    ) -> ADAutomountMap:
        """
        Create new AD automount map.

        :return: Self.
        :rtype: ADAutomountMap
        """
        attrs = {
            "objectClass": "nisMap",
            "cn": self.name,
            "nisMapName": self.name,
        }

        args: CLIBuilderArgs = {
            "Name": (self.cli.option.VALUE, self.name),
            "Type": (self.cli.option.VALUE, "nisMap"),
            "OtherAttributes": (self.cli.option.PLAIN, attrs_to_hash(attrs)),
            "Path": (self.cli.option.VALUE, self.path),
        }

        self._add(args)
        return self

    def key(self, name: str) -> ADAutomountKey:
        """
        Get automount key object for this map.

        :param name: Automount key name.
        :type name: str
        :return: New automount key object.
        :rtype: ADAutomountKey
        """
        return ADAutomountKey(self.role, name, self)


class ADAutomountKey(ADObject):
    """
    AD automount key management.
    """

    def __init__(
        self,
        role: AD,
        name: str,
        map: ADAutomountMap,
    ) -> None:
        """
        :param role: AD role object.
        :type role: AD
        :param name: Automount key name.
        :type name: str
        :param map: Automount map that is a parent to this key.
        :type map: ADAutomountMap
        """
        super().__init__(role, "Object", name, f"cn={name}", map)
        self.map: ADAutomountMap = map
        self.info: str | None = None

    def add(self, *, info: str | NFSExport | ADAutomountMap) -> ADAutomountKey:
        """
        Create new AD automount key.

        :param info: Automount information.
        :type info: str | NFSExport | ADAutomountMap
        :return: Self.
        :rtype: ADAutomountKey
        """
        parsed = self.__get_info(info)
        if isinstance(parsed, DeleteAttribute) or parsed is None:
            # This should not happen, it is here just to silence mypy
            raise ValueError("Invalid value of info attribute")

        attrs = {
            "objectClass": "nisObject",
            "cn": self.name,
            "nisMapEntry": parsed,
            "nisMapName": self.map.name,
        }

        args: CLIBuilderArgs = {
            "Name": (self.cli.option.VALUE, self.name),
            "Type": (self.cli.option.VALUE, "nisObject"),
            "OtherAttributes": (self.cli.option.PLAIN, attrs_to_hash(attrs)),
            "Path": (self.cli.option.VALUE, self.path),
        }

        self._add(args)
        self.info = parsed
        return self

    def modify(
        self,
        *,
        info: str | NFSExport | ADAutomountMap | DeleteAttribute | None = None,
    ) -> ADAutomountKey:
        """
        Modify existing AD automount key.

        Parameters that are not set are ignored. If needed, you can delete an
        attribute by setting the value to :attr:`Delete`.

        :param info: Automount information, defaults to ``None``
        :type info:  str | NFSExport | ADAutomountMap | DeleteAttribute | None
        :return: Self.
        :rtype: ADAutomountKey
        """
        parsed = self.__get_info(info)
        attrs = {
            "nisMapEntry": parsed,
        }

        clear = [key for key, value in attrs.items() if isinstance(value, DeleteAttribute)]
        replace = {
            key: value for key, value in attrs.items() if value is not None and not isinstance(value, DeleteAttribute)
        }

        args: CLIBuilderArgs = {
            **self._identity,
            "Replace": (self.cli.option.PLAIN, attrs_to_hash(replace)),
            "Clear": (self.cli.option.PLAIN, ",".join(clear) if clear else None),
        }

        self._modify(args)
        self.info = parsed if not isinstance(parsed, DeleteAttribute) else ""
        return self

    def dump(self) -> str:
        """
        Dump the key in the ``automount -m`` format.

        .. code-block:: text

            export1 | -fstype=nfs,rw,sync,no_root_squash nfs.test:/dev/shm/exports/export1

        You can also call ``str(key)`` instead of ``key.dump()``.

        :return: Key information in ``automount -m`` format.
        :rtype: str
        """
        return f"{self.name} | {self.info}"

    def __str__(self) -> str:
        """
        Alias for :meth:`dump` method.

        :return: Key information in ``automount -m`` format.
        :rtype: str
        """
        return self.dump()

    def __get_info(
        self, info: str | NFSExport | ADAutomountMap | DeleteAttribute | None
    ) -> str | DeleteAttribute | None:
        if isinstance(info, NFSExport):
            return info.get()

        if isinstance(info, ADAutomountMap):
            return info.name

        return info


class GPO(BaseObject[ADHost, AD]):
    """
    Group policy object management.
    """

    def __init__(self, role: AD, name: str) -> None:
        """
        :param role: AD host object.
        :type role:  ADHost
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

        self._dn = self.get("DistinguishedName")
        """Group policy dn."""

        self._cn = self.get("CN")
        """Group policy cn."""

    def get(self, key: str) -> str | None:
        """
        Get group policy attributes.

        :param key: Attribute to get.
        :type key: str
        :return: Key value.
        :rtype: str
        """
        result = self.role.host.ssh.run(
            rf"""
            $query = "(&(ObjectClass=groupPolicyContainer)(DisplayName={self.name}))"
            Get-ADObject -SearchBase "{self._search_base}" -Properties "*" -LDAPFilter $query
            """
        ).stdout_lines

        i = 0
        while i < len(result):
            if result[i].startswith(key):
                if result[i + 1].startswith(" "):
                    value = (result[i].strip() + result[i + 1].strip()).split(":")
                    return value[1].strip()
                else:
                    value = result[i].split(":")
                    return value[1].strip()
            i += 1

        return None

    def delete(self) -> None:
        """
        Delete group policy object.
        """
        self.role.host.ssh.run(f'Remove-GPO -Guid "{self._cn}" -Confirm:$false')

    def add(self) -> GPO:
        """
        Add a group policy object.

        This creates an empty GPO, the security part of the policy cannot be configured using
        official GroupPolicy cmdlets, because the settings are actually stored in security database.
        The workaround, is to manually edit policy. First create the SecEdit directory path,
        'C:\\Windows\\SYSVOL\\domain\\Policies\\{GUID}\\Machines\\Microsoft\\Windows NT\\SecEdit'.

        Second, create and edit GptTmpl.inf file in this directory. Only the headers, are
        added at this time. The rest of the configuration is done by policy method.

        :return: Group policy object
        :rtype: GPO
        """
        self.role.host.ssh.run(f'New-GPO -name "{self.name}"')

        self._cn = self.get("CN")
        self._dn = self.get("DistinguishedName")

        self.role.host.ssh.run(
            rf"""
            Import-Module GroupPolicy, PSIni
            $path = "C:\\Windows\\SYSVOL\\domain\\Policies\\{self._cn}\\Machine\\Microsoft\\Windows NT\\SecEdit"
            $file = Join-Path $path GptTmpl.inf
            $content = @{{'Unicode'=@{{'Unicode'='yes'}};'Version'=@{{'signature'='"$CHICAGO$"';'Revision'='1'}}}}
            New-Item -Path "$path" -ItemType Directory
            New-Item -Path "$file" -ItemType File
            Out-IniFile -InputObject $content -FilePath $file
            Test-Path -Path "$path"
            Exit 0
            """
        )
        return self

    def link(
        self,
        op: str | None = "New",
        target: str | None = None,
        args: list[str] | str | None = None,
    ) -> GPO:
        """
        Link the group policy to the a target object inside the directory, a site, domain or an ou.

        ..Note::
            The New and Set cmdlets are identical. To modify an an existing link,
            change the $op parameter to "Set", i.e. to disable 'Enforced'

            ou_policy.link("Set", args=["-Enforced No"])

        :param op: Cmdlet operation, defaults to "New"
        :type op: str, optional
        :param target: Group policy target
        :type target: str, optional
        :param args: Additional arguments
        :type args: list[str] | None, optional
        :return: Group policy object
        :rtype: GPO
        """
        if args is None:
            args = []

        if isinstance(args, list):
            args = " ".join(args)
        elif args is None:
            args = ""

        if target is None and self.target is None:
            self.target = "Default-First-Site-Name"

        if target is not None and self.target is None:
            self.target = target

        self.role.host.ssh.run(f'{op}-GPLink -Guid "{self._cn}" -Target "{self.target}" -LinkEnabled Yes {args}')

        return self

    def unlink(self) -> GPO:
        """
        Unlink the group policy from the target.

        :return: Group policy object
        :rtype: GPO
        """
        self.role.host.ssh.run(f'Remove-GPLink -Guid "{self._cn}" -Target "{self.target}"')

        return self

    def permissions(self, target: str, permission_level: str, target_type: str | None = "Group") -> GPO:
        """
        Configure group policy object permissions.

        :param target: Target object
        :type target: str
        :param permission_level: Permission level
        :type permission_level: str, 'GpoRead | GpoApply | GpoEdit | GpoEditDeleteModifySecurity | None'
        :param target_type: Target type, defaults to 'group'
        :type target_type: str, optional, values should be 'user | group | computer'
        :return: Group policy object
        :rtype: GPO
        """
        if permission_level == "None" and target == "Authenticated Users":
            self.role.host.ssh.run(
                rf"""
                # Some test scenarios require making the GPO unreadable. Changing the 'Authenticated Users',
                # 'S-1-5-11' SID permissions to 'None' accomplishes that. The confirm prompt cannot be skipped
                # using Set-GPPermissions, for more information. https://support.microsoft.com/kb/3163622
                # Setting the permission using ADSI is a workaround for automation.

                $authenticated_users = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")
                $gpo = Get-GPO -Guid "{self._cn}"
                $gid = $gpo.id
                $search_base = "cn=policies,cn=system," + "{self.host.naming_context}"
                $filter = "(&(objectClass=groupPolicyContainer)(cn={{$gid}}))"
                $gpo_object = Get-ADObject -SearchBase "$search_base" -Properties "*" -LDAPFilter $filter
                $gpo_ldap = "LDAP://" + $gpo_object.DistinguishedName
                $gpo_adsi = [ADSI]"$gpo_ldap"
                $extRight = [system.guid]"edacfd8f-ffb3-11d1-b41d-00a0c968f939"
                $ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $authenticated_users, "ReadProperty", "Deny")
                $gpo_adsi.psbase.get_objectSecurity().AddAccessRule($ace)
                $gpo_adsi.psbase.CommitChanges()
                """
            )
        else:
            self.role.host.ssh.run(
                f'Set-GPPermission -Guid "{self._cn}" '
                f'-TargetName "{target}" '
                f'-PermissionLevel "{permission_level}" '
                f'-TargetType "{target_type}" -Replace:$True -Confirm:$False'
            )

        return self

    def policy(self, logon_rights: dict[str, list[ADObject]], cfg: dict[str, Any] | None = None) -> GPO:
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

        There is a test case where GptTmpl.inf contains invalid values. The parameter
        gpttmpl takes a dictionary that will modify the GptTmpl.inf for this scenario.

        :param logon_rights: List of logon rights.
        :type logon_rights: dict[str, list[ADObject]]
        :param cfg: Extra configuration for GptTmpl.inf file, defaults to None
        :type cfg: dict[str, Any] | None, optional
        :return: Group policy object
        :rtype: GPO
        """
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

        ps_logon_rights = attrs_to_hash(_logon_rights)

        self.host.ssh.run(
            rf"""
            Import-Module PSIni
            $path = "C:\\Windows\\SYSVOL\\domain\\Policies\\{self._cn}\\Machine\\Microsoft\\Windows NT\\SecEdit"
            $file = Join-Path $path GptTmpl.inf
            $policy = @{{"Privilege Rights"={ps_logon_rights}}}
            Out-IniFile -InputObject $policy -FilePath "$file"
            Exit 0
            """
        )

        if cfg is not None:
            ps_cfg = attrs_to_hash(cfg)
            self.host.ssh.run(
                rf"""
                Import-Module PSIni
                $path = "C:\\Windows\\SYSVOL\\domain\\Policies\\{self._cn}\\Machine\\Microsoft\\Windows NT\\SecEdit"
                $file = Join-Path $path GptTmpl.inf
                $policy = {ps_cfg}
                Out-IniFile -InputObject $policy -FilePath "$file"
                Exit 0
                """
            )

        self.host.ssh.run(
            rf"""
            $gpc = "[{{827D319E-6EAC-11D2-A4EA-00C04F79F83A}}{{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}}]"
            Set-ADObject -Identity "{self._dn}" -Replace @{{gPCMachineExtensionNames=$gpc}}
            Exit 0
            """
        )

        return self


ADNetgroupMember: TypeAlias = LDAPNetgroupMember[ADUser, ADNetgroup]
