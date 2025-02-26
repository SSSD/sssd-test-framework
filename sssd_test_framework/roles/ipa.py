"""IPA multihost role."""

from __future__ import annotations

from textwrap import dedent
from typing import Any

from pytest_mh.cli import CLIBuilderArgs
from pytest_mh.conn import ProcessResult

from ..hosts.ipa import IPAHost
from ..misc import attrs_include_value, attrs_parse, to_list, to_list_of_strings
from ..utils.sssctl import SSSCTLUtils
from ..utils.sssd import SSSDUtils
from .base import BaseLinuxRole, BaseObject
from .generic import GenericNetgroupMember, GenericPasswordPolicy
from .nfs import NFSExport

__all__ = [
    "IPA",
    "IPAObject",
    "IPAPasswordPolicy",
    "IPAUser",
    "IPAGroup",
    "IPASudoRule",
    "IPAAutomount",
    "IPAAutomountLocation",
    "IPAAutomountMap",
    "IPAAutomountKey",
]


class IPA(BaseLinuxRole[IPAHost]):
    """
    IPA role.

    Provides unified Python API for managing objects in the IPA server.

    .. code-block:: python
        :caption: Creating user and group

        @pytest.mark.topology(KnownTopology.IPA)
        def test_example(ipa: IPA):
            u = ipa.user('tuser').add()
            g = ipa.group('tgroup').add()
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
        IPA domain name.
        """

        self.realm: str = self.host.realm
        """
        Kerberos realm.
        """

        self.sssd: SSSDUtils = SSSDUtils(self.host, self.fs, self.svc, self.authselect, load_config=True)
        """
        Managing and configuring SSSD.
        """

        self.sssctl: SSSCTLUtils = SSSCTLUtils(self.host, self.fs)
        """
        Call commands from sssctl.
        """

        self.automount: IPAAutomount = IPAAutomount(self)
        """
        Manage automount locations, maps and keys.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.IPA)
            def test_example(client: Client, ipa: IPA, nfs: NFS):
                nfs_export1 = nfs.export('export1').add()
                nfs_export2 = nfs.export('export2').add()
                nfs_export3 = nfs.export('sub/export3').add()

                # Create automout location
                loc = ipa.automount.location('boston').add()

                # Create automount maps
                auto_master = loc.map('auto.master').add()
                auto_home = loc.map('auto.home').add()
                auto_sub = loc.map('auto.sub').add()

                # Create mount points
                auto_master.key('/ehome').add(info=auto_home)
                auto_master.key('/esub/sub1/sub2').add(info=auto_sub)

                # Create mount keys
                key1 = auto_home.key('export1').add(info=nfs_export1)
                key2 = auto_home.key('export2').add(info=nfs_export2)
                key3 = auto_sub.key('export3').add(info=nfs_export3)

                # Start SSSD
                client.sssd.common.autofs()
                client.sssd.domain['ipa_automount_location'] = 'boston'
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

    def setup(self) -> None:
        """
        Obtain IPA admin Kerberos TGT.
        """
        super().setup()
        self.host.kinit()

    @property
    def password(self) -> IPAPasswordPolicy:
        """
        Domain password policy management.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.IPA)
            def test_example(client: Client, ipa: IPA):
                # Enable password complexity
                ipa.password.complexity(enable=True)

                # Set 3 login attempts and 30 lockout duration
                ipa.password.lockout(attempts=3, duration=30)

                # Set password length requirement to 12 characters
                ipa.password.requirement(length=12)

                # Set password max age to 30 seconds
                ipa.password.age(maximum=30)
        """
        return IPAPasswordPolicy(self)

    def user(self, name: str) -> IPAUser:
        """
        Get user object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.IPA)
            def test_example(client: Client, ipa: IPA):
                # Create user
                ipa.user('user-1').add()

                # Start SSSD
                client.sssd.start()

                # Call `id user-1` and assert the result
                result = client.tools.id('user-1')
                assert result is not None
                assert result.user.name == 'user-1'
                assert result.group.name == 'user-1'

        :param name: Username.
        :type name: str
        :return: New user object.
        :rtype: IPAUser
        """
        return IPAUser(self, name)

    def group(self, name: str) -> IPAGroup:
        """
        Get group object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.IPA)
            def test_example_group(client: Client, ipa: IPA):
                # Create user
                user = ipa.user('user-1').add()

                # Create secondary group and add user as a member
                ipa.group('group-1').add().add_member(user)

                # Start SSSD
                client.sssd.start()

                # Call `id user-1` and assert the result
                result = client.tools.id('user-1')
                assert result is not None
                assert result.user.name == 'user-1'
                assert result.group.name == 'user-1'
                assert result.memberof('group-1')

        :param name: Group name.
        :type name: str
        :return: New group object.
        :rtype: IPAGroup
        """
        return IPAGroup(self, name)

    def netgroup(self, name: str) -> IPANetgroup:
        """
        Get netgroup object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.IPA)
            def test_example_netgroup(client: Client, ipa: IPA):
                # Create user
                user = ipa.user("user-1").add()

                # Create two netgroups
                ng1 = ipa.netgroup("ng-1").add()
                ng2 = ipa.netgroup("ng-2").add()

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
                assert "(-,user-1,ipa.test)" in result.members
                assert "(client.test,-,ipa.test)" in result.members

        :param name: Netgroup name.
        :type name: str
        :return: New netgroup object.
        :rtype: IPANetgroup
        """
        return IPANetgroup(self, name)

    def host_account(self, name: str) -> IPAHostAccount:
        """
        Get host object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.IPA)
            def test_example(client: Client, ipa: IPA):
                # Create host
                ipa.host_account(f'myhost.{ipa.domain}').add(ip="10.255.251.10")

        :param name: Hostname.
        :type name: str
        :return: New host account object.
        :rtype: IPAHostAccount
        """
        return IPAHostAccount(self, name)

    def sudorule(self, name: str) -> IPASudoRule:
        """
        Get sudo rule object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.IPA)
            def test_example(client: Client, ipa: IPA):
                user = ipa.user('user-1').add(password="Secret123")
                ipa.sudorule('testrule').add(user=user, host='ALL', command='/bin/ls')

                client.sssd.common.sudo()
                client.sssd.start()

                # Test that user can run /bin/ls
                assert client.auth.sudo.run('user-1', 'Secret123', command='/bin/ls')

        :param name: Sudo rule name.
        :type name: str
        :return: New sudo rule object.
        :rtype: IPASudoRule
        """
        return IPASudoRule(self, name)


class IPAObject(BaseObject[IPAHost, IPA]):
    """
    Base class for IPA object management.

    Provides shortcuts for command execution and implementation of :meth:`get`
    and :meth:`delete` methods.
    """

    def __init__(self, role: IPA, name: str, command_group: str) -> None:
        """
        :param role: IPA role object.
        :type role: IPA
        :param name: Object name.
        :type name: str
        :param command_group: IPA command group.
        :type command_group: str
        """
        super().__init__(role)
        self.command_group: str = command_group
        """IPA cli command group."""

        self.name: str = name
        """Object name."""

    def _exec(
        self, op: str, args: list[str] | None = None, ipaargs: list[str] | None = None, **kwargs
    ) -> ProcessResult:
        """
        Execute IPA command.

        .. code-block:: console

            $ ipa $ipaargs $command_group-$op $name $args
            for example >>> ipa user-add tuser

        :param op: Command group operation (usually add, mod, del, show)
        :type op: str
        :param args: List of additional command arguments, defaults to None
        :type args: list[str] | None, optional
        :param ipaargs: List of additional command arguments to the ipa main command, defaults to None
        :type ipaargs: list[str] | None, optional
        :return: SSH process result.
        :rtype: ProcessResult
        """
        if args is None:
            args = []

        if ipaargs is None:
            ipaargs = []

        return self.role.host.conn.exec(["ipa", *ipaargs, f"{self.command_group}-{op}", self.name, *args], **kwargs)

    def _add(self, attrs: CLIBuilderArgs | None = None, input: str | None = None):
        """
        Add IPA object.

        :param attrs: Object attributes in :class:`pytest_mh.cli.CLIBuilder` format, defaults to None
        :type attrs: pytest_mh.cli.CLIBuilderArgs | None, optional
        :param input: Contents of standard input given to the executed command, defaults to None
        :type input: str | None, optional
        """
        if attrs is None:
            attrs = {}

        self._exec("add", self.cli.args(attrs), input=input)

    def _modify(self, attrs: CLIBuilderArgs, input: str | None = None):
        """
        Modify IPA object.

        :param attrs: Object attributes in :class:`pytest_mh.cli.CLIBuilder` format, defaults to dict()
        :type attrs: pytest_mh.cli.CLIBuilderArgs, optional
        :param input: Contents of standard input given to the executed command, defaults to None
        :type input: str | None, optional
        """
        self._exec("mod", self.cli.args(attrs), input=input)

    def delete(self) -> None:
        """
        Delete IPA object.
        """
        self._exec("del")

    def get(self, attrs: list[str] | None = None) -> dict[str, list[str]] | None:
        """
        Get IPA object attributes.

        :param attrs: If set, only requested attributes are returned, defaults to None
        :type attrs: list[str] | None, optional
        :return: Dictionary with attribute name as a key or None if no such attribute is found.
        :rtype: dict[str, list[str]] | None
        """
        cmd = self._exec("show", ["--all", "--raw"], raise_on_error=False)

        # ipa output starts with space
        lines = dedent(cmd.stdout).splitlines()

        if lines is None or len(lines) == 0:
            return None

        # Remove first line that contains the object name and not attribute
        return attrs_parse(lines[1:], attrs)


class IPAUser(IPAObject):
    """
    IPA user management.
    """

    def __init__(self, role: IPA, name: str) -> None:
        """
        :param role: IPA role object.
        :type role: IPA
        :param name: Username.
        :type name: str
        """
        super().__init__(role, name, command_group="user")

    def add(
        self,
        *,
        uid: int | None = None,
        gid: int | None = None,
        password: str | None = "Secret123",
        home: str | None = None,
        gecos: str | None = None,
        shell: str | None = None,
        require_password_reset: bool = False,
        user_auth_type: str | list[str] | None = None,
        sshpubkey: str | list[str] | None = None,
    ) -> IPAUser:
        """
        Create new IPA user.

        Parameters that are not set are ignored.

        :param uid: User id, defaults to None
        :type uid: int | None, optional
        :param gid: Primary group id, defaults to None
        :type gid: int | None, optional
        :param password: Password, defaults to 'Secret123'
        :type password: str | None, optional
        :param home: Home directory, defaults to None
        :type home: str | None, optional
        :param gecos: GECOS, defaults to None
        :type gecos: str | None, optional
        :param shell: Login shell, defaults to None
        :type shell: str | None, optional
        :param require_password_reset: Require password reset on first login, defaults to False
        :type require_password_reset: bool, optional
        :param user_auth_type: Types of supported user authentication, defaults to None
        :type user_auth_type: str | list[str] | None, optional
        :param sshpubkey: SSH public key, defaults to None
        :type sshpubkey: str | list[str] | None, optional
        :return: Self.
        :rtype: IPAUser
        """
        attrs = {
            "first": (self.cli.option.VALUE, self.name),
            "last": (self.cli.option.VALUE, self.name),
            "uid": (self.cli.option.VALUE, uid),
            "gidnumber": (self.cli.option.VALUE, gid),
            "homedir": (self.cli.option.VALUE, home),
            "gecos": (self.cli.option.VALUE, gecos),
            "shell": (self.cli.option.VALUE, shell),
            "password": (self.cli.option.SWITCH, True) if password is not None else None,
            "user-auth-type": (self.cli.option.VALUE, user_auth_type),
            "sshpubkey": (self.cli.option.VALUE, sshpubkey),
        }

        if not require_password_reset:
            attrs["password-expiration"] = (self.cli.option.VALUE, "20380101120000Z")

        self._add(attrs, input=password)
        return self

    def modify(
        self,
        *,
        first: str | None = None,
        last: str | None = None,
        uid: int | None = None,
        gid: int | None = None,
        password: str | None = None,
        home: str | None = None,
        gecos: str | None = None,
        shell: str | None = None,
        user_auth_type: str | list[str] | None = None,
        idp: str | None = None,
        idp_user_id: str | None = None,
        password_expiration: str | None = None,
        sshpubkey: str | list[str] | None = None,
    ) -> IPAUser:
        """
        Modify existing IPA user.

        :param first: First name of user.
        :type first: str | None, optional
        :param last: Last name of user.
        :type last: str | None, optional
        :param uid: User id, defaults to None
        :type uid: int | None, optional
        :param gid: Primary group id, defaults to None
        :type gid: int | None, optional
        :param password: Password, defaults to 'Secret123'
        :type password: str | None, optional
        :param home: Home directory, defaults to None
        :type home: str | None, optional
        :param gecos: GECOS, defaults to None
        :type gecos: str | None, optional
        :param shell: Login shell, defaults to None
        :type shell: str | None, optional
        :param user_auth_type: Types of supported user authentication, defaults to None
        :type user_auth_type: str | list[str] | None, optional
        :param idp: Name of external IdP configured in IPA for user.
        :type idp: str | None, optional
        :param idp_user_id: User ID used to map IPA user to external IdP user.
        :type idp_user_id: str | None, optional
        :param password_expiration: Date and time stamp for password expiration.
        :type password_expiration: str | None, optional
        :param sshpubkey: SSH public key, defaults to None
        :type sshpubkey: str | list[str] | None, optional
        :return: Self.
        :rtype: IPAUser
        """
        attrs = {
            "first": (self.cli.option.VALUE, first),
            "last": (self.cli.option.VALUE, last),
            "uid": (self.cli.option.VALUE, uid),
            "gidnumber": (self.cli.option.VALUE, gid),
            "homedir": (self.cli.option.VALUE, home),
            "gecos": (self.cli.option.VALUE, gecos),
            "shell": (self.cli.option.VALUE, shell),
            "password": (self.cli.option.SWITCH, True) if password is not None else None,
            "user-auth-type": (self.cli.option.VALUE, user_auth_type),
            "idp": (self.cli.option.VALUE, idp),
            "idp-user-id": (self.cli.option.VALUE, idp_user_id),
            "password-expiration": (self.cli.option.VALUE, password_expiration),
            "sshpubkey": (self.cli.option.VALUE, sshpubkey),
        }

        self._modify(attrs, input=password)
        return self

    def reset(self, password: str | None = "Secret123") -> IPAUser:
        """
        Reset user password.

        :param password: Password, defaults to 'Secret123'
        :type password: str, optional
        :return: Self.
        :rtype: IPAUser
        """
        pwinput = f"{password}\n{password}"
        self.role.host.conn.run(f"ipa passwd {self.name}", input=pwinput)
        self.expire("20380101120000Z")

        return self

    def expire(self, expiration: str | None = "19700101000000Z") -> IPAUser:
        """
        Set user password expiration date and time.

        :param expiration: Date and time for user password expiration, defaults to 19700101000000
        :type expiration: str, optional
        :return: Self.
        :rtype: IPAUser
        """
        self.modify(password_expiration=expiration)

        return self

    def password_change_at_logon(self) -> IPAUser:
        """
        Force user to change password next logon.

        :return: Self.
        :rtype: IPAUser
        """
        self.host.conn.run(f"ipa user-mod {self.name} --setattr=krbPasswordExpiration=20010203203734Z")
        return self

    def passkey_add(self, passkey_mapping: str) -> IPAUser:
        """
        Add passkey mapping to the user.

        :param passkey_mapping: Passkey mapping generated by ``sssctl passkey-register``.
        :type passkey_mapping: str
        :return: Self.
        :rtype: IPAUser
        """
        self._exec("add-passkey", [passkey_mapping])
        return self

    def passkey_add_register(
        self,
        *,
        pin: str | int | None,
        device: str,
        ioctl: str,
        script: str,
    ) -> str:
        """
        Register passkey with the user (run ipa user-add-passkey --register).

        :param pin: Passkey PIN.
        :type pin: str | int | None
        :param device: Path to local umockdev device file.
        :type device: str
        :param ioctl: Path to local umockdev ioctl file.
        :type ioctl: str
        :param script: Path to local umockdev script file.
        :type script: str
        :return: Generated passkey mapping string.
        :rtype: str
        """
        device_path = self.role.fs.upload_to_tmp(device, mode="a=r")
        ioctl_path = self.role.fs.upload_to_tmp(ioctl, mode="a=r")
        script_path = self.role.fs.upload_to_tmp(script, mode="a=r")
        verify = pin is not None

        command = self.role.fs.mktmp(
            rf"""
            #!/bin/bash

            LD_PRELOAD=/opt/random.so umockdev-run \
                --device '{device_path}'                \
                --ioctl '/dev/hidraw1={ioctl_path}'     \
                --script '/dev/hidraw1={script_path}'   \
                -- ipa user-add-passkey '{self.name}' --register --cose-type=es256 --require-user-verification={verify}
            """,
            mode="a=rx",
        )

        if pin is not None:
            result = self.host.conn.expect(
                f"""
                spawn {command}
                expect {{
                    "Enter PIN:*" {{send -- "{pin}\r"}}
                    timeout {{puts "expect result: Unexpected output"; exit 201}}
                    eof {{puts "expect result: Unexpected end of file"; exit 202}}
                }}

                expect eof
                """,
                raise_on_error=True,
            )
        else:
            result = self.host.conn.expect(
                f"""
                spawn {command}
                expect eof
                """,
                raise_on_error=True,
            )

        return result.stdout_lines[-1].strip()

    def passkey_remove(self, passkey_mapping: str) -> IPAUser:
        """
        Add passkey mapping from the user.

        :param passkey_mapping: Passkey mapping generated by ``sssctl passkey-register``
        :type passkey_mapping: str
        :return: Self.
        :rtype: IPAUser.
        """
        self._exec("remove-passkey", [passkey_mapping])
        return self


class IPAGroup(IPAObject):
    """
    IPA group management.
    """

    def __init__(self, role: IPA, name: str) -> None:
        """
        :param role: IPA role object.
        :type role: IPA
        :param name: Group name.
        :type name: str
        """
        super().__init__(role, name, command_group="group")

    def add(
        self,
        *,
        gid: int | None = None,
        description: str | None = None,
        nonposix: bool = False,
        external: bool = False,
    ) -> IPAGroup:
        """
        Create new IPA group.

        Parameters that are not set are ignored.

        :param gid: Group id, defaults to None
        :type gid: int | None, optional
        :param description: Description, defaults to None
        :type description: str | None, optional
        :param nonposix: Group is non-posix group, defaults to False
        :type nonposix: bool, optional
        :param external: Group is external group, defaults to False
        :type external: bool, optional
        :return: Self.
        :rtype: IPAGroup
        """
        attrs = {
            "gid": (self.cli.option.VALUE, gid),
            "desc": (self.cli.option.VALUE, description),
            "nonposix": (self.cli.option.SWITCH, True) if nonposix else None,
            "external": (self.cli.option.SWITCH, True) if external else None,
        }

        self._add(attrs)
        return self

    def modify(
        self,
        *,
        gid: int | None = None,
        description: str | None = None,
    ) -> IPAGroup:
        """
        Modify existing IPA group.

        Parameters that are not set are ignored.

        :param gid: Group id, defaults to None
        :type gid: int | None, optional
        :param description: Description, defaults to None
        :type description: str | None, optional
        :return: Self.
        :rtype: IPAGroup
        """
        attrs: CLIBuilderArgs = {
            "gid": (self.cli.option.VALUE, gid),
            "desc": (self.cli.option.VALUE, description),
        }

        self._modify(attrs)
        return self

    def add_member(self, member: IPAUser | IPAGroup | str) -> IPAGroup:
        """
        Add group member.

        Member can be either IPAUser, IPAGroup or a string in which case it
        is added as an external member.

        :param member: User or group to add as a member.
        :type member: IPAUser | IPAGroup | str
        :return: Self.
        :rtype: IPAGroup
        """
        return self.add_members([member])

    def add_members(self, members: list[IPAUser | IPAGroup | str]) -> IPAGroup:
        """
        Add multiple group members.

        Member can be either IPAUser, IPAGroup or a string in which case it
        is added as an external member.

        :param members: List of users or groups to add as members.
        :type members: list[IPAUser | IPAGroup | str]
        :return: Self.
        :rtype: IPAGroup
        """
        self._exec("add-member", ipaargs=["--no-prompt"], args=self.__get_member_args(members))
        return self

    def remove_member(self, member: IPAUser | IPAGroup | str) -> IPAGroup:
        """
        Remove group member.

        Member can be either IPAUser, IPAGroup or a string in which case
        an external member is removed.

        :param member: User or group to remove from the group.
        :type member: IPAUser | IPAGroup | str
        :return: Self.
        :rtype: IPAGroup
        """
        return self.remove_members([member])

    def remove_members(self, members: list[IPAUser | IPAGroup | str]) -> IPAGroup:
        """
        Remove multiple group members.

        Member can be either IPAUser, IPAGroup or a string in which case
        an external member is removed.

        :param members: List of users or groups to remove from the group.
        :type members: list[IPAUser | IPAGroup | str]
        :return: Self.
        :rtype: IPAGroup
        """
        self._exec("remove-member", ipaargs=["--no-prompt"], args=self.__get_member_args(members))
        return self

    def __get_member_args(self, members: list[IPAUser | IPAGroup | str]) -> list[str]:
        users = [x for item in members if isinstance(item, IPAUser) for x in ("--users", item.name)]
        groups = [x for item in members if isinstance(item, IPAGroup) for x in ("--groups", item.name)]
        external = [x for item in members if isinstance(item, str) for x in ("--external", item)]
        return [*users, *groups, *external]


class IPANetgroup(IPAObject):
    """
    IPA netgroup management.
    """

    def __init__(self, role: IPA, name: str) -> None:
        """
        :param role: IPA role object.
        :type role: IPA
        :param name: Netgroup name.
        :type name: str
        """
        super().__init__(role, name, command_group="netgroup")

    def add(self) -> IPANetgroup:
        """
        Create new IPA netgroup.

        :return: Self.
        :rtype: IPANetgroup
        """
        self._add()
        return self

    def add_member(
        self,
        *,
        host: str | None = None,
        user: IPAUser | str | None = None,
        group: IPAGroup | str | None = None,
        hostgroup: str | None = None,
        ng: IPANetgroup | str | None = None,
    ) -> IPANetgroup:
        """
        Add netgroup member.

        :param host: Host, defaults to None
        :type host: str | None, optional
        :param user: User, defaults to None
        :type user: IPAUser | str | None, optional
        :param group: Group, defaults to None
        :type group: IPAGroup | str | None, optional
        :param hostgroup: Hostgroup, defaults to None
        :type hostgroup: str | None, optional
        :param ng: Netgroup, defaults to None
        :type ng: IPANetgroup | str | None, optional
        :return: Self.
        :rtype: IPANetgroup
        """
        return self.add_members([IPANetgroupMember(host=host, user=user, group=group, hostgroup=hostgroup, ng=ng)])

    def add_members(self, members: list[IPANetgroupMember]) -> IPANetgroup:
        """
        Add multiple netgroup members.

        :param members: Netgroup members.
        :type members: list[IPANetgroupMember]
        :return: Self.
        :rtype: IPANetgroup
        """
        self._exec("add-member", self.__get_member_args(members))
        return self

    def remove_member(
        self,
        *,
        host: str | None = None,
        user: IPAUser | str | None = None,
        group: IPAGroup | str | None = None,
        hostgroup: str | None = None,
        ng: IPANetgroup | str | None = None,
    ) -> IPANetgroup:
        """
        Remove netgroup member.

        :param host: Host, defaults to None
        :type host: str | None, optional
        :param user: User, defaults to None
        :type user: IPAUser | str | None, optional
        :param group: Group, defaults to None
        :type group: IPAGroup | str | None, optional
        :param hostgroup: Hostgroup, defaults to None
        :type hostgroup: str | None, optional
        :param ng: Netgroup, defaults to None
        :type ng: IPANetgroup | str | None, optional
        :return: Self.
        :rtype: IPANetgroup
        """
        return self.remove_members([IPANetgroupMember(host=host, user=user, group=group, hostgroup=hostgroup, ng=ng)])

    def remove_members(self, members: list[IPANetgroupMember]) -> IPANetgroup:
        """
        Remove multiple netgroup members.

        :param members: Netgroup members.
        :type members: list[IPANetgroupMember]
        :return: Self.
        :rtype: IPANetgroup
        """
        self._exec("remove-member", self.__get_member_args(members))
        return self

    def __get_member_args(self, members: list[IPANetgroupMember]) -> list[str]:
        users = [x for item in members if item.user is not None for x in ("--users", item.user)]
        groups = [x for item in members if item.group is not None for x in ("--groups", item.group)]
        hosts = [x for item in members if item.host is not None for x in ("--hosts", item.host)]
        hostgroups = [x for item in members if item.hostgroup is not None for x in ("--hostgroups", item.hostgroup)]
        netgroups = [x for item in members if item.netgroup is not None for x in ("--netgroups", item.netgroup)]

        return [*users, *groups, *hosts, *hostgroups, *netgroups]


class IPANetgroupMember(GenericNetgroupMember):
    """
    IPA netgroup member.
    """

    def __init__(
        self,
        *,
        host: str | None = None,
        user: IPAUser | str | None = None,
        group: IPAGroup | str | None = None,
        hostgroup: str | None = None,
        ng: IPANetgroup | str | None = None,
    ) -> None:
        """
        :param host: Host, defaults to None
        :type host: str | None, optional
        :param user: User, defaults to None
        :type user: IPAUser | str | None, optional
        :param group: Group, defaults to None
        :type group: IPAGroup | str | None, optional
        :param hostgroup: Hostgroup, defaults to None
        :type hostgroup: str | None, optional
        :param ng: Netgroup, defaults to None
        :type ng: IPANetgroup | str | None, optional
        """
        super().__init__(host=host, user=user, ng=ng)

        self.group: str | None = self._get_name(group)
        """Netgroup group."""

        self.hostgroup: str | None = hostgroup
        """Netgroup hostgroup."""


class IPAHostAccount(IPAObject):
    """
    IPA host management.
    """

    def __init__(self, role: IPA, name: str) -> None:
        """
        :param role: IPA role object.
        :type role: IPA
        :param name: Group name.
        :type name: str
        """
        super().__init__(role, name, command_group="host")

    def add(
        self,
        *,
        description: str | None = None,
        ip: str,
        sshpubkey: str | list[str] | None = None,
    ) -> IPAHostAccount:
        """
        Create new IPA host.

        Parameters that are not set are ignored.

        .. note::

            If you need a reverse DNS record, use IP address from
            10.255.251.0/24 address space. There is reverse zone for this
            address space available on the IPA server.

        :param description: Description, defaults to None
        :type description: str | None, optional
        :param ip: IP address.
        :type ip: str
        :param sshpubkey: SSH public key, defaults to None
        :type sshpubkey: str | list[str] | None, optional
        :return: Self.
        :rtype: IPAHostAccount
        """
        attrs: CLIBuilderArgs = {
            "desc": (self.cli.option.VALUE, description),
            "ip-address": (self.cli.option.VALUE, ip),
            "sshpubkey": (self.cli.option.VALUE, sshpubkey),
        }

        self._add(attrs)
        return self

    def modify(
        self,
        *,
        description: str | None = None,
        sshpubkey: str | list[str] | None = None,
    ) -> IPAHostAccount:
        """
        Modify existing IPA host.

        Parameters that are not set are ignored.

        :param description: Description, defaults to None
        :type description: str | None, optional
        :param sshpubkey: SSH public key, defaults to None
        :type sshpubkey: str | list[str] | None, optional
        :return: Self.
        :rtype: IPAGroup
        """
        attrs: CLIBuilderArgs = {
            "desc": (self.cli.option.VALUE, description),
            "sshpubkey": (self.cli.option.VALUE, sshpubkey),
        }

        self._modify(attrs)
        return self


class IPASudoRule(IPAObject):
    """
    IPA sudo rule management.
    """

    def __init__(self, role: IPA, name: str) -> None:
        """
        :param role: IPA role object.
        :type role: IPA
        :param name: Sudo rule name.
        :type name: str
        """
        super().__init__(role, name, command_group="sudorule")
        self.__rule: dict[str, Any] = dict()

    def add(
        self,
        *,
        user: str | IPAUser | IPAGroup | list[str | IPAUser | IPAGroup] | None = None,
        host: str | list[str] | None = None,
        command: str | list[str] | None = None,
        option: str | list[str] | None = None,
        runasuser: str | IPAUser | IPAGroup | list[str | IPAUser | IPAGroup] | None = None,
        runasgroup: str | IPAGroup | list[str | IPAGroup] | None = None,
        order: int | None = None,
        nopasswd: bool | None = None,
    ) -> IPASudoRule:
        """
        Create new sudo rule.

        :param user: sudoUser attribute, defaults to None
        :type user: str | IPAUser | IPAGroup | list[str  |  IPAUser  |  IPAGroup] | None, optional
        :param host: sudoHost attribute, defaults to None
        :type host: str | list[str] | None, optional
        :param command: sudoCommand attribute, defaults to None
        :type command: str | list[str] | None, optional
        :param option: sudoOption attribute, defaults to None
        :type option: str | list[str] | None, optional
        :param runasuser: sudoRunAsUser attribute, defaults to None
        :type runasuser: str | IPAUser | IPAGroup | list[str  |  IPAUser  |  IPAGroup] | None, optional
        :param runasgroup: sudoRunAsGroup attribute, defaults to None
        :type runasgroup: str | IPAGroup | list[str  |  IPAGroup] | None, optional
        :param order: sudoOrder attribute, defaults to None
        :type order: int | None, optional
        :param nopasswd: If true, no authentication is required (NOPASSWD), defaults to None (no change)
        :type nopasswd: bool | None, optional
        :return: _description_
        :rtype: IPASudoRule
        """
        # Remember arguments so we can use them in modify if needed
        self.__rule = dict(
            user=user,
            host=host,
            command=command,
            option=option,
            runasuser=runasuser,
            runasgroup=runasgroup,
            order=order,
            nopasswd=nopasswd,
        )

        # Prepare data
        (allow_commands, deny_commands, cmdcat) = self.__get_commands(command)
        (hosts, hostcat) = self.__get_hosts(host)
        (users, groups, usercat) = self.__get_users_and_groups(user)
        options = to_list_of_strings(option)
        (runasuser_users, runasuser_groups, runasusercat) = self.__get_run_as_user(runasuser)
        (runasgroup_groups, runasgroupcat) = self.__get_run_as_group(runasgroup)

        if nopasswd is True:
            options = attrs_include_value(options, "!authenticate")
        elif nopasswd is False:
            options = attrs_include_value(options, "authenticate")

        # Add commands
        for cmd in allow_commands + deny_commands:
            self.role.host.conn.run(f'ipa sudocmd-find "{cmd}" || ipa sudocmd-add "{cmd}"')

        # Add command group for commands allowed by this rule
        self.role.host.conn.run(f'ipa sudocmdgroup-add "{self.name}_allow"')
        args = self.__args_from_list("sudocmds", allow_commands)
        self.__exec_with_args("sudocmdgroup-add-member", f"{self.name}_allow", args)

        # Add command groups for commands denied by this rule
        self.role.host.conn.run(f'ipa sudocmdgroup-add "{self.name}_deny"')
        args = self.__args_from_list("sudocmds", deny_commands)
        self.__exec_with_args("sudocmdgroup-add-member", f"{self.name}_deny", args)

        # Add sudo rule
        args = "" if order is None else f'"{order}"'
        args += f" {cmdcat} {usercat} {hostcat} {runasusercat} {runasgroupcat}"
        self.role.host.conn.run(f'ipa sudorule-add "{self.name}" {args}')

        # Allow and deny commands through command groups
        if not cmdcat:
            self.role.host.conn.run(
                f'ipa sudorule-add-allow-command "{self.name}" "--sudocmdgroups={self.name}_allow"'
            )
            self.role.host.conn.run(f'ipa sudorule-add-deny-command "{self.name}" "--sudocmdgroups={self.name}_deny"')

        # Add hosts
        args = self.__args_from_list("hosts", hosts)
        self.__exec_with_args("sudorule-add-host", self.name, args)

        # Add options
        for opt in options:
            self.role.host.conn.run(f'ipa sudorule-add-option "{self.name}" "--sudooption={opt}"')

        # Add run as user
        args_users = self.__args_from_list("users", runasuser_users)
        args_groups = self.__args_from_list("groups", runasuser_groups)
        self.__exec_with_args("sudorule-add-runasuser", self.name, args_users + args_groups)

        # Add run as group
        args = self.__args_from_list("groups", runasgroup_groups)
        self.__exec_with_args("sudorule-add-runasgroup", self.name, args)

        # Add users and groups
        args_users = self.__args_from_list("users", users)
        args_groups = self.__args_from_list("groups", groups)
        self.__exec_with_args("sudorule-add-user", self.name, args_users + args_groups)

        return self

    def modify(
        self,
        *,
        user: str | IPAUser | IPAGroup | list[str | IPAUser | IPAGroup] | None = None,
        host: str | list[str] | None = None,
        command: str | list[str] | None = None,
        option: str | list[str] | None = None,
        runasuser: str | IPAUser | IPAGroup | list[str | IPAUser | IPAGroup] | None = None,
        runasgroup: str | IPAGroup | list[str | IPAGroup] | None = None,
        order: int | None = None,
        nopasswd: bool | None = None,
    ) -> IPASudoRule:
        """
        Modify existing IPA sudo rule.

        :param user: sudoUser attribute, defaults to None
        :type user: str | IPAUser | IPAGroup | list[str  |  IPAUser  |  IPAGroup] | None, optional
        :param host: sudoHost attribute, defaults to None
        :type host: str | list[str] | None, optional
        :param command: sudoCommand attribute, defaults to None
        :type command: str | list[str] | None, optional
        :param option: sudoOption attribute, defaults to None
        :type option: str | list[str] | None, optional
        :param runasuser: sudoRunAsUser attribute, defaults to None
        :type runasuser: str | IPAUser | IPAGroup | list[str  |  IPAUser  |  IPAGroup] | None, optional
        :param runasgroup: sudoRunAsGroup attribute, defaults to None
        :type runasgroup: str | IPAGroup | list[str  |  IPAGroup] | None, optional
        :param order: sudoOrder attribute, defaults to None
        :type order: int | None, optional
        :param nopasswd: If true, no authentication is required (NOPASSWD), defaults to None (no change)
        :type nopasswd: bool | None, optional
        :return: _description_
        :rtype: IPASudoRule
        """
        self.delete()
        self.add(
            user=user if user is not None else self.__rule.get("user", None),
            host=host if host is not None else self.__rule.get("host", None),
            command=command if command is not None else self.__rule.get("command", None),
            option=option if option is not None else self.__rule.get("option", None),
            runasuser=runasuser if runasuser is not None else self.__rule.get("runasuser", None),
            runasgroup=runasgroup if runasgroup is not None else self.__rule.get("runasgroup", None),
            order=order if order is not None else self.__rule.get("order", None),
            nopasswd=nopasswd if nopasswd is not None else self.__rule.get("nopasswd", None),
        )

        return self

    def delete(self) -> None:
        """
        Delete sudo rule from IPA.
        """
        self.role.host.conn.run(f'ipa sudorule-del "{self.name}"')
        self.role.host.conn.run(f'ipa sudocmdgroup-del "{self.name}_allow"')
        self.role.host.conn.run(f'ipa sudocmdgroup-del "{self.name}_deny"')

    def __get_commands(self, value: str | list[str] | None) -> tuple[list[str], list[str], str]:
        allow_commands = []
        deny_commands = []
        category = ""
        for cmd in to_list_of_strings(value):
            if cmd == "ALL":
                category = "--cmdcat=all"
                continue

            if cmd.startswith("!"):
                deny_commands.append(cmd[1:])
                continue

            allow_commands.append(cmd)

        return allow_commands, deny_commands, category

    def __get_hosts(self, value: str | list[str] | None) -> tuple[list[str], str]:
        hosts = []
        category = ""
        for host in to_list_of_strings(value):
            if host == "ALL":
                category = "--hostcat=all"
                continue

            hosts.append(host)

        return hosts, category

    def __get_users_and_groups(
        self, value: str | IPAUser | IPAGroup | list[str | IPAUser | IPAGroup] | None
    ) -> tuple[list[str], list[str], str]:
        users = []
        groups = []
        category = ""
        for item in to_list(value):
            if isinstance(item, str) and item == "ALL":
                category = "--usercat=all"
                continue

            if isinstance(item, IPAGroup):
                groups.append(item.name)
                continue

            if isinstance(item, str) and item.startswith("%"):
                groups.append(item[1:])
                continue

            if isinstance(item, IPAUser):
                users.append(item.name)
                continue

            if isinstance(item, str):
                users.append(item)
                continue

            raise ValueError(f"Unsupported type: {type(item)}")

        return users, groups, category

    def __get_run_as_user(
        self, value: str | IPAUser | IPAGroup | list[str | IPAUser | IPAGroup] | None
    ) -> tuple[list[str], list[str], str]:
        (users, groups, category) = self.__get_users_and_groups(value)
        if category:
            category = "--runasusercat=all"

        return users, groups, category

    def __get_run_as_group(self, value: str | IPAGroup | list[str | IPAGroup] | None) -> tuple[list[str], str]:
        groups = []
        category = ""
        for item in to_list(value):
            if isinstance(item, str) and item == "ALL":
                category = "--runasgroupcat=all"
                continue

            if isinstance(item, IPAGroup):
                groups.append(item.name)
                continue

            if isinstance(item, str):
                groups.append(item)
                continue

            raise ValueError(f"Unsupported type: {type(item)}")

        return groups, category

    def __args_from_list(self, option: str, value: list[str]) -> str:
        if not value:
            return ""

        args = ""
        for cmd in value:
            args += f' "--{option}={cmd}"'

        return args

    def __exec_with_args(self, cmd: str, name: str, args: str) -> None:
        if args:
            self.role.host.conn.run(f'ipa {cmd} "{name}" {args}')


class IPAAutomount(object):
    """
    IPA automount management.
    """

    def __init__(self, role: IPA) -> None:
        """
        :param role: IPA role object.
        :type role: IPA
        """
        self.__role = role

    def location(self, name: str) -> IPAAutomountLocation:
        """
        Get automount location object.

        :param name: Automount location name
        :type name: str
        :return: New automount location object.
        :rtype: IPAAutomountLocation
        """
        return IPAAutomountLocation(self.__role, name)

    def map(self, name: str, location: str = "default") -> IPAAutomountMap:
        """
        Get automount map object.

        :param name: Automount map name.
        :type name: str
        :param location: Automount map location, defaults to ``default``
        :type location: str
        :return: New automount map object.
        :rtype: IPAAutomountMap
        """
        return IPAAutomountMap(self.__role, name, location)

    def key(self, name: str, map: IPAAutomountMap) -> IPAAutomountKey:
        """
        Get automount key object.

        :param name: Automount key name.
        :type name: str
        :param map: Automount map that is a parent to this key.
        :type map: IPAAutomountMap
        :return: New automount key object.
        :rtype: IPAAutomountKey
        """
        return IPAAutomountKey(self.__role, name, map)


class IPAAutomountLocation(IPAObject):
    """
    IPA automount location management.
    """

    def __init__(
        self,
        role: IPA,
        name: str,
    ) -> None:
        """
        :param role: IPA role object.
        :type role: IPA
        :param name: Automount map location
        :type name: str
        """
        super().__init__(role, name, command_group="automountlocation")

    def add(
        self,
    ) -> IPAAutomountLocation:
        """
        Create new IPA automount location.

        :return: Self.
        :rtype: IPAAutomountLocation
        """
        self._add()

        # Delete auto.master and auto.direct maps that are automatically created
        # in a newly added location. This makes the IPA initial state consistent
        # with other providers and the tests can be more explicit.
        self.map("auto.master").delete()
        self.map("auto.direct").delete()

        return self

    def map(self, name: str) -> IPAAutomountMap:
        """
        Get automount map object for this location.

        :param name: Automount map name.
        :type name: str
        :return: New automount map object.
        :rtype: IPAAutomountMap
        """
        return IPAAutomountMap(self.role, name, self)


class IPAAutomountMap(IPAObject):
    """
    IPA automount map management.
    """

    def __init__(self, role: IPA, name: str, location: IPAAutomountLocation | str = "default") -> None:
        """
        :param role: IPA role object.
        :type role: IPA
        :param name: Automount map name.
        :type name: str
        :param location: Automount map location, defaults to ``default``
        :type location: IPAAutomountLocation | str
        """
        super().__init__(role, name, command_group="automountmap")
        self.location: IPAAutomountLocation = self.__get_location(location)

    def __get_location(self, location: IPAAutomountLocation | str) -> IPAAutomountLocation:
        if isinstance(location, str):
            return IPAAutomountLocation(self.role, location)
        elif isinstance(location, IPAAutomountLocation):
            return location
        else:
            raise ValueError(f"Unexpected location type: {type(location)}")

    def _exec(
        self, op: str, args: list[str] | None = None, ipaargs: list[str] | None = None, **kwargs
    ) -> ProcessResult:
        """
        Execute automountmap IPA command.

        .. code-block:: console

            $ ipa $ipaargs automountmap-$op $location $mapname $args
            for example >>> ipa automountmap-add default-location newmap

        :param op: Command group operation (usually add, mod, del, show)
        :type op: str
        :param args: List of additional command arguments, defaults to None
        :type args: list[str] | None, optional
        :param ipaargs: List of additional command arguments to the ipa main command, defaults to None
        :type ipaargs: list[str] | None, optional
        :return: SSH process result.
        :rtype: ProcessResult
        """
        if args is None:
            args = []

        if ipaargs is None:
            ipaargs = []

        defargs = self.cli.args(
            {
                "location": (self.cli.option.POSITIONAL, self.location.name),
                "mapname": (self.cli.option.POSITIONAL, self.name),
            }
        )
        return self.role.host.conn.exec(["ipa", *ipaargs, f"{self.command_group}-{op}", *defargs, *args], **kwargs)

    def add(
        self,
    ) -> IPAAutomountMap:
        """
        Create new IPA Automount map.

        :return: Self.
        :rtype: IPAAutomountMap
        """
        self._add()
        return self

    def key(self, name: str) -> IPAAutomountKey:
        """
        Get automount key object for this map.

        :param name: Automount key name.
        :type name: str
        :return: New automount key object.
        :rtype: IPAAutomountKey
        """
        return IPAAutomountKey(self.role, name, self)


class IPAAutomountKey(IPAObject):
    """
    IPA automount key management.
    """

    def __init__(
        self,
        role: IPA,
        name: str,
        map: IPAAutomountMap,
    ) -> None:
        """
        :param role: IPA role object.
        :type role: IPA
        :param name: Automount key name.
        :type name: str
        :param map: Automount map that is a parent to this key.
        :type map: IPAAutomountMap
        """
        super().__init__(role, name, command_group="automountkey")
        self.map: IPAAutomountMap = map
        self.info: str | None = None

    def _exec(
        self, op: str, args: list[str] | None = None, ipaargs: list[str] | None = None, **kwargs
    ) -> ProcessResult:
        """
        Execute automountkey IPA command.

        .. code-block:: console

            $ ipa $ipaargs automountkey-$op $location $mapname $keyname $args
            for example >>> ipa automountkey-add default-location newmap newkey --info=autofsinfo

        :param op: Command group operation (usually add, mod, del, show)
        :type op: str
        :param args: List of additional command arguments, defaults to None
        :type args: list[str] | None, optional
        :return: SSH process result.
        :rtype: ProcessResult
        """
        if args is None:
            args = []

        if ipaargs is None:
            ipaargs = []

        defargs = self.cli.args(
            {
                "location": (self.cli.option.POSITIONAL, self.map.location.name),
                "mapname": (self.cli.option.POSITIONAL, self.map.name),
                "key": (self.cli.option.VALUE, self.name),
            }
        )
        return self.role.host.conn.exec(["ipa", *ipaargs, f"{self.command_group}-{op}", *defargs, *args], **kwargs)

    def add(self, *, info: str | NFSExport | IPAAutomountMap) -> IPAAutomountKey:
        """
        Create new IPA automount key.

        :param info: Automount information
        :type info: str | NFSExport | IPAAutomountMap
        :return: Self.
        :rtype: IPAAutomountKey
        """
        parsed: str | None = self.__get_info(info)
        attrs: CLIBuilderArgs = {"info": (self.cli.option.VALUE, parsed)}

        self._add(attrs)
        self.info = parsed
        return self

    def modify(
        self,
        *,
        info: str | NFSExport | IPAAutomountMap | None = None,
    ) -> IPAAutomountKey:
        """
        Modify existing IPA automount key.

        :param info: Automount information, defaults to ``None``
        :type info: str | NFSExport | IPAAutomountMap | None
        :return: Self.
        :rtype: IPAAutomountKey
        """
        parsed: str | None = self.__get_info(info)
        attrs: CLIBuilderArgs = {
            "info": (self.cli.option.VALUE, parsed),
        }

        self._modify(attrs)
        self.info = parsed
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

    def __get_info(self, info: str | NFSExport | IPAAutomountMap | None) -> str | None:
        if isinstance(info, NFSExport):
            return info.get()

        if isinstance(info, IPAAutomountMap):
            return info.name

        return info


class IPAPasswordPolicy(IPAObject, GenericPasswordPolicy):
    """
    Password policy management.
    """

    def __init__(self, role: IPA, name: str = "ipausers"):
        """
        :param role: IPA host object.
        :type role: IPAHost
        :param name: Name of target object, defaults to 'ipausers'.
        :type name: str
        """
        super().__init__(role, name, command_group="pwpolicy")

    def complexity(self, enable: bool) -> IPAPasswordPolicy:
        """
        Enable or disable password complexity.

        :param enable: Enable or disable password complexity.
        :type enable: bool
        :return: IPAPasswordPolicy object.
        :rtype: IPAPasswordPolicy
        """
        if enable and self.get() is None:
            attrs: CLIBuilderArgs = {
                "dictcheck": (self.cli.option.VALUE, "True"),
                "usercheck": (self.cli.option.VALUE, "True"),
                "minlength": (self.cli.option.VALUE, 8),
                "minclasses": (self.cli.option.VALUE, 5),
                "priority": (self.cli.option.VALUE, 1),
            }
            self._add(attrs)
        else:
            _attrs: CLIBuilderArgs = {
                "dictcheck": (self.cli.option.VALUE, "False"),
                "usercheck": (self.cli.option.VALUE, "False"),
                "minlength": (self.cli.option.VALUE, 0),
                "minclasses": (self.cli.option.VALUE, 0),
                "priority": (self.cli.option.VALUE, 1),
            }
            self._modify(_attrs)

        return self

    def lockout(self, duration: int, attempts: int) -> IPAPasswordPolicy:
        """
        Set lockout duration and login attempts.

        :param duration: Duration of lockout in seconds.
        :type duration: int
        :param attempts: Number of login attempts.
        :type attempts: int
        :return: IPAPasswordPolicy object.
        :rtype: IPAPasswordPolicy
        """
        attrs: CLIBuilderArgs = {
            "lockouttime": (self.cli.option.VALUE, str(duration)),
            "maxfail": (self.cli.option.VALUE, str(attempts)),
        }
        self._add(attrs)

        return self

    def age(self, minimum: int, maximum: int) -> IPAPasswordPolicy:
        """
        Set maximum and minimum password age.

        :param minimum: Minimum password age in seconds, converted to days.
        :type minimum: int
        :param maximum: Maximum password age in seconds, converted to days.
        :type maximum: int
        :return: IPAPasswordPolicy object.
        :rtype: IPAPasswordPolicy
        """
        attrs: CLIBuilderArgs = {
            "minlife": (self.cli.option.VALUE, str(minimum)),
            "maxlife": (self.cli.option.VALUE, str(maximum)),
        }

        self._add(attrs)

        return self

    def requirements(self, length: int) -> IPAPasswordPolicy:
        """
        Set password requirements, like length.

        :param length: Required password character count.
        :type length: int
        :return: IPAPasswordPolicy object.
        :rtype: IPAPasswordPolicy
        """
        attrs: CLIBuilderArgs = {
            "minlength": (self.cli.option.VALUE, length),
        }
        self._add(attrs)

        return self
