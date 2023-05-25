"""Generic roles used with topology parametrization."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Protocol

from pytest_mh import MultihostRole
from pytest_mh.utils.firewall import GenericFirewall

from ..hosts.base import BaseHost
from .base import BaseObject
from .nfs import NFSExport

__all__ = [
    "ProtocolName",
    "GenericProvider",
    "GenericADProvider",
    "GenericUser",
    "GenericGroup",
    "GenericNetgroup",
    "GenericNetgroupMember",
    "GenericSudoRule",
    "GenericAutomount",
    "GenericAutomountMap",
    "GenericAutomountKey",
]


class ProtocolName(Protocol):
    """
    Used to hint that the type must contain name attribute.
    """

    name: str


class GenericProvider(ABC, MultihostRole[BaseHost]):
    """
    Generic provider interface. All providers implements this interface.

    .. note::

        This class provides generic interface for provider roles. It can be used
        for type hinting only on parametrized tests that runs on multiple
        topologies.
    """

    @property
    @abstractmethod
    def firewall(self) -> GenericFirewall:
        pass

    @abstractmethod
    def user(self, name: str) -> GenericUser:
        """
        Get user object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
            def test_example(client: Client, provider: GenericProvider):
                # Create user
                provider.user('user-1').add()

                # Start SSSD
                client.sssd.start()

                # Call `id user-1` and assert the result
                result = client.tools.id('user-1')
                assert result is not None
                assert result.user.name == 'user-1'

        :param name: User name.
        :type name: str
        :return: New user object.
        :rtype: GenericUser
        """
        pass

    @abstractmethod
    def group(self, name: str) -> GenericGroup:
        """
        Get group object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
            def test_example(client: Client, provider: GenericProvider):
                # Create user
                user = provider.user('user-1').add()

                # Create secondary group and add user as a member
                provider.group('group-1').add().add_member(user)

                # Start SSSD
                client.sssd.start()

                # Call `id user-1` and assert the result
                result = client.tools.id('user-1')
                assert result is not None
                assert result.user.name == 'user-1'
                assert result.memberof('group-1')

        :param name: Group name.
        :type name: str
        :return: New group object.
        :rtype: GenericGroup
        """
        pass

    @abstractmethod
    def netgroup(self, name: str) -> GenericNetgroup:
        """
        Get netgroup object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
            def test_example_netgroup(client: Client, provider: GenericProvider):
                # Create user
                user = provider.user("user-1").add()

                # Create two netgroups
                ng1 = provider.netgroup("ng-1").add()
                ng2 = provider.netgroup("ng-2").add()

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
        :return: New netgroup object.
        :rtype: GenericNetgroup
        """
        pass

    @abstractmethod
    def sudorule(self, name: str) -> GenericSudoRule:
        """
        Get sudo rule object.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
            def test_example(client: Client, provider: GenericProvider):
                user = provider.user('user-1').add(password="Secret123")
                provider.sudorule('testrule').add(user=user, host='ALL', command='/bin/ls')

                client.sssd.common.sudo()
                client.sssd.start()

                # Test that user can run /bin/ls
                assert client.auth.sudo.run('user-1', 'Secret123', command='/bin/ls')

        :param name: Sudo rule name.
        :type name: str
        :return: New sudo rule object.
        :rtype: GenericSudoRule
        """
        pass

    @property
    @abstractmethod
    def automount(self) -> GenericAutomount:
        """
        Manage automount maps and keys.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
            def test_example(client: Client, provider: GenericProvider, nfs: NFS):
                nfs_export1 = nfs.export('export1').add()
                nfs_export2 = nfs.export('export2').add()
                nfs_export3 = nfs.export('sub/export3').add()

                # Create automount maps
                auto_master = provider.automount.map('auto.master').add()
                auto_home = provider.automount.map('auto.home').add()
                auto_sub = provider.automount.map('auto.sub').add()

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
        pass


class GenericADProvider(GenericProvider):
    """
    Generic Active Directory provider interface. Active Directory and Samba
    providers implements this interface.

    .. note::

        This class provides generic interface for Active Directory-based
        roles. It can be used for type hinting only on parametrized tests
        that runs on both Samba and Active Directory.
    """

    @property
    @abstractmethod
    def firewall(self) -> GenericFirewall:
        pass


class GenericUser(ABC, BaseObject):
    """
    Generic user management.
    """

    @property
    @abstractmethod
    def name(self):
        """
        User name.
        """
        pass

    @abstractmethod
    def add(
        self,
        *,
        uid: int | None = None,
        gid: int | None = None,
        password: str = "Secret123",
        home: str | None = None,
        gecos: str | None = None,
        shell: str | None = None,
    ) -> GenericUser:
        """
        Create a new user.

        Parameters that are not set are ignored.

        :param uid: User id, defaults to None
        :type uid: int | None, optional
        :param gid: Primary group id, defaults to None
        :type gid: int | None, optional
        :param password: User password, defaults to 'Secret123'
        :type password: str, optional
        :param home: Home directory, defaults to None
        :type home: str | None, optional
        :param gecos: GECOS, defaults to None
        :type gecos: str | None, optional
        :param shell: Login shell, defaults to None
        :type shell: str | None, optional
        :return: Self.
        :rtype: GenericUser
        """
        pass

    @abstractmethod
    def modify(
        self,
        *,
        uid: int | None = None,
        gid: int | None = None,
        password: str | None = None,
        home: str | None = None,
        gecos: str | None = None,
        shell: str | None = None,
    ) -> GenericUser:
        """
        Modify existing user.

        Parameters that are not set are ignored.

        :param uid: User id, defaults to None
        :type uid: int | None, optional
        :param gid: Primary group id, defaults to None
        :type gid: int | None, optional
        :param password: Password, defaults to None
        :type password: str, optional
        :param home: Home directory, defaults to None
        :type home: str | None, optional
        :param gecos: GECOS, defaults to None
        :type gecos: str | None, optional
        :param shell: Login shell, defaults to None
        :type shell: str | None, optional
        :return: Self.
        :rtype: GenericUser
        """
        pass

    @abstractmethod
    def delete(self) -> None:
        """
        Delete the user.
        """
        pass

    @abstractmethod
    def get(self, attrs: list[str] | None = None) -> dict[str, list[str]]:
        """
        Get user attributes.

        :param attrs: If set, only requested attributes are returned, defaults to None
        :type attrs: list[str] | None, optional
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]]
        """
        pass

    @abstractmethod
    def passkey_add(self, passkey_mapping: str) -> GenericUser:
        """
        Add passkey mapping to the user.

        :param passkey_mapping: Passkey mapping generated by ``sssctl passkey-register``
        :type passkey_mapping: str
        :return: Self.
        :rtype: GenericUser
        """
        pass

    @abstractmethod
    def passkey_remove(self, passkey_mapping: str) -> GenericUser:
        """
        Remove passkey mapping from the user.

        :param passkey_mapping: Passkey mapping generated by ``sssctl passkey-register``
        :type passkey_mapping: str
        :return: Self.
        :rtype: GenericUser.
        """
        pass


class GenericGroup(ABC, BaseObject):
    """
    Generic group management.
    """

    @property
    @abstractmethod
    def name(self):
        """
        Group name.
        """
        pass

    @abstractmethod
    def add(
        self,
        *,
        gid: int | None = None,
        description: str | None = None,
    ) -> GenericGroup:
        """
        Create a new group.

        Parameters that are not set are ignored.

        :param gid: Group id, defaults to None
        :type gid: int | None, optional
        :param description: Description, defaults to None
        :type description: str | None, optional
        :return: Self.
        :rtype: GenericGroup
        """
        pass

    @abstractmethod
    def modify(
        self,
        *,
        gid: int | None = None,
        description: str | None = None,
    ) -> GenericGroup:
        """
        Modify existing group.

        Parameters that are not set are ignored.

        :param gid: Group id, defaults to None
        :type gid: int | None, optional
        :param description: Description, defaults to None
        :type description: str | None, optional
        :return: Self.
        :rtype: GenericGroup
        """
        pass

    @abstractmethod
    def delete(self) -> None:
        """
        Delete the group.
        """
        pass

    @abstractmethod
    def get(self, attrs: list[str] | None = None) -> dict[str, list[str]]:
        """
        Get group attributes.

        :param attrs: If set, only requested attributes are returned, defaults to None
        :type attrs: list[str] | None, optional
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]]
        """
        pass

    @abstractmethod
    def add_member(self, member: GenericUser | GenericGroup) -> GenericGroup:
        """
        Add group member.

        :param member: User or group to add as a member.
        :type member: GenericUser | GenericGroup
        :return: Self.
        :rtype: GenericGroup
        """
        pass

    @abstractmethod
    def add_members(self, members: list[GenericUser | GenericGroup]) -> GenericGroup:
        """
        Add multiple group members.

        :param member: List of users or groups to add as members.
        :type member: list[GenericUser | GenericGroup]
        :return: Self.
        :rtype: GenericGroup
        """
        pass

    @abstractmethod
    def remove_member(self, member: GenericUser | GenericGroup) -> GenericGroup:
        """
        Remove group member.

        :param member: User or group to remove from the group.
        :type member: GenericUser | GenericGroup
        :return: Self.
        :rtype: GenericGroup
        """
        pass

    @abstractmethod
    def remove_members(self, members: list[GenericUser | GenericGroup]) -> GenericGroup:
        """
        Remove multiple group members.

        :param member: List of users or groups to remove from the group.
        :type member: list[GenericUser | GenericGroup]
        :return: Self.
        :rtype: GenericGroup
        """
        pass


class GenericNetgroup(ABC, BaseObject):
    """
    Generic netgroup management.
    """

    @property
    @abstractmethod
    def name(self):
        """
        Netgroup name.
        """
        pass

    @abstractmethod
    def add(self) -> GenericNetgroup:
        """
        Create a new netgroup.

        :return: Self.
        :rtype: GenericNetroup
        """
        pass

    @abstractmethod
    def delete(self) -> None:
        """
        Delete the netgroup.
        """
        pass

    @abstractmethod
    def get(self, attrs: list[str] | None = None) -> dict[str, list[str]]:
        """
        Get netgroup attributes.

        :param attrs: If set, only requested attributes are returned, defaults to None
        :type attrs: list[str] | None, optional
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]]
        """
        pass

    @abstractmethod
    def add_member(
        self,
        *,
        host: str | None = None,
        user: GenericUser | str | None = None,
        ng: GenericNetgroup | str | None = None,
    ) -> GenericNetgroup:
        """
        Add netgroup member.

        :param host: Host, defaults to None
        :type host: str | None, optional
        :param user: User, defaults to None
        :type user: GenericUser | str | None, optional
        :param ng: Netgroup, defaults to None
        :type ng: GenericNetgroup | str | None, optional
        :return: Self.
        :rtype: GenericNetgroup
        """
        pass

    @abstractmethod
    def add_members(self, members: list[GenericNetgroupMember]) -> GenericNetgroup:
        """
        Add multiple netgroup members at once.

        :param member: List of netgroup members to add.
        :type member: list[GenericNetgroupMember]
        :return: Self.
        :rtype: GenericNetgroup
        """
        pass

    @abstractmethod
    def remove_member(
        self,
        *,
        host: str | None = None,
        user: GenericUser | str | None = None,
        ng: GenericNetgroup | str | None = None,
    ) -> GenericNetgroup:
        """
        Remove group member.

        :param host: Host, defaults to None
        :type host: str | None, optional
        :param user: User, defaults to None
        :type user: GenericUser | str | None, optional
        :param ng: Netgroup, defaults to None
        :type ng: GenericNetgroup | str | None, optional
        :return: Self.
        :rtype: GenericNetroup
        """
        pass

    @abstractmethod
    def remove_members(self, members: list[GenericNetgroupMember]) -> GenericNetgroup:
        """
        Remove multiple group members.

        :param member: List of netgroup members to add.
        :type member: list[GenericNetgroupMember]
        :return: Self.
        :rtype: GenericNetroup
        """
        pass


class GenericNetgroupMember(object):
    """
    Generic netgroup member.

    .. note::

        This is a essentially a NIS Netgroup Triple, but we have to omit the
        domain part as it is not supported by FreeIPA. In addition to the
        triple, it can also hold a netgroup as a member.

    """

    def __init__(
        self, *, host: str | None = None, user: ProtocolName | str | None = None, ng: ProtocolName | str | None = None
    ) -> None:
        """
        :param host: Host, defaults to None
        :type host: str | None, optional
        :param user: User, defaults to None
        :type user: ProtocolName | str | None, optional
        :param ng: Netgroup, defaults to None
        :type ng: ProtocolName | str | None, optional
        """
        self.host: str | None = host
        """Member host."""

        self.user: str | None = self._get_name(user)
        """Member user."""

        self.netgroup: str | None = self._get_name(ng)
        """Member netgroup."""

    def _get_name(self, item: ProtocolName | str | None = None) -> str | None:
        if item is None:
            return None

        if hasattr(item, "name"):
            return item.name

        return item


class GenericSudoRule(ABC, BaseObject):
    """
    Generic sudo rule management.
    """

    @property
    @abstractmethod
    def name(self):
        """
        Sudo rule name.
        """
        pass

    @abstractmethod
    def add(
        self,
        *,
        user: str | GenericUser | GenericGroup | list[str | GenericUser | GenericGroup] | None = None,
        host: str | list[str] | None = None,
        command: str | list[str] | None = None,
        option: str | list[str] | None = None,
        runasuser: str | GenericUser | GenericGroup | list[str | GenericUser | GenericGroup] | None = None,
        runasgroup: str | GenericGroup | list[str | GenericGroup] | None = None,
        order: int | None = None,
        nopasswd: bool | None = None,
    ) -> GenericSudoRule:
        """
        Create new sudo rule.

        :param user: sudoUser attribute, defaults to None
        :type user: str | GenericUser | GenericGroup | list[str  |  GenericUser  |  GenericGroup] | None, optional
        :param host: sudoHost attribute, defaults to None
        :type host: str | list[str] | None, optional
        :param command: sudoCommand attribute, defaults to None
        :type command: str | list[str] | None, optional
        :param option: sudoOption attribute, defaults to None
        :type option: str | list[str] | None, optional
        :param runasuser: sudoRunAsUser attribute, defaults to None
        :type runasuser: str | GenericUser | GenericGroup | list[str  |  GenericUser  |  GenericGroup] | None, optional
        :param runasgroup: sudoRunAsGroup attribute, defaults to None
        :type runasgroup: str | GenericGroup | list[str  |  GenericGroup] | None, optional
        :param order: sudoOrder attribute, defaults to None
        :type order: int | None, optional
        :param nopasswd: If true, no authentication is required (NOPASSWD), defaults to None (no change)
        :type nopasswd: bool | None, optional
        :return: _description_
        :rtype: GenericSudoRule
        """
        pass

    @abstractmethod
    def modify(
        self,
        *,
        user: str | GenericUser | GenericGroup | list[str | GenericUser | GenericGroup] | None = None,
        host: str | list[str] | None = None,
        command: str | list[str] | None = None,
        option: str | list[str] | None = None,
        runasuser: str | GenericUser | GenericGroup | list[str | GenericUser | GenericGroup] | None = None,
        runasgroup: str | GenericGroup | list[str | GenericGroup] | None = None,
        order: int | None = None,
        nopasswd: bool | None = None,
    ) -> GenericSudoRule:
        """
        Create new sudo rule.

        :param user: sudoUser attribute, defaults to None
        :type user: str | GenericUser | GenericGroup | list[str  |  GenericUser  |  GenericGroup] | None, optional
        :param host: sudoHost attribute, defaults to None
        :type host: str | list[str] | None, optional
        :param command: sudoCommand attribute, defaults to None
        :type command: str | list[str] | None, optional
        :param option: sudoOption attribute, defaults to None
        :type option: str | list[str] | None, optional
        :param runasuser: sudoRunAsUser attribute, defaults to None
        :type runasuser: str | GenericUser | GenericGroup | list[str  |  GenericUser  |  GenericGroup] | None, optional
        :param runasgroup: sudoRunAsGroup attribute, defaults to None
        :type runasgroup: str | GenericGroup | list[str  |  GenericGroup] | None, optional
        :param order: sudoOrder attribute, defaults to None
        :type order: int | None, optional
        :param nopasswd: If true, no authentication is required (NOPASSWD), defaults to None (no change)
        :type nopasswd: bool | None, optional
        :return: _description_
        :rtype: GenericSudoRule
        """
        pass

    @abstractmethod
    def delete(self) -> None:
        """
        Delete the sudo rule.
        """
        pass

    @abstractmethod
    def get(self, attrs: list[str] | None = None) -> dict[str, list[str]]:
        """
        Get sudo rule attributes.

        :param attrs: If set, only requested attributes are returned, defaults to None
        :type attrs: list[str] | None, optional
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]]
        """
        pass


class GenericAutomount(ABC):
    """
    Generic automount management.
    """

    @abstractmethod
    def map(self, name: str) -> GenericAutomountMap:
        """
        Get automount map object.

        :param name: Automount map name.
        :type name: str
        :return: New automount map object.
        :rtype: GenericAutomountMap
        """
        pass

    @abstractmethod
    def key(self, name: str, map: GenericAutomountMap) -> GenericAutomountKey:
        """
        Get automount key object.

        :param name: Automount key name.
        :type name: str
        :param map: Automount map that is a parent to this key.
        :type map: GenericAutomountMap
        :return: New automount key object.
        :rtype: GenericAutomountKey
        """
        pass


class GenericAutomountMap(ABC, BaseObject):
    """
    Generic automount map management.
    """

    @property
    @abstractmethod
    def name(self):
        """
        Automount map name.
        """
        pass

    @abstractmethod
    def add(self) -> GenericAutomountMap:
        """
        Create new automount map.

        :return: Self.
        :rtype: GenericAutomountMap
        """
        pass

    @abstractmethod
    def key(self, name: str) -> GenericAutomountKey:
        """
        Get automount key object for this map.

        :param name: Automount key name.
        :type name: str
        :return: New automount key object.
        :rtype: GenericAutomountKey
        """
        pass

    @abstractmethod
    def delete(self) -> None:
        """
        Delete the automout map.
        """
        pass

    @abstractmethod
    def get(self, attrs: list[str] | None = None) -> dict[str, list[str]]:
        """
        Get automount map attributes.

        :param attrs: If set, only requested attributes are returned, defaults to None
        :type attrs: list[str] | None, optional
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]]
        """
        pass


class GenericAutomountKey(ABC, BaseObject):
    """
    Generic automount key management.
    """

    @property
    @abstractmethod
    def name(self):
        """
        Automoutn key name.
        """
        pass

    @abstractmethod
    def add(self, *, info: str | NFSExport | GenericAutomountMap) -> GenericAutomountKey:
        """
        Create new automount key.

        :param info: Automount information.
        :type info: str | NFSExport | GenericAutomountMap
        :return: Self.
        :rtype: GenericAutomountKey
        """
        pass

    @abstractmethod
    def modify(
        self,
        *,
        info: str | NFSExport | GenericAutomountMap | None = None,
    ) -> GenericAutomountKey:
        """
        Modify existing automount key.

        :param info: Automount information, defaults to ``None``
        :type info: str | NFSExport | GenericAutomountMap | None
        :return: Self.
        :rtype: GenericAutomountKey
        """
        pass

    @abstractmethod
    def delete(self) -> None:
        """
        Delete the automount key.
        """
        pass

    @abstractmethod
    def get(self, attrs: list[str] | None = None) -> dict[str, list[str]]:
        """
        Get automount key attributes.

        :param attrs: If set, only requested attributes are returned, defaults to None
        :type attrs: list[str] | None, optional
        :return: Dictionary with attribute name as a key.
        :rtype: dict[str, list[str]]
        """
        pass

    @abstractmethod
    def dump(self) -> str:
        """
        Dump the key in the ``automount -m`` format.

        .. code-block:: text

            export1 | -fstype=nfs,rw,sync,no_root_squash nfs.test:/dev/shm/exports/export1

        You can also call ``str(key)`` instead of ``key.dump()``.

        :return: Key information in ``automount -m`` format.
        :rtype: str
        """
        pass

    @abstractmethod
    def __str__(self) -> str:
        pass
