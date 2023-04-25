from __future__ import annotations

import json
import shlex

from pytest_mh.ssh import SSHProcessResult

from ..hosts.keycloak import KeycloakHost
from .base import BaseLinuxRole, BaseObject

__all__ = [
    "Keycloak",
    "KeycloakUser",
    "KeycloakGroup",
]


class Keycloak(BaseLinuxRole[KeycloakHost]):
    """
    Keycloak service management.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    def setup(self) -> None:
        """
        Make sure we have admin's TGT so we can run ipa cli commands.
        """
        super().setup()
        self.host.kclogin()

    def kcadm(self, command: str) -> SSHProcessResult:
        """
        Run kcadm command on the Keycloak server.

        This is the CLI to interface with the Keycloak API to perform functions
        like adding users, deleting groups, etc.

        :param command: kcadm command
        :type command: str
        """
        kcadm = "/opt/keycloak/bin/kcadm.sh"
        command_split = shlex.split(command)
        result = self.host.ssh.exec([kcadm] + command_split)
        return result

    def user(self, name: str) -> KeycloakUser:
        """
        Get user object.

        :param name: User name.
        :type name: str
        :return: New user object.
        :rtype: KeycloakUser
        """
        return KeycloakUser(self, name)

    def group(self, name: str) -> KeycloakGroup:
        """
        Get group object.

        :param name: Group name.
        :type name: str
        :return: New group object.
        :rtype: KeycloakGroup
        """
        return KeycloakGroup(self, name)


class KeycloakObject(BaseObject[KeycloakHost, Keycloak]):
    """
    Keycloak Object.
    """

    def __init__(self, role: Keycloak, name: str) -> None:
        """
        :param role: Keycloak role object.
        :type role: Keycloak
        :param name: User name.
        :type name: str
        """
        super().__init__(role)
        self.name = name
        self.id: str = ""


class KeycloakUser(KeycloakObject):
    """
    Keycloak user management.
    """

    def __init__(self, role: Keycloak, name: str) -> None:
        """
        :param role: Keycloak role object.
        :type role: Keycloak
        :param name: User name.
        :type name: str
        """
        super().__init__(role, name)

    def add(
        self,
        *,
        password: str | None = "Secret123",
    ) -> KeycloakUser:
        """
        Create new Keycloak user.

        Parameters that are not set are ignored.

        :param password: Password, defaults to 'Secret123'
        :type password: str | None, optional
        :return: Self.
        :rtype: KeycloakUser
        """
        create_user = (
            "create users -r master " f"-s username={self.name} " f"-s email={self.name}@ipa.test " "-s enabled=true"
        )
        result = self.role.kcadm(create_user)

        self.id = result.stderr.split()[-1].strip("'")

        set_password = "set-password -r master " f"--username {self.name} " f"--new-password {password}"
        self.role.kcadm(set_password)

        return self

    def delete(self) -> None:
        """
        Delete Keycloak user.
        """
        del_user = f"delete users/{self.id}"
        self.role.kcadm(del_user)

    def get(self) -> dict[str, list[str]]:
        """
        Get Keycloak user details.

        :return: Dict of user info
        :rtype: Dict
        """
        get_user = f"get users -q username={self.name}"
        result = self.role.kcadm(get_user)

        out: dict[str, list[str]] = {}
        if not result.stdout or result.stdout == "[ ]":
            return out

        json1 = json.loads(result.stdout)[0]
        for key in json1.keys():
            out.setdefault(key, [])
            out[key].append(json1[key])

        return out

    def get_groups(self) -> list[dict[str, list[str]]]:
        """
        Get Keycloak groups that user is a member of.

        :return: Dict of user info
        :rtype: Dict
        """
        get_groups = f"get users/{self.id}/groups"
        result = self.role.kcadm(get_groups)

        outlist: list[dict[str, list[str]]] = []
        if not result.stdout:
            return outlist

        json1 = json.loads(result.stdout)
        for item in json1:
            out: dict[str, list[str]] = {}
            for key in item.keys():
                out.setdefault(key, [])
                out[key].append(item[key])
            outlist.append(out)

        return outlist


class KeycloakGroup(KeycloakObject):
    """
    Keycloak group management.
    """

    def __init__(self, role: Keycloak, name: str) -> None:
        """
        :param role: Keycloak role object.
        :type role: Keycloak
        :param name: Group name.
        :type name: str
        """
        super().__init__(role, name)

    def add(self) -> KeycloakGroup:
        """
        Create new Keycloak group.

        Parameters that are not set are ignored.

        :return: Self.
        :rtype: KeycloakGroup
        """
        create_group = f"create groups -r master -s name={self.name}"
        result = self.role.kcadm(create_group)

        self.id = result.stderr.split()[-1].strip("'")
        return self

    def add_member(self, member: KeycloakUser | KeycloakGroup) -> KeycloakGroup:
        """
        Add group member.

        :param member: User or group to add as a member.
        :type member: KeycloakUser | KeycloakGroup
        :return: Self.
        :rtype: KeycloakGroup
        """
        return self.add_members([member])

    def add_members(self, members: list[KeycloakUser | KeycloakGroup]) -> KeycloakGroup:
        """
        Add multiple group members.

        :param member: List of users or groups to add as members.
        :type member: list[KeycloakUser | KeycloakGroup]
        :return: Self.
        :rtype: KeycloakGroup
        """
        for item in self.__get_member_args(members):
            update_group = f"update {item}/groups/{self.id} -r master"
            self.role.kcadm(update_group)
        return self

    def remove_member(self, member: KeycloakUser | KeycloakGroup) -> KeycloakGroup:
        """
        Remove group member.

        :param member: User or group to remove from the group.
        :type member: KeycloakUser | KeycloakGroup
        :return: Self.
        :rtype: KeycloakGroup
        """
        return self.remove_members([member])

    def remove_members(self, members: list[KeycloakUser | KeycloakGroup]) -> KeycloakGroup:
        """
        Remove multiple group members.

        :param member: List of users or groups to remove from the group.
        :type member: list[KeycloakUser | KeycloakGroup]
        :return: Self.
        :rtype: KeycloakGroup
        """
        remove_member = f"remove-member {self.__get_member_args(members)}"
        self.role.kcadm(remove_member)
        return self

    def __get_member_args(self, members: list[KeycloakUser | KeycloakGroup]) -> list[str]:
        users = [x for item in members if isinstance(item, KeycloakUser) for x in (f"users/{item.id}",)]
        groups = [x for item in members if isinstance(item, KeycloakGroup) for x in (f"groups/{item.id}",)]
        return [*users, *groups]
