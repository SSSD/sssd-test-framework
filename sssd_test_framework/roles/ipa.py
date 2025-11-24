"""IPA multihost role."""

from __future__ import annotations

import os
import re
import shlex
import uuid
from itertools import groupby
from textwrap import dedent
from typing import Any, Literal, Optional

from pytest_mh import MultihostHost
from pytest_mh.cli import CLIBuilder, CLIBuilderArgs
from pytest_mh.conn import ProcessError, ProcessResult
from pytest_mh.utils.fs import LinuxFileSystem

from ..hosts.ipa import IPAHost
from ..misc import (
    attrs_include_value,
    attrs_parse,
    delimiter_parse,
    get_attr,
    ip_version,
    to_list,
    to_list_of_strings,
    to_list_without_none,
)
from ..misc.globals import test_venv_bin
from ..roles.client import Client
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
    "IPADNSServer",
    "IPADNSZone",
    "IPACertificateAuthority",
    "IPAHBACService",
    "IPAHBACServiceGroup",
    "IPAHostGroup",
    "IPAHBAC",
]

RevocationReason = Literal[
    "unspecified",
    "key_compromise",
    "ca_compromise",
    "affiliation_changed",
    "superseded",
    "cessation_of_operation",
    "certificate_hold",
    "remove_from_crl",
    "privilege_withdrawn",
    "aa_compromise",
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

        self.name: str = "ipa"
        """
        Generic provider name.
        """

        self.server: str = self.host.hostname
        """
        Generic server name.
        """

        self.sssd: SSSDUtils = SSSDUtils(self.host, self.fs, self.svc, self.authselect, load_config=True)
        """
        Managing and configuring SSSD.
        """

        self.sssctl: SSSCTLUtils = SSSCTLUtils(self.host, self.fs)
        """
        Call commands from sssctl.
        """

        self._password_policy: IPAPasswordPolicy = IPAPasswordPolicy(self)
        """
        Manage password policy.
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

        self.ca = IPACertificateAuthority(self.host, self.fs)
        """
        IPA Certificate Authority management.

        Provides certificate operations:
        - Request certificates for services/users
        - Revoke certificates with configurable reasons
        - Manage certificate holds
        - Retrieve certificate details

        Example:
            cert, key, csr = ipa.ca.request(principal="HTTP/client.ipa.test")
            ipa.ca.revoke_hold(cert)
            ipa.ca.revoke(cert, reason="key_compromise")
        """

    @property
    def password_policy(self) -> IPAPasswordPolicy:
        """
        Domain password policy management.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.IPA)
            def test_example(client: Client, ipa: IPA):
                # Enable password complexity
                ipa.password_policy.complexity(enable=True)

                # Set 3 login attempts and 30 lockout duration
                ipa.password_policy.lockout(attempts=3, duration=30)
        """
        return self._password_policy

    @property
    def naming_context(self) -> str:
        """
        Naming context.
        """
        ipa_default = self.fs.read("/etc/ipa/default.conf")
        _ipa_default = ipa_default.strip().splitlines()
        for i in _ipa_default:
            if "basedn" in i:
                return str(i.split("=", 1)[1])

        raise ValueError("basedn not found in /etc/ipa/default.conf!")

    def setup(self) -> None:
        """
        Obtain IPA admin Kerberos TGT.
        """
        super().setup()

        # Restart SSSD so it is opened with new database files.
        self.sssd.stop()
        self.sssd.clear(db=True, memcache=True, logs=True, config=False)
        self.sssd.start()

        # Obtain admin TGT
        self.host.kinit()

    def fqn(self, name: str) -> str:
        """
        Return fully qualified name in form name@domain.

        :param name: Username.
        :type name: str
        :return: Fully qualified name.
        :rtype: str
        """
        return f"{name}@{self.domain}"

    @staticmethod
    def ipa_search(
        role: IPA,
        command: str,
        criteria: str | None = None,
        attr: str = "cn",
        all: bool = False,
    ) -> list[str]:
        """
        Perform a generic IPA search command and extract attribute values.

        :param role: IPA role object.
        :type role: IPA
        :param command: IPA command to run (e.g., 'hostgroup-find').
        :type command: str
        :param criteria: Optional search filter string.
        :type criteria: str or None, optional
        :param attr: Attribute name to extract from each entry.
        :type attr: str, optional
        :param all: Prints all attributes, default is False.
        :type all: bool, optional
        :return: List of extracted attribute values.
        :rtype: list[str]
        """
        cmd = ["ipa", command]
        if all:
            cmd.append("--all")
        if criteria:
            cmd.append(criteria)
        result = role.host.conn.exec(cmd)

        names: list[str] = []
        blocks = (
            list(group) for key, group in groupby(result.stdout_lines, key=lambda line: line.strip() == "") if not key
        )

        for block in blocks:
            attrs = attrs_parse(block)
            values = attrs.get(attr, [])
            for value in values:
                if isinstance(value, list):
                    names.extend(value)
                else:
                    names.append(value)
        return names

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

    def idview(self, name: str) -> IPAIDView:
        """
        IPA ID View object.

        Here, we only add the IPA ID view, that can be used
        while creating a new User ID override.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.IPA)
            def test_example(ipa: IPA):
                ipa.idview("newview").add(description="This is a new view")
                ipa.idview("newview").apply(hosts="client.test")
                ipa.idview("newview").delete()

        :param name: ID View name.
        :type name: str
        :return: New ID View object.
        """
        return IPAIDView(self, name)

    def dns(self) -> IPADNSServer:
        """
        Get DNS server object.

            Get methods use dig and is parsed by jc. The data from jc contains several nested dict,
            but two are returned as a tuple, ``answer, authority``.

        .. code-block:: python
            :caption: Example usage

            # Create forward zone and add forward record
            zone = ipa.dns().zone("example.test").create()
            zone.add_record("client", "172.16.200.15")

            # Create reverse zone and add reverse record
            zone = ipa.dns().zone("10.0.10.in-addr.arpa").create()
            zone.add_ptr_record("client.example.test", 15)

            # Add forward record to default domain
            ipa.dns().zone(ipa.domain).add_record("client", "1.2.3.4")

            # Add a global forwarder
            ipa.dns().add_forwarder("1.1.1.1")

            # Remove a global forwarder
            ipa.dns().remove_forwarder("1.1.1.1")

            # Clear all forwarders
            ipa.dns().clear_forwarders()
        """
        return IPADNSServer(self)

    def hbac(self, name: str) -> IPAHBAC:
        """
        IPA HBAC object.

        Provides access to manage HBAC (Host-Based Access Control) rules in IPA.
        This allows creating rules and setting access controls for particular hosts and services.

        .. rubric:: Example usage

        .. code-block:: python

            @pytest.mark.topology(KnownTopology.IPA)
            def test_ipa__validate_hbac_rule_check_access_sshd_service(client: Client, ipa: IPA):
                # Disable all users to access all services on all hosts.
                ipa.hbac("allow_all").disable()

                ssh_access_rule = ipa.hbac("ssh_access_user1").create(
                    description="SSH access rule for user1",
                    users="user1",
                    hosts="client.test",
                    services="sshd"
                )

                hbactest_out1 = ssh_access_rule.test(user="user1", host="client.test",
                                                    service="sshd", rule="ssh_access_user1")
                assert hbactest_out1["access_granted"], "Access was not granted as expected"
                assert "ssh_access_user1" in hbactest_out1["matched_rules"], \
                    "Matched rule ssh_access_user1 was not found as expected"

                hbactest_out2 = ssh_access_rule.test(user="user2", host="client.test",
                                                    service="sshd", rule="ssh_access_user1")
                assert not hbactest_out2["access_granted"], "Access was granted which is not expected"
                assert "ssh_access_user1" in hbactest_out2["not_matched_rules"], \
                    "Rule should not match for user2"

                hbactest_out3 = ssh_access_rule.test(user="user1", host="client.test",
                                                    service="sshd", rule="nonexistent_rule")
                assert "nonexistent_rule" in hbactest_out3["invalid_rules"], \
                    "Non-existent rule nonexistent_rule should be reported as invalid"

                hbactest_out4 = ssh_access_rule.test(user="user2", host="client.test",
                                                    service="sshd", rule="nonexistent_rule")
                assert "nonexistent_rule" in hbactest_out4["invalid_rules"], \
                    "Non-existent rule nonexistent_rule should be reported as invalid"

                client.sssd.restart()

                assert client.auth.ssh.password("user1", "Secret123"), "user1 should be able to SSH"
                assert not client.auth.ssh.password("user2", "Secret123"), "user2 should be denied SSH"
                assert not client.auth.ssh.password("user3", "Secret123"), "user3 should be denied SSH"

                ssh_access_rule.delete()

                client.sssd.restart()

                assert not client.auth.ssh.password("user1", "Secret123"), "user1 should be denied after rule deletion"
                assert not client.auth.ssh.password("user2", "Secret123"), "user2 should be denied after rule deletion"
                assert not client.auth.ssh.password("user3", "Secret123"), "user3 should be denied after rule deletion"

        :param name: IPA HBAC rule name.
        :type name: str
        :return: New HBAC object.
        :rtype: IPAHBAC
        """
        return IPAHBAC(self, name)

    def hostgroup(self, name: str) -> IPAHostGroup:
        """
        IPA Host Group object.

        Here, we can create and manage IPA host groups, which are collections
        of hosts that can be used in HBAC rules for simplified host management.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.IPA)
            def test_ipa__validate_hbac_rule_host_group_access(client: Client, ipa: IPA):
                # Create users for testing
                users = ["user1", "user2"]
                for user in users:
                    ipa.user(user).add()

                # Create host groups
                web_group = ipa.hostgroup("webservers").add(description="Web servers group")
                db_group = ipa.hostgroup("dbservers").add(description="Database servers group")

                # Add hosts to webservers group
                web_group.add_member(host=["client.test"])

                # Disable default allow_all rule
                ipa.hbac("allow_all").disable()

                # Create HBAC rule using host group
                webservers_ssh_rule = ipa.hbac("webservers_ssh_access").create(
                    description="SSH access for webservers host group",
                    users="user1",
                    hostgroups="webservers",
                    services="sshd"
                )

                # Test access via host group
                hbactest_result = webservers_ssh_rule.test(user="user1", host="client.test", service="sshd")
                assert hbactest_result["access_granted"], "user1 should have access via host group"

                # Remove host from group and test access is denied
                web_group.remove_member(host=["client.test"])
                client.sssd.restart()

                assert not client.auth.ssh.password("user1", "Secret123"), "user1 should be denied after host removal"

        :param name: IPA host group name.
        :type name: str
        :return: New host group object.
        :rtype: IPAHostGroup
        """
        return IPAHostGroup(self, name)

    def hbacsvc(self, name: str) -> IPAHBACService:
        """
        IPA HBAC Service object.

        This method creates and returns an IPA HBAC service object, which represents
        individual services that can be used in HBAC rules to control access at the service level.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.IPA)
            def test_ipa__validate_hbac_rule_service_access(client: Client, ipa: IPA):
                # Create users for testing
                users = ["user1", "user2"]
                for user in users:
                    ipa.user(user).add()

                # Create HBAC service
                ssh_service = ipa.hbacsvc("sshd").add(description="SSH service")

                # Disable default allow_all rule
                ipa.hbac("allow_all").disable()

                # Create HBAC rule using the service
                remote_services_rule = ipa.hbac("remote_services_access").create(
                    description="Remote access via specific services",
                    users="user1",
                    hosts="client.test",
                    services="sshd"
                )

                # Test access to the sshd service
                hbactest_ssh = remote_services_rule.test(user="user1", host="client.test", service="sshd")
                assert hbactest_ssh["access_granted"], "user1 should have sshd access"

                # Test access to a service not authorized
                hbactest_http = remote_services_rule.test(user="user1", host="client.test", service="httpd")
                assert not hbactest_http["access_granted"], "user1 should be denied httpd access"

                # Remove service from the HBAC rule and test access is denied
                ipa.hbacsvc("sshd").remove_member()
                client.sssd.restart()

                assert not client.auth.ssh.password("user1", "Secret123"), "user1 denied after service removal"

        :param name: IPA HBAC service name.
        :type name: str
        :return: New HBAC service object.
        :rtype: IPAHBACService
        """
        return IPAHBACService(self, name)

    def hbacsvcgroup(self, name: str) -> IPAHBACServiceGroup:
        """
        IPA HBAC Service Group object.

        In this we can create and manage IPA HBAC service groups, which are collections
        of services that can be used in HBAC rules for simplified service management.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.IPA)
            def test_ipa__validate_hbac_rule_service_group_access(client: Client, ipa: IPA):
                # Create users for testing
                users = ["user1", "user2"]
                for user in users:
                    ipa.user(user).add()

                # Create service group and add services
                remote_svc_group = ipa.hbacsvcgroup("remote_access").add(description="Remote access services")
                remote_svc_group.add_member(hbacsvc=["sshd"])

                # Disable default allow_all rule
                ipa.hbac("allow_all").disable()

                # Create HBAC rule using service group
                remote_services_rule = ipa.hbac("remote_services_access").create(
                    description="Remote access via service groups",
                    users="user1",
                    hosts="client.test",
                    servicegroups="remote_access"
                )

                # Test access to services in the group
                hbactest_ssh = remote_services_rule.test(user="user1", host="client.test", service="sshd")
                assert hbactest_ssh["access_granted"], "user1 should have sshd access via service group"


                # Test access to service not in group
                hbactest_http = remote_services_rule.test(user="user1", host="client.test", service="httpd")
                assert not hbactest_http["access_granted"], "user1 should be denied httpd access"

                # Remove service from group and test access is denied
                remote_svc_group.remove_member(hbacsvc=["sshd"])
                client.sssd.restart()

                assert not client.auth.ssh.password("user1", "Secret123"), "user1 denied after service removal"

        :param name: IPA HBAC service group name.
        :type name: str
        :return: New HBAC service group object.
        :rtype: IPAHBACServiceGroup
        """
        return IPAHBACServiceGroup(self, name)


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
        email: str | None = None,
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
        :param email: email attribute, defaults to None
        :type email: str | None, optional
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
            "email": (self.cli.option.VALUE, email),
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
        email: str | None = None,
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
        :param email: email attribute, defaults to None
        :type email: str | None, optional
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
            "email": (self.cli.option.VALUE, email),
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

    def password_change_at_logon(self, **kwargs) -> IPAUser:
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

    def passkey_add_register(self, **kwargs) -> str:
        """wrapper for passkey_add_register methods"""
        if "virt_type" in kwargs and kwargs["virt_type"] == "vfido":
            del kwargs["virt_type"]
            return self.vfido_passkey_add_register(**kwargs)
        else:
            return self.umockdev_passkey_add_register(**kwargs)

    def umockdev_passkey_add_register(
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

    def vfido_passkey_add_register(
        self,
        *,
        client: Client,
        pin: str | int | None = None,
    ) -> str:
        """
        Register user passkey when using virtual-fido
        """

        if pin is None:
            pin = "empty"

        client.host.conn.exec(["kinit", f"{self.host.adminuser}@{self.host.realm}"], input=self.host.adminpw)

        result = client.host.conn.expect(
            f"""
            set pin "{pin}"
            set timeout 60

            spawn ipa user-add-passkey {self.name} --register
            set ID_reg $spawn_id

            if {{ ($pin ne "empty") }} {{
                expect {{
                    -i $ID_reg -re "Enter PIN:*" {{}}
                    -i $ID_reg timeout {{puts "expect result: Unexpected output"; exit 201}}
                    -i $ID_reg eof {{puts "expect result: Unexpected end of file"; exit 202}}
                }}

                puts "Entering PIN\n"
                send -i $ID_reg "{pin}\r"
            }}

            expect {{
                -i $ID_reg -re "Please touch the device.*" {{}}
                -i $ID_reg timeout {{puts "expect result: Unexpected output"; exit 203}}
                -i $ID_reg eof {{puts "expect result: Unexpected end of file"; exit 204}}
            }}

            puts "Touching device"
            spawn {test_venv_bin}/vfido_touch
            set ID_touch $spawn_id

            expect {{
                -i $ID_reg -re "Added passkey mappings.*" {{}}
                -i $ID_reg timeout {{puts "expect result: Unexpected output"; exit 205}}
                -i $ID_reg eof {{puts "expect result: Unexpected end of file"; exit 206}}
            }}

            expect -i $ID_reg eof
            expect -i $ID_touch eof
            """,
            raise_on_error=True,
        )

        return result.stdout_lines[-1].strip()

    def iduseroverride(self) -> IDUserOverride:
        """
        Add override to the IPA user.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.IPA)
            def test_example(client: Client, ipa: IPA):
                ipa.idview("newview1").add(description="This is a new view")
                ipa.idview("newview1").apply(f"{client.host.hostname}")
                ipa.user("user-1").add().iduseroverride().add_override("newview1", uid=1344567)
                client.sssd.restart()
                lookup1 = client.tools.id("user-1")
                assert lookup1.user.id == 1344567

        :return: New IDOverride object.
        :rtype: IDOverride
        """
        return IDUserOverride(self)

    def subid(self) -> IPASubID:
        """
        IPA subid management.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.IPA)
            def test_ipa__subids_configured(ipa: IPA):
                user = ipa.user("user1").add()
                user.subid().generate()
        """
        return IPASubID(self.role, self.name)


class IDUserOverride(IPAUser):
    """
    IPA ID override for users.
    """

    def __init__(self, user: IPAUser) -> None:
        """
        :param user: IPA user object.
        :type user: IPAUser
        """
        super().__init__(user.role, user.name)
        self.name = user.name

    def add_override(
        self,
        idview_name: str,
        *,
        description: str | None = None,
        login: str | None = None,
        uid: int | None = None,
        gid: int | None = None,
        gecos: str | None = None,
        home: str | None = None,
        shell: str | None = None,
        sshpubkey: str | None = None,
        certificate: str | list[str] | None = None,
        **kwargs,
    ) -> tuple[ProcessResult[ProcessError], list[str] | str | list | None]:
        """
        Add a new User ID override.

        :param idview_name: Name of IDView.
        :type idview_name: str
        :param description: Description.
        :type description: str | None, defaults to None
        :param login: Overridden User login.
        :type login: str | None, defaults to None
        :param uid: Overridden User ID number.
        :type uid: str | None, defaults to None
        :param gid: Overridden Group ID number.
        :type gid: str | None, defaults to None
        :param gecos: Overridden Gecos.
        :type gecos: str | None, defaults to None
        :param home: Overridden Home directory.
        :type home: str | None, defaults to None
        :param shell: Overridden Login shell.
        :type shell: str | None, defaults to None
        :param sshpubkey: Overridden SSH public key.
        :type sshpubkey: str | None, defaults to None
        :param certificate: Overridden Certificate.
        :type certificate: str | list[str] | None, defaults to None
        :return: ProcessResult, cert
        :rtype: tuple[ProcessResult, list[str] | str | list | None]
        """
        certs = [certificate] if isinstance(certificate, str) else certificate or []

        attrs: CLIBuilderArgs = {
            "desc": (self.cli.option.VALUE, description),
            "login": (self.cli.option.VALUE, login),
            "uid": (self.cli.option.VALUE, uid),
            "gidnumber": (self.cli.option.VALUE, gid),
            "gecos": (self.cli.option.VALUE, gecos),
            "homedir": (self.cli.option.VALUE, home),
            "shell": (self.cli.option.VALUE, shell),
            "sshpubkey": (self.cli.option.VALUE, sshpubkey),
        }

        if kwargs:
            unexpected_keys = ", ".join(kwargs.keys())
            raise TypeError(f"Unexpected keyword arguments: {unexpected_keys}")

        # Create the ID override first
        result = self.role.host.conn.exec(
            ["ipa", "idoverrideuser-add", idview_name, self.name] + to_list_without_none(self.cli.args(attrs)),
            raise_on_error=False,
        )

        # Add certificates if any exist
        if certs:
            cert_cmd = ["ipa", "idoverrideuser-add-cert", idview_name, self.name]
            for cert in certs:
                self.role.host.conn.exec(cert_cmd + [f"--certificate={cert}"])

        return (result, certs)

    def modify_override(
        self,
        idview_name: str,
        *,
        description: str | None = None,
        login: str | None = None,
        uid: int | None = None,
        gid: int | None = None,
        gecos: str | None = None,
        home: str | None = None,
        shell: str | None = None,
        sshpubkey: str | None = None,
        certificate: str | list[str] | None = None,
    ) -> IDUserOverride:
        """
        Modify an User ID override.

        :param idview_name: Name of IDView.
        :type idview_name: str
        :param description: Description.
        :type description: str | None, defaults to None
        :param login: Overridden User login.
        :type login: str | None, defaults to None
        :param uid: Overridden User ID number.
        :type uid: str | None, defaults to None
        :param gid: Overridden Group ID.
        :type gid: str | None, defaults to None
        :param gecos: Overridden Gecos.
        :type gecos: str | None, defaults to None
        :param home: Overridden Home directory.
        :type home: str | None, defaults to None
        :param shell: Overridden Login shell.
        :type shell: str | None, defaults to None
        :param sshpubkey: Overridden SSH public key.
        :type sshpubkey: str | None, defaults to None
        :param certificate: Overridden Certificate.
        :type certificate: str | list[str] | None, defaults to None
        :return: self.
        :rtype: IDUserOverride
        """

        attrs: CLIBuilderArgs = {
            "desc": (self.cli.option.VALUE, description),
            "login": (self.cli.option.VALUE, login),
            "uid": (self.cli.option.VALUE, uid),
            "gidnumber": (self.cli.option.VALUE, gid),
            "gecos": (self.cli.option.VALUE, gecos),
            "homedir": (self.cli.option.VALUE, home),
            "shell": (self.cli.option.VALUE, shell),
            "sshpubkey": (self.cli.option.VALUE, sshpubkey),
            "certificate": (self.cli.option.VALUE, certificate),
        }

        attrs = CLIBuilderArgs(attrs)
        self.role.host.conn.exec(
            ["ipa", "idoverrideuser-mod", idview_name, self.name] + to_list_without_none(self.cli.args(attrs))
        )

        return self

    def delete_override(self, idview_name: str) -> ProcessResult[ProcessError]:
        """
        Delete an User ID override.

        :param idview_name: Name of IDView.
        :type idview_name: str
        :return: ProcessResult[ProcessError]
        :rtype: [ProcessError]
        """

        result = self.role.host.conn.exec(["ipa", "idoverrideuser-del", idview_name, self.name])
        return result

    def remove_cert(self, idview_name: str, certificate: str | list[str]) -> IDUserOverride:
        """
        Remove one or more certificates to the idoverrideuser entry.

        :param idview_name: Name of IDView.
        :type idview_name: str
        :param certificate: Overridden Certificate.
        :type certificate: str | list[str]
        :return: self.
        :rtype: IDOverride
        """
        self.role.host.conn.exec(
            ["ipa", "idoverrideuser-remove-cert", idview_name, self.name, f"--certificate={certificate}"]
        )
        return self

    def find_override(self, idview_name: str) -> dict[str, list[str]]:
        """
        Search for an User ID override.

        :param idview_name: Name of IDView.
        :type idview_name: str
        :return: Dict of IDOverride user information.
        :rtype: dict[str, list[str]]
        """

        cmd = self.role.host.conn.exec(["ipa", "idoverrideuser-find", idview_name, "--anchor", self.name, "--raw"])
        cleaned_data = [dedent(line).strip() for line in cmd.stdout_lines if not set(line) == {"-"} and line.strip()]

        lines = [line for line in cleaned_data if ":" in line]

        return attrs_parse(lines)

    def show_override(self, idview_name: str) -> dict[str, list[str]]:
        """
        Display information about an User ID override.

        :param idview_name: Name of IDView.
        :type idview_name: str
        :return: dict of IDOverride user information.
        :rtype: dict[str, list[str]]
        """
        cmd = self.role.host.conn.exec(["ipa", "idoverrideuser-show", idview_name, self.name, "--raw"])

        lines = [line.strip() for line in cmd.stdout_lines if ":" in line]

        return attrs_parse(lines)


class IPASubID(BaseObject[IPAHost, IPA]):
    """
    IPA sub id management.
    """

    def __init__(self, role: IPA, user: str) -> None:
        """
        :param user: Username.
        :type user: str
        """
        super().__init__(role)

        self.name = user
        """ Owner name."""

        self.uid_start: int | None = None
        """ SubUID range start"""

        self.uid_size: int | None = None
        """ SubUID range size."""

        self.gid_start: int | None = None
        """ SubGID range start."""

        self.gid_size: int | None = None
        """ SubGID range size."""

    def generate(self) -> IPASubID:
        """
        Generate subordinate id.
        """
        self.host.conn.run(f"ipa subid-generate --owner {self.name}")
        result = self.host.conn.run(f"ipa subid-find --owner {self.name}").stdout_lines
        result = [item for item in result if ":" in item]
        subids = delimiter_parse(result)

        self.uid_start = int(subids["SubUID range start"]) if subids.get("SubUID range start") else None
        self.uid_size = int(subids["SubUID range size"]) if subids.get("SubUID range size") else None
        self.gid_start = int(subids["SubGID range start"]) if subids.get("SubGID range start") else None
        self.gid_size = int(subids["SubGID range size"]) if subids.get("SubGID range size") else None

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

    def idgroupoverride(self) -> IDGroupOverride:
        """
        Add override to the IPA Group.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.IPA)
            def test_example(client: Client, ipa: IPA):
                ipa.idview("newview1").add(description="This is a new view")
                ipa.idview("newview1").apply(hosts=f"{client.host.hostname}")
                ipa.group("group-1").add().idgroupoverride().add_override("newview1", gid=1344567)
                client.sssd.restart()
                g_lookup = client.tools.getent.group("group-1")
                assert g_lookup.gid == 1344567

        :return: New IDOverride object.
        :rtype: IDOverride
        """
        return IDGroupOverride(self)


class IDGroupOverride(IPAGroup):
    """
    IPA group ID override.
    """

    def __init__(self, group: IPAGroup) -> None:
        """
        :param user: IPA group object.
        :type user: IPAGroup
        """
        super().__init__(group.role, group.name)
        self.name = group.name

    def add_override(
        self,
        idview_name: str,
        *,
        description: str | None = None,
        name: str | None = None,
        gid: int | None = None,
    ) -> IDGroupOverride:
        """
        Add a new Group ID override.

        :param idview_name: Name of IDView.
        :type idview_name: str
        :param description: Description.
        :type description: str | None, defaults to None
        :param name: Overridden group name.
        :type name: str | None, defaults to None
        :param gid: Overridden Group ID Number.
        :type gid: str | None, defaults to None
        :return: self.
        :rtype: IDGroupOverride
        """

        attrs: CLIBuilderArgs = {
            "desc": (self.cli.option.VALUE, description),
            "group-name": (self.cli.option.VALUE, name),
            "gid": (self.cli.option.VALUE, gid),
        }

        self.role.host.conn.exec(["ipa", "idoverridegroup-add", idview_name, self.name] + list(self.cli.args(attrs)))
        return self

    def modify_override(
        self,
        idview_name: str,
        *,
        description: str | None = None,
        name: str | None = None,
        gid: int | None = None,
    ) -> IDGroupOverride:
        """
        Modify an Group ID override.

        :param idview_name: Name of IDView.
        :type idview_name: str
        :param description: Description.
        :type description: str | None, defaults to None
        :param name: Overridden group name.
        :type name: str | None, defaults to None
        :param gid: Overridden Group ID Number.
        :type gid: str | None, defaults to None
        :return: self.
        :rtype: IDGroupOverride
        """

        attrs: CLIBuilderArgs = {
            "desc": (self.cli.option.VALUE, description),
            "group-name": (self.cli.option.VALUE, name),
            "gid": (self.cli.option.VALUE, gid),
        }
        attrs = CLIBuilderArgs(attrs)
        self.role.host.conn.exec(["ipa", "idoverridegroup-mod", idview_name, self.name] + list(self.cli.args(attrs)))

        return self

    def delete_override(self, idview_name: str) -> ProcessResult[ProcessError]:
        """
        Delete an Group ID override.
        :param idview_name: Name of IDView.
        :type idview_name: str
        :return: ProcessResult[ProcessError]
        :rtype: [ProcessError]
        """
        result = self.role.host.conn.exec(["ipa", "idoverridegroup-del", idview_name, self.name])
        return result

    def find_override(self, idview_name: str) -> dict[str, list[str]]:
        """
        Search for an Group ID override.

        :param idview_name: Name of IDView.
        :type: idview_name: str
        :return: dict of Group ID override information.
        :rtype: dict[str, list[str]]
        """
        cmd = self.role.host.conn.exec(["ipa", "idoverridegroup-find", idview_name, "--anchor", self.name, "--raw"])
        cleaned_data = [dedent(line).strip() for line in cmd.stdout_lines if not set(line) == {"-"} and line.strip()]

        lines = [line for line in cleaned_data if ":" in line]

        return attrs_parse(lines)

    def show_override(self, idview_name: str) -> dict[str, list[str]]:
        """
        Display information about an Group ID override.

        :param idview_name: Name of IDView.
        :type idview_name: str
        :return: dict of Group ID Override information.
        :rtype: dict[str, list[str]]
        """
        cmd = self.role.host.conn.exec(["ipa", "idoverridegroup-show", idview_name, self.name, "--raw"])

        lines = [line.strip() for line in cmd.stdout_lines if ":" in line]

        return attrs_parse(lines)


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
        attrs: CLIBuilderArgs

        if enable:
            attrs = {
                "dictcheck": (self.cli.option.VALUE, "True"),
                "usercheck": (self.cli.option.VALUE, "True"),
                "minlength": (self.cli.option.VALUE, 8),
                "minclasses": (self.cli.option.VALUE, 4),
                "priority": (self.cli.option.VALUE, 1),
            }
        else:
            attrs = {
                "dictcheck": (self.cli.option.VALUE, "False"),
                "usercheck": (self.cli.option.VALUE, "False"),
                "minlength": (self.cli.option.VALUE, 0),
                "minclasses": (self.cli.option.VALUE, 0),
                "priority": (self.cli.option.VALUE, 1),
            }

        if self.get() is None:
            self._add(attrs)
        else:
            self._modify(attrs)

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


class IPAIDView(IPAObject):
    """
    IPA ID view management.
    """

    def __init__(self, role: IPA, name: str) -> None:
        """
        :param role: IPA role.
        :type role: IPA
        :param name: Name of IPA ID view.
        :type name: str
        """
        super().__init__(role, name, command_group="idview")

    def add(
        self,
        *,
        description: str | None = None,
    ) -> IPAIDView:
        """
        Add a new ID View.

        :param description: Description of ID View.
        :type description: str | None, default to None
        :return: Self.
        :rtype: IPAIDView
        """
        attrs: CLIBuilderArgs = {
            "desc": (self.cli.option.VALUE, description),
        }

        self._add(attrs)
        return self

    def modify(
        self,
        *,
        description: str | None = None,
        rename: str | None = None,
    ) -> IPAIDView:
        """
        Modify existing IPA ID view.

        :param description: Description, defaults to None
        :type description: str | None, optional
        :param rename: Name of IPA ID view, defaults to None
        :type rename: str | None, optional
        :return: Self.
        :rtype: IPAIDView
        """
        attrs: CLIBuilderArgs = {
            "desc": (self.cli.option.VALUE, description),
            "rename": (self.cli.option.VALUE, rename),
        }

        self._modify(attrs)
        return self

    def apply(self, *, hosts: list[str] | str | None = None, hostgroups: str | None = None) -> ProcessResult:
        """
        Applies ID View to specified hosts or current members of specified
        hostgroups.

        :description: If any other ID View is applied to the host, it is overridden.
        :param hosts: Hosts to apply the ID View to, defaults to None
        :type hosts: list[str] | str | None
        :param hostgroups: Hostgroups to apply the ID View to, defaults to None
        :type hostgroups: str | None
        :return: SSH Process result.
        :rtype: ProcessResult
        """
        if not hosts and not hostgroups:
            raise ValueError("Either 'hosts' or 'hostgroups' must be provided.")

        attrs: CLIBuilderArgs = {}
        if hosts:
            attrs["hosts"] = (self.cli.option.VALUE, hosts)
        if hostgroups:
            attrs["hostgroups"] = (self.cli.option.VALUE, hostgroups)

        result = self._exec("apply", self.cli.args(attrs), raise_on_error=False)
        return result

    def delete(self) -> None:
        """
        Delete existing IPA ID view.
        """
        self._exec("del", ["--continue"])


class IPADNSServer(BaseObject[IPAHost, IPA]):
    """
    DNS management utilities.
    """

    def __init__(self, role: IPA):
        """
        :param role: IPA host object.
        :type role: ADHost
        """
        super().__init__(role)

        self.domain: str = role.domain
        """Domain name."""

        self.server: str = role.server
        """Server name."""

    def zone(self, name: str) -> IPADNSZone:
        """
        Get IPADNSZone object.

        :param name: Zone name.
        :type name: str
        :return: IPADNSZone object.
        :rtype: IPADNSZone
        """
        return IPADNSZone(self.role, name)

    def get_forwarders(self) -> list[str] | None:
        """
        Get DNS global forwarders.

        :return: DNS global forwarders.:
        :rtype: list[str] | None
        """
        result = self.host.conn.run("ipa dnsconfig-show --raw").stdout_lines
        result = [line.strip() for line in result if line.startswith(" ")]
        if result is not None and isinstance(result, list):
            forwarders = attrs_parse(result, ["idnsforwarders"])
            if forwarders is not None and isinstance(forwarders, dict):
                return forwarders.get("idnsforwarders")
        return None

    def add_forwarder(self, ip_address: str) -> IPADNSServer:
        """
        Add a DNS server forwarder.

        :param ip_address: IP address.
        :type ip_address: str
        :return:  Self.
        :rtype: IPADNSServer
        """
        self.host.conn.run(f"ipa dnsconfig-mod --forwarder {ip_address}")
        return self

    def remove_forwarder(self, ip_address: str) -> None:
        """
        Remove DNS server forwarders.

        :param ip_address: IP address.
        :type ip_address: str
        """
        forwarders = self.get_forwarders()
        if forwarders and ip_address in forwarders:
            forwarders = [fwd for fwd in forwarders if fwd != ip_address]
            self.host.conn.run(f"ipa dnsconfig-mod --forwarder \"{' '.join(forwarders)}\"")

    def clear_forwarders(self) -> None:
        """
        Clear all DNS server forwarders.

        IPA has no global forwarders by default.
        """
        forwarders = self.get_forwarders()

        if isinstance(forwarders, list) and not None:
            for forwarder in forwarders:
                self.remove_forwarder(forwarder)

    def list_zones(self) -> list[str] | None:
        """
        List zones.
        :return: List of zones.
        :rtype: dict[str, list[str]] | None"
        """
        result = self.host.conn.run("ipa dnszone-find --raw").stdout_lines
        result = [line.strip() for line in result if line.startswith(" ")]
        if result is None:
            raise ValueError("No zones found.")
        else:
            zones = [line.rstrip(".") for line in result]
            parsed_result = attrs_parse(zones, ["idnsname"])
            if isinstance(parsed_result, dict):
                if isinstance(parsed_result["idnsname"], list):
                    return parsed_result.get("idnsname")
            else:
                return None


class IPADNSZone(IPADNSServer):
    """
    DNS zone management.
    """

    def __init__(self, role: IPA, name: str):
        """
        :param role: IPA host object.
        :type role: IPAHost
        :param name: DNS zone name.
        :type name: str
        """
        super().__init__(role)

        self.zone_name: str = name
        """Zone name."""

    def create(self) -> IPADNSZone:
        """
        Create new zone.

        :return: IPADNSServer object.
        :rtype: IPADNSServer
        """
        self.host.conn.run(f"ipa dnszone-add {self.zone_name} --dynamic-update=TRUE --skip-overlap-check")
        return self

    def delete(self) -> None:
        """
        Delete zone.
        """
        self.host.conn.run(f"dnszone-del {self.zone_name}")

    def add_record(self, name: str, data: str | int) -> IPADNSZone:
        """
        Add DNS record.

        If ``data`` is a str, a forward record will be added.
        If an integer a reverse record will be added.

        :param name: Record name.
        :type name: str
        :param data: Record data.
        :type data: str | int
        :return: IPADNSZone object.
        :rtype: IPADNSZone
        """
        args = ""

        if isinstance(data, int):
            args = f"{str(data)} --ptr-rec={name}."
        elif isinstance(data, str) and ip_version(data) == 4:
            args = f"{name} --a-rec={data}"
        elif isinstance(data, str) and ip_version(data) == 6:
            args = f"{name} --aaaa-rec={data}"

        self.host.conn.run(f"ipa dnsrecord-add {self.zone_name} {args}")

        return self

    def delete_record(self, name: str) -> None:
        """
        Delete DNS record.

        :param name: Name of the record.
        :type name: str
        """
        self.host.conn.run(f"ipa dnsrecord-del {self.zone_name} {name}")

    def print(self) -> str:
        """
        Prints all dns records in a zone as text.

        :return: Print zone data.
        :rtype: str
        """
        result = self.host.conn.run(f"ipa dnszone-show {self.zone_name}").stdout
        return result


class IPACertificateAuthority:
    """
    Provides helper methods for FreeIPA Certificate Authority operations.

    This class allows requesting, revoking, placing/removing certificate holds,
    and retrieving certificate information via the ipa CLI.

    .. code-block:: python
       :caption: Example usage

       import pytest
       from pytest_mh import Client, IPA, KnownTopology

       @pytest.mark.topology(KnownTopology.IPA)
       def test_smartcard___su_as_ipa_user(client: Client, ipa: IPA):
           # Add user in IPA
           ipa.user('ipacertuser1').add()

           # Request certificate from IPA CA
           cert, key, _ = ipa.ca.request('ipacertuser1')

           # Read contents of certificate and key
           cert_content = ipa.fs.read(cert)
           key_content = ipa.fs.read(key)

           # Write to client filesystem
           client.fs.write('/opt/test_ca/ipacertuser1.crt', cert_content)
           client.fs.write('/opt/test_ca/ipacertuser1.key', key_content)

           # Initialize smartcard and add cert/key
           client.smartcard.initialize_card()
           client.smartcard.add_key('/opt/test_ca/ipacertuser1.key')
           client.smartcard.add_cert('/opt/test_ca/ipacertuser1.crt')

           # Enable smartcard authentication via authselect
           client.authselect.select("sssd", ["with-smartcard"])
           client.sssd.pam["pam_cert_auth"] = "True"
           client.sssd.start()
           client.svc.restart("virt_cacard.service")

           # Attempt to su and check for PIN prompt
           result = client.host.conn.run(
               "su - ipacertuser1 -c 'su - ipacertuser1 -c whoami'", input="123456"
           )
           assert "PIN" in result.stderr, "String 'PIN' was not found in stderr!"
           assert "ipacertuser1" in result.stdout, "'ipacertuser1' not found in 'whoami' output!"
    """

    def __init__(self, host: MultihostHost, fs: LinuxFileSystem) -> None:
        """
        Initialize the IPA Certificate Authority helper.

        :param host: Remote test host.
        :type host: MultihostHost
        :param fs: Filesystem helper for remote file operations.
        :type fs: LinuxFileSystem
        """
        self.host = host
        self.fs = fs
        self.cli: CLIBuilder = host.cli
        self.temp_dir = f"/tmp/ipa_test_certs_{os.getpid()}_{uuid.uuid4().hex}"
        self.fs.mkdir_p(self.temp_dir, mode="700")
        self.fs.backup(self.temp_dir)

    def request(
        self,
        principal: str,
        subject: Optional[str] = None,
        add_service: bool = False,
        key_size: int = 2048,
    ) -> tuple[str, str, str]:
        """
        Request a certificate from the IPA CA.

        :param principal: The principal (user or service) name.
        :type principal: str
        :param subject: Optional OpenSSL subject (e.g., /CN=example). If omitted, derived from principal.
        :type subject: str | None
        :param add_service: Whether to add the principal as an IPA service.
        :type add_service: bool
        :param key_size: RSA key size in bits.
        :type key_size: int
        :returns: A tuple of (certificate_path, key_path, csr_path).
        :rtype: tuple[str, str, str]
        :raises ValueError: If subject cannot be derived from principal.
        :raises RuntimeError: If CSR generation fails.
        """
        base = re.sub(r"[^a-zA-Z0-9.\_-]", "_", principal)
        key_path = os.path.join(self.temp_dir, f"{base}.key")
        csr_path = os.path.join(self.temp_dir, f"{base}.csr")
        cert_path = os.path.join(self.temp_dir, f"{base}.crt")

        if subject is None:
            hostname = principal.split("@")[0].split("/")[-1] if "@" in principal else principal.split("/")[-1]
            if not hostname:
                raise ValueError(f"Cannot derive subject from principal '{principal}'")
            subject = f"/CN={hostname}"

        self._generate_csr(key_path, csr_path, subject, key_size)

        if add_service:
            self.host.conn.run(f"ipa service-add {shlex.quote(principal)}", raise_on_error=False)

        args: CLIBuilderArgs = {
            "principal": (self.cli.option.VALUE, principal),
            "certificate-out": (self.cli.option.VALUE, cert_path),
        }

        self.host.conn.run(
            self.cli.command(f"ipa cert-request {shlex.quote(csr_path)}", args),
            raise_on_error=True,
        )

        return cert_path, key_path, csr_path

    def revoke(self, cert_path: str, reason: RevocationReason = "unspecified") -> None:
        """
        Revoke a certificate in IPA.

        :param cert_path: Path to the certificate file.
        :type cert_path: str
        :param reason: Reason for revocation.
        :type reason: RevocationReason
        :raises RuntimeError: If revocation fails.
        """
        serial = self._get_cert_serial(cert_path)
        reason_code = self._revocation_reason_to_code(reason)
        args: CLIBuilderArgs = {
            "serial": (self.cli.option.VALUE, serial),
            "revocation-reason": (self.cli.option.VALUE, str(reason_code)),
        }
        result = self.host.conn.run(self.cli.command("ipa cert-revoke", args), raise_on_error=False)
        if result.rc != 0:
            raise RuntimeError(f"IPA cert-revoke failed: {result.stderr}!")

    def revoke_hold(self, cert_path: str) -> None:
        """
        Place a certificate on hold.

        :param cert_path: Path to the certificate file.
        :type cert_path: str
        """
        self.revoke(cert_path, reason="certificate_hold")

    def revoke_hold_remove(self, cert_path: str) -> None:
        """
        Remove hold from a certificate.

        :param cert_path: Path to the certificate file.
        :type cert_path: str
        :raises RuntimeError: If hold removal fails.
        """
        serial = self._get_cert_serial(cert_path)
        args: CLIBuilderArgs = {"serial": (self.cli.option.VALUE, serial)}
        result = self.host.conn.run(self.cli.command("ipa cert-remove-hold", args), raise_on_error=False)
        if result.rc != 0:
            raise RuntimeError(f"ipa cert-remove-hold failed: {result.stderr}!")

    def get(self, cert_path: str) -> dict[str, list[str]]:
        """
        Retrieve certificate details from IPA.
        :param cert_path: Path to the certificate file.
        :type cert_path: str
        :returns: A dictionary of certificate attributes.
        :rtype: dict[str, list[str]]
        :raises ValueError: If the certificate is not found in IPA.
        """
        serial = self._get_cert_serial(cert_path)
        args: CLIBuilderArgs = {
            "serial": (self.cli.option.VALUE, serial),
            "all": (self.cli.option.SWITCH, True),
        }
        result = self.host.conn.run(self.cli.command("ipa cert-show", args), raise_on_error=False)
        if result.rc != 0:
            raise ValueError(f"Certificate with serial '{serial}' not found in IPA: {result.stderr}!")
        return self._parse_cert_info(result.stdout)

    def _generate_csr(self, key_path: str, csr_path: str, subject: str, key_size: int = 2048) -> None:
        """
        Generate a CSR and key using OpenSSL.

        :param key_path: Path to save the private key.
        :type key_path: str
        :param csr_path: Path to save the CSR file.
        :type csr_path: str
        :param subject: Subject for the CSR (e.g., /CN=example).
        :type subject: str
        :param key_size: RSA key size in bits.
        :type key_size: int
        :raises RuntimeError: If CSR generation fails.
        """
        args: CLIBuilderArgs = {
            "newkey": (self.cli.option.VALUE, f"rsa:{key_size}"),
            "nodes": (self.cli.option.SWITCH, True),
            "keyout": (self.cli.option.VALUE, key_path),
            "out": (self.cli.option.VALUE, csr_path),
            "subj": (self.cli.option.VALUE, subject),
        }
        result = self.host.conn.run(self.cli.command("openssl req", args), raise_on_error=False)
        if result.rc != 0:
            raise RuntimeError(f"OpenSSL CSR generation failed: {result.stderr}!")

    def _get_cert_serial(self, cert_path: str) -> str:
        """
        Extract the certificate serial number using OpenSSL.

        :param cert_path: Path to the certificate file.
        :type cert_path: str
        :returns: The certificate serial number as a lowercase hex string.
        :rtype: str
        :raises RuntimeError: If serial extraction fails.
        """
        cmd = ["openssl", "x509", "-in", cert_path, "-noout", "-serial"]
        cmdline = " ".join(shlex.quote(p) for p in cmd)
        result = self.host.conn.run(cmdline, raise_on_error=False)
        if result.rc != 0:
            raise RuntimeError(f"Failed to get serial from certificate: {result.stderr}!")
        out = (result.stdout or "").strip()
        if "=" in out:
            return out.split("=", 1)[1].lower()
        return out.lower()

    def _revocation_reason_to_code(self, reason: RevocationReason) -> int:
        """
        Map a revocation reason string to its corresponding numeric code.

        :param reason: Revocation reason string.
        :type reason: RevocationReason
        :returns: Numeric reason code.
        :rtype: int
        """
        reason_map = {
            "unspecified": 0,
            "key_compromise": 1,
            "ca_compromise": 2,
            "affiliation_changed": 3,
            "superseded": 4,
            "cessation_of_operation": 5,
            "certificate_hold": 6,
            "remove_from_crl": 8,
            "privilege_withdrawn": 9,
            "aa_compromise": 10,
        }
        return reason_map[reason]

    def _parse_cert_info(self, output: str) -> dict[str, list[str]]:
        """
        Parse ipa cert-show output into a dictionary.

        :param output: Raw command output from ipa cert-show.
        :type output: str
        :returns: Dictionary of certificate attributes with list of values.
        :rtype: Dict[str, list[str]]
        """
        lines = [line.strip() for line in (output or "").splitlines() if line.strip()]

        return attrs_parse(lines)


class IPAHostGroup(IPAObject):
    """
    IPA host group management.
    """

    def __init__(self, role: IPA, name: str) -> None:
        """
        Initialize IPAHostGroup.

        :param role: IPA role object.
        :type role: IPA
        :param name: Host group name.
        :type name: str
        """
        super().__init__(role, name, command_group="hostgroup")

    def add(
        self,
        description: str | None = None,
    ) -> IPAHostGroup:
        """
        Create new IPA host group.

        :param description: Description, defaults to None.
        :type description: str | None, optional
        :return: Self.
        :rtype: IPAHostGroup
        """
        attrs: CLIBuilderArgs = {}
        if description is not None:
            attrs["desc"] = (self.cli.option.VALUE, description)
        self._add(attrs)
        return self

    def modify(
        self,
        description: str | None = None,
    ) -> IPAHostGroup:
        """
        Modify existing IPA host group.

        :param description: Description, defaults to None
        :type description: str | None, optional
        :return: Self.
        :rtype: IPAHostGroup
        """
        attrs: CLIBuilderArgs = {}
        if description is not None:
            attrs["desc"] = (self.cli.option.VALUE, description)
        self._modify(attrs)
        return self

    def delete(self) -> None:
        """
        Delete the IPA host group.
        """
        cmd = ["ipa", f"{self.command_group}-del", self.name]
        self.role.host.conn.exec(cmd)

    def show(self, attrs: list[str] | None = None) -> dict[str, list[str]] | None:
        """
        Show detailed info of the host group or selected attributes.

        :param attrs: List of attributes to show, None shows all, defaults to None.
        :type: list[str] | None, optional
        :return: Dictionary of requested host group attributes or None if not found.
        :rtype: dict[str, list[str]]
        """
        cmd = ["ipa", f"{self.command_group}-show", self.name, "--raw"]
        result = self.role.host.conn.exec(cmd)
        lines = result.stdout.splitlines()
        parsed_attrs = attrs_parse(lines)
        if parsed_attrs is None:
            return None
        if attrs is None:
            return parsed_attrs
        else:
            return {attr: get_attr(parsed_attrs, attr) for attr in attrs}

    @classmethod
    def search(cls, role: IPA, criteria: str, all: bool = False) -> list[str]:
        """
        Search for host groups matching criteria.

        :param role: IPA role object.
        :type role: IPA
        :param criteria: Search filter string.
        :type criteria: str
        :param all: Prints all attributes, default is False.
        :type all: bool
        :return: List of matching HBAC host group names.
        :rtype: list[str]
        """
        return IPA.ipa_search(role, "hostgroup-find", criteria, all=all)

    def add_member(
        self,
        host: list[str] | str | None = None,
        hostgroup: list[str] | str | None = None,
    ) -> IPAHostGroup:
        """
        Add host group members.

        :param host: Host(s) to add as member(s), defaults to None.
        :type host: list[str] | str | None, optional
        :param hostgroup: Host group(s) to add as member(s), defaults to None.
        :type hostgroup: list[str] | str | None, optional
        :return: Self.
        :rtype: IPAHostGroup
        """
        cmd = ["ipa", f"{self.command_group}-add-member", self.name]
        if host:
            hosts_list = [host] if isinstance(host, str) else host
            cmd.append(f"--hosts={','.join(hosts_list)}")
        if hostgroup:
            hostgroups_list = [hostgroup] if isinstance(hostgroup, str) else hostgroup
            cmd.append(f"--hostgroups={','.join(hostgroups_list)}")
        if host or hostgroup:
            self.role.host.conn.exec(cmd)
        return self

    def remove_member(
        self,
        host: list[str] | str | None = None,
        hostgroup: list[str] | str | None = None,
    ) -> IPAHostGroup:
        """
        Remove host group members.

        :param host: Host(s) to remove as member(s), defaults to None.
        :type host: list[str] | str | None, optional
        :param hostgroup: Host group(s) to remove as member(s), defaults to None.
        :type hostgroup: list[str] | str | None, optional
        :return: Self.
        :rtype: IPAHostGroup
        """
        cmd = ["ipa", f"{self.command_group}-remove-member", self.name]
        if host:
            hosts_list = [host] if isinstance(host, str) else host
            cmd.append(f"--hosts={','.join(hosts_list)}")
        if hostgroup:
            hostgroups_list = [hostgroup] if isinstance(hostgroup, str) else hostgroup
            cmd.append(f"--hostgroups={','.join(hostgroups_list)}")
        if host or hostgroup:
            self.role.host.conn.exec(cmd)
        return self

    def add_member_manager(
        self,
        host: list[str] | str | None = None,
        hostgroup: list[str] | str | None = None,
    ) -> IPAHostGroup:
        """
        Add host group member managers.

        :param host: Host(s) to add as member manager(s), defaults to None.
        :type host: list[str] | str | None, optional
        :param hostgroup: Host group(s) to add as member manager(s), defaults to None.
        :type hostgroup: list[str] | str | None, optional
        :return: Self.
        :rtype: IPAHostGroup
        """
        cmd = ["ipa", f"{self.command_group}-add-member-manager", self.name]
        if host:
            hosts_list = [host] if isinstance(host, str) else host
            cmd.append(f"--hosts={','.join(hosts_list)}")
        if hostgroup:
            hostgroups_list = [hostgroup] if isinstance(hostgroup, str) else hostgroup
            cmd.append(f"--hostgroups={','.join(hostgroups_list)}")
        if host or hostgroup:
            self.role.host.conn.exec(cmd)
        return self

    def remove_member_manager(
        self,
        host: list[str] | str | None = None,
        hostgroup: list[str] | str | None = None,
    ) -> IPAHostGroup:
        """
        Remove host group member managers.

        :param host: Host(s) to remove as member manager(s), defaults to None.
        :type host: list[str] | str | None, optional
        :param hostgroup: Host group(s) to remove as member manager(s), defaults to None.
        :type hostgroup: list[str] | str | None, optional
        :return: Self.
        :rtype: IPAHostGroup
        """
        cmd = ["ipa", f"{self.command_group}-remove-member-manager", self.name]
        if host:
            hosts_list = [host] if isinstance(host, str) else host
            cmd.append(f"--hosts={','.join(hosts_list)}")
        if hostgroup:
            hostgroups_list = [hostgroup] if isinstance(hostgroup, str) else hostgroup
            cmd.append(f"--hostgroups={','.join(hostgroups_list)}")
        if host or hostgroup:
            self.role.host.conn.exec(cmd)
        return self


class IPAHBACService(IPAObject):
    """
    IPA HBAC service management.
    """

    def __init__(self, role: IPA, name: str) -> None:
        """
        :param role: IPA role object.
        :type role: IPA
        :param name: HBAC service name.
        :type name: str
        """
        super().__init__(role, name, command_group="hbacsvc")

    def add(
        self,
        *,
        description: str | None = None,
    ) -> IPAHBACService:
        """
        Create new IPA HBAC service.

        :param description: Description, defaults to None
        :type description: str | None, optional
        :return: Self.
        :rtype: IPAHBACService
        """
        attrs: CLIBuilderArgs = {}
        if description is not None:
            attrs["desc"] = (self.cli.option.VALUE, description)
        self._add(attrs)
        return self

    def modify(
        self,
        *,
        description: str | None = None,
    ) -> IPAHBACService:
        """
        Modify existing IPA HBAC service.

        :param description: Description, defaults to None
        :type description: str | None, optional
        :return: Self.
        :rtype: IPAHBACService
        """
        attrs: CLIBuilderArgs = {}
        if description is not None:
            attrs["desc"] = (self.cli.option.VALUE, description)
        self._modify(attrs)
        return self

    def delete(self) -> None:
        """
        Delete the IPA HBAC service.
        """
        self._exec("del")

    def show(self, attrs: list[str]) -> dict[str, list[str]] | None:
        """
        Show detailed info of the HBAC service.

        :param attrs: Returned attributes.
        :type attrs: list[str]
        :return: Service attributes, None if not found.
        :rtype: dict[str, list[str]] | None
        """
        return self.get(attrs)

    @classmethod
    def search(cls, role: IPA, criteria: str, all: bool = False) -> list[str]:
        """
        Search for HBAC services matching criteria.

        :param role: IPA role object.
        :type role: IPA
        :param criteria: Search filter string.
        :type criteria: str
        :param all: Prints all attributes, default is False.
        :type all: bool
        :return: List of matching HBAC host group names.
        :rtype: list[str]
        """
        return IPA.ipa_search(role, "hbacsvc-find", criteria, all=all)


class IPAHBACServiceGroup(IPAObject):
    """
    IPA HBAC service group management.
    """

    def __init__(self, role: IPA, name: str) -> None:
        """
        :param role: IPA role object.
        :type role: IPA
        :param name: HBAC service group name.
        :type name: str
        """
        super().__init__(role, name, command_group="hbacsvcgroup")

    def add(
        self,
        *,
        description: str | None = None,
    ) -> IPAHBACServiceGroup:
        """
        Create new IPA HBAC service group.

        :param description: Description, defaults to None
        :type description: str | None, optional
        :return: Self.
        :rtype: IPAHBACServiceGroup
        """
        attrs: CLIBuilderArgs = {
            "desc": (self.cli.option.VALUE, description),
        }

        self._add(attrs)
        return self

    def modify(
        self,
        *,
        description: str | None = None,
    ) -> IPAHBACServiceGroup:
        """
        Modify existing IPA HBAC service group.

        :param description: Description, defaults to None
        :type description: str | None, optional
        :return: Self.
        :rtype: IPAHBACServiceGroup
        """
        attrs: CLIBuilderArgs = {
            "desc": (self.cli.option.VALUE, description),
        }

        self._modify(attrs)
        return self

    def add_member(
        self,
        *,
        hbacsvc: list[str] | str | None = None,
        hbacsvcgroup: list[str] | str | None = None,
    ) -> IPAHBACServiceGroup:
        """
        Add HBAC service group members.

        :param hbacsvc: HBAC service(s) to add as member(s).
        :type hbacsvc: list[str] | str | None, optional
        :param hbacsvcgroup: HBAC service group(s) to add as member(s).
        :type hbacsvcgroup: list[str] | str | None, optional
        :return: Self.
        :rtype: IPAHBACServiceGroup
        """
        cmd = ["ipa", f"{self.command_group}-add-member", self.name]

        if hbacsvc:
            services_list = [hbacsvc] if isinstance(hbacsvc, str) else hbacsvc
            for service in services_list:
                cmd.append(f"--hbacsvcs={service}")

        if hbacsvcgroup:
            servicegroups_list = [hbacsvcgroup] if isinstance(hbacsvcgroup, str) else hbacsvcgroup
            for servicegroup in servicegroups_list:
                cmd.append(f"--hbacsvcgroups={servicegroup}")

        if hbacsvc or hbacsvcgroup:
            self.role.host.conn.exec(cmd)

        return self

    def remove_member(
        self,
        *,
        hbacsvc: list[str] | str | None = None,
        hbacsvcgroup: list[str] | str | None = None,
    ) -> IPAHBACServiceGroup:
        """
        Remove HBAC service group members.

        :param hbacsvc: HBAC service(s) to remove as member(s).
        :type hbacsvc: list[str] | str | None, optional
        :param hbacsvcgroup: HBAC service group(s) to remove as member(s).
        :type hbacsvcgroup: list[str] | str | None, optional
        :return: Self.
        :rtype: IPAHBACServiceGroup
        """
        cmd = ["ipa", f"{self.command_group}-remove-member", self.name]

        if hbacsvc:
            services_list = [hbacsvc] if isinstance(hbacsvc, str) else hbacsvc
            for service in services_list:
                cmd.append(f"--hbacsvcs={service}")

        if hbacsvcgroup:
            servicegroups_list = [hbacsvcgroup] if isinstance(hbacsvcgroup, str) else hbacsvcgroup
            for servicegroup in servicegroups_list:
                cmd.append(f"--hbacsvcgroups={servicegroup}")

        if hbacsvc or hbacsvcgroup:
            self.role.host.conn.exec(cmd)

        return self

    def delete(self) -> None:
        """
        Delete the IPA HBAC service group.
        """

        cmd = ["ipa", f"{self.command_group}-del", self.name]
        self.role.host.conn.exec(cmd)

    def show(self, attrs: list[str] | None = None) -> dict[str, list[str]] | None:
        """
        Show detailed info of the HBAC service group.

        :param attrs: If set, only requested attributes are returned, defaults to None
        :type attrs: list[str] | None, optional
        :return: Dictionary of HBAC service group attributes or None if not found
        :rtype: dict[str, list[str]]
        """
        return self.get(attrs)

    @classmethod
    def search(cls, role: IPA, criteria: str, all: bool = False) -> list[str]:
        """
        Search for host groups matching criteria.

        :param role: IPA role object.
        :type role: IPA
        :param criteria: Search filter string.
        :type criteria: str
        :param all: Prints all attributes, default is False.
        :type all: bool
        :return: List of matching HBAC host group names.
        :rtype: list[str]
        """
        return IPA.ipa_search(role, "hbacsvcgroup-find", criteria, all=all)


class IPAHBAC(IPAObject):
    """
    Manages IPA HBAC (Host-Based Access Control) rule.
    """

    def __init__(self, role: IPA, name: str):
        """
        Initializes an HBAC rule manager.

        :param role: IPA role.
        :type role: IPA
        :param name: Name of IPA HBAC rule.
        :type name: str
        """
        super().__init__(role, name, command_group="hbacrule")

    def _add_members_to_rule(self, command: str, items: list[str] | str | None, option: str) -> None:
        """
        Helper method to add members to HBAC rule.

        :param command: IPA command to use (e.g., "hbacrule-add-user")
        :type command: str
        :param items: Items to add (single string or list of strings)
        :type items: list[str] | str | None, optional
        :param option: Command line option (e.g., "--users", "--groups")
        :type option: str
        """
        if items:
            items_list = [items] if isinstance(items, str) else items
            for item in items_list:
                self.role.host.conn.exec(["ipa", command, self.name, f"{option}={item}"])

    def create(
        self,
        users: list[str] | str | None = None,
        groups: list[str] | str | None = None,
        hosts: list[str] | str | None = None,
        hostgroups: list[str] | str | None = None,
        services: list[str] | str | None = None,
        servicegroups: list[str] | str | None = None,
        description: str | None = None,
        hostcat: str | None = None,
        servicecat: str | None = None,
        usercat: str | None = None,
        **kwargs,
    ) -> IPAHBAC:
        """
        Creates a new HBAC rule with all components in one call.
        Can also be used to add components to existing rules.

        :param users: User(s) to create HBAC rule.
        :type users: list[str] | str | None
        :param groups: Group(s) to create HBAC rule.
        :type groups: list[str] | str | None
        :param hosts: Host(s) to create HBAC rule.
        :type hosts: list[str] | str | None
        :param hostgroups: Host(s) group(s) to create HBAC rule.
        :type hostgroups: list[str] | str | None
        :param services: Service(s) to create HBAC rule.
        :type services: list[str] | str | None
        :param servicegroups: Service(group(s) to create HBAC rule.)
        :type servicegroups: list[str] | str | None
        :param description: Description(s) to create HBAC rule.
        :type description: str | None
        :param hostcat: Host(cat) to create HBAC rule.
        :type hostcat: str | None
        :param servicecat: Service(cat) to create HBAC rule.
        :type servicecat: str | None
        :param usercat: User(cat) to create HBAC rule.
        :type usercat: str | None
        :return: Self.
        :rtype: IPAHBAC
        """
        try:
            self.role.host.conn.exec(["ipa", "hbacrule-show", self.name], raise_on_error=True)
            rule_exists = True
        except Exception:
            rule_exists = False

        if not rule_exists:
            cmd = ["ipa", "hbacrule-add", self.name]

            if description:
                cmd.extend(["--desc", description])
            if hostcat:
                cmd.append(f"--hostcat={hostcat}")
            if servicecat:
                cmd.append(f"--servicecat={servicecat}")
            if usercat:
                cmd.append(f"--usercat={usercat}")

            self.role.host.conn.exec(cmd, **kwargs)

        # Add all components (works for both new and existing rules)
        self._add_members_to_rule("hbacrule-add-user", users, "--users")
        self._add_members_to_rule("hbacrule-add-user", groups, "--groups")
        self._add_members_to_rule("hbacrule-add-host", hosts, "--hosts")
        self._add_members_to_rule("hbacrule-add-host", hostgroups, "--hostgroups")
        self._add_members_to_rule("hbacrule-add-service", services, "--hbacsvcs")
        self._add_members_to_rule("hbacrule-add-service", servicegroups, "--hbacsvcgroups")

        return self

    def modify(
        self,
        description: str | None = None,
        hostcat: str | None = None,
        servicecat: str | None = None,
        usercat: str | None = None,
        **kwargs,
    ) -> IPAHBAC:
        """
        Modifies an existing HBAC rule.

        :param description: Description(s) to modify HBAC rule.
        :type description: str | None
        :param hostcat: Host(cat) to modify HBAC rule.
        :type hostcat: str | None
        :param servicecat: Service(cat) to modify HBAC rule.
        :type servicecat: str | None
        :param usercat: User(cat) to modify HBAC rule.
        :type usercat: str | None
        :return: Self.
        :rtype: IPAHBAC
        """
        cmd = ["ipa", "hbacrule-mod", self.name]

        if description is not None:
            cmd.extend(["--desc", description])
        if hostcat is not None:
            cmd.append(f"--hostcat={hostcat}")
        if servicecat is not None:
            cmd.append(f"--servicecat={servicecat}")
        if usercat is not None:
            cmd.append(f"--usercat={usercat}")

        self.role.host.conn.exec(cmd, **kwargs)
        return self

    def delete(self) -> None:
        """
        Deletes the HBAC rule.
        """
        self.role.host.conn.exec(["ipa", "hbacrule-del", self.name])

    def enable(self) -> IPAHBAC:
        """
        Enables the HBAC rule.

        :return: Self.
        :rtype: IPAHBAC
        """
        self.role.host.conn.exec(["ipa", "hbacrule-enable", self.name])
        return self

    def disable(self) -> IPAHBAC:
        """
        Disables the HBAC rule.

        :return: Self.
        :rtype: IPAHBAC
        """
        self.role.host.conn.exec(["ipa", "hbacrule-disable", self.name])
        return self

    def _fetch_rule_data(self) -> dict[str, Any]:
        """
        Return parsed ``hbacrule-show`` output for the rule.

        :return: Parsed ``hbacrule-show`` output.
        :rtype: dict[str, Any]
        """
        result = self.role.host.conn.exec(["ipa", "hbacrule-show", self.name, "--all"])
        lines = [line.strip() for line in result.stdout_lines if ":" in line]
        return attrs_parse(lines)

    @classmethod
    def search(cls, role: IPA, criteria: str, all: bool = False) -> list[str]:
        """
        Search for HBAC rules.

        :param role: IPA role object.
        :type role: IPA
        :param criteria: Search filter string.
        :type criteria: str
        :param all: Prints all attributes, default is False.
        :type all: bool
        :return: List of matching List of matching HBAC rules names.
        :rtype: list[str]
        """
        return IPA.ipa_search(role, "hbacrule-find", criteria, all=all)

    def remove_members(
        self,
        *,
        users: list[str] | str | None = None,
        hosts: list[str] | str | None = None,
        services: list[str] | str | None = None,
    ) -> IPAHBAC:
        """
        Remove users, hosts, and/or services from HBAC rule.

        :param users: Users to remove.
        :type users: list[str] | str | None, default to None
        :param hosts: Hosts to remove.
        :type hosts: list[str] | str | None, default to None
        :param services: Services to remove.
        :type services: list[str] | str | None, default to None
        :return: Self.
        :rtype: IPAHBAC
        """
        errors = []

        def remove_items(item_type: str, items):
            items_list = [items] if isinstance(items, str) else items
            for item in items_list:
                try:
                    self.role.host.conn.exec(
                        ["ipa", f"hbacrule-remove-{item_type}", self.name, f"--{item_type}={item}"]
                    )
                except Exception as e:
                    errors.append(f"Failed to remove {item_type[:-1]} '{item}': {e}")

        if users:
            remove_items("users", users)
        if hosts:
            remove_items("hosts", hosts)
        if services:
            remove_items("services", services)

        if errors:
            error_message = "Errors occurred while removing members:\n" + "\n".join(errors)
            raise RuntimeError(error_message)

        return self

    def test(
        self,
        user: str,
        host: str,
        service: str,
        nodetail: bool = False,
        **kwargs,
    ) -> dict[str, Any]:
        """
        Tests HBAC rule evaluation and returns comprehensive results.
        Evaluates all configured rules to determine access and shows which rules match.

        :param user: User(s) to create HBAC rule.
        :type user: str | None
        :param host: Host(s) to create HBAC rule.
        :type host: str | None
        :param service: Service(s) to create HBAC rule.
        :type service: str | None
        :param nodetail: Whether to return nodetail rules.
        :type nodetail: bool | None
        :param kwargs: Keyword arguments to pass to ``ipa.hbacrule-test``.
        :type kwargs: dict[str, Any]
        :return: parsed ``hbacrule-test`` output.
        :rtype: dict[str, Any]
        """
        cmd = ["ipa", "hbactest", f"--user={user}", f"--host={host}", f"--service={service}"]

        if nodetail:
            cmd.append("--nodetail")

        # Handle negative test cases by not raising errors on command failure
        result = self.role.host.conn.exec(cmd, raise_on_error=False, **kwargs)
        lines = [line.strip() for line in result.stdout_lines if ":" in line]

        raw_results = attrs_parse(lines)

        # Return comprehensive results
        return {
            "access_granted": get_attr(raw_results, "Access granted") == "True",
            "matched_rules": to_list(get_attr(raw_results, "Matched rules")),
            "not_matched_rules": to_list(get_attr(raw_results, "Not matched rules")),
            "invalid_rules": to_list(get_attr(raw_results, "Non-existent or invalid rules")),
            "raw_output": raw_results,
            "user": user,
            "host": host,
            "service": service,
        }

    def status(
        self,
        *,
        user: str | None = None,
        group: str | None = None,
        host: str | None = None,
        service: str | None = None,
        include_members: bool = False,
    ) -> dict[str, Any]:
        """
        Get rule status, optionally checking membership and returning the raw member lists.

        :param user: Username to check for membership in the rule.
        :type: str | None, default to None
        :param group: Group name to check for membership in the rule.
        :type: str | None, default to None
        :param host: Hostname to check for membership in the rule.
        :type: str | None, default to None
        :param service: Service name to check for membership in the rule.
        :type: str | None, default to None
        :param include_members: When ``True`` return the resolved member lists in the output.
        :type: bool | None, default to False
        :return: Dictionary with rule status information and optional membership results.
        :rtype: dict[str, Any]
        """
        raw_data = self._fetch_rule_data()

        users = to_list(get_attr(raw_data, "Users", default=[]))
        user_groups = to_list(get_attr(raw_data, "User Groups", default=[]))
        hosts = to_list(get_attr(raw_data, "Hosts", default=[]))
        host_groups = to_list(get_attr(raw_data, "Host Groups", default=[]))
        services = to_list(get_attr(raw_data, "HBAC Services", default=[]))
        service_groups = to_list(get_attr(raw_data, "HBAC Service Groups", default=[]))

        membership_checks: dict[str, bool] = {}
        if user is not None:
            membership_checks["user"] = user in users
        if group is not None:
            membership_checks["group"] = group in user_groups
        if host is not None:
            membership_checks["host"] = host in hosts
        if service is not None:
            membership_checks["service"] = service in services

        payload: dict[str, Any] = {
            "name": self.name,
            "enabled": str(get_attr(raw_data, "Enabled", default="FALSE")).upper() == "TRUE",
            "description": get_attr(raw_data, "Description"),
            "user_count": len(users) + len(user_groups),
            "host_count": len(hosts) + len(host_groups),
            "service_count": len(services) + len(service_groups),
            "categories": {
                "user": get_attr(raw_data, "User category"),
                "host": get_attr(raw_data, "Host category"),
                "service": get_attr(raw_data, "Service category"),
            },
        }

        if membership_checks:
            payload["membership"] = membership_checks

        if include_members:
            payload["members"] = {
                "users": users,
                "user_groups": user_groups,
                "hosts": hosts,
                "host_groups": host_groups,
                "services": services,
                "service_groups": service_groups,
            }

        return payload

    def contains(self, **kwargs) -> bool:
        """
        Convenience method to check if any membership filter matches.

        :return: True if any membership filter matches, else False.
        :rtype: bool
        """
        membership = self.status(**kwargs).get("membership", {})
        return any(membership.values()) if membership else False
