"""Manage and configure SSSD."""

from __future__ import annotations

from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.cli import CLIBuilder, CLIBuilderArgs
from pytest_mh.ssh import SSHProcessResult
from pytest_mh.utils.fs import LinuxFileSystem

__all__ = [
    "SSSCTLUtils",
]


class SSSCTLUtils(MultihostUtility[MultihostHost]):
    """
    Call commands from sssctl.
    """

    def __init__(self, host: MultihostHost, fs: LinuxFileSystem) -> None:
        super().__init__(host)

        self.cli: CLIBuilder = self.host.cli
        """Command line builder."""

        self.fs: LinuxFileSystem = fs
        """Filesystem utils."""

    def cache_expire(
        self,
        *,
        everything: bool = False,
        user: str | None = None,
        users: bool = False,
        group: str | None = None,
        groups: bool = False,
        netgroup: str | None = None,
        netgroups: bool = False,
        service: str | None = None,
        services: bool = False,
        autofs_map: str | None = None,
        autofs_maps: bool = False,
        ssh_host: str | None = None,
        ssh_hosts: bool = False,
        sudorule: str | None = None,
        sudorules: bool = False,
        domain: str | None = None,
    ) -> None:
        """
        Call ``sssctl cache-expire`` with given arguments.

        :param everything: Invalidate all cached entries, defaults to False
        :type everything: bool, optional
        :param user: Invalidate particular user, defaults to None
        :type user: str | None, optional
        :param users: Invalidate all users, defaults to False
        :type users: bool, optional
        :param group: Invalidate particular group, defaults to None
        :type group: str | None, optional
        :param groups: Invalidate all groups, defaults to False
        :type groups: bool, optional
        :param netgroup: Invalidate particular netgroup, defaults to None
        :type netgroup: str | None, optional
        :param netgroups: Invalidate all netgroups, defaults to False
        :type netgroups: bool, optional
        :param service: Invalidate particular service, defaults to None
        :type service: str | None, optional
        :param services: Invalidate all services, defaults to False
        :type services: bool, optional
        :param autofs_map: Invalidate particular autofs map, defaults to None
        :type autofs_map: str | None, optional
        :param autofs_maps: Invalidate all autofs maps, defaults to False
        :type autofs_maps: bool, optional
        :param ssh_host: Invalidate particular SSH host, defaults to None
        :type ssh_host: str | None, optional
        :param ssh_hosts: Invalidate all SSH hosts, defaults to False
        :type ssh_hosts: bool, optional
        :param sudorule: Invalidate particular sudo rule, defaults to None
        :type sudorule: str | None, optional
        :param sudorules: Invalidate all cached sudo rules, defaults to False
        :type sudorules: bool, optional
        :param domain: Only invalidate entries from a particular domain, defaults to None
        :type domain: str | None, optional
        """
        args: CLIBuilderArgs = {
            "everything": (self.cli.option.SWITCH, everything),
            "user": (self.cli.option.VALUE, user),
            "users": (self.cli.option.SWITCH, users),
            "group": (self.cli.option.VALUE, group),
            "groups": (self.cli.option.SWITCH, groups),
            "netgroup": (self.cli.option.VALUE, netgroup),
            "netgroups": (self.cli.option.SWITCH, netgroups),
            "service": (self.cli.option.VALUE, service),
            "services": (self.cli.option.SWITCH, services),
            "autofs-map": (self.cli.option.VALUE, autofs_map),
            "autofs-maps": (self.cli.option.SWITCH, autofs_maps),
            "ssh-host": (self.cli.option.VALUE, ssh_host),
            "ssh-hosts": (self.cli.option.SWITCH, ssh_hosts),
            "sudo-rule": (self.cli.option.VALUE, sudorule),
            "sudo-rules": (self.cli.option.SWITCH, sudorules),
            "domain": (self.cli.option.VALUE, domain),
        }

        self.host.ssh.exec(["sssctl", "cache-expire"] + self.cli.args(args))

    def passkey_register(
        self,
        username: str,
        domain: str,
        *,
        pin: str | int | None,
        device: str,
        ioctl: str,
        script: str,
    ) -> str:
        """
        Call ``sssctl passkey-register``

        :param username: User name
        :type username: str
        :param domain: Domain name
        :type domain: str
        :param pin: Passkey PIN.
        :type pin: str | int | None
        :param device: Path to local umockdev device file.
        :type device: str
        :param ioctl: Path to local umockdev ioctl file.
        :type ioctl: str
        :param script: Path to local umockdev script file
        :type script: str
        :return: Generated passkey mapping string.
        :rtype: str
        """
        device_path = self.fs.upload_to_tmp(device, mode="a=r")
        ioctl_path = self.fs.upload_to_tmp(ioctl, mode="a=r")
        script_path = self.fs.upload_to_tmp(script, mode="a=r")

        command = self.fs.mktmp(
            rf"""
            #!/bin/bash

            LD_PRELOAD=/opt/random.so umockdev-run      \
                --device '{device_path}'                \
                --ioctl '/dev/hidraw1={ioctl_path}'     \
                --script '/dev/hidraw1={script_path}'   \
                -- sssctl passkey-register --username '{username}' --domain '{domain}' -d=0xfff0 --debug-libfido2
            """,
            mode="a=rx",
        )

        if pin is not None:
            result = self.host.ssh.expect(
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
            result = self.host.ssh.expect(
                f"""
                spawn {command}
                expect eof
                """,
                raise_on_error=True,
            )

        return result.stdout_lines[-1].strip()

    def user_checks(self, username: str, action: str = "acct", service: str = "system-auth") -> SSHProcessResult:
        """
        Print information about a user and check authentication

        :param username: User that will be checked
        :type username: str
        :param action: PAM action, defaults to "acct"
        :type action: str
        :param service: PAM service, defaults to "system-auth"
        :type service: str
        :return: Result of called command
        :rtype: SSHProcessResult
        """
        return self.host.ssh.exec(["sssctl", "user-checks", username, "-a", action, "-s", service])

    def user_show(self, user: str | None = None, sid: str | None = None, uid: int | None = None) -> SSHProcessResult:
        """
        Information about cached user

        :param user: User that will be showed, defaults to None
        :type user: str | None
        :param sid: Search by SID, defaults to None
        :type sid: str | None
        :param uid: Search by user ID, defaults to None
        :type uid: int | None
        :return: Result of called command
        :rtype: SSHProcessResult
        """
        options = []
        if user is not None:
            options += [user]
        if sid is not None:
            options += ["-s", sid]
        if uid is not None:
            options += ["-u", str(uid)]

        return self.host.ssh.exec(["sssctl", "user-show", *options])

    def config_check(self, config: str | None = None, snippet: str | None = None) -> SSHProcessResult:
        """
        Call ``sssctl config-check`` with additional arguments

        :param config: Non default config file, defaults to None
        :type config: str
        :param snippet: Non default snippet dir, defaults to None
        :type snippet: str
        :return: Result of called command
        :rtype: SSHProcessResult
        """
        args: CLIBuilderArgs = {
            "config": (self.cli.option.VALUE, config),
            "snippet": (self.cli.option.VALUE, snippet),
        }

        return self.host.ssh.exec(["sssctl", "config-check"] + self.cli.args(args), raise_on_error=False)
