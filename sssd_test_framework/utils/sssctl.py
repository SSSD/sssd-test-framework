"""Manage and configure SSSD."""

from __future__ import annotations

from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.cli import CLIBuilder, CLIBuilderArgs
from pytest_mh.conn import ProcessResult
from pytest_mh.utils.fs import LinuxFileSystem

from ..misc.globals import test_venv_bin

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

        self.host.conn.exec(["sssctl", "cache-expire"] + self.cli.args(args))

    def passkey_register(self, *args, **kwargs) -> str:
        """wrapper for passkey_register methods"""
        if "virt_type" in kwargs and kwargs["virt_type"] == "vfido":
            del kwargs["virt_type"]
            return self.vfido_passkey_register(*args, **kwargs)
        else:
            return self.umockdev_passkey_register(*args, **kwargs)

    def vfido_passkey_register(
        self,
        username: str,
        domain: str,
        *,
        pin: str | int | None = None,
    ) -> str:
        """
        Register user passkey when using virtual-fido
        """

        if pin is None:
            pin = "empty"

        result = self.host.conn.expect(
            f"""
            set pin "{pin}"
            set timeout 60

            spawn sssctl passkey-register --username {username} --domain {domain}
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
            sleep 1
            spawn {test_venv_bin}/vfido_touch
            set ID_touch $spawn_id

            expect {{
                -i $ID_reg -re "passkey:.*,.*" {{}}
                -i $ID_reg timeout {{puts "expect result: Unexpected output"; exit 205}}
                -i $ID_reg eof {{puts "expect result: Unexpected end of file"; exit 206}}
            }}

            expect -i $ID_reg eof
            expect -i $ID_touch eof
            """,
            raise_on_error=True,
        )

        self.logger.info(f"EXPECT STDOUT: {result.stdout}")
        for line in result.stdout_lines:
            if line.startswith("passkey:"):
                return line.strip()
        raise ValueError("passkey mapping entry not returned by registration")

    def umockdev_passkey_register(
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

    def user_checks(self, username: str, action: str = "acct", service: str = "system-auth") -> ProcessResult:
        """
        Print information about a user and check authentication

        :param username: User that will be checked
        :type username: str
        :param action: PAM action, defaults to "acct"
        :type action: str
        :param service: PAM service, defaults to "system-auth"
        :type service: str
        :return: Result of called command
        :rtype: ProcessResult
        """
        return self.host.conn.exec(["sssctl", "user-checks", username, "-a", action, "-s", service])

    def user_show(self, user: str | None = None, sid: str | None = None, uid: int | None = None) -> ProcessResult:
        """
        Information about cached user

        :param user: User that will be showed, defaults to None
        :type user: str | None
        :param sid: Search by SID, defaults to None
        :type sid: str | None
        :param uid: Search by user ID, defaults to None
        :type uid: int | None
        :return: Result of called command
        :rtype: ProcessResult
        """
        options = []
        if user is not None:
            options += [user]
        if sid is not None:
            options += ["-s", sid]
        if uid is not None:
            options += ["-u", str(uid)]

        return self.host.conn.exec(["sssctl", "user-show", *options])

    def config_check(self, config: str | None = None, snippet: str | None = None) -> ProcessResult:
        """
        Call ``sssctl config-check`` with additional arguments

        :param config: Non default config file, defaults to None
        :type config: str
        :param snippet: Non default snippet dir, defaults to None
        :type snippet: str
        :return: Result of called command
        :rtype: ProcessResult
        """
        args: CLIBuilderArgs = {
            "config": (self.cli.option.VALUE, config),
            "snippet": (self.cli.option.VALUE, snippet),
        }

        return self.host.conn.exec(["sssctl", "config-check"] + self.cli.args(args), raise_on_error=False)

    def domain_status(
        self,
        domain: str,
        *,
        online: bool = False,
        active: bool = False,
        servers: bool = False,
        start: bool = False,
    ) -> ProcessResult:
        """
        Call ``sssctl domain-status @domain`` with additional arguments.

        :param domain: Domain name.
        :type domain: str
        :param online: Show online status, defaults to False
        :type online: bool, optional
        :param active: Show information about active server, defaults to False
        :type active: bool, optional
        :param servers: Show list of discovered servers, defaults to False
        :type servers: bool, optional
        :param start: Start SSSD if it is not running, defaults to False
        :type start: bool, optional
        :return: Result of called command.
        :rtype: ProcessResult
        """
        args: CLIBuilderArgs = {
            "online": (self.cli.option.SWITCH, online),
            "active-server": (self.cli.option.SWITCH, active),
            "servers": (self.cli.option.SWITCH, servers),
            "start": (self.cli.option.SWITCH, start),
            "domain": (self.cli.option.POSITIONAL, domain),
        }

        return self.host.conn.exec(["sssctl", "domain-status"] + self.cli.args(args), raise_on_error=False)

    def analyze_request(self, command: str, source: str | None = None, logdir: str | None = None) -> ProcessResult:
        """
        Call ``sssctl analyze [arguments] request command``

        :param command: request command
        :type command: str
        :param source: "files" or "journald", defaults to None
        :type source: str | None, optional
        :param logdir: SSSD Log directory to parse log files from, defaults to None
        :type logdir: str | None, optional
        :return: Result of called command
        :rtype: ProcessResult
        """
        args: CLIBuilderArgs = {
            "source": (self.cli.option.VALUE, source),
            "logdir": (self.cli.option.VALUE, logdir),
        }

        return self.host.conn.exec(
            ["sssctl", "analyze"] + self.cli.args(args) + ["request"] + command.split(), raise_on_error=False
        )

    def logs_remove(self) -> ProcessResult:
        """
        Call ``sssctl logs-remove``

        :return: Result of called command
        :rtype: ProcessResult
        """
        return self.host.conn.exec(["sssctl", "logs-remove"], raise_on_error=False)

    def logs_fetch(self, output_file: str) -> ProcessResult:
        """
        Call ``sssctl logs-fetch``

        :param output_file: Path where to save the log archive
        :type output_file: str
        :return: Result of called command
        :rtype: ProcessResult
        """
        return self.host.conn.exec(["sssctl", "logs-fetch", output_file], raise_on_error=False)

    def debug_level(
        self,
        level: str | None = None,
        *,
        set: bool = False,
        domain: str | None = None,
        nss: bool = False,
        pam: bool = False,
        sudo: bool = False,
        autofs: bool = False,
        ssh: bool = False,
        pac: bool = False,
        ifp: bool = False,
        secrets: bool = False,
        kcm: bool = False,
        all: bool = False,
    ) -> ProcessResult:
        """
        Call ``sssctl debug-level`` with specific targets

        :param level: Debug level to set (e.g., "9", "0x3ff0")
        :type level: str | None
        :param set: Set debug level (use with level parameter), defaults to False
        :type set: bool, optional
        :param domain: Apply to specific domain, defaults to None
        :type domain: str | None, optional
        :param nss: Apply to NSS responder, defaults to False
        :type nss: bool, optional
        :param pam: Apply to PAM responder, defaults to False
        :type pam: bool, optional
        :param sudo: Apply to SUDO responder, defaults to False
        :type sudo: bool, optional
        :param autofs: Apply to AUTOFS responder, defaults to False
        :type autofs: bool, optional
        :param ssh: Apply to SSH responder, defaults to False
        :type ssh: bool, optional
        :param pac: Apply to PAC responder, defaults to False
        :type pac: bool, optional
        :param ifp: Apply to InfoPipe responder, defaults to False
        :type ifp: bool, optional
        :param secrets: Apply to SECRETS service, defaults to False
        :type secrets: bool, optional
        :param kcm: Apply to KCM service, defaults to False
        :type kcm: bool, optional
        :param all: Apply to all services, defaults to False
        :type all: bool, optional
        :return: Result of called command
        :rtype: ProcessResult
        """
        args: CLIBuilderArgs = {
            "set": (self.cli.option.SWITCH, set),
            "domain": (self.cli.option.VALUE, domain),
            "nss": (self.cli.option.SWITCH, nss),
            "pam": (self.cli.option.SWITCH, pam),
            "sudo": (self.cli.option.SWITCH, sudo),
            "autofs": (self.cli.option.SWITCH, autofs),
            "ssh": (self.cli.option.SWITCH, ssh),
            "pac": (self.cli.option.SWITCH, pac),
            "ifp": (self.cli.option.SWITCH, ifp),
            "secrets": (self.cli.option.SWITCH, secrets),
            "kcm": (self.cli.option.SWITCH, kcm),
            "all": (self.cli.option.SWITCH, all),
            "level": (self.cli.option.POSITIONAL, level),
        }

        return self.host.conn.exec(["sssctl", "debug-level"] + self.cli.args(args), raise_on_error=False)

    def group_show(self, group: str | None = None, gid: int | None = None, sid: str | None = None) -> ProcessResult:
        """
        Information about cached group

        :param group: Group that will be showed, defaults to None
        :type group: str | None, optional
        :param gid: Search by group ID, defaults to None
        :type gid: int | None, optional
        :param sid: Search by SID, defaults to None
        :type sid: str | None
        :return: Result of called command
        :rtype: ProcessResult
        """
        param_count = sum(1 for x in [group, gid, sid] if x is not None)

        if param_count == 0:
            raise ValueError("At least one of group, gid, or sid must be provided")
        elif param_count > 1:
            raise ValueError("Only one of group, gid, or sid should be provided")

        if group is not None:
            return self.host.conn.exec(["sssctl", "group-show", group], raise_on_error=False)
        elif gid is not None:
            return self.host.conn.exec(["sssctl", "group-show", "-g", str(gid)], raise_on_error=False)
        else:
            return self.host.conn.exec(["sssctl", "group-show", "-s", sid], raise_on_error=False)

    def netgroup_show(self, netgroup: str) -> ProcessResult:
        """
        Information about cached netgroup

        :param netgroup: Netgroup that will be showed
        :type netgroup: str
        :return: Result of called command
        :rtype: ProcessResult
        """
        return self.host.conn.exec(["sssctl", "netgroup-show", netgroup], raise_on_error=False)
