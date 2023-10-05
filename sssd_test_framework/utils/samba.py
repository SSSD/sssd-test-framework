"""Manage and configure Samba as a Standalone server."""

from __future__ import annotations

import configparser
import subprocess
from io import StringIO
from random import randint
from typing import TYPE_CHECKING

from pytest_mh import MultihostHost
from pytest_mh.ssh import SSHLog

from .sssd import SSSDUtils

if TYPE_CHECKING:
    from pytest_mh.utils.fs import LinuxFileSystem
    from pytest_mh.utils.services import SystemdServices

    from .authselect import AuthselectUtils

__all__ = [
    "SambaUtils",
]


class SambaUtils(SSSDUtils):
    """
    Manage and configure Samba as a Standalone server.

    .. note::

        All changes are automatically reverted when a test is finished.
    """

    def __init__(
        self,
        host: MultihostHost,
        fs: LinuxFileSystem,
        svc: SystemdServices,
        authselect: AuthselectUtils,
        load_config: bool = False,
    ) -> None:
        """
        :param host: Multihost host.
        :type host: MultihostHost
        :param fs: File system utils.
        :type fs: LinuxFileSystem
        :param svc: Systemd utils.
        :type svc: SystemdServices
        :param authselect: Authselect utils.
        :type authselect: AuthselectUtils
        :param load_config: If True, existing configuration is loaded to
            :attr:`config`, otherwise default configuration is generated,
            defaults to False
        :type load_config: bool, optional
        """ """"""
        super().__init__(host, fs, svc, authselect)

        self.__load_config: bool = load_config

    def setup_when_used(self) -> None:
        """
        Setup Samba on the host.

        - load configuration from the host (if requested in constructor) or set
          default configuration otherwise

        :meta private:
        """
        # Load existing configuration if requested
        if self.__load_config:
            self.config_load()
            return

        # Set default configuration
        self.config.read_string(
            """
            [global]
            server string = Samba Server
        """
        )

    def clear(self, *, db: bool = True, memcache: bool = True, config: bool = False, logs: bool = False):
        """
        Clear Samba data.

        :param db: Remove cache and database, defaults to True
        :type db: bool, optional
        :param memcache: Remove in-memory cache, defaults to True
        :type memcache: bool, optional
        :param config: Remove configuration files, defaults to False
        :type config: bool, optional
        :param logs: Remove logs, defaults to False
        :type logs: bool, optional
        """
        cmd = "rm -fr"

        if db:
            cmd += "  /var/lib/samba/lock/msg.lock"

        if config:
            cmd += " /etc/samba/*.conf /etc/samba/lmhosts"

        if logs:
            cmd += " /var/log/samba/*"

        self.host.ssh.run(cmd)

    def config_load(self) -> None:
        """
        Load remote Samba configuration.
        """
        result = self.host.ssh.exec(["cat", "/etc/samba/smb.conf"], log_level=SSHLog.Short)
        self.config.clear()
        self.config.read_string(result.stdout)

    def config_apply(self, check_config: bool = True, debug_level: str | None = "4") -> None:
        """
        Apply current configuration on remote host.

        :param check_config: Check configuration for typos, defaults to True
        :type check_config: bool, optional
        :param debug_level: Automatically set debug level to the given value, defaults to 4
        :type debug_level:  str | None, optional
        """
        cfg = self.__set_debug_level(debug_level)
        contents = self.__config_dumps(cfg)
        self.fs.write("/etc/samba/smb.conf", contents, mode="0600")

        if check_config:
            self.host.ssh.run("testparm -s")

    def share(self, name: str | None = None, path: str | None = None) -> None:
        """
        Create samba share on the host.
        :param name: Share name
        :type name: str | None
        :param path: Share path
        :type path: str | None
        """
        rand = randint(1000, 10000)
        if not name:
            name = f"share-{rand}"
        if not path:
            path = f"/tmp/{name}"

        self.fs.mkdir_p(path)

        selinux_context = f"chcon unconfined_u:object_r:samba_share_t:s0 {path}"
        # Skip applying selinux content if selinux is disabled
        try:
            self.host.ssh.run(selinux_context)
        except subprocess.CalledProcessError:
            pass

        # Initialize share with default values
        default_value = {
            "path": path,
            "comment": f"test share {name}",
            "browseable": "yes",
            "writable": "yes",
            "printable": "no",
            "read only": "no",
        }
        self.section(name).update(default_value)

    def smbclient(
        self, host: str = "localhost", section: str | None = None, command: str | None = None,
            user: str | None = None, password: str | None = None) -> None:
        """
        Samba client to access SMB/CIFS resources on servers
        :param host: host where smbclient will be executed
        :type host: str
        :param section: section in smb.conf (usually samba share)
        :type section: str | None
        :param command: command to execute on samba server
        :type command: str | None
        :param user: samba username
        :type user: str | None
        :param password: samba user password
        :type password: str | None

        """
        self.host.ssh.run(f"smbclient '//{host}/{section}' -c " f"'{command}'" f" -U {user}%{password}")

    @property
    def global_(self) -> configparser.SectionProxy:
        """
        Configuration of the global section of smb.conf.
        """
        return self.__get("global")

    @global_.setter
    def global_(self, value: dict[str, str]) -> None:
        return self.__set("sssd", value)

    @global_.deleter
    def global_(self) -> None:
        return self.__del("sssd")

    @staticmethod
    def __config_dumps(cfg: configparser.ConfigParser) -> str:
        """Convert configparser to string."""
        with StringIO() as ss:
            cfg.write(ss)
            ss.seek(0)
            return ss.read()

    def __set_debug_level(self, debug_level: str | None = None) -> configparser.ConfigParser:
        """Set debug level in all sections."""
        cfg = configparser.ConfigParser()
        cfg.read_dict(self.config)

        if debug_level is None:
            return self.config

        sections = ["global"]

        cfg.setdefault(sections[0], {})
        if "log level" not in cfg[sections[0]]:
            cfg[sections[0]]["log level"] = debug_level

        return cfg
