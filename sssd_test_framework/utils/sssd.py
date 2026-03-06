"""Manage and configure SSSD."""

from __future__ import annotations

import configparser
from io import StringIO
from typing import TYPE_CHECKING, Literal

import pytest
from pytest_mh import MultihostHost, MultihostRole, MultihostUtility
from pytest_mh.conn import Process, ProcessLogLevel, ProcessResult

from ..hosts.base import BaseDomainHost
from ..hosts.client import ClientHost
from ..hosts.ipa import IPAHost
from ..misc import to_list
from ..roles.generic import GenericProvider

if TYPE_CHECKING:
    from pytest_mh.utils.fs import LinuxFileSystem
    from pytest_mh.utils.services import SystemdServices

    from ..roles.base import BaseRole
    from ..roles.kdc import KDC
    from .authselect import AuthselectUtils


__all__ = [
    "SSSDCommonConfiguration",
    "SSSDLogsPath",
    "SSSDUtils",
]


class SSSDUtils(MultihostUtility[MultihostHost]):
    """
    Manage and configure SSSD.

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
        super().__init__(host)

        self.authselect: AuthselectUtils = authselect
        """Authselect utils."""

        self.fs: LinuxFileSystem = fs
        """Filesystem utils."""

        self.svc: SystemdServices = svc
        """Systemd utils."""

        self.config: configparser.ConfigParser = configparser.ConfigParser(interpolation=None)
        """SSSD configuration object."""

        self.default_domain: str | None = None
        """Default SSSD domain."""

        self.__load_config: bool = load_config

        self.common: SSSDCommonConfiguration = SSSDCommonConfiguration(self)
        """
        Shortcuts to setup common SSSD configurations.
        """

        self.logs: SSSDLogsPath = SSSDLogsPath(self)
        """
        Shortcuts to SSSD log paths.
        """

    def setup(self) -> None:
        """
        Setup SSSD on the host.

        - load configuration from the host (if requested in constructor) or set
          default configuration otherwise

        :meta private:
        """
        # Load existing configuration if requested
        if self.__load_config:
            self.config_load()
            return

        # Set default configuration
        self.config.read_string("""
            [sssd]
            services = nss, pam
            """)

    def async_start(
        self,
        service="sssd",
        service_user="sssd",
        *,
        apply_config: bool = True,
        check_config: bool = True,
        debug_level: str | None = "0xfff0",
        clean: bool = False,
    ) -> Process:
        """
        Start the SSSD and KCM services. Non-blocking call.

        :param service: Service to start, defaults to 'sssd'
        :type service: str, optional
        :param service_user: User used to start the service, defaults to 'sssd'
        :type service_user: str, optional
        :param apply_config: Apply current configuration, defaults to True
        :type apply_config: bool, optional
        :param check_config: Check configuration for typos, defaults to True
        :type check_config: bool, optional
        :param debug_level: Automatically set debug level to the given value, defaults to 0xfff0
        :type debug_level:  str | None, optional
        :param clean: Does a clean restart, clearing the cache, defaults to False
        :type clean: bool, defaults to False
        :return: Running SSH process.
        :rtype: Process
        """
        self.set_service_user(service_user)

        if apply_config:
            self.config_apply(check_config=check_config, debug_level=debug_level)

        # Also stop kcm so that it is started when first used.
        if service == "sssd":
            self.svc.async_stop("sssd-kcm.service")

        if clean and service == "sssd":
            self.clear()

        return self.svc.async_start(service)

    def start(
        self,
        service="sssd",
        service_user="sssd",
        *,
        raise_on_error: bool = True,
        apply_config: bool = True,
        check_config: bool = True,
        debug_level: str | None = "0xfff0",
        clean: bool = False,
    ) -> ProcessResult:
        """
        Start the SSSD and KCM services. The call will wait until the operation is finished.

        :param service: Service to start, defaults to 'sssd'
        :type service: str, optional
        :param service_user: User used to start the service, defaults to 'sssd'
        :type service_user: str, optional
        :param raise_on_error: Raise exception on error, defaults to True
        :type raise_on_error: bool, optional
        :param apply_config: Apply current configuration, defaults to True
        :type apply_config: bool, optional
        :param check_config: Check configuration for typos, defaults to True
        :type check_config: bool, optional
        :param debug_level: Automatically set debug level to the given value, defaults to 0xfff0
        :type debug_level:  str | None, optional
        :param clean: Does a clean restart, clearing the cache, defaults to False
        :type clean: bool, defaults to False
        :return: SSH process result.
        :rtype: ProcessResult
        """
        self.set_service_user(service_user)

        if apply_config:
            self.config_apply(check_config=check_config, debug_level=debug_level)

        # Also stop kcm so that it is started when first used.
        if service == "sssd":
            self.svc.stop("sssd-kcm.service")

        if clean and service == "sssd":
            self.clear()

        return self.svc.start(service, raise_on_error=raise_on_error)

    def async_stop(self, service="sssd") -> Process:
        """
        Stop the SSSD and KCM services. Non-blocking call.

        :param service: Service to start, defaults to 'sssd'
        :type service: str, optional
        :return: Running SSH process.
        :rtype: Process
        """
        # Also stop kcm. Nevertheless, it will be started when first used.
        if service == "sssd":
            self.svc.async_stop("sssd-kcm.service")

        return self.svc.async_stop(service)

    def stop(self, service="sssd", *, raise_on_error: bool = True) -> ProcessResult:
        """
        Stop the SSSD and KCM services. The call will wait until the operation is finished.

        :param service: Service to start, defaults to 'sssd'
        :type service: str, optional
        :param raise_on_error: Raise exception on error, defaults to True
        :type raise_on_error: bool, optional
        :return: SSH process result.
        :rtype: Process
        """
        # Also stop kcm. Nevertheless, it will be started when first used.
        if service == "sssd":
            self.svc.stop("sssd-kcm.service")

        return self.svc.stop(service, raise_on_error=raise_on_error)

    def async_restart(
        self,
        service="sssd",
        *,
        apply_config: bool = True,
        check_config: bool = True,
        debug_level: str | None = "0xfff0",
        clean: bool = False,
    ) -> Process:
        """
        Restart the SSSD and KCM services. Non-blocking call.

        :param service: Service to start, defaults to 'sssd'
        :type service: str, optional
        :param apply_config: Apply current configuration, defaults to True
        :type apply_config: bool, optional
        :param check_config: Check configuration for typos, defaults to True
        :type check_config: bool, optional
        :param debug_level: Automatically set debug level to the given value, defaults to 0xfff0
        :type debug_level:  str | None, optional
        :param clean: Does a clean restart, clearing the cache, defaults to False
        :type clean: bool, defaults to False
        :return: Running SSH process.
        :rtype: Process
        """
        if apply_config:
            self.config_apply(check_config=check_config, debug_level=debug_level)

        # Also stop kcm so that it is started when first used.
        if service == "sssd":
            self.svc.async_stop("sssd-kcm.service")

        if clean and service == "sssd":
            self.clear()

        return self.svc.async_restart(service)

    def restart(
        self,
        service="sssd",
        *,
        raise_on_error: bool = True,
        apply_config: bool = True,
        check_config: bool = True,
        debug_level: str | None = "0xfff0",
        clean: bool = False,
    ) -> ProcessResult:
        """
        Restart the SSSD and KCM services. The call will wait until the operation is finished.

        :param service: Service to start, defaults to 'sssd'
        :type service: str, optional
        :param raise_on_error: Raise exception on error, defaults to True
        :type raise_on_error: bool, optional
        :param apply_config: Apply current configuration, defaults to True
        :type apply_config: bool, optional
        :param check_config: Check configuration for typos, defaults to True
        :type check_config: bool, optional
        :param debug_level: Automatically set debug level to the given value, defaults to 0xfff0
        :type debug_level:  str | None, optional
        :param clean: Does a clean restart, clearing the cache, defaults to False
        :type clean: bool, defaults to False
        :return: SSH process result.
        :rtype: ProcessResult
        """
        if apply_config:
            self.config_apply(check_config=check_config, debug_level=debug_level)

        # Also stop kcm so that it is started when first used.
        if service == "sssd":
            self.svc.stop("sssd-kcm.service")

        if clean and service == "sssd":
            self.clear()

        return self.svc.restart(service, raise_on_error=raise_on_error)

    def clear(self, *, db: bool = True, memcache: bool = True, config: bool = False, logs: bool = False):
        """
        Clear SSSD data.

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
            cmd += " /var/lib/sss/db/*"

        if memcache:
            cmd += " /var/lib/sss/mc/*"

        if config:
            cmd += " /etc/sssd/*.conf /etc/sssd/conf.d/*"

        if logs:
            cmd += " /var/log/sssd/*"

        self.host.conn.run(cmd)

    def set_service_user(self, user: str) -> None:
        """
        Reconfigures 'sssd.service' systemd service description
        to run SSSD service under 'user' (only 'root' or 'sssd'
        are supported by SSSD).
        Take a note, this currently doesn't handle reconfiguration
        of socket activated services.

        :param user: Option value to set.
        :type user: str
        :raises ValueError: in case error happens.
        """
        if isinstance(self.host, ClientHost):
            if not self.host.features["non-privileged"]:
                return  # service user configuration isn't supported at all
        elif isinstance(self.host, IPAHost):
            return  # not supported
        else:
            raise ValueError("Unexpected host type")

        if user == self.host.sssd_service_user:
            return  # requested service user matches default, nothing to do

        service_file = "/usr/lib/systemd/system/sssd.service"
        rw = self.host.conn.run(f"test -w {service_file}", raise_on_error=False)
        if rw.rc != 0:
            # Can't change service user on read only filesystem
            pytest.skip(f"Cannot write {service_file}")

        self.fs.backup(service_file)
        cmd = f'sed -i "s/^User=.*/User={user}/g" {service_file}\n'
        cmd += f'sed -i "s/^Group=.*/Group={user}/g" {service_file}\n'
        if user == "root":
            cmd += f'sed -i "s/^#SupplementaryGroups=sssd$/SupplementaryGroups=sssd/g" {service_file}\n'
            cmd += f'sed -i "s/sssd:sssd/root:root/g" {service_file}\n'
        elif user == "sssd":
            cmd += f'sed -i "s/^SupplementaryGroups=sssd$/#SupplementaryGroups=sssd/g" {service_file}\n'
            cmd += f'sed -i "s/root:root/sssd:sssd/g" {service_file}\n'
        else:
            raise ValueError("Unexpected value of 'user'")
        cmd += f"chown -f {user}:{user} /var/lib/sss/db/*.ldb || true\n"
        cmd += "rm -f /var/lib/sss/db/fast_ccache_* || true"
        self.host.conn.run(cmd)
        self.svc.reload_daemon()

    def set_server(self, provider: GenericProvider) -> None:
        """
        Set the correct 'ldap_server | ipa_server | ad_server' parameter and value for the role.

        :param provider: Generic provider object.
        :type provider: GenericProvider
        """
        if provider.name == "ldap":
            self.domain["ldap_uri"] = f"ldap://{provider.server}"
        elif provider.name in ("ipa", "ad"):
            self.domain[f"{provider.name}_server"] = provider.server
        else:
            raise ValueError("Unexpected 'provider' value")

    def set_invalid_primary_server(self, provider: GenericProvider) -> None:
        """
        Sets an non working server  value for 'ldap_server | ipa_server | ad_server' parameter and
        a working server  value for 'ldap_backup_server | ipa_backup_server | ad_backup_server'
        for failover testing.

        :param provider: Generic provider object.
        :type provider: GenericProvider
        """
        if provider.name == "ldap":
            self.domain["ldap_uri"] = f"ldap://invalid.{provider.domain}"
            self.domain["ldap_backup_uri"] = f"ldap://{provider.server}"
        elif provider.name in ("ipa", "ad"):
            self.domain[f"{provider.name}_server"] = f"invalid.{provider.domain}"
            self.domain[f"{provider.name}_backup_server"] = provider.server
        else:
            raise ValueError("Unexpected 'provider' value")

    def enable_responder(self, responder: str) -> None:
        """
        Include the responder in the [sssd]/service option.

        :param responder: Responder to enable.
        :type responder: str
        """
        self.config.setdefault("sssd", {})
        svc = self.config["sssd"].get("services", "")
        if responder not in svc:
            self.config["sssd"]["services"] += ", " + responder
            self.config["sssd"]["services"].lstrip(", ")

    def import_domain(self, name: str, role: MultihostRole) -> None:
        """
        Import SSSD domain from role object.

        :param name: SSSD domain name.
        :type name: str
        :param role: Provider role object to use for import.
        :type role: MultihostRole
        :raises ValueError: If unsupported provider is given.
        """
        host = role.host

        if not isinstance(host, BaseDomainHost):
            raise ValueError(f"Host type {type(host)} can not be imported as domain")

        self.config[f"domain/{name}"] = host.client
        self.config["sssd"].setdefault("domains", "")

        if not self.config["sssd"]["domains"]:
            self.config["sssd"]["domains"] = name
        elif name not in [x.strip() for x in self.config["sssd"]["domains"].split(",")]:
            self.config["sssd"]["domains"] += ", " + name

        if self.default_domain is None:
            self.default_domain = name

    def merge_domain(self, name: str, role: BaseRole) -> None:
        """
        Merge SSSD domain configuration from role object into the domain.

        If domain name is not provided then the default domain is used.

        :param name: Target SSSD domain name
        :type name: str
        :param role: Provider role object to use for import.
        :type role: BaseRole
        :raises ValueError: If unsupported provider is given.
        """
        if not isinstance(role.host, BaseDomainHost):
            raise ValueError(f"Host type {type(role.host)} can not be imported as domain")

        if name is None:
            name = self.default_domain

        if f"domain/{name}" not in self.config:
            raise ValueError(f'Domain "{name}" does not yet exist, create it first')

        self.dom(name).update(role.host.client)

    def config_dumps(self) -> str:
        """
        Get current SSSD configuration.

        :return: SSSD configuration.
        :rtype: str
        """
        return self.__config_dumps(self.config)

    def config_load(self) -> None:
        """
        Load remote SSSD configuration.
        """
        result = self.host.conn.exec(["cat", "/etc/sssd/sssd.conf"], log_level=ProcessLogLevel.Short)
        self.config.clear()
        self.config.read_string(result.stdout)

    def config_apply(self, check_config: bool = True, debug_level: str | None = "0xfff0") -> None:
        """
        Apply current configuration on remote host.

        :param check_config: Check configuration for typos, defaults to True
        :type check_config: bool, optional
        :param debug_level: Automatically set debug level to the given value, defaults to 0xfff0
        :type debug_level:  str | None, optional
        """
        cfg = self.__set_debug_level(debug_level)
        service_user = self.svc.get_property("sssd", "User")
        if service_user == "":
            service_user = "root"
        contents = self.__config_dumps(cfg)
        self.fs.write("/etc/sssd/sssd.conf", contents, mode="0600", user=service_user, group=service_user)

        if check_config:
            self.host.conn.run("sssctl config-check")

    def genconf(self, section: str | None = None) -> ProcessResult:
        """
        Exec ``sssd --genconf`` or ``sssd --genconf-section=section`` if ``section`` is not ``None``.

        :param section: Section that will be refreshed. Defaults to ``None``.
        :type section: str | None, optional
        :return: Result of the ran command.
        :rtype: ProcessResult
        """
        if section is None:
            return self.host.conn.exec(["/usr/sbin/sssd", "--genconf"])

        return self.host.conn.exec(["/usr/sbin/sssd", f"--genconf-section={section}"])

    def bring_offline(self) -> None:
        """
        Send SIGUSR1 to SSSD process in order to bring it offline and terminate
        existing connections.
        """
        self.logger.info(f"Bringing SSSD offline on {self.host.hostname}")
        self.host.conn.run("pkill --signal SIGUSR1 sssd", log_level=ProcessLogLevel.Error)

    def bring_online(self) -> None:
        """
        Send SIGUSR2 to SSSD process in order to bring it back online.
        """
        self.logger.info(f"Bringing SSSD online on {self.host.hostname}")
        self.host.conn.run("pkill --signal SIGUSR2 sssd", log_level=ProcessLogLevel.Error)

    def section(self, name: str) -> configparser.SectionProxy:
        """
        Get sssd.conf section.

        :param name: Section name.
        :type name: str
        :return: Section configuration object.
        :rtype: configparser.SectionProxy
        """
        return self.__get(name)

    def dom(self, name: str) -> configparser.SectionProxy:
        """
        Get sssd.conf domain section.

        :param name: Domain name.
        :type name: str
        :return: Section configuration object.
        :rtype: configparser.SectionProxy
        """
        return self.section(f"domain/{name}")

    def subdom(self, domain: str, subdomain: str) -> configparser.SectionProxy:
        """
        Get sssd.conf subdomain section.

        :param domain: Domain name.
        :type domain: str
        :param subdomain: Subdomain name.
        :type subdomain: str
        :return: Section configuration object.
        :rtype: configparser.SectionProxy
        """
        return self.section(f"domain/{domain}/{subdomain}")

    @property
    def domain(self) -> configparser.SectionProxy:
        """
        Default domain section configuration object.

        Default domain is the first domain imported by :func:`import_domain`.

        :raises ValueError: If no default domain is set.
        :return: Section configuration object.
        :rtype: configparser.SectionProxy
        """
        if self.default_domain is None:
            raise ValueError(f"{self.__class__}.default_domain is not set")

        return self.dom(self.default_domain)

    @domain.setter
    def domain(self, value: dict[str, str]) -> None:
        if self.default_domain is None:
            raise ValueError(f"{self.__class__}.default_domain is not set")

        self.config[f"domain/{self.default_domain}"] = value

    @domain.deleter
    def domain(self) -> None:
        if self.default_domain is None:
            raise ValueError(f"{self.__class__}.default_domain is not set")

        del self.config[f"domain/{self.default_domain}"]

    def __get(self, section: str) -> configparser.SectionProxy:
        self.config.setdefault(section, {})
        return self.config[section]

    def __set(self, section: str, value: dict[str, str]) -> None:
        self.config[section] = value

    def __del(self, section: str) -> None:
        del self.config[section]

    @property
    def sssd(self) -> configparser.SectionProxy:
        """
        Configuration of the sssd section of sssd.conf.
        """
        return self.__get("sssd")

    @sssd.setter
    def sssd(self, value: dict[str, str]) -> None:
        return self.__set("sssd", value)

    @sssd.deleter
    def sssd(self) -> None:
        return self.__del("sssd")

    @property
    def autofs(self) -> configparser.SectionProxy:
        """
        Configuration of the autofs section of sssd.conf.
        """
        return self.__get("autofs")

    @autofs.setter
    def autofs(self, value: dict[str, str]) -> None:
        return self.__set("autofs", value)

    @autofs.deleter
    def autofs(self) -> None:
        return self.__del("autofs")

    @property
    def ifp(self) -> configparser.SectionProxy:
        """
        Configuration of the ifp section of sssd.conf.
        """
        return self.__get("ifp")

    @ifp.setter
    def ifp(self, value: dict[str, str]) -> None:
        return self.__set("ifp", value)

    @ifp.deleter
    def ifp(self) -> None:
        return self.__del("ifp")

    @property
    def kcm(self) -> configparser.SectionProxy:
        """
        Configuration of the kcm section of sssd.conf.
        """
        return self.__get("kcm")

    @kcm.setter
    def kcm(self, value: dict[str, str]) -> None:
        return self.__set("kcm", value)

    @kcm.deleter
    def kcm(self) -> None:
        return self.__del("kcm")

    @property
    def nss(self) -> configparser.SectionProxy:
        """
        Configuration of the nss section of sssd.conf.
        """
        return self.__get("nss")

    @nss.setter
    def nss(self, value: dict[str, str]) -> None:
        return self.__set("nss", value)

    @nss.deleter
    def nss(self) -> None:
        return self.__del("nss")

    @property
    def pac(self) -> configparser.SectionProxy:
        """
        Configuration of the pac section of sssd.conf.
        """
        return self.__get("pac")

    @pac.setter
    def pac(self, value: dict[str, str]) -> None:
        return self.__set("pac", value)

    @pac.deleter
    def pac(self) -> None:
        return self.__del("pac")

    @property
    def pam(self) -> configparser.SectionProxy:
        """
        Configuration of the pam section of sssd.conf.
        """
        return self.__get("pam")

    @pam.setter
    def pam(self, value: dict[str, str]) -> None:
        return self.__set("pam", value)

    @pam.deleter
    def pam(self) -> None:
        return self.__del("pam")

    @property
    def ssh(self) -> configparser.SectionProxy:
        """
        Configuration of the ssh section of sssd.conf.
        """
        return self.__get("ssh")

    @ssh.setter
    def ssh(self, value: dict[str, str]) -> None:
        return self.__set("ssh", value)

    @ssh.deleter
    def ssh(self) -> None:
        return self.__del("ssh")

    @property
    def sudo(self) -> configparser.SectionProxy:
        """
        Configuration of the sudo section of sssd.conf.
        """
        return self.__get("sudo")

    @sudo.setter
    def sudo(self, value: dict[str, str]) -> None:
        return self.__set("sudo", value)

    @sudo.deleter
    def sudo(self) -> None:
        return self.__del("sudo")

    @staticmethod
    def __config_dumps(cfg: configparser.ConfigParser) -> str:
        """Convert configparser to string."""
        with StringIO() as ss:
            cfg.write(ss)
            ss.seek(0)
            return ss.read()

    def __set_debug_level(self, debug_level: str | None = None) -> configparser.ConfigParser:
        """Set debug level in all sections."""
        cfg = configparser.ConfigParser(interpolation=None)
        cfg.read_dict(self.config)

        if debug_level is None:
            return self.config

        sections = ["sssd", "autofs", "ifp", "kcm", "nss", "pac", "pam", "ssh", "sudo"]
        sections += [section for section in cfg.keys() if section.startswith("domain/")]

        for section in sections:
            cfg.setdefault(section, {})
            if "debug_level" not in cfg[section]:
                cfg[section]["debug_level"] = debug_level

        return cfg


class SSSDLogsPath(object):
    def __init__(self, sssd: SSSDUtils) -> None:
        self.__sssd: SSSDUtils = sssd

    @property
    def monitor(self) -> str:
        """Return path to SSSD monitor logs."""
        return "/var/log/sssd/sssd.log"

    @property
    def autofs(self) -> str:
        """Return path to SSSD autofs logs."""
        return "/var/log/sssd/sssd_autofs.log"

    @property
    def ifp(self) -> str:
        """Return path to SSSD ifp logs."""
        return "/var/log/sssd/sssd_ifp.log"

    @property
    def kcm(self) -> str:
        """Return path to SSSD kcm logs."""
        return "/var/log/sssd/sssd_kcm.log"

    @property
    def nss(self) -> str:
        """Return path to SSSD nss logs."""
        return "/var/log/sssd/sssd_nss.log"

    @property
    def pac(self) -> str:
        """Return path to SSSD pac logs."""
        return "/var/log/sssd/sssd_pac.log"

    @property
    def pam(self) -> str:
        """Return path to SSSD pam logs."""
        return "/var/log/sssd/sssd_pam.log"

    @property
    def ssh(self) -> str:
        """Return path to SSSD ssh logs."""
        return "/var/log/sssd/sssd_ssh.log"

    @property
    def sudo(self) -> str:
        """Return path to SSSD sudo logs."""
        return "/var/log/sssd/sssd_sudo.log"

    def domain(self, name: str | None = None) -> str:
        """
        Return path to SSSD domain log for given domain. If the domain name is
        not set then :attr:`SSSDUtils.default_domain` is used.

        :param name: Domain name, defaults to None (=:attr:`SSSDUtils.default_domain`)
        :type name: str | None, optional
        :return: Path to SSSD domain log.
        :rtype: str
        """
        if name is None:
            name = self.__sssd.default_domain

        return f"/var/log/sssd/sssd_{name}.log"


class SSSDCommonConfiguration(object):
    """
    Setup common SSSD configurations.

    This class provides shortcuts to setup SSSD for common scenarios.
    """

    def __init__(self, sssd: SSSDUtils) -> None:
        self.sssd: SSSDUtils = sssd
        """SSSD utils."""

    def local(self) -> None:
        """
        Create ``local`` SSSD domain for local users.

        This is a proxy domain that uses nss_files and PAM system-auth service.
        """
        self.sssd.dom("local").update(
            enabled="true",
            id_provider="proxy",
            proxy_lib_name="files",
            proxy_pam_target="system-auth",
        )
        self.sssd.default_domain = "local"

    def krb_provider(self, backend: KDC | GenericProvider) -> None:
        """
        Set auth_provider to krb5 and populate krb5 options.

        This method sets ``auth_provider=krb5`` and configures
        ``krb5_realm``, ``krb5_server``, and ``krb5_kpasswd`` based on
        the provided backend (KDC, IPA, or AD).

        :param backend: Backend role object (KDC, IPA, or AD).
        :type backend: KDC | GenericProvider
        """
        host = backend.host
        if not isinstance(host, BaseDomainHost):
            raise TypeError(f"Expected BaseDomainHost, got {type(host)}")

        host.client.setdefault("auth_provider", "krb5")
        host.client.setdefault("krb5_realm", host.realm)
        host.client.setdefault("krb5_server", host.hostname)
        host.client.setdefault("krb5_kpasswd", host.hostname)

    def krb5_auth(self, kdc: KDC, domain: str | None = None) -> None:
        """
        Configure auth_provider to krb5, using the KDC from the multihost
        configuration.

        #. Merge KDC configuration into the given domain (or default domain)
        #. Generate /etc/krb5.conf from given KDC role

        :param kdc: KDC role object.
        :type kdc: KDC
        :param domain: Existing domain name, defaults to None (= default domain)
        :type domain: str | None, optional
        :raises ValueError: if invalid domain is given.
        """
        if domain is None:
            domain = self.sssd.default_domain

        if domain is None:
            raise ValueError("No domain specified!")

        self.sssd.merge_domain(domain, kdc)
        self.sssd.fs.write("/etc/krb5.conf", kdc.config(), user="root", group="root", mode="0644")

    def kcm(self, kdc: KDC, *, local_domain: bool = True) -> None:
        """
        Configure Kerberos to allow KCM tests.

        #. Generate /etc/krb5.conf from given KDC role
        #. If ``local_domain`` is ``True``, create an SSSD domain ``local`` for local users

        :param kdc: KDC role object.
        :type kdc: KDC
        :param local_domain: Create ``local`` SSSD domain for local users, defaults to ``True``
        :type bool: If ``True`` a ``local`` SSSD domain for local users is created
        """
        self.sssd.fs.write("/etc/krb5.conf", kdc.config(), user="root", group="root", mode="0644")
        if local_domain:
            self.local()

    def sudo(self) -> None:
        """
        Configure SSSD with sudo.

        #. Select authselect sssd profile with 'with-sudo'
        #. Enable sudo responder
        """
        self.sssd.authselect.select("sssd", ["with-sudo"])
        self.sssd.enable_responder("sudo")

    def gssapi(self) -> None:
        """
        Configure SSSD with gssapi.

        #. Select authselect sssd profile with "with-gssapi" and "with-sudo"
        #. Configure SSSD pam_gssapi_services in SSSD configuration
        """

        self.sssd.authselect.select("sssd", ["with-gssapi", "with-sudo"])
        self.sssd.enable_responder("sudo")

        self.sssd.domain["pam_gssapi_services"] = "sudo, sudo-i"
        self.sssd.domain["pam_gssapi_check_upn"] = "False"

    def autofs(self) -> None:
        """
        Configure SSSD with autofs.

        #. Select authselect sssd profile
        #. Enable autofs responder
        """
        self.sssd.authselect.select("sssd")
        self.sssd.enable_responder("autofs")

    def mkhomedir(self) -> None:
        """
        Configure SSSD with mkhomedir and oddjobd.

        #. Select authselect sssd profile with 'with-mkhomedir'
        #. Start oddjobd.service
        """
        self.sssd.authselect.select("sssd", ["with-mkhomedir"])
        self.sssd.svc.start("oddjobd.service")

    def dyndns(self, device: str = "dummy0") -> None:
        """
        Configure SSSD for dynamic DNS.

        :param device: Network device, defaults to 'dummy0'
        :type device: str
        """
        self.sssd.domain["dyndns_update"] = "True"
        # Note: The default value is False for IPA.The IPA server updates the PTR record itself.
        self.sssd.domain["dyndns_update_ptr"] = "True"
        self.sssd.domain["dyndns_iface"] = device
        self.sssd.domain["dyndns_refresh_interval"] = "1"
        self.sssd.domain["dyndns_refresh_interval_offset"] = "5"

    def ldap_provider(
        self,
        server: str,
        naming_context: str,
        bind_user_dn: str,
        bind_password: str,
        subids: bool = False,
        cacert: str = "/etc/ipa/ca.crt",
        tls_reqcert: str = "demand",
        ssl: bool = False,
        config: dict[str, str] | None = None,
    ) -> None:
        """
        Configure SSSD to use the ldap_provider to connect to IPA or AD.
        This is an alternate configuration and should rarely be used. LDAP
        provider test cases should cover these scenarios.

        :param server: LDAP server.
        :type server: str
        :param naming_context: Naming context
        :type naming_context: str
        :param bind_user_dn: Bind user distinguished name.
        :type bind_user_dn: str
        :param bind_password: Bind password.
        :type bind_password: str
        :param subids: Enable subids, optional
        :type subids: bool
        :param cacert: CA certificate, defaults to'/etc/ipa/ca.crt'
        :type cacert: str
        :param tls_reqcert: Force TLS, defaults to 'demand'
        :type tls_reqcert: str
        :param ssl: Enable SSL, defaults to 'False'
        :type ssl: bool
        :param config: Additional configuration, optional
        :type config: dict[str, str] | None
        """
        self.sssd.domain.clear()
        self.sssd.domain.update(
            id_provider="ldap",
            auth_provider="ldap",
            ldap_uri=f"ldap://{server}",
            ldap_search_base=f"cn=accounts,{naming_context.strip()}",
            ldap_tls_reqcert=tls_reqcert,
            ldap_tls_cacert=cacert,
            ldap_default_bind_dn=bind_user_dn,
            ldap_default_authtok_type="password",
            ldap_default_authtok=bind_password,
        )

        if ssl:
            self.sssd.domain.update(
                ldap_uri=f"ldaps://{server}",
                ldap_id_use_start_tls="False",
            )

        if subids:
            self.sssd.domain.update(
                ldap_subid_ranges_search_base=f"cn=subids,cn=accounts,{naming_context.strip()}",
                ldap_subuid_object_class="ipasubordinateidentry",
                ldap_subuid_count="ipaSubUidCount",
                ldap_subgid_count="ipaSubGidCount",
                ldap_subuid_number="ipaSubUidNumber",
                ldap_subgid_number="ipaSubGidNumber",
                ldap_subid_range_owner="ipaOwner",
            )

        if config is not None and isinstance(config, dict):
            for key, value in config.items():
                self.sssd.domain[key] = value

        self.sssd.config_apply()

    def proxy(
        self,
        proxy: Literal["files", "ldap"] = "files",
        provider: str | list[str] = "id",
        proxy_pam_target: str | None = None,
        proxy_pam_stack: str | None = None,
        server_hostname: str | None = None,
        domain: str | None = None,
    ):
        """
        Configure files or ldap proxy domain.

        :param proxy: ``ldap`` or ``files``, defaults to ``files``
        :type proxy: Literal["files", "ldap"]
        :param provider: SSSD providers (``id``, ``auth``, ``chpass``, ...), defaults to ``id``
        :type provider: str | list[str]
        :param proxy_pam_target: SSSD option proxy_pam_target, defaults to
            ``None`` (= ``system-auth`` (files), ``sssdproxyldap`` (ldap))
        :type proxy_pam_target: str | None
        :param proxy_pam_stack: Custom PAM stack written to
            /etc/pam.d/@proxy_pam_target, defaults to ``None`` (= ignored (files), pam_ldap.so (ldap))
        :type proxy_pam_stack: str | None
        :param server_hostname: LDAP server hostname for ldap proxy (ldap), ignored (files), defaults to ``None``
        :type server_hostname: str | None
        :param domain: Proxy domain name, defaults to None (= default domain)
        :type domain: str | None, optional
        """
        if domain is None:
            domain = self.sssd.default_domain

        if domain is None:
            raise ValueError("No domain specified and default domain is not set!")

        if domain is not None and self.sssd.default_domain is None:
            self.sssd.default_domain = domain

        match proxy:
            case "ldap":
                if proxy_pam_target is None:
                    proxy_pam_target = "sssdproxyldap"

                if proxy_pam_stack is None:
                    proxy_pam_stack = """
                        auth     required pam_ldap.so
                        account  required pam_ldap.so
                        password required pam_ldap.so
                        session  required pam_ldap.so
                    """

                if server_hostname is None:
                    raise ValueError("No server_hostname specified!")

                self.sssd.fs.write(
                    "/etc/nslcd.conf", f"uid nslcd\ngid ldap\nuri ldap://{server_hostname}\n", dedent=False
                )
                self.sssd.svc.restart("nslcd")
            case "files":
                if proxy_pam_target is None:
                    proxy_pam_target = "system-auth"
            case _:
                raise ValueError(f"Unknown proxy type: {proxy}")

        if proxy_pam_stack is not None:
            self.sssd.fs.write(f"/etc/pam.d/{proxy_pam_target}", proxy_pam_stack)

        options = {
            "enabled": "true",
            "proxy_lib_name": proxy,
            "proxy_pam_target": proxy_pam_target,
            **{f"{x}_provider": "proxy" for x in to_list(provider)},
        }

        self.sssd.dom(domain).clear()
        self.sssd.dom(domain).update(options)

    def pam(self, features: list[str] | None = None) -> None:
        """
        Configure SSSD with pam.

        #. Select authselect sssd profile
        #. Enable pam responder in sssd profile

        :param features: list of authselect features
        :type features: list[str], optional
        """
        if features is None:
            features = []

        self.sssd.authselect.select("sssd", features)
        self.sssd.enable_responder("pam")

    def socket_responders(self, responders: list[str] | None = None) -> None:
        """
        Configure SSSD for socket-activated responders.

        Removes specified responders from the services line in sssd.conf
        to enable socket activation, while keeping other services running
        as traditional services.

        :param responders: List of responders to enable via socket activation.
                          If None, enables all known socket responders.
        :type responders: list[str] | None
        :raises RuntimeError: If starting a socket unit fails.
        """
        # All known SSSD responders that support socket activation
        all_responders = ["nss", "pam", "sudo", "ssh", "pac", "autofs"]

        if responders is None:
            responders = all_responders

        # Get current services list from the configuration
        current_services = self.sssd.sssd.get("services", "")

        # Parse the current services line
        services_list = [s.strip() for s in current_services.split(",")] if current_services else []

        # Remove responders that should use socket activation
        updated_services = [s for s in services_list if s not in responders]

        # Update the services line
        # - Empty string: all responders use socket activation
        # - Non-empty: listed services run as traditional, others use socket activation
        self.sssd.sssd["services"] = ", ".join(updated_services) if updated_services else ""

        # Ensure socket units are started using SystemdServices for proper management
        for responder in responders:
            socket_unit = f"sssd-{responder}.socket"
            self.sssd.svc.start(socket_unit)

    def subid(self) -> None:
        """
        Configure SSSD for subid.
        """
        self.sssd.authselect.select("sssd", ["with-subid"])
