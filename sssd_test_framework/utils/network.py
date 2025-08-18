"""Network utilities."""

from __future__ import annotations

from typing import Any

import jc
from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.conn import ProcessResult
from pytest_mh.utils.fs import LinuxFileSystem

from ..misc.ssh import SSHKillableProcess

__all__ = ["NetworkUtils", "IPUtils"]


class NetworkUtils(MultihostUtility[MultihostHost]):

    def __init__(self, host: MultihostHost, fs: LinuxFileSystem) -> None:
        """
        :param host: Remote host.
        :type host: MultihostHost
        :param fs: File system object.
        :type fs: LinuxFileSystem
        """
        super().__init__(host)

        self.fs: LinuxFileSystem = fs

        self.__fs: LinuxFileSystem = fs
        self.__rollback: list[str] = []
        self.__ips: list[IPUtils] = []

    def ip(self, name: str | None = None) -> IPUtils:
        """
        Run ip commands.
        """
        inst = IPUtils(self.host, self.fs, name)
        self.__ips.append(inst)

        return inst

    def tcpdump(self, pcap_path: str, args: list[Any] | None = None) -> SSHKillableProcess:
        """
        Run tcpdump. The packets are captured in ``pcap_path``.

        :param pcap_path: Path to the capture file.
        :type pcap_path: str
        :param args: Arguments to ``tcpdump``, defaults to None
        :type args: list[Any] | None, optional
        :return: Killable process.
        :rtype: SSHKillableProcess
        """
        if args is None:
            args = []

        self.__fs.backup(pcap_path)

        command = SSHKillableProcess(self.host.conn, ["tcpdump", *args, "-w", pcap_path])

        # tcpdump requires some time to process and capture packets
        command.kill_delay = 1

        return command

    def tshark(self, args: list[Any] | None = None) -> ProcessResult:
        """
        Execute tshark command with given arguments.

        :param args: Arguments to ``tshark``, defaults to None
        :type args: list[Any] | None, optional
        :return: SSH Process result
        :rtype: ProcessResult
        """
        if args is None:
            args = []

        return self.host.conn.exec(["tshark", *args])

    def dig(self, args: list[Any] | None = None) -> Any:
        """
        Execute and parse dig command with given arguments.

        Useful keys and values,
        {"status":  "NOERROR"}, query is a success.
        {"status":  "NXDOMAIN"}, query did not return any results.

        {"answer_num": int}, number of results.
        {"answer": list[dict{name: str, class: str, type: str, ttl: int, data: str}]

        When querying a server, the results may have several answers. If you need a simple does it exist assertion,
        use ``nslookup``.

        :param args: Arguments to ``dig``, defaults to None
        :type args: list[Any] | None, optional
        :return: JC parsed dictionary of results.
        :rtype: Any
        """
        if args is None:
            args = []

        return jc.parse("dig", self.host.conn.exec(["dig", *args]).stdout)

    def nslookup(self, args: list[str]) -> ProcessResult:
        """
        Execute nslookup command with given arguments.

        :param args: Arguments to ``nslookup``, defaults to None
        :type args: list[str]
        :return: SSH Process result
        :rtype: ProcessResult
        """

        return self.host.conn.exec(["nslookup", *args], raise_on_error=False)

    def teardown(self):
        """
        Revert all changes.

        :meta private:
        """
        errors = []
        for ip in self.__ips:
            try:
                ip.teardown()
            except Exception as e:
                self.logger.warning("Failed to teardown %s: %s", ip, e)
                errors.append({"ip": ip, "error": e})

        cmd = "\n".join(reversed(self.__rollback))
        if cmd:
            self.host.conn.run(cmd)

        if errors:
            raise ExceptionGroup(errors)
        super().teardown()


class IPUtils(MultihostUtility[MultihostHost]):
    """
    IP  utilities.

    .. code-block:: python
        :caption: Example usage

        # Create dummy interfaces
        client.net.ip(name="dummy0").add_device(ip="172.16.2.40", netmask="255.255.255.0")
        client.net.ip(name="dummy0").add_device(ip="172.16.2.40", netmask="24")
        client.net.ip(name="dummy0").add_device(ip="172.16.2.40")

        # Get default device
        default_device  = client.net.ip().default_device

        # Get default gateway
        gateway_ip = client.net.ip().default_gateway
    """

    def __init__(self, host: MultihostHost, fs: LinuxFileSystem, name: str | None) -> None:
        """
        :param host: Remote host.
        :type host: MultihostHost
        :param fs: File system object.
        :type fs: LinuxFileSystem
        :param name: Name of interface.
        :type name: str | None
        """
        super().__init__(host)

        self._name: str | None = name
        """Device name."""

        self._ifconfig_stdout: Any | None = None
        """Ifconfig output."""

        self.default_device: Any | None = self._get_route()[0]
        """Default device."""

        self.default_gateway: Any | None = self._get_route()[1]
        """Default gateway."""

        self.__fs: LinuxFileSystem = fs
        self.__rollback: list[str] = []

    @property
    def name(self) -> Any | None:
        """Device name."""
        if self._name is not None:
            return self._name
        else:
            self._name = self.default_device
            return self._name

    def _get(self, args: list[str] | None = None) -> dict[str, Any | None]:
        """
        Get and parses ifconfig output.

        :param args: List of keys to return, defaults to None
        :type args: list[str] | None, optional
        :return: Keys and values.
        :rtype: dict[str, Any | None]
        """
        if self._ifconfig_stdout is not None:
            result = self._ifconfig_stdout
        else:
            result = jc.parse("ifconfig", self.host.conn.exec(["ifconfig", "-a"]).stdout)
            self._ifconfig_stdout = result

        parsed_results = {}
        if isinstance(result, list) and len(result) > 0:
            for i in result:
                if isinstance(i, dict) and self.name == i.get("name"):
                    if args is None:
                        return i
                    else:
                        for y in args:
                            parsed_results[y] = i.get(y)

        return parsed_results

    def _get_route(self) -> tuple[Any | None, Any | None]:
        """
        Get default gateway device name and ip.

        :return: Default gateway  device name and ip.
        :rtype: tuple[Any | None, Any | None]
        """
        result = jc.parse("ip-route", self.host.conn.exec(["ip", "route"]).stdout)
        if isinstance(result, list):
            if isinstance(result[0], dict) and result[0]["ip"] == "default":
                device_name = result[0].get("dev")
                device_ip = result[0].get("via")

        return device_name, device_ip

    @property
    def nameservers(self) -> Any | None:
        """Get nameservers."""
        result = jc.parse("resolve-conf", self.host.conn.exec(["cat", "/etc/resolv.conf"]).stdout)
        if not isinstance(result, dict):
            raise TypeError("Nameservers is the wrong type, expecting a dictionary!")
        else:
            nameservers = result.get("nameservers")
            return nameservers

    @property
    def address(self) -> Any | None:
        """Get ipv4 address."""
        return self._get(["ipv4_addr"]).get("ipv4_addr")

    @property
    def addresses(self) -> tuple[Any | None, Any | None]:
        """Get ipv4 and ipv6 addresses."""
        ipv4 = self._get(["ipv4_addr"]).get("ipv4_addr")
        ipv6 = self._get(["ipv6_addr"]).get("ipv6_addr")
        return ipv4, ipv6

    @property
    def netmask(self) -> str | None:
        """Get network mask."""
        netmask = self._get(["ipv4_mask"]).get("ipv4_mask")
        return netmask if netmask is not None else None

    def add_device(self, ip: str, netmask: str = "255.255.255.0") -> IPUtils:
        """
        Add and create a link to a dummy device.This is used by dyndns tests.

        :param ip: IP address.
        :type ip: str
        :param netmask: IP network mask, defaults to 255.255.255.0
        :type netmask: str, optional
        :return: IPUtils object.
        :rtype: IPUtils
        """
        if self.name != self.default_device or self.name is not None:
            self.host.conn.exec(["ip", "link", "add", self.name, "type", "dummy"])
            self.host.conn.exec(["ip", "addr", "add", f"{ip}/{netmask}", "dev", self.name])
            self.__rollback.append(f"ip link del {self.name}")
            return self
        else:
            raise Exception(f"Modifying the default {self.name} will render the system unresponsive!")

    def teardown(self):
        """
        Revert all changes.

        :meta private:
        """
        cmd = "\n".join(reversed(self.__rollback))
        if cmd:
            self.host.conn.run(cmd)

        super().teardown()
