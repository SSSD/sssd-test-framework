"""IP utility."""

from __future__ import annotations

from typing import Any

import jc
from pytest_mh import MultihostHost, MultihostUtility

__all__ = [
    "IPUtils",
]


class IPUtils(MultihostUtility[MultihostHost]):
    """
    IP utilities.

    .. code-block:: python
        :caption: Example usage

        # Create dummy interfaces
        client.ip.add(dev="dummy1", ip="172.16.151240", netmask="255.255.255.0")

        # Netmask also accepts the CIDR notation.
        client.ip.add(dev="dummy2", ip="172.16.151.40", netmask="24")

        # Get the default gateway
        gw: = client.ip.gateway

        # Get all device information
        config = client.ip.get([])
    """

    def __init__(self, host: MultihostHost) -> None:
        """
        :param host: Remote host.
        :type host: MultihostHost
        """
        super().__init__(host)
        self._dev: str | None = None
        self.__rollback: list[str] = []

    def teardown(self):
        """
        Revert all changes.

        :meta private:
        """
        cmd = "\n".join(reversed(self.__rollback))
        if cmd:
            self.host.conn.run(cmd)

        super().teardown()

    def _get_default_dev(self) -> str:
        """Get default device name."""
        result = jc.parse("ip-route", self.host.conn.exec(["ip", "route"]).stdout)

        if isinstance(result, list):
            for i in result:
                if isinstance(i, dict):
                    if "default" in i.values():
                        dev = str(i.get("dev"))
        return dev

    @property
    def gateway(self) -> Any | None:
        """Get default gateway."""
        result = jc.parse("ip-route", self.host.conn.exec(["ip", "route"]).stdout)
        if isinstance(result, list):
            if isinstance(result[0], dict):
                return result[0].get("via")
        else:
            raise LookupError("Gateway not found!")

    @property
    def nameservers(self) -> Any | None:
        """Get nameservers."""
        result = jc.parse("resolve-conf", self.host.conn.exec(["cat", "/etc/resolv.conf"]).stdout)
        if isinstance(result, dict):
            return result.get("nameservers")
        else:
            raise LookupError("Nameservers not found!")

    @property
    def dev(self) -> str:
        """Get device name."""
        if self._dev is None:
            self._dev = self._get_default_dev()

        return self._dev

    def get(self, args: list[str] | str = ["name", "ipv4_addr", "ipv4_mask"]) -> dict[Any, Any]:
        """
        Get device configuration values, defaults to ["name", "ipv4_addr", "ipv4_mask"].

        Additional useful keys are ["type","mac_addr","ipv6_addr", "ipv6_mask", "ipv6_type", "ipv6_scope"].
        Optionally, set an empty list to retrieve all values.

        :param args: List of configuration keys, defaults to ["name", "ipv4_addr", "ipv4_mask"]
        :type args: list[str] = ["name", "ipv4_addr", "ipv4_mask]
        :return: Dictionary of configuration keys and values.
        :rtype: dict[str, str | dict | list]
        """
        config = {}
        if self._dev is None:
            self._get_default_dev()

        if isinstance(args, str):
            args = [args]

        result = jc.parse("ifconfig", self.host.conn.exec(["ifconfig", "-a"]).stdout)
        if isinstance(result, list) and len(result) > 0:
            for i in result:
                if isinstance(i, dict):
                    if self._dev == i.get("name"):
                        for j, k in i.items():
                            if not args:
                                config[j] = k
                            else:
                                if j in args:
                                    config[j] = k
        return config

    @property
    def address(self) -> dict[Any, Any]:
        """Get ip address."""
        return self.get("ipv4_addr")

    @property
    def netmask(self) -> dict[Any, Any]:
        """Get network mask."""
        return self.get(["ipv4_mask"])

    def add(self, dev: str, ip: str, netmask: str = "255.255.255.0") -> IPUtils:
        """
        Add and create a link to a dummy device.This is used by dyndns tests.

        :param dev: Device name.
        :type dev: str
        :param ip: IP address.
        :type ip: str
        :param netmask: IP network mask, defaults to 255.255.255.0
        :type netmask: str, optional
        :return: IPUtils object.
        :rtype: IPUtils
        """
        self._dev = dev

        if self._dev == self._get_default_dev():
            raise Exception(f"Modifying the default dev {self._dev} will render the system unresponsive!")

        self.host.conn.exec(["ip", "link", "add", self._dev, "type", "dummy"])
        self.host.conn.exec(["ip", "addr", "add", f"{ip}/{netmask}", "dev", self._dev])

        self.__rollback.append(f"ip link del {self._dev}")

        return self
