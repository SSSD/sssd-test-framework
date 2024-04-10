"""Manage D-Bus operations"""

from __future__ import annotations

import xml.etree.ElementTree as xml
from abc import ABC
from typing import Any, Final

from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.ssh import SSHProcessResult

from .dbus.types import DBUSResult, DBUSSignatureReader, DBUSType, DBUSTypeString, DBUSTypeVariant

__all__ = [
    "DBUSDestination",
    "DBUSKnownBus",
]


class DBUSKnownBus(str):
    """
    Weel-known D-Bus buses.
    """

    SYSTEM: Final = "--SYSTEM--"
    """The system bus"""

    SESSION: Final = "--SESSION--"
    """The session bus"""

    MONITOR: Final = "unix:path=/var/lib/sss/pipes/private/sbus-monitor"
    """Monitor's private bus"""


class ProxyObject(ABC):
    """
    Abstract class representing a D-Bus object (method or property).

    Corresponding concrete classes are provided for their instantiation.
    """

    def __init__(
        self,
        host: MultihostHost,
        dest: str,
        objpath: str,
        bus: str,
        /,
        interface: str | None = None,
        child: xml.Element | None = None,
    ):
        """
        Constructor to be called by the subclasses either explicitely or by inheritance.
        """
        match bus:
            case DBUSKnownBus.SYSTEM:
                _bus_param = "--system"
            case DBUSKnownBus.SESSION:
                _bus_param = "--session"
            case _:
                _bus_param = "--bus=" + bus

        self.host = host
        self.dest = dest
        self.objpath = objpath
        self.bus = bus
        self.interface = objpath[1:].replace("/", ".") if interface is None else interface
        self.child = child
        self.cmd = f"dbus-send {_bus_param} --print-reply --dest={dest} {self.objpath}"

    def _run(self, command: str, *args):
        """
        Run dbus-send over ssh on the remote host.
        """
        cmd = self.cmd + f" {command}"
        for arg in args:
            cmd += " " + arg.param()

        result = self.host.ssh.run(cmd)
        if result.stdout_lines[0].startswith("method return"):
            lines = result.stdout_lines[1:]
        else:
            lines = result.stdout_lines

        return SSHProcessResult(result.rc, lines, result.stderr_lines)


class ProxyProperty(ProxyObject):
    """
    A D-Bus property accessible as an object
    """

    # interface and child are mandatory for this class
    def __init__(
        self,
        host: MultihostHost,
        dest: str,
        objpath: str,
        bus: str,
        /,
        interface: str,
        child: xml.Element,
        type: DBUSType,
    ):
        super().__init__(host, dest, objpath, bus, interface=interface, child=child)
        # Properties always return a variant of the provided type.
        self.type: DBUSTypeVariant = DBUSTypeVariant(type)
        # access can be "read", "write" or "readwrite"
        self.readable = "read" in child.attrib["access"]
        self.writable = "write" in child.attrib["access"]
        self.arg_interface = DBUSTypeString()
        self.arg_interface.value = self.interface
        self.arg_name = DBUSTypeString()
        self.arg_name.value = self.child.attrib["name"]  # type: ignore[union-attr]

    def get_value(self) -> Any:
        """
        Get the property's value
        """
        if not self.readable:
            raise PermissionError("Execution failed: not a readable property")

        res = self._run("org.freedesktop.DBus.Properties.Get", self.arg_interface, self.arg_name)
        if res.rc != 0:
            raise RuntimeError(res.stderr)

        ret = self.type.mimic()
        ret.parse(DBUSResult(res.stdout))
        return ret.value

    def set_value(self, value) -> None:
        """
        Set the property's value
        """
        if not self.writable:
            raise RuntimeError("Execution failed: not a writable property")

        val = self.type.mimic()
        val.value = value

        res = self._run("org.freedesktop.DBus.Properties.Set", self.arg_interface, self.arg_name, val)
        if res.rc != 0:
            raise RuntimeError(res.stderr)


class ProxyMethod(ProxyObject):
    """
    A D-Bus method accessible as an object
    """

    def __init__(
        self,
        host: MultihostHost,
        dest: str,
        objpath: str,
        bus: str,
        /,
        interface: str | None = None,
        child: xml.Element | None = None,
        input: list[DBUSType] | None = None,
        output: list[DBUSType] | None = None,
    ):
        super().__init__(host, dest, objpath, bus, interface, child)
        self.input = input
        self.output = output

    def __call__(self, *args) -> Any:
        """
        Execute the method
        """
        # In some internal cases we don't provide the child nor the interface at
        # at instantiation because we don't use them, but on normal calls they are
        # required.
        if self.child is None:
            raise RuntimeError("Execution failed: no child.")
        if self.interface is None:
            raise RuntimeError("Execution failed: no interface.")

        objargs = []
        if self.input is not None:
            for i in range(len(self.input)):
                obj = self.input[i].mimic()
                try:
                    obj.value = args[i]
                except IndexError:
                    raise RuntimeError(
                        f"Execution failed: {len(self.input)} " f"arguments required but only {i} provided."
                    )
                objargs.append(obj)

        method = f'{self.interface}.{self.child.attrib["name"]}'
        res = self._run(method, *tuple(objargs))
        if res.rc != 0:
            raise RuntimeError(f'Execution of \'{self.child.attrib["name"]}{args}\' failed: ' + res.stderr)

        if self.output is None:
            ret = None
        else:
            values = []
            result = DBUSResult(res.stdout)
            for i in range(len(self.output)):
                obj = self.output[i].mimic()
                obj.parse(result)
                values.append(obj.value)

            ret = tuple(values) if len(values) > 1 else values[0]

        return ret


class DBUSObject:
    """
    A D-Bus object accesible as a Python object.

    Objects of this class represent D-Bus nodes.
    """

    def __init__(self, host: MultihostHost, *, dest: str, objpath: str, bus: str):
        self.host = host
        self._properties: dict[Any, Any] = {}
        self._objpath = objpath
        self._dest = dest
        self._bus = bus

        introspection = ProxyMethod(host, dest, objpath, bus)
        res = introspection._run("org.freedesktop.DBus.Introspectable.Introspect")
        if res.rc != 0:
            raise RuntimeError(f"Instrospection failed for {objpath}")

        xmlstr = res.stdout.removeprefix('   string "').removesuffix('"')
        self._xml = xml.fromstring(xmlstr)

    def _find_child_node(self, root, name: str):
        """
        Find an XML child element of the given name.
        """
        for child in root:
            if child.attrib["name"] == name:
                return child
            if child.tag == "interface":
                res = self._find_child_node(child, name)
                if res is not None:
                    return res

        return None

    def _find_interface(self, elem: xml.Element) -> xml.Element | None:
        """
        Find the interface the provided XML element belongs to.
        """
        for child in self._xml:
            if child.tag == "interface":
                found = self._find_child_node(child, elem.attrib["name"])
                if found == elem:
                    return child

        return None

    def _get_method_args(self, method: xml.Element, dir: str) -> list[DBUSType]:
        """
        Get a list of DBUSType objects produced from the given method's signature.

        The direction must be "in" or "out."
        """
        params = []
        for arg in method:
            if arg.tag == "arg" and arg.attrib["direction"] == dir:
                params.append(DBUSSignatureReader.read(arg.attrib["type"]))
        return params

    def _get_property_type(self, prop: xml.Element) -> DBUSType:
        return DBUSSignatureReader.read(prop.attrib["type"])

    def _make_prop(self, child: xml.Element) -> ProxyProperty:
        """
        Add a D-Bus proxy property to the current node.
        """
        iface = self._find_interface(child)
        if iface is None:
            raise RuntimeError(f"No interface found for {child.attrib['name']}")

        type = self._get_property_type(child)

        prop = ProxyProperty(
            self.host, self._dest, self._objpath, self._bus, interface=iface.attrib["name"], child=child, type=type
        )
        self._properties[child.attrib["name"]] = prop
        return prop.get_value()

    def _make_method(self, child) -> ProxyMethod:
        """
        Add a D-Bus proxy method to the current node.
        """
        iface = self._find_interface(child)
        if iface is None:
            raise RuntimeError(f"No interface found for {child.attrib['name']}")

        input = self._get_method_args(child, "in")
        output = self._get_method_args(child, "out")

        method = ProxyMethod(
            self.host,
            self._dest,
            self._objpath,
            self._bus,
            interface=iface.attrib["name"],
            child=child,
            input=input,
            output=output,
        )
        self.__setattr__(child.attrib["name"], method)
        return method

    def _make_node(self, child) -> DBUSObject:
        """
        Add a D-Bus child node to the current node.
        """
        node = DBUSObject(
            self.host, objpath=self._objpath + "/" + child.attrib["name"], dest=self._dest, bus=self._bus
        )
        self.__setattr__(child.attrib["name"], node)
        return node

    def _make_attr(self, child):
        """
        Make a D-Bus attribute and add it to the current node.
        """
        match child.tag:
            case "property":
                obj = self._make_prop(child)
            case "method":
                obj = self._make_method(child)
            case "node":
                obj = self._make_node(child)
            case _:
                raise AttributeError(
                    f"'{self.__class__.__name__}' object has an attribute '{child.attrib['name']}'"
                    f" of unkown type '{child.tag}'"
                )

        return obj

    def __getattr__(self, attr) -> Any:
        """
        When acccessing an attribute that doesn't belong to the object,
        create it if it should exist.
        """

        # This check avoids extra and recursive calls during object initialization
        if "_properties" in self.__dict__ and attr in self._properties:
            return self._properties[attr].get_value()

        # This check avoids extra and recursive calls during object initialization
        # if "_find_child" in self.__dict__ and "_xml" in self.__dict__:
        if "_xml" in self.__dict__:
            c = self._find_child_node(self._xml, attr)
            if c is not None:
                return self._make_attr(c)

        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{attr}'")

    def __setattr__(self, attr: str, value: Any) -> None:
        """
        If the caller sets a property, invoke the set_value() method
        of the corresponding proxy property.
        """
        # This check avoids extra and recursive calls during object initialization
        if "_properties" in self.__dict__ and attr in self._properties:
            return self._properties[attr].set_value(value)

        return super().__setattr__(attr, value)


class DBUSDestination(MultihostUtility[MultihostHost]):
    def __init__(self, host: MultihostHost, dest: str, bus: str):
        """
        Create a destination object associated to a bus and a name.

        .. code-block:: python
            :caption: Example

            monitor = DBUSDestination(client.host, dest="sssd.monitor", bus=DBUSKnownBus.MONITOR)

            paths = monitor.getObjectPaths()
            assert len(paths) == 2
            assert "/" in paths
            assert "/sssd" in paths

            sssd = monitor.getObject(objpath="/sssd")
            sssd.debug_level = 0x0070
            assert sssd.debug_level == 0x0070

        .. _test code:
           https://github.com/aplopez/sssd/blob/dbus/src/tests/system/tests/test_infopipe.py

        A few more examples can be seen in the `test code`_.

        :param host: The host where the D-Bus serices run.
        :type host: MultihostHost
        :param dest: Destination application to contact.
        :type dest: str
        :param bus: The bus to use for the communications. Defaults to ``DBUSBus.SYSTEM``.
            For other cases, a string can be provided with the explicit bus path.
        :type bus: str | DBUSBus, optional
        """
        super().__init__(host)
        self._dest = dest
        self._bus = bus
        self._objPaths: list[str] | None = None

    def _introspect(self, objPath: str) -> xml.Element:
        introspection = ProxyMethod(self.host, self._dest, objPath, self._bus)
        res = introspection._run("org.freedesktop.DBus.Introspectable.Introspect")
        if res.rc != 0:
            raise RuntimeError(f"Introspection failed for {objPath}")

        xmlstr = res.stdout.removeprefix('   string "').removesuffix('"')
        return xml.fromstring(xmlstr)

    def _listNodes(self, path: str) -> list[str]:
        lst: list[str] = []

        root = self._introspect(path)
        if root.tag == "node":
            lst.append(path)
            for child in root:
                if child.tag == "node":
                    childPath = (path if path != "/" else "") + "/" + child.attrib["name"]
                    lst += self._listNodes(childPath)

        return lst

    def getObjectPaths(self) -> list[str]:
        """
        Returns the list of the paths available at this destination.
        """
        if self._objPaths is None:
            self._objPaths = self._listNodes("/")

        return self._objPaths

    def getObject(self, objpath: str) -> DBUSObject:
        """
        Creates and returns an object representing the D-Bus object and *object path*
        associated to the *destination*.

        :param objpath: The path to the object at destination.
        :type objpath: str
        """
        return DBUSObject(self.host, dest=self._dest, objpath=objpath, bus=self._bus)
