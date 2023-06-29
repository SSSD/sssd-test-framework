"""Manage D-Bus operations"""

from __future__ import annotations

import re
import xml.etree.ElementTree as xml
from abc import ABC
from enum import Enum, auto
from typing import Any

from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.ssh import SSHProcessResult

__all__ = [
    "SBUSUtils",
    "DBUSBus",
    "Variant",
]


class DBUSBus(Enum):
    """
    Types of predefined D-Bus buses.
    """

    SYSTEM = auto()
    """The system bus"""
    SESSION = auto()
    """The session bus"""


class Variant:
    """
    Python representation for the D-Bus ``variant`` type.

    This is a container for other types.
    """

    def __init__(self, value):
        self.value = value
        """The actual value stored in the variant type"""


class DBUSObject(MultihostUtility[MultihostHost]):
    """
    D-Bus access.

    Objects of this class represent the root or child D-Bus nodes.
    """

    class ProxyAttribute(ABC):
        """
        Abstract class representing a D-Bus attribute (method or property).

        Corresponding concrete classes are provided for their instantiation.
        """

        def __init__(
            self,
            host: MultihostHost,
            dest: str,
            objpath: str,
            bus: str | DBUSBus,
            /,
            interface: str | None = None,
            child: xml.Element | None = None,
        ):
            match bus:
                case DBUSBus.SYSTEM:
                    _bus_param = "--system"
                case DBUSBus.SESSION:
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

        @classmethod
        def _get_dbus_type(cls, var):
            """
            Produce a basic python type from a text string describing a basic D-Bus type.
            """
            if isinstance(var, int):
                return "uint32"
            if isinstance(var, str):
                return "string"
            if isinstance(var, bool):
                return "boolean"
            raise TypeError(f"{type(var)} is not a basic type")

        @classmethod
        def _get_dbus_param(cls, var) -> str:
            """
            Produce a complex python type from a text string describing a possibly complex D-Bus type.
            """
            try:
                return f"{cls._get_dbus_type(var)}:{var}"
            except TypeError:
                pass

            if isinstance(var, Variant):
                return f"variant:{cls._get_dbus_param(var.value)}"

            if isinstance(var, list):
                val = f"array:{cls._get_dbus_type(var[0])}:"
                delim = ""
                for e in var:
                    val += delim + str(e)
                    delim = ","
                return val

            if isinstance(var, dict):
                k = list(var)[0]
                val = f"dict:{cls._get_dbus_type(k)}:{cls._get_dbus_type(var[k])}:"
                delim = ""
                for k, v in var.items():
                    val += f"{delim}{str(k)},{str(v)}"
                    delim = ","
                return val

            raise TypeError(f"Unhandled type {type(var)}")

        @classmethod
        def _get_python_dict(cls, text: str) -> dict[Any, Any]:
            """
            Produce a python list from a text string describing a D-Bus array.
            """
            text = text.strip()
            res = {}
            while len(text) > 0:
                (key, value), pos = cls._get_python_dict_entry(text)
                res[key] = value
                text = text[pos:].strip()

            return res

        @classmethod
        def _get_python_list(cls, text: str) -> list[Any]:
            text = text.strip()
            res = []
            while len(text) > 0:
                value, pos = cls._get_python_value(text)
                res.append(value)
                text = text[pos:].strip()

            return res

        @classmethod
        def _get_python_dict_entry(cls, text: str) -> tuple:
            """
            Produce a python dictionary from a text string describing a D-Bus dictionary.
            """
            key, pos1 = cls._get_python_value(text)
            value, pos2 = cls._get_python_value(text[pos1:])
            return (key, value), pos1 + pos2

        @classmethod
        def _get_python_value(cls, text: str) -> tuple:
            """
            Given a text string resulting from the invocation of ``dbus-send``,
            parse it and produce the equivalent structure in python types.
            """
            text = text.replace("\n", "")
            res = re.match("^ *u?int[0-9]{2} +([0-9]+)", text)
            if res is not None:
                return int(res.group(1)), res.span()[1]

            res = re.match('^ *(string|object +path) +"([^"]*)"', text)
            if res is not None:
                return res.group(2), res.span()[1]

            res = re.match("^ *boolean +(([Tt][Rr][Uu][Ee])|([Ff][Aa][Ll][Ss][Ee]))", text)
            if res is not None:
                return (res.group(1).lower() == "true"), res.span()[1]

            res = re.match("^ *variant +(.+) *$", text)
            if res is not None:
                value, _ = cls._get_python_value(res.group(1))
                return Variant(value), res.span()[1]

            res = re.match("^ *dict entry +\\((.+)\\)", text)
            if res is not None:
                return cls._get_python_dict_entry(res.group(1)), res.span()[1]

            # dbus-send doesn't return "dict {...}" but "array [ dict entry (...) ... ]"
            res = re.match("^ *array +\\[( *dict entry +.+)\\] *$", text)
            if res is not None:
                return cls._get_python_dict(res.group(1)), res.span()[1]

            res = re.match("^ *array +\\[(.+)\\] *$", text)
            if res is not None:
                return cls._get_python_list(res.group(1)), res.span()[1]

            raise TypeError(f"Unhandled D-Bus type {text}")

        def _run(self, command: str, *args):
            """
            Run dbus-send over ssh on the remote host.
            """
            cmd = self.cmd + f" {command}"
            for param in args:
                cmd += " " + self._get_dbus_param(param)

            rslt = self.host.ssh.run(cmd)
            if rslt.stdout_lines[0].startswith("method return"):
                lines = rslt.stdout_lines[1:]
            else:
                lines = rslt.stdout_lines

            return SSHProcessResult(rslt.rc, lines, rslt.stderr_lines)

    class ProxyProperty(ProxyAttribute):
        """
        A D-Bus property accessible as an object
        """

        # interface and child are mandatory for this class
        def __init__(
            self,
            host: MultihostHost,
            dest: str,
            objpath: str,
            bus: str | DBUSBus,
            /,
            interface: str,
            child: xml.Element,
        ):
            super().__init__(host, dest, objpath, bus, interface=interface, child=child)

        def get_value(self) -> Any:
            """
            Get the property's value
            """
            if self.child is None:
                raise RuntimeError("Execution failed: no child.")

            res = self._run("org.freedesktop.DBus.Properties.Get", self.interface, self.child.attrib["name"])
            if res.rc != 0:
                raise RuntimeError(res.stderr)

            value, _ = self._get_python_value(res.stdout)
            return value.value

        def set_value(self, value) -> None:
            """
            Set the property's value
            """
            if self.child is None:
                raise RuntimeError("Execution failed: no child.")

            res = self._run(
                "org.freedesktop.DBus.Properties.Set",
                self.interface,
                self.child.attrib["name"],
                Variant(value),
            )
            if res.rc != 0:
                raise RuntimeError(res.stderr)

    class ProxyMethod(ProxyAttribute):
        """
        A D-Bus method accessible as an object
        """

        def __call__(self, *args) -> Any:
            """
            Execute the method
            """
            if self.child is None:
                raise RuntimeError("Execution failed: no child.")

            method = f'{self.interface}.{self.child.attrib["name"]}'
            res = self._run(method, *args)
            if res.rc != 0:
                raise RuntimeError(f'Execution of \'{self.child.attrib["name"]}{args}\' failed: ' + res.stderr)

            value, _ = self._get_python_value(res.stdout)
            return value

    def __init__(self, host: MultihostHost, *, dest: str, objpath: str = "/", bus: str | DBUSBus = DBUSBus.SYSTEM):
        super().__init__(host)

        self._properties: dict[Any, Any] = {}
        self._objpath = objpath
        self._dest = dest
        self._bus = bus

        introspection = self.ProxyMethod(host, dest, objpath, bus)
        res = introspection._run("org.freedesktop.DBus.Introspectable.Introspect")
        if res.rc != 0:
            raise RuntimeError(f"Instrospection failed for {objpath}")

        xmlstr = res.stdout.removeprefix('   string "').removesuffix('"')
        self._xml = xml.fromstring(xmlstr)

    @classmethod
    def _find_child(cls, root, name: str):
        """
        Find an XML child element of the given name.
        """
        for child in root:
            if child.attrib["name"] == name:
                return child
            if child.tag == "interface":
                res = cls._find_child(child, name)
                if res is not None:
                    return res

        return None

    def _find_interface(self, elem: xml.Element) -> xml.Element | None:
        """
        Find the interface the provided XML element belongs to.
        """
        for child in self._xml:
            if child.tag == "interface":
                found = self._find_child(child, elem.attrib["name"])
                if found == elem:
                    return child

        return None

    def _make_prop(self, child: xml.Element) -> ProxyProperty:
        """
        Add a D-Bus proxy property to the current node.
        """
        iface = self._find_interface(child)
        if iface is None:
            raise RuntimeError(f"No interface found for {child.attrib['name']}")

        prop = self.ProxyProperty(
            self.host, self._dest, self._objpath, self._bus, interface=iface.attrib["name"], child=child
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

        method = self.ProxyMethod(
            self.host, self._dest, self._objpath, self._bus, interface=iface.attrib["name"], child=child
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
        When an acccessing an attribute that doesn't belong to the object,
        create it if it should exist.
        """

        # Required for the initialization
        if attr == "_properties":
            return {}

        if attr in self._properties:
            return self._properties[attr].get_value()

        c = self._find_child(self._xml, attr)
        if c is not None:
            return self._make_attr(c)

        return super().__getattribute__(attr)

    def __setattr__(self, attr: str, value: Any) -> None:
        """
        If the caller sets a property, invoke the set_value() method
        of the corresponding proxy property.
        """
        if attr in self._properties:
            return self._properties[attr].set_value(value)
        return super().__setattr__(attr, value)

    def __enter__(self):
        return self

    def __exit__(*args):
        pass


class SBUSInfoPipe(DBUSObject):
    """
    Specific case of the InfoPipe D-Bus object.
    """

    def __init__(self, host: MultihostHost):
        super().__init__(host, dest="org.freedesktop.sssd.infopipe", objpath="/org/freedesktop/sssd/infopipe")


class SBUSUtils:
    """
    Tool to access D-Bus from a host.
    """

    def __init__(self, host: MultihostHost):
        self._host = host
        self.ifp = SBUSInfoPipe(host)
        """Always exists and can be used to access ``infopipe``."""

    def getObject(self, *, dest: str, objpath: str = "/", bus: str | DBUSBus = DBUSBus.SYSTEM):
        """
        Creates and returns an object representing the D-Bus object on the given *bus*,
        *destination* and *object path*.

        :param dest: Destination application to contact.
        :type dest: str
        :param objpath: Path to the root object to address in the destination. Defaults to ``/``.
        :type objpath: str, optional
        :param bus: The bus to use for the communications. Defaults to ``DBUSBus.SYSTEM``.
            For other cases, a string can be provided with the explicit bus path.
        :type bus: str | DBUSBus, optional
        """
        return DBUSObject(self._host, dest=dest, objpath=objpath, bus=bus)

    def __enter__(self):
        return self

    def __exit__(*args):
        pass
