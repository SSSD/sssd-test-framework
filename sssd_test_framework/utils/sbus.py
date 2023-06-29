"""Manage D-Bus operations"""

from __future__ import annotations

import re
import xml.etree.ElementTree as xml
from abc import ABC, abstractmethod
from enum import Enum, auto
from typing import Any

from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.ssh import SSHProcessResult

__all__ = [
    "SBUSUtils",
    "DBUSBus",
    "DBUSTypeVariant",
]


class DBUSBus(Enum):
    """
    Types of predefined D-Bus buses.
    """

    SYSTEM = auto()
    """The system bus"""
    SESSION = auto()
    """The session bus"""


class DBUSResult:
    """
    The result from the D-Bus operation executed by dbus-send.
    It is used to simplify parsing of the result as the string
    must be modified.
    """

    def __init__(self, text: str):
        self.text = text.replace("\n", "")


class DBUSType(ABC):
    """
    Abstract class to create classes thta handle type conversion
    between D-Bus and Python.

    It is important to know that dbus-send does not have a simetric
    behavior with relation to how the types are described as text
    when used as parameters or results.
    """

    class Types(Enum):
        """
        Identifiers for the D-Bus types.
        """

        INTEGER = auto()
        BOOLEAN = auto()
        STRING = auto()
        ARRAY = auto()
        DICT = auto()
        VARIANT = auto()

        @classmethod
        def get_dbus_type(cls, var):
            if isinstance(var, int):
                return cls.INTEGER

            if isinstance(var, bool):
                return cls.BOOLEAN

            if isinstance(var, str):
                return cls.STRING

            if isinstance(var, list):
                return cls.ARRAY

            if isinstance(var, dict):
                return cls.DICT

            if isinstance(var, DBUSTypeVariant):
                return cls.VARIANT

            raise TypeError(f"Unhandled type {type(var)}")

        @classmethod
        def get_dbus_object(cls, var) -> DBUSType:
            """
            Resturn a concrete instance of a DBUSType object based on the
            type of ``var``.
            """
            type = cls.get_dbus_type(var)
            match type:
                case cls.INTEGER:
                    return DBUSTypeInteger(var)

                case cls.BOOLEAN:
                    return DBUSTypeBoolean(var)

                case cls.STRING:
                    return DBUSTypeString(var)

                case cls.ARRAY:
                    return DBUSTypeArray(var)

                case cls.DICT:
                    return DBUSTypeDict(var)

                case cls.VARIANT:
                    return var

                case _:
                    raise TypeError(f"Unknown type {type}")

        def __str__(self):
            match self:
                case self.INTEGER:
                    return "uint32"
                case self.BOOLEAN:
                    return "boolean"
                case self.STRING:
                    return "string"
                case self.ARRAY:
                    return "array"
                case self.DICT:
                    return "dict"
                case self.VARIANT:
                    return "variant"
            return self.__repr__()

    def __init__(self, value):
        self.value = value
        """The actual value stored as a python type"""

    @classmethod
    def get_dbus_param(cls, var) -> str:
        """
        Produce a text string describing a possibly complex D-Bus type from a
        possibly complex python type. The resulting string will be suitable for
        use with ``dbus-send``.
        """
        return cls.Types.get_dbus_object(var).build()

    @classmethod
    def get_python_value(cls, result: DBUSResult):
        """
        Given a text string resulting from the invocation of ``dbus-send``,
        parse it and produce the equivalent structure in python types.
        """
        try:
            return DBUSTypeInteger.parse(result).value
        except TypeError:
            pass

        try:
            return DBUSTypeBoolean.parse(result).value
        except TypeError:
            pass

        try:
            return DBUSTypeString.parse(result).value
        except TypeError:
            pass

        try:
            return DBUSTypeVariant.parse(result).value
        except TypeError:
            pass

        # Because a dictionary is represented as a special case of an array,
        # we better try to identify it before a generic array.
        try:
            return DBUSTypeDict.parse(result).value
        except TypeError:
            pass

        try:
            return DBUSTypeArray.parse(result).value
        except TypeError:
            pass

        raise TypeError("Unhandled D-Bus type")

    @abstractmethod
    def build(self) -> str:
        """
        Produce a string representation for the instantiated type.
        The resulting string will be suitable for using with ``dbus-send``.
        """
        raise NotImplementedError("Abstract method invoked")

    @classmethod
    @abstractmethod
    def parse(cls, result: DBUSResult) -> DBUSType:
        """
        Parse a string resulting from ``dbus-send`` and instantiate
        the corresponding ``DBUSType``.
        """
        raise NotImplementedError("Abstract method invoked")


class DBUSTypeInteger(DBUSType):
    def __init__(self, value: int):
        self.value = value
        """The actual value stored as a python type"""

    def build(self) -> str:
        return f"uint32:{self.value}"

    @classmethod
    def parse(cls, result: DBUSResult) -> DBUSTypeInteger:
        text = result.text
        res = re.match(r"^ *u?int[0-9]{2} +([0-9]+)", text)
        if res is None:
            raise TypeError("Not an integer")

        result.text = text[res.span()[1] :].strip()
        return DBUSTypeInteger(int(res.group(1)))


class DBUSTypeBoolean(DBUSType):
    def __init__(self, value: bool):
        self.value = value
        """The actual value stored as a python type"""

    def build(self) -> str:
        return f"boolean:{self.value}"

    @classmethod
    def parse(cls, result: DBUSResult) -> DBUSTypeBoolean:
        text = result.text
        res = re.match(r"^ *boolean +(([Tt][Rr][Uu][Ee])|([Ff][Aa][Ll][Ss][Ee]))", text)
        if res is None:
            raise TypeError("Not a boolean")

        result.text = text[res.span()[1] :]
        return DBUSTypeBoolean(res.group(1).lower() == "true")


class DBUSTypeString(DBUSType):
    def __init__(self, value: str):
        self.value = value
        """The actual value stored as a python type"""

    def build(self) -> str:
        return f"string:{self.value}"

    @classmethod
    def parse(cls, result: DBUSResult) -> DBUSTypeString:
        text = result.text
        res = re.match(r'^ *(string|object +path) +"([^"]*)"', text)
        if res is None:
            raise TypeError("Not a string")

        result.text = text[res.span()[1] :].strip()
        return DBUSTypeString(res.group(2))


class DBUSTypeVariant(DBUSType):
    """
    Python representation for the D-Bus ``variant`` type.

    This is a container for other types.
    """

    def build(self) -> str:
        return "variant:" + self.get_dbus_param(self.value)

    @classmethod
    def parse(cls, result: DBUSResult) -> DBUSTypeVariant:
        res = re.match(r"^ *variant +", result.text)
        if res is None:
            raise TypeError("Not a variant")

        result.text = result.text.removeprefix(res.group(0))
        dvalue = cls.get_python_value(result)
        return DBUSTypeVariant(dvalue)


class DBUSTypeArray(DBUSType):
    def __init__(self, value: list):
        self.value = value
        """The actual value stored as a python type"""

    def build(self) -> str:
        val = f"array:{self.Types.get_dbus_type(self.value[0])}:"
        delim = ""
        for e in self.value:
            val += delim + str(e)
            delim = ","
        return val

    @classmethod
    def parse(cls, result: DBUSResult) -> DBUSTypeArray:
        # dbus-send doesn't return "dict {...}" but "array [ dict entry (...) ... ]"
        dict = None
        old = result.text
        try:
            dict = DBUSTypeDict.parse(result)
        except TypeError:
            pass
        if dict is not None:
            result.text = old
            raise TypeError("Not an array")

        res = re.match(r"^ *array +\[", result.text)
        if res is None:
            raise TypeError("Not an array")

        array = []
        result.text = result.text.removeprefix(res.group(0)).strip()
        res = re.match(r"^ *\] *", result.text)
        while len(result.text) > 0 and res is None:
            value = cls.get_python_value(result)
            array.append(value)
            result.text = result.text.strip()
            res = re.match(r"^\] *", result.text)
        if res is None:
            raise TypeError("Malformed an array")

        result.text = result.text.removeprefix(res.group(0))
        return DBUSTypeArray(array)


class DBUSTypeDict(DBUSType):
    def __init__(self, value: dict):
        self.value = value
        """The actual value stored as a python type"""

    def build(self) -> str:
        k = list(self.value)[0]
        val = f"dict:{self.Types.get_dbus_type(k)}:{self.Types.get_dbus_type(self.value[k])}:"
        delim = ""
        for k, v in self.value.items():
            val += f"{delim}{str(k)},{str(v)}"
            delim = ","
        return val

    @classmethod
    def _parse_dict_entry(cls, result: DBUSResult) -> tuple:
        res = re.match(r"^ *dict entry *\(", result.text)
        if res is None:
            raise TypeError("Not a dictionary entry")

        result.text = result.text.removeprefix(res.group(0))
        key = cls.get_python_value(result)
        value = cls.get_python_value(result)

        res = re.match(r"^ *\) *", result.text)
        if res is None:
            raise TypeError("Malformed dictionary entry")

        result.text = result.text.removeprefix(res.group(0)).strip()
        return key, value

    @classmethod
    def parse(cls, result: DBUSResult) -> DBUSTypeDict:
        res = re.match(r"^ *array +\[ *(dict entry *\(.+\)) *\] *", result.text)
        if res is None:
            raise TypeError("Not a dictionary")

        res2 = DBUSResult(res.group(1).strip())
        dict = {}
        while len(res2.text) > 0:
            key, value = cls._parse_dict_entry(res2)
            dict[key] = value.value if isinstance(value, DBUSTypeVariant) else value

        result.text = result.text[res.span()[1] :].strip()
        return DBUSTypeDict(dict)


class DBUSObject(MultihostUtility[MultihostHost]):
    """
    D-Bus access.

    Objects of this class represent the root or child D-Bus nodes.
    """

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
            bus: str | DBUSBus,
            /,
            interface: str | None = None,
            child: xml.Element | None = None,
        ):
            """
            Constructor to be called by the subclasses either explicitely or by inheritance.
            """
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

        def _run(self, command: str, *args):
            """
            Run dbus-send over ssh on the remote host.
            """
            cmd = self.cmd + f" {command}"
            for param in args:
                cmd += " " + DBUSType.get_dbus_param(param)

            rslt = self.host.ssh.run(cmd)
            if rslt.stdout_lines[0].startswith("method return"):
                lines = rslt.stdout_lines[1:]
            else:
                lines = rslt.stdout_lines

            return SSHProcessResult(rslt.rc, lines, rslt.stderr_lines)

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

            return DBUSType.get_python_value(DBUSResult(res.stdout))

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
                DBUSTypeVariant(value),
            )
            if res.rc != 0:
                raise RuntimeError(res.stderr)

    class ProxyMethod(ProxyObject):
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

            value = DBUSType.get_python_value(DBUSResult(res.stdout))
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
