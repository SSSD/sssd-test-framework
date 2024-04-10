"""D-Bus Type mapping to and from Python Types"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Generic, TypeVar

__all__ = [
    "DBUSResult",
    "DBUSType",
    "DBUSTypeBoolean",
    "DBUSTypeString",
    "DBUSTypeObjectPath",
    "DBUSTypeInteger",
    "DBUSTypeByte",
    "DBUSTypeInt16",
    "DBUSTypeInt32",
    "DBUSTypeInt64",
    "DBUSTypeUInt16",
    "DBUSTypeUInt32",
    "DBUSTypeUInt64",
    "DBUSTypeDouble",
    "DBUSTypeContainer",
    "DBUSTypeArray",
    "DBUSTypeDict",
    "DBUSTypeVariant",
    "DBUSSignatureReader",
]


# A NOTE ABOUT DBUS-SEND
# **********************
# It is important to know that dbus-send does not have a symmetric
# behavior with relation to how the types are described in text
# form when used as parameters or results.


# TYPES PENDING IMPLEMENTATION
# ****************************
# The following D-Bus types are not implemented because they are not
# currently recognized by dbus-send:
# - Signature
# - UNIX FD
# - Struct


class MutableString:
    """A helper class implementing an extremely simple mutable string"""

    def __init__(self, text: str):
        self.text = text

    def __str__(self):
        return self.text


class DBUSResult(MutableString):
    """
    The result from the D-Bus operation executed by dbus-send.
    It is used to simplify parsing of the result as the string
    must be modified and have no carriage return.
    """

    def __init__(self, text: str):
        self.text = text.replace("\n", "")


PythonType = TypeVar("PythonType")


class DBUSType(ABC, Generic[PythonType]):
    """
    Abstract class to create classes that handle type conversion
    between D-Bus and Python.
    """

    def __init__(self) -> None:
        self._value: PythonType | None = None

    @property
    @abstractmethod
    def _type_prefix(self) -> str:
        """The D-Bus type prefix"""
        pass

    @property
    @abstractmethod
    def value(self) -> PythonType:
        """The value as a Pyhton type"""
        pass

    @value.setter
    @abstractmethod
    def value(self, val: PythonType):
        pass

    def __str__(self) -> str:
        """
        Produce a string representation for the instantiated type's Python value.
        """
        return str(self.value)

    @abstractmethod
    def mimic(self) -> DBUSType[PythonType]:
        """Duplicate this object. Structure is deepcopied, but values are not."""
        pass

    def param(self) -> str:
        """
        Produce a string representation for the instantiated type suitable for
        using as a parameter for ``dbus-send``.
        """
        return f"{self._type_prefix}:{self}"

    @abstractmethod
    def parse(self, result: DBUSResult) -> None:
        """
        Parse a resulting string from ``dbus-send`` and instantiate
        the corresponding ``DBUSType``.

        It consumes the beginning of the provided result.
        """
        pass

    @classmethod
    def _guess_next_type(cls, result: DBUSResult) -> DBUSType:
        """
        Try to guess which is the next type.

        This is mostly needed for variants whose signature doesn't include the subtype.
        """
        for subcls in cls.__subclasses__():
            try:
                # If one of our classes has subclasses, it means it is an intermediate
                # abstract class and we need to make a recursive call. Otherwise,
                # it is a concrete class and we can try to parse the value.
                if not subcls.__subclasses__():
                    obj = subcls()
                    obj.parse(DBUSResult(result.text))
                else:
                    obj = subcls._guess_next_type(result)
                return obj
            except TypeError:
                pass

        raise TypeError("Couldn't guess the type")


class DBUSTypeBasic(DBUSType[PythonType]):
    """
    Abstract class to group the basic types together.
    """

    def mimic(self) -> DBUSTypeBasic[PythonType]:
        """Duplicate this object. Structure is deepcopied, but values are not."""
        return self.__class__()


class DBUSTypeInteger(DBUSTypeBasic[int]):
    """
    Abstract integer class to create classes that handle type conversion
    between D-Bus and Python integers.
    """

    @property
    @abstractmethod
    def _match_exp(self) -> str:
        """The regexp that must be matched during the type recognision"""
        pass

    @property
    @abstractmethod
    def _max_bit_length(self) -> int:
        """The number of bit the type has"""
        pass

    @property
    @abstractmethod
    def _signed(self) -> bool:
        """Whether the type is signed"""
        pass

    @property
    def value(self) -> int:
        if self._value is None:
            raise ValueError("Value has not been set")
        return self._value

    @value.setter
    def value(self, val: int):
        val = int(val)
        if self._signed:
            if val.bit_length() > self._max_bit_length - 1:
                raise TypeError("Integer too large")
        else:
            if val < 0:
                raise TypeError("Negative value")
            if val.bit_length() > self._max_bit_length:
                raise TypeError("Integer too large")

        self._value = val

    # A generic parsing method used by all the subclasses.
    # It uses the class-specific `_match_exp` variable to adapt its behavior.
    # It will be invoked from the concrete subclasses.
    # It consumes the beginning of the provided result.
    def parse(self, result: DBUSResult) -> None:
        text = result.text
        res = re.match(self._match_exp, text)
        if res is None:
            raise TypeError("Invalid integer")

        result.text = text[res.span()[1] :].strip()
        self.value = int(res.group(1))


class DBUSTypeByte(DBUSTypeInteger):
    @property
    def _type_prefix(self) -> str:
        return "byte"

    @property
    def _match_exp(self) -> str:
        return r"^ *byte +([-+]?[0-9]+)"

    @property
    def _max_bit_length(self) -> int:
        return 8

    @property
    def _signed(self) -> bool:
        return False


class DBUSTypeInt16(DBUSTypeInteger):
    @property
    def _type_prefix(self) -> str:
        return "int16"

    @property
    def _match_exp(self) -> str:
        return r"^ *int16 +([-+]?[0-9]+)"

    @property
    def _max_bit_length(self) -> int:
        return 16

    @property
    def _signed(self) -> bool:
        return True


class DBUSTypeInt32(DBUSTypeInteger):
    @property
    def _type_prefix(self) -> str:
        return "int32"

    @property
    def _match_exp(self) -> str:
        return r"^ *int32 +([-+]?[0-9]+)"

    @property
    def _max_bit_length(self) -> int:
        return 32

    @property
    def _signed(self) -> bool:
        return True


class DBUSTypeInt64(DBUSTypeInteger):
    @property
    def _type_prefix(self) -> str:
        return "int64"

    @property
    def _match_exp(self) -> str:
        return r"^ *int64 +([-+]?[0-9]+)"

    @property
    def _max_bit_length(self) -> int:
        return 64

    @property
    def _signed(self) -> bool:
        return True


class DBUSTypeUInt16(DBUSTypeInteger):
    @property
    def _type_prefix(self) -> str:
        return "int16"

    @property
    def _match_exp(self) -> str:
        return r"^ *int16 +([-+]?[0-9]+)"

    @property
    def _max_bit_length(self) -> int:
        return 16

    @property
    def _signed(self) -> bool:
        return False


class DBUSTypeUInt32(DBUSTypeInteger):
    @property
    def _type_prefix(self) -> str:
        return "uint32"

    @property
    def _match_exp(self) -> str:
        return r"^ *uint32 +([0-9]+)"

    @property
    def _max_bit_length(self) -> int:
        return 32

    @property
    def _signed(self) -> bool:
        return False


class DBUSTypeUInt64(DBUSTypeInteger):
    @property
    def _type_prefix(self) -> str:
        return "uint64"

    @property
    def _match_exp(self) -> str:
        return r"^ *uint64 +([0-9]+)"

    @property
    def _max_bit_length(self) -> int:
        return 64

    @property
    def _signed(self) -> bool:
        return False


class DBUSTypeDouble(DBUSTypeBasic[float]):
    @property
    def _type_prefix(self) -> str:
        return "double"

    @property
    def value(self) -> float:
        if self._value is None:
            raise ValueError("Value has not been set")
        return self._value

    @value.setter
    def value(self, val: float):
        self._value = float(val)

    def parse(self, result: DBUSResult) -> None:
        text = result.text
        res = re.match(r"^ *double +([-+]?[0-9]+(\.[0-9]+)?)", text)
        if res is None:
            raise TypeError("Invalid double")

        result.text = text[res.span()[1] :].strip()
        self.value = float(res.group(1))


class DBUSTypeBoolean(DBUSTypeBasic[bool]):
    @property
    def _type_prefix(self) -> str:
        return "boolean"

    @property
    def value(self) -> bool:
        if self._value is None:
            raise ValueError("Value has not been set")
        return self._value

    @value.setter
    def value(self, val: bool):
        self._value = bool(val)

    # Parsing:   boolean false|true
    def parse(self, result: DBUSResult) -> None:
        text = result.text
        res = re.match(r"^ *boolean +((true)|(false))", text, re.IGNORECASE)
        if res is None:
            raise TypeError("Not a boolean")

        result.text = text[res.span()[1] :]
        self.value = res.group(1).lower() == "true"

    # Param:   boolean:false|true


class DBUSTypeString(DBUSTypeBasic[str]):
    @property
    def _type_prefix(self) -> str:
        return "string"

    @property
    def value(self) -> str:
        if self._value is None:
            raise ValueError("Value has not been set")
        return self._value

    @value.setter
    def value(self, val: str):
        self._value = str(val)

    def __str__(self) -> str:
        return f"'{self.value}'"

    # Parsing: string "My string"
    def parse(self, result: DBUSResult) -> None:
        text = result.text
        res = re.match(r'^ *string +"([^"]*)"', text)
        if res is None:
            raise TypeError("Not a string")

        result.text = text[res.span()[1] :].strip()
        self.value = res.group(1)

    # Param: string:"My string"


class DBUSTypeObjectPath(DBUSTypeBasic[str]):
    @property
    def _type_prefix(self) -> str:
        return "objpath"

    @property
    def value(self) -> str:
        if self._value is None:
            raise ValueError("Value has not been set")
        return self._value

    @value.setter
    def value(self, val: str):
        self._value = str(val)

    # Parsing: object path "/org/freedesktop/sssd/infopipe/Components/monitor"
    def parse(self, result: DBUSResult) -> None:
        text = result.text
        res = re.match(r'^ *object path +"([^"]*)"', text)
        if res is None:
            raise TypeError("Not an object path")

        result.text = text[res.span()[1] :].strip()
        self.value = res.group(1)

    # Param: objpath:/org/freedesktop/sssd/infopipe/Components/monitor


class DBUSTypeContainer(DBUSType[PythonType]):
    """
    Abstract class to group the container types together.
    """

    pass


class DBUSTypeVariant(DBUSTypeContainer[PythonType]):
    """
    Python representation for the D-Bus ``variant`` type.

    This is a container for other types.
    """

    @property
    def _type_prefix(self) -> str:
        return "variant"

    def __init__(self, model_element: DBUSType | None = None):
        """
        An object of the expected type can be passed as parameter.
        This object will be used as a model.

        If the object is not passed, we will try to guess it. This behavior is
        required because the variant type doesn't include the subtype in the
        signature.
        """
        self._element: DBUSType | None = None if model_element is None else model_element.mimic()
        """The element stored by the variant"""

    @property
    def value(self) -> PythonType:
        if self._element is None:
            raise ValueError("No subtype set for Variant")
        return self._element.value

    @value.setter
    def value(self, val: PythonType):
        if self._element is None:
            raise ValueError("No subtype set for Variant")
        self._element.value = val

    def __str__(self) -> str:
        return str(self._element)

    def mimic(self) -> DBUSTypeVariant:
        return self.__class__(self._element)

    # Parsing:  variant <type> <value>
    def parse(self, result: DBUSResult) -> None:
        res = re.match(r"^ *variant +", result.text)
        if res is None:
            raise TypeError("Not a variant")

        old_text = result.text
        result.text = result.text.removeprefix(res.group(0))

        if self._element is None:
            self._element = DBUSType._guess_next_type(result)

        try:
            self._element.parse(result)
        except Exception as e:
            result.text = old_text
            raise e

    # Param:  variant:<type>:<value>
    def param(self) -> str:
        if self._element is None:
            raise ValueError("No value set")
        return f"{self._type_prefix}:{self._element.param()}"


class DBUSTypeDict(DBUSTypeContainer[dict]):
    @property
    def _type_prefix(self) -> str:
        return "dict"

    def __init__(self, model_key: DBUSTypeBasic | None = None, model_value: DBUSType | None = None):
        """
        Build a dictionary containing elements of a single type and keys of
        another type.

        An object of each type can be passed as parameter. This object will be
        mimic'ed to create the elements when values are assigned.

        If the objects are not passed, we will try to guess them. This behavior
        is required because the variant type doesn't include the subtype in
        the signature.
        """
        if (model_key is None or model_value is None) and model_key != model_value:
            raise ValueError("Both arguments or none must be None")

        self._model_key = model_key
        self._model_value = model_value
        self._str: str | None = None

    @property
    def value(self) -> dict:
        if self._value is None:
            raise ValueError("Value has not been set")
        return dict(self._value)

    @value.setter
    def value(self, val: dict):
        if self._model_key is None or self._model_value is None:
            raise ValueError("No subtype set")

        self._value = dict(val)
        self._dict = {}
        for k in val.keys():
            ko = self._model_key.mimic()
            ko.value = k
            vo = self._model_value.mimic()
            vo.value = val[k]
            self._dict[ko] = vo

    def __str__(self) -> str:
        if self._str is None:
            val = ""
            delim = ""
            for k, v in self._dict.items():
                val += f"{delim}{k},{v}"
                delim = ","
            self._str = val

        return self._str

    def mimic(self) -> DBUSTypeDict:
        return self.__class__(self._model_key, self._model_value)

    # We may need to handle dict entry as a separate type as that's how D-Bus
    # considers it.
    # For the moment, there is no gain in doing it, so we keep this.
    def _parse_dict_entry(self, result: DBUSResult) -> tuple:
        res = re.match(r"^ *dict entry *\(", result.text)
        if res is None:
            raise TypeError("Not a dictionary entry")

        result.text = result.text.removeprefix(res.group(0))

        if self._model_key is None:
            k = DBUSType._guess_next_type(DBUSResult(result.text))
            if not isinstance(k, DBUSTypeBasic):
                raise ValueError(f"Basic type expected but got {k.__class__}")
            self._model_key = k
        key = self._model_key.mimic()
        key.parse(result)

        if self._model_value is None:
            self._model_value = DBUSType._guess_next_type(DBUSResult(result.text))
        value = self._model_value.mimic()
        value.parse(result)

        res = re.match(r"^ *\) *", result.text)
        if res is None:
            raise TypeError("Malformed dictionary entry: unfinished expression")

        result.text = result.text.removeprefix(res.group(0)).strip()
        return key, value

    # Parsing: (without the newlines)
    #     array [
    #        dict entry(
    #           <key type> <key>
    #           <value type> <value>
    #        )
    #        ...
    #     ]
    def parse(self, result: DBUSResult) -> None:
        match1 = re.match(r"^( *array +\[ *)dict entry *\(.+\) *\]", result.text)
        if match1 is None:
            raise TypeError("Not a dictionary")

        odict = {}
        pdict = {}
        result2 = DBUSResult(result.text.removeprefix(match1.group(1)).strip())
        match2 = re.match(r"^ *\] *", result2.text)
        while len(result2.text) > 0 and match2 is None:
            key, value = self._parse_dict_entry(result2)
            odict[key] = value
            pdict[key.value] = value.value
            match2 = re.match(r"^ *\] *", result2.text)

        if match2 is None:
            raise TypeError("Malformed dictionary: unfinished expression")

        result.text = result2.text.removeprefix(match2.group(0)).strip()
        self._value = pdict
        self._dict = odict

    # Param: dict:<key type>:<value type>:<key>,<value>[,<key>,<value>]...
    def param(self) -> str:
        if self._model_key is None or self._model_value is None:
            raise ValueError("No subtype set")

        str = f"{self._type_prefix}:{self._model_key._type_prefix}:"
        str += f"{self._model_value._type_prefix}:{self}"
        return str


class DBUSTypeArray(DBUSTypeContainer[list]):
    @property
    def _type_prefix(self) -> str:
        return "array"

    def __init__(self, model_element: DBUSType | None = None):
        """
        Build an array containing elements of a single type. An object of
        this type can be passed as parameter. This object will be mimic'ed
        to create the elements when values are assigned.

        If the object is not passed, we will try to guess it. This behavior
        is required because the variant type doesn't include the subtype in
        the signature.
        """
        self._model_element = model_element
        self._str: str | None = None

    @property
    def value(self) -> list:
        if self._value is None:
            raise ValueError("Value has not been set")
        return list(self._value)

    @value.setter
    def value(self, val: list):
        if self._model_element is None:
            raise ValueError("No subtype set")

        self._value = list(val)
        self._array = []
        for v in val:
            vo = self._model_element.mimic()
            vo.value = v
            self._array.append(vo)

    def __str__(self) -> str:
        if self._str is None:
            val = ""
            delim = ""
            for v in self._array:
                val += delim + str(v)
                delim = ","
            self._str = val

        return self._str

    def mimic(self) -> DBUSTypeArray:
        return self.__class__(self._model_element)

    # Parsing:  array [ <type> <value> [ <type> <value> ]... ]
    def parse(self, result: DBUSResult) -> None:
        old = result.text
        match = re.match(r"^ *array +\[", result.text)
        if match is None:
            raise TypeError("Not an array")

        oarray = []
        parray = []
        result.text = result.text.removeprefix(match.group(0)).strip()
        match = re.match(r"^ *\] *", result.text)
        while len(result.text) > 0 and match is None:
            if self._model_element is None:
                self._model_element = DBUSType._guess_next_type(DBUSResult(result.text))

            obj = self._model_element.mimic()
            obj.parse(result)

            oarray.append(obj)
            parray.append(obj.value)
            result.text = result.text.strip()
            match = re.match(r"^\] *", result.text)

        if match is None:
            result.text = old
            raise TypeError("Malformed array: unfinished expression")

        result.text = result.text.removeprefix(match.group(0))
        self._array = oarray
        self._value = parray

    # Param:  array:<type>:<value>[,<value>...]
    def param(self) -> str:
        if self._model_element is None:
            raise ValueError("No subtype set")

        return f"{self._type_prefix}:{self._model_element._type_prefix}:{self}"


class DBUSSignatureReader:
    """
    D-Bus type builder from the method signature.
    """

    _type_mapping: dict[str, tuple] = {
        "a{": (DBUSTypeDict, 2, "}"),  # Must be placed before "a"
        "a": (DBUSTypeArray, 1, None),
        "b": (DBUSTypeBoolean, 0, None),
        "d": (DBUSTypeDouble, 0, None),
        "i": (DBUSTypeInt32, 0, None),
        "n": (DBUSTypeInt16, 0, None),
        "o": (DBUSTypeObjectPath, 0, None),
        "q": (DBUSTypeUInt16, 0, None),
        "s": (DBUSTypeString, 0, None),
        "t": (DBUSTypeUInt64, 0, None),
        "u": (DBUSTypeUInt32, 0, None),
        "v": (DBUSTypeVariant, 0, None),
        "x": (DBUSTypeInt64, 0, None),
        # Types not implemented by dbus-send.
        # "g": (Signature, 0, None),
        # "h": (UNIX FD, 0, None),
        # "(": (Struct, 0, ")")
    }
    """
    The mapping between dbus type codes and `DBUSType`s.

    Taken from `the D-Bus specification <https://dbus.freedesktop.org/doc/dbus-specification.html#basic-types>`
    """

    @classmethod
    def read(cls, signature: str | MutableString) -> DBUSType:
        if isinstance(signature, str):
            signature = MutableString(signature)

        for prefix in cls._type_mapping.keys():
            if signature.text.startswith(prefix):
                dbustype, items, suffix = cls._type_mapping[prefix]
                reminder = MutableString(signature.text.removeprefix(prefix))

                objs = []
                for i in range(items):
                    obj = cls.read(reminder)
                    objs.append(obj)

                if suffix is not None:
                    if not reminder.text.startswith(suffix):
                        raise ValueError(
                            f"Found the prefix '{prefix}' but no suffix " f"'{suffix}' in the signature '{signature}'"
                        )

                    reminder.text = reminder.text.removeprefix(suffix)

                signature.text = reminder.text
                tobjs = tuple(objs)
                return dbustype(*tobjs)

        raise ValueError(f"Unidentified signature '{signature}'")
