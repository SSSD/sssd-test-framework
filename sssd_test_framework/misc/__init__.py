"""Miscellaneous functions."""

from __future__ import annotations

import ipaddress
import itertools
from functools import wraps
from time import sleep
from typing import Any, Callable, ParamSpec, TypeVar


def attrs_parse(lines: list[str], attrs: list[str] | None = None) -> dict[str, list[str]]:
    """
    Parse LDAP attributes from output.

    :param lines: Output.
    :type lines: list[str]
    :param attrs: If set, only requested attributes are returned, defaults to None
    :type attrs: list[str] | None, optional
    :return: Dictionary with attribute name as a key.
    :rtype: dict[str, list[str]]
    """
    out: dict[str, list[str]] = {}
    i = 0
    while i < len(lines):
        line = lines[i].rstrip("\r")
        if not line:
            i += 1
            continue

        key, value = map(lambda x: x.lstrip(), line.split(":", 1))
        key = key.strip()
        while i < len(lines) - 1:
            if lines[i + 1].startswith(" "):
                value += lines[i + 1][1:]
                i += 1
            else:
                break

        if attrs is None or key in attrs:
            out.setdefault(key, [])
            out[key].append(value)
        i += 1
    return out


def delimiter_parse(lines: list[str], delimiter: str = ":") -> dict[str, str]:
    """
    Parse delimited lines from output.

    :param lines: Output.
    :type lines: list[str]
    :param delimiter: Delimiter, optional
    :type delimiter: str, defaults to :
    :return: Dictionary with first element as the name as a key.
    :rtype: dict[str, str]
    """
    out: dict[str, str] = {}

    for item in lines:
        key, value = item.split(delimiter, 1)
        out[key.strip()] = value.strip()

    return out


def attrs_include_value(attr: Any | list[Any] | None, value: Any) -> list[Any]:
    """
    Include ``value`` to attribute list if it is not yet present.

    If ``attr`` is not a list, then it is first converted into a list.

    :param attr: List of attribute values or a single value.
    :type attr: Any | list[Any]
    :param value: Value to add to the list.
    :type value: Any
    :return: New list with the value included.
    :rtype: list[Any]
    """
    attr = to_list(attr)

    if value not in attr:
        return [*attr, value]

    return attr


def to_list(value: Any | list[Any] | None) -> list[Any]:
    """
    Convert value into a list.

    - if value is ``None`` then return an empty list
    - if value is already a list then return it unchanged
    - if value is not a list then return ``[value]``

    :param value: Value that should be converted to a list.
    :type value: Any | list[Any] | None
    :return: List with the value as an element.
    :rtype: list[Any]
    """
    if value is None:
        return []

    if isinstance(value, list):
        return value

    return [value]


def to_list_of_strings(value: Any | list[Any] | None) -> list[str]:
    """
    Convert given list or single value to list of strings.

    The ``value`` is first converted to a list and then ``str(item)`` is run on
    each of its item.

    :param value: Value to convert.
    :type value: Any | list[Any] | None
    :return: List of strings.
    :rtype: list[str]
    """
    return [str(x) for x in to_list(value)]


def to_list_without_none(r_list: list[Any]) -> list[Any]:
    """
    Remove all elements that are ``None`` from the list.

    :param r_list: List of all elements.
    :type r_list: list[Any]
    :return: New list with all values from the given list that are not ``None``.
    :rtype: list[Any]
    """
    return [x for x in r_list if x is not None]


def parse_ldif(ldif: str) -> dict[str, dict[str, list[str]]]:
    """
    Convert given LDIF to dictionary.

    :param ldif: Output of ldbsearch.
    :type ldif: str
    :return: Data of given ldif in format: dict[dn, dict[attribute, list[attrvalue]]].
    :rtype: dict[str, dict[str, list[str]]
    """
    output = {}
    uncommented = [x for x in ldif.split("\n") if not x.startswith("#")]
    parsed = [list(group) for k, group in itertools.groupby(uncommented, lambda x: x == "") if not k]

    for record in parsed:
        result = attrs_parse(record)
        output[result["dn"][0]] = result

    return output


def attrs_to_hash(attrs: dict[str, Any]) -> str | None:
    """
    Convert attributes into an Powershell hash table records.

    :param attrs: Attributes names and values.
    :type attrs: dict[str, Any]
    :return: Attributes in powershell hash record format.
    :rtype: str | None
    """
    out = ""
    for key, value in attrs.items():
        if value is not None:
            if isinstance(value, list):
                values = [f'"{x}"' for x in value]
                out += f'"{key}"={",".join(values)};'
            else:
                out += f'"{key}"="{value}";'

    if not out:
        return None

    return "@{" + out.rstrip(";") + "}"


Param = ParamSpec("Param")
RetType = TypeVar("RetType")


def seconds_to_timespan(seconds: int) -> str:
    """
    Convert seconds to powershell timespan format, 'Days:Hours:Minutes:Seconds:Fractions'.

    :param seconds: Seconds.
    :type seconds: int
    :return: Time in timespan format.
    :rtype: str
    """
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    d, h = divmod(h, 24)

    return f"{d:02d}:{h:02d}:{m:02d}:{s:02d}:00"


def ip_to_ptr(ip_address: str) -> str:
    """
    Get the reverse pointer from given address.

    :param ip_address: Address.
    :type ip_address: str
    :return: Reverse pointer.
    :rtype: str
    """
    ip = ipaddress.ip_address(ip_address)
    if ip.version == 4:
        octets = ip.packed
        ptr = f"{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa."
    elif ip.version == 6:
        hex_parts = ip.exploded.replace(":", "").lower()
        ptr = f"{hex_parts[::-1]}.ip6.arpa."
    else:
        raise ValueError("Unsupported IP version")
    return ptr


def ip_version(ip_address: str) -> int | None:
    """
    Parse str and return the IP version.

    ::param ip_address: IP address.
    :type ip_address: str
    :return:  IP version or None if not found.
    :rtype: int | None
    """
    try:
        return ipaddress.IPv4Address(ip_address).version
    except ValueError:
        try:
            return ipaddress.IPv6Address(ip_address).version
        except ValueError:
            return None


def retry(
    max_retries: int = 5,
    delay: float = 1,
    on: type[Exception] | list[type[Exception]] | None = None,
) -> Callable[[Callable[Param, RetType]], Callable[Param, RetType]]:
    """
    Decorated function will be retried if it raises an exception.

    :param max_retries: Maximum number of retry attempts, defaults to 5
    :type max_retries: int, optional
    :param delay: Delay in seconds between each retry, defaults to 1
    :type delay: float, optional
    :param on: If set, retry only on given exceptions, defaults to None
    :type on: type[Exception] | list[type[Exception]] | None, optional

    :return: Decorated function.
    :rtype: Callable
    """
    if on is None:
        on = [Exception]

    types = tuple(to_list(on))

    def decorator(func: Callable[Param, RetType]) -> Callable[Param, RetType]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> RetType:
            retry: int = 0
            while True:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if retry >= max_retries or not isinstance(e, types):
                        raise

                    retry += 1
                    sleep(delay)

        return wrapper

    return decorator


def get_attr(data: dict[str, Any], key: str, default: Any | None = None) -> Any | list[Any]:
    """
    Retrieve a value from a dictionary with list-aware semantics.
    This helper makes working with parsed command output or API responses easier:
    - Single-item lists → returns the first element.
    - Multi-item lists → returns the full list.
    - Missing, empty, or None values → returns `default`.
    - Non-list values → returned as-is.

    .. code-block:: python
        :caption: Example usage

        result = {
            "login": ["user-1"],
            "uidnumber": [1234567],
            "groups": ["admins", "developers"],
            "services": [],
            "nested": {
                "sshpubkey": ["ssh-rsa AAAAB3Nza..."],
                "email": ["user1@example.com"],
            },
        }
        assert get_attr(result, "login") == "user-1"
        assert get_attr(result, "groups") == ["admins", "developers"]
        assert get_attr(result, "uidnumber") == 1234567
        assert get_attr(result, "services") is None
        assert get_attr(result, "missing", default="N/A") == "N/A"
        # Nested dictionary
        nested = get_attr(result, "nested")
        assert isinstance(nested, dict)
        assert get_attr(nested, "email") == "user1@example.com"

    :param data: Dictionary returned from command parsing.
    :type data: dict[str, Any]
    :param key: Attribute name to look up.
    :type key: str
    :param default: Value to return if key is missing or empty, defaults to None.
    :type default: Any | None, optional
    :return: A single value or list of values.
    :rtype: Any | list[Any]
    """
    value: Any = data
    for part in key.split("."):
        if not isinstance(value, dict) or part not in value:
            return default
        value = value[part]

    if value is None:
        return default
    if isinstance(value, list):
        if not value:
            return default
        return value[0] if len(value) == 1 else value
    return value
