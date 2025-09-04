from __future__ import annotations

from typing import Any, Dict, List, Union


def _normalize_value(value: Union[str, List[str]]) -> Any:
    """
    Normalize raw IPA attribute values:

    - Flatten single-element lists
    - Convert "TRUE"/"FALSE" -> bool
    - Convert digit strings -> int
    - Leave multi-value lists as lists
    """
    if isinstance(value, list):
        if len(value) == 1:
            return _normalize_value(value[0])
        return [_normalize_value(v) for v in value]

    if isinstance(value, str):
        val = value.strip()
        low = val.lower()
        if low == "true":
            return True
        if low == "false":
            return False
        if val.isdigit():
            return int(val)
        return val

    return value


def get_attr(raw: Dict[str, List[str]], key: str, default: Any = None) -> Any:
    """
    Look up an IPA attribute by name (case-insensitive)
    and return it in a clean, test-friendly format.

    Example:
        get_attr(raw, "enabled") -> True/False
        get_attr(raw, "uid") -> int
        get_attr(raw, "usercertificate") -> str or list[str]
        get_attr(raw, "missing", "N/A") -> "N/A"

    :param raw: Raw IPA result (dict[str, list[str]])
    :param key: Attribute name (case-insensitive)
    :param default: Value if attribute not found
    :return: Normalized value
    """
    key_lower = key.lower()
    for k, v in raw.items():
        if k.lower() == key_lower:
            return _normalize_value(v)
    return default
