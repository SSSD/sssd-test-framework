"""Miscellaneous functions."""
from __future__ import annotations

import pytest

from sssd_test_framework.misc import (
    attrs_include_value,
    attrs_parse,
    to_list,
    to_list_of_strings,
    to_list_without_none,
)


def test_attrs_parse__nofilter():
    lines = """
    param1: value1
    param2: value2
    param3: value3
    """.split(
        "\n"
    )

    expected = {
        "param1": ["value1"],
        "param2": ["value2"],
        "param3": ["value3"],
    }

    assert attrs_parse(lines) == expected


def test_attrs_parse__filter():
    lines = """
    param1: value1
    param2: value2
    param3: value3
    param4: value4
    """.split(
        "\n"
    )

    expected = {
        "param2": ["value2"],
        "param3": ["value3"],
    }

    assert attrs_parse(lines, ["param2", "param3"]) == expected


@pytest.mark.parametrize(
    "value,include,expected",
    [
        ("value1", "value1", ["value1"]),
        (["value1"], "value1", ["value1"]),
        ("value1", "value2", ["value1", "value2"]),
        (["value1"], "value2", ["value1", "value2"]),
    ],
)
def test_attrs_include_value(value, include, expected):
    assert attrs_include_value(value, include) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, []),
        ([1], [1]),
        ([1, "a"], [1, "a"]),
        (1, [1]),
        ("a", ["a"]),
    ],
)
def test_to_list(value, expected):
    assert to_list(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, []),
        ([1], ["1"]),
        ([1, "a"], ["1", "a"]),
        (1, ["1"]),
        ("a", ["a"]),
    ],
)
def test_to_list_of_strings(value, expected):
    assert to_list_of_strings(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ([None], []),
        ([1], [1]),
        ([1, None], [1]),
        ([1, None, "a"], [1, "a"]),
    ],
)
def test_to_list_without_none(value, expected):
    assert to_list_without_none(value) == expected
