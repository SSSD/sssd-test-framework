"""Miscellaneous functions."""
from __future__ import annotations

import textwrap

import pytest

from sssd_test_framework.misc import (
    attrs_include_value,
    attrs_parse,
    parse_ldif,
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


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            """
            # record 1
            dn: cn=1
            cn: sssd
            config: 22

            # record 2
            dn: cn=2
            version: 22
            """,
            {
                "cn=1": {"dn": ["cn=1"], "cn": ["sssd"], "config": ["22"]},
                "cn=2": {"dn": ["cn=2"], "version": ["22"]},
            },
        ),
        (
            """
            # record 1
            dn: cn=1
            cn: 1
            debug: first

            # record 2
            debug: first
            dn: cn=2
            cn: 2
            debug: second
            """,
            {
                "cn=1": {"dn": ["cn=1"], "cn": ["1"], "debug": ["first"]},
                "cn=2": {"dn": ["cn=2"], "cn": ["2"], "debug": ["first", "second"]},
            },
        ),
        (
            """
            # record 1
            dn: cn=sssd
            cn: sssd
            cn: sssd

            # returned 1 records
            # 1 entries
            # 0 referrals
            """,
            {
                "cn=sssd": {"dn": ["cn=sssd"], "cn": ["sssd", "sssd"]},
            },
        ),
        (
            """
            # returned 0 records
            # 0 entries
            # 0 referrals
            """,
            {},
        ),
    ],
)
def test_parse_ldif(value, expected):
    value = textwrap.dedent(value).strip()
    assert parse_ldif(value) == expected
