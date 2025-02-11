"""Miscellaneous functions."""

from __future__ import annotations

import textwrap
import time

import pytest

from sssd_test_framework.misc import (
    attrs_include_value,
    attrs_parse,
    attrs_to_hash,
    parse_ldif,
    retry,
    seconds_to_timespan,
    to_list,
    to_list_of_strings,
    to_list_without_none,
)


def test_attrs_parse__nofilter():
    lines = """
    param1: value1
    param2: value2
    param3: value3
    """
    lines = textwrap.dedent(lines).strip().split("\n")

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
    """
    lines = textwrap.dedent(lines).strip().split("\n")
    expected = {
        "param2": ["value2"],
        "param3": ["value3"],
    }

    assert attrs_parse(lines, ["param2", "param3"]) == expected


@pytest.mark.parametrize(
    "input,expected",
    [
        (
            ["cn: sudorules", "distinguishedName: objectSID=123,cn=id_m", " appings,cn=test,cn=sysdb"],
            {"cn": ["sudorules"], "distinguishedName": ["objectSID=123,cn=id_mappings,cn=test,cn=sysdb"]},
        ),
        (
            [
                "description: My teacher is a good ",
                " one but I do not like him",
                "  very much: he wears a dirty c",
                " oat.",
            ],
            {"description": ["My teacher is a good one but I do not like him very much: he wears a dirty coat."]},
        ),
        (
            ["cn: sudorules", "numbers: one,", "  two,", "  three"],
            {"cn": ["sudorules"], "numbers": ["one, two, three"]},
        ),
        (
            ["\r", "\r", "DistinguishedName: CN=user1,CN=Users,DC=ad-n97b,DC=test\r"],
            {"DistinguishedName": ["CN=user1,CN=Users,DC=ad-n97b,DC=test"]},
        ),
    ],
)
def test_attrs_parse__long_line(input, expected):
    assert attrs_parse(input) == expected


@pytest.mark.parametrize(
    "input,expected",
    [
        (
            [
                "DistinguishedName : CN=username,CN=Users,DC=ad,DC=test",
                "Enabled           : True",
                "GivenName         : dummyfirstname",
                "Name              : username",
                "ObjectClass       : user",
                "SamAccountName    : username",
            ],
            {
                "DistinguishedName": ["CN=username,CN=Users,DC=ad,DC=test"],
                "Enabled": ["True"],
                "GivenName": ["dummyfirstname"],
                "Name": ["username"],
                "ObjectClass": ["user"],
                "SamAccountName": ["username"],
            },
        ),
    ],
)
def test_attrs_parse__strip_extra_white_space(input, expected):
    assert attrs_parse(input) == expected


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


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            {"key1": "value1", "key2": "value2 value2.1", "key3": "value3", "key4": "value4, value4.1"},
            """@{"key1"="value1";"key2"="value2 value2.1";"key3"="value3";"key4"="value4, value4.1"}""",
        )
    ],
)
def test_attrs_to_hash(value, expected):
    assert attrs_to_hash(value) == expected


@pytest.mark.parametrize(
    "seconds",
    [
        (0, "00:00:00:00:00"),
        (9, "00:00:00:09:00"),
        (59, "00:00:00:59:00"),
        (60, "00:00:01:00:00"),
        (61, "00:00:01:01:00"),
        (119, "00:00:01:59:00"),
        (600, "00:00:10:00:00"),
        (601, "00:00:10:01:00"),
        (3600, "00:01:00:00:00"),
        (3601, "00:01:00:01:00"),
    ],
)
def test_seconds_to_timespan(seconds: tuple[int, str]):
    assert seconds_to_timespan(seconds[0]) == seconds[1]


def test_retry__all_exceptions():
    rounds = []

    @retry(max_retries=5, delay=0)
    def test():
        if len(rounds) < 4:
            rounds.append(True)
            raise Exception("My exception")

        return len(rounds)

    assert test() == 4


def test_retry__single_exception__positive():
    rounds = []

    @retry(max_retries=5, delay=0, on=ValueError)
    def test():
        if len(rounds) < 4:
            rounds.append(True)
            raise ValueError("My exception")

        return len(rounds)

    assert test() == 4


def test_retry__single_exception__negative():
    rounds = []

    @retry(max_retries=5, delay=0, on=ValueError)
    def test():
        if len(rounds) < 4:
            rounds.append(True)
            raise KeyError("My exception")

        return len(rounds)

    with pytest.raises(KeyError):
        test()


def test_retry__multiple_exceptions__positive():
    rounds = []

    @retry(max_retries=5, delay=0, on=(ValueError, KeyError))
    def test():
        if len(rounds) < 2:
            rounds.append(True)
            raise KeyError("My exception")

        if len(rounds) < 4:
            rounds.append(True)
            raise ValueError("My exception")

        return len(rounds)

    assert test() == 4


def test_retry__multiple_exceptions__negative():
    rounds = []

    @retry(max_retries=5, delay=0, on=(TypeError, KeyError))
    def test():
        if len(rounds) < 2:
            rounds.append(True)
            raise KeyError("My exception")

        if len(rounds) < 4:
            rounds.append(True)
            raise ValueError("My exception")

        return len(rounds)

    with pytest.raises(ValueError):
        test()


def test_retry__delay():
    @retry(max_retries=5, delay=1)
    def test():
        raise ValueError("My exception")

    now = time.time()
    with pytest.raises(ValueError):
        test()

    assert time.time() - now >= 5
