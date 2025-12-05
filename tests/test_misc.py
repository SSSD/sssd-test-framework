"""Miscellaneous functions."""

from __future__ import annotations

import textwrap
import time

import pytest

from sssd_test_framework.misc import (
    attrs_include_value,
    attrs_parse,
    attrs_to_hash,
    delimiter_parse,
    get_attr,
    ip_to_ptr,
    ip_version,
    parse_ad_object_info,
    parse_cert_info,
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
    "input,expected, delimiter",
    [
        (
            ["Unique ID: 5fe04e66-da53-4ac0-94f3-fd0cd5cefd6d", "Owner: user1"],
            {"Unique ID": "5fe04e66-da53-4ac0-94f3-fd0cd5cefd6d", "Owner": "user1"},
            ":",
        ),
        (
            ["Unique ID, 5fe04e66-da53-4ac0-94f3-fd0cd5cefd6d", "Owner, user1"],
            {"Unique ID": "5fe04e66-da53-4ac0-94f3-fd0cd5cefd6d", "Owner": "user1"},
            ",",
        ),
    ],
)
def test_delimiter_parse(input, expected, delimiter):
    assert delimiter_parse(input, delimiter=delimiter) == expected


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


@pytest.mark.parametrize(
    "value, expected",
    [
        ("192.168.1.0", "1.168.192.in-addr.arpa."),
        ("2001:db8::1", "1000000000000000000000008bd01002.ip6.arpa."),
    ],
)
def test_ip_to_ptr(value, expected):
    assert ip_to_ptr(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("hostname", None),
        ("hostname.domain.com", None),
        ("192.168.1.1", 4),
        ("192.168.1.256", None),
        ("::1", 6),
        ("001:db8::", 6),
    ],
)
def test_ip_version(value, expected):
    assert ip_version(value) == expected


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


@pytest.fixture
def get_attr_sample_data():
    return {
        "uid": [1001],
        "enabled": [True],
        "groups": ["admins", "devops"],
        "usercertificate": ["CERTDATA"],
        "empty": [],
        "rawstring": ["hello"],
        "nested": {"level": {"deep": ["value"]}},
        "description": [None],
        "owner": None,
    }


@pytest.mark.parametrize(
    "key, expected, check_membership",
    [
        ("uid", 1001, None),
        ("enabled", True, None),
        ("groups", ["admins", "devops"], "admins"),
        ("nested.level.deep", "value", None),
        ("rawstring", "hello", None),
        ("description", None, None),
        ("owner", None, None),
        ("empty", "", None),
        ("missing", "some value", None),
        ("usercertificate", "CERTDATA", "CERTDATA"),
    ],
)
def test_get_attr(get_attr_sample_data, key, expected, check_membership):
    default_return_value = expected if expected is not None else None
    value = get_attr(get_attr_sample_data, key, default=default_return_value)

    assert value == expected
    if check_membership:
        values = value if isinstance(value, list) else [value]
        assert check_membership in values


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            """
            Serial Number: 1a2b3c4d5e6f
            Issuer: CN=Test CA, O=Test Org, C=US
            Subject: CN=user1, O=Test Org, C=US
            Thumbprint: a1b2c3d4e5f6
            """,
            {
                "Serial Number": ["1a2b3c4d5e6f"],
                "Issuer": ["CN=Test CA, O=Test Org, C=US"],
                "Subject": ["CN=user1, O=Test Org, C=US"],
                "Thumbprint": ["a1b2c3d4e5f6"],
            },
        ),
    ],
)
def test_parse_cert_info(value, expected):
    value = textwrap.dedent(value).strip()
    assert parse_cert_info(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        (
            """
            DistinguishedName : CN=user1,CN=Users,DC=ad,DC=test
            Enabled           : True
            GivenName         : John
            Name              : user1
            SamAccountName    : user1
            """,
            {
                "DistinguishedName": ["CN=user1,CN=Users,DC=ad,DC=test"],
                "Enabled": ["True"],
                "GivenName": ["John"],
                "Name": ["user1"],
                "SamAccountName": ["user1"],
            },
        ),
    ],
)
def test_parse_ad_object_info(value, expected):
    value = textwrap.dedent(value).strip()
    assert parse_ad_object_info(value) == expected
