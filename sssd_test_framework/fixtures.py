"""Pytest fixtures."""

from __future__ import annotations

import os

import pytest
from pytest_mh import mh_fixture

from .roles.ad import AD
from .roles.client import Client


@pytest.fixture(scope="session")
def datadir(request: pytest.FixtureRequest) -> str:
    """
    Data directory shared for all tests.

    :return: Path to the data directory ``(root-pytest-dir)/data``.
    :rtype: str
    """
    return os.path.join(request.node.path, "data")


@pytest.fixture(scope="module")
def moduledatadir(datadir: str, request: pytest.FixtureRequest) -> str:
    """
    Data directory shared for all tests within a single module.

    :return: Path to the data directory ``(root-pytest-dir)/data/$module_name``.
    :rtype: str
    """
    name = request.module.__name__
    return os.path.join(datadir, name)


@pytest.fixture(scope="function")
def testdatadir(moduledatadir: str, request: pytest.FixtureRequest) -> str:
    """
    Data directory for current test.

    :return: Path to the data directory ``(root-pytest-dir)/data/$module_name/$test_name``.
    :rtype: str
    """
    if not isinstance(request.node, pytest.Function):
        raise TypeError(f"Excepted pytest.Function, got {type(request.node)}")

    name = request.node.originalname
    return os.path.join(moduledatadir, name)


def _ad_forest_leave(client: Client, domain: AD) -> None:
    client.host.conn.exec(
        ["realm", "leave", "--unattended", domain.domain],
        input=domain.host.adminpw,
        raise_on_error=False,
    )


def _ad_forest_set_dns(client: Client, target: AD, forest: tuple[AD, ...]) -> None:
    """Point the client resolver at the forest root DC and joined domain DC.

    The root DC holds conditional forwarders for tree domains; the joined DC
    is needed for local SRV records when the client is enrolled in a child or
    tree domain (legacy ad_forest / ad_other_dc.sh behaviour).
    """
    client.fs.backup("/etc/resolv.conf")
    search = " ".join(domain.domain for domain in forest)
    root = forest[0]
    nameservers: list[str] = []
    for domain in (root, target):
        address = getattr(domain.host.conn, "host", domain.host.hostname)
        if address not in nameservers:
            nameservers.append(address)
    ns_lines = "\n".join(f"nameserver {address}" for address in nameservers)
    client.fs.write("/etc/resolv.conf", f"search {search}\n{ns_lines}\n")


def _ad_forest_restore_dns(client: Client) -> None:
    client.fs.restore("/etc/resolv.conf")


def _ad_forest_remove_stale_computer(forest: tuple[AD, ...], short_hostname: str) -> None:
    """Remove leftover computer accounts before join/rejoin (legacy ad_forest)."""
    for domain in forest:
        domain.host.conn.run(
            f"""
            Import-Module ActiveDirectory
            Get-ADComputer -Identity '{short_hostname}' -ErrorAction SilentlyContinue |
                Remove-ADComputer -Confirm:$false
            """,
            raise_on_error=False,
        )


def _ad_forest_remove_linuxservers_ou(domain: AD) -> None:
    """Remove ``linuxservers`` OU and contents (legacy ad_forest ldapdelete -r)."""
    domain.host.conn.run(
        """
        Import-Module ActiveDirectory
        $base = (Get-ADDomain).DistinguishedName
        $ou = Get-ADOrganizationalUnit -LDAPFilter '(ou=linuxservers)' -SearchBase $base -ErrorAction SilentlyContinue
        if ($ou) { Remove-ADOrganizationalUnit -Identity $ou -Recursive -Confirm:$false }
        """,
        raise_on_error=False,
    )


def _ad_forest_configure_sssd(client: Client, joined: AD, ad_root: AD | None = None) -> None:
    """Import the joined AD domain and apply common forest client settings."""
    client.sssd.import_domain(joined.domain, joined)
    # Child/tree join: use SRV discovery so forest root/tree lookups work.
    if ad_root is not None and joined.domain != ad_root.domain:
        client.sssd.dom(joined.domain)["ad_server"] = "_srv_"
    client.sssd.dom(joined.domain)["use_fully_qualified_names"] = "True"
    client.sssd.dom(joined.domain)["fallback_homedir"] = "/home/%d/%u"
    client.sssd.dom(joined.domain)["cache_credentials"] = "True"


def _ad_forest_block_servers(client: Client, ad: AD, ad_child: AD, ad_tree: AD) -> None:
    """Block outbound traffic to all forest DCs and bring SSSD offline."""
    for domain in (ad, ad_child, ad_tree):
        # Use DC SSH addresses; hostname-based drop_host needs dig/DNS.
        client.firewall.outbound.drop_host(getattr(domain.host.conn, "host", domain.host.hostname))
    client.sssd.bring_offline()


def _ad_forest_rejoin_with_host_upn(client: Client, target: AD, forest: tuple[AD, ...]) -> None:
    """Rejoin with host/ UPN so ``kinit -k host/FQDN@REALM`` works (legacy ad_join … host)."""
    hostname = client.host.conn.run("hostname -f").stdout.strip()
    short_hostname = hostname.split(".")[0]

    for domain in forest:
        _ad_forest_leave(client, domain)

    client.fs.rm("/etc/krb5.conf")
    client.fs.rm("/etc/krb5.keytab")
    _ad_forest_remove_stale_computer(forest, short_hostname)

    client.host.conn.exec(
        [
            "realm",
            "join",
            f"--user-principal=host/{hostname}@{target.realm}",
            target.domain,
        ],
        input=target.host.adminpw,
    )
    client.sssd.stop(raise_on_error=False)
    _ad_forest_set_dns(client, target, forest)
    target.host.client["ad_server"] = "_srv_"


def _ad_forest_join(client: Client, target: AD, forest: tuple[AD, ...]) -> str:
    """Leave any forest domain, set hostname, join ``target``. Return prior hostname."""
    old_hostname = client.host.conn.run("hostname").stdout.strip()
    short_hostname = old_hostname.split(".")[0].strip()
    hostname = f"{short_hostname}.{target.domain}"

    client.fs.write("/etc/hostname", f"{hostname}\n")
    client.host.conn.run(f"hostname {hostname}")

    for domain in forest:
        _ad_forest_leave(client, domain)

    client.fs.rm("/etc/krb5.conf")
    client.fs.rm("/etc/krb5.keytab")

    # Stale computer objects (especially after leave/rejoin across forest domains)
    # cause "Insufficient permissions to join the domain".
    _ad_forest_remove_stale_computer(forest, short_hostname)

    result = client.host.conn.exec(
        ["realm", "join", target.domain],
        input=target.host.adminpw,
        raise_on_error=False,
    )
    if result.rc != 0:
        _ad_forest_leave(client, target)
        _ad_forest_remove_stale_computer(forest, short_hostname)
        client.host.conn.exec(["realm", "join", target.domain], input=target.host.adminpw)

    # realmd starts sssd with its own conf; stop it so later client.sssd.start()
    # applies the test-written configuration (systemctl start is a no-op if active).
    client.sssd.stop(raise_on_error=False)

    _ad_forest_set_dns(client, target, forest)
    # Cross-forest GC lookups need SRV discovery (legacy ad_forest auth.sh).
    target.host.client["ad_server"] = "_srv_"

    return old_hostname


def _ad_forest_restore_hostname(client: Client, hostname: str) -> None:
    client.fs.write("/etc/hostname", f"{hostname}\n")
    client.host.conn.run(f"hostname {hostname}", raise_on_error=False)


@mh_fixture()
def join_ad_root(client: Client, ad: AD, ad_child: AD, ad_tree: AD):
    """
    Join the client to the AD forest root.

    Yields ``ad`` — use it for users/groups and ``client.sssd.import_domain``.
    For :attr:`~sssd_test_framework.topology.KnownTopology.ADForest`. Leaves on teardown.
    """
    forest = (ad, ad_child, ad_tree)
    old_hostname = _ad_forest_join(client, ad, forest)
    yield ad
    _ad_forest_leave(client, ad)
    _ad_forest_restore_dns(client)
    _ad_forest_restore_hostname(client, old_hostname)


@mh_fixture()
def join_ad_child(client: Client, ad: AD, ad_child: AD, ad_tree: AD):
    """
    Join the client to the AD child domain.

    Yields ``ad_child`` — use it for users/groups and ``client.sssd.import_domain``.
    For :attr:`~sssd_test_framework.topology.KnownTopology.ADForest`. Leaves on teardown.
    """
    forest = (ad, ad_child, ad_tree)
    old_hostname = _ad_forest_join(client, ad_child, forest)
    yield ad_child
    _ad_forest_leave(client, ad_child)
    _ad_forest_restore_dns(client)
    _ad_forest_restore_hostname(client, old_hostname)


@mh_fixture()
def join_ad_tree(client: Client, ad: AD, ad_child: AD, ad_tree: AD):
    """
    Join the client to the AD tree domain.

    Yields ``ad_tree`` — use it for users/groups and ``client.sssd.import_domain``.
    For :attr:`~sssd_test_framework.topology.KnownTopology.ADForest`. Leaves on teardown.
    """
    forest = (ad, ad_child, ad_tree)
    old_hostname = _ad_forest_join(client, ad_tree, forest)
    yield ad_tree
    _ad_forest_leave(client, ad_tree)
    _ad_forest_restore_dns(client)
    _ad_forest_restore_hostname(client, old_hostname)
