"""SSSD predefined well-known topologies."""

from __future__ import annotations

from enum import unique
from typing import final

from pytest_mh import KnownTopologyBase, KnownTopologyGroupBase, Topology, TopologyDomain

from .config import SSSDTopologyMark
from .topology_controllers import (
    ADTopologyController,
    ClientTopologyController,
    IPATopologyController,
    IPATrustADTopologyController,
    IPATrustIPATopologyController,
    IPATrustSambaTopologyController,
    LDAPTopologyController,
    SambaTopologyController,
)

__all__ = [
    "KnownTopology",
    "KnownTopologyGroup",
]


@final
@unique
class KnownTopology(KnownTopologyBase):
    """
    Well-known topologies that can be given to ``pytest.mark.topology``
    directly. It is expected to use these values in favor of providing
    custom marker values.

    .. code-block:: python
        :caption: Example usage

        @pytest.mark.topology(KnownTopology.LDAP)
        def test_ldap(client: Client, ldap: LDAP):
            assert True
    """

    Client = SSSDTopologyMark(
        name="client",
        topology=Topology(TopologyDomain("sssd", client=1, kdc=1)),
        controller=ClientTopologyController(),
        fixtures=dict(client="sssd.client[0]", kdc="sssd.kdc[0]"),
    )
    """
    .. topology-mark:: KnownTopology.Client
    """

    LDAP = SSSDTopologyMark(
        name="ldap",
        topology=Topology(TopologyDomain("sssd", client=1, ldap=1, nfs=1, kdc=1)),
        controller=LDAPTopologyController(),
        domains=dict(test="sssd.ldap[0]"),
        fixtures=dict(
            client="sssd.client[0]", ldap="sssd.ldap[0]", provider="sssd.ldap[0]", nfs="sssd.nfs[0]", kdc="sssd.kdc[0]"
        ),
    )
    """
    .. topology-mark:: KnownTopology.LDAP
    """

    IPA = SSSDTopologyMark(
        name="ipa",
        topology=Topology(TopologyDomain("sssd", client=1, ipa=1, nfs=1)),
        controller=IPATopologyController(),
        domains=dict(test="sssd.ipa[0]"),
        fixtures=dict(client="sssd.client[0]", ipa="sssd.ipa[0]", provider="sssd.ipa[0]", nfs="sssd.nfs[0]"),
    )
    """
    .. topology-mark:: KnownTopology.IPA
    """

    AD = SSSDTopologyMark(
        name="ad",
        topology=Topology(TopologyDomain("sssd", client=1, ad=1, nfs=1)),
        controller=ADTopologyController(),
        domains=dict(test="sssd.ad[0]"),
        fixtures=dict(client="sssd.client[0]", ad="sssd.ad[0]", provider="sssd.ad[0]", nfs="sssd.nfs[0]"),
    )
    """
    .. topology-mark:: KnownTopology.AD
    """

    Samba = SSSDTopologyMark(
        name="samba",
        topology=Topology(TopologyDomain("sssd", client=1, samba=1, nfs=1)),
        controller=SambaTopologyController(),
        domains={"test": "sssd.samba[0]"},
        fixtures=dict(client="sssd.client[0]", samba="sssd.samba[0]", provider="sssd.samba[0]", nfs="sssd.nfs[0]"),
    )
    """
    .. topology-mark:: KnownTopology.Samba
    """

    IPATrustAD = SSSDTopologyMark(
        name="ipa-trust-ad",
        topology=Topology(TopologyDomain("sssd", client=1, ipa=1, ad=1)),
        controller=IPATrustADTopologyController(),
        domains=dict(test="sssd.ipa[0]"),
        fixtures=dict(client="sssd.client[0]", ipa="sssd.ipa[0]", ad="sssd.ad[0]", trusted="sssd.ad[0]"),
    )
    """
    .. topology-mark:: KnownTopology.IPATrustAD
    """

    IPATrustSamba = SSSDTopologyMark(
        name="ipa-trust-samba",
        topology=Topology(TopologyDomain("sssd", client=1, ipa=1, samba=1)),
        controller=IPATrustSambaTopologyController(),
        domains=dict(test="sssd.ipa[0]"),
        fixtures=dict(client="sssd.client[0]", ipa="sssd.ipa[0]", samba="sssd.samba[0]", trusted="sssd.samba[0]"),
    )
    """
    .. topology-mark:: KnownTopology.IPATrustSamba
    """

    IPATrustIPA = SSSDTopologyMark(
        name="ipa-trust-ipa",
        topology=Topology(TopologyDomain("sssd", client=1, ipa=1), TopologyDomain("ipa2", ipa=1)),
        controller=IPATrustIPATopologyController(),
        domains=dict(test="sssd.ipa[0]"),
        fixtures=dict(client="sssd.client[0]", ipa="sssd.ipa[0]", trusted="ipa2.ipa[0]"),
    )
    """
    .. topology-mark:: KnownTopology.IPATrustIPA
    """


class KnownTopologyGroup(KnownTopologyGroupBase):
    """
    Groups of well-known topologies that can be given to ``pytest.mark.topology``
    directly. It is expected to use these values in favor of providing
    custom marker values.

    The test is parametrized and runs multiple times, once per each topology.

    .. code-block:: python
        :caption: Example usage (runs on AD, IPA, LDAP and Samba topology)

        @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
        def test_ldap(client: Client, provider: GenericProvider):
            assert True
    """

    AnyProvider = [KnownTopology.AD, KnownTopology.IPA, KnownTopology.LDAP, KnownTopology.Samba]
    """
    .. topology-mark:: KnownTopologyGroup.AnyProvider
    """

    AnyAD = [KnownTopology.AD, KnownTopology.Samba]
    """
    .. topology-mark:: KnownTopologyGroup.AnyAD
    """

    IPATrustAD = [KnownTopology.IPATrustAD, KnownTopology.IPATrustSamba]
    """
    .. topology-mark:: KnownTopologyGroup.IPATrustAD
    """

    AnyIPATrust = [KnownTopology.IPATrustAD, KnownTopology.IPATrustSamba, KnownTopology.IPATrustIPA]
    """
    .. topology-mark:: KnownTopologyGroup.AnyIPATrust
    """
