from __future__ import annotations

from typing import Any, Mapping, Self, Tuple, Type

import pytest
from pytest_mh import (
    MultihostConfig,
    MultihostDomain,
    MultihostHost,
    MultihostRole,
    Topology,
    TopologyController,
    TopologyMark,
)

__all__ = [
    "SSSDMultihostConfig",
    "SSSDMultihostDomain",
]


class SSSDTopologyMark(TopologyMark):
    """
    Topology mark is used to describe test case requirements. It defines:

    * **name**, that is used to identify topology in pytest output
    * **topology** (:class:Topology) that is required to run the test
    * **fixtures** that are available during the test run
    * **domains** that will be automatically configured on the client

    .. code-block:: python
        :caption: Example usage

        @pytest.mark.topology(name, topology, domains, fixture1='path1', fixture2='path2', ...)
        def test_fixture_name(fixture1: BaseRole, fixture2: BaseRole, ...):
            assert True

    Fixture path points to a host in the multihost configuration and can be
    either in the form of ``$domain-type.$role`` (all host of given role) or
    ``$domain-type.$role[$index]`` (specific host on given index).

    The ``name`` is visible in verbose pytest output after the test name, for example:

    .. code-block:: console

        tests/test_basic.py::test_case (topology-name) PASSED
    """

    def __init__(
        self,
        name: str,
        topology: Topology,
        *,
        controller: TopologyController | None = None,
        fixtures: dict[str, str] | None = None,
        domains: dict[str, str] | None = None,
    ) -> None:
        """
        :param name: Topology name used in pytest output.
        :type name: str
        :param topology: Topology required to run the test.
        :type topology: Topology
        :param controller: Topology controller, defaults to None
        :type controller: TopologyController | None, optional
        :param fixtures: Dynamically created fixtures available during the test run.
        :type fixtures: dict[str, str] | None, optional
        :param domains: Automatically created SSSD domains on client host
        :type domains: dict[str, str] | None, optional
        """
        super().__init__(name, topology, controller=controller, fixtures=fixtures)

        self.domains: dict[str, str] = domains if domains is not None else {}
        """Map hosts to SSSD domains."""

    def export(self) -> dict:
        """
        Export the topology mark into a dictionary object that can be easily
        converted to JSON, YAML or other formats.

        .. code-block:: python

            {
                'name': 'client',
                'fixtures': { 'client': 'sssd.client[0]' },
                'topology': [
                    {
                        'type': 'sssd',
                        'hosts': { 'client': 1 }
                    }
                ],
                'domains': { 'test': 'sssd.ldap[0]' },
            }

        :rtype: dict
        """
        d = super().export()
        d["domains"] = self.domains

        return d

    @classmethod
    def CreateFromArgs(cls, item: pytest.Function, args: Tuple, kwargs: Mapping[str, Any]) -> Self:
        """
        Create :class:`TopologyMark` from pytest.mark.topology arguments.

        .. warning::

            This should only be called internally. You can inherit from
            :class:`TopologyMark` and override this in order to add additional
            attributes to the marker.

        :param item: Pytest item.
        :type item: pytest.Function
        :raises ValueError: If the marker is invalid.
        :return: Instance of TopologyMark.
        :rtype: Self
        """
        # First three parameters are positional, the rest are keyword arguments.
        if len(args) != 2 and len(args) != 3:
            nodeid = item.parent.nodeid if item.parent is not None else ""
            error = f"{nodeid}::{item.originalname}: invalid arguments for @pytest.mark.topology"
            raise ValueError(error)

        name = args[0]
        topology = args[1]
        domains = args[2] if len(args) == 3 else {}
        controller = kwargs.get("controller", None)
        fixtures = {k: str(v) for k, v in kwargs.get("fixtures", {}).items()}

        return cls(name, topology, controller=controller, fixtures=fixtures, domains=domains)


class SSSDMultihostConfig(MultihostConfig):
    @property
    def provisioned_topologies(self) -> list[str]:
        out = self.confdict.get("provisioned_topologies", [])
        return out if out is not None else []

    @property
    def TopologyMarkClass(self) -> Type[TopologyMark]:
        return SSSDTopologyMark

    @property
    def id_to_domain_class(self) -> dict[str, Type[MultihostDomain]]:
        """
        Map domain id to domain class. Asterisk ``*`` can be used as fallback
        value.

        :rtype: Class name.
        """
        return {"*": SSSDMultihostDomain}


class SSSDMultihostDomain(MultihostDomain[SSSDMultihostConfig]):
    def __init__(self, config: SSSDMultihostConfig, confdict: dict[str, Any]) -> None:
        super().__init__(config, confdict)

    @property
    def role_to_host_class(self) -> dict[str, Type[MultihostHost]]:
        """
        Map role to host class. Asterisk ``*`` can be used as fallback value.

        :rtype: Class name.
        """
        from .hosts.ad import ADHost
        from .hosts.client import ClientHost
        from .hosts.ipa import IPAHost
        from .hosts.kdc import KDCHost
        from .hosts.keycloak import KeycloakHost
        from .hosts.ldap import LDAPHost
        from .hosts.nfs import NFSHost
        from .hosts.samba import SambaHost

        return {
            "ad": ADHost,
            "client": ClientHost,
            "ldap": LDAPHost,
            "ipa": IPAHost,
            "samba": SambaHost,
            "nfs": NFSHost,
            "kdc": KDCHost,
            "keycloak": KeycloakHost,
        }

    @property
    def role_to_role_class(self) -> dict[str, Type[MultihostRole]]:
        """
        Map role to role class. Asterisk ``*`` can be used as fallback value.

        :rtype: Class name.
        """
        from .roles.ad import AD
        from .roles.client import Client
        from .roles.ipa import IPA
        from .roles.kdc import KDC
        from .roles.keycloak import Keycloak
        from .roles.ldap import LDAP
        from .roles.nfs import NFS
        from .roles.samba import Samba

        return {
            "client": Client,
            "ad": AD,
            "ipa": IPA,
            "ldap": LDAP,
            "samba": Samba,
            "nfs": NFS,
            "kdc": KDC,
            "keycloak": Keycloak,
        }
