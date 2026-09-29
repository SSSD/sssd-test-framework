Testing AD Forest
#################

Use :attr:`~sssd_test_framework.topology.KnownTopology.ADForest` for a single
Active Directory forest with a root domain, a child domain, and a tree
domain.

Topology
========

The multihost configuration must provide **three** ``client`` hosts and
**three** ``ad`` hosts, in this order: forest root, child domain, tree domain.
Each client is enrolled into exactly one domain, once, when the topology is
set up -- there is no leave/rejoin between tests.

.. code-block:: yaml
    :caption: Example ``mhc.yaml`` hosts (host order matters for both roles)

    - hostname: client.test
      role: client

    - hostname: client.child.ad.test
      role: client

    - hostname: client.tree.test
      role: client

    - hostname: dc.ad.test
      role: ad
      config:
        client:
          ad_domain: ad.test

    - hostname: dc.child.ad.test
      role: ad
      config:
        client:
          ad_domain: child.ad.test

    - hostname: dc.tree.test
      role: ad
      config:
        client:
          ad_domain: tree.test

Fixtures from the topology mark:

.. list-table::
   :header-rows: 1
   :widths: 20 20 60

   * - Fixture
     - Type
     - Joined to / represents
   * - ``client``
     - :class:`~sssd_test_framework.roles.client.Client`
     - forest root (``ad``)
   * - ``client_child``
     - :class:`~sssd_test_framework.roles.client.Client`
     - child domain (``ad_child``)
   * - ``client_tree``
     - :class:`~sssd_test_framework.roles.client.Client`
     - tree domain (``ad_tree``)
   * - ``ad``
     - :class:`~sssd_test_framework.roles.ad.AD`
     - forest root
   * - ``ad_child``
     - :class:`~sssd_test_framework.roles.ad.AD`
     - child domain
   * - ``ad_tree``
     - :class:`~sssd_test_framework.roles.ad.AD`
     - tree domain

Forest trusts between the three domains must already exist (lab / IdM-CI
provisioning) -- :class:`~sssd_test_framework.topology_controllers.ADForestTopologyController`
does not create them, it only enrolls the three clients, one per domain, in
parallel. It also fails fast in ``topology_setup`` if the ``ad`` hosts in
``mhc.yaml`` are not actually ordered root, child, tree (checked by comparing
domain names), so a lab misconfiguration shows up as a clear setup error
instead of confusing per-test failures.

Unlike :attr:`~sssd_test_framework.topology.KnownTopology.AD`, this topology
does **not** import an SSSD domain or start SSSD on any client. Configure and
start SSSD the same way every other topology does:

.. code-block:: python
    :caption: Root client looks up a user in the child domain via trust

    @pytest.mark.topology(KnownTopology.ADForest)
    def test_forest__child_lookup_from_root(client: Client, ad: AD, ad_child: AD):
        user = ad_child.user("child-user").add()

        client.sssd.import_domain("test", ad)
        client.sssd.start()

        # SSSD discovers the child domain through the forest trust.
        result = client.tools.id(ad_child.fqn(user.name))
        assert result is not None

.. code-block:: python
    :caption: A client joined directly to the child domain

    @pytest.mark.topology(KnownTopology.ADForest)
    def test_forest__child_member_lookup(client_child: Client, ad_child: AD):
        user = ad_child.user("child-user").add()

        client_child.sssd.import_domain("test", ad_child)
        client_child.sssd.start()

        assert client_child.tools.id(user.name) is not None

.. warning::

   Do not assume ``ad`` is reachable or authoritative for objects created on
   ``ad_child`` or ``ad_tree``, or vice versa. Create objects on the role that
   matches the domain you mean, and import/start SSSD on the client that is
   actually joined to it.

Cross-domain groups
====================

:meth:`~sssd_test_framework.roles.ad.ADGroup.add_members` accepts members from
a different forest domain (e.g. a group on ``ad`` with a member from
``ad_child``). Cross-domain adds go through ADSI instead of
``Add-ADGroupMember`` and retry briefly to tolerate replication lag; same the
domain members are unaffected.

.. code-block:: python
    :caption: Group on the root domain with a child-domain member

    @pytest.mark.topology(KnownTopology.ADForest)
    def test_forest__cross_domain_group(ad: AD, ad_child: AD):
        user = ad_child.user("child-user").add()
        group = ad.group("root-group").add()
        group.add_members([user])

GPOs linked across domains
===========================

A GPO created on one domain can be linked onto another domain's site or OU.
Every AD host's :meth:`~sssd_test_framework.hosts.ad.ADHost.restore` already
scrubs orphan ``gPLink`` entries on its own domain root and on the (shared)
site at the end of every test, so a cross-domain link to the domain root or
default site is cleaned up automatically even if the test does nothing. If a
test links a GPO onto some other OU, or wants the GPO gone *immediately*
within the test rather than waiting for teardown, call
:meth:`~sssd_test_framework.roles.ad.GPO.cleanup` explicitly instead:

.. code-block:: python
    :caption: Clean up a GPO linked across domains immediately

    @pytest.mark.topology(KnownTopology.ADForest)
    def test_forest__gpo_cross_domain(ad: AD, ad_child: AD):
        gpo = ad.gpo("forest-policy").add()
        try:
            gpo.link(target=ad_child.host.naming_context)
            ...
        finally:
            GPO.cleanup(gpo)

.. seealso::

   * :attr:`sssd_test_framework.topology.KnownTopology.ADForest`
   * :class:`sssd_test_framework.topology_controllers.ADForestTopologyController`
   * :meth:`sssd_test_framework.roles.ad.ADGroup.add_members`
   * :meth:`sssd_test_framework.roles.ad.GPO.cleanup`
   * :ref:`importing-domain`
   * :doc:`testing-gpo`
