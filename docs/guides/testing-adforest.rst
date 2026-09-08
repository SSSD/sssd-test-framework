Testing AD Forest
#################

Use :attr:`~sssd_test_framework.topology.KnownTopology.ADForest` for a single
Active Directory forest with a root domain, a child domain, and a tree domain.

Topology
========

The multihost configuration must provide one client and three ``ad`` hosts,
**in this order**: forest root, child domain, tree domain.

.. code-block:: yaml
    :caption: Example ``mhc.yaml`` hosts (role ``ad`` order matters)

    - hostname: client.test
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

Role fixtures from the topology mark:

* ``client`` — SSSD client
* ``ad`` — forest root (``sssd.ad[0]``)
* ``ad_child`` — child domain (``sssd.ad[1]``)
* ``ad_tree`` — tree domain (``sssd.ad[2]``)

Forest trusts and domain relationships must already exist (lab / IdM-CI
provisioning). The topology controller does **not** enroll the client and does
**not** set a ``provider`` fixture or auto-import an SSSD domain.

Joining a domain
================

Request one of the join fixtures from
:mod:`sssd_test_framework.fixtures`. Each fixture sets the client hostname,
leaves any forest domain, joins the target with ``realm``, stops ``sssd``
(so a later ``client.sssd.start()`` loads the test configuration — ``realmd``
starts SSSD on join and ``systemctl start`` is a no-op while it is active),
and leaves again on teardown. The fixture **yields the**
:class:`~sssd_test_framework.roles.ad.AD`
**role for that domain** — use that object for users, groups, GPOs, and
``client.sssd.import_domain``.

.. list-table::
   :header-rows: 1
   :widths: 25 30 45

   * - Fixture
     - Joins
     - Yields
   * - ``join_ad_root``
     - forest root
     - ``ad``
   * - ``join_ad_child``
     - child domain
     - ``ad_child``
   * - ``join_ad_tree``
     - tree domain
     - ``ad_tree``

.. warning::

   Do not invent a ``provider`` alias that always points at the root. Creating
   users or groups on ``ad`` while the client is joined to the child or tree
   puts objects in the wrong domain. Prefer the yielded join fixture, or the
   matching role (``ad`` / ``ad_child`` / ``ad_tree``).

Example
=======

.. code-block:: python
    :caption: Join child domain, create a user there, import SSSD domain

    @pytest.mark.topology(KnownTopology.ADForest)
    def test_forest__child_lookup(client: Client, join_ad_child: AD, ad: AD):
        user = join_ad_child.user("child-user").add()

        client.sssd.import_domain("test", join_ad_child)
        client.sssd.start()

        assert client.tools.id(user.name) is not None
        # Root DC is still available when the test needs cross-domain data
        assert ad.domain != join_ad_child.domain

When joined to the forest root, SSSD can discover child and tree domains for
lookup and authentication of users in those domains. When joined to the child
or tree, configure and import the SSSD domain from the same role you joined.

.. seealso::

   * :attr:`sssd_test_framework.topology.KnownTopology.ADForest`
   * :class:`sssd_test_framework.topology_controllers.ADForestTopologyController`
   * :func:`sssd_test_framework.fixtures.join_ad_root`
   * :func:`sssd_test_framework.fixtures.join_ad_child`
   * :func:`sssd_test_framework.fixtures.join_ad_tree`
   * :ref:`importing-domain`
   * :doc:`testing-gpo`
