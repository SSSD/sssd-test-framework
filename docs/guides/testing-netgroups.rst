Testing Netgroups
#################

Class :class:`sssd_test_framework.utils.tools.LinuxToolsUtils` provides access
to common system tools, especially the ``getent netgroup`` command which can
be used to assert netgroup triples returned from SSSD. The method can be
accessed from the ``client`` fixture as ``client.tools.getent.netgroup(name)``.

.. code-block:: python
    :caption: getent netgroup command example

    @pytest.mark.topology(KnownTopology.LDAP)
    def test_netgroup(client: Client, ldap: LDAP):
        @pytest.mark.topology(KnownTopology.LDAP)
        def test_example_netgroup(client: Client, ldap: LDAP):
            # Create user
            user = ldap.user("user-1").add()

            # Create two netgroups
            ng1 = ldap.netgroup("ng-1").add()
            ng2 = ldap.netgroup("ng-2").add()

            # Add user and ng2 as members to ng1
            ng1.add_member(user=user)
            ng1.add_member(ng=ng2)

            # Add host as member to ng2
            ng2.add_member(host="client")

            # Start SSSD
            client.sssd.start()

            # Call `getent netgroup ng-1` and assert the results
            result = client.tools.getent.netgroup("ng-1")
            assert result is not None
            assert result.name == "ng-1"
            assert len(result.members) == 2

            # Assert full netgroup triple, including the domain part
            assert "(-,user-1,)" in result.members
            assert "(client,-,)" in result.members
            # or
            assert ("-", "user-1", "") in result.members
            assert ("client", "-", "") in result.members

            # Omit the domain part, it is not checked at all
            assert "(-,user-1)" in result.members
            assert "(client,-)" in result.members
            # or
            assert ("-", "user-1") in result.members
            assert ("client", "-") in result.members


Different styles of asserting members
=====================================

You can use string or tuple to assert netgroups members. Optionally, you can
omit the domain part in which case the domain is not checked at all. This is
useful for topology parametrization due to differences in the IPA provider which
automatically adds IPA domain and it can not be set manually.

There are four possible formats:

* ``"(host, user, domain)"``
* ``"(host, user)"`` - ignores the domain part
* ``("host", "user", "domain")``
* ``("host", "user")`` - ignores the domain part

.. code-block:: python

    # Assert full netgroup triple, including the domain part
    assert "(-,user-1,)" in result.members
    assert "(client,-,)" in result.members
    # or
    assert ("-", "user-1", "") in result.members
    assert ("client", "-", "") in result.members

    # Omit the domain part, it is not checked at all
    assert "(-,user-1)" in result.members
    assert "(client,-)" in result.members
    # or
    assert ("-", "user-1") in result.members
    assert ("client", "-") in result.members

You probably want to use plain string in most scenarios as it is more readable
and easier to write. But it may be nicer to use tuples if you use variables for
the values instead of hard coded string.

Topology parametrization with netgroups
=======================================

Active Directory, LDAP and Samba providers behave exactly the same, however,
there is quite a difference with IPA provider that you must have in mind when
writing generic tests for netgroups.

.. note::

    **The differences are:**

    * IPA automatically adds IPA domain to the netgroup triple
    * The domain part can not be set manually
    * IPA converts existing hosts to the fully qualified name (e.g. ``client``
      to ``client.ipa.test``)
    * IPA generate triples for all host-user combination (so there might be more
      or less triples then you would expect)

    In the following code, we add three members: admin user, client and test
    host. The client host exists in the IPA environment. If this was in plain
    LDAP, we would probably create three triples: ``(-,admin,)``,
    ``(client,-,)``, ``(test,-,)``. But this is what happens:

    .. code-block:: console

        $ ipa netgroup-add ng-1
        $ ipa netgroup-add-member ng1 --users admin
        $ ipa netgroup-add-member ng1 --hosts client
        $ ipa netgroup-add-member ng1 --hosts test
        $ getent netgroup ng-1
        ng-1                  (client.test,admin,ipa.test) (test,admin,ipa.test)

For most simple cases, you can avoid comparing the domain part like this:

.. code-block:: python
    :caption: Example with topology parametrization

    @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
    def test_netgroup(client: Client, provider: GenericProvider):
        u1 = provider.user("user-1").add()
        u2 = provider.user("user-2").add()

        ng1 = provider.netgroup("ng-1").add().add_member(user=u1)
        ng2 = provider.netgroup("ng-2").add().add_member(user=u2, ng=ng1)

        client.sssd.start()

        result = client.tools.getent.netgroup("ng-2")
        assert result is not None
        assert result.name == "ng-2"
        assert len(result.members) == 2
        assert "(-, user-1)" in result.members
        assert "(-, user-2)" in result.members

If you need to test with complex netgroup triples, you need to make sure that
what you create in LDAP and other providers is exactly the same what you get
from IPA (but you can still skip checking the domain part if the test allows
it).
