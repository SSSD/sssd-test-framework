Testing IPA Trusts
##################

To test setup with IPA server and trusted Active Directory or Samba domain,
you can use the following topologies:

* :attr:`sssd_test_framework.topology.KnownTopology.IPATrustAD`
* :attr:`sssd_test_framework.topology.KnownTopology.IPATrustSamba`
* :attr:`sssd_test_framework.topology.KnownTopologyGroup.IPATrust` (parametrized)

The topology provides `trusted` fixture, which is the reference to the trusted
domain role object (either :class:`~sssd_test_framework.roles.ad.AD` or
:class:`~sssd_test_framework.roles.ad.Samba`). You can use
:class:`~sssd_test_framework.roles.generic.GenericADProvider` generic class for
parametrized tests.

.. code-block:: python
    :caption: Example usage

    @pytest.mark.topology(KnownTopologyGroup.IPATrust)
    def test_trust__example(ipa: IPA, trusted: GenericADProvider):
        username = trusted.fqn("administrator")
        external = ipa.group("external-group").add(external=True).add_member(username)
        ipa.group("posix-group").add(gid=5001).add_member(external)

        ipa.sssd.clear(db=True, memcache=True, logs=True)
        ipa.sssd.restart()

        # Cache trusted user
        result = ipa.tools.id(username)
        assert result is not None
        assert result.user.name == username
        assert result.memberof("posix-group")

        # Expire the user and resolve it again, this will trigger the affected code path
        ipa.sssctl.cache_expire(user=username)
        result = ipa.tools.id(username)
        assert result is not None
        assert result.user.name == username
        assert result.memberof("posix-group")

        # Check that SSSD did not go offline
        result = ipa.sssctl.domain_status(trusted.domain, online=True)
        assert "online status: offline" not in result.stdout.lower()
        assert "online status: online" in result.stdout.lower()
