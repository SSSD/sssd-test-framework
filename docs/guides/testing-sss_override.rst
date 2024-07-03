Local override of users and groups
###################################

Class :class:`sssd_test_framework.utils.sss_override.SSSOverrideUtils` provides
an API to manage local overrides for users and groups. Also known as ID views,
instead of being stored in IPA/LDAP server the override data is stored locally
in SSSD's cache.

SSSD must be running for this API to work and it must be restarted after the
first override is created so SSSD can start looking into newly created local
view.

.. code-block:: python
    :caption: Examples

    @pytest.mark.topology(KnownTopology.LDAP)
    @pytest.mark.topology(KnownTopology.AD)
    def test_local_overrides__user(client: Client, provider: GenericProvider):
        # Add user
        provider.user("user-1").add(uid=10001, gid=10001, gecos="gecos")

        # SSSD must be running for sss_override to work
        client.sssd.start()

        # Create local override for the user
        client.sss_override.user("user-1").add(name="o-user-1", uid=20001, gid=20001, gecos="o-gecos")

        # SSSD must be restarted so newly created view can be applied
        client.sssd.restart()

        # Check the result
        result = client.tools.getent.passwd("o-user-1")
        assert result is not None
        assert result.name == "o-user-1"
        assert result.uid == 20001
        assert result.gid == 20001
        assert result.gecos == "o-gecos"
