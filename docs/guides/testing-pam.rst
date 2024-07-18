Testing PAM Modules
###################

Class :class:`sssd_test_framework.utils.pam.PAMUtils` provides
an API to manage PAM module configuration. Currently pam_access and pam_faillock is supported.

pam_access
==========
A module for logdaemon style login access control. This is managed by /etc/security/access.conf.

.. code-block:: python
    :caption: Example PAM Access usage

    @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
    def test_example(client: Client, provider: GenericProvider):
        # Add users
        provider.user("user-1").add()
        provider.user("user-2").add()

        # Add access rules
        access = client.pam.access()
        access.config_set([{"access": "+", "user": "user-1", "origin": "ALL"},
                               {"access": "-", "user": "user-2", "origin": "ALL"}])

        client.sssd.authselect.enable_feature(["with-pamaccess"])
        client.sssd.domain["use_fully_qualified_names"] = "False"
        client.sssd.start()

        assert client.auth.ssh.password("user-1", "Secret123")
        assert not client.auth.ssh.password("user-2", "Secret123")

pam_faillock
============
A module that counts authentication failures. This is configured in /etc/security/faillock.conf.

.. code-block:: python
    :caption: Example PAM Faillock usage

    @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
    def test_example(client: Client, provider: GenericProvider):
        # Add user
        provider.user("user-1").add()
        faillock = client.pam.faillock()
        faillock.config_set({"deny": "3", "unlock_time": "300"})

        client.sssd.common.pam(["with-faillock"])
        client.sssd.start()

        assert client.auth.ssh.password("user-1", "Secret123")

        for i in range(3):
            client.auth.ssh.password("user-1", "BadSecret123")

        assert not client.auth.ssh.password("user-1", "Secret123")

        # Reset user lockout
        client.tools.faillock(["--user", "user-1", "--reset"])

        assert client.auth.ssh.password("user-1", "Secret123")
