Testing SSSD in offline mode
############################

In order to test SSSD in offline mode, we can use the firewall module from
pytest-mh that is accessible on all Linux and Windows through
:attr:`sssd_test_framework.roles.base.BaseLinuxRole.firewall` (Linux),
:attr:`sssd_test_framework.roles.base.BaseWindowsRole.firewall` (Windows) or
:attr:`sssd_test_framework.roles.generic.GenericProvider.firewall` for
parametrized topology.

Depending on your use case, you want to reject or drop connections to following
ports:

* 389 - LDAP
* 636 - LDAPS
* 88 - KDC
* 3268 - AD Global Catalog (LDAP)
* 3269 - AD Global Catalog (LDAPS)

.. note::

    To test SSSD in offline mode, you usually want to block both lookup and
    authentication ports. You can do it with the following line:

    .. code-block:: python

        # For LDAP (default configuration)
        provider.firewall.drop([88, 389, 3268])

        # For LDAPS
        provider.firewall.drop([88, 636, 3269])

.. note::

    Windows Firewall does not support reject rules only drop rules. Reject rule
    is usually faster since it actively sends "connection rejected" to the
    source and therefore SSSD do not have to wait for timeout. Drop mode will
    just drop the connection and the source must timeout in order to realize
    that.

.. warning::

    **Creating a new firewall rule does not close connections that were already
    established. Therefore SSSD will not go offline until it is forced to
    reconnect and it is fully capable of serving requests in the mean time**.

    To mitigate this, you can either restart SSSD or preferably bring SSSD
    offline by sending SIGUSR1 signal to it. You can do this through our
    framework like this:

    .. code-block:: python

        client.sssd.bring_offline()

.. code-block:: python
    :caption: Testing offline authentication

    @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
    @pytest.mark.parametrize("method", ["su", "ssh"])
    def test_example(client: Client, provider: GenericProvider, method: str):
        # Create user
        provider.user("user-1").add(password="Secret123")

        # Configure SSSD to support offline authentication
        client.sssd.domain["cache_credentials"] = "True"
        client.sssd.domain["krb5_store_password_if_offline"] = "True"
        client.sssd.pam["offline_credentials_expiration"] = "0"

        # Start SSSD
        client.sssd.start()

        # Authenticate the user in order to cache the password
        assert client.auth.parametrize(method).password("user-1", "Secret123")

        # Block KDC, LDAP and Global Catalog ports.
        provider.firewall.drop([88, 389, 3268])

        # There might be active connections that are not terminated by creating
        # firewall rule. We need to terminated it by bringing SSSD to offline state
        # explicitly.
        client.sssd.bring_offline()

        # Check that the user can still authenticate with correct password
        assert client.auth.parametrize(method).password("user-1", "Secret123")

        # Check that wrong password is rejected
        assert not client.auth.parametrize(method).password("user-1", "WrongPassword")
