Testing When SSSD is Offline
############################

In order to test SSSD in offline mode, we can use the firewall module from
pytest-mh that is accessible on all Linux and Windows through
:attr:`sssd_test_framework.roles.base.BaseLinuxRole.firewall` (Linux),
:attr:`sssd_test_framework.roles.base.BaseWindowsRole.firewall` (Windows) or
:attr:`sssd_test_framework.roles.generic.GenericProvider.firewall` for
parametrized topology.

Depending on your use case, you want to reject or drop all connections to the
provider; or reject or drop connections to specific ports.

You can do this by creating inbound firewall rules on the provider side or
outbound rules on the client side. Outbound rules are preferred for most
scenarios.

Blocking all connections to specific host
=========================================

This is the preferred method to bring SSSD offline since it blocks all
connections and therefore you can not make a mistake but keeping some important
ports opened (like Global Catalog). It also plays nice with topology
parametrization.

.. code-block:: python

    @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
    def test_firewall(client: Client, provider: GenericProvider):
        client.firewall.outbound.reject_host(provider)

        client.sssd.start()
        ...

The ``reject`` rule sends icmp-host-unreachable reply therefore SSSD does not
have to wait for timeouts, which is beneficial for most cases. If you actually
want SSSD to go through full timeout prodecure, use ``drop_host`` instead.

.. warning::

    **Creating a new firewall rule does not close connections that were already
    established. Therefore if SSSD is running before the rule is created, it
    will not go offline until it is forced to reconnect and it is fully capable
    of serving requests in the mean time**.

    To mitigate this, you can either restart SSSD or preferably bring SSSD
    offline by sending SIGUSR1 signal to it. You can do this through our
    framework like this:

    .. code-block:: python

        @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
        def test_firewall(client: Client, provider: GenericProvider):
            client.sssd.start()
            client.firewall.outbound.reject_host(provider)
            client.sssd.bring_offline()
            ...

Blocking individual ports
=========================

You can block individual ports on both incoming and outgoing connections. Using
outgoing connections is the preferred method to mitigate some cases where the
provider does not have firewall enabled.

    .. code-block:: python
        :caption: Using outbound rules on the client side

        @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
        def test_firewall(client: Client, provider: GenericProvider):
            # Block KDC, LDAP and Global Catalog ports.
            client.firewall.outbound.reject_port([88, 389, 3268])

            client.sssd.start()
            ...

    .. code-block:: python
        :caption: Using inbound rules on the provider side

        @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
        def test_firewall(client: Client, provider: GenericProvider):
            # Block KDC, LDAP and Global Catalog ports.
            provider.firewall.inbound.drop_port([88, 389, 3268])

            client.sssd.start()
            ...

.. note::

    Windows Firewall does not support reject rules only drop rules. Reject rule
    is usually faster since it actively sends "connection rejected" to the
    source and therefore SSSD does not have to wait for timeout. Drop mode will
    just drop the connection and the source must timeout in order to realize
    that.

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

        # Block all communication to the provider.
        client.firewall.outbound.reject_host(provider)

        # There might be active connections that are not terminated by creating
        # firewall rule. We need to terminated it by bringing SSSD to offline state
        # explicitly.
        client.sssd.bring_offline()

        # Check that the user can still authenticate with correct password
        assert client.auth.parametrize(method).password("user-1", "Secret123")

        # Check that wrong password is rejected
        assert not client.auth.parametrize(method).password("user-1", "WrongPassword")
