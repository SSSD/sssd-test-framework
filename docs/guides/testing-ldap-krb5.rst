Testing LDAP With Kerberos
##########################

SSSD's LDAP provider can be configured to use Kerberos as the authentication
provider. The framework provides tools to automatically configure the LDAP
domain with ``auth_provider = krb5``, using the Kerberos configuration from
given KDC role object. It also provides means to run Kerberos tools such as
``kinit``, ``klist`` and ``kdestroy``.

LDAP_KRB5 topology
------------------

:attr:`~sssd_test_framework.topology.KnownTopology.LDAP_KRB5` is the mark for
client + LDAP + KDC with **no NFS** host. Think of it as
:attr:`~sssd_test_framework.topology.KnownTopology.BareLDAP` plus a KDC fixture.

Setup is handled by
:class:`~sssd_test_framework.topology_controllers.LDAPKRB5TopologyController`:

* ensure ``host/<client fqdn>`` exists in the KDC (create if missing);
* place keys in ``/etc/krb5.keytab`` on the client;
* set ``ldap_krb5_keytab`` on the LDAP provider defaults when not already set in
  multihost config.

That is enough for LDAP GSSAPI (``ldap_sasl_mech = gssapi``) without each test
running ``ktadd``/upload itself. Tests still call
``client.sssd.common.krb5_auth(kdc)`` and configure the SSSD domain as usual.

Reusable client utilities
-------------------------

LDAP/Kerberos system tests can share the following helpers (no per-test ``named``
or ``getent`` boilerplate):

* :class:`~sssd_test_framework.utils.tools.AHostSv4Entry` /
  :meth:`~sssd_test_framework.utils.tools.GetentUtils.ahostsv4` —
  first IPv4 from ``getent ahostsv4`` on the client (NSS, not ``dig``).

* :meth:`~sssd_test_framework.utils.tools.GetentUtils.resolve_ipv4` —
  ``client.tools.getent.resolve_ipv4(hostname, host=role.host)`` uses topology
  ``host.ip`` when set, otherwise ``getent ahostsv4``.

* :meth:`~sssd_test_framework.utils.network.NetworkUtils.dig` —
  ``client.net.dig(name, server)`` for A/PTR/SRV checks (prefer over shell ``dig``).

* :meth:`~sssd_test_framework.utils.network.NetworkUtils.prepare_ldap_krb5_srv_discovery` —
  ensures ``_ldap._tcp`` and ``_kerberos._udp`` SRV for the discovery domain (lab DNS,
  ``dns.test``, or local ``named`` on the client).

* :meth:`~sssd_test_framework.utils.network.NetworkUtils.setup_sasl_canonicalize_bogus_ptr` —
  local ``named`` + ``/etc/hosts`` setup for BZ 732935 (bogus PTR for the LDAP
  server IP, forward A for the LDAP FQDN, ``resolv.conf`` → ``127.0.0.1``).
  Files are backed up via ``client.fs`` and restored after the test.

* :func:`~sssd_test_framework.misc.ip_to_ptr` — reverse zone name for an IPv4
  address (also used inside the bogus-PTR helper).

Kerberos templates from :meth:`~sssd_test_framework.roles.kdc.KDC.config` include
``rdns = false`` in ``[libdefaults]`` so tests that call
``client.sssd.common.krb5_auth(kdc)`` do not need to edit ``/etc/krb5.conf`` for
that option.

.. seealso::

    * :class:`sssd_test_framework.roles.kdc.KDC`
    * :class:`sssd_test_framework.utils.authentication.KerberosAuthenticationUtils`
    * :attr:`sssd_test_framework.utils.authentication.AuthenticationUtils.kerberos`

.. note::

    To access the KDC role, you need to add additional hostname to the
    ``mhc.yaml`` multihost configuration. For example:

    .. code-block:: yaml

        - hostname: kdc.test
          role: kdc
          config:
            realm: TEST
            domain: test
            client:
              krb5_server: kdc.test
              krb5_kpasswd: kdc.test
              krb5_realm: TEST


.. code-block:: python
    :caption: LDAP with Kerberos authentication example

    @pytest.mark.topology(KnownTopology.LDAP)
    def test_kdc(client: Client, ldap: LDAP, kdc: KDC):
        ldap.user('tuser').add()
        kdc.principal('tuser').add()

        client.sssd.common.krb5_auth(kdc)
        client.sssd.start()

        with client.ssh('tuser', 'Secret123') as ssh:
            with client.auth.kerberos(ssh) as krb:
                result = krb.klist()
                assert f'krbtgt/{kdc.realm}@{kdc.realm}' in result.stdout
