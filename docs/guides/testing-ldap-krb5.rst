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
