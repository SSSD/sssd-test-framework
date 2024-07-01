Testing AD GPO HBAC
====================

:class:`~sssd_test_framework.roles.ad.AD.GPO`
provides Group Policy Objects (GPO) management to configure GPO policies on AD. Allowing us
to manage Host Based Access Control(HBAC) from the domain controller. GPOs are windows policies,
consisting of computer and user configurations, registry keys, administrative template, security
settings that are deployed to computers on the domain.

.. code-block:: python
    :caption: Test allow and deny users using GPOs

    @pytest.mark.topology(KnownTopology.AD)
    def test_ad__gpo_is_set_to_enforcing(client: Client, ad: AD):

        allow_user = ad.user("allow_user").add()
        deny_user = ad.user("deny_user").add()

        ad.gpo("test policy").add().policy(
            {
                "SeInteractiveLogonRight": [allow_user, ad.group("Domain Admins")],
                "SeRemoteInteractiveLogonRight": [allow_user, ad.group("Domain Admins")],
                "SeDenyInteractiveLogonRight": [deny_user],
                "SeRemoteDenyInteractiveLogonRight": [deny_user],
            }
        ).link()

        client.sssd.domain["ad_gpo_access_control"] = "enforcing"
        client.sssd.start()

        assert client.auth.ssh.password(username="allow_user", password="Secret123")
        assert not client.auth.ssh.password(username="deny_user", password="Secret123")

Policies
========
SSSD uses the following security keys to manage access control.

* SeInteractiveLogonRight: User or group is permitted to log in locally, TTY sessions and su (required).
* SeRemoteInteractiveLogonRight: User or group is permitted to log in through SSH.
* SeDenyInteractiveLogonRight: User or group is denied to log in locally. (required)
* SeDenyRemoteInteractiveLogonRight: User or group is denied to log in through SSH.

The *Remote* keys can be omitted, in which case the value is copied from the other similar key. The above
policy examples are the same.

.. code-block:: python
    :caption: Remote keys

        ad.gpo("test policy").add().policy(
            {
                "SeInteractiveLogonRight": [allow_user, ad.group("Domain Admins")],
                "SeDenyInteractiveLogonRight": [deny_user],
            }
        ).link()

.. note::
   When configuring the policy, an Administrators group must be added to login.


Inheritance
===========
GPOs are created and linked to a targets, sites, domains, or OUs. Local settings are processed first,
then sites, domains and lastly OUs. Making GPOs linked to the OU take highest precedence. The values
are keys, so the values will not be constructed from all the policies, it will be replaced by the
policy with the higher priority. GPOs can be set to enforcing, which then no policy will override
the enforced policy. Lastly the GPO does have an order, so the order can be defined manually.
