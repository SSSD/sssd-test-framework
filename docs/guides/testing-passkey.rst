Testing Passkeys
################

Passkey can be tested using passkey related methods from
:class:`sssd_test_framework.utils.sssctl.SSSCTLUtils` and
:meth:`sssd_test_framework.utils.authentication.SUAuthenticationUtils.passkey`.
It requires `virtual-fido <https://github.com/bulwarkid/virtual-fido>`_ in order to
simulate a virtual FIDO2 authenticator for testing passkey functionality.

**System Requirements**

The ``vhci-hcd`` kernel module must be installed and loaded for virtual-fido
to function properly:

.. code-block:: bash

    # Install the kernel module
    sudo dnf install -y kernel-modules-extra  # On Fedora/RHEL
    # or
    sudo apt install -y linux-modules-extra-$(uname -r)  # On Ubuntu/Debian

    # Load the module
    sudo modprobe vhci-hcd

    # Verify the module is loaded
    lsmod | grep vhci

    # Load the module automatically at boot
    sudo sh -c 'echo "vhci-hcd" > /etc/modules-load.d/vhci-hcd.conf'

Test examples
=============

.. code-block:: python

    from __future__ import annotations

    import pytest
    from sssd_test_framework.roles.client import Client
    from sssd_test_framework.roles.generic import GenericProvider
    from sssd_test_framework.roles.ipa import IPA
    from sssd_test_framework.topology import KnownTopology


    @pytest.mark.topology(KnownTopology.Client)
    @pytest.mark.builtwith(client=["passkey", "vfido"])
    def test_passkey__register_sssctl(client: Client):
        """
        Test registration of the passkey token with sssctl passkey-register
        """
        client.vfido.reset()
        client.vfido.pin_enable()
        client.vfido.pin_set(123456)
        client.vfido.start()

        mapping = client.sssctl.passkey_register(
            username="user1",
            domain="ldap.test",
            pin=123456,
            virt_type="vfido"
        )

        assert mapping.startswith("passkey:"), f"Invalid mapping prefix: {mapping}"


    @pytest.mark.topology(KnownTopology.IPA)
    @pytest.mark.builtwith(client=["passkey", "vfido"], ipa="passkey")
    def test_passkey__register_ipa(client: Client, ipa: IPA):
        """
        Test registration of the passkey token with ipa user-add-passkey --register
        """
        client.vfido.reset()
        client.vfido.pin_enable()
        client.vfido.pin_set(123456)
        client.vfido.start()

        mapping = (
            ipa.user("user1")
            .add()
            .passkey_add_register(
                client=client,
                pin=123456,
                virt_type="vfido"
            )
        )

        assert mapping.startswith("Passkey mapping: passkey:")


    @pytest.mark.topology(KnownTopology.LDAP)
    @pytest.mark.topology(KnownTopology.IPA)
    @pytest.mark.builtwith(client=["passkey", "vfido"], ipa="passkey")
    def test_passkey__su_user(client: Client, provider: GenericProvider):
        """
        Test passkey authentication with su
        """
        client.vfido.reset()
        client.vfido.pin_enable()
        client.vfido.pin_set(123456)
        client.vfido.start()

        user = provider.user("user1").add()
        if isinstance(provider, IPA):
            user.passkey_add_register(client=client, pin=123456, virt_type="vfido")
        else:
            mapping = client.sssctl.passkey_register(
                username="user1", domain=provider.domain, pin=123456, virt_type="vfido"
            )
            user.passkey_add(mapping)

        client.sssd.start()

        assert client.auth.su.passkey(
            username="user1",
            pin=123456,
            virt_type="vfido",
        )
