Testing Passkeys
################

Passkey can be tested using passkey related methods from
:class:`sssd_test_framework.utils.sssctl.SSSCTLUtils` and
:meth:`sssd_test_framework.utils.authentication.SUAuthenticationUtils.passkey`.
It requires umockdev in order to correctly mock the passkey hardware token and
record and playback the communications that happens between SSSD and
the token.

Three umockdev files are required to mock the device and playback the communication:

* device description (can be shared with all tests)
* ioctl description (can be shared with all tests)
* script of communication (mostly unique for each test)

You can store the files in data directories that are returned by
:func:`sssd_test_framework.fixtures.moduledatadir` (device and ioctl) and
:func:`sssd_test_framework.fixtures.testdatadir` (script, passkey mapping)
fixtures.

Test examples
=============

.. code-block:: python

    from __future__ import annotations

    import pytest
    from sssd_test_framework.roles.client import Client
    from sssd_test_framework.roles.generic import GenericProvider
    from sssd_test_framework.roles.ipa import IPA
    from sssd_test_framework.topology import KnownTopology


    @pytest.mark.tier(0)
    @pytest.mark.topology(KnownTopology.Client)
    def test_passkey__register__sssctl(client: Client, moduledatadir: str, testdatadir: str):
        """ Test registration of the passkey token with sssctl passkey-register"""
        mapping = client.sssctl.passkey_register(
            username="user1",
            domain="ldap.test",
            pin=123456,
            device=f"{moduledatadir}/umockdev.device",
            ioctl=f"{moduledatadir}/umockdev.ioctl",
            script=f"{testdatadir}/umockdev.script",
        )
        with open(f"{testdatadir}/passkey-mapping") as f:
            assert mapping == f.read().strip()


    @pytest.mark.tier(0)
    @pytest.mark.topology(KnownTopology.IPA)
    def test_passkey__register__ipa(ipa: IPA, moduledatadir: str, testdatadir: str):
        """ Test registration of the passkey token with ipa user-add-passkey --register"""
        mapping = (
            ipa.user("user1")
            .add()
            .passkey_add_register(
                pin=123456,
                device=f"{moduledatadir}/umockdev.device",
                ioctl=f"{moduledatadir}/umockdev.ioctl",
                script=f"{testdatadir}/umockdev.script",
            )
        )

        with open(f"{testdatadir}/passkey-mapping") as f:
            assert mapping == f.read().strip()


    @pytest.mark.tier(0)
    @pytest.mark.topology(KnownTopology.LDAP)
    @pytest.mark.topology(KnownTopology.IPA)
    def test_passkey__su(client: Client, provider: GenericProvider, moduledatadir: str, testdatadir: str):
        """ Test passkey authentication with su"""
        suffix = type(provider).__name__.lower()

        with open(f"{testdatadir}/passkey-mapping.{suffix}") as f:
            provider.user("user1").add().passkey_add(f.read().strip())

        client.sssd.start()

        assert client.auth.su.passkey(
            username="user1",
            pin=123456,
            device=f"{moduledatadir}/umockdev.device",
            ioctl=f"{moduledatadir}/umockdev.ioctl",
            script=f"{testdatadir}/umockdev.script.{suffix}",
        )
