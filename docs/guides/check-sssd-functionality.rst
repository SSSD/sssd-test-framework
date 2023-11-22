Skipping tests if SSSD is missing feature
#########################################

On some situations, SSSD code base is providing specific functionality by
enabling it via a configure time flag. A typical example is a files provider
which is now deprecated and disabled by default, but it is possible to build
SSSD with files provide enabled. In such situation, it is desirable to run
files provider tests but skip them if SSSD is built without files provider
support.

You can use ``@pytest.mark.builtwith`` decorator to add requirement on
specific SSSD feature.

.. code-block:: python

    @pytest.mark.topology(KnownTopology.Client)
    @pytest.mark.builtwith("files-provider")
    def test_files_provider__example(client: Client):
        pass

.. note::

    The SSSD client can automatically detect supported SSSD features. To extend
    the detection mechanism, alter
    :attr:`sssd_test_framework.hosts.client.ClientHost.features`.

.. seealso::

    ``@pytest.mark.builtwith`` is internally converted into
    ``@pytest.mark.require`` which comes from pytest-mh. You can use this marker
    for some advanced conditions. See `pytest-mh documentation
    <https://pytest-mh.readthedocs.io/en/latest/runtime-requirements.html>`__
    for more information.

Supported features
==================

* ``files-provider`` - SSSD is built with files provider support
* ``passkey`` - SSSD is built with 'passkey' authentication support

Checking supported functionality in other roles
###############################################

Even though the main purpose and default setting of the
``@pytest.mark.builtwith`` marker is to check built functionality of SSSD on the
client machine, it is also possible to use this marker in a more generic way to
check functionality on other hosts as well by adding keyword arguments to the
marker. Each key is one of the test role fixture.

.. code-block:: python

    @pytest.mark.topology(KnownTopology.IPA)
    @pytest.mark.builtwith(ipa="passkey")
    def test_passkey_ipa__example(client: Client, ipa: IPA):
        pass

It is also possible to check for multiple features at once. In this case,
features must be supported by all hosts, otherwise the test is skipped.

.. code-block:: python

    @pytest.mark.topology(KnownTopology.IPA)
    @pytest.mark.builtwith(client="passkey", ipa="passkey")
    def test_passkey_client_and_ipa__example(client: Client, ipa: IPA):
        pass

.. note::

    It is also possible to specify multiple features at once as a list for more
    complex requirements.

    .. code-block:: python

        @pytest.mark.topology(KnownTopology.IPA)
        @pytest.mark.builtwith(client=["client-feature-1", "client-feature-2"], ipa=["ipa-feature-1", "ipa-feature-2"])
        def test_example(client: Client, ipa: IPA):
            pass
