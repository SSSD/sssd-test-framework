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
