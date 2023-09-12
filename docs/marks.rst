Additional markers and metadata
###############################

Additional test metadata
************************

The following metadata are **required** to be present in docstring of each test.
These metadata are used to organize test in Polarion to provide evidency and
traceability for enterprise releases.

.. code-block:: python
    :caption: Required metadata

    def test_example():
        """
        :title: Human readable test title
        :setup:
            1. Setup step
            ...
            N. Setup step
        :steps:
            1. Assert step
            ...
            N. Assert step
        :expectedresults:
            1. Expected result of assert step 1
            ...
            N. Expected result of assert step N
        :teardown:
            1. Teardown step
            ...
            N. Teardown step
        :customerscenario: False|True
        """

* **title**: Simple test case description.
* **setup**: All steps required to setup the environment before assertions (e.g.
  what users are created).
* **steps**: Individual test or assertion steps.
* **expectedresults**: Expected result of each step.
* **teardown** (optional): All steps required to teardown environment. This
  field is usually omitted. But it can be used to document some very specific
  teardown steps if required.
* **customerscenario**: Is this test related to a Red Hat Customer Case?

.. code-block:: python
    :caption: Metadata example

    @pytest.mark.topology(KnownTopology.Client)
    def test_kcm__tgt_renewal(client: Client, kdc: KDC):
        """
        :title: Automatic ticket-granting ticket renewal.
        :setup:
            1. Add Kerberos principal "tuser" to KDC
            2. Add local user "tuser"
            3. Enable TGT renewal in KCM
            4. Start SSSD
        :steps:
            1. Authenticate as "tuser" over SSH
            2. Kinit as "tuser" and request renewable ticket
            3. Wait until automatic renewal is triggered and check that is was renewed
        :expectedresults:
            1. User is logged into the host
            2. TGT is available
            3. TGT was renewed
        :customerscenario: False
        """

Additional markers
******************

Besides the ``topology`` mark, that is required and that defines which hosts
from the multihost configuration are relevant for the test, there are also other
marks that you can use to enhance the testing experience.

@pytest.mark.ticket
===================

The `ticket mark <https://github.com/next-actions/pytest-ticket>`__ can
associate a test with Github issues and Bugzilla or JIRA tickets.

The ``@pytest.mark.ticket`` takes one or more keyword arguments that represents
the tracker tool and the ticket identifier. The value may be single ticket or
list of tickets.

.. code-block:: python
    :caption: Examples

    @pytest.mark.ticket(gh=3433)
    def test_gh()
        pass

    @pytest.mark.ticket(bz=5003433)
    def test_bz()
        pass

    @pytest.mark.ticket(jira="SSSD-3433")
    def test_jira()
        pass

    @pytest.mark.ticket(gh=3433, bz=5003433, jira="SSSD-3433")
    def test_all()
        pass

    @pytest.mark.ticket(gh=3433, bz=[5003433, 5003434], jira="SSSD-3433")
    def test_multi()
        pass

You can then run tests that are relevant only to the selected ticket:

.. code-block:: text

    cd src/tests/system
    pytest --mh-config=mhc.yaml --mh-lazy-ssh -v --ticket=gh#3433

@pytest.mark.importance
=======================

The `importance mark <https://github.com/next-actions/pytest-importance>`__ can
associate a test with a level of importance. This is used by quality engineers to
prioritize the test determined by the level of impact to the customer.

The ``@pytest.mark.importance`` takes a string as an argument. The values used
are "critical", "high", "medium" and "low". If no marker is defined, the importance
defaults to medium.

.. code-block:: python
    :caption: Examples

    @pytest.mark.importance("critical")
    def test_importance_critical()
        pass

    @pytest.mark.importance("high")
    def test_importance_high()
        pass

You can then run the tests by importance:

.. code-block:: text

    cd src/tests/system
    pytest --mh-config=mhc.yaml --mh-lazy-ssh -v --importance="critical"

Importance definition
---------------------

* **critical:**
  Core subset of tests that covers most important operational features.
  This is used in pipelines where it maybe ran multiple times a day in downstream CI.
  The execution time should be kept as short as possible.

* **high:** The comprehensive set of tests, that covers all operational features.
  This is used for gating where it maybe ran several times a day in downstream CI.
  To manage resources, the execution time should be kept under an hour.

* **medium:** Extended set that covers tests that do not impact operational functionality,
  like the CLI commands included in sss-tools package. Tests that cover negative
  scenarios and misconfigured environment fit here as well.

* **low:** Tests that may have a long execution time, edge cases or complex scenarios that
  demand a lot of resources. Consider performance and stress tests as part of this set.

@pytest.mark.custom
===================

The use of `custom markers <https://docs.pytest.org/en/latest/how-to/mark.html>`__
help group tests into categories; identity, authentication, authorization are
some examples. This is predominately used by quality engineers to organize tests by features.

.. code-block:: python
    :caption: Examples

    @pytest.mark.authentication
    def test_authenticate_user()
        pass

You can run tests by custom markers:

.. code-block:: text

    cd src/tests/system
    pytest --mh-config-mhc=mhc.yaml --mh-lazy-ssh -v -m authentication

Custom Marker definitions
-------------------------

* **authentication:** Tests checking user and password policies and anything to do with the login prompt.
* **authorization:** Tests checking user access after login like sudo and credential delegation.
* **cache:** Tests checking the local cache like timeout, negative cache and refresh.
* **config:** Tests for SSSD configuration file, editing and tooling. 
* **contains_workaround:** Test requires workaround for an existing bug. (gh=...,bz=...)
* **identity:** Tests checking user identity lookups, group memberships, domain priority and id mapping.
* **schema:** Tests checking ldap schemas, rfc2307, rfc2307bis, AD and directory attributes.
* **slow:** Tests that are slow. (deselect with '-m "not slow"')
* **tools:** Tests for all SSSD CLI commands; sssctl, sss_cache, sss_override, etc.
