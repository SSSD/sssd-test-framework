Multihost configuration
#######################

The multihost configuration file contains definition of the domains, hosts and
their roles that are available to run the tests. It uses the `YAML
<https://en.wikipedia.org/wiki/YAML>`__ language.

Basic definition
****************

.. code-block:: yaml

    provisioned_topologies:
    - <list-of-topologies>
    domains:
    - id: <domain id>
      hosts:
      - hostname: <dns host name>
        role: <host role>
        conn:
          type: ssh
          host: <ssh host> (optional, defaults to host name)
          port: <ssh port> (optional, defaults to 22)
          username: <ssh username> (optional, defaults to "root")
          password: <ssh password> (optional, defaults to "Secret123")
        config: <additional configuration> (optional, defaults to {})
        artifacts: <list of produced artifacts> (optional, defaults to {})

Optionally, a list of topologies that are already provisioned my be specified in
``provisioned_topologies`` field. If a topology name is given, it is considered
fully provisioned and tests are run directly. If a topology is not found in this
list, it is provisioned via a topology controller before any test for this
topology is executed.

The main element of the multihost configuration is list of ``domains``. Each
domain has ``id`` attribute and defines the list of available hosts.

* ``id``: domain identifier which is used in the path inside ``mh`` fixture, see
  :ref:`mh-fixture`
* ``hosts``: list of available hosts and their roles

  * ``hostname``: DNS host name, it may not necessarily be resolvable from the
    machine that runs pytest
  * ``role``: host role
  * ``conn.host``: ssh host to connect to (it may be a resolvable host name or an
    IP address), defaults to the value of ``hostname``
  * ``conn.port``: ssh port, defaults to 22
  * ``conn.username``: ssh username, defaults to ``root``
  * ``conn.password``: ssh password for the user, defaults to ``Secret123``
  * ``config``: additional host configuration
  * ``artifacts``: list of artifacts that are automatically downloaded

.. _available-roles:

Available roles
***************

Currently available roles are:

* ``client``: SSSD client enrolled into desired providers
* ``ldap``: 389ds directory server
* ``ipa``: FreeIPA server
* ``ad``: Active Directory server
* ``samba``: Samba DC
* ``nfs``: NFS server
* ``kdc``: KDC server

client
======

SSSD client enrolled into the provider that you want to run the tests against.
If a keytab is required by the provider it must be present somewhere on the
host. The keytab is then specified in the additional configuration of the
provider host.

.. code-block:: yaml
    :caption: Client role example

    - hostname: client.test
      role: client
      artifacts:
      - /etc/sssd/*
      - /var/log/sssd/*
      - /var/lib/sss/db/*

Additional configuration (host/config section)
----------------------------------------------

* :ref:`config-artifacts`
* :ref:`config-auditd`

.. seealso::

    `Example setup of the Client host <https://github.com/SSSD/sssd-ci-containers/blob/master/src/ansible/roles/client/tasks/main.yml>`__

ldap
====

Fresh installation of 389ds directory server with TLS/SSL enabled and no data
present (i.e. no object is present under the default naming context).

.. code-block:: yaml
    :caption: LDAP role example

    - hostname: master.ldap.test
      role: ldap
      config:
        binddn: cn=Directory Manager
        bindpw: Secret123
        client:
          ldap_tls_reqcert: demand
          ldap_tls_cacert: /data/certs/ca.crt
          dns_discovery_domain: ldap.test

Additional configuration (host/config section)
----------------------------------------------

* :ref:`config-artifacts`
* :ref:`config-ldap`
* :ref:`config-providers-client`
* :ref:`config-auditd`

.. seealso::

    `Example setup of the LDAP host <https://github.com/SSSD/sssd-ci-containers/blob/master/src/ansible/roles/ldap/tasks/main.yml>`__

ipa
===

Fresh installation of FreeIPA server with no additional data. Trust to single
Active Directory and Samba domain is created.

.. code-block:: yaml
    :caption: IPA role example

    - hostname: master.ipa.test
      role: ipa
      config:
        client:
          ipa_domain: ipa.test
          krb5_keytab: /enrollment/ipa.keytab
          ldap_krb5_keytab: /enrollment/ipa.keytab

Additional configuration (host/config section)
----------------------------------------------

* :ref:`config-artifacts`
* :ref:`config-providers-client`
* :ref:`config-auditd`
* :ref:`config-coredumpd`

.. seealso::

    `Example setup of the IPA host <https://github.com/SSSD/sssd-ci-containers/blob/master/src/ansible/roles/ipa/tasks/main.yml>`__

ad
==

Fresh installation of Active Directory with no additional data. SSH is installed
on the host and user's default shell is set to PowerShell.

The following extra schema must be installed:

* `sudo schema <https://github.com/SSSD/sssd-ci-containers/blob/master/src/ansible/roles/ad/files/sudo.schema>`__

.. code-block:: yaml
    :caption: AD role example

    - hostname: dc.ad.test
      role: ad
      username: Administrator@ad.test
      password: vagrant
      config:
        binddn: Administrator@ad.test
        bindpw: vagrant
        client:
          ad_domain: ad.test
          krb5_keytab: /enrollment/ad.keytab
          ldap_krb5_keytab: /enrollment/ad.keytab

Additional configuration (host/config section)
----------------------------------------------

* :ref:`config-artifacts`
* :ref:`config-providers-client`

.. seealso::

    `Example setup of the AD host <https://github.com/SSSD/sssd-ci-containers/blob/master/src/ansible/roles/ad/tasks/main.yml>`__

samba
=====

Fresh installation of Samba DC with no additional data.

The following extra schema must be installed:

* sudo schema `class <https://github.com/SSSD/sssd-ci-containers/blob/master/src/ansible/roles/samba/files/sudo.class.ldif>`__, `attrs <https://github.com/SSSD/sssd-ci-containers/blob/master/src/ansible/roles/samba/files/sudo.attrs.ldif>`__

.. code-block:: yaml
    :caption: Samba role example

    - hostname: dc.samba.test
      role: samba
      config:
        binddn: CN=Administrator,CN=Users,DC=samba,DC=test
        bindpw: Secret123
        client:
          ad_domain: samba.test
          krb5_keytab: /enrollment/samba.keytab
          ldap_krb5_keytab: /enrollment/samba.keytab

Additional configuration (host/config section)
----------------------------------------------

* :ref:`config-artifacts`
* :ref:`config-ldap`
* :ref:`config-providers-client`
* :ref:`config-auditd`
* :ref:`config-coredumpd`

.. seealso::

    `Example setup of the Samba host <https://github.com/SSSD/sssd-ci-containers/blob/master/src/ansible/roles/samba/tasks/main.yml>`__

nfs
===

Fresh installation of NFS server, with the server running and no exported
directories.

.. code-block:: yaml
    :caption: NFS role example

    - hostname: nfs.test
      role: nfs
      config:
        exports_dir: /dev/shm/exports

Additional configuration (host/config section)
----------------------------------------------

* ``exports_dir``: Path to the directory that will be used as a parent for all
  directories that will be created and exported on the NFS server. On
  containers, this should be ``/dev/shm/exports`` or other writable location
  that runs on ``tmpfs`` file system.
* :ref:`config-artifacts`
* :ref:`config-auditd`
* :ref:`config-coredumpd`

.. seealso::

    `Example setup of the NFS host <https://github.com/SSSD/sssd-ci-containers/blob/master/src/ansible/roles/nfs/tasks/main.yml>`__

kdc
===

Fresh installation of Kerberos KDC server, with the server running and no
additional principals.

.. code-block:: yaml
    :caption: KDC role example

    - hostname: kdc.test
      role: kdc

Additional configuration (host/config section)
----------------------------------------------

* ``domain``: Default Kerberos domain.
* ``realm``: Default Kerberos realm.
* :ref:`config-artifacts`
* :ref:`config-providers-client`
* :ref:`config-auditd`
* :ref:`config-coredumpd`

.. seealso::

    `Example setup of the KDC host <https://github.com/SSSD/sssd-ci-containers/blob/master/src/ansible/roles/kdc/tasks/main.yml>`__

Additional configuration (host/config section)
**********************************************

.. _config-artifacts:

Gathering artifacts
===================

The ``config`` section of the host definition can be also used to specify which
artifacts should be automatically collected from the host when a test is
finished using the ``artifacts`` keyword which contains a list of artifacts. The
values are path to the artifacts with a possible wildcard character. For
example:

.. code-block:: yaml

  - hostname: client.test
    role: client
    artifacts:
    - /etc/sssd/*
    - /var/log/sssd/*
    - /var/lib/sss/db/*

.. _config-ldap:

LDAP configuration
==================

This additional configuration can be used on roles with direct LDAP access.

* ``binddn``: Bind DN to authentication with.
* ``bindpw``: Bind password of the user.

.. code-block:: yaml

    - hostname: master.ldap.test
      role: ldap
      config:
        binddn: cn=Directory Manager
        bindpw: Secret123

.. _config-providers-client:

Provider specific client configuration
======================================

``client`` section of the additional configuration can specify SSSD options
required for the client to successfully connect to the provider. It is a list of
key-value pairs that represent options from ``sssd.conf``. These options are
automatically put into the client's ``sssd.conf`` when a domain is imported from
the role using :meth:`sssd_test_framework.utils.sssd.HostSSSD.import_domain`.

.. seealso::

    :ref:`importing-domain`

.. code-block:: yaml
    :caption: Client config example

    - hostname: master.ipa.test
      role: ipa
      config:
        client:
          ipa_domain: ipa.test
          krb5_keytab: /enrollment/ipa.keytab
          ldap_krb5_keytab: /enrollment/ipa.keytab

The example above will add the given options to ``sssd.conf``, these are
required by the client to successfully connect to the IPA server. The keytab
paths are local paths on the client host.

.. _config-auditd:

Auditd and automatic AVC denials detection
==========================================

Linux-based roles has access to Auditd utility that automatically collects
audit.log when a test ends. It can also automatically detect AVC denials and
fail the test if required conditions are met.

It is possible to set that AVC detection mode to one of ``fail`` (test is marked
as failed if AVC denial is detected), ``warn`` (result of a test is used but the
test is marked as ``AVC DENIAL`` if denial is detected) or ``ignore``
(auto-detection is turned off, default).

It is also possible to set a regular expression that is used to filter the AVC
denials in order to fail only if any of the AVC denial records match the
provided filter. This expression is evaluated on top of the full output of
``ausearch`` command.

.. code-block:: yaml
    :caption: Config example

    - hostname: master.ipa.test
      role: ipa
      config:
        auditd:
          avc_mode: fail|warn|ignore
          avc_filter: <regex>

.. _config-coredumpd:

Coredumpd and automatic core files collection
=============================================

Linux-based roles has access to Coredumpd utility that automatically collects
any core files generated during a test. If any core file is produced, it can
optionally fail the test if required conditions are met.

It is possible to set the core file detection mode to one of ``fail`` (test is
marked as failed if core file is generated), ``warn`` (result of a test is used
but the test is marked as ``COREDUMP`` if core file is detected) or ``ignore``
(auto-detection is turned off, default).

It is also possible to set regular expression that is used to filter the core
files names in order to fail only if the core file was produced by certain
process. This expression is evaluated on each name of generated core file.

.. code-block:: yaml
    :caption: Config example

    - hostname: master.ipa.test
      role: ipa
      config:
        coredumpd:
          mode: fail|warn|ignore
          filter: <regex>
