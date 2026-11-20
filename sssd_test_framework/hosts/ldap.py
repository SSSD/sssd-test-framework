"""LDAP multihost host."""

from __future__ import annotations

import textwrap
from pathlib import PurePosixPath
from typing import Any

from pytest_mh.conn import ProcessLogLevel

from .base import BaseLDAPDomainHost, BaseLinuxHost

__all__ = [
    "LDAPHost",
]


class LDAPHost(BaseLDAPDomainHost, BaseLinuxHost):
    """
    LDAP host object.

    Provides features specific to native directory server like 389ds.

    .. note::

        Full backup and restore is supported via ``dsctl db2bak`` / ``bak2db``.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self._features: dict[str, bool] | None = None
        self._ldap_service_name = self.config.get("ldap_service_name", "dirsrv@localhost.service")
        self._ldap_cert_dir = self.config.get("ldap_cert_dir", "/var/data/certs")

        # Additional client configuration
        self.client.setdefault("id_provider", "ldap")
        self.client.setdefault("ldap_uri", f"ldap://{self.hostname}")

        # Use different default for domain
        if "domain" not in self.config and "dns_discovery_domain" in self.client:
            self.domain = self.client["dns_discovery_domain"]

        # Use different default for realm
        if "realm" not in self.config:
            self.realm = self.domain.upper()

    @property
    def features(self) -> dict[str, bool]:
        """
        Features supported by the host.
        """
        if self._features is not None:
            return self._features

        self.logger.info(f"Detecting features on {self.hostname}")

        result = self.conn.run(
            """
            set -ex

            grep -r "passkey" /etc/dirsrv/ &> /dev/null && echo "passkey" || :
            """,
            log_level=ProcessLogLevel.Error,
        )

        # Set default values
        self._features = {
            "passkey": False,
        }

        self._features.update({k: True for k in result.stdout_lines})
        self.logger.info("Detected features:", extra={"data": {"Features": self._features}})

        return self._features

    def create_additional_instance(
        self,
        name: str,
        *,
        hostname: str,
        port: int,
        secure_port: int,
        suffix: str | None = None,
    ) -> None:
        """
        Create, configure and start an additional 389ds instance on this host.

        The primary instance is provisioned when the host image is built, this
        only ever adds further instances alongside it.

        The instance shares the host's bind credentials and TLS certificate, so
        it can be used as a second, distinct LDAP server in failover topologies.
        SSSD keys its failover server list on the hostname, therefore ``hostname``
        must differ from the primary instance's name for the two to be treated
        as separate servers, even though they share an address.

        The operation is idempotent, an existing instance of the same name is
        left untouched.

        This is meant to be called from a topology controller, so that the
        instance is shared by every test in the topology instead of being paid
        for per test. See
        :class:`~sssd_test_framework.topology_controllers.MultiLDAPTopologyController`
        for the implementation used by ``KnownTopology.MultiLDAP``, and
        subclass it to change the instance name or ports rather than calling
        this directly.

        :param name: Instance name, the resulting unit is ``dirsrv@<name>.service``.
        :type name: str
        :param hostname: Fully qualified name the instance is reachable under.
        :type hostname: str
        :param port: LDAP port.
        :type port: int
        :param secure_port: LDAPS port.
        :type secure_port: int
        :param suffix: Naming context, defaults to the primary instance's suffix.
        :type suffix: str | None, optional
        """
        if suffix is None:
            suffix = self.naming_context

        self.logger.info(f"Creating 389ds instance '{name}' on {self.hostname} as {hostname}:{port}")

        self.conn.run(
            textwrap.dedent(f"""
            set -ex

            # Nothing to do if the instance already exists.
            if dsctl -l | grep -qx 'slapd-{name}'; then
                exit 0
            fi

            # The extra ports are not part of ldap_port_t, so a confined
            # ns-slapd cannot bind them until they are labelled, and they must
            # be opened in the firewall. Both are skipped where the tooling is
            # absent or inactive, such as containers run with SELinux disabled.
            if command -v semanage > /dev/null && selinuxenabled 2> /dev/null; then
                for extra_port in {port} {secure_port}; do
                    semanage port -a -t ldap_port_t -p tcp "$extra_port" 2> /dev/null \
                        || semanage port -m -t ldap_port_t -p tcp "$extra_port"
                done
            fi

            # Permanent, because the instance has to outlive the individual
            # tests and pytest_mh's Firewalld utility reloads firewalld in its
            # per test setup and teardown, which drops runtime only rules.
            if command -v firewall-cmd > /dev/null && firewall-cmd --state > /dev/null 2>&1; then
                firewall-cmd --permanent --add-port={port}/tcp --add-port={secure_port}/tcp
                firewall-cmd --reload
            fi

            cat > '/root/{name}.inf' <<EOF
            [general]
            config_version = 2
            full_machine_name = {hostname}

            [slapd]
            instance_name = {name}
            port = {port}
            secure_port = {secure_port}
            root_dn = {self.binddn}
            root_password = {self.bindpw}

            [backend-userroot]
            suffix = {suffix}
            create_suffix_entry = True
            EOF

            dscreate from-file '/root/{name}.inf'

            # Share the primary instance's certificate. It carries the alias as a
            # subjectAltName, so TLS to the second name passes hostname validation.
            dsconf '{name}' security ca-certificate add --file '{self._ldap_cert_dir}/ca.crt' --name 'sssd-ca'
            dsconf '{name}' security ca-certificate set-trust-flags 'sssd-ca' --flags 'CT,,'

            ARGS=
            # Workaround for https://github.com/389ds/389-ds-base/issues/7470
            if dsctl '{name}' tls import-server-key-cert --help 2>&1 | grep -q -- '--nickname'; then
                ARGS='--nickname Server-Cert'
            fi
            dsctl '{name}' tls import-server-key-cert $ARGS \
                '{self._ldap_cert_dir}/{self.hostname}.crt' '{self._ldap_cert_dir}/{self.hostname}.key'

            systemctl restart 'dirsrv@{name}.service'

            # The unit returning does not mean the instance is already
            # answering, wait for it so that callers and the modify below do
            # not race against startup. The final search is unguarded on
            # purpose, so that an instance that never comes up fails here
            # rather than somewhere less obvious.
            for _ in $(seq 30); do
                ldapsearch -x -H 'ldap://localhost:{port}' -b '' -s base > /dev/null 2>&1 && break
                sleep 1
            done
            ldapsearch -x -H 'ldap://localhost:{port}' -b '' -s base > /dev/null
            """),
            log_level=ProcessLogLevel.Error,
        )

        # Match the primary instance, which grants anonymous read access.
        result = self.conn.run(
            f"""ldapmodify -D '{self.binddn}' -w '{self.bindpw}' -H 'ldap://localhost:{port}' -x""",
            input=(
                f"dn: {suffix}\n"
                "changetype: modify\n"
                "add: aci\n"
                'aci: (targetattr=*)(version 3.0; acl "Enable anyone read"; '
                'allow (read, search, compare)(userdn="ldap:///anyone");)\n'
            ),
            log_level=ProcessLogLevel.Error,
            raise_on_error=False,
        )

        # The aci is already there if the instance is being reused, anything
        # else is a real failure and must not pass silently.
        if result.rc != 0 and "Type or value exists" not in result.stderr:
            result.throw()

    def remove_additional_instance(self, name: str) -> None:
        """
        Stop and remove an instance created by :func:`create_additional_instance`.

        Also drops the firewall rule and SELinux port label that
        :func:`create_additional_instance` added, so the host is left as it was
        found. The operation is idempotent, removing a non existent instance is
        a no-op.

        Called from a topology controller's teardown, see
        :class:`~sssd_test_framework.topology_controllers.MultiLDAPTopologyController`.

        :param name: Instance name.
        :type name: str
        """
        self.logger.info(f"Removing 389ds instance '{name}' from {self.hostname}")

        self.conn.run(
            textwrap.dedent(f"""
            set -ex

            dse='/etc/dirsrv/slapd-{name}/dse.ldif'
            extra_ports=
            if [ -f "$dse" ]; then
                # Recover the ports from the instance itself so the host is
                # left as it was found, rather than trusting the caller to
                # pass the same values again.
                extra_ports=$(sed -n 's/^nsslapd-\\(secure\\)\\?[Pp]ort: *//p' "$dse" | sort -u)
            fi

            if dsctl -l | grep -qx 'slapd-{name}'; then
                dsctl '{name}' remove --do-it
            fi

            rm --force '/root/{name}.inf'

            for extra_port in $extra_ports; do
                if command -v firewall-cmd > /dev/null && firewall-cmd --state > /dev/null 2>&1; then
                    firewall-cmd --permanent --remove-port="$extra_port"/tcp || :
                fi

                # Only removes a locally added label, entries that come from
                # the base policy are left alone.
                if command -v semanage > /dev/null && selinuxenabled 2> /dev/null; then
                    semanage port -d -t ldap_port_t -p tcp "$extra_port" 2> /dev/null || :
                fi
            done

            if [ -n "$extra_ports" ] \
                && command -v firewall-cmd > /dev/null && firewall-cmd --state > /dev/null 2>&1; then
                firewall-cmd --reload
            fi
            """),
            log_level=ProcessLogLevel.Error,
        )

    def remove_backup(self, backup_data: Any | None) -> None:
        """
        Remove backup data from the host.

        :param backup_data: Backup data.
        :type backup_data: Any | None
        """
        if backup_data is None:
            return

        if not isinstance(backup_data, PurePosixPath):
            raise TypeError(f"Expected PurePosixPath, got {type(backup_data)}")

        self.conn.run(
            f'rm --force --recursive "{backup_data}" "{backup_data}.db2bak"',
            log_level=ProcessLogLevel.Error,
        )

    def start(self) -> None:
        self.svc.start(self._ldap_service_name)

    def stop(self) -> None:
        self.svc.stop(self._ldap_service_name)

    def backup(self) -> Any:
        """
        Backup all directory server data.

        Stop 389-ds, wait for ``ns-slapd`` to exit, then take a binary database
        backup with ``dsctl db2bak`` (same approach as sssd-ci-containers LDAP
        image and IPA PR #298). Plain filesystem copies of ``/var/lib/dirsrv``
        leave the instance unable to answer LDAP after restart on RHEL.

        :return: Backup data.
        :rtype: Any
        """
        self.logger.info("Creating backup of LDAP server")
        self.disconnect()

        result = self.conn.run(
            """
            set -x
            set -e

            path=`mktemp -d`

            systemctl stop dirsrv@localhost.service || systemctl stop dirsrv.target
            set +e
            count=0
            while pgrep -a ns-slapd > /dev/null; do
                if [ "$count" -ge "60" ]; then
                    echo "Directory server failed to stop in 60 seconds"
                    exit 1
                fi
                count=$((count + 1))
                sleep 1
            done
            set -e

            ds_inst=`dsctl -l | sed 's/^slapd-//' | head -n1`
            dsctl "$ds_inst" db2bak "$path.db2bak"

            systemctl start dirsrv@localhost.service || systemctl start dirsrv.target

            for _ in $(seq 60); do
                ldapsearch -x -H 'ldap://127.0.0.1' -b '' -s base > /dev/null 2>&1 && break
                sleep 1
            done
            ldapsearch -x -H 'ldap://127.0.0.1' -b '' -s base > /dev/null

            echo $path
            """,
            log_level=ProcessLogLevel.Error,
        )

        return PurePosixPath(result.stdout_lines[-1].strip())

    def restore(self, backup_data: Any | None) -> None:
        """
        Restore directory server data.

        Stop 389-ds, wait for ``ns-slapd`` to exit, restore the binary backup
        created by :meth:`backup` with ``dsctl bak2db``, then start and wait
        until LDAP answers. This restores the full database state (including
        test users and extra naming contexts).

        :return: Backup data.
        :rtype: Any
        """
        if backup_data is None:
            return

        if not isinstance(backup_data, PurePosixPath):
            raise TypeError(f"Expected PurePosixPath, got {type(backup_data)}")

        backup_path = str(backup_data)
        self.logger.info(f"Restoring LDAP server from {backup_path}")

        self.disconnect()
        self.conn.run(
            f"""
            set -x
            set -e

            systemctl stop dirsrv@localhost.service || systemctl stop dirsrv.target
            set +e
            count=0
            while pgrep -a ns-slapd > /dev/null; do
                if [ "$count" -ge "60" ]; then
                    echo "Directory server failed to stop in 60 seconds"
                    exit 1
                fi
                count=$((count + 1))
                sleep 1
            done
            set -e

            ds_inst=`dsctl -l | sed 's/^slapd-//' | head -n1`
            dsctl "$ds_inst" bak2db "{backup_path}.db2bak"

            systemctl start dirsrv@localhost.service || systemctl start dirsrv.target

            for _ in $(seq 60); do
                ldapsearch -x -H 'ldap://127.0.0.1' -b '' -s base > /dev/null 2>&1 && break
                sleep 1
            done
            ldapsearch -x -H 'ldap://127.0.0.1' -b '' -s base > /dev/null
            """,
            log_level=ProcessLogLevel.Error,
        )
