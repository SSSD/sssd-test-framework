"""IPA multihost host."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

from pytest_mh.conn import ProcessLogLevel

from ..misc.ssh import retry_command
from .base import BaseDomainHost, BaseLinuxHost

__all__ = [
    "IPAHost",
]


class IPAHost(BaseDomainHost, BaseLinuxHost):
    """
    IPA host object.

    Provides features specific to IPA server.

    This class adds ``config.adminpw`` multihost configuration option to set
    password of the IPA admin user so we can obtain Kerberos TGT for the user
    automatically.

    .. code-block:: yaml
        :caption: Example multihost configuration
        :emphasize-lines: 6

        - hostname: master.ipa.test
          role: ipa
          config:
            adminpw: Secret123
            client:
              ipa_domain: ipa.test
              krb5_keytab: /enrollment/ipa.keytab
              ldap_krb5_keytab: /enrollment/ipa.keytab

    .. note::

        Full backup and restore is supported. However, the operation relies on
        ``ipa-backup`` and ``ipa-restore`` commands which can take several
        seconds to finish.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.adminpw: str = self.config.get("adminpw", "Secret123")
        """Password of the admin user, defaults to ``Secret123``."""

        self._features: dict[str, bool] | None = None

        # Additional client configuration
        self.client.setdefault("id_provider", "ipa")
        self.client.setdefault("access_provider", "ipa")
        self.client.setdefault("ipa_server", self.hostname)
        self.client.setdefault("dyndns_update", False)

        # Use different default for domain
        if "domain" not in self.config and "ipa_domain" in self.client:
            self.domain = self.client["ipa_domain"]

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
        self.kinit()

        result = self.conn.run(
            """
            set -ex

            [ -f "/usr/libexec/sssd/passkey_child" ] && \
                ipa help user | grep user-add-passkey 1> /dev/null && \
                echo "passkey" || :
            ipa trust-add --help | grep 'Trust type' | grep 'ipa' 1> /dev/null && \
            echo "ipa-ipa-trust" || :
            """,
            log_level=ProcessLogLevel.Error,
        )

        # Set default values
        self._features = {
            "passkey": False,
            "ipa-ipa-trust": False,
        }

        self._features.update({k: True for k in result.stdout_lines})
        self.logger.info("Detected features:", extra={"data": {"Features": self._features}})

        return self._features

    def kinit(self) -> None:
        """
        Obtain ``admin`` user Kerberos TGT.
        """
        self.conn.exec(["kinit", "admin"], input=self.adminpw)

    def start(self) -> None:
        self.svc.start("ipa.service")

    def stop(self) -> None:
        self.svc.stop("ipa.service")

    def backup(self) -> Any:
        """
        Backup all IPA server data.

        This is done by calling ``ipa-backup --data --online`` on the server
        and can take several seconds to finish.

        :return: Backup data.
        :rtype: Any
        """

        # Race condition: https://pagure.io/freeipa/issue/9584
        @retry_command(delay=0, match_stderr="Unable to add LDIF task: This entry already exists")
        def _backup():
            return self.conn.run(
                """
                set -ex

                function backup {
                    if [ -d "$1" ] || [ -f "$1" ]; then
                        cp --force --archive "$1" "$2"
                    fi
                }

                ipa-backup --data --online

                path=`mktemp -d`
                mv `find /var/lib/ipa/backup -maxdepth 1 -type d | tail -n 1` $path/ipa
                backup /etc/krb5.conf "$path/krb5.conf"
                backup /etc/krb5.keytab "$path/krb5.keytab"
                backup /etc/sssd "$path/config"
                backup /var/log/sssd "$path/logs"
                backup /var/lib/sss "$path/lib"

                echo $path
                """,
                log_level=ProcessLogLevel.Error,
            )

        self.logger.info("Creating backup of IPA server")
        result = _backup()
        return PurePosixPath(result.stdout_lines[-1].strip())

    def restore(self, backup_data: Any | None) -> None:
        """
        Restore all IPA server data to its original state.

        This is done by calling ``ipa-restore --data --online`` on the server
        and can take several seconds to finish.

        :return: Backup data.
        :rtype: Any
        """
        if backup_data is None:
            return

        if not isinstance(backup_data, PurePosixPath):
            raise TypeError(f"Expected PurePosixPath, got {type(backup_data)}")

        # Bind sometimes fails: https://pagure.io/freeipa/issue/9669
        @retry_command(delay=0, match_stderr="Unable to bind to LDAP server", check_rc=False)
        def _restore():
            return self.conn.run(
                f"""
                set -ex

                function restore {{
                    rm --force --recursive "$2"
                    if [ -d "$1" ] || [ -f "$1" ]; then
                        cp --force --archive "$1" "$2"
                    fi
                }}

                ipa-restore --unattended --password "{self.adminpw}" --data --online "{backup_path}/ipa"

                rm --force --recursive /etc/sssd /var/lib/sss /var/log/sssd
                restore "{backup_path}/krb5.conf" /etc/krb5.conf
                restore "{backup_path}/krb5.keytab" /etc/krb5.keytab
                restore "{backup_path}/config" /etc/sssd
                restore "{backup_path}/logs" /var/log/sssd
                restore "{backup_path}/lib" /var/lib/sss
                """,
                log_level=ProcessLogLevel.Error,
            )

        backup_path = str(backup_data)
        self.logger.info(f"Restoring IPA server from {backup_path}")
        _restore()
        self.svc.restart("sssd.service")
