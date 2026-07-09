"""Selecting authselect profiles."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pytest_mh import MultihostHost, MultihostUtility

if TYPE_CHECKING:
    from pytest_mh.utils.fs import LinuxFileSystem

__all__ = [
    "AuthselectUtils",
]

from pytest_mh.utils.fs import LinuxFileSystem


class AuthselectUtils(MultihostUtility[MultihostHost]):
    """
    Use authselect to configure nsswitch and PAM.

    .. code-block:: python
        :caption: Example usage

        @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
        def test_example(client: Client, provider: GenericProvider):
            client.authselect.select('sssd', ['with-mkhomedir'])

    .. note::

        All changes are automatically reverted when a test is finished.
    """

    def __init__(self, host: MultihostHost, fs: LinuxFileSystem) -> None:
        """
        :param host: Remote host instance.
        :type host: MultihostHost
        """
        super().__init__(host)
        self.__backup: str | None = None
        self.__backup_custom: list[str] = []

        self.fs: LinuxFileSystem = fs
        """Filesystem utils."""

        self.common: AuthselectCommonConfiguration = AuthselectCommonConfiguration(self)
        """Common Authselect configurations."""

    def teardown(self):
        """
        Revert to original state.

        :meta private:
        """
        if self.__backup is not None:
            self.host.conn.exec(["authselect", "backup-restore", self.__backup])
            self.host.conn.exec(["rm", "-fr", f"/var/lib/authselect/backups/{self.__backup}"])
            self.__backup = None

        for profile_name in self.__backup_custom:
            self.host.conn.exec(["rm", "-fr", f"/etc/authselect/custom/{profile_name}"])
        self.__backup_custom = []

        super().teardown()

    def select(self, profile: str, features: list[str] = []) -> None:
        """
        Select an authselect profile.

        :param profile: Authselect profile name.
        :type profile: str
        :param features: Authselect features to enable, defaults to []
        :type features: list[str], optional
        """
        backup = []
        if self.__backup is None:
            self.__backup = "multihost.backup"
            backup = [f"--backup={self.__backup}"]

        self.host.conn.exec(["authselect", "select", profile, *features, "--force", *backup])

    def current(self) -> str:
        """
        List current Authselect configuration.
        :return: Authselect configuration
        :rtype: str
        """
        result = self.host.conn.exec(["authselect", "current"]).stdout

        return result

    def disable_feature(self, features: list[str]) -> None:
        """
        Disable Authselect feature.
        :param features: Authselect features to disable
        :type: list[str], required
        """
        backup = []
        if self.__backup is None:
            self.__backup = "multihost.backup"
            backup = [f"--backup={self.__backup}"]
        self.host.conn.exec(["authselect", "disable-feature", *features, *backup])

    def enable_feature(self, features: list[str]) -> None:
        """
        Enable Authselect feature.
        :param features:  Authselect features to enable
        :type: list[str], required
        """
        backup = []
        if self.__backup is None:
            self.__backup = "multihost.backup"
            backup = [f"--backup={self.__backup}"]

        self.host.conn.exec(["authselect", "enable-feature", *features, *backup])

    def create_profile(self, profile_name: str, base_profile: str = "sssd") -> None:
        """
        Create a custom Authselect profile.

        :param profile_name: Name of the new profile.
        :type profile_name: str
        :param base_profile: Base profile to use for the new profile, defaults to 'sssd'
        :type base_profile: str = "sssd"
        """
        self.host.conn.exec(["authselect", "create-profile", profile_name, "--base-on", base_profile])
        self.__backup_custom.append(profile_name)


class AuthselectCommonConfiguration(object):
    """
    Setup common Authselect configurations.

    This class provides shortcuts to enable common PAM configurations.
    """

    def __init__(self, authselect: AuthselectUtils) -> None:
        self.authselect: AuthselectUtils = authselect
        """Authselect utils."""

        self.profile_path: str = "/etc/authselect/custom/"
        """Custom Authselect profile path."""

        self.account: str = """
            account     required    pam_unix.so
            account     sufficient  pam_localuser.so
            account     sufficient  pam_sss.so
            account     required    pam_permit.so
        """
        
        self.password: str = """
            password    requisite   pam_pwquality.so try_first_pass local_users_only
            password    sufficient  pam_unix.so try_first_pass use_authtok nullok sha512 shadow
            password    sufficient  pam_sss.so use_authtok
            password    required    pam_deny.so
        """
        
        self.session: str = """
            session     optional      pam_keyinit.so revoke
            session     required      pam_limits.so
            -session    optional      pam_systemd.so
            session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
            session     required      pam_unix.so
            session     optional      pam_sss.so
        """

    def offline_login(self, profile_name: str = "offline-login", pam_files: list[str] | None = None) -> None:
        """
        Configure custom Authselect profile for offline logins.

        :param profile_name: Authselect profile name, optional
        :type profile_name: str = "offline-login"
        :param pam_files: List of PAM files to configure, optional
        :type pam_files: list[str] | None = None
        """
        stack = f"""
            auth        required    pam_env.so
            auth        sufficient  pam_unix.so try_first_pass likeauth nullok
            auth        required    pam_sss.so forward_pass use_first_pass
            
            {self.account}
            
            {self.password}
    
            session     optional    pam_keyinit.so revoke
            session     required    pam_limits.so
            -session    optional    pam_systemd.so
            session     required    pam_unix.so
            session     optional    pam_sss.so forward_pass
        """
        if not pam_files:
            pam_files = ["system-auth", "password-auth"]
        self.authselect.create_profile(profile_name)
        for files in pam_files:
            self.authselect.fs.write(f"{self.profile_path}/{profile_name}/{files}", stack)
        self.authselect.select(profile_name, ["with-mkhomedir"])

    def sss_domains(self, profile_name: str = "sss-domains", pam_files: list[str] | None = None) -> None:
        """
        Configure custom Authselect profile for SSSD domains.

        :param profile_name: Authselect profile name, optional
        :type profile_name: str = "sss-domains"
        :param pam_files: List of PAM files to configure, optional
        :type pam_files: list[str] | None = None
        """
        stack = f"""
            auth        required      pam_env.so
            auth        sufficient    pam_unix.so nullok try_first_pass
            auth        requisite     pam_succeed_if.so uid >= 1000 quiet_success
            auth        sufficient    pam_sss.so forward_pass
            auth        required      pam_deny.so

            {self.account}

            password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=
            password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok
            password    sufficient    pam_sss.so use_authtok
            password    required      pam_deny.so

            {self.session}
        """
        if not pam_files:
            pam_files = ["system-auth"]
        self.authselect.create_profile(profile_name)
        for files in pam_files:
            self.authselect.fs.write(f"{self.profile_path}/{profile_name}/{files}", stack)
        self.authselect.select(profile_name)
