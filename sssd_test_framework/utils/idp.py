"""Authenticate to External Identity Providers."""

from __future__ import annotations

from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.utils.fs import LinuxFileSystem

__all__ = [
    "IdpAuthenticationUtils",
]


class IdpAuthenticationUtils(MultihostUtility[MultihostHost]):
    """
    Methods for testing authentication to an external Identity Provider
    """

    def __init__(self, host: MultihostHost, fs: LinuxFileSystem) -> None:
        """
        :param host: Multihost host.
        :type host: MultihostHost
        :param fs: Linux File system.
        :type fs: LinuxFileSystem.
        """

        super().__init__(host)
        self.fs: LinuxFileSystem = fs

    def keycloak_with_output(self, uri: str, username: str, password: str) -> tuple[int, str, str]:
        """
        Authenticate to Keycloak using External IdP Device Authorization Grant and return output

        :param uri: IdP Device Access Grant login URI
        :type uri: str
        :param username: IdP username
        :type username: str
        :param password: IdP user password
        :type password: str
        :return: Tuple containing [return code, stdout, stderr]
        :rtype: Tuple[int, str, str]
        """

        login_script = "/opt/test_venv/bin/idp_login_keycloak.py"
        result = self.host.conn.exec([login_script, uri, username, password], raise_on_error=False)

        return result.rc, result.stdout, result.stderr

    def keycloak(self, uri: str, username: str, password: str) -> bool:
        """
        Authenticate to Keycloak using External IdP Device Authorization Grant and return boolean

        :param uri: IdP Device Access Grant login URI
        :type uri: str
        :param username: IdP username
        :type username: str
        :param password: IdP user password
        :type password: str
        :return: True if authentication was successful, otherwise return False
        :rtype: bool
        """
        rc, stdout, stderr = self.keycloak_with_output(uri, username, password)
        self.logger.info("================ Keycloak authentication output ===================")
        self.logger.info(f"STDOUT:\n{stdout}")
        self.logger.info("=================")
        self.logger.info(f"STDERR:\n{stderr}")
        self.logger.info("===================================================================")
        return rc == 0
