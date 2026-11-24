"""Authenticate to External Identity Providers."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import yaml
from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.conn import ProcessLogLevel
from pytest_mh.utils.fs import LinuxFileSystem

if TYPE_CHECKING:
    from ..roles.client import Client
    from ..roles.keycloak import Keycloak

__all__ = [
    "IdpAuthenticationUtils",
    "IdpConfigUtils",
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
        # Pass the password over stdin, not argv, so it stays out of the process
        # listing. ProcessLogLevel.Error suppresses command/input logging (the
        # command is only logged on failure, and stdin is never logged).
        result = self.host.conn.exec(
            [login_script, uri, username],
            input=password,
            log_level=ProcessLogLevel.Error,
            raise_on_error=False,
        )

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

    def entraid_with_output(self, uri: str, username: str, password: str) -> tuple[int, str, str]:
        """
        Authenticate to EntraID using External IdP Device Authorization Grant and return output.

        :param uri: IdP Device Access Grant login URI
        :type uri: str
        :param username: IdP username (UPN)
        :type username: str
        :param password: IdP user password
        :type password: str
        :return: Tuple containing [return code, stdout, stderr]
        :rtype: Tuple[int, str, str]
        """
        # Extract device code from URI for EntraID
        import re
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(uri)
        params = parse_qs(parsed.query)
        device_code = params.get("user_code", [""])[0]

        if not device_code:
            # Try regex fallback
            match = re.search(r"user_code=([^&\s]+)", uri)
            device_code = match.group(1) if match else ""

        login_script = "/opt/test_venv/bin/idp_login_entraid.py"
        # Pass the password over stdin, not argv, so it stays out of the process
        # listing. ProcessLogLevel.Error suppresses command/input logging (the
        # command is only logged on failure, and stdin is never logged).
        result = self.host.conn.exec(
            [login_script, uri, device_code, username],
            input=password,
            log_level=ProcessLogLevel.Error,
            raise_on_error=False,
        )

        return result.rc, result.stdout, result.stderr

    def entraid(self, uri: str, username: str, password: str) -> bool:
        """
        Authenticate to EntraID using External IdP Device Authorization Grant and return boolean.

        :param uri: IdP Device Access Grant login URI
        :type uri: str
        :param username: IdP username (UPN)
        :type username: str
        :param password: IdP user password
        :type password: str
        :return: True if authentication was successful, otherwise return False
        :rtype: bool
        """
        rc, stdout, stderr = self.entraid_with_output(uri, username, password)
        self.logger.info("================ EntraID authentication output ===================")
        self.logger.info(f"STDOUT:\n{stdout}")
        self.logger.info("=================")
        self.logger.info(f"STDERR:\n{stderr}")
        self.logger.info("===================================================================")
        return rc == 0


class IdpConfigUtils(MultihostUtility[MultihostHost]):
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

    def load_idp_cfg(self, client: Client) -> dict:
        """
        Load IdP configuration from the controller-local YAML credentials file.

        The ``idp-credentials`` host config option must point to a YAML file on
        the controller whose contents become the IdP dictionary. An optional
        top-level ``idp:`` wrapper key is unwrapped if present.

        :param client: Client whose host config provides ``idp-credentials``
        :type client: Client role
        :return: IdP configuration dictionary
        :rtype: dict
        """
        credentials_file = client.host.config.get("idp-credentials", None)
        if not credentials_file:
            pytest.skip(reason="Missing idp-credentials in mhc.yaml config file")

        try:
            with open(credentials_file) as f:
                idp = yaml.safe_load(f) or {}
        except OSError as e:
            pytest.skip(reason=f"Unable to read IdP credentials file ({credentials_file}): {e}")
        except yaml.YAMLError as e:
            pytest.skip(reason=f"Unable to parse IdP credentials file ({credentials_file}): {e}")

        # Allow an optional top-level "idp:" wrapper
        if isinstance(idp, dict) and "idp" in idp:
            idp = idp["idp"]

        return idp or {}

    def config_check(self, client: Client, idp_type: str = "keycloak"):
        """
        :param client: Client on which to configure SSSD for IdP
        :type client: Client role
        :param idp_type: type of IdP to configure (keycloak|entraid)
        :type idp_type: string
        """
        idp = self.load_idp_cfg(client)
        if idp == {}:
            pytest.skip(reason="Missing IdP Config in idp-credentials file")

        if idp_type not in idp:
            pytest.skip(reason=f"Missing IdP Config for type ({idp_type})")

        required_options = [
            "domain_name",
            "tenant_id",
            "client_id",
            "client_secret",
            "user1_username",
            "user1_password"
        ]

        for required_option in required_options:
            if required_option not in idp[idp_type]:
                pytest.skip(reason=f"Missing IdP Config option ({required_option}) for type ({idp_type})")

        if "@" not in idp[idp_type]["user1_username"]:
            pytest.skip(reason="IdP test user1_username should include a domain")

    def setup_config(
        self, client: Client, keycloak: Keycloak, idp_type: str = "keycloak", use_fully_qualified_names: str = "True"
    ):
        """
        :param client: Client on which to configure SSSD for IdP
        :type client: Client role
        :param keycloak: Keycloak access
        :type keycloak: Keycloak role
        :param idp_type: type of IdP to configure (keycloak|entraid)
        :type idp_type: string
        :param use_fully_qualified_names: parameter to set option with same name
        :type use_fully_qualified_names: str defaults to "True"
        """
        idp = self.load_idp_cfg(client)
        if idp == {}:
            pytest.skip(reason="Missing IdP Config in idp-credentials file")

        domain_name = idp[idp_type]["domain_name"]
        tenant_id = idp[idp_type]["tenant_id"]
        client_id = idp[idp_type]["client_id"]
        client_secret = idp[idp_type]["client_secret"]

        client.sssd.default_domain = domain_name
        client.sssd.sssd["domains"] = domain_name
        client.sssd.config.remove_section("domain/test")
        client.sssd.config.add_section(f"domain/{domain_name}")

        if idp_type == "keycloak":
            # Set default SSSD IdP configuration for Keycloak
            keycloak.idp_client("myclient").add()
            client.sssd.domain["id_provider"] = "idp"
            client.sssd.domain["idp_type"] = (
                f"keycloak:https://{keycloak.host.hostname}:8443/auth/admin/realms/{tenant_id}/"
            )
            client.sssd.domain["idp_client_id"] = client_id
            client.sssd.domain["idp_client_secret"] = client_secret
            client.sssd.domain["idp_token_endpoint"] = (
                f"https://{keycloak.host.hostname}:8443/auth/realms/{tenant_id}/protocol/openid-connect/token"
            )
            client.sssd.domain["idp_userinfo_endpoint"] = (
                f"https://{keycloak.host.hostname}:8443/auth/realms/{tenant_id}/protocol/openid-connect/userinfo"
            )
            client.sssd.domain["idp_device_auth_endpoint"] = (
                f"https://{keycloak.host.hostname}:8443/auth/realms/{tenant_id}/protocol/openid-connect/auth/device"
            )
            client.sssd.domain["idp_id_scope"] = "profile"
            client.sssd.domain["idp_auth_scope"] = "openid profile email"
        elif idp_type == "entra_id":
            # Set default SSSD IdP configuration for EntraID
            client.sssd.domain["id_provider"] = "idp"
            client.sssd.domain["idp_type"] = "entra_id"
            client.sssd.domain["idp_client_id"] = client_id
            client.sssd.domain["idp_client_secret"] = client_secret
            client.sssd.domain["idp_token_endpoint"] = (
                f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
            )
            client.sssd.domain["idp_userinfo_endpoint"] = "https://graph.microsoft.com/v1.0/me"
            client.sssd.domain["idp_device_auth_endpoint"] = (
                f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/devicecode"
            )
            client.sssd.domain["idp_id_scope"] = "https://graph.microsoft.com/.default"
            client.sssd.domain["idp_auth_scope"] = "openid profile email"

        client.sssd.domain["use_fully_qualified_names"] = use_fully_qualified_names
        client.sssd.nss["default_shell"] = "/bin/bash"
        client.sssd.nss["fallback_homedir"] = "/home/%u"

        client.sssd.start(check_config=False, disable_out=True)
