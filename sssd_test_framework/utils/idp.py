
"""Authenticate to External Identity Providers."""

from __future__ import annotations

from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.conn import ProcessResult
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

        :return: Tuple containing [return code, stdout, stderr]
        :rtype: Tuple[int, str, str]
        """

        command = self.fs.mktmp(
            rf"""
            #!/opt/sssd_test_venv/bin/python3

            import sys

            from selenium import webdriver
            from datetime import datetime
            from packaging.version import parse
            from selenium.webdriver.firefox.options import Options
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.support import expected_conditions as EC

            verification_uri = "{uri}"

            options = Options()
            if  parse(webdriver.__version__) < parse('4.10.0'):
                options.headless = True
                driver = webdriver.Firefox(executable_path="/opt/sssd_test_venv/bin/geckodriver",
                                        options=options)
            else:
                options.add_argument('-headless')
                service = webdriver.FirefoxService(
                    executable_path="/opt/sssd_test_venv/bin/geckodriver")
                driver = webdriver.Firefox(options=options, service=service)

            driver.get(verification_uri)
            try:
                element = WebDriverWait(driver, 90).until(
                    EC.presence_of_element_located((By.ID, "username")))
                driver.find_element(By.ID, "username").send_keys("{username}")
                driver.find_element(By.ID, "password").send_keys("{password}")
                driver.find_element(By.ID, "kc-login").click()
                element = WebDriverWait(driver, 90).until(
                    EC.presence_of_element_located((By.ID, "kc-login")))
                driver.find_element(By.ID, "kc-login").click()
                assert "Device Login Successful" in driver.page_source
            finally:
                now = datetime.now().strftime("%M-%S")
                driver.get_screenshot_as_file("/var/log/httpd/screenshot-%s.png" % now)
                driver.quit()
            """,
            mode="a=rx",
        )

        result = self.host.conn.exec([command])

        return result.rc, result.stdout, result.stderr

    def keycloak(self, uri: str, username: str, password: str) -> bool:
        """
        Authenticate to Keycloak using External IdP Device Authorization Grant and return boolean

        :return: True if authentication was successful, otherwise return False
        :rtype: bool
        """
        rc, _, _ = self.keycloak_with_output(uri, username, password)
        return rc == 0