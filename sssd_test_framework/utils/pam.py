"""PAM Tools."""

from __future__ import annotations

import re

from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.utils.fs import LinuxFileSystem

__all__ = [
    "PAMAccessUtils",
    "PAMFaillockUtils",
]


class PAMAccessUtils(MultihostUtility):
    """
    Management of PAM Access on the client host.

    .. code-block:: python
        :caption: Example usage

        @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
        def test_example(client: Client, provider: GenericProvider):
            # Add users
            provider.user("user-1").add()
            provider.user("user-2").add()

            with mh_utility(PAMAccessUtils(client.host, client.fs)) as access:
                # Add rule to permit "user-1" and deny "user-2"
                access.config_set([
                    {
                        "access": "+",
                        "user": "user-1",
                        "origin": "ALL",
                    },
                    {
                        "access": "-",
                        "user": "user-2",
                         "origin": "ALL"
                    }
                ])

                client.sssd.authselect.enable_feature(["with-pamaccess"])
                client.sssd.start()

                # Check the results
                assert client.auth.ssh.password("user-1", "Secret123")
                assert not client.auth.ssh.password("user-2", "Secret123")
    """

    def __init__(self, host: MultihostHost, fs: LinuxFileSystem, file: str = "/etc/security/access.conf") -> None:
        """
        :param host: Multihost object
        :type host: MultihostHost
        :param fs: LinuxFileSystem object
        :type fs: LinuxFileSystem
        :param file: File name of access file, defaults to ``/etc/security/access.conf``
        :type file: str
        """
        super().__init__(host)

        self.fs: LinuxFileSystem = fs
        self.file: str = file
        self.path: str = "/files" + self.file
        self.args: str = f'--noautoload --transform "Access.lns incl {self.file}"'
        self.cmd: str = ""

    def setup(self) -> None:
        super().setup()
        self.fs.backup(self.file)

    def teardown(self) -> None:
        self.fs.restore(self.file)
        return super().teardown()

    def config_read(self) -> str:
        """
        Read access file as Augeas tree.
        :return: PAM access configuration
        :rtype: str
        """
        self.logger.info(f"Reading {self.file} and parsing as Augeas tree")
        result = self.host.conn.run(f"augtool {self.args} print {self.path}")

        return result.stdout

    def config_delete(self, value: list[dict[str, str]]) -> None:
        """
        Delete access configuration.
        :param value: Configuration.
        :type value: list[dict[str, str]]
        :return: None
        """
        if value is None:
            raise ValueError("No data!")

        index = 1
        for i in self.host.conn.run(f"augtool {self.args} match {self.path}/*").stdout_lines:
            node = re.sub("\\d", str(index), i.split("=")[0].strip())
            leaf = self.host.conn.run(f"augtool {self.args} match {node}/*").stdout_lines
            access = i.split("=")[1].strip()
            user = leaf[0].split("=")[1].strip()
            origin = leaf[1].split("=")[1].strip()
            match = {"access": access, "user": user, "origin": origin}
            for y in value:
                if match == y:
                    self.logger.info(f"Deleting node in Augeas tree {self.file}")
                    self.host.conn.run(f"augtool {self.args} --autosave rm {node}")
                else:
                    index = +index

    def config_set(self, value: list[dict[str, str]]) -> None:
        """
        Configure access configuration file.
        :param value: Access rule
        :type value: list[list[str]]
        :return: None
        """
        if value is None:
            raise ValueError("No data!")

        count = 1
        for i in value:
            self.cmd = self.cmd + f"set {self.path}/access[{count}] " + i["access"] + "\n"
            self.cmd = self.cmd + f"set {self.path}/access[{count}]/user " + i["user"] + "\n"
            self.cmd = self.cmd + f"set {self.path}/access[{count}]/origin " + i["origin"] + "\n"
            count = +count

        self.host.conn.run(f"augtool --echo {self.args}", input=f"{self.cmd} save\n")


class PAMFaillockUtils(MultihostUtility):
    """
    Management of PAM Faillock on the client host.

    .. code-block:: python
        :caption: Example usage

        @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
        def test_example(client: Client, provider: GenericProvider):
            # Add user
            provider.user("user-1").add()

            with mh_utility(PAMFaillockUtils(client.host, client.fs)) as faillock:
                # Setup faillock
                faillock.config_set({"deny": "3", "unlock_time": "300"})
                client.sssd.common.pam(["with-faillock"])

                # Start SSSD
                client.sssd.start()

                # Check the results
                assert client.auth.ssh.password("user-1", "Secret123")

                # Three failed login attempts
                for i in range(3):
                    assert not client.auth.ssh.password("user-1", "bad_password")

                assert not client.auth.ssh.password("user-1", "Secret123")
    """

    def __init__(self, host: MultihostHost, fs: LinuxFileSystem, file: str = "/etc/security/faillock.conf") -> None:
        """
        :param host: MultihostHost object
        :type host: MultihostHost
        :param fs: LinuxFileSystem object
        :type fs: LinuxFileSystem
        :param file: Faillock configuration file, defaults to ``/etc/security/faillock.conf``
        :type file: str
        """
        super().__init__(host)

        self.fs: LinuxFileSystem = fs
        self.file: str = file
        self.path: str = "/files" + self.file
        self.args: str = f'--noautoload --transform "Simplevars.lns incl {self.file}"'
        self.cmd: str = ""

    def setup(self) -> None:
        super().setup()
        self.fs.backup(self.file)

    def teardown(self) -> None:
        self.fs.restore(self.file)
        super().teardown()

    def config_read(self) -> str:
        """
        Read faillock configuration as augeas tree.
        :return: PAM access configuration
        :rtype: str
        """
        self.logger.info(f"Reading {self.file} and parsing as Augeas tree")
        result = self.host.conn.run(f"augtool {self.args} print {self.path}").stdout

        return result

    def config_delete(self, value: dict[str, str]) -> None:
        """
        Delete faillock configuration.
        :param value: Configuration.
        :type value: dict[str, str]
        :return: None
        """
        if value is None:
            raise ValueError("No data!")

        self.logger.info(f"Deleting node in Augeas tree in {self.file}")
        for k, v in value.items():
            self.host.conn.run(f"augtool {self.args} --autosave rm {self.path}/{k} {v}")

    def config_set(self, value: dict[str, str]) -> None:
        """
        Set faillock configuration.
        :param value: Configuration parameter(s) and value(s).
        :type value: dict[str, str]
        :return: None
        """
        if value is None:
            raise ValueError("No data!")

        for k, v in value.items():
            self.cmd = self.cmd + f"set {self.path}/{k} {v}\n"

        self.host.conn.run(f"augtool --echo {self.args}", input=f"{self.cmd}save\n")
