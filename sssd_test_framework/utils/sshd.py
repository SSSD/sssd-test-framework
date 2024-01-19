"""SSH Daemon Tools."""

from __future__ import annotations

from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.ssh import SSHProcessResult
from pytest_mh.utils.fs import LinuxFileSystem
from pytest_mh.utils.services import SystemdServices

__all__ = [
    "SSHDUtils",
]


class SSHDUtils(MultihostUtility[MultihostHost]):
    """
    Managing global and server SSH configuration files.

    .. warning:: Incorrectly configuring sshd may disable the ability to connect to the host.
    .. code-block:: python
        :caption: Example usage

        @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
        def test_example(client: Client, provider: GenericProvider):
            # Add user
            provider.user("user1").add()

            # Select authselect profile and feature
            client.authselect.select("sssd", ["with-gssapi", "with-mkhomedir"])

            # Start sssd
            client.sssd.start()

            # Configure ssh client and daemon
            client.sshd.config_set([{"GSSAPIAuthentication": "yes"}])

            # Reload sshd configuration
            client.sshd.reload()
    """

    def __init__(
        self, host: MultihostHost, fs: LinuxFileSystem, svc: SystemdServices, file: str = "/etc/ssh/sshd_config"
    ) -> None:
        """
        :param host: Remote host instance.
        :type host: MultihostHost
        :param fs: Linux file system instance.
        :type fs: LinuxFileSystem
        :param svc: Systemd utils.
        :type svc: SystemdServices
        :param file: Configuration file.
        :type file: str
        """
        super().__init__(host)
        self.__backup: str | None
        self.fs: LinuxFileSystem = fs
        self.svc: SystemdServices = svc

        self.file: str = file
        self.path: str = "/files" + self.file
        self.args: str = f'--transform "sshd.lns incl {self.file}"'
        self.cmd: str = ""

    def setup_when_used(self) -> None:
        super().setup_when_used()
        self.fs.backup(self.file)

    def teardown_when_used(self) -> None:
        super().teardown_when_used()
        self.svc.reload("sshd")

    def config_read(self) -> str:
        """
        Read SSH daemon configuration as Augeas tree.

        :return: sshd configuration
        :rtype: str
        """
        self.logger.info(f"Reading {self.file} and parsing as Augeas tree")
        result = self.host.ssh.run(f"augtool {self.args} print {self.path}")

        return result.stdout

    def config_delete(self, value: list[dict[str, str]]) -> None:
        """
        Delete SSH daemon configuration.

        :param value: Configuration.
        :type value: list[dict[str, str]]
        :return: None
        """
        if value is None:
            raise ValueError("No data!")

        self.logger.info(f"Deleting node in Augeas tree in {self.file}")
        for i in value:
            for k, v in i.items():
                self.host.ssh.run(f"augtool {self.args} --autosave rm {self.path}/{k} {v}")

    def config_set(self, value: list[dict[str, str]]) -> None:
        """
        Set SSH daemon configuration.

        :param value: sshd parameter
        :type value: list[list[str]]
        :return: None
        """
        if value is None:
            raise ValueError("No data!")

        for i in value:
            for k, v in i.items():
                self.cmd = self.cmd + f"set {self.path}/{k} {v}\n"

        self.host.ssh.run(f"augtool --echo {self.args}", input=f"{self.cmd}save\n")

    def reload(
        self,
        service="sshd",
        *,
        raise_on_error: bool = True,
    ) -> SSHProcessResult:
        """
        Reload the SSH daemon.

        :param service: Service to start, defaults to 'sshd'
        :type service: str, optional
        :param raise_on_error: Raise exception on error, defaults to True
        :type raise_on_error: bool, optional
        :return: SSH process result.
        :rtype: SSHProcessResult
        """
        return self.svc.reload(service, raise_on_error=raise_on_error)
