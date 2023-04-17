"""Manage and configure SSSD."""

from __future__ import annotations

from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.utils.fs import LinuxFileSystem

__all__ = [
    "SSSCTLUtils",
]


class SSSCTLUtils(MultihostUtility[MultihostHost]):
    """
    Call commands from sssctl.
    """

    def __init__(self, host: MultihostHost, fs: LinuxFileSystem) -> None:
        super().__init__(host)

        self.fs: LinuxFileSystem = fs
        """Filesystem utils."""

    def passkey_register(
        self,
        username: str,
        domain: str,
        *,
        pin: str | int | None,
        device: str,
        ioctl: str,
        script: str,
    ) -> str:
        """
        Call ``sssctl passkey-register``

        :param username: User name
        :type username: str
        :param domain: Domain name
        :type domain: str
        :param pin: Passkey PIN.
        :type pin: str | int | None
        :param device: Path to local umockdev device file.
        :type device: str
        :param ioctl: Path to local umockdev ioctl file.
        :type ioctl: str
        :param script: Path to local umockdev script file
        :type script: str
        :return: Generated passkey mapping string.
        :rtype: str
        """
        device_path = self.fs.upload_to_tmp(device, mode="a=r")
        ioctl_path = self.fs.upload_to_tmp(ioctl, mode="a=r")
        script_path = self.fs.upload_to_tmp(script, mode="a=r")

        command = self.fs.mktmp(
            rf"""
            #!/bin/bash

            LD_PRELOAD=/opt/random.so umockdev-run      \
                --device '{device_path}'                \
                --ioctl '/dev/hidraw1={ioctl_path}'     \
                --script '/dev/hidraw1={script_path}'   \
                -- sssctl passkey-register --username '{username}' --domain '{domain}' -d=0xfff0 --debug-libfido2
            """,
            mode="a=rx",
        )

        if pin is not None:
            result = self.host.ssh.expect(
                f"""
                spawn {command}
                expect {{
                    "Enter PIN:*" {{send -- "{pin}\r"}}
                    timeout {{puts "expect result: Unexpected output"; exit 201}}
                    eof {{puts "expect result: Unexpected end of file"; exit 202}}
                }}

                expect eof
                """,
                raise_on_error=True,
            )
        else:
            result = self.host.ssh.expect(
                f"""
                spawn {command}
                expect eof
                """,
                raise_on_error=True,
            )

        return result.stdout_lines[-1].strip()
