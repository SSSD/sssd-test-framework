"""Testing authentications and authorization mechanisms."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pytest_mh import MultihostHost, MultihostUtility
from pytest_mh.conn import Connection, ProcessResult
from pytest_mh.utils.fs import LinuxFileSystem

from ..misc.errors import ExpectScriptError

__all__ = [
    "AuthenticationUtils",
    "KerberosAuthenticationUtils",
    "SSHAuthenticationUtils",
    "SUAuthenticationUtils",
    "SudoAuthenticationUtils",
]

DEFAULT_AUTHENTICATION_TIMEOUT: int = 60
"""Default timeout for authentication failure."""


class PasskeyAuthenticationUseCases(Enum):
    """
    Authentication methods for passkey authentication.
    """

    PASSKEY_PIN = 0
    PASSKEY_PIN_AND_PROMPTS = 1
    PASSKEY_PROMPTS_NO_PIN = 2
    PASSKEY_NO_PIN_NO_PROMPTS = 3
    PASSKEY_FALLBACK_TO_PASSWORD = 4


class AuthenticationUtils(MultihostUtility[MultihostHost]):
    """
    Methods for testing various authentication and authorization mechanisms.

    It executes commands on remote host in order to test authentication and
    authorization via su, ssh, sudo and kerberos.

    .. note::

        Since the authentication via su and ssh command can be mostly done via
        the same mechanisms (like password or two-factor authentication), it
        implements the same API. Therefore you can test su and ssh in the same
        test case through parametrization.

        .. code-block:: python
            :caption: Example

            @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
            @pytest.mark.parametrize('method', ['su', 'ssh'])
            def test_example(client: Client, provider: GenericProvider, method: str):
                ldap.user('tuser').add(password='Secret123')

                client.sssd.start()
                assert client.auth.parametrize(method).password('tuser', 'Secret123')
    """

    def __init__(self, host: MultihostHost, fs: LinuxFileSystem) -> None:
        """
        :param host: Remote host.
        :type host: MultihostHost
        :param fs: File system utils.
        :type fs: LinuxFileSystem
        """
        super().__init__(host)

        self.su: SUAuthenticationUtils = SUAuthenticationUtils(host, fs)
        """
        Test authentication and authorization via su.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.LDAP)
            def test_example(client: Client, ldap: LDAP):
                ldap.user('tuser').add(password='Secret123')

                client.sssd.start()
                assert client.auth.su.password('tuser', 'Secret123')
        """

        self.sudo: SudoAuthenticationUtils = SudoAuthenticationUtils(host)
        """
        Test authentication and authorization via sudo.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.LDAP)
            def test_example(client: Client, ldap: LDAP):
                u = ldap.user('tuser').add(password='Secret123')
                ldap.sudorule('allow_ls').add(user=u, host='ALL', command='/bin/ls')

                client.sssd.common.sudo()
                client.sssd.start()

                assert client.auth.sudo.list('tuser', 'Secret123', expected=['(root) /bin/ls'])
                assert client.auth.sudo.run('tuser', 'Secret123', command='/bin/ls /root')
        """

        self.ssh: SSHAuthenticationUtils = SSHAuthenticationUtils(host)
        """
        Test authentication and authorization via ssh.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.LDAP)
            def test_example(client: Client, ldap: LDAP):
                ldap.user('tuser').add(password='Secret123')

                client.sssd.start()
                assert client.auth.ssh.password('tuser', 'Secret123')
        """

        self.passwd: PasswdUtils = PasswdUtils(host)
        """
        Change authentication tokens with passwd tool

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.LDAP)
            def test_example(client: Client, ldap: LDAP):
                ldap.user('tuser').add(password='Secret123')
                # Change the ACI record so that users can change their password
                ldap.aci.add(
                    '(targetattr="userpassword")(version 3.0; acl "pwp test"; allow (all) userdn="ldap:///self";)'
                )

                client.sssd.start()
                assert client.auth.passwd.password('tuser', 'Secret123', 'New_password123')
        """

    def parametrize(self, method: str) -> SUAuthenticationUtils | SSHAuthenticationUtils:
        """
        Return authentication tool based on the method. The method can be
        either ``su`` or ``ssh``.

        :param method: ``su`` or ``ssh``
        :type method: str
        :raises ValueError: If invalid method is specified.
        :return: Authentication tool.
        :rtype: HostSU | HostSSH
        """

        allowed = ["su", "ssh"]
        if method not in allowed:
            raise ValueError(f"Unknown method {method}, choose from {allowed}.")

        return getattr(self, method)

    def kerberos(self, ssh: Connection) -> KerberosAuthenticationUtils:
        """
        Test authentication and authorization via Kerberos.

        .. code-block:: python
            :caption: Example usage

            @pytest.mark.topology(KnownTopology.LDAP)
            def test_example(client: Client, ldap: LDAP, kdc: KDC):
                ldap.user('tuser').add()
                kdc.principal('tuser').add()

                client.sssd.common.krb5_auth(kdc)
                client.sssd.start()

                with client.ssh('tuser', 'Secret123') as ssh:
                    with client.auth.kerberos(ssh) as krb:
                        assert krb.has_tgt(kdc.realm)

        :param ssh: SSH connection for the target user.
        :type ssh: Connection
        :return: Kerberos authentication object.
        :rtype: KerberosAuthenticationUtils
        """
        return KerberosAuthenticationUtils(self.host, ssh)


class SUAuthenticationUtils(MultihostUtility[MultihostHost]):
    """
    Methods for testing authentication and authorization via su.
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

    def password_with_output(self, username: str, password: str) -> tuple[int, int, str, str]:
        """
        Call ``su - $username`` and authenticate the user with password and captures standard output and error.

        :param username: Username.
        :type username: str
        :param password: User password.
        :type password: str
        :return: Tuple containing [return code, command code, stdout, stderr].
        :rtype: Tuple[int, int, str, str]
        """

        result = self.host.conn.expect_nobody(
            rf"""
            # Disable debug output
            # exp_internal 0

            proc exitmsg {{ msg code }} {{
                # Close spawned program, if we are in the prompt
                catch close

                # Wait for the exit code
                lassign [wait] pid spawnid os_error_flag rc

                puts ""
                puts "expect result: $msg"
                puts "expect exit code: $code"
                puts "expect spawn exit code: $rc"
                exit $code
            }}

            # It takes some time to get authentication failure
            set timeout {DEFAULT_AUTHENTICATION_TIMEOUT}
            set prompt "\n.*\[#\$>\] $"

            spawn su - "{username}"

            expect {{
                "Password:" {{send "{password}\n"}}
                timeout {{exitmsg "Unexpected output" 201}}
                eof {{exitmsg "Unexpected end of file" 202}}
            }}

            expect {{
                -re $prompt {{exitmsg "Password authentication successful" 0}}
                "Authentication failure" {{exitmsg "Authentication failure" 1}}
                "su: Permission denied" {{exitmsg "Permission denied" 2}}
                "Current Password:" {{exitmsg "Password change requested" 3 }}
                timeout {{exitmsg "Unexpected output" 201}}
                eof {{exitmsg "Unexpected end of file" 202}}
            }}

            exitmsg "Unexpected code path" 203
        """,
            verbose=False,
        )

        if result.rc > 200:
            raise ExpectScriptError(result.rc)

        expect_data = result.stdout_lines[-3:]

        # Get command exit code.
        cmdrc = int(expect_data[2].split(":")[1].strip())

        # Alter stdout, first line is spawned command, the last three are our expect output.
        stdout = "\n".join(result.stdout_lines[1:-3])

        return result.rc, cmdrc, stdout, result.stderr

    def password(self, username: str, password: str) -> bool:
        """
        SSH to the remote host and authenticate the user with password.

        :param username: Username.
        :type username: str
        :param password: User password.
        :type password: str
        :return: True if authentication was successful, False otherwise.
        :rtype: bool
        """
        rc, _, _, _ = self.password_with_output(username, password)
        return rc == 0

    def password_expired_with_output(
        self, username: str, password: str, new_password: str
    ) -> tuple[int, int, str, str]:
        """
        Call ``su - $username`` and authenticate the user with password, expect that the password
        is expired and change it to the new password and captures standard output and error.

        :param username: Username.
        :type username: str
        :param password: Old, expired user password.
        :type password: str
        :param new_password: New user password.
        :type new_password: str
        :return: Tuple containing [return code, command code, stdout, stderr].
        :rtype: Tuple[int, int, str, str]
        """
        result = self.host.conn.expect_nobody(
            rf"""
            # Disable debug output
            # exp_internal 0

            proc exitmsg {{ msg code }} {{
                # Close spawned program, if we are in the prompt
                catch close

                # Wait for the exit code
                lassign [wait] pid spawnid os_error_flag rc

                puts ""
                puts "expect result: $msg"
                puts "expect exit code: $code"
                puts "expect spawn exit code: $rc"
                exit $code
            }}

            # It takes some time to get authentication failure
            set timeout {DEFAULT_AUTHENTICATION_TIMEOUT}
            set prompt "\n.*\[#\$>\] $"
            log_user 1
            log_file /tmp/expect.log

            spawn su - "{username}"

            expect {{
                "Password:" {{send "{password}\n"}}
                timeout {{exitmsg "Unexpected output" 201}}
                eof {{exitmsg "Unexpected end of file" 202}}
            }}

            expect {{
                "Password expired. Change your password now." {{ }}
                -re $prompt {{exitmsg "Authentication succeeded without password change" 2}}
                "Authentication failure" {{exitmsg "Authentication failure" 1}}
                timeout {{exitmsg "Unexpected output" 201}}
                eof {{exitmsg "Unexpected end of file" 202}}
            }}

            expect {{
                "Current Password:" {{send "{password}\n"}}
                timeout {{exitmsg "Unexpected output" 201}}
                eof {{exitmsg "Unexpected end of file" 202}}
            }}

            expect {{
                "New password:" {{send "{new_password}\n"}}
                timeout {{exitmsg "Unexpected output" 201}}
                eof {{exitmsg "Unexpected end of file" 202}}
            }}

            expect {{
                "Retype new password:" {{send "{new_password}\n"}}
                timeout {{exitmsg "Unexpected output" 201}}
                eof {{exitmsg "Unexpected end of file" 202}}
            }}

            expect {{
                -re $prompt {{exitmsg "Password change was successful" 0}}
                "Please make sure the password meets the complexity constraints." {{exitmsg "Complexity failure" 1}}
                "Password too short" {{exitmsg "Complexity failure" 1}}
                "Password is too short" {{exitmsg "Complexity failure" 1}}
                "Failed to update password" {{exitmsg "Password change failed" 1}}
                timeout {{exitmsg "Unexpected output" 201}}
                eof {{exitmsg "Unexpected end of file" 202}}
            }}

            exitmsg "Unexpected code path" 203
        """,
            verbose=False,
        )

        if result.rc > 200:
            raise ExpectScriptError(result.rc)

        expect_data = result.stdout_lines[-3:]

        # Get command exit code.
        cmdrc = int(expect_data[2].split(":")[1].strip())

        # Alter stdout, first line is spawned command, the last three are our expect output.
        stdout = "\n".join(result.stdout_lines[1:-3])

        return result.rc, cmdrc, stdout, result.stderr

    def password_expired(self, username: str, password: str, new_password: str) -> bool:
        """
        Call ``su - $username`` and authenticate the user with password, expect
        that the password is expired and change it to the new password.

        :param username: Username.
        :type username: str
        :param password: Old, expired user password.
        :type password: str
        :param new_password: New user password.
        :type new_password: str
        :return: True if password change is successful.
        :rtype: bool
        """
        rc, _, _, _ = self.password_expired_with_output(username, password, new_password)
        return rc == 0

    def passkey_with_output(
        self,
        username: str,
        *,
        device: str,
        ioctl: str,
        script: str,
        pin: str | int | None = None,
        interactive_prompt: str = "Insert your passkey device, then press ENTER.",
        touch_prompt: str = "Please touch the device.",
        command: str = "exit 0",
        auth_method: PasskeyAuthenticationUseCases = PasskeyAuthenticationUseCases.PASSKEY_PIN,
    ) -> tuple[int, int, str, str]:
        """
        Call ``su - $username`` and authenticate the user with passkey.

        :param username: Username
        :type username: str
        :param device: Path to local umockdev device file.
        :type device: str
        :param ioctl: Path to local umockdev ioctl file.
        :type ioctl: str
        :param script: Path to local umockdev script file
        :type script: str
        :param pin: Passkey PIN, defaults to None
        :type pin: str | int | None
        :param interactive_prompt: Interactive prompt, defaults to "Insert your passkey device, then press ENTER."
        :type interactive_prompt: str
        :param touch_prompt: Touch prompt, defaults to "Can you touch this device"
        :type touch_prompt: str
        :param command: Command executed after user is authenticated, defaults to "exit 0"
        :type command: str
        :param auth_method: Authentication method, defaults to PasskeyAuthenticationUseCases.PASSKEY_WITH_PIN
        :type auth_method: PasskeyAuthenticationUseCases
        :return: Tuple containing [return code, command code, stdout, stderr].
        :rtype: Tuple[int, int, str, str]
        """
        self.fs.backup("/usr/libexec/sssd/passkey_child")
        self.fs.copy("/usr/libexec/sssd/passkey_child", "/usr/libexec/sssd/passkey_child.orig")

        device_path = self.fs.upload_to_tmp(device, mode="a=r")
        ioctl_path = self.fs.upload_to_tmp(ioctl, mode="a=r")
        script_path = self.fs.upload_to_tmp(script, mode="a=r")

        match auth_method:
            case (PasskeyAuthenticationUseCases.PASSKEY_PIN, PasskeyAuthenticationUseCases.PASSKEY_PIN_AND_PROMPTS):
                if pin is None:
                    raise ValueError(f"PIN is required for {str(auth_method)}")
            case (
                PasskeyAuthenticationUseCases.PASSKEY_PROMPTS_NO_PIN,
                PasskeyAuthenticationUseCases.PASSKEY_FALLBACK_TO_PASSWORD,
                PasskeyAuthenticationUseCases.PASSKEY_NO_PIN_NO_PROMPTS,
            ):
                if pin is not None:
                    raise ValueError(f"PIN is not required for {str(auth_method)}")

        run_su = self.fs.mktmp(
            rf"""
                #!/bin/bash
                set -ex
                echo '#!/bin/bash' > /usr/libexec/sssd/passkey_child
                echo -n 'export ' >> /usr/libexec/sssd/passkey_child
                env | grep ^UMOCKDEV_ >> /usr/libexec/sssd/passkey_child
                echo -n 'export ' >> /usr/libexec/sssd/passkey_child
                printf "LD_PRELOAD=$LD_PRELOAD\n" >> /usr/libexec/sssd/passkey_child
                echo 'exec /usr/libexec/sssd/passkey_child.orig $@' >> /usr/libexec/sssd/passkey_child
                chmod 755 /usr/libexec/sssd/passkey_child
                chmod -R a+rwx $UMOCKDEV_DIR

                su --shell /bin/sh nobody -c "su - '{username}' -c '{command}'"
                """,
            mode="a=rx",
        )

        playback_umockdev = self.fs.mktmp(
            rf"""
            #!/bin/bash

            LD_PRELOAD=/opt/random.so umockdev-run \
                --device '{device_path}' \
                --ioctl '/dev/hidraw1={ioctl_path}' \
                --script '/dev/hidraw1={script_path}' \
                -- '{run_su}'
            """,
            mode="a=rx",
        )

        result = self.host.conn.expect(
            rf"""
            # Disable debug output
            # exp_internal 0

            proc exitmsg {{ msg code }} {{
                # Close spawned program, if we are in the prompt
                catch close

                # Wait for the exit code
                lassign [wait] pid spawnid os_error_flag rc

                puts ""
                puts "expect result: $msg"
                puts "expect exit code: $code"
                puts "expect spawn exit code: $rc"
                exit $code
            }}

            # It takes some time to get authentication failure
            set timeout {DEFAULT_AUTHENTICATION_TIMEOUT}
            set prompt "\n.*\[#\$>\] $"
            set command "{command}"
            set auth_method "{auth_method}"

            spawn "{playback_umockdev}"

            # If the authentication method set without entering the PIN, it will directly ask
            # prompt, if we set prompting options in sssd.conf it will ask interactive and touch prompt.

            if {{ ($auth_method eq "{PasskeyAuthenticationUseCases.PASSKEY_NO_PIN_NO_PROMPTS}")
                || ($auth_method eq "{PasskeyAuthenticationUseCases.PASSKEY_PROMPTS_NO_PIN}") }}  {{
                expect {{
                    "{interactive_prompt}*" {{ send -- "\n" }}
                    timeout {{exitmsg "Unexpected output" 201 }}
                    eof {{exitmsg "Unexpected end of file" 202 }}
                }}
                # If prompt options are set
                if {{ ($auth_method eq "{PasskeyAuthenticationUseCases.PASSKEY_PROMPTS_NO_PIN}") }} {{
                    expect {{
                        "{touch_prompt}*" {{ send -- "\n" }}
                        timeout {{exitmsg "Unexpected output" 201 }}
                        eof {{exitmsg "Unexpected end of file" 202 }}
                    }}
                }}
            }}

            # If authentication method set with PIN, after interactive prompt always ask to Enter the PIN.
            # If PIN is correct with prompt options in sssd.conf it will ask interactive and touch prompt.
            # If we press Enter key for PIN, sssd will fallback to next auth method, here it will ask
            # for Password.

            if {{ ($auth_method eq "{PasskeyAuthenticationUseCases.PASSKEY_PIN}")
                || ($auth_method eq "{PasskeyAuthenticationUseCases.PASSKEY_PIN_AND_PROMPTS}")
                || ($auth_method eq "{PasskeyAuthenticationUseCases.PASSKEY_FALLBACK_TO_PASSWORD}")}} {{
                expect {{
                    "{interactive_prompt}*" {{ send -- "\n" }}
                    timeout {{exitmsg "Unexpected output" 201 }}
                    eof {{exitmsg "Unexpected end of file" 202 }}
                }}
                expect {{
                    "Enter PIN:*" {{send -- "{pin}\r"}}
                    timeout {{exitmsg "Unexpected output" 201}}
                    eof {{exitmsg "Unexpected end of file" 202}}
                }}
                if {{ ($auth_method eq "{PasskeyAuthenticationUseCases.PASSKEY_FALLBACK_TO_PASSWORD}") }} {{
                    expect {{
                        "Password:*" {{send -- "Secret123\r"}}
                        timeout {{exitmsg "Unexpected output" 201}}
                        eof {{exitmsg "Unexpected end of file" 202}}
                    }}
                }}
                if {{ ($auth_method eq "{PasskeyAuthenticationUseCases.PASSKEY_PIN_AND_PROMPTS}") }} {{
                    expect {{
                        "{touch_prompt}*" {{ send -- "\n" }}
                        timeout {{exitmsg "Unexpected output" 201 }}
                        eof {{exitmsg "Unexpected end of file" 202 }}
                    }}
                }}
            }}

            expect {{
                "Authentication failure" {{exitmsg "Authentication failure" 1}}
                eof {{exitmsg "Password authentication successful" 0}}
                timeout {{exitmsg "Unexpected output" 201}}
            }}

            exitmsg "Unexpected code path" 203
            """,
            verbose=False,
        )

        self.fs.restore("/usr/libexec/sssd/passkey_child")

        if result.rc > 200:
            raise ExpectScriptError(result.rc)

        expect_data = result.stdout_lines[-3:]

        # Get command exit code.
        cmdrc = int(expect_data[2].split(":")[1].strip())

        # Alter stdout, first line is spawned command, the last three are our expect output.
        stdout = "\n".join(result.stdout_lines[1:-3])

        return result.rc, cmdrc, stdout, result.stderr

    def passkey(
        self,
        username: str,
        *,
        device: str,
        ioctl: str,
        script: str,
        pin: str | int | None = None,
        command: str = "exit 0",
    ) -> bool:
        """
        Call ``su - $username`` and authenticate the user with passkey.

        :param username: Username
        :type username: str
        :param pin: Passkey PIN.
        :type pin: str | int
        :param device: Path to local umockdev device file.
        :type device: str
        :param ioctl: Path to local umockdev ioctl file.
        :type ioctl: str
        :param script: Path to local umockdev script file
        :type script: str
        :return: Generated passkey mapping string.
        :rtype: str
        :param command: Command executed after user is authenticated, defaults to "exit 0"
        :type command: str
        :return: True if authentication was successful, False otherwise.
        :rtype: bool
        """
        rc, _, _, _ = self.passkey_with_output(
            username=username, pin=pin, device=device, ioctl=ioctl, script=script, command=command
        )
        return rc == 0


class SSHAuthenticationUtils(MultihostUtility[MultihostHost]):
    """
    Methods for testing authentication and authorization via ssh.
    """

    def __init__(self, host: MultihostHost) -> None:
        """
        :param host: Multihost host.
        :type host: MultihostHost
        """
        super().__init__(host)

        self.opts = "-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"
        """SSH CLI options."""

    def password_with_output(
        self, username: str, password: str, hostname: str = "localhost"
    ) -> tuple[int, int, str, str]:
        """
        SSH to the remote host and authenticate the user with password and captures standard output and error.

        :param username: Username.
        :type username: str
        :param password: User password.
        :type password: str
        :param hostname: The hostname to connect to.
        :type hostname: str
        :return: Tuple containing [except return code, command exit code, stdout, stderr].
        :rtype: Tuple[int, int, str, str]
        """

        result = self.host.conn.expect_nobody(
            rf"""
            # Disable debug output
            exp_internal 0

            proc exitmsg {{ msg code }} {{
                # Close spawned program, if we are in the prompt
                catch close

                # Wait for the exit code
                lassign [wait] pid spawnid os_error_flag rc

                puts ""
                puts "expect result: $msg"
                puts "expect exit code: $code"
                puts "expect spawn exit code: $rc"
                exit $code
            }}

            # It takes some time to get authentication failure
            set timeout {DEFAULT_AUTHENTICATION_TIMEOUT}
            set prompt "\n.*\[#\$>\] $"
            log_user 1
            log_file /tmp/expect.log

            spawn ssh {self.opts} \
                -o PreferredAuthentications=password \
                -o NumberOfPasswordPrompts=1 \
                -l "{username}" "{hostname}"

            expect {{
                "password:" {{send "{password}\n"}}
                timeout {{exitmsg "Unexpected output" 201}}
                eof {{exitmsg "Unexpected end of file" 202}}
            }}

            expect {{
                -re $prompt {{exitmsg "Password authentication successful" 0}}
                "{username}@{hostname}: Permission denied" {{exitmsg "Authentication failure" 1}}
                "Connection closed by * port *" {{exitmsg "Connection closed" 2}}
                "Current Password:" {{exitmsg "Password change requested" 3 }}
                timeout {{exitmsg "Unexpected output" 201}}
                eof {{exitmsg "Unexpected end of file" 202}}
            }}

            exitmsg "Unexpected code path" 203
            """,
            verbose=False,
        )

        if result.rc > 200:
            raise ExpectScriptError(result.rc)

        expect_data = result.stdout_lines[-3:]

        # Get command exit code.
        cmdrc = int(expect_data[2].split(":")[1].strip())

        # Alter stdout, first line is spawned command, the last three are our expect output.
        stdout = "\n".join(result.stdout_lines[1:-3])

        return result.rc, cmdrc, stdout, result.stderr

    def password(self, username: str, password: str, hostname: str = "localhost") -> bool:
        """
        SSH to the remote host and authenticate the user with password.

        :param username: Username.
        :type username: str
        :param password: User password.
        :type password: str
        :param hostname: The hostname to connect to.
        :type hostname: str
        :return: True if authentication was successful, False otherwise.
        :rtype: bool
        """
        rc, _, _, _ = self.password_with_output(username, password, hostname)
        return rc == 0

    def password_expired_with_output(
        self, username: str, password: str, new_password: str, hostname: str = "localhost"
    ) -> tuple[int, int, str, str]:
        """
        SSH to the remote host and authenticate the user with password, expect that the password
        is expired and change it to the new password and captures standard output and error.

        :param username: Username.
        :type username: str
        :param password: Old, expired user password.
        :type password: str
        :param new_password: New user password.
        :type new_password: str
        :param hostname: The hostname to connect to.
        :type hostname: str
        :return: Tuple containing [except return code, command exit code, stdout, stderr].
        :rtype: Tuple[int, int, str, str]
        """
        result = self.host.conn.expect_nobody(
            rf"""
            # Disable debug output
            exp_internal 0

            proc exitmsg {{ msg code }} {{
                # Close spawned program, if we are in the prompt
                catch close

                # Wait for the exit code
                lassign [wait] pid spawnid os_error_flag rc

                puts ""
                puts "expect result: $msg"
                puts "expect exit code: $code"
                puts "expect spawn exit code: $rc"
                exit $code
            }}

            # It takes some time to get authentication failure
            set timeout {DEFAULT_AUTHENTICATION_TIMEOUT}
            set prompt "\n.*\[#\$>\] $"
            log_user 1
            log_file /tmp/expect.log

            spawn ssh {self.opts} \
                -o PreferredAuthentications=password \
                -o NumberOfPasswordPrompts=1 \
                -l "{username}" localhost

            expect {{
                "password:" {{send "{password}\n"}}
                timeout {{exitmsg "Unexpected output" 201}}
                eof {{exitmsg "Unexpected end of file" 202}}
            }}

            expect {{
                "Current Password:" {{send "{password}\n"}}
                timeout {{exitmsg "Unexpected output" 201}}
                eof {{exitmsg "Unexpected end of file" 202}}
            }}

            expect {{
                "New password:" {{send "{new_password}\n"}}
                timeout {{exitmsg "Unexpected output" 201}}
                eof {{exitmsg "Unexpected end of file" 202}}
            }}

            expect {{
                "Retype new password:" {{send "{new_password}\n"}}
                timeout {{exitmsg "Unexpected output" 201}}
                eof {{exitmsg "Unexpected end of file" 202}}
            }}

            expect {{
                "password updated successfully" {{exitmsg "Password change was successful" 0}}
                "Please make sure the password meets the complexity constraints." {{exitmsg "Complexity failure" 1}}
                "Password too short" {{exitmsg "Complexity failure" 1}}
                "Password is too short" {{exitmsg "Complexity failure" 1}}
                "Failed to update password" {{exitmsg "Password change failed" 1}}
                timeout {{exitmsg "Unexpected output" 201}}
                eof {{exitmsg "Unexpected end of file" 202}}
            }}

            exitmsg "Unexpected code path" 203
            """,
            verbose=False,
        )

        if result.rc > 200:
            raise ExpectScriptError(result.rc)

        expect_data = result.stdout_lines[-3:]

        # Get command exit code.
        cmdrc = int(expect_data[2].split(":")[1].strip())

        # Alter stdout, first line is spawned command, the last three are our expect output.
        stdout = "\n".join(result.stdout_lines[1:-3])

        return result.rc, cmdrc, stdout, result.stderr

    def password_expired(self, username: str, password: str, new_password: str, hostname: str = "localhost") -> bool:
        """
        SSH to the remote host and authenticate the user with password, expect
        that the password is expired and change it to the new password.

        :param username: Username.
        :type username: str
        :param password: Old, expired user password.
        :type password: str
        :param new_password: New user password.
        :type new_password: str
        :param hostname: The hostname to connect to.
        :type hostname: str
        :return: True if authentication and password change was successful, False otherwise.
        :rtype: bool
        """
        rc, _, _, _ = self.password_expired_with_output(username, password, new_password, hostname)
        return rc == 0


class SudoAuthenticationUtils(MultihostUtility[MultihostHost]):
    """
    Methods for testing authentication and authorization via sudo.
    """

    def run(self, username: str, password: str | None = None, *, command: str) -> bool:
        """
        Execute sudo command.

        :param username: Username that calls sudo.
        :type username: str
        :param password: User password, defaults to None
        :type password: str | None, optional
        :param command: Command to execute (make sure to properly escape any quotes).
        :type command: str
        :return: True if the command was successful, False if the command failed or the user can not run sudo.
        :rtype: bool
        """
        result = self.host.conn.run(
            f'su - "{username}" -c "sudo --stdin {command}"', input=password, raise_on_error=False
        )

        return result.rc == 0

    def list(self, username: str, password: str | None = None, *, expected: list[str] | None = None) -> bool:
        """
        List commands that the user can run under sudo.

        :param username: Username that runs sudo.
        :type username: str
        :param password: User password, defaults to None
        :type password: str | None, optional
        :param expected: List of expected commands (formatted as sudo output), defaults to None
        :type expected: list[str] | None, optional
        :return: True if the user can run sudo and allowed commands match expected commands (if set), False otherwise.
        :rtype: bool
        """
        result = self.host.conn.run(f'su - "{username}" -c "sudo --stdin -l"', input=password, raise_on_error=False)
        if result.rc != 0:
            return False

        if expected is None:
            return True

        allowed = []
        for line in reversed(result.stdout_lines):
            if not line.startswith("    "):
                break
            allowed.append(line.strip())

        for line in expected:
            if line not in allowed:
                return False
            allowed.remove(line)

        if len(allowed) > 0:
            return False

        return True


class KerberosAuthenticationUtils(MultihostUtility[MultihostHost]):
    """
    Methods for testing Kerberos authentication and KCM.
    """

    def __init__(self, host: MultihostHost, ssh: Connection | None = None) -> None:
        """
        :param host: Multihost host.
        :type host: MultihostHost
        :param ssh: SSH client for the target user, defaults to None
        :type ssh: Connection | None, optional
        """
        super().__init__(host)

        self.conn: Connection = ssh if ssh is not None else host.conn
        """SSH client for the target user."""

    def kinit(
        self, principal: str, *, password: str, realm: str | None = None, args: list[str] | None = None
    ) -> ProcessResult:
        """
        Run ``kinit`` command.

        Principal can be without the realm part. The realm can be given in
        separate parameter ``realm``, in such case the principal name is
        constructed as ``$principal@$realm``. If the principal does not contain
        realm specification and ``realm`` parameter is not set then the default
        realm is used.

        :param principal: Kerberos principal.
        :type principal: str
        :param password: Principal's password.
        :type password: str
        :param realm: Kerberos realm that is appended to the principal (``$principal@$realm``), defaults to None
        :type realm: str | None, optional
        :param args: Additional parameters to ``klist``, defaults to None
        :type args: list[str] | None, optional
        :return: Command result.
        :rtype: ProcessResult
        """
        if args is None:
            args = []

        if realm is not None:
            principal = f"{principal}@{realm}"

        return self.conn.exec(["kinit", *args, principal], input=password)

    def kvno(self, principal: str, *, realm: str | None = None, args: list[str] | None = None) -> ProcessResult:
        """
        Run ``kvno`` command.

        Principal can be without the realm part. The realm can be given in
        separate parameter ``realm``, in such case the principal name is
        constructed as ``$principal@$realm``. If the principal does not contain
        realm specification and ``realm`` parameter is not set then the default
        realm is used.

        :param principal: Kerberos principal.
        :type principal: str
        :param realm: Kerberos realm that is appended to the principal (``$principal@$realm``), defaults to None
        :type realm: str | None, optional
        :param args: Additional parameters to ``klist``, defaults to None
        :type args: list[str] | None, optional
        :return: Command result.
        :rtype: ProcessResult
        """
        if args is None:
            args = []

        if realm is not None:
            principal = f"{principal}@{realm}"

        return self.conn.exec(["kvno", *args, principal])

    def klist(self, *, args: list[str] | None = None) -> ProcessResult:
        """
        Run ``klist`` command.

        :param args: Additional parameters to ``klist``, defaults to None
        :type args: list[str] | None, optional
        :return: Command result.
        :rtype: ProcessResult
        """
        if args is None:
            args = []

        return self.conn.exec(["klist", *args])

    def kswitch(self, principal: str, realm: str) -> ProcessResult:
        """
        Run ``kswitch -p principal@realm`` command.

        :param principal: Kerberos principal.
        :type principal: str
        :param realm: Kerberos realm that is appended to the principal (``$principal@$realm``)
        :type realm: str
        :return: Command result.
        :rtype: ProcessResult
        """
        if "@" not in principal:
            principal = f"{principal}@{realm}"

        return self.conn.exec(["kswitch", "-p", principal])

    def kdestroy(
        self, *, all: bool = False, ccache: str | None = None, principal: str | None = None, realm: str | None = None
    ) -> ProcessResult:
        """
        Run ``kdestroy`` command.

        Principal can be without the realm part. The realm can be given in
        separate parameter ``realm``, in such case the principal name is
        constructed as ``$principal@$realm``. If the principal does not contain
        realm specification and ``realm`` parameter is not set then the default
        realm is used.

        :param all: Destroy all ccaches (``kdestroy -A``), defaults to False
        :type all: bool, optional
        :param ccache: Destroy specific ccache (``kdestroy -c $cache``), defaults to None
        :type ccache: str | None, optional
        :param principal: Destroy ccache for given principal (``kdestroy -p $princ``), defaults to None
        :type principal: str | None, optional
        :param realm: Kerberos realm that is appended to the principal (``$principal@$realm``), defaults to None
        :type realm: str | None, optional
        :return: Command result.
        :rtype: ProcessResult
        """
        args = []

        if all:
            args.append("-A")

        if ccache is not None:
            args.append("-c")
            args.append(ccache)

        if realm is not None and principal is not None:
            principal = f"{principal}@{realm}"

        if principal is not None:
            args.append("-p")
            args.append(principal)

        return self.conn.exec(["kdestroy", *args])

    def has_tgt(self, principal: str | None, realm: str) -> bool:
        """
        Check that the user has obtained Kerberos Ticket Granting Ticket for
        given principle. If ``principal`` is ``None`` then primary principal is
        checked.

        :param principal: Expected principal for which the TGT was obtained (without the realm part).
        :type principal: str | None
        :param realm: Expected realm for which the TGT was obtained.
        :type realm: str
        :return: True if TGT is available, False otherwise.
        :rtype: bool
        """
        if principal is not None:
            result = self.klist()
            return f"krbtgt/{realm}@{realm}" in result.stdout

        principals = self.list_principals()
        tickets = principals.get(f"{principal}@{realm}", [])

        return "krbtgt/{realm}@{realm}" in tickets

    def has_primary_cache(self, principal: str, realm: str) -> bool:
        """
        Check that the ccache for given principal is the primary one.

        :param principal: Kerberos principal.
        :type principal: str
        :param realm: Kerberos realm that is appended to the principal (``$principal@$realm``)
        :type realm: str
        :return: True if the ccache for given principal is the primary one.
        :rtype: bool
        """
        result = self.conn.exec(["klist", "-l"], raise_on_error=False)
        if result.rc != 0:
            return False

        if len(result.stdout_lines) <= 2:
            return False

        primary = result.stdout_lines[2]

        return f"{principal}@{realm}" in primary

    def has_tickets(self, principal: str, realm: str, expected: list[str]) -> bool:
        """
        Check that the ccache contains all tickets from ``expected`` and nothing
        more.

        :param principal: Kerberos principal.
        :type principal: str
        :param realm: Kerberos realm that is appended to the principal
            (``$principal@$realm``)
        :type realm: str
        :param expected: List of tickets that must be present in the ccache.
        :type expected: list[str]
        :return: True if the ccache contains exactly ``expected`` tickets.
        :rtype: bool
        """
        ccaches = self.list_principals()
        principal = f"{principal}@{realm}"

        if principal not in ccaches:
            return False

        return ccaches[principal] == expected

    def cache_count(self) -> int:
        """
        Return number of existing credential caches (or number of principals)
        for active user (klist -l).

        :return: Number of existing ccaches.
        :rtype: int
        """
        result = self.conn.exec(["klist", "-l"], raise_on_error=False)
        if result.rc != 0:
            return 0

        if len(result.stdout_lines) <= 2:
            return 0

        return len(result.stdout_lines) - 2

    def list_principals(self, env: dict[str, Any] | None = None) -> dict[str, list[str]]:
        """
        List all principals that have existing credential cache.

        :param env: Additional environment variables passed to ``klist -A`` command, defaults to None
        :type env: dict[str, Any] | None, optional
        :return: Dictionary with principal as the key and list of available tickets as value.
        :rtype: dict[str, list[str]]
        """

        def __parse_output(result: ProcessResult) -> dict[str, list[str]]:
            ccache_principal: str | None = None
            ccache: dict[str, list[str]] = dict()

            for line in result.stdout_lines:
                if line.startswith("Default principal"):
                    ccache_principal = line.split()[-1]
                    ccache.setdefault(ccache_principal, [])
                    continue

                if ccache_principal is not None and "@" in line:
                    ticket = line.split()[-1]
                    ccache[ccache_principal].append(ticket)

            return ccache

        result = self.conn.exec(["klist", "-A"], env=env, raise_on_error=False)
        if result.rc != 0:
            return dict()

        return __parse_output(result)

    def list_ccaches(self) -> dict[str, str]:
        """
        List all available ccaches.

        :return: Dictionary with principal as the key and ccache name as value.
        :rtype: dict[str, str]
        """

        def __parse_output(result: ProcessResult) -> dict[str, str]:
            if len(result.stdout_lines) <= 2:
                return dict()

            ccaches: dict[str, str] = dict()
            for line in result.stdout_lines[2:]:
                (principal, ccache) = line.split(maxsplit=2)
                ccaches[principal] = ccache

            return ccaches

        result = self.conn.exec(["klist", "-l"], raise_on_error=False)
        if result.rc != 0:
            return dict()

        return __parse_output(result)

    def list_tgt_times(self, realm: str) -> tuple[datetime, datetime]:
        """
        Return start and expiration time of primary ccache TGT.

        :param realm: Expected realm for which the TGT was obtained.
        :type realm: str
        :return: (start time, expiration time) of the TGT
        :rtype: tuple[int, int]
        """
        tgt = f"krbtgt/{realm}@{realm}"
        result = self.klist()
        for line in result.stdout_lines:
            if tgt in line:
                (sdate, stime, edate, etime, principal) = line.split(maxsplit=5)

                start = None
                end = None

                # format may be different on different hosts
                for format in ["%m/%d/%y %H:%M:%S", "%m/%d/%Y %H:%M:%S"]:
                    try:
                        start = datetime.strptime(f"{sdate} {stime}", format)
                        end = datetime.strptime(f"{edate} {etime}", format)
                    except ValueError:
                        continue

                if start is None:
                    raise ValueError(f"Unable to parse datetime: {sdate} {stime}")

                if end is None:
                    raise ValueError(f"Unable to parse datetime: {edate} {etime}")

                return (start, end)

        raise Exception("TGT was not found")

    def __enter__(self) -> KerberosAuthenticationUtils:
        """
        Connect to the host over ssh if not already connected.

        :return: Self..
        :rtype: HostKerberos
        """
        self.conn.connect()
        return self

    def __exit__(self, exception_type, exception_value, traceback) -> None:
        """
        Disconnect.
        """
        self.kdestroy(all=True)


class PasswdUtils(MultihostUtility[MultihostHost]):
    """
    Change authentication tokens with passwd tool.
    """

    def __init__(self, host: MultihostHost):
        super().__init__(host)

    def password(self, user: str, password: str, new_password: str, retyped: str | None = None) -> bool:
        """
        Changing password as a given user.

        @retyped is only used if the test needs to fail because the passwords don't match, otherwise it is redundant

        :param user: Username.
        :type user: str
        :param password: Current password of user.
        :type password: str
        :param new_password: New password of user.
        :type new_password: str
        :param retyped: Retyped new password of user.
        :type retyped: str | None, optional
        :raises ExpectScriptError: If EOF or timeout occured.
        :return: True if password change was successful, False otherwise.
        :rtype: bool
        """
        if retyped is None:
            retyped = new_password

        result = self.host.conn.expect(
            rf"""
            set timeout {DEFAULT_AUTHENTICATION_TIMEOUT}
            set prompt "\n.*\[#\$>\] $"

            spawn su - {user} -c passwd

            expect {{
                -nocase "Current Password: " {{send "{password}\n"}}
                timeout {{puts "expect result: Unexpected output"; exit 201}}
                eof {{puts "expect result: Unexpected end of file"; exit 202}}
            }}

            expect {{
                -nocase "New password:" {{send "{new_password}\n"}}
                "Password change failed. Server message: Old password not accepted." {{exit 1}}
                timeout {{puts "expect result: Unexpected output"; exit 201}}
                eof {{puts "expect result: Unexpected end of file"; exit 202}}
            }}

            expect {{
                -nocase "Retype new password:" {{send "{retyped}\n"}}
                timeout {{puts "expect result: Unexpected output"; exit 201}}
                eof {{puts "expect result: Unexpected end of file"; exit 202}}
            }}

            expect {{
                -re "passwd: .+ updated successfully." {{exit 0}}
                "Sorry, passwords do not match." {{exit 1}}
                "Password change failed." {{exit 1}}
                timeout {{puts "expect result: Unexpected output"; exit 201}}
                eof {{puts "expect result: Unexpected end of file"; exit 202}}
            }}

            puts "expect result: Unexpected code path"
            exit 203
            """
        )

        if result.rc > 200:
            raise ExpectScriptError(result.rc)

        return result.rc == 0
