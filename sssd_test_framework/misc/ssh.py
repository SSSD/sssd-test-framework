from __future__ import annotations

import shlex
from functools import wraps
from time import sleep
from typing import Any, Callable, ParamSpec

from pytest_mh.conn import Connection, Process, ProcessError, ProcessLogLevel, ProcessResult

from . import to_list_of_strings


class SSHKillableProcess(object):
    """
    Run an asynchronous process that requires ``SIGTERM`` to be terminated.
    """

    def __init__(
        self,
        client: Connection,
        argv: list[Any],
        *,
        cwd: str | None = None,
        env: dict[str, Any] | None = None,
        input: str | None = None,
        log_level: ProcessLogLevel = ProcessLogLevel.Full,
    ) -> None:
        """
        :param client: SSH client.
        :type client: Connection
        :param argv: Command to run.
        :type argv: list[Any]
        :param cwd: Working directory, defaults to None (= do not change)
        :type cwd: str | None, optional
        :param env: Additional environment variables, defaults to None
        :type env: dict[str, Any] | None, optional
        :param input: Content of standard input, defaults to None
        :type input: str | None, optional
        :param log_level: Log level, defaults to ProcessLogLevel.Full
        :type log_level: ProcessLogLevel, optional
        """
        if env is None:
            env = {}

        argv = to_list_of_strings(argv)
        command = shlex.join(argv)
        pidfile = "/tmp/.mh.sshkillableprocess.pid"

        self.client: Connection = client
        self.process: Process = client.async_run(
            f"""
                set -m
                {command} &
                echo $! &> "{pidfile}"
                fg
            """,
            cwd=cwd,
            env=env,
            input=input,
            log_level=log_level,
        )

        # Get pid
        result = self.client.run(
            f"""
            until [ -f "{pidfile}" ]; do sleep 0.005; done
            cat "{pidfile}"
            rm -f "{pidfile}"
        """
        )

        self.pid = result.stdout.strip()
        """Process id."""

        self.kill_delay: int = 0
        """Wait ``kill_delay`` seconds before killing the process."""

        self.__killed: bool = False

    def kill(self) -> None:
        if self.__killed:
            return

        self.client.run(f"sleep {self.kill_delay}; kill {self.pid}")
        self.__killed = True

    def __enter__(self) -> SSHKillableProcess:
        return self

    def __exit__(self, exception_type, exception_value, traceback) -> None:
        self.kill()
        self.process.wait()


Param = ParamSpec("Param")


def retry_command(
    max_retries: int = 5,
    delay: float = 1,
    match_stdout: str | None = None,
    match_stderr: str | None = None,
) -> Callable[[Callable[Param, ProcessResult]], Callable[Param, ProcessResult]]:
    """
    Decorated function will be retried if its return code is non zero.

    :param max_retries: Maximum number of retry attempts, defaults to 5
    :type max_retries: int, optional
    :param delay: Delay in seconds between each retry, defaults to 1
    :type delay: float, optional
    :param match_stdout: If set, retry only of string is found in stdout, defaults to None
    :type match_stdout: str | None, optional
    :param match_stderr: If set, retry only of string is found in stderr, defaults to None
    :type match_stderr: str | None, optional

    :return: Decorated function.
    :rtype: Callable
    """

    def decorator(func: Callable[Param, ProcessResult]) -> Callable[Param, ProcessResult]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> ProcessResult:
            error: ProcessError | None = None
            retry: int = 0
            while True:
                if retry >= max_retries:
                    break

                rc = 0
                stdout = ""
                stderr = ""
                try:
                    error = None
                    result = func(*args, **kwargs)
                    rc = result.rc
                    stdout = result.stdout
                    stderr = result.stderr
                except ProcessError as e:
                    error = e
                    rc = e.rc
                    stdout = e.stdout
                    stderr = e.stderr

                if rc == 0:
                    break

                if match_stdout is not None and match_stdout not in stdout:
                    break

                if match_stderr is not None and match_stderr not in stderr:
                    break

                retry += 1
                sleep(delay)

            if error is not None:
                raise error

            return result

        return wrapper

    return decorator
