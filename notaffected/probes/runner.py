"""Transport layer for executing read-only probes locally or over SSH.

Never uses shell=True on local execution, and uses shlex.join over SSH with
BatchMode=yes so prompts never hang automation.
"""

from __future__ import annotations

import shlex
import socket
import subprocess
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class CommandResult:
    """Result of executing a read-only command on a target host."""

    returncode: int
    stdout: str
    stderr: str
    transport_error: bool = False


class HostRunner(Protocol):
    """Protocol implemented by LocalRunner, SSHRunner, and MockRunner."""

    host_name: str

    def run(self, argv: list[str]) -> CommandResult:
        ...


class LocalRunner:
    """Executes probe commands directly on the local machine without a shell."""

    def __init__(self, host_name: str | None = None, timeout: int = 10) -> None:
        self.host_name = host_name or socket.gethostname() or "localhost"
        self.timeout = timeout

    def run(self, argv: list[str]) -> CommandResult:
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                shell=False,
                check=False,
            )
            return CommandResult(
                returncode=proc.returncode,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                transport_error=False,
            )
        except FileNotFoundError as exc:
            return CommandResult(
                returncode=127,
                stdout="",
                stderr=str(exc),
                transport_error=False,
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                returncode=124,
                stdout="",
                stderr=f"Command timed out after {self.timeout}s: {exc}",
                transport_error=True,
            )
        except OSError as exc:
            return CommandResult(
                returncode=255,
                stdout="",
                stderr=str(exc),
                transport_error=True,
            )


class SSHRunner:
    """Executes probe commands over standard OpenSSH client (`ssh`)."""

    def __init__(
        self,
        target: str,
        host_name: str | None = None,
        timeout: int = 10,
        port: int | None = None,
    ) -> None:
        self.target = target
        self.host_name = host_name or target
        self.timeout = timeout
        self.port = port

    def run(self, argv: list[str]) -> CommandResult:
        remote_cmd = shlex.join(argv)
        ssh_argv = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={self.timeout}",
        ]
        if self.port:
            ssh_argv.extend(["-p", str(self.port)])
        ssh_argv.extend(["--", self.target, remote_cmd])
        try:
            proc = subprocess.run(
                ssh_argv,
                capture_output=True,
                text=True,
                timeout=self.timeout + 5,
                shell=False,
                check=False,
            )
            is_ssh_err = proc.returncode == 255
            return CommandResult(
                returncode=proc.returncode,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                transport_error=is_ssh_err,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            return CommandResult(
                returncode=255,
                stdout="",
                stderr=str(exc),
                transport_error=True,
            )


class MockRunner:
    """Deterministic in-memory runner for unit and golden fleet tests."""

    def __init__(
        self,
        host_name: str,
        responses: dict[tuple[str, ...], CommandResult],
    ) -> None:
        self.host_name = host_name
        self.responses = dict(responses)

    def run(self, argv: list[str]) -> CommandResult:
        key = tuple(argv)
        if key in self.responses:
            return self.responses[key]
        return CommandResult(
            returncode=127,
            stdout="",
            stderr=f"MockRunner({self.host_name}): unmocked command {argv!r}",
            transport_error=False,
        )
