"""Transport layer for executing read-only probes locally or over SSH.

Never uses shell=True on local execution, and uses shlex.join over SSH with
BatchMode=yes so prompts never hang automation.
"""

from __future__ import annotations

import base64
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
    os_family: str

    def run(self, argv: list[str]) -> CommandResult:
        ...


class LocalRunner:
    """Executes probe commands directly on the local machine without a shell."""

    def __init__(
        self,
        host_name: str | None = None,
        timeout: int = 10,
        os_family: str = "linux",
    ) -> None:
        self.host_name = host_name or socket.gethostname() or "localhost"
        self.timeout = timeout
        self.os_family = os_family.lower()
        self._cache: dict[tuple[str, ...], CommandResult] = {}

    def run(self, argv: list[str]) -> CommandResult:
        key = tuple(argv)
        if key in self._cache:
            return self._cache[key]
        res = self._run_uncached(argv)
        self._cache[key] = res
        return res

    def _run_uncached(self, argv: list[str]) -> CommandResult:
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
        os_family: str = "linux",
    ) -> None:
        self.target = target
        self.host_name = host_name or target
        self.timeout = timeout
        self.port = port
        self.os_family = os_family.lower()
        self._cache: dict[tuple[str, ...], CommandResult] = {}

    def run(self, argv: list[str]) -> CommandResult:
        key = tuple(argv)
        if key in self._cache:
            return self._cache[key]
        res = self._run_uncached(argv)
        self._cache[key] = res
        return res

    def _run_uncached(self, argv: list[str]) -> CommandResult:
        if (
            self.os_family == "windows"
            and len(argv) >= 2
            and argv[0].lower() in ("powershell", "powershell.exe", "pwsh")
            and argv[-2].lower() == "-command"
        ):
            encoded = base64.b64encode(argv[-1].encode("utf-16le")).decode("ascii")
            remote_cmd = f"powershell -NoProfile -NonInteractive -EncodedCommand {encoded}"
        else:
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


class DockerRunner:
    """Executes read-only probe commands inside a running Docker container (`docker exec`)."""

    def __init__(
        self,
        container: str,
        host_name: str | None = None,
        timeout: int = 10,
        os_family: str = "linux",
    ) -> None:
        self.container = container
        self.host_name = host_name or f"docker:{container}"
        self.timeout = timeout
        self.os_family = os_family.lower()
        self._cache: dict[tuple[str, ...], CommandResult] = {}

    def run(self, argv: list[str]) -> CommandResult:
        key = tuple(argv)
        if key in self._cache:
            return self._cache[key]
        res = self._run_uncached(argv)
        self._cache[key] = res
        return res

    def _run_uncached(self, argv: list[str]) -> CommandResult:
        if not self.container or self.container.startswith("-"):
            return CommandResult(
                returncode=255,
                stdout="",
                stderr=f"Invalid Docker container identifier: {self.container!r}",
                transport_error=True,
            )
        docker_argv = ["docker", "exec", "--", self.container, *argv]
        try:
            proc = subprocess.run(
                docker_argv,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                shell=False,
                check=False,
            )
            stderr_lower = (proc.stderr or "").lower()
            is_daemon_err = proc.returncode == 125 or (
                proc.returncode != 0
                and any(
                    phrase in stderr_lower
                    for phrase in (
                        "error response from daemon",
                        "oci runtime",
                        "no such container",
                        "is not running",
                        "cannot connect to the docker daemon",
                        "permission denied while trying to connect",
                    )
                )
            )
            return CommandResult(
                returncode=proc.returncode,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                transport_error=is_daemon_err,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            return CommandResult(
                returncode=255,
                stdout="",
                stderr=str(exc),
                transport_error=True,
            )


class K8sRunner:
    """Executes read-only probe commands inside a Kubernetes pod (`kubectl exec`)."""

    def __init__(
        self,
        pod: str,
        namespace: str | None = None,
        container: str | None = None,
        host_name: str | None = None,
        timeout: int = 10,
        os_family: str = "linux",
    ) -> None:
        if namespace is None and "/" in pod:
            ns_part, pod_part = pod.split("/", 1)
            self.namespace: str | None = ns_part
            self.pod = pod_part
        else:
            self.namespace = namespace
            self.pod = pod
        self.container = container
        default_label = f"k8s:{self.namespace}/{self.pod}" if self.namespace else f"k8s:{self.pod}"
        self.host_name = host_name or default_label
        self.timeout = timeout
        self.os_family = os_family.lower()
        self._cache: dict[tuple[str, ...], CommandResult] = {}

    def run(self, argv: list[str]) -> CommandResult:
        key = tuple(argv)
        if key in self._cache:
            return self._cache[key]
        res = self._run_uncached(argv)
        self._cache[key] = res
        return res

    def _run_uncached(self, argv: list[str]) -> CommandResult:
        if (
            not self.pod
            or self.pod.startswith("-")
            or (self.namespace and self.namespace.startswith("-"))
            or (self.container and self.container.startswith("-"))
        ):
            return CommandResult(
                returncode=255,
                stdout="",
                stderr=f"Invalid Kubernetes pod/namespace identifier: {self.pod!r}",
                transport_error=True,
            )
        k_argv = ["kubectl", "exec"]
        if self.namespace:
            k_argv.extend(["-n", self.namespace])
        if self.container:
            k_argv.extend(["-c", self.container])
        k_argv.extend([self.pod, "--", *argv])
        try:
            proc = subprocess.run(
                k_argv,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                shell=False,
                check=False,
            )
            stderr_lower = (proc.stderr or "").lower()
            is_k8s_err = proc.returncode != 0 and any(
                phrase in stderr_lower
                for phrase in (
                    "error from server",
                    "error:",
                    "unable to connect to the server",
                    "unable to upgrade connection",
                    "the connection to the server",
                    "forbidden",
                    "container not found",
                    "pod does not exist",
                )
            )
            return CommandResult(
                returncode=proc.returncode,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                transport_error=is_k8s_err,
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
        os_family: str = "linux",
        simulate_dpkg_db: bool = False,
    ) -> None:
        self.host_name = host_name
        self.responses = dict(responses)
        self.os_family = os_family.lower()
        self.simulate_dpkg_db = simulate_dpkg_db

    def run(self, argv: list[str]) -> CommandResult:
        key = tuple(argv)
        if key in self.responses:
            return self.responses[key]
        if self.simulate_dpkg_db:
            if len(argv) == 4 and argv[0] == "dpkg-query" and argv[1] == "-W":
                return CommandResult(
                    returncode=1,
                    stdout="",
                    stderr=f"dpkg-query: no packages found matching {argv[3]}\n",
                    transport_error=False,
                )
            if len(argv) >= 2 and argv[0] == "systemctl" and argv[1] == "is-active":
                return CommandResult(returncode=3, stdout="inactive\n", stderr="")
            if len(argv) >= 3 and argv[0] == "sysctl" and argv[1] == "-n":
                return CommandResult(returncode=0, stdout="1\n", stderr="")
            if argv[0] == "powershell" and "Get-Service" in argv[-1]:
                return CommandResult(returncode=0, stdout="Stopped\n", stderr="")
        return CommandResult(
            returncode=127,
            stdout="",
            stderr=f"MockRunner({self.host_name}): unmocked command {argv!r}",
            transport_error=False,
        )
