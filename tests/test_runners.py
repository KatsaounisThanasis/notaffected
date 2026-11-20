"""Transport runners: argv building and failure classification, without opening any connection.

`subprocess.run` is replaced by a recorder, so no ssh/docker/kubectl process is started.
"""

from __future__ import annotations

import base64
import subprocess

import pytest

from notaffected.probes import runner as runner_mod
from notaffected.probes.runner import DockerRunner, K8sRunner, LocalRunner, SSHRunner


class _Proc:
    def __init__(self, returncode: int = 0, stdout: str = "ok\n", stderr: str = "") -> None:
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


@pytest.fixture
def recorder(monkeypatch):
    calls: list[tuple[list[str], dict]] = []
    result = {"proc": _Proc()}

    def _run(argv, **kwargs):
        calls.append((list(argv), kwargs))
        if isinstance(result["proc"], BaseException):
            raise result["proc"]
        return result["proc"]

    monkeypatch.setattr(runner_mod.subprocess, "run", _run)
    return calls, result


def test_ssh_argv_is_batch_mode_with_end_of_options_before_target(recorder):
    calls, _ = recorder
    res = SSHRunner(target="ops@10.0.0.5", port=2222, timeout=7).run(["cat", "/etc/os-release"])
    argv, kwargs = calls[0]
    assert argv[:5] == ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=7"]
    assert argv[5:7] == ["-p", "2222"]
    assert argv[7:] == ["--", "ops@10.0.0.5", "cat /etc/os-release"]
    assert kwargs["shell"] is False and kwargs["errors"] == "replace"
    assert res.returncode == 0 and res.stdout == "ok\n" and not res.transport_error


def test_ssh_quotes_arguments_and_classifies_failures(recorder):
    calls, result = recorder
    SSHRunner(target="h").run(["grep", "-c", "a b; rm -rf /", "/etc/x"])
    assert calls[-1][0][-1] == "grep -c 'a b; rm -rf /' /etc/x"

    result["proc"] = _Proc(255, "", "ssh: connect to host h port 22: Connection refused")
    assert SSHRunner(target="h").run(["uname", "-r"]).transport_error is True
    result["proc"] = _Proc(1, "", "no such file")
    assert SSHRunner(target="h").run(["uname", "-r"]).transport_error is False
    result["proc"] = subprocess.TimeoutExpired(cmd="ssh", timeout=1)
    res = SSHRunner(target="h").run(["uname", "-r"])
    assert res.transport_error is True and res.returncode == 255


def test_ssh_windows_powershell_uses_encoded_command(recorder):
    calls, _ = recorder
    script = "(Get-Service -Name 'Spooler').Status"
    SSHRunner(target="admin@win", os_family="windows").run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script]
    )
    remote = calls[0][0][-1]
    assert remote.startswith("powershell -NoProfile -NonInteractive -EncodedCommand ")
    assert base64.b64decode(remote.rsplit(" ", 1)[1]).decode("utf-16le") == script


def test_every_runner_decodes_with_replacement(recorder):
    calls, _ = recorder
    LocalRunner().run(["uname", "-r"])
    DockerRunner(container="c1").run(["uname", "-r"])
    K8sRunner(pod="p1", namespace="ns").run(["uname", "-r"])
    SSHRunner(target="h").run(["uname", "-r"])
    assert len(calls) == 4
    assert all(kw.get("errors") == "replace" and kw.get("text") is True for _, kw in calls)


def test_local_runner_survives_non_utf8_output():
    # Real, read-only local command printing a Latin-1 byte.
    res = LocalRunner().run(["printf", "caf\\351"])
    assert res.returncode == 0 and res.stdout.startswith("caf") and "�" in res.stdout
