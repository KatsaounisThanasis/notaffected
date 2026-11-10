"""Host inventory loader supporting `--host local`, `--ssh user@host`, and YAML/INI files."""

from __future__ import annotations

from pathlib import Path

import yaml

from notaffected.probes.runner import (
    CommandResult,
    DockerRunner,
    HostRunner,
    K8sRunner,
    LocalRunner,
    MockRunner,
    SSHRunner,
)


def load_demo_fleet() -> list[HostRunner]:
    """Return a realistic 3-host simulated fleet (laptop, exposed server, patched DB)
    so users can test multi-host verdicts without configuring SSH targets.
    """
    laptop = MockRunner(
        host_name="dev-laptop-01",
        responses={
            ("uname", "-r"): CommandResult(0, "6.8.0-40-generic\n", ""),
            ("dpkg", "--compare-versions", "6.8.0-40", "lt", "4.4.0"): CommandResult(1, "", ""),
            ("dpkg", "--compare-versions", "6.8.0-40", "lt", "6.8.0-45"): CommandResult(0, "", ""),
            ("dpkg", "--compare-versions", "6.8.0-40", "lt", "6.2.0-21"): CommandResult(1, "", ""),
            ("cat", "/proc/modules"): CommandResult(0, "tls 163840 0 - Live 0x0\n", ""),
            ("dpkg-query", "-W", "-f=${db:Status-Abbrev}\\t${Version}\\n", "cups-browsed"): CommandResult(
                0, "ii \t2.0.0-0ubuntu10.1\n", ""
            ),
            ("dpkg", "--compare-versions", "2.0.0-0ubuntu10.1", "lt", "2.0.0-0ubuntu10.2"): CommandResult(
                0, "", ""
            ),
            ("dpkg-query", "-W", "-f=${db:Status-Abbrev}\\t${Version}\\n", "openssh-server"): CommandResult(
                1, "", "dpkg-query: no packages found matching openssh-server\n"
            ),
            ("ps", "-eo", "comm,args", "--no-headers"): CommandResult(0, "systemd /sbin/init\n", ""),
            ("cat", "/etc/ssh/sshd_config"): CommandResult(1, "", "cat: /etc/ssh/sshd_config: No such file or directory"),
            ("systemctl", "is-active", "cups-browsed.service"): CommandResult(3, "inactive\n", ""),
            ("ss", "-tulpnH"): CommandResult(
                0,
                "udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\n"
                "tcp LISTEN 0 128 127.0.0.1:631 0.0.0.0:*\n",
                "",
            ),
            ("ufw", "status", "verbose"): CommandResult(
                0,
                "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n",
                "",
            ),
        },
    )
    edge_server = MockRunner(
        host_name="prod-edge-api-01",
        responses={
            ("uname", "-r"): CommandResult(0, "6.8.0-40-generic\n", ""),
            ("dpkg", "--compare-versions", "6.8.0-40", "lt", "4.4.0"): CommandResult(1, "", ""),
            ("dpkg", "--compare-versions", "6.8.0-40", "lt", "6.8.0-45"): CommandResult(0, "", ""),
            ("dpkg", "--compare-versions", "6.8.0-40", "lt", "6.2.0-21"): CommandResult(1, "", ""),
            ("cat", "/proc/modules"): CommandResult(0, "tls 163840 0 - Live 0x0\n", ""),
            ("dpkg-query", "-W", "-f=${db:Status-Abbrev}\\t${Version}\\n", "cups-browsed"): CommandResult(
                1, "", "dpkg-query: no packages found matching cups-browsed\n"
            ),
            ("dpkg-query", "-W", "-f=${db:Status-Abbrev}\\t${Version}\\n", "openssh-server"): CommandResult(
                0, "ii \t1:9.6p1-3ubuntu13\n", ""
            ),
            ("dpkg", "--compare-versions", "1:9.6p1-3ubuntu13", "lt", "1:9.6p1-3ubuntu13.3"): CommandResult(
                0, "", ""
            ),
            ("ps", "-eo", "comm,args", "--no-headers"): CommandResult(
                0, "sshd /usr/sbin/sshd -D\nnginx nginx: master process\n", ""
            ),
            ("cat", "/etc/ssh/sshd_config"): CommandResult(0, "PermitRootLogin no\nLoginGraceTime 120\n", ""),
            ("apt-cache", "policy", "linux-image-generic"): CommandResult(
                0,
                "linux-image-generic:\n  Installed: 6.8.0-40.40\n  Candidate: 6.8.0-45.45\n"
                "  Version table:\n     6.8.0-45.45 500\n"
                "        500 http://archive.ubuntu.com/ubuntu noble-proposed/main amd64 Packages\n",
                "",
            ),
            ("dpkg", "--compare-versions", "6.8.0-45.45", "ge", "6.8.0-45.45"): CommandResult(0, "", ""),
            ("ss", "-tulpnH"): CommandResult(
                0,
                "tcp LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:((\"nginx\",pid=900,fd=6))\n"
                "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=850,fd=3))\n",
                "",
            ),
            ("ufw", "status", "verbose"): CommandResult(
                0,
                "Status: active\nDefault: deny (incoming)\n443/tcp ALLOW IN Anywhere\n",
                "",
            ),
        },
    )
    patched_db = MockRunner(
        host_name="prod-db-01",
        responses={
            ("uname", "-r"): CommandResult(0, "6.8.0-45-generic\n", ""),
            ("dpkg", "--compare-versions", "6.8.0-45", "lt", "4.4.0"): CommandResult(1, "", ""),
            ("dpkg", "--compare-versions", "6.8.0-45", "lt", "6.8.0-45"): CommandResult(1, "", ""),
            ("dpkg", "--compare-versions", "6.8.0-45", "lt", "6.2.0-21"): CommandResult(1, "", ""),
            ("cat", "/proc/modules"): CommandResult(0, "tls 163840 0 - Live 0x0\n", ""),
            ("dpkg-query", "-W", "-f=${db:Status-Abbrev}\\t${Version}\\n", "cups-browsed"): CommandResult(
                1, "", "dpkg-query: no packages found matching cups-browsed\n"
            ),
            ("dpkg-query", "-W", "-f=${db:Status-Abbrev}\\t${Version}\\n", "openssh-server"): CommandResult(
                0, "ii \t1:9.6p1-3ubuntu13.4\n", ""
            ),
            ("dpkg", "--compare-versions", "1:9.6p1-3ubuntu13.4", "lt", "1:9.6p1-3ubuntu13.3"): CommandResult(
                1, "", ""
            ),
            ("ps", "-eo", "comm,args", "--no-headers"): CommandResult(0, "sshd /usr/sbin/sshd -D\n", ""),
            ("cat", "/etc/ssh/sshd_config"): CommandResult(0, "LoginGraceTime 0\n", ""),
            ("ss", "-tulpnH"): CommandResult(
                0,
                "tcp LISTEN 0 128 0.0.0.0:5432 0.0.0.0:*\n",
                "",
            ),
            ("ufw", "status", "verbose"): CommandResult(0, "Status: inactive\n", ""),
        },
    )
    ps_kb_cmd = (
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "$cv = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'; "
        "$build = \"$($cv.CurrentBuildNumber).$($cv.UBR)\"; "
        "$kbs = @(Get-HotFix -ErrorAction SilentlyContinue | Select-Object -ExpandProperty HotFixID) -join ','; "
        "Write-Output \"BUILD=$build|KBS=$kbs\"",
    )
    ps_reg_ipv6 = (
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters' "
        "-Name 'DisabledComponents' -ErrorAction Stop).'DisabledComponents'",
    )
    ps_svc_spooler = (
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "(Get-Service -Name 'Spooler' -ErrorAction Stop).Status",
    )
    win_dc = MockRunner(
        host_name="win-dc-01",
        os_family="windows",
        responses={
            ps_kb_cmd: CommandResult(0, "BUILD=20348.2402|KBS=KB5039217\n", ""),
            ps_reg_ipv6: CommandResult(0, "0\n", ""),
            ps_svc_spooler: CommandResult(0, "Running\n", ""),
        },
    )
    win_filesrv = MockRunner(
        host_name="win-filesrv-02",
        os_family="windows",
        responses={
            ps_kb_cmd: CommandResult(0, "BUILD=20348.2402|KBS=KB5039217\n", ""),
            ps_reg_ipv6: CommandResult(0, "255\n", ""),
            ps_svc_spooler: CommandResult(0, "Stopped\n", ""),
        },
    )
    return [laptop, edge_server, patched_db, win_dc, win_filesrv]


def load_runners(
    host: str | None = None,
    ssh_targets: list[str] | None = None,
    win_ssh_targets: list[str] | None = None,
    docker_targets: list[str] | None = None,
    win_docker_targets: list[str] | None = None,
    k8s_targets: list[str] | None = None,
    inventory_path: Path | None = None,
    timeout: int = 10,
) -> list[HostRunner]:
    """Build a list of HostRunners from CLI flags or a YAML/plain inventory file."""
    runners: list[HostRunner] = []

    if inventory_path is not None:
        raw = inventory_path.read_text(encoding="utf-8")
        try:
            parsed = yaml.safe_load(raw)
        except Exception:
            parsed = None

        if isinstance(parsed, dict) and isinstance(parsed.get("hosts"), list):
            for entry in parsed["hosts"]:
                if isinstance(entry, str):
                    if entry in ("local", "localhost"):
                        runners.append(LocalRunner(timeout=timeout))
                    else:
                        runners.append(SSHRunner(target=entry, timeout=timeout))
                elif isinstance(entry, dict):
                    name = str(
                        entry.get("name")
                        or entry.get("ssh")
                        or entry.get("docker")
                        or entry.get("k8s")
                        or entry.get("host")
                        or "host"
                    )
                    etype = str(entry.get("type") or "").lower()
                    os_family = str(entry.get("os") or entry.get("os_family") or "linux").lower()
                    if os_family not in ("linux", "windows"):
                        raise ValueError(
                            f"Unsupported OS family in inventory for {name}: {os_family!r} (expected 'linux' or 'windows')"
                        )
                    ssh_dest = entry.get("ssh") or entry.get("host")
                    docker_dest = entry.get("docker")
                    k8s_dest = entry.get("k8s")
                    port: int | None = None
                    if entry.get("port") is not None:
                        try:
                            port = int(entry["port"])
                        except (ValueError, TypeError) as exc:
                            raise ValueError(
                                f"Invalid SSH port in inventory for {name}: {entry['port']!r}"
                            ) from exc
                    if etype == "local" or ssh_dest in ("local", "localhost"):
                        runners.append(
                            LocalRunner(host_name=name, timeout=timeout, os_family=os_family)
                        )
                    elif docker_dest:
                        runners.append(
                            DockerRunner(
                                container=str(docker_dest),
                                host_name=name,
                                timeout=timeout,
                                os_family=os_family,
                            )
                        )
                    elif k8s_dest:
                        runners.append(
                            K8sRunner(
                                pod=str(k8s_dest),
                                namespace=entry.get("namespace"),
                                container=entry.get("container"),
                                host_name=name,
                                timeout=timeout,
                                os_family=os_family,
                            )
                        )
                    elif ssh_dest:
                        runners.append(
                            SSHRunner(
                                target=str(ssh_dest),
                                host_name=name,
                                timeout=timeout,
                                port=port,
                                os_family=os_family,
                            )
                        )
        else:
            # Fallback line-by-line inventory (ignores comments and [group] headers)
            for line in raw.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or stripped.startswith("["):
                    continue
                token = stripped.split()[0]
                if token in ("local", "localhost"):
                    runners.append(LocalRunner(timeout=timeout))
                else:
                    runners.append(SSHRunner(target=token, timeout=timeout))

    if ssh_targets:
        for target in ssh_targets:
            runners.append(SSHRunner(target=target, timeout=timeout))

    if win_ssh_targets:
        for target in win_ssh_targets:
            runners.append(SSHRunner(target=target, timeout=timeout, os_family="windows"))

    if docker_targets:
        for container in docker_targets:
            runners.append(DockerRunner(container=container, timeout=timeout))

    if win_docker_targets:
        for container in win_docker_targets:
            runners.append(DockerRunner(container=container, timeout=timeout, os_family="windows"))

    if k8s_targets:
        for pod_spec in k8s_targets:
            runners.append(K8sRunner(pod=pod_spec, timeout=timeout))

    if host:
        if host in ("local", "localhost"):
            runners.append(LocalRunner(timeout=timeout))
        else:
            runners.append(SSHRunner(target=host, timeout=timeout))

    if not runners:
        runners.append(LocalRunner(timeout=timeout))

    return runners
