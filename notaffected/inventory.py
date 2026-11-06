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
            ("ss", "-tulpnH"): CommandResult(
                0,
                "tcp LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:((\"nginx\",pid=900,fd=6))\n",
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
            ("ss", "-tulpnH"): CommandResult(
                0,
                "tcp LISTEN 0 128 0.0.0.0:5432 0.0.0.0:*\n",
                "",
            ),
            ("ufw", "status", "verbose"): CommandResult(0, "Status: inactive\n", ""),
        },
    )
    return [laptop, edge_server, patched_db]


def load_runners(
    host: str | None = None,
    ssh_targets: list[str] | None = None,
    docker_targets: list[str] | None = None,
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
                        runners.append(LocalRunner(host_name=name, timeout=timeout))
                    elif docker_dest:
                        runners.append(
                            DockerRunner(
                                container=str(docker_dest),
                                host_name=name,
                                timeout=timeout,
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
                            )
                        )
                    elif ssh_dest:
                        runners.append(
                            SSHRunner(
                                target=str(ssh_dest),
                                host_name=name,
                                timeout=timeout,
                                port=port,
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

    if docker_targets:
        for container in docker_targets:
            runners.append(DockerRunner(container=container, timeout=timeout))

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
