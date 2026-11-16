"""Tests for deterministic read-only probes and host transport (Task 2)."""

from notaffected.model import Precondition, ProbeStatus, VexJustification
from notaffected.probes.primitives import run_probe
from notaffected.probes.runner import CommandResult, LocalRunner, MockRunner


def test_kernel_module_loaded_met_and_not_met():
    proc_modules = "nf_tables 327680 12 - Live 0x0000000000000000\ntls 163840 0 - Live 0x0000000000000000\n"
    runner = MockRunner(
        host_name="node-01",
        responses={
            ("cat", "/proc/modules"): CommandResult(0, proc_modules, ""),
        },
    )
    pre_met = Precondition(
        probe="kernel_module_loaded",
        params={"module": "nf_tables"},
        description="nf_tables module loaded",
    )
    res_met = run_probe(pre_met, runner)
    assert res_met.status == ProbeStatus.MET
    assert "nf_tables" in res_met.evidence

    pre_not_met = Precondition(
        probe="kernel_module_loaded",
        params={"module": "ksmbd"},
        description="ksmbd module loaded",
    )
    res_not_met = run_probe(pre_not_met, runner)
    assert res_not_met.status == ProbeStatus.NOT_MET
    assert "not loaded" in res_not_met.evidence


def test_sysctl_equals_met_not_met_and_unknown():
    runner = MockRunner(
        host_name="node-01",
        responses={
            ("sysctl", "-n", "kernel.unprivileged_userns_clone"): CommandResult(0, "1\n", ""),
            ("sysctl", "-n", "net.mptcp.enabled"): CommandResult(0, "0\n", ""),
            ("sysctl", "-n", "kernel.missing_key"): CommandResult(255, "", "sysctl: cannot stat"),
        },
    )
    p1 = Precondition("sysctl_equals", {"key": "kernel.unprivileged_userns_clone", "value": "1"}, "userns enabled")
    assert run_probe(p1, runner).status == ProbeStatus.MET

    p2 = Precondition("sysctl_equals", {"key": "net.mptcp.enabled", "value": "1"}, "mptcp enabled")
    assert run_probe(p2, runner).status == ProbeStatus.NOT_MET

    p3 = Precondition("sysctl_equals", {"key": "kernel.missing_key", "value": "1"}, "missing sysctl")
    assert run_probe(p3, runner).status == ProbeStatus.UNKNOWN


def test_network_listener_loopback_vs_public():
    # Loopback-only host (including %lo scope suffix and IPv6 ::1)
    ss_loopback_only = (
        "udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\n"
        "tcp LISTEN 0 4096 127.0.0.1:631 0.0.0.0:* users:((\"cupsd\",pid=912,fd=7))\n"
        "tcp LISTEN 0 4096 [::1]:631 [::]:* users:((\"cupsd\",pid=912,fd=6))\n"
    )
    runner_local = MockRunner(
        host_name="laptop-01",
        responses={("ss", "-tulpnH"): CommandResult(0, ss_loopback_only, "")},
    )
    pre_any_tcp = Precondition(
        probe="network_listener",
        params={"proto": "tcp", "scope": "non_loopback"},
        description="Any non-loopback TCP listener",
    )
    res_local = run_probe(pre_any_tcp, runner_local)
    assert res_local.status == ProbeStatus.NOT_MET
    assert "only loopback" in res_local.evidence.lower() or "no non-loopback" in res_local.evidence.lower()

    # Public listener host (0.0.0.0:443 and *:22)
    ss_public = (
        "udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\n"
        "tcp LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:((\"nginx\",pid=1024,fd=6))\n"
        "udp UNCONN 0 0 0.0.0.0:631 0.0.0.0:* users:((\"cups-browsed\",pid=1100,fd=8))\n"
    )
    runner_pub = MockRunner(
        host_name="edge-01",
        responses={("ss", "-tulpnH"): CommandResult(0, ss_public, "")},
    )
    res_pub = run_probe(pre_any_tcp, runner_pub)
    assert res_pub.status == ProbeStatus.MET
    assert "0.0.0.0:443" in res_pub.evidence

    pre_cups_udp = Precondition(
        probe="network_listener",
        params={"proto": "udp", "port": 631, "scope": "non_loopback"},
        description="UDP 631 non-loopback listener",
    )
    assert run_probe(pre_cups_udp, runner_pub).status == ProbeStatus.MET
    assert run_probe(pre_cups_udp, runner_local).status == ProbeStatus.NOT_MET


def test_package_probe_distinguishes_absent_from_ssh_failure():
    runner_absent = MockRunner(
        host_name="clean-host",
        responses={
            ("dpkg-query", "-W", "-f=${db:Status-Abbrev}\\t${Version}\\n", "cups-browsed"): CommandResult(
                1, "", "dpkg-query: no packages found matching cups-browsed\n"
            ),
        },
    )
    pre = Precondition(
        probe="package_installed_vulnerable",
        params={"package": "cups-browsed", "fixed_version": "2.0.0-0ubuntu10.2"},
        description="cups-browsed installed and < 2.0.0-0ubuntu10.2",
        justification_if_not_met=VexJustification.COMPONENT_NOT_PRESENT,
    )
    res_absent = run_probe(pre, runner_absent)
    assert res_absent.status == ProbeStatus.NOT_MET
    assert "not installed" in res_absent.evidence.lower()

    # Transport failure (e.g. SSH connection refused / timeout)
    runner_ssh_err = MockRunner(
        host_name="unreachable-host",
        responses={
            ("dpkg-query", "-W", "-f=${db:Status-Abbrev}\\t${Version}\\n", "cups-browsed"): CommandResult(
                255, "", "ssh: connect to host unreachable-host port 22: Connection timed out", transport_error=True
            ),
        },
    )
    res_ssh_err = run_probe(pre, runner_ssh_err)
    assert res_ssh_err.status == ProbeStatus.UNKNOWN


def test_firewall_probe_permission_denied_yields_unknown():
    runner_perm = MockRunner(
        host_name="restricted-host",
        responses={
            ("ufw", "status"): CommandResult(1, "", "ERROR: You need to be root to run this script"),
            ("nft", "list", "tables"): CommandResult(1, "", "Operation not permitted"),
        },
    )
    pre = Precondition(
        probe="firewall_allows_port",
        params={"port": "any", "proto": "tcp"},
        description="Host firewall allows incoming TCP connections",
    )
    res = run_probe(pre, runner_perm)
    assert res.status == ProbeStatus.UNKNOWN

    # Active UFW blocking incoming by default with no rules allowing external access
    ufw_blocking = "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n"
    runner_ufw_block = MockRunner(
        host_name="laptop-ufw",
        responses={
            ("ufw", "status", "verbose"): CommandResult(0, ufw_blocking, ""),
        },
    )
    res_block = run_probe(pre, runner_ufw_block)
    assert res_block.status == ProbeStatus.NOT_MET
    assert "deny (incoming)" in res_block.evidence


def test_kernel_version_and_systemd_probes():
    runner = MockRunner(
        host_name="srv-01",
        responses={
            ("uname", "-r"): CommandResult(0, "6.8.0-40-generic\n", ""),
            ("dpkg", "--compare-versions", "6.8.0-40", "lt", "6.8.0-45"): CommandResult(0, "", ""),
            ("systemctl", "is-active", "cups-browsed.service"): CommandResult(3, "inactive\n", ""),
        },
    )
    pre_kern = Precondition(
        probe="kernel_version_vulnerable",
        params={"fixed_version": "6.8.0-45"},
        description="Kernel < 6.8.0-45",
    )
    assert run_probe(pre_kern, runner).status == ProbeStatus.MET

    pre_svc = Precondition(
        probe="systemd_service_active",
        params={"service": "cups-browsed.service"},
        description="cups-browsed.service is active",
    )
    assert run_probe(pre_svc, runner).status == ProbeStatus.NOT_MET


def test_local_runner_executes_uname():
    local = LocalRunner()
    res = local.run(["uname", "-s"])
    assert res.returncode == 0
    assert "Linux" in res.stdout


def test_review_fixes_dpkg_error_ufw_allow_and_invalid_port():
    # 1. dpkg --compare-versions exit code 2 (syntax error) must yield UNKNOWN, not NOT_MET
    runner_dpkg_err = MockRunner(
        host_name="bad-ver-host",
        responses={
            ("dpkg-query", "-W", "-f=${db:Status-Abbrev}\\t${Version}\\n", "openssl"): CommandResult(
                0, "ii \t3.0.2-0ubuntu1\n", ""
            ),
            ("dpkg", "--compare-versions", "3.0.2-0ubuntu1", "lt", "~~bad$$"): CommandResult(
                2, "", "dpkg: warning: version '~~bad$$' has bad syntax"
            ),
        },
    )
    pre_pkg = Precondition(
        probe="package_installed_vulnerable",
        params={"package": "openssl", "fixed_version": "~~bad$$"},
        description="openssl check",
    )
    assert run_probe(pre_pkg, runner_dpkg_err).status == ProbeStatus.UNKNOWN

    # 2. ufw active with Default: allow (incoming) and no explicit rule lines -> MET
    runner_ufw_allow = MockRunner(
        host_name="open-ufw",
        responses={
            ("ufw", "status", "verbose"): CommandResult(
                0,
                "Status: active\nDefault: allow (incoming), deny (outgoing), disabled (routed)\n",
                "",
            )
        },
    )
    pre_fw = Precondition(
        probe="firewall_allows_port",
        params={"port": "any", "proto": "tcp"},
        description="firewall allows tcp",
    )
    assert run_probe(pre_fw, runner_ufw_allow).status == ProbeStatus.MET

    # 3. Invalid non-numeric port parameter in network_listener -> UNKNOWN
    runner_ss = MockRunner(
        host_name="ss-host",
        responses={
            ("ss", "-tulpnH"): CommandResult(0, "tcp LISTEN 0 128 0.0.0.0:80 0.0.0.0:*\n", ""),
        },
    )
    pre_bad_port = Precondition(
        probe="network_listener",
        params={"proto": "tcp", "port": "http_invalid", "scope": "non_loopback"},
        description="invalid port",
    )
    assert run_probe(pre_bad_port, runner_ss).status == ProbeStatus.UNKNOWN


def test_docker_and_k8s_runner_transport_errors(monkeypatch):
    import subprocess

    from notaffected.probes.runner import DockerRunner, K8sRunner

    def fake_run_missing_container(argv, **kwargs):
        return subprocess.CompletedProcess(
            args=argv,
            returncode=1,
            stdout="",
            stderr="Error response from daemon: No such container: ghost-container",
        )

    monkeypatch.setattr(subprocess, "run", fake_run_missing_container)
    d_runner = DockerRunner(container="ghost-container")
    d_res = d_runner.run(["uname", "-r"])
    assert d_res.transport_error is True

    def fake_run_missing_pod(argv, **kwargs):
        return subprocess.CompletedProcess(
            args=argv,
            returncode=1,
            stdout="",
            stderr='Error from server (NotFound): pods "ghost-pod" not found',
        )

    monkeypatch.setattr(subprocess, "run", fake_run_missing_pod)
    k_runner = K8sRunner(pod="ghost-pod", namespace="prod")
    k_res = k_runner.run(["uname", "-r"])
    assert k_res.transport_error is True

    # Lowercase `error: ...` from kubectl exec (returncode 1) + option injection guard (`-` prefix)
    def fake_run_kubectl_completed_pod(argv, **kwargs):
        return subprocess.CompletedProcess(
            args=argv,
            returncode=1,
            stdout="",
            stderr="error: cannot exec into a container in a completed pod; current phase is Succeeded",
        )

    monkeypatch.setattr(subprocess, "run", fake_run_kubectl_completed_pod)
    k_res2 = k_runner.run(["dpkg-query", "-W", "openssl"])
    assert k_res2.transport_error is True

    bad_k8s = K8sRunner(pod="--kubeconfig=/tmp/evil")
    assert bad_k8s.run(["uname", "-r"]).transport_error is True


def test_runner_caches_identical_commands(monkeypatch):
    import subprocess

    call_count = 0

    def counting_run(argv, **kwargs):
        nonlocal call_count
        call_count += 1
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="6.8.0-45-generic\n", stderr="")

    monkeypatch.setattr(subprocess, "run", counting_run)
    runner = LocalRunner(host_name="cache-test")
    r1 = runner.run(["uname", "-r"])
    r2 = runner.run(["uname", "-r"])
    r3 = runner.run(["uname", "-r"])
    assert r1.stdout == r2.stdout == r3.stdout == "6.8.0-45-generic\n"
    assert call_count == 1


def test_config_contains_and_process_running_probes():
    ps_output = (
        "systemd         /sbin/init\n"
        "sshd            sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups\n"
        "nginx           nginx: master process /usr/sbin/nginx\n"
    )
    sshd_config_commented = (
        "# OpenSSH server config\n"
        "#PermitRootLogin yes\n"
        "LoginGraceTime 0\n"
    )
    sshd_config_vulnerable = (
        "# OpenSSH server config\n"
        "PermitRootLogin yes\n"
        "LoginGraceTime 120\n"
    )
    runner = MockRunner(
        host_name="app-node",
        responses={
            ("ps", "-eo", "comm,args", "--no-headers"): CommandResult(0, ps_output, ""),
            ("cat", "/etc/ssh/sshd_config"): CommandResult(0, sshd_config_commented, ""),
            ("cat", "/etc/ssh/sshd_config_vuln"): CommandResult(0, sshd_config_vulnerable, ""),
            ("cat", "/etc/shadow"): CommandResult(1, "", "cat: /etc/shadow: Permission denied"),
        },
    )

    # 1. process_running
    p_sshd = Precondition("process_running", {"process": "sshd"}, "sshd process running")
    assert run_probe(p_sshd, runner).status == ProbeStatus.MET

    p_redis = Precondition("process_running", {"process": "redis-server"}, "redis running")
    assert run_probe(p_redis, runner).status == ProbeStatus.NOT_MET

    # 2. config_contains ignores commented-out `#PermitRootLogin yes`
    p_root_login = Precondition(
        "config_contains",
        {"path": "/etc/ssh/sshd_config", "pattern": r"^\s*PermitRootLogin\s+yes\b"},
        "PermitRootLogin enabled",
    )
    assert run_probe(p_root_login, runner).status == ProbeStatus.NOT_MET

    p_root_vuln = Precondition(
        "config_contains",
        {"path": "/etc/ssh/sshd_config_vuln", "pattern": r"^\s*PermitRootLogin\s+yes\b"},
        "PermitRootLogin enabled",
    )
    assert run_probe(p_root_vuln, runner).status == ProbeStatus.MET

    # 3. config_contains with `negate=True` (e.g. LoginGraceTime 0 mitigates CVE-2024-6387)
    p_grace = Precondition(
        "config_contains",
        {"path": "/etc/ssh/sshd_config", "pattern": r"^\s*LoginGraceTime\s+0\b", "negate": True},
        "LoginGraceTime is not set to 0",
        justification_if_not_met=VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST,
    )
    assert run_probe(p_grace, runner).status == ProbeStatus.NOT_MET

    # 4. Path traversal or disallowed directory -> UNKNOWN
    p_traversal = Precondition(
        "config_contains",
        {"path": "/etc/../root/.bashrc", "pattern": "export"},
        "traversal attempt",
    )
    assert run_probe(p_traversal, runner).status == ProbeStatus.UNKNOWN

    # 5. Permission denied -> UNKNOWN (never NOT_MET)
    p_perm = Precondition(
        "config_contains",
        {"path": "/etc/shadow", "pattern": "root"},
        "unreadable config",
    )
    assert run_probe(p_perm, runner).status == ProbeStatus.UNKNOWN

    # 6. String "false" for negate and inline `#` comment stripping
    sshd_inline_comment = "PermitRootLogin no # PermitRootLogin yes\n"
    runner_inline = MockRunner(
        host_name="inline-node",
        responses={("cat", "/etc/ssh/sshd_config"): CommandResult(0, sshd_inline_comment, "")},
    )
    p_inline = Precondition(
        "config_contains",
        {"path": "/etc/ssh/sshd_config", "pattern": r"PermitRootLogin\s+yes", "negate": "false"},
        "inline comment should not match",
    )
    assert run_probe(p_inline, runner_inline).status == ProbeStatus.NOT_MET



def test_live_apt_policy_patch_tracker():
    from notaffected.advisories.builtin_specs import BUILTIN_SPECS
    from notaffected.probes.patch_tracker import resolve_host_patch_info

    cups_spec = BUILTIN_SPECS["CVE-2024-47176"]
    apt_policy_ready = (
        "cups-browsed:\n"
        "  Installed: 2.0.0-0ubuntu10.1\n"
        "  Candidate: 2.0.0-0ubuntu10.3\n"
        "  Version table:\n"
        "     2.0.0-0ubuntu10.3 500\n"
        "        500 http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages\n"
        " *** 2.0.0-0ubuntu10.1 100\n"
        "        100 /var/lib/dpkg/status\n"
    )
    runner_ready = MockRunner(
        host_name="srv-ready",
        responses={
            ("apt-cache", "policy", "cups-browsed"): CommandResult(0, apt_policy_ready, ""),
            ("dpkg", "--compare-versions", "2.0.0-0ubuntu10.3", "ge", "2.0.0-0ubuntu10.2"): CommandResult(0, "", ""),
        },
    )
    patch_ready = resolve_host_patch_info(cups_spec, runner_ready)
    assert "available-in-apt" in patch_ready.status
    assert "2.0.0-0ubuntu10.3" in patch_ready.status
    assert patch_ready.pocket == "noble-security"

    # Candidate is still older than fixed_version (e.g. fix is in -proposed, not enabled on host)
    # Also verify that an unpinned -backports stanza above the Candidate stanza does not hijack pocket
    kern_spec = BUILTIN_SPECS["CVE-2026-98432"]
    apt_policy_multi_stanza = (
        "linux-image-generic:\n"
        "  Installed: 6.8.0-40.40\n"
        "  Candidate: 6.8.0-45.45\n"
        "  Version table:\n"
        "     6.8.0-99.99 100\n"
        "        100 http://archive.ubuntu.com/ubuntu noble-backports/main amd64 Packages\n"
        "     6.8.0-45.45 500\n"
        "        500 http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages\n"
        " *** 6.8.0-40.40 500\n"
        "        500 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages\n"
    )
    runner_stanza = MockRunner(
        host_name="srv-stanza",
        responses={
            ("apt-cache", "policy", "linux-image-generic"): CommandResult(0, apt_policy_multi_stanza, ""),
            ("dpkg", "--compare-versions", "6.8.0-45.45", "ge", "6.8.0-45.45"): CommandResult(0, "", ""),
        },
    )
    patch_stanza = resolve_host_patch_info(kern_spec, runner_stanza)
    assert patch_stanza.pocket == "noble-security"
    apt_policy_pending = (
        "linux-image-generic:\n"
        "  Installed: 6.8.0-40.40\n"
        "  Candidate: 6.8.0-40.40\n"
        "  Version table:\n"
        " *** 6.8.0-40.40 500\n"
        "        500 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages\n"
    )
    runner_pending = MockRunner(
        host_name="srv-pending",
        responses={
            ("apt-cache", "policy", "linux-image-generic"): CommandResult(0, apt_policy_pending, ""),
            ("dpkg", "--compare-versions", "6.8.0-40.40", "ge", "6.8.0-45.45"): CommandResult(1, "", ""),
        },
    )
    patch_pending = resolve_host_patch_info(kern_spec, runner_pending)
    assert "not-yet-in-apt" in patch_pending.status


def test_windows_probes_build_registry_and_service():
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

    # 1. Vulnerable Windows Server: unpatched build 20348.2402, missing KB5041585, IPv6 enabled (0), Spooler Running
    win_vuln = MockRunner(
        host_name="win-dc-01",
        os_family="windows",
        responses={
            ps_kb_cmd: CommandResult(0, "BUILD=20348.2402|KBS=KB5039217,KB5040437\n", ""),
            ps_reg_ipv6: CommandResult(0, "0\n", ""),
            ps_svc_spooler: CommandResult(0, "Running\n", ""),
        },
    )
    p_kb = Precondition(
        "windows_build_vulnerable",
        {"kb": "KB5041585", "fixed_build": "20348.2655"},
        "Missing KB5041585 and build < 20348.2655",
    )
    assert run_probe(p_kb, win_vuln).status == ProbeStatus.MET

    p_reg = Precondition(
        "windows_registry_equals",
        {
            "path": r"HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters",
            "name": "DisabledComponents",
            "value": "255",
            "negate": True,
        },
        "IPv6 DisabledComponents is not set to 0xff (255)",
    )
    assert run_probe(p_reg, win_vuln).status == ProbeStatus.MET

    p_svc = Precondition(
        "windows_service_active",
        {"service": "Spooler"},
        "Print Spooler service is running",
    )
    assert run_probe(p_svc, win_vuln).status == ProbeStatus.MET

    # 2. Mitigated/Patched Windows Server: KB5041585 installed OR DisabledComponents=255, Spooler Stopped
    win_safe = MockRunner(
        host_name="win-safe-02",
        os_family="windows",
        responses={
            ps_kb_cmd: CommandResult(0, "BUILD=20348.2655|KBS=KB5041585\n", ""),
            ps_reg_ipv6: CommandResult(0, "255\n", ""),
            ps_svc_spooler: CommandResult(0, "Stopped\n", ""),
        },
    )
    assert run_probe(p_kb, win_safe).status == ProbeStatus.NOT_MET
    assert run_probe(p_reg, win_safe).status == ProbeStatus.NOT_MET
    assert run_probe(p_svc, win_safe).status == ProbeStatus.NOT_MET

    # 3. Injection attempt in registry path (including Unicode curly quotes) -> UNKNOWN
    p_inj = Precondition(
        "windows_registry_equals",
        {"path": "HKLM:\\Software; Stop-Computer", "name": "Foo", "value": "1"},
        "injection test",
    )
    assert run_probe(p_inj, win_vuln).status == ProbeStatus.UNKNOWN

    p_unicode_inj = Precondition(
        "windows_registry_equals",
        {"path": "HKLM:\\Software\u2019 -or (Restart-Computer)", "name": "Foo", "value": "1"},
        "unicode quote injection test",
    )
    assert run_probe(p_unicode_inj, win_vuln).status == ProbeStatus.UNKNOWN

    # 4. Cross-major OS build without matching KB -> UNKNOWN (never false NOT_MET)
    win_different_branch = MockRunner(
        host_name="win11-01",
        os_family="windows",
        responses={
            ps_kb_cmd: CommandResult(0, "BUILD=22621.100|KBS=KB5000001\n", ""),
        },
    )
    assert run_probe(p_kb, win_different_branch).status == ProbeStatus.UNKNOWN

    # 5. Windows process_running (.exe normalization)
    ps_proc_cmd = (
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "Get-Process | Select-Object -ExpandProperty ProcessName",
    )
    win_proc_runner = MockRunner(
        host_name="win-proc-01",
        os_family="windows",
        responses={ps_proc_cmd: CommandResult(0, "System\nspoolsv\nlsass\n", "")},
    )
    p_win_proc = Precondition("process_running", {"process": "spoolsv.exe"}, "spoolsv running")
    assert run_probe(p_win_proc, win_proc_runner).status == ProbeStatus.MET


def test_package_installed_source_package_fallback() -> None:
    dpkg_src_cmd = (
        "dpkg-query",
        "-W",
        "-f=${db:Status-Abbrev}\\t${binary:Package}\\t${source:Package}\\t${Version}\\t${source:Version}\\n",
    )
    runner = MockRunner(
        host_name="ubuntu-node",
        simulate_dpkg_db=True,
        responses={
            dpkg_src_cmd: CommandResult(
                0,
                "ii \tlibc6\tglibc\t2.39-0ubuntu8.12\t2.39-0ubuntu8.12\n",
                "",
            ),
            ("dpkg", "--compare-versions", "2.39-0ubuntu8.12", "lt", "2.38-1ubuntu6"): CommandResult(1, "", ""),
        },
    )
    pre = Precondition(
        "package_installed_vulnerable",
        {"package": "glibc", "fixed_version": "2.38-1ubuntu6"},
        "glibc vulnerable",
    )
    res = run_probe(pre, runner)
    assert res.status == ProbeStatus.NOT_MET
    assert "glibc (binary: libc6)" in res.evidence
    assert "2.39-0ubuntu8.12" in res.evidence









