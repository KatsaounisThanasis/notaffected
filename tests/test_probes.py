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
            # not loaded is proof only when the module is blocked from loading
            ("modprobe", "-c"): CommandResult(0, "blacklist floppy\ninstall ksmbd /bin/false\n", ""),
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
    assert "not loaded" in res_not_met.evidence and "blocked" in res_not_met.evidence


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
            # the full listing answers on a real dpkg host; nothing builds from a 'cups-browsed' source
            (
                "dpkg-query",
                "-W",
                "-f=${db:Status-Abbrev}\\t${binary:Package}\\t${source:Package}\\t${Version}\\t${source:Version}\\n",
            ): CommandResult(0, "", ""),
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
            ("ip", "-o", "link", "show", "docker0"): CommandResult(1, "", 'Device "docker0" does not exist.\n'),
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
            ("systemctl", "show", "-p", "LoadState", "--value", "cups-browsed.service"): CommandResult(
                0, "loaded\n", ""
            ),
            ("systemctl", "is-active", "cups-browsed.socket"): CommandResult(3, "inactive\n", ""),
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
            ("cat", "/etc/os-release"): CommandResult(0, 'ID=ubuntu\nVERSION_ID="24.04"\n', ""),
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











def _pkg_pre(fixed: str = "") -> Precondition:
    return Precondition("package_installed_vulnerable", {"package": "openssh-server", "fixed_version": fixed}, "pkg")


def _dpkg_q(status_ver: str) -> dict:
    return {
        ("dpkg-query", "-W", "-f=${db:Status-Abbrev}\\t${Version}\\n", "openssh-server"): CommandResult(
            0, status_ver, ""
        )
    }


def test_dpkg_status_abbrev_second_char_decides_installed():
    # held package (hi) is installed and vulnerable
    resp = _dpkg_q("hi \t1:9.6p1-3ubuntu13\n")
    resp[("dpkg", "--compare-versions", "1:9.6p1-3ubuntu13", "lt", "1:9.6p1-3ubuntu13.3")] = CommandResult(0, "", "")
    res = run_probe(_pkg_pre("1:9.6p1-3ubuntu13.3"), MockRunner("h", resp))
    assert res.status == ProbeStatus.MET, res.evidence
    # unpacked but not configured (iU) still has the files on disk
    assert run_probe(_pkg_pre(), MockRunner("h", _dpkg_q("iU \t1:9.6p1-3ubuntu13\n"))).status == ProbeStatus.MET
    # removed, config files only (rc) is absent
    assert run_probe(_pkg_pre(), MockRunner("h", _dpkg_q("rc \t1:9.6p1-3ubuntu13\n"))).status == ProbeStatus.NOT_MET


def test_version_comparison_never_guesses():
    # dpkg rejects the version with a warning (rc 1): unreadable, not "patched"
    kpre = Precondition("kernel_version_vulnerable", {"fixed_version": "6.8.0-45"}, "k")
    runner = MockRunner(
        "h",
        {
            ("uname", "-r"): CommandResult(0, "abc\n", ""),
            ("dpkg", "--compare-versions", "abc", "lt", "6.8.0-45"): CommandResult(
                1, "", "dpkg: warning: version 'abc' has bad syntax: version number does not start with digit\n"
            ),
        },
    )
    assert run_probe(kpre, runner).status == ProbeStatus.UNKNOWN

    # rpm host (no dpkg-query, no dpkg): no digit-list fallback, so UNKNOWN
    rpm_runner = MockRunner(
        "rhel9",
        {("rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}\\n", "openssh-server"): CommandResult(0, "8.7p1-38.el9\n", "")},
    )
    res = run_probe(_pkg_pre("1:9.6p1-3ubuntu13.3"), rpm_runner)
    assert res.status == ProbeStatus.UNKNOWN, res.evidence

    # apk comparator fails: UNKNOWN instead of a digit-list guess
    apk_runner = MockRunner(
        "alpine",
        {
            ("apk", "info", "-e", "-v", "openssh-server"): CommandResult(0, "openssh-server-9.7_p1-r3\n", ""),
            ("apk", "version", "-t", "9.7_p1-r3", "9.7_p1-r4"): CommandResult(1, "", "apk: error\n"),
        },
    )
    res = run_probe(_pkg_pre("9.7_p1-r4"), apk_runner)
    assert res.status == ProbeStatus.UNKNOWN, res.evidence


def _rel_runner(os_release: str, dpkg_line: str | None) -> MockRunner:
    resp = {("cat", "/etc/os-release"): CommandResult(0, os_release, "")}
    q = ("dpkg-query", "-W", "-f=${db:Status-Abbrev}\\t${Version}\\n", "libfoo")
    resp[q] = CommandResult(0, dpkg_line, "") if dpkg_line else CommandResult(1, "", "dpkg-query: no packages found matching libfoo\n")
    if not dpkg_line:
        resp[
            (
                "dpkg-query",
                "-W",
                "-f=${db:Status-Abbrev}\\t${binary:Package}\\t${source:Package}\\t${Version}\\t${source:Version}\\n",
            )
        ] = CommandResult(0, "", "")
    return MockRunner("h", resp)


def test_release_fixes_never_borrow_another_release_fix():
    fixes = {"ubuntu:22.04": "1.2.0-1ubuntu0.22.04.1", "ubuntu:24.04": ""}
    pre = Precondition(
        "package_installed_vulnerable",
        {"package": "libfoo", "fixed_version": "1.2.0-1ubuntu0.22.04.1", "release_fixes": fixes},
        "libfoo",
    )
    noble = 'ID=ubuntu\nVERSION_ID="24.04"\n'
    # listed as affected with no fix on the host's release -> MET, never the 22.04 fix
    res = run_probe(pre, _rel_runner(noble, "ii \t1.4.0-2build1\n"))
    assert res.status == ProbeStatus.MET, res.evidence
    assert "no fix" in res.evidence
    # host release not listed -> UNKNOWN, installed or not (package names differ across distros)
    bookworm = 'ID=debian\nVERSION_ID="12"\n'
    assert run_probe(pre, _rel_runner(bookworm, "ii \t1.4.0-2\n")).status == ProbeStatus.UNKNOWN
    assert run_probe(pre, _rel_runner(bookworm, None)).status == ProbeStatus.UNKNOWN


def test_kernel_track_parsing():
    from notaffected.probes.primitives import _kernel_track

    assert _kernel_track("6.5.0-14-generic") == ("6.5", "generic")
    assert _kernel_track("6.8.0-1001-azure") == ("6.8", "azure")
    assert _kernel_track("5.15.0-1059-azure-fde") == ("5.15", "azure-fde")
    assert _kernel_track("6.8.0-40-lowlatency") == ("6.8", "lowlatency")
    assert _kernel_track("5.14.0-427.13.1.el9_4.x86_64") == ("5.14", "")
    assert _kernel_track("6.1.0-17-amd64") == ("6.1", "amd64")


def _kernel_runner(uname: str, extra: dict | None = None) -> MockRunner:
    resp = {("uname", "-r"): CommandResult(0, uname + "\n", "")}
    resp.update(extra or {})
    return MockRunner("k", resp)


def test_kernel_compared_only_within_its_own_track():
    jammy = {("cat", "/etc/os-release"): CommandResult(0, 'ID=ubuntu\nVERSION_ID="22.04"\n', "")}
    tracks = {
        "ubuntu:22.04:5.15:generic": "5.15.0-101.111",
        "ubuntu:22.04:6.5:generic": "6.5.0-26.26~22.04.1",
        "ubuntu:22.04:6.2:generic": "",
    }
    pre = Precondition("kernel_version_vulnerable", {"fixed_version": "5.15.0-101.111", "track_fixes": tracks}, "k")
    hwe = dict(jammy)
    hwe[("dpkg", "--compare-versions", "6.5.0-14", "lt", "6.5.0-26")] = CommandResult(0, "", "")
    assert run_probe(pre, _kernel_runner("6.5.0-14-generic", hwe)).status == ProbeStatus.MET
    res = run_probe(pre, _kernel_runner("6.2.0-39-generic", jammy))
    assert res.status == ProbeStatus.MET and "no fix" in res.evidence
    # a track the advisory does not list (cloud flavour, other distro) is never compared
    assert run_probe(pre, _kernel_runner("5.15.0-1059-azure", jammy)).status == ProbeStatus.UNKNOWN

    legacy = Precondition("kernel_version_vulnerable", {"fixed_version": "6.8.0-45"}, "k")
    for uname in ("6.8.0-1001-azure", "5.14.0-427.13.1.el9_4.x86_64", "7.0.0-43-generic"):
        assert run_probe(legacy, _kernel_runner(uname)).status == ProbeStatus.UNKNOWN, uname

    mainline = Precondition("kernel_version_vulnerable", {"fixed_version": "6.2.0-21", "mainline_from": "6.4"}, "k")
    res = run_probe(mainline, _kernel_runner("6.8.0-40-generic"))
    assert res.status == ProbeStatus.NOT_MET and "upstream fix" in res.evidence


def _ufw(rules: str, default: str = "deny") -> str:
    return (
        "Status: active\nLogging: on (low)\n"
        f"Default: {default} (incoming), allow (outgoing), disabled (routed)\n\n"
        "To                         Action      From\n--                         ------      ----\n" + rules
    )


def _fw(port: str, out: str, docker0: bool = False) -> ProbeStatus:
    resp = {("ufw", "status", "verbose"): CommandResult(0, out, "")}
    resp[("ip", "-o", "link", "show", "docker0")] = (
        CommandResult(0, "4: docker0: <BROADCAST> mtu 1500\n", "") if docker0 else CommandResult(1, "", "")
    )
    pre = Precondition("firewall_allows_port", {"port": port, "proto": "tcp"}, "fw")
    return run_probe(pre, MockRunner("fw", resp)).status


def test_ufw_rules_are_parsed_by_column():
    assert _fw("8080", _ufw("8000:9000/tcp              ALLOW IN    Anywhere\n")) == ProbeStatus.MET
    assert _fw("22", _ufw("22/tcp                     LIMIT IN    Anywhere\n")) == ProbeStatus.MET
    assert _fw("22", _ufw("22/tcp                     ALLOW IN    Anywhere                   # from outside\n")) == ProbeStatus.MET
    assert _fw("443", _ufw("80,443/tcp                 ALLOW IN    Anywhere\n")) == ProbeStatus.MET
    # source-restricted or app-profile rules cannot be matched to "reachable from anywhere"
    assert _fw("22", _ufw("Anywhere                   ALLOW IN    10.0.0.0/8\n")) == ProbeStatus.UNKNOWN
    assert _fw("22", _ufw("OpenSSH                    ALLOW IN    Anywhere\n")) == ProbeStatus.UNKNOWN
    # outgoing rules never open an incoming port
    assert _fw("22", _ufw("22/tcp                     ALLOW OUT   Anywhere\n")) == ProbeStatus.NOT_MET
    # default deny with no matching rule is NOT_MET, unless Docker can publish ports around ufw
    assert _fw("22", _ufw("80/tcp                     ALLOW IN    Anywhere\n")) == ProbeStatus.NOT_MET
    assert _fw("22", _ufw("80/tcp                     ALLOW IN    Anywhere\n"), docker0=True) == ProbeStatus.UNKNOWN
    assert _fw("any", _ufw(""), docker0=True) == ProbeStatus.UNKNOWN
    # a rule row without the table header still counts (never a silent NOT_MET)
    headerless = "Status: active\nDefault: deny (incoming)\n443/tcp ALLOW IN Anywhere\n"
    assert _fw("443", headerless) == ProbeStatus.MET
    assert _fw("any", headerless) == ProbeStatus.MET


def test_ss_listener_without_visible_process_or_unlisted_proto_is_unknown():
    ss_out = "tcp LISTEN 0 100 0.0.0.0:8080 0.0.0.0:*\n"
    pre = Precondition("network_listener", {"proto": "tcp", "port": 8080, "process": "java"}, "l")
    res = run_probe(pre, MockRunner("h", {("ss", "-tulpnH"): CommandResult(0, ss_out, "")}))
    assert res.status == ProbeStatus.UNKNOWN and "hidden" in res.evidence
    own = 'tcp LISTEN 0 100 0.0.0.0:8080 0.0.0.0:* users:(("nginx",pid=1,fd=6))\n'
    res = run_probe(pre, MockRunner("h", {("ss", "-tulpnH"): CommandResult(0, own, "")}))
    assert res.status == ProbeStatus.NOT_MET  # process info visible and it is not java
    sctp = Precondition("network_listener", {"proto": "sctp", "port": 3868}, "l")
    assert run_probe(sctp, MockRunner("h", {("ss", "-tulpnH"): CommandResult(0, ss_out, "")})).status == ProbeStatus.UNKNOWN


def test_systemd_unit_not_found_or_invalid_is_unknown_and_socket_activation_counts():
    pre = Precondition("systemd_service_active", {"service": "ssh.service"}, "s")
    not_found = MockRunner("h", {("systemctl", "is-active", "ssh.service"): CommandResult(4, "inactive\n", "")})
    assert run_probe(pre, not_found).status == ProbeStatus.UNKNOWN
    inactive = {
        ("systemctl", "is-active", "ssh.service"): CommandResult(3, "inactive\n", ""),
        ("systemctl", "show", "-p", "LoadState", "--value", "ssh.service"): CommandResult(0, "loaded\n", ""),
    }
    inactive[("systemctl", "is-active", "ssh.socket")] = CommandResult(3, "inactive\n", "")
    assert run_probe(pre, MockRunner("h", inactive)).status == ProbeStatus.NOT_MET
    inactive[("systemctl", "is-active", "ssh.socket")] = CommandResult(0, "active\n", "")
    res = run_probe(pre, MockRunner("h", inactive))
    assert res.status == ProbeStatus.MET and "ssh.socket" in res.evidence
    bad = Precondition("systemd_service_active", {"service": "-H evil"}, "s")
    assert run_probe(bad, MockRunner("h", {})).status == ProbeStatus.UNKNOWN

    proc = Precondition("process_running", {"process": "sshd", "socket_unit": "ssh.socket"}, "p")
    resp = {
        ("ps", "-eo", "comm,args", "--no-headers"): CommandResult(0, "systemd /sbin/init\n", ""),
        ("systemctl", "is-active", "ssh.socket"): CommandResult(0, "active\n", ""),
    }
    res = run_probe(proc, MockRunner("h", resp))
    assert res.status == ProbeStatus.MET and "on demand" in res.evidence



class _Recorder(MockRunner):
    def __init__(self, responses: dict):
        super().__init__("rec", responses)
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv):
        self.calls.append(tuple(argv))
        return super().run(argv)


def test_module_not_loaded_is_proof_only_when_blocked():
    mods = {("cat", "/proc/modules"): CommandResult(0, "tls 1 0 - Live\n", "")}
    pre = Precondition("kernel_module_loaded", {"module": "nf_tables"}, "m")
    loadable = dict(mods)
    loadable[("modprobe", "-c")] = CommandResult(0, "blacklist floppy\nalias net-pf-16-proto-12 nfnetlink\n", "")
    loadable[("cat", "/proc/sys/kernel/modules_disabled")] = CommandResult(0, "0\n", "")
    res = run_probe(pre, MockRunner("h", loadable))
    assert res.status == ProbeStatus.UNKNOWN and "on demand" in res.evidence
    disabled = dict(loadable)
    disabled[("cat", "/proc/sys/kernel/modules_disabled")] = CommandResult(0, "1\n", "")
    assert run_probe(pre, MockRunner("h", disabled)).status == ProbeStatus.NOT_MET
    bad = Precondition("kernel_module_loaded", {"module": "nf_tables; reboot"}, "m")
    assert run_probe(bad, MockRunner("h", mods)).status == ProbeStatus.UNKNOWN


def test_sysctl_option_injection_is_refused_without_running_anything():
    for key in ("--system", "-p", "a b"):
        rec = _Recorder({})
        res = run_probe(Precondition("sysctl_equals", {"key": key, "value": "1"}, "s"), rec)
        assert res.status == ProbeStatus.UNKNOWN, key
        assert rec.calls == [], key


def test_config_first_occurrence_semantics_for_sshd():
    def cfg(text: str, sshd_t: str | None = None) -> MockRunner:
        resp = {("cat", "/etc/ssh/sshd_config"): CommandResult(0, text, "")}
        if sshd_t is not None:
            resp[("sshd", "-T")] = CommandResult(0, sshd_t, "")
        return MockRunner("ssh", resp)

    pre = Precondition(
        "config_contains",
        {
            "path": "/etc/ssh/sshd_config",
            "pattern": r"^\s*LoginGraceTime\s+0\b",
            "negate": True,
            "semantics": "first",
            "directive": "LoginGraceTime",
        },
        "grace",
    )
    # sshd uses the FIRST value: an appended "LoginGraceTime 0" after 60 does not mitigate
    assert run_probe(pre, cfg("Port 22\nLoginGraceTime 60\nLoginGraceTime 0\n")).status == ProbeStatus.MET
    assert run_probe(pre, cfg("LoginGraceTime 0\nLoginGraceTime 60\n")).status == ProbeStatus.NOT_MET
    # an Include can override the main file: without `sshd -T` the effective value is unknown
    inc = "Include /etc/ssh/sshd_config.d/*.conf\nLoginGraceTime 0\n"
    assert run_probe(pre, cfg(inc)).status == ProbeStatus.UNKNOWN
    # `sshd -T` (effective config) wins when it is readable
    assert run_probe(pre, cfg(inc, "port 22\nlogingracetime 0\n")).status == ProbeStatus.NOT_MET
    assert run_probe(pre, cfg(inc, "port 22\nlogingracetime 120\n")).status == ProbeStatus.MET

    # generic configs: full-line ';' comments are skipped like '#'
    ini = Precondition("config_contains", {"path": "/etc/samba/smb.conf", "pattern": r"^server min protocol"}, "ini")
    runner = MockRunner("smb", {("cat", "/etc/samba/smb.conf"): CommandResult(0, "; server min protocol = SMB3\n", "")})
    assert run_probe(ini, runner).status == ProbeStatus.NOT_MET


def test_helper_checks_that_cannot_run_are_unknown_not_absent():
    transport = CommandResult(255, "", "ssh: connection reset", transport_error=True)
    inactive = {
        ("systemctl", "is-active", "cups-browsed.service"): CommandResult(3, "inactive\n", ""),
        ("systemctl", "show", "-p", "LoadState", "--value", "cups-browsed.service"): CommandResult(0, "loaded\n", ""),
        ("systemctl", "is-active", "cups-browsed.socket"): transport,
    }
    svc = Precondition("systemd_service_active", {"service": "cups-browsed.service"}, "s")
    assert run_probe(svc, MockRunner("h", inactive)).status == ProbeStatus.UNKNOWN

    proc = Precondition("process_running", {"process": "sshd", "socket_unit": "ssh.socket"}, "p")
    resp = {
        ("ps", "-eo", "comm,args", "--no-headers"): CommandResult(0, "systemd /sbin/init\n", ""),
        ("systemctl", "is-active", "ssh.socket"): transport,
    }
    assert run_probe(proc, MockRunner("h", resp)).status == ProbeStatus.UNKNOWN

    deny = _ufw("80/tcp                     ALLOW IN    Anywhere\n")
    fw = Precondition("firewall_allows_port", {"port": "22", "proto": "tcp"}, "fw")
    for ip_res, expected in (
        (transport, ProbeStatus.UNKNOWN),
        (CommandResult(127, "", "ip: command not found"), ProbeStatus.UNKNOWN),
        (CommandResult(1, "", 'Device "docker0" does not exist.'), ProbeStatus.NOT_MET),
    ):
        runner = MockRunner(
            "h",
            {("ufw", "status", "verbose"): CommandResult(0, deny, ""), ("ip", "-o", "link", "show", "docker0"): ip_res},
        )
        assert run_probe(fw, runner).status == expected, ip_res


def test_ufw_without_visible_default_policy_is_unknown():
    runner = MockRunner(
        "h",
        {
            ("ufw", "status", "verbose"): CommandResult(1, "", "ERROR"),
            ("ufw", "status"): CommandResult(0, "Status: active\n", ""),
            ("ip", "-o", "link", "show", "docker0"): CommandResult(1, "", ""),
        },
    )
    fw = Precondition("firewall_allows_port", {"port": "22", "proto": "tcp"}, "fw")
    assert run_probe(fw, runner).status == ProbeStatus.UNKNOWN


def test_dpkg_warning_in_any_language_is_unreadable_not_patched():
    kpre = Precondition("kernel_version_vulnerable", {"fixed_version": "6.8.0-45"}, "k")
    runner = MockRunner(
        "h",
        {
            ("uname", "-r"): CommandResult(0, "6.8.0-40-generic\n", ""),
            ("dpkg", "--compare-versions", "6.8.0-40", "lt", "6.8.0-45"): CommandResult(
                1, "", "dpkg: Warnung: Version »6.8.0-40« hat falsche Syntax\n"
            ),
        },
    )
    assert run_probe(kpre, runner).status == ProbeStatus.UNKNOWN


def test_failed_source_package_listing_is_unknown_not_absent():
    pre = Precondition("package_installed_vulnerable", {"package": "openssh"}, "p")
    src_fmt = "-f=${db:Status-Abbrev}\\t${binary:Package}\\t${source:Package}\\t${Version}\\t${source:Version}\\n"
    runner = MockRunner(
        "h",
        {
            ("dpkg-query", "-W", "-f=${db:Status-Abbrev}\\t${Version}\\n", "openssh"): CommandResult(
                1, "", "dpkg-query: no packages found matching openssh\n"
            ),
            ("dpkg-query", "-W", src_fmt): CommandResult(255, "", "timeout", transport_error=True),
        },
    )
    assert run_probe(pre, runner).status == ProbeStatus.UNKNOWN
