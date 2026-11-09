"""Curated, deterministic CheckSpecs for high-profile Linux CVEs.

These work 100% offline with zero external API or LLM calls.
"""

from __future__ import annotations

from notaffected.model import CheckSpec, PatchInfo, Precondition, VexJustification

BUILTIN_SPECS: dict[str, CheckSpec] = {
    "CVE-2026-98432": CheckSpec(
        cve_id="CVE-2026-98432",
        summary=(
            "Linux kernel IPv4 TCP/MPTCP options use-after-free race condition "
            "allowing remote code execution against exposed TCP listeners"
        ),
        severity="CRITICAL",
        preconditions=[
            Precondition(
                probe="kernel_version_vulnerable",
                params={"min_version": "4.4.0", "fixed_version": "6.8.0-45"},
                description="Running Linux kernel is older than patched release (6.8.0-45)",
                justification_if_not_met=VexJustification.VULNERABLE_CODE_NOT_PRESENT,
            ),
            Precondition(
                probe="network_listener",
                params={"proto": "tcp", "scope": "non_loopback"},
                description="At least one TCP/MPTCP service is listening on a non-loopback address",
                justification_if_not_met=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
            ),
            Precondition(
                probe="firewall_allows_port",
                params={"port": "any", "proto": "tcp"},
                description="Host firewall allows incoming TCP traffic from external networks",
                justification_if_not_met=VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST,
            ),
        ],
        mitigation=[
            "sudo ufw default deny incoming && sudo ufw enable",
            "sudo sysctl -w net.mptcp.enabled=0",
            "Drop IPv4 packets carrying Record Route (type 7) or Timestamp (type 68) TCP/IP options at perimeter firewall",
        ],
        patch=PatchInfo(
            status="staged",
            fixed_version="6.8.0-45.45",
            pocket="noble-proposed",
            advisory_url="https://ubuntu.com/security/CVE-2026-98432",
        ),
        confidence="high",
        source="builtin",
    ),
    "CVE-2024-47176": CheckSpec(
        cve_id="CVE-2024-47176",
        summary="OpenPrinting cups-browsed UDP port 631 remote code execution chain",
        severity="CRITICAL",
        preconditions=[
            Precondition(
                probe="package_installed_vulnerable",
                params={"package": "cups-browsed", "fixed_version": "2.0.0-0ubuntu10.2"},
                description="Package 'cups-browsed' is installed and < 2.0.0-0ubuntu10.2",
                justification_if_not_met=VexJustification.COMPONENT_NOT_PRESENT,
            ),
            Precondition(
                probe="systemd_service_active",
                params={"service": "cups-browsed.service"},
                description="systemd unit 'cups-browsed.service' is running",
                justification_if_not_met=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
            ),
            Precondition(
                probe="network_listener",
                params={"proto": "udp", "port": 631, "scope": "non_loopback"},
                description="UDP port 631 is listening on a non-loopback address",
                justification_if_not_met=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
            ),
        ],
        mitigation=[
            "sudo systemctl disable --now cups-browsed.service",
            "sudo ufw deny 631/udp",
        ],
        patch=PatchInfo(
            status="released",
            fixed_version="2.0.0-0ubuntu10.2",
            pocket="noble-security",
            advisory_url="https://ubuntu.com/security/CVE-2024-47176",
        ),
        confidence="high",
        source="builtin",
    ),
    "CVE-2023-32233": CheckSpec(
        cve_id="CVE-2023-32233",
        summary="Linux kernel Netfilter nf_tables anonymous sets use-after-free local privilege escalation",
        severity="HIGH",
        preconditions=[
            Precondition(
                probe="kernel_version_vulnerable",
                params={"fixed_version": "6.2.0-21"},
                description="Running Linux kernel is < 6.2.0-21",
                justification_if_not_met=VexJustification.VULNERABLE_CODE_NOT_PRESENT,
            ),
            Precondition(
                probe="kernel_module_loaded",
                params={"module": "nf_tables"},
                description="Kernel module 'nf_tables' is loaded in /proc/modules",
                justification_if_not_met=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
            ),
            Precondition(
                probe="sysctl_equals",
                params={"key": "kernel.unprivileged_userns_clone", "value": "1"},
                description="Unprivileged user namespaces enabled (kernel.unprivileged_userns_clone = 1)",
                justification_if_not_met=VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST,
            ),
        ],
        mitigation=[
            "sudo sysctl -w kernel.unprivileged_userns_clone=0",
            "echo 'blacklist nf_tables' | sudo tee /etc/modprobe.d/blacklist-nftables.conf",
        ],
        patch=PatchInfo(
            status="released",
            fixed_version="6.2.0-21.21",
            pocket="ubuntu-security",
            advisory_url="https://ubuntu.com/security/CVE-2023-32233",
        ),
        confidence="high",
        source="builtin",
    ),
    "CVE-2022-47942": CheckSpec(
        cve_id="CVE-2022-47942",
        summary="Linux kernel ksmbd in-kernel SMB server pre-auth remote code execution",
        severity="CRITICAL",
        preconditions=[
            Precondition(
                probe="kernel_module_loaded",
                params={"module": "ksmbd"},
                description="In-kernel SMB server module 'ksmbd' is loaded in /proc/modules",
                justification_if_not_met=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
            ),
            Precondition(
                probe="network_listener",
                params={"proto": "tcp", "port": 445, "scope": "non_loopback"},
                description="TCP port 445 (SMB) is listening on a non-loopback address",
                justification_if_not_met=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
            ),
        ],
        mitigation=[
            "sudo modprobe -r ksmbd",
            "echo 'install ksmbd /bin/false' | sudo tee /etc/modprobe.d/disable-ksmbd.conf",
            "sudo ufw deny 445/tcp",
        ],
        patch=PatchInfo(
            status="released",
            fixed_version="5.19.0-28",
            pocket="ubuntu-security",
            advisory_url="https://ubuntu.com/security/CVE-2022-47942",
        ),
        confidence="high",
        source="builtin",
    ),
    "CVE-2024-6387": CheckSpec(
        cve_id="CVE-2024-6387",
        summary="OpenSSH server (sshd) regreSSHion SIGALRM race condition unauthenticated RCE",
        severity="CRITICAL",
        preconditions=[
            Precondition(
                probe="package_installed_vulnerable",
                params={"package": "openssh-server", "fixed_version": "1:9.6p1-3ubuntu13.3"},
                description="Package 'openssh-server' is installed and < 1:9.6p1-3ubuntu13.3",
                justification_if_not_met=VexJustification.COMPONENT_NOT_PRESENT,
            ),
            Precondition(
                probe="process_running",
                params={"process": "sshd"},
                description="OpenSSH daemon ('sshd') process is running",
                justification_if_not_met=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
            ),
            Precondition(
                probe="network_listener",
                params={"proto": "tcp", "port": 22, "scope": "non_loopback"},
                description="TCP port 22 (SSH) is listening on a non-loopback address",
                justification_if_not_met=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
            ),
            Precondition(
                probe="config_contains",
                params={
                    "path": "/etc/ssh/sshd_config",
                    "pattern": r"^\s*LoginGraceTime\s+0\b",
                    "negate": True,
                },
                description="LoginGraceTime is not set to 0 in /etc/ssh/sshd_config",
                justification_if_not_met=VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST,
            ),
        ],
        mitigation=[
            "echo 'LoginGraceTime 0' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl reload ssh",
            "sudo apt update && sudo apt install --only-upgrade openssh-server",
        ],
        patch=PatchInfo(
            status="released",
            fixed_version="1:9.6p1-3ubuntu13.3",
            pocket="noble-security",
            advisory_url="https://ubuntu.com/security/CVE-2024-6387",
        ),
        confidence="high",
        source="builtin",
    ),
}
