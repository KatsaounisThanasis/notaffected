# Changelog

All notable changes to `notaffected` are documented in this file.

## [1.0.1] - 2026-11-26

### Documentation & Polish
- Tightened `README.md` with the `[✓]` logo, DevSecOps how-it-works visual, and concise quick-start flow; moved the full probe reference, custom YAML rules guide, Docker lab, and BYOM AI provider matrix to `docs/reference.md`.
- Unified the `[✓]` mark across the local Web Dashboard (`notaffected ui`) and standalone HTML audit report favicons.
- Added `Changelog` and `Security` project URLs and PEP 639 license metadata in `pyproject.toml`.

## [1.0.0] - 2026-11-26

Initial public release of `notaffected`.

### Highlights
- **Deterministic Reachability Engine:** Three-valued (`MET` / `NOT_MET` / `UNKNOWN`) fail-closed evaluation over a closed set of 12 read-only probes for Linux (`dpkg`, `apk`, `rpm`, `systemd`, `ss`, `ufw`, `firewalld`, `nftables`, `sysctl`, `/proc/modules`, config files) and Windows Server (PowerShell over OpenSSH: build/KB, Registry, Services, Processes).
- **Native Multi-Distro Package & Firewall Support:** Exact `dpkg --compare-versions`, `apk version -t`, and pure-Python native RPM EVR (`rpmvercmp`) comparison with per-release fix matching (Ubuntu, Debian, Alpine, RHEL, Rocky Linux, AlmaLinux), plus fail-closed `ufw`, `firewalld`, and `nftables` inspection.
- **Multi-Source Advisory Feeds:** Built-in curated golden specs, OSV.dev (Ubuntu, Debian, Alpine), Red Hat Security Data API, Microsoft MSRC CVRF v3.0, MITRE CVE v5, and CISA KEV live auto-scan (`notaffected scan`) with concurrent fetching and atomic local caching.
- **Custom & Bundled YAML Rules (`--rules`):** Ships with 25 curated Linux & Windows Server rules (including 18 bundled YAML rules under `notaffected/rules/`) and loads/validates user-authored CheckSpec YAML files or directories across `spec`, `check`, `filter`, `scan`, and `ui`.
- **Standards-Compliant Outputs:** Official **OpenVEX v0.2.0** (`.vex.json`) with Package URLs (`pkg:deb/...`, `pkg:rpm/...`, `pkg:apk/...`) compatible with `trivy --vex`, full **Audit JSON**, and a self-contained Obsidian Dark/Light **Standalone HTML** report.
- **Local Web Dashboard (`notaffected ui`):** Zero-dependency master-detail dark console with Light/Dark toggle, False-Positive Noise Cut KPI, interactive Probe Inspector drawer, lab-only 1-click mitigations with re-verification, and strict loopback/token/CSRF hardening (`--allow-remote` + `NOTAFFECTED_REMOTE_TOKEN`).
- **Optional BYOM AI Advisor:** Off by default; supports any OpenAI-compatible server, Ollama, OpenAI, Anthropic, Gemini, or CLI provider for grounded parameter extraction (`--llm`) and operational remediation briefings (`--ai-explain`) without ever deciding verdicts.
- **Scanner & Fleet Support:** Filter Trivy and Grype JSON reports (`notaffected filter`), target local hosts, Linux/Windows SSH fleets, Docker containers, Kubernetes pods, YAML inventories (`notaffected init`), or the built-in 5-host mixed Linux + Windows Server `--demo-fleet`.
