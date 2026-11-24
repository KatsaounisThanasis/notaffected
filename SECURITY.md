# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `notaffected` (for example: command injection in a probe or runner, SSRF bypass in advisory fetchers, authentication or CSRF bypass in the local Web UI, or a false `not_affected` verdict under normal fail-closed guarantees), please report it privately rather than opening a public GitHub issue.

- **Preferred:** Use [GitHub Private Vulnerability Reporting](https://github.com/KatsaounisThanasis/notaffected/security/advisories/new) on this repository.
- **Response target:** Initial acknowledgement within 72 hours.

Please include reproduction steps, affected version (`notaffected --version`), and impact assessment.

## Security Model & Trust Boundaries

`notaffected` is designed to evaluate untrusted advisory text and untrusted scanner output against real hosts without mutating targets:

1. **Read-only host probing:** All 12 built-in probes execute fixed argument vectors (`subprocess` / `ssh` / `docker exec` / `kubectl exec` with `shell=False`) and validate parameters against option injection, path traversal, and PowerShell quote breakout.
2. **Fail-closed verdicts:** Transport errors, missing permissions, unreadable configs, cross-distro version mismatches, ambiguous firewall rules, or Docker bridge bypasses resolve to `under_investigation`, never `not_affected`.
3. **AI advisor boundary:** Optional BYOM LLM integration is disabled by default. When enabled, the LLM may only propose probe parameters grounded in advisory text; it never executes commands, never sets the OS family or OpenVEX justification, and a `NOT_MET` from an LLM-proposed or keyword-heuristic check never produces `not_affected` on its own.
4. **Lab-only mitigations:** The Web UI **Run Mitigation** action refuses local hosts, SSH hosts, and any Docker container without the explicit `notaffected.lab=true` label.
5. **Local Web Dashboard (`notaffected ui`):** Binds strictly to `127.0.0.1` by default, validates `Host` and `Origin` headers, and requires a per-process `X-Notaffected-Token`. Non-loopback binding is refused unless both `--allow-remote` and `NOTAFFECTED_REMOTE_TOKEN` (>= 16 characters) are set; in remote mode the token is never embedded in HTML and is required on all `/api/*` endpoints.
6. **Advisory fetching:** Outbound reference fetching enforces HTTPS-only public-IP SSRF checks (blocking loopback, RFC1918, link-local, metadata endpoints, and DNS resolution failures) and writes cache files atomically.

## Supported Versions

| Version | Supported |
|---|---|
| `1.x` | Yes |
