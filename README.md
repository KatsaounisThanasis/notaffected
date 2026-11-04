# notaffected

**From 10,000 noisy CVE alerts down to the 3 that actually matter — with deterministic proof and OpenVEX output for all the rest.**

`notaffected` bridges the gap between vulnerability advisories and the real runtime state of your Linux hosts. Instead of flagging every machine that has a package installed, it extracts attack preconditions (kernel modules, sysctls, exposed network listeners, firewall policies, systemd units) and runs read-only deterministic probes to prove whether each machine is truly exposed.

## Quick Start

```bash
# Inspect the extracted preconditions & mitigations for a CVE
notaffected spec CVE-2026-98432

# Check local or remote hosts and emit an OpenVEX file
notaffected check CVE-2026-98432 CVE-2024-47176 --host local --emit-vex vex.json

# Filter an existing Trivy or Grype JSON scan against real host state
notaffected filter trivy-results.json --host local --emit-vex vex.json
```
