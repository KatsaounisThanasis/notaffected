#!/usr/bin/env bash
set -euo pipefail

CONTAINERS=("lab-ssh-vuln" "lab-ssh-mitigated" "lab-win-dc01" "lab-win-filesrv02")
for c in "${CONTAINERS[@]}"; do
  docker rm -f "$c" >/dev/null 2>&1 || true
done
echo "All lab containers removed."
