#!/usr/bin/env bash
set -euo pipefail

IMAGE="alpine:3.20"
CONTAINERS=("lab-ssh-vuln" "lab-ssh-mitigated" "lab-win-dc01" "lab-win-filesrv02")

for c in "${CONTAINERS[@]}"; do
  docker rm -f "$c" >/dev/null 2>&1 || true
done

echo "[1/4] Starting Linux container: lab-ssh-vuln (Vulnerable OpenSSH CVE-2024-6387)..."
docker run -d --name lab-ssh-vuln --label notaffected.lab=true --label notaffected.os=linux --memory 32m --cpus 0.1 "$IMAGE" sleep infinity >/dev/null
docker exec lab-ssh-vuln sh -c '
  mkdir -p /etc/ssh /usr/local/bin
  # The simulated host is Ubuntu 24.04 (noble packages), so per-release fixes resolve as on a real one.
  printf "ID=ubuntu\nVERSION_ID=\"24.04\"\n" > /etc/os-release
  printf "Port 22\nPermitRootLogin no\nLoginGraceTime 120\n" > /etc/ssh/sshd_config
  echo "1:9.6p1-3ubuntu13" > /etc/ssh/openssh_version

  cat << "EOF" > /usr/local/bin/uname
#!/bin/sh
case "$1" in
  -s) echo "Linux" ;;
  *) echo "6.8.0-45-generic" ;;
esac
EOF
  chmod +x /usr/local/bin/uname

  cat << "EOF" > /usr/local/bin/dpkg-query
#!/bin/sh
pkg=""
for arg in "$@"; do pkg="$arg"; done
ssh_ver="1:9.6p1-3ubuntu13"
if [ -f /etc/ssh/openssh_version ]; then
  ssh_ver="$(cat /etc/ssh/openssh_version)"
fi
if [ "$pkg" = "openssh-server" ]; then
  printf "ii \t%s\n" "$ssh_ver"
  exit 0
fi
case "$pkg" in
  -f=*source:Package*)
    printf "ii \tlibc6\tglibc\t2.39-0ubuntu8.3\t2.39-0ubuntu8.3\n"
    printf "ii \topenssh-server\topenssh\t%s\t%s\n" "$ssh_ver" "$ssh_ver"
    exit 0
    ;;
esac
echo "dpkg-query: no packages found matching $pkg" >&2
exit 1
EOF
  chmod +x /usr/local/bin/dpkg-query

  cat << "EOF" > /usr/local/bin/apt
#!/bin/sh
for arg in "$@"; do
  if [ "$arg" = "openssh-server" ]; then
    echo "1:9.6p1-3ubuntu13.3" > /etc/ssh/openssh_version
    echo "Upgraded openssh-server to 1:9.6p1-3ubuntu13.3"
    exit 0
  fi
done
exit 0
EOF
  chmod +x /usr/local/bin/apt

  cat << "EOF" > /usr/local/bin/dpkg
#!/bin/sh
v1="$2"
op="$3"
v2="$4"
if [ "$op" = "lt" ]; then
  [ "$v1" != "$v2" ] && [ "$(printf "%s\n%s\n" "$v1" "$v2" | sort -V | head -n1)" = "$v1" ] && exit 0 || exit 1
fi
exit 0
EOF
  chmod +x /usr/local/bin/dpkg

  cat << "EOF" > /usr/local/bin/ps
#!/bin/sh
printf "sshd            /usr/sbin/sshd -D\n"
EOF
  chmod +x /usr/local/bin/ps

  cat << "EOF" > /usr/local/bin/ss
#!/bin/sh
printf "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=850,fd=3))\n"
EOF
  chmod +x /usr/local/bin/ss

  cat << "EOF" > /usr/local/bin/apt-cache
#!/bin/sh
cat << "APTEOF"
openssh-server:
  Installed: 1:9.6p1-3ubuntu13
  Candidate: 1:9.6p1-3ubuntu13.3
  Version table:
     1:9.6p1-3ubuntu13.3 500
        500 http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages
APTEOF
EOF
  chmod +x /usr/local/bin/apt-cache
'

echo "[2/4] Starting Linux container: lab-ssh-mitigated (Mitigated OpenSSH CVE-2024-6387)..."
docker run -d --name lab-ssh-mitigated --label notaffected.lab=true --label notaffected.os=linux --memory 32m --cpus 0.1 "$IMAGE" sleep infinity >/dev/null
docker exec lab-ssh-mitigated sh -c '
  mkdir -p /etc/ssh /usr/local/bin
  # The simulated host is Ubuntu 24.04 (noble packages), so per-release fixes resolve as on a real one.
  printf "ID=ubuntu\nVERSION_ID=\"24.04\"\n" > /etc/os-release
  printf "Port 22\nPermitRootLogin no\nLoginGraceTime 0\n" > /etc/ssh/sshd_config

  cat << "EOF" > /usr/local/bin/uname
#!/bin/sh
case "$1" in
  -s) echo "Linux" ;;
  *) echo "6.8.0-45-generic" ;;
esac
EOF
  chmod +x /usr/local/bin/uname

  cat << "EOF" > /usr/local/bin/dpkg-query
#!/bin/sh
pkg=""
for arg in "$@"; do pkg="$arg"; done
if [ "$pkg" = "openssh-server" ]; then
  printf "ii \t1:9.6p1-3ubuntu13\n"
  exit 0
fi
case "$pkg" in
  -f=*source:Package*)
    printf "ii \tlibc6\tglibc\t2.39-0ubuntu8.3\t2.39-0ubuntu8.3\n"
    printf "ii \topenssh-server\topenssh\t1:9.6p1-3ubuntu13\t1:9.6p1-3ubuntu13\n"
    exit 0
    ;;
esac
echo "dpkg-query: no packages found matching $pkg" >&2
exit 1
EOF
  chmod +x /usr/local/bin/dpkg-query

  cat << "EOF" > /usr/local/bin/dpkg
#!/bin/sh
v1="$2"
op="$3"
v2="$4"
if [ "$op" = "lt" ]; then
  [ "$v1" != "$v2" ] && [ "$(printf "%s\n%s\n" "$v1" "$v2" | sort -V | head -n1)" = "$v1" ] && exit 0 || exit 1
fi
exit 0
EOF
  chmod +x /usr/local/bin/dpkg

  cat << "EOF" > /usr/local/bin/ps
#!/bin/sh
printf "sshd            /usr/sbin/sshd -D\n"
EOF
  chmod +x /usr/local/bin/ps

  cat << "EOF" > /usr/local/bin/ss
#!/bin/sh
printf "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=850,fd=3))\n"
EOF
  chmod +x /usr/local/bin/ss
'

install_win_shim() {
  local cname="$1"
  local build="$2"
  local kbs="$3"
  local disabled_comp="$4"
  local spooler="$5"

  docker exec "$cname" sh -c "
    mkdir -p /etc/win-sim /usr/local/bin
    echo '$build' > /etc/win-sim/build
    echo '$kbs' > /etc/win-sim/kbs
    echo '$disabled_comp' > /etc/win-sim/DisabledComponents
    echo '$spooler' > /etc/win-sim/Spooler

    cat << 'EOF' > /usr/local/bin/powershell
#!/bin/sh
cmd=\"\"
for arg in \"\$@\"; do cmd=\"\$arg\"; done

case \"\$cmd\" in
  *\"CurrentBuildNumber\"*)
    b=\$(cat /etc/win-sim/build)
    k=\$(cat /etc/win-sim/kbs)
    echo \"BUILD=\${b}|KBS=\${k}\"
    exit 0
    ;;
  *\"Set-ItemProperty\"*\"DisabledComponents\"*)
    echo \"255\" > /etc/win-sim/DisabledComponents
    exit 0
    ;;
  *\"Stop-Service\"*\"Spooler\"*)
    echo \"Stopped\" > /etc/win-sim/Spooler
    exit 0
    ;;
  *\"DisabledComponents\"*)
    cat /etc/win-sim/DisabledComponents
    exit 0
    ;;
  *\"Get-Service\"*\"Spooler\"*)
    cat /etc/win-sim/Spooler
    exit 0
    ;;
  *\"Get-Service\"*)
    echo \"Stopped\"
    exit 0
    ;;
esac
exit 1
EOF
    chmod +x /usr/local/bin/powershell
  "
}

echo "[3/4] Starting Simulated Windows Server: lab-win-dc01 (Vulnerable CVE-2024-38063 & CVE-2021-34527)..."
docker run -d --name lab-win-dc01 --label notaffected.lab=true --label notaffected.os=windows --memory 32m --cpus 0.1 "$IMAGE" sleep infinity >/dev/null
install_win_shim "lab-win-dc01" "20348.2402" "KB5039217" "0" "Running"

echo "[4/4] Starting Simulated Windows Server: lab-win-filesrv02 (Mitigated CVE-2024-38063 & CVE-2021-34527)..."
docker run -d --name lab-win-filesrv02 --label notaffected.lab=true --label notaffected.os=windows --memory 32m --cpus 0.1 "$IMAGE" sleep infinity >/dev/null
install_win_shim "lab-win-filesrv02" "20348.2402" "KB5039217" "255" "Stopped"

echo "Lab ready: 4 ultra-lightweight containers running."
