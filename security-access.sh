#!/bin/bash
set -euo pipefail

echo ""
echo "        Security access only for" 
echo "     Cloudflare , Tailscale and Local"
echo "        Welcome to use This Tool"
echo "         Powered by FuionPlmH"
echo ""

# 0. Permission check
if [ "$EUID" -ne 0 ]; then
  echo "Error: Please run this script with root privileges (e.g. sudo)."
  exit 1
fi

## 1. Check support and install package
check_and_install() {
    local package=$1
    if ! dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q "install ok installed"; then
        echo "Installing $package..."
        apt-get update -qq && apt-get install -y -qq "$package"
    else
        echo "$package is already installed."
    fi
}

check_and_install ufw
check_and_install fail2ban

## 2. Initialize and Ensure UFW is Active First
echo "Initializing UFW default policies and enabling firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw logging low
ufw --force enable >/dev/null 2>&1

## 3. Safely check and clean legacy port 443 rules (100% Guaranteed Cleanup)
echo "Checking existing UFW rules for legacy entries..."

if ufw status 2>/dev/null | grep -w -q "443"; then
    echo "Found legacy 443 port rules, cleaning up..."
    while ufw status numbered 2>/dev/null | grep -w "443" | grep -q "\["; do
        num=$(ufw status numbered 2>/dev/null | grep -w "443" | head -n1 | sed -E 's/.*\[ *([0-9]+)\].*/\1/')
        if [ -n "$num" ]; then
            echo "Deleting 443 rule #$num..."
            echo "y" | ufw delete "$num" >/dev/null 2>&1 || break
        else
            break
        fi
    done
fi

## 4. Check Cloudflare WARP / Mesh
WARP_IF=""
if ip link show CloudflareWARP >/dev/null 2>&1; then
    WARP_IF="CloudflareWARP"
elif ip link show warp0 >/dev/null 2>&1; then
    WARP_IF="warp0"
fi

if [ -n "$WARP_IF" ]; then
    echo "Cloudflare WARP/Mesh ($WARP_IF) is installed, adding rules..."
    ufw allow in on "$WARP_IF" to any
    ufw allow out on "$WARP_IF" to any
else
    echo "Cloudflare WARP/Mesh not installed, skipping..."
fi

## 5. Check Proxmox Virtual Environment
if (echo > /dev/tcp/127.0.0.1/8006) >/dev/null 2>&1; then
    echo "Proxmox Virtual Environment is active, adding rules..."
    cidr=$(ip -4 route show dev vmbr0 2>/dev/null | awk '/proto kernel/ {print $1}' | head -n1 || true)
    
    if [[ "$cidr" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        echo "Allowing PVE web management on vmbr0 interface from CIDR: $cidr..."
        ufw allow in on vmbr0 from "$cidr" to any port 8006
    else
        echo "Valid CIDR on vmbr0 not detected, skipping Proxmox rule..."
    fi
else
    echo "Proxmox Virtual Environment not active or not installed, skipping..."
fi

## 6. Check Tailscale interface
if ip link show tailscale0 >/dev/null 2>&1; then
    echo "Tailscale is installed, adding rules..."
    ufw allow in on tailscale0 to any
    ufw allow out on tailscale0 to any
else
    echo "Tailscale not installed, skipping..."
fi

## 7. Setting Up Fail2ban
echo "Setting Up Fail2ban..."
touch /var/log/ufw.log

tee /etc/fail2ban/jail.local > /dev/null <<'EOF'
[sshd]
enabled = true
port = ssh
filter = sshd
backend = systemd
maxretry = 5
findtime = 1d
bantime = 7d

[ufw]
enabled = true
filter = ufw-aggressive
action = ufw
logpath = /var/log/ufw.log
maxretry = 5
findtime = 1d
bantime = 7d
EOF

tee /etc/fail2ban/filter.d/ufw-aggressive.conf > /dev/null <<'EOF'
[Definition]
failregex = \[UFW BLOCK\].*SRC=<HOST> DST
ignoreregex =
EOF

## 8. Reload UFW & Restart Fail2ban
ufw reload >/dev/null 2>&1
systemctl enable fail2ban
systemctl restart fail2ban

echo ""
echo "=================================================="
echo "Current active UFW rules (including manual rules):"
echo "=================================================="
ufw status verbose

echo ""
echo "Security rules setup completed successfully."
