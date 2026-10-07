#!/bin/bash
set -euo pipefail

echo ""
echo "        Security access only for" 
echo "     Cloudflare , Tailscale and Local"
echo "        Welcome to use This Tool"
echo "         Powered by FsuionPlmH"
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
        if grep -Eqi "debian|ubuntu" /etc/issue* /proc/version* /etc/os-release*; then
            echo "Your system is supported. Now installing $package..."
            apt-get update -qq && apt-get install -y -qq "$package"
        else
            echo "$package not supported on this system."
            exit 1
        fi
    else
        echo "$package is already installed."
    fi
}

check_and_install ufw
check_and_install fail2ban

## 2. Check and clean legacy port 443 rules safely
echo "Checking existing UFW rules for legacy entries..."

if ufw status | grep -q "443"; then
    echo "Found legacy 443 port rules, cleaning up..."
    ufw status numbered | (grep "443" || true) | awk -F'[][]' '{print $2}' | sort -nr | while read -r num; do
        echo "y" | ufw delete "$num" >/dev/null 2>&1 || true
    done
fi

## 3. Check Cloudflare WARP / Mesh
WARP_IF=""
if ip link show CloudflareWARP >/dev/null 2>&1; then
    WARP_IF="CloudflareWARP"
elif ip link show warp0 >/dev/null 2>&1; then
    WARP_IF="warp0"
fi

if [ -n "$WARP_IF" ]; then
    echo "Cloudflare WARP/Mesh ($WARP_IF) is installed, adding rules..."
    ufw allow on "$WARP_IF"
else
    echo "Cloudflare WARP/Mesh not installed, skipping..."
fi

## 4. Check Proxmox Virtual Environment
if (echo > /dev/tcp/127.0.0.1/8006) >/dev/null 2>&1; then
    echo "Proxmox Virtual Environment is active, adding rules..."
    cidr=$(ip route show dev vmbr0 2>/dev/null | awk '/proto kernel/ {print $1}' | head -n1 || true)
    
    # Strictly validate CIDR format before applying UFW rule
    if [[ "$cidr" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        echo "Allowing PVE web management from validated CIDR: $cidr..."
        ufw allow from "$cidr" to any port 8006
    else
        echo "Valid CIDR on vmbr0 not detected, skipping Proxmox rule..."
    fi
else
    echo "Proxmox Virtual Environment not active or not installed, skipping..."
fi

## 5. Check Tailscale interface
if ip link show tailscale0 >/dev/null 2>&1; then
    echo "Tailscale is installed, adding rules..."
    ufw allow on tailscale0
else
    echo "Tailscale not installed, skipping..."
fi

## 6. Setup UFW defaults and logging
ufw default deny incoming
ufw default allow outgoing
ufw logging low

## 7. Setting Up Fail2ban
echo "Setting Up Fail2ban..."
touch /var/log/ufw.log

rm -f /etc/fail2ban/jail.local
rm -f /etc/fail2ban/filter.d/ufw-aggressive.conf

tee /etc/fail2ban/jail.local > /dev/null <<'EOF'
[ufw]
enabled = true
filter = ufw-aggressive
action = ufw
logpath = /var/log/ufw.log
maxretry = 5
bantime = 7d
EOF

tee /etc/fail2ban/filter.d/ufw-aggressive.conf > /dev/null <<'EOF'
[Definition]
failregex = \[UFW BLOCK\].*SRC=<HOST> DST
ignoreregex =
EOF

## 8. Enable UFW / Restart Fail2ban
ufw --force enable
systemctl enable fail2ban
systemctl restart fail2ban

echo ""
echo "=================================================="
echo "Current active UFW rules (including manual rules):"
echo "=================================================="
ufw status verbose

echo ""
echo "Security rules setup completed successfully."
