#!/bin/bash
set -euo pipefail

echo ""
echo "        Security access only for" 
echo "Cloudflared Tunnel, Tailscale and Local"
echo "        Welcome to use This Tool"
echo "         Powered by FsuionPlmH"

## Check support and install package
check_and_install() {
    package=$1
    if ! dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q "install ok installed"; then
        if grep -Eqi "debian|ubuntu" /etc/issue* /proc/version* /etc/os-release*; then
            echo "Your system is supported. Now installing $package..."
            sudo apt update && sudo apt install -y "$package"
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

## Check Cloudflared
if command -v cloudflared >/dev/null 2>&1; then
    if systemctl is-active --quiet cloudflared; then
        echo "Cloudflared has been installed, adding rules..."
        # 使用空格分隔 curl 输出的多个 IP
        for line in $(curl -s https://www.cloudflare.com/ips-v4) $(curl -s https://www.cloudflare.com/ips-v6); do
            ufw allow from "$line" to any port 443
        done
    else
        echo "Cloudflared installed but not active. Skipping rule addition..."
    fi
else
    echo "Cloudflared not installed, skipping..."
fi

## Check Proxmox Virtual Environment
if nc -zv localhost 8006 2>&1 | grep -q 'open'; then
    echo "Proxmox Virtual Environment is installed, adding rules..."
    pve_ip_address=$(ip -4 addr show vmbr0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || true)
    if [[ -n "$pve_ip_address" ]] && ( [[ $pve_ip_address =~ ^10\. ]] || [[ $pve_ip_address =~ ^172\.1[6-9]\. ]] || [[ $pve_ip_address =~ ^172\.2[0-9]\. ]] || [[ $pve_ip_address =~ ^172\.3[0-1]\. ]] || [[ $pve_ip_address =~ ^192\.168\. ]] ); then
        prefix=$(ip -o -f inet addr show dev vmbr0 | awk '{print $4}' | cut -d '/' -f2)
        ip_range=$(ip -o -f inet addr show dev vmbr0 | awk '{print $4}' | cut -d '/' -f1 | awk -F. '{OFS="."; $4=0; print}')
        cidr="$ip_range/$prefix"
        ufw allow from "$cidr" to any port 8006
    else
        echo "vmbr0 interface not found or IP is out of expected range, skipping Proxmox rule..."
    fi
else
    echo "Proxmox Virtual Environment not installed, skipping..."
fi

## Check Tailscale port
if ip a | grep -q 'tailscale0'; then
    echo "Tailscale is installed, adding rules..."
    ufw allow in out on tailscale0
else
    echo "Tailscale not installed, skipping..."
fi

sudo ufw default deny incoming
sudo ufw default allow outgoing

echo "Setting Up Fail2ban..."

sudo tee /etc/fail2ban/jail.local > /dev/null <<'EOF'
[ufw]
enabled = true
filter = ufw-aggressive
action = iptables-allports
logpath = /var/log/ufw.log
maxretry = 5
bantime = 7d
EOF

sudo tee /etc/fail2ban/filter.d/ufw-aggressive.conf > /dev/null <<'EOF'
[Definition]
failregex = \[UFW BLOCK\].*SRC=<HOST> DST
ignoreregex =
EOF

sudo ufw --force enable

sudo systemctl enable fail2ban
sudo systemctl restart fail2ban
