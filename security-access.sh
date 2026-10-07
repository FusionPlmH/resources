#!/bin/bash
set -euo pipefail

# Color definitions for better UI
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}"
echo "        Security access only for" 
echo "     Cloudflare , Tailscale and Local"
echo "        Welcome to use This Tool"
echo "          Powered by FusionPlmH"
echo -e "${NC}"

# 0. Permission check
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: Please run this script with root privileges (e.g. sudo).${NC}"
  exit 1
fi

## 1. Check support and install package
check_and_install() {
    local package=$1
    if ! dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q "install ok installed"; then
        echo -e "Installing ${YELLOW}$package${NC}..."
        apt-get update -qq && apt-get install -y -qq "$package" >/dev/null 2>&1
    else
        echo -e "${GREEN}$package${NC} is already installed."
    fi
}

check_and_install ufw
check_and_install fail2ban

## 2. Initialize and Ensure UFW is Active First
echo "Initializing UFW policies..."
systemctl enable ufw >/dev/null 2>&1 || true
systemctl start ufw >/dev/null 2>&1 || true
ufw default deny incoming >/dev/null 2>&1 || true
ufw default allow outgoing >/dev/null 2>&1 || true
ufw logging low >/dev/null 2>&1 || true
ufw --force enable >/dev/null 2>&1 || true

## 3. Safely check and clean legacy port rules (443 & unqualified 8006)
echo "Checking existing UFW rules for legacy entries..."

# 3.1 Cleanup legacy 443 rules
if ufw status 2>/dev/null | grep -w -q "443"; then
    echo -e "${YELLOW}Cleaning up legacy 443 rules...${NC}"
    while ufw status numbered 2>/dev/null | grep -w "443" | grep -q "\["; do
        num=$(ufw status numbered 2>/dev/null | grep -w "443" | head -n1 | sed -E 's/.*\[ *([0-9]+)\].*/\1/')
        if [ -n "$num" ]; then
            echo "y" | ufw delete "$num" >/dev/null 2>&1 || break
        else
            break
        fi
    done
fi

# 3.2 Cleanup unqualified 8006 rules
if ufw status 2>/dev/null | grep -v "on vmbr" | grep -v "on wlp" | grep -w -q "8006"; then
    echo -e "${YELLOW}Cleaning up unqualified 8006 legacy rules...${NC}"
    while ufw status numbered 2>/dev/null | grep -v "on vmbr" | grep -v "on wlp" | grep -w "8006" | grep -q "\["; do
        num=$(ufw status numbered 2>/dev/null | grep -v "on vmbr" | grep -v "on wlp" | grep -w "8006" | head -n1 | sed -E 's/.*\[ *([0-9]+)\].*/\1/')
        if [ -n "$num" ]; then
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
    echo -e "Configuring Cloudflare WARP/Mesh (${GREEN}$WARP_IF${NC})..."
    ufw allow in on "$WARP_IF" to any >/dev/null 2>&1 || true
    ufw allow out on "$WARP_IF" to any >/dev/null 2>&1 || true
    echo -e "${GREEN}✓ Cloudflare WARP rules applied.${NC}"
else
    echo "Cloudflare WARP/Mesh not installed, skipping..."
fi

## 5. Check Proxmox Virtual Environment & Smart Routing-Based Discovery
if (echo > /dev/tcp/127.0.0.1/8006) >/dev/null 2>&1; then
    echo "Proxmox Virtual Environment is active, determining active network interface via routing table..."
    
    applied_count=0
    vmbr0_block=$(awk '/^iface vmbr0/,/^$/' /etc/network/interfaces 2>/dev/null || true)
    
    # 判斷 vmbr0 是實體橋接還是純內部 bridge-ports none
    if echo "$vmbr0_block" | grep -q "bridge-ports\s\+none"; then
        echo "vmbr0 is in internal mode (bridge-ports none). Finding active default gateway interface..."
        
        # 核心新思路：直接從系統路由表中找出當前預設對外的網卡名稱（例如 wlp1s0f0 或 enp3s0）
        active_iface=$(ip -4 route show default 2>/dev/null | awk '/default/ {print $5}' | head -n1 || true)
        
        if [ -z "$active_iface" ]; then
            active_iface="wlp1s0f0" # 若取不到則預設退回你的網卡名稱
        fi
        
        # 自動抓取該網卡的 IP 與 CIDR 網段
        iface_cidr=$(ip -4 addr show dev "$active_iface" 2>/dev/null | awk '/inet / {print $2}' | head -n1 || true)
        nat_subnet=""
        
        if [ -n "$iface_cidr" ]; then
            iface_ip=$(echo "$iface_cidr" | cut -d/ -f1)
            nat_subnet=$(echo "$iface_ip" | awk -F. '{print $1"."$2"."$3".0/24"}')
        fi
        
        # 如果路由介面沒抓到，退回檢查 vmbr0 自身的 IP
        if [ -z "$nat_subnet" ]; then
            vmbr0_cidr=$(ip -4 addr show dev vmbr0 2>/dev/null | awk '/inet / {print $2}' | head -n1 || true)
            if [ -n "$vmbr0_cidr" ]; then
                vmbr0_ip=$(echo "$vmbr0_cidr" | cut -d/ -f1)
                nat_subnet=$(echo "$vmbr0_ip" | awk -F. '{print $1"."$2"."$3".0/24"}')
            fi
        fi
        
        if [ -n "$nat_subnet" ]; then
            echo -e "Detected active interface: ${GREEN}$active_iface${NC}, Subnet: ${GREEN}$nat_subnet${NC}"
            ufw allow in on "$active_iface" from "$nat_subnet" to any port 8006 >/dev/null 2>&1 || true
            applied_count=$((applied_count + 1))
        else
            echo -e "${YELLOW}Warning: Could not determine subnet for active interface.${NC}"
        fi
    else
        # 標準橋接模式：提取 bridge-ports 後面的實體網卡
        physical_port=$(echo "$vmbr0_block" | grep "bridge-ports" | awk '{print $2}' || true)
        if [ -z "$physical_port" ]; then
            physical_port="vmbr0"
        fi
        echo -e "vmbr0 has physical binding (${GREEN}$physical_port${NC}). Extracting CIDR from this interface..."
        
        ips=$(ip -4 addr show dev "$physical_port" 2>/dev/null | awk '/inet / {print $2}' || true)
        if [ -z "$ips" ]; then
            ips=$(ip -4 addr show dev vmbr0 2>/dev/null | awk '/inet / {print $2}' || true)
        fi
        
        for cidr in $ips; do
            if [[ -n "$cidr" ]]; then
                local_ip=$(echo "$cidr" | cut -d/ -f1)
                subnet_prefix=$(echo "$local_ip" | awk -F. '{print $1"."$2"."$3".0/24"}')
                if [[ "$subnet_prefix" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.) ]]; then
                    echo -e "Allowing PVE web management on ${GREEN}$physical_port${NC} from detected subnet: ${GREEN}$subnet_prefix${NC}..."
                    ufw allow in on "$physical_port" from "$subnet_prefix" to any port 8006 >/dev/null 2>&1 || true
                    applied_count=$((applied_count + 1))
                fi
            fi
        done
    fi

    if [ "$applied_count" -gt 0 ]; then
        echo -e "${GREEN}✓ PVE 8006 adaptive rules applied successfully.${NC}"
    else
        echo -e "${YELLOW}Warning: No valid private subnets detected for 8006 exposure.${NC}"
    fi
else
    echo "Proxmox Virtual Environment not active or not installed, skipping..."
fi

## 6. Check Tailscale interface
if ip link show tailscale0 >/dev/null 2>&1; then
    echo -e "Configuring Tailscale rules..."
    ufw allow in on tailscale0 to any >/dev/null 2>&1 || true
    ufw allow out on tailscale0 to any >/dev/null 2>&1 || true
    echo -e "${GREEN}✓ Tailscale rules applied.${NC}"
else
    echo "Tailscale not installed, skipping..."
fi

## 7. Setting Up Fail2ban
echo "Configuring Fail2ban protection..."
touch /var/log/ufw.log >/dev/null 2>&1 || true

tee /etc/fail2ban/jail.local > /dev/null <<'EOF'
[sshd]
enabled = true
port = ssh
filter = sshd
backend = systemd
maxretry = 5
findtime = 1d
bantime = 7d

[proxmox]
enabled = true
port = https,http,8006
filter = proxmox
backend = systemd
maxretry = 3
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

tee /etc/fail2ban/filter.d/proxmox.conf > /dev/null <<'EOF'
[Definition]
failregex = pveproxy\[.*authentication failure; rhost=<HOST>.*
ignoreregex =
EOF

tee /etc/fail2ban/filter.d/ufw-aggressive.conf > /dev/null <<'EOF'
[Definition]
failregex = \[UFW BLOCK\].*SRC=<HOST> DST
ignoreregex =
EOF

## 8. Reload UFW & Restart Fail2ban
ufw reload >/dev/null 2>&1 || true
systemctl enable fail2ban >/dev/null 2>&1 || true
systemctl restart fail2ban >/dev/null 2>&1 || true

## Enable autorun on every network reboot
INTERFACES_FILE="/etc/network/interfaces"
if [ -f "$INTERFACES_FILE" ]; then
    if ! grep -q "security-access.sh" "$INTERFACES_FILE"; then
        echo "Adding auto-update post-up hook to /etc/network/interfaces..."
        sed -i '/post-down iptables.*MASQUERADE/a \
        post-up    wget -qO /usr/local/bin/security-access.sh https://raw.githubusercontent.com/FusionPlmH/resources/main/security-access.sh && chmod +x /usr/local/bin/security-access.sh && /usr/local/bin/security-access.sh' "$INTERFACES_FILE"
    fi
fi

echo ""
echo "=================================================="
echo -e "${GREEN}Current active UFW rules:${NC}"
echo "=================================================="
ufw status verbose || true

echo ""
echo -e "${GREEN}Security rules setup completed successfully!${NC}"
