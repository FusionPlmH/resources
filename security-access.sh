#!/bin/bash
set -euo pipefail

# Color definitions for better UI
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}"
echo "        Security access only for" 
echo "     Cloudflare , Tailscale and Local"
echo "        Welcome to use This Tool"
echo "         Powered by FusionPlmH"
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
        apt-get update -qq && apt-get install -y -qq "$package"
    else
        echo -e "${GREEN}$package${NC} is already installed."
    fi
}

check_and_install ufw
check_and_install fail2ban

## 2. Initialize and Ensure UFW is Active First
echo "Initializing UFW default policies and enabling firewall..."
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
    echo -e "${YELLOW}Found legacy 443 port rules, cleaning up...${NC}"
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

# 3.2 Cleanup unqualified 8006 rules (rules not tied to vmbr0)
if ufw status 2>/dev/null | grep -v "on vmbr0" | grep -w -q "8006"; then
    echo -e "${YELLOW}Found unqualified 8006 legacy rules (without vmbr0 interface), cleaning up...${NC}"
    while ufw status numbered 2>/dev/null | grep -v "on vmbr0" | grep -w "8006" | grep -q "\["; do
        num=$(ufw status numbered 2>/dev/null | grep -v "on vmbr0" | grep -w "8006" | head -n1 | sed -E 's/.*\[ *([0-9]+)\].*/\1/')
        if [ -n "$num" ]; then
            echo "Deleting unqualified 8006 rule #$num..."
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
    echo -e "Cloudflare WARP/Mesh (${GREEN}$WARP_IF${NC}) is installed, adding rules..."
    ufw allow in on "$WARP_IF" to any >/dev/null 2>&1
    ufw allow out on "$WARP_IF" to any >/dev/null 2>&1
    echo -e "${GREEN}✓ Cloudflare WARP rules added successfully.${NC}"
else
    echo "Cloudflare WARP/Mesh not installed, skipping..."
fi

## 5. Check Proxmox Virtual Environment & Fully Adaptive CIDR Extraction
if (echo > /dev/tcp/127.0.0.1/8006) >/dev/null 2>&1; then
    echo "Proxmox Virtual Environment is active, parsing network configuration for adaptive subnets..."
    
    target_dev=""
    declare -a candidate_cidrs=()
    
    # 5.1 Parse vmbr0 configured subnets automatically
    if ip link show vmbr0 >/dev/null 2>&1; then
        while read -r vmbr_cidr; do
            if [[ -n "$vmbr_cidr" ]]; then
                candidate_cidrs+=("$vmbr_cidr")
            fi
        done < <(ip -4 -o addr show dev vmbr0 2>/dev/null | awk '{print $4}')
    fi
    
    # 5.2 Parse /etc/network/interfaces for physical device or iptables NAT routing device
    if [ -f /etc/network/interfaces ]; then
        bridge_val=$(awk '/^iface vmbr0/,/^iface|^auto|^mapping/ {if ($1=="bridge-ports") print $2}' /etc/network/interfaces | head -n1)
        
        if [ -n "$bridge_val" ] && [ "$bridge_val" != "none" ]; then
            target_dev="$bridge_val"
            echo "Found bridge-ports device: $target_dev"
        else
            iptables_line=$(awk '/^iface vmbr0/,/^iface|^auto|^mapping/ {if ($1=="post-up" && $0~/iptables/) print $0}' /etc/network/interfaces | head -n1)
            if [ -n "$iptables_line" ]; then
                target_dev=$(echo "$iptables_line" | sed -E 's/.*-o[[:space:]]+([a-zA-Z0-9_-]+).*/\1/')
                echo "Extracted physical interface from iptables rule: $target_dev"
            fi
        fi
    fi
    
    # 5.3 Obtain subnet from the physical interface if available
    if [ -n "$target_dev" ] && ip link show "$target_dev" >/dev/null 2>&1; then
        while read -r phys_cidr; do
            if [[ -n "$phys_cidr" ]]; then
                candidate_cidrs+=("$phys_cidr")
            fi
        done < <(ip -4 route show dev "$target_dev" 2>/dev/null | awk '/proto kernel/ {print $1}')
    fi
    
    # 5.4 Fallback to default route interface if nothing found
    if [ ${#candidate_cidrs[@]} -eq 0 ]; then
        default_dev=$(ip -4 route show default 2>/dev/null | awk '/default/ {print $5}' | head -n1 || true)
        if [ -n "$default_dev" ]; then
            while read -r def_cidr; do
                if [[ -n "$def_cidr" ]]; then
                    candidate_cidrs+=("$def_cidr")
                fi
            done < <(ip -4 route show dev "$default_dev" 2>/dev/null | awk '/proto kernel/ {print $1}')
        fi
    fi
    
    # 5.5 Deduplicate and apply UFW rules adaptively for private subnets only
    applied_count=0
    for raw_cidr in "${candidate_cidrs[@]}"; do
        # Validate CIDR format
        if [[ "$raw_cidr" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
            # Verify if it is a private IP range (RFC 1918)
            if [[ "$raw_cidr" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.) ]]; then
                echo -e "Allowing PVE web management on vmbr0 from adaptive subnet: ${GREEN}$raw_cidr${NC}..."
                ufw allow in on vmbr0 from "$raw_cidr" to any port 8006 >/dev/null 2>&1
                ((applied_count++))
            fi
        fi
    done
    
    if [ "$applied_count" -gt 0 ]; then
        echo -e "${GREEN}✓ PVE 8006 adaptive rules added successfully ($applied_count subnets allowed).${NC}"
    else
        echo -e "${YELLOW}Warning: No valid private subnets dynamically detected for 8006 exposure.${NC}"
    fi
else
    echo "Proxmox Virtual Environment not active or not installed, skipping..."
fi

## 6. Check Tailscale interface
if ip link show tailscale0 >/dev/null 2>&1; then
    echo -e "Tailscale is installed, adding rules..."
    ufw allow in on tailscale0 to any >/dev/null 2>&1
    ufw allow out on tailscale0 to any >/dev/null 2>&1
    echo -e "${GREEN}✓ Tailscale rules added successfully.${NC}"
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
systemctl enable fail2ban >/dev/null 2>&1
systemctl restart fail2ban >/dev/null 2>&1

echo ""
echo "=================================================="
echo -e "${GREEN}Current active UFW rules:${NC}"
echo "=================================================="
ufw status verbose

echo ""
echo -e "${GREEN}Security rules setup completed successfully!${NC}"
