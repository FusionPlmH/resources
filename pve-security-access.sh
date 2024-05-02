#!/bin/bash
echo ""
echo "  Proxmox VE Access only for" 
echo "Cloudflared Tunnel and Tailscale"
echo "   Welcome to use This Tool "
echo "    Powered by FsuionPlmH"

if ! command -v ufw >/dev/null 2>&1; then
    if grep -Eqi "debian|ubuntu" /etc/issue* /proc/version* /etc/os-release*; then
        apt update && apt install -y ufw
    else
        echo "Not supported"
        exit 1
    fi
fi

for line in $(curl -s https://www.cloudflare.com/ips-v4)$(curl -s https://www.cloudflare.com/ips-v6); do
    ufw allow from $line to any port 443
done

ufw allow in out on tailscale0
ufw enable
