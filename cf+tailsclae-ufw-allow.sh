#!/bin/bash

echo "Proxmox VE Access only for Cloudflared Tunnel and Tailscale"
echo "Welcome to use This Tool"
echo "Powered by FsuionPlmH"

if ! command -v ufw >/dev/null 2>&1; then
    if grep -Eqi "debian|ubuntu" /etc/issue* /proc/version* /etc/os-release*; then
        release=$(grep -Eo "debian|ubuntu" /etc/issue* /proc/version* /etc/os-release* | head -1)
        apt update && apt install -y ufw
    else
        echo "Not supported"
        exit 1
    fi
fi

for line in $(curl -s https://www.cloudflare.com/ips-v4); do
    echo "Reading $line from CloudFlare's official IP list."
    ufw allow from $line to any port 80,443,8006
done

for line in $(curl -s https://www.cloudflare.com/ips-v6); do
    echo "Reading $line from CloudFlare's official IP list."
    ufw allow from $line to any port 80,443,8006
done

ufw allow in on tailscale0
ufw allow out on tailscale0
ufw enable
