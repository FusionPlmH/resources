#!/bin/bash
echo ""
echo ""
echo "Proxmox VE Access only for Cloudflared Tunnel and Tailscale"
echo ""
echo ""
echo ""
echo "   Welcome to use This Tool "
echo ""
echo "    Power by FsuionPlmH"
if !command -v ufw >/dev/null 2>&1; then
if cat /etc/issue | grep -Eqi "debian"; then
    release="debian"
    apt update && apt install -y ufw
elif cat /etc/issue | grep -Eqi "ubuntu"; then
    release="ubuntu"
    apt update && apt install -y ufw
elif cat /proc/version | grep -Eqi "debian"; then
    release="debian"
    apt update && apt install -y ufw
elif cat /proc/version | grep -Eqi "ubuntu"; then
    release="ubuntu"
    apt update && apt install -y ufw
elif cat /etc/os-release | grep -Eqi "ubuntu"; then
    release="ubuntu"
    apt update && apt install -y ufw
elif cat /etc/os-release | grep -Eqi "debian"; then
    release="debian"
    apt update && apt install -y ufw
else
    echo "==============="
    echo "Not supported"
    echo "==============="
    exit
exit 1
fi
for line in `curl https://www.cloudflare.com/ips-v4`
do
  echo "Reading $line from CloudFlare's offical ip list."
  ufw allow from $line to any port 80
  ufw allow from $line to any port 443
  ufw allow from $line to any port 8006
done
for line in `curl https://www.cloudflare.com/ips-v6`
do
  echo "Reading $line from CloudFlare's offical ip list."
  ufw allow from $line to any port 80
  ufw allow from $line to any port 443
  ufw allow from $line to any port 8006
done
ufw allow in on tailscale0
ufw allow out on tailscale0
ufw enable
