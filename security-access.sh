#!/bin/bash
echo ""
echo "        Security access only for" 
echo "Cloudflared Tunnel , Tailscale and Local"
echo "        Welcome to use This Tool "
echo "         Powered by FsuionPlmH"


## Check support and install package
if ! command -v ufw >/dev/null 2>&1; then
    if grep -Eqi "debian|ubuntu" /etc/issue* /proc/version* /etc/os-release*; then
		echo "Your system is supported now install the tools"
        apt update && apt install -y ufw fail2ban
    else
        echo "Not supported"
        exit 1
    fi
fi


## Check Cloudflared
if command -v cloudflared >/dev/null 2>&1; then
    if systemctl is-active --quiet cloudflared; then
        echo "Cloudflared has Installed add into rule......"
		for line in $(curl -s https://www.cloudflare.com/ips-v4)$(curl -s https://www.cloudflare.com/ips-v6) ;do
			ufw allow from $line to any port 443
		done
    else
        echo "Cloudflared has Installed but Not in Active ......"
		echo "Skip Add rule for Cloudflared......"
    fi
else
    echo "Cloudflared Not Installed skip......"
fi

## Check Proxmox Virtual Environment
if nc -zv localhost 8006 2>&1 | grep -q 'open'; then
	echo "Proxmox Virtual Environment has Installed add into rule......"
	pve_ip_address=$(ip -4 addr show vmbr0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
	if [[ $pve_ip_address =~ ^10\. ]] ||
		[[ $pve_ip_address =~ ^172\.1[6-9]\. ]] ||
		[[ $pve_ip_address =~ ^172\.2[0-9]\. ]] ||
		[[ $pve_ip_address =~ ^172\.3[0-1]\. ]] ||
		[[ $pve_ip_address =~ ^192\.168\. ]]; then
		prefix=$(ip -o -f inet addr show dev vmbr0 | awk '{print $4}' | cut -d '/' -f 2)
		ip_range=$(ip -o -f inet addr show dev vmbr0 | awk '{print $4}' | cut -d '/' -f 1 | awk -F. '{OFS="."; $4=0; print}')
		cidr="$ip_range/$prefix"
		ufw allow from $cidr to any port 8006
	fi
else
    echo "Proxmox Virtual Environment Not Installed skip......"
fi

## Check Tailscale port
if ip a | grep -q 'tailscale0'; then
	echo "Tailscale has Installed add into rule......"
    ufw allow in out on tailscale0
else
    echo "Tailscale Not Installed skip......"
fi



echo "[ufw]" >> /etc/fail2ban/jail.conf
echo "enabled=true" >> /etc/fail2ban/jail.conf
echo "filter=ufw.aggressive" >> /etc/fail2ban/jail.conf
echo "action=iptables-allports" >> /etc/fail2ban/jail.conf
echo "logpath=/var/log/ufw.log" >> /etc/fail2ban/jail.conf
echo "maxretry=5" >> /etc/fail2ban/jail.conf
echo "bantime=7d" >> /etc/fail2ban/jail.conf


touch /etc/fail2ban/filter.d/ufw.aggressive.conf
echo "[Definition]" >> /etc/fail2ban/filter.d/ufw.aggressive.conf
echo "failregex = [UFW BLOCK].+SRC=<HOST> DST" >> /etc/fail2ban/filter.d/ufw.aggressive.conf
echo "ignoreregex =" >> /etc/fail2ban/filter.d/ufw.aggressive.conf


ufw enable
systemctl enable fail2ban
systemctl start fail2ban

