#!/bin/bash
echo ""
echo "        Security access only for" 
echo "Cloudflared Tunnel , Tailscale and Local"
echo "        Welcome to use This Tool "
echo "         Powered by FsuionPlmH"


## Check support and install package
check_and_install() {
    package=$1
    if !  dpkg-query -W -f='${Status}' $package 2>/dev/null | grep -q "install ok installed"; then
        if grep -Eqi "debian|ubuntu" /etc/issue* /proc/version* /etc/os-release*; then
            echo "Your system is supported. Now installing $package..."
            sudo apt update && sudo apt install -y $package
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



echo "Setting Up Fail2ban......"
echo "[ufw]" >> /etc/fail2ban/jail.local
echo "enabled=true" >> /etc/fail2ban/jail.local
echo "filter=ufw.aggressive" >> /etc/fail2ban/jail.local
echo "action=iptables-allports" >> /etc/fail2ban/jail.local
echo "logpath=/var/log/ufw.log" >> /etc/fail2ban/jail.local
echo "maxretry=5" >> /etc/fail2ban/jail.local
echo "bantime=7d" >> /etc/fail2ban/jail.local


touch /etc/fail2ban/filter.d/ufw.aggressive.conf
echo "[Definition]" >> /etc/fail2ban/filter.d/ufw.aggressive.conf
echo "failregex = [UFW BLOCK].+SRC=<HOST> DST" >> /etc/fail2ban/filter.d/ufw.aggressive.conf
echo "ignoreregex =" >> /etc/fail2ban/filter.d/ufw.aggressive.conf




touch /etc/fail2ban/filter.d/ufw.aggressive.conf
echo "[Definition]" >> /etc/fail2ban/filter.d/ufw.aggressive.conf
echo "failregex = [UFW BLOCK].+SRC=<HOST> DST" >> /etc/fail2ban/filter.d/ufw.aggressive.conf
echo "ignoreregex =" >> /etc/fail2ban/filter.d/ufw.aggressive.conf


ufw enable
systemctl enable fail2ban
systemctl start fail2ban

