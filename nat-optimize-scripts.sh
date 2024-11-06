#!/bin/bash

# Define constants
PAM_LIMITS="/etc/p.d/common-session"
LIMITS_CONF="/etc/security/limits.conf"
SYSCTL_CONF="/etc/sysctl.conf"
INTERFACE="ens19"
LOG_FILE="/var/log/system_tuning.log"

# Set up logging
exec > >(tee -i "$LOG_FILE") 2>&1

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Function to check and install a package
check_and_install() {
    package=$1
    if ! dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q "install ok installed"; then
        if grep -Eqi "debian|ubuntu" /etc/issue* /proc/version* /etc/os-release*; then
            echo "Installing $package..."
            if ! apt update -qq && apt install -yqq "$package"; then
                echo "Error: Failed to install $package"
                exit 1
            fi
        else
            echo "$package not supported on this system."
            exit 1
        fi
    else
        echo "$package is already installed."
    fi
}

# Function to run commands silently
run_command() {
  echo "Running: $*" # Show the command being run
  if ! "$@" > /dev/null 2>&1; then
      echo "Error: Command '$*' failed"
      exit 1
  fi
}

# Function to check and install required packages
check_required_packages() {
    local packages=("wget" "gpg" "ufw" "sed" "iproute2" "iptables")

    for package in "${packages[@]}"; do
        check_and_install "$package"
    done
}

# Function to check and create sysctl.conf if not exists
check_sysctl() {
  [ ! -f "$SYSCTL_CONF" ] && touch "$SYSCTL_CONF"
}

# Function to remove existing entries from sysctl.conf
remove_existing_entries() {
  local keys=(
    "net.core.default_qdisc"
    "net.ipv4.tcp_congestion_control"
    "net.ipv4.ip_forward"
    "net.ipv4.conf.all.rp_filter"
    "net.ipv4.icmp_echo_ignore_broadcasts"
    "net.ipv4.conf.default.forwarding"
    "net.ipv4.conf.default.proxy_arp"
    "net.ipv4.conf.default.send_redirects"
    "net.ipv4.conf.all.send_redirects"
    "net.ipv6.conf.all.disable_ipv6"
    "net.ipv6.conf.default.disable_ipv6"
    "fs.file-max"
    "net.core.somaxconn"
    "net.ipv4.tcp_max_tw_buckets"
    "net.ipv4.ip_local_port_range"
    "net.ipv4.tcp_moderate_rcvbuf"
    "net.ipv4.tcp_window_scaling"
    "net.core.rmem_max"
    "net.core.wmem_max"
    "net.core.rmem_default"
    "net.ipv4.tcp_rmem"
    "net.ipv4.tcp_wmem"
    "net.ipv4.tcp_fastopen"
    "net.core.netdev_max_backlog"
    "net.ipv4.tcp_max_syn_backlog"
    "net.ipv4.tcp_syncookies"
    "net.ipv4.tcp_retries2"
    "net.ipv4.tcp_syn_retries"
    "net.ipv4.tcp_synack_retries"
    "net.ipv4.tcp_fin_timeout"
    "net.core.optmem_max"
    "net.ipv4.udp_mem"
    "net.ipv4.udp_rmem_min"
    "net.ipv4.udp_wmem_min"
  )

  for key in "${keys[@]}"; do
    sed -i "\|^$key|d" "$SYSCTL_CONF"
  done
}

# Function to apply ulimit and other configurations
ulimited_tuning() {
  check_sysctl

  # Enable 'session required pam_limits.so'
  grep -q 'pam_limits.so' "$PAM_LIMITS" || echo 'session required pam_limits.so' >> "$PAM_LIMITS"

  # Update limits.conf
  {
    echo '* soft nofile 65535'
    echo '* hard nofile 65535'
    echo '* soft nproc 65536'
    echo '* hard nproc 65536'
    echo '* soft memlock unlimited'
    echo '* hard memlock unlimited'
  } > "$LIMITS_CONF"

  # Set ulimit in profile if not set
  grep -q "ulimit" /etc/profile || echo "ulimit -SHn 65535" >> /etc/profile

  # Apply ulimit settings
  ulimit -SHn 65535 && ulimit -c unlimited
}

# Function to apply TCP/UDP tuning
tcp_udp_tuning() {
  check_sysctl
  remove_existing_entries

  # Add TCP and network settings
  cat << EOF >> "$SYSCTL_CONF"
# General network settings
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.default.forwarding=1
net.ipv4.conf.default.proxy_arp=0
net.ipv4.conf.default.send_redirects=1
net.ipv4.conf.all.send_redirects=0
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
fs.file-max=65535

# TCP settings for performance
net.core.somaxconn=65535
net.ipv4.tcp_max_tw_buckets=2000000
net.ipv4.ip_local_port_range=10240 65000
net.ipv4.tcp_moderate_rcvbuf=1
net.ipv4.tcp_window_scaling=1
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.core.rmem_default=16777216
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.ipv4.tcp_fastopen=3
net.core.netdev_max_backlog=250000
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_retries2=8
net.ipv4.tcp_syn_retries=3
net.ipv4.tcp_synack_retries=3
net.ipv4.tcp_fin_timeout=15

# UDP settings
net.core.optmem_max=25165824
net.ipv4.udp_mem=65536 131072 262144
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192
EOF
}

# Function to reload sysctl settings
reload_sysctl() {
  run_command sysctl -p
  run_command sysctl --system
}

# Function to install Xanmod kernel
install_xanmod_kernel() {
  run_command wget -qO - https://dl.xanmod.org/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg
  echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-release.list
  run_command apt update -qq
  run_command apt install -yqq linux-xanmod-rt-x64v3
}

# Function to configure GRUB
configure_grub() {
  run_command sed -i 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=1/' /etc/default/grub
  run_command update-grub
}

# Function to configure network interface
configure_network() {
  local config_file="/etc/network/interfaces"
  
  if ip link show | grep -q "$INTERFACE"; then
    echo "Configuring $INTERFACE..."

    # Backup current configuration
    cp "$config_file" "${config_file}.bak"

    # Edit interface configuration
    sed -i "/iface $INTERFACE inet/d" "$config_file"
    sed -i "/auto $INTERFACE/d" "$config_file"

    # Add new configuration
    {
      echo "auto $INTERFACE"
      echo "iface $INTERFACE inet static"
      echo "    address 10.10.10.1/24"
      echo "    netmask 255.255.255.0"
      echo "    post-up echo 1 > /proc/sys/net/ipv4/ip_forward"
      echo "    post-up iptables -t nat -A POSTROUTING -s '10.10.10.0/24' -j MASQUERADE"
      echo "    post-down iptables -t nat -D POSTROUTING -s '10.10.10.0/24' -j MASQUERADE"
    } >> "$config_file"

    # Restart networking
    run_command systemctl restart networking
  else
    echo "Interface $INTERFACE not found."
  fi
}

# Function to install and configure UFW
configure_firewall() {
  echo "Installing and configuring UFW..."
  run_command apt update -qq
  run_command apt install -yqq ufw

  # Allow SSH
  run_command ufw allow ssh

  # Deny ping
  echo "Blocking ICMP (ping)..."
  echo "net.ipv4.icmp_echo_ignore_all=1" >> "$SYSCTL_CONF"
  run_command sysctl -p

  # Enable UFW
  run_command ufw enable
}

# Main function to execute all scripts
main() {
  check_required_packages
  configure_network
  configure_firewall
  ulimited_tuning
  tcp_udp_tuning
  reload_sysctl
  install_xanmod_kernel
  configure_grub
}

# Run the main function
main
echo "System tuning and Xanmod kernel installation complete. Please reboot your system."
