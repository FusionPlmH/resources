#!/bin/bash
#===============================================================================
# security-access.sh
#
# DESIGN
# ------
# Goal: expose this host on exactly two TCP ports (8006 and SSH) and only to
#       three trusted paths: the local LAN, cloudflared, and tailscale0.
#
# 1. Policy model
#    - inbound : default DROP, explicit "interface + port" allow rules only.
#    - outbound: default ACCEPT. cloudflared needs 7844/tcp+udp to the edge,
#      tailscale needs 41641/udp and 443/tcp (DERP), plus DNS. Denying egress
#      would break the very paths this script is supposed to allow.
#    - forward : UFW defaults it to DROP; re-opened only when NAT is detected
#      so that guests keep their internet access.
#
# 2. Interface selection (why vmbr0 and not eno1)
#    Traffic addressed to the host's bridge IP enters the input chain with
#    IN=vmbr0. The physical member (e.g. "bridge-ports eno1") never matches,
#    so per-port rules must be attached to the L3 interface, not the member.
#
# 3. Source selection
#    LAN rules are scoped to "from <link subnet of that interface>". The subnet
#    is read from the routing table (ip route ... scope link), so /16, /22 or
#    /25 networks are handled correctly. An interface is only treated as LAN
#    when it owns a private (RFC1918) address.
#
# 4. Order of operations
#    allow rules -> legacy cleanup -> default policies -> ufw enable.
#    Enabling UFW before the allow rules exist can lock the operator out.
#
# 5. Overlay paths
#    - tailscale0 : 8006 + SSH from the tailnet.
#    - cloudflared: the connector dials out and re-enters through loopback
#      (lo); inside a container it arrives on docker0/br-* instead.
#    - WARP/mesh  : CloudflareWARP / warp0 / cloudflared* tunnel interfaces.
#
# 6. Fail2ban safety
#    A fail2ban ban is inserted at the top of the ufw chains and therefore
#    overrides allow rules. RFC1918, CGNAT (100.64.0.0/10) and the Tailscale
#    IPv6 prefix are listed in ignoreip so internal clients are never banned.
#===============================================================================
set -euo pipefail

# Color definitions for better UI
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info() { echo -e "${GREEN}$*${NC}"; }
warn() { echo -e "${YELLOW}$*${NC}"; }
error() { echo -e "${RED}$*${NC}"; }

PVE_PORT="${PVE_PORT:-8006}"
TS_SUBNET_ROUTING="${TS_SUBNET_ROUTING:-0}"
TS_DIRECT_UDP="${TS_DIRECT_UDP:-0}"

echo -e "${GREEN}"
echo "        Security access only for"
echo "     Cloudflare , Tailscale and Local"
echo "        Welcome to use This Tool"
echo "          Powered by FusionPlmH"
echo -e "${NC}"

# 0. Permission check
if [ "$EUID" -ne 0 ]; then
  error "Error: Please run this script with root privileges (e.g. sudo)."
  exit 1
fi

## 1. Check support and install package
check_and_install() {
    local package=$1
    if ! dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q "install ok installed"; then
        warn "Installing $package..."
        if ! { apt-get update -qq && apt-get install -y -qq "$package" >/dev/null 2>&1; }; then
            error "Failed to install $package."
            return 1
        fi
    else
        info "$package is already installed."
    fi
    return 0
}

check_and_install ufw || { error "ufw is mandatory, aborting."; exit 1; }
HAVE_FAIL2BAN=0
if check_and_install fail2ban; then
    HAVE_FAIL2BAN=1
fi

## 2. Helpers
# Only RFC1918 addresses are treated as "internal".
is_private_v4() {
    case "${1:-}" in
        10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;
    esac
    return 1
}

# Overlay / virtual interfaces are handled explicitly, not via subnet matching.
is_overlay_iface() {
    case "${1:-}" in
        lo|tailscale*|warp*|CloudflareWARP*|cloudflared*|wg*|tun*|tap*|docker*|br-*|veth*|virbr*|zt*) return 0 ;;
    esac
    return 1
}

iface_exists() {
    ip link show "$1" >/dev/null 2>&1
}

# Real prefix length from the routing table; never assume /24.
iface_v4_nets() {
    ip -4 route show dev "$1" scope link 2>/dev/null \
        | awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/ {print $1}'
}

iface_v4_addrs() {
    ip -4 -o addr show dev "$1" scope global 2>/dev/null | awk '{print $4}'
}

# Actual listening SSH port(s) so a non-default port keeps working.
detect_ssh_ports() {
    local ports=""
    if command -v ss >/dev/null 2>&1; then
        ports=$(ss -H -lntp 2>/dev/null \
            | awk '/sshd/ {print $4}' \
            | sed -E 's/.*:([0-9]+)$/\1/' \
            | grep -E '^[0-9]+$' | sort -un | tr '\n' ' ' || true)
    fi
    echo "${ports:-22 }"
}

# Allowed TCP ports: Proxmox web UI plus every real SSH port.
ALLOW_PORTS=("$PVE_PORT")
for port in $(detect_ssh_ports); do
    if [ "$port" != "$PVE_PORT" ]; then
        ALLOW_PORTS+=("$port")
    fi
done

# Allow the management ports in/out of one interface.
# $1 = interface, $2 = optional source CIDR (empty means any source).
allow_mgmt() {
    local ifc="$1" src="${2:-}" port
    if ! iface_exists "$ifc"; then
        return 0
    fi
    for port in "${ALLOW_PORTS[@]}"; do
        if [ -n "$src" ]; then
            ufw allow in on "$ifc" from "$src" to any port "$port" proto tcp >/dev/null 2>&1 \
                || warn "  failed: allow in on $ifc from $src port $port"
        else
            ufw allow in on "$ifc" to any port "$port" proto tcp >/dev/null 2>&1 \
                || warn "  failed: allow in on $ifc port $port"
        fi
        # Documentation value while the default outbound policy stays ACCEPT.
        ufw allow out on "$ifc" to any port "$port" proto tcp >/dev/null 2>&1 || true
    done
}

# Delete rules by pattern, highest index first so numbering does not shift.
delete_rules_matching() {
    local pattern="$1" numbers number
    numbers=$(ufw status numbered 2>/dev/null \
        | grep -E "$pattern" \
        | sed -nE 's/^\[ *([0-9]+)\].*/\1/p' | sort -rn || true)
    if [ -z "$numbers" ]; then
        return 0
    fi
    for number in $numbers; do
        ufw --force delete "$number" >/dev/null 2>&1 || true
    done
}

MANAGED_IFACES=()
add_managed() {
    local entry="$1|${2:-}" existing
    for existing in ${MANAGED_IFACES[@]+"${MANAGED_IFACES[@]}"}; do
        if [ "$existing" = "$entry" ]; then
            return 0
        fi
    done
    MANAGED_IFACES+=("$entry")
}

## 3. Collect managed interfaces
info "Detecting management interfaces..."

# 3.1 LAN: any physical or bridge interface holding a private IPv4 address.
while read -r ifc; do
    if [ -z "$ifc" ]; then continue; fi
    if is_overlay_iface "$ifc"; then continue; fi

    matched=0
    while read -r net; do
        if [ -z "$net" ]; then continue; fi
        if is_private_v4 "${net%%/*}"; then
            add_managed "$ifc" "$net"
            matched=1
        fi
    done <<< "$(iface_v4_nets "$ifc")"

    # Fallback when no scope-link route is present: allow any source, still
    # limited to the two management ports.
    if [ "$matched" -eq 0 ]; then
        while read -r addr; do
            if [ -z "$addr" ]; then continue; fi
            if is_private_v4 "${addr%%/*}"; then
                add_managed "$ifc" ""
                matched=1
            fi
        done <<< "$(iface_v4_addrs "$ifc")"
    fi

    if [ "$matched" -eq 1 ]; then
        info "  LAN interface: $ifc"
    fi
done < <(ip -4 -o addr show scope global 2>/dev/null | awk '{print $2}' | sort -u)

# 3.2 Tailscale and Cloudflare tunnel / WARP interfaces.
for ifc in tailscale0 CloudflareWARP warp0 cloudflared; do
    if iface_exists "$ifc"; then
        add_managed "$ifc" ""
        info "  Overlay interface: $ifc"
    fi
done
while read -r ifc; do
    if [ -z "$ifc" ]; then continue; fi
    case "$ifc" in
        warp*|cloudflared*|CloudflareWARP*)
            add_managed "$ifc" ""
            info "  Overlay interface: $ifc"
            ;;
    esac
done < <(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | tr -d ' ' | sort -u)

# 3.3 cloudflared origin path: loopback, plus Docker bridges when the
#     connector runs as a container.
add_managed lo ""
while read -r ifc; do
    if [ -z "$ifc" ]; then continue; fi
    case "$ifc" in
        docker0|br-*)
            add_managed "$ifc" ""
            info "  Container origin interface: $ifc"
            ;;
    esac
done < <(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | tr -d ' ' | sort -u)

if [ "${#MANAGED_IFACES[@]}" -eq 0 ]; then
    error "No manageable interface found, aborting to avoid a lockout."
    exit 1
fi

## 4. Apply allow rules (always before enabling UFW)
if (echo > "/dev/tcp/127.0.0.1/${PVE_PORT}") >/dev/null 2>&1; then
    info "Proxmox VE detected on port ${PVE_PORT}."
else
    warn "Port ${PVE_PORT} is not listening; applying rules anyway."
fi

info "Applying rules (ports: ${ALLOW_PORTS[*]} /tcp)..."
for entry in ${MANAGED_IFACES[@]+"${MANAGED_IFACES[@]}"}; do
    allow_mgmt "${entry%%|*}" "${entry#*|}"
done

## 5. Cleanup legacy rules
# Only rules without an interface qualifier are removed; the interface-scoped
# rules created above can never match this pattern.
echo "Checking existing UFW rules for legacy entries..."
delete_rules_matching '^\[ *[0-9]+\] +(8006|8006/tcp) +ALLOW (IN|OUT) +Anywhere( \(v6\))? *$'

# Rules attached to a bridge member (eno1, ...) can never match host traffic.
for member in $(awk '/^[[:space:]]*bridge-ports[[:space:]]/ {for (i=2; i<=NF; i++) if ($i != "none") print $i}' \
                    /etc/network/interfaces /etc/network/interfaces.d/* 2>/dev/null | sort -u || true); do
    delete_rules_matching "^\\[ *[0-9]+\\] +(8006|8006/tcp) +on ${member} +ALLOW IN"
done

## 6. Default policies and enable UFW
echo "Initializing UFW policies..."
systemctl enable ufw >/dev/null 2>&1 || true
systemctl start ufw >/dev/null 2>&1 || true
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw logging low >/dev/null
ufw --force enable >/dev/null
info "UFW enabled; inbound limited to ${ALLOW_PORTS[*]}."

## 7. Preserve forwarding
WAN_IF="$(ip -4 route show default 2>/dev/null | awk '/default/ {print $5; exit}' || true)"

# Internal NAT hosts must keep vmbr0 -> WAN forwarding, otherwise guests lose
# their internet access once the forward policy becomes DROP.
if grep -rqE '(post-up|pre-up|post-down).*MASQUERADE' /etc/network/interfaces /etc/network/interfaces.d/ 2>/dev/null; then
    if [ -n "$WAN_IF" ] && [ "$WAN_IF" != "vmbr0" ] && iface_exists vmbr0; then
        if ufw route allow in on vmbr0 out on "$WAN_IF" >/dev/null 2>&1; then
            info "Preserved vmbr0 -> $WAN_IF forwarding for NAT."
        else
            warn "Could not add the NAT forwarding rule."
        fi
    fi
fi

# Optional: tailscale subnet router / exit node.
if [ "$TS_SUBNET_ROUTING" = "1" ] && iface_exists tailscale0; then
    ufw route allow in on tailscale0 >/dev/null 2>&1 || true
    ufw route allow out on tailscale0 >/dev/null 2>&1 || true
    sysctl -qw net.ipv4.ip_forward=1 || true
    info "Tailscale forwarding enabled (TS_SUBNET_ROUTING=1)."
fi

# Optional: direct tailscale connections (otherwise traffic stays on DERP).
if [ "$TS_DIRECT_UDP" = "1" ] && [ -n "$WAN_IF" ] && iface_exists tailscale0; then
    if ufw allow in on "$WAN_IF" to any port 41641 proto udp >/dev/null 2>&1; then
        info "Allowed UDP/41641 on $WAN_IF for direct tailscale links."
    fi
fi

## 8. Setting up fail2ban
if [ "$HAVE_FAIL2BAN" = "1" ]; then
    info "Configuring fail2ban..."
    install -d -m 0755 /etc/fail2ban/filter.d /etc/fail2ban/jail.d

    cat > /etc/fail2ban/filter.d/proxmox.conf <<'EOF'
[Definition]
failregex = ^.*pveproxy\[\d+\]: authentication failure; rhost=<HOST> user=.*$
ignoreregex =
EOF

    cat > /etc/fail2ban/filter.d/ufw-management.conf <<'EOF'
[Definition]
failregex = \[UFW (BLOCK|AUDIT)\].*SRC=<HOST> DST=
ignoreregex =
EOF

    # ufw writes to /var/log/ufw.log only when rsyslog is present.
    if systemctl is-active --quiet rsyslog 2>/dev/null; then
        UFW_JAIL_SOURCE="logpath = /var/log/ufw.log"
    else
        UFW_JAIL_SOURCE="backend = systemd"
    fi

    SSH_PORT_LIST="$(detect_ssh_ports | tr ' ' ',')"
    SSH_PORT_LIST="${SSH_PORT_LIST%,}"

    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
# Internal, CGNAT and Tailscale ranges must never be banned: a ban is inserted
# before the allow rules and would override them.
ignoreip = 127.0.0.1/8 ::1 fe80::/10 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 fd7a:115c:a1e0::/48
findtime = 1d
maxretry = 5
bantime  = 1w

[sshd]
enabled  = true
port     = ${SSH_PORT_LIST}
filter   = sshd
backend  = systemd
maxretry = 5

[proxmox]
enabled  = true
port     = ${PVE_PORT},https,http
filter   = proxmox
backend  = systemd
maxretry = 3

[ufw]
enabled  = true
filter   = ufw-management
action   = ufw
${UFW_JAIL_SOURCE}
maxretry = 5
EOF

    systemctl enable fail2ban >/dev/null 2>&1 || true
    if systemctl restart fail2ban >/dev/null 2>&1; then
        info "fail2ban restarted."
    else
        warn "fail2ban restart failed; see /var/log/fail2ban.log."
    fi
fi

## 9. Persist on boot
# Run the local copy only: no network access is required and a failure can no
# longer prevent vmbr0 from coming up.
SELF_PATH="$(readlink -f "$0" 2>/dev/null || true)"
if [ -n "$SELF_PATH" ] && [ -f "$SELF_PATH" ] && [ "$SELF_PATH" != "/usr/local/bin/security-access.sh" ]; then
    install -m 0755 "$SELF_PATH" /usr/local/bin/security-access.sh
    info "Installed this script to /usr/local/bin/security-access.sh"
fi

if [ -f /etc/network/interfaces ]; then
    if grep -q "security-access" /etc/network/interfaces; then
        info "post-up hook already present, skipping."
    elif ! grep -qE '^[[:space:]]*iface[[:space:]]+vmbr0([[:space:]]|$)' /etc/network/interfaces; then
        warn "No vmbr0 stanza found, skipping post-up hook."
    else
        cp -a /etc/network/interfaces "/etc/network/interfaces.bak.$(date +%Y%m%d-%H%M%S)"
        hook='        post-up    /usr/local/bin/security-access.sh > /var/log/security-access.log 2>&1 || true'
        # Insert inside the vmbr0 stanza only, after bridge-fd 0 when present.
        awk -v hook="$hook" '
            BEGIN { in_vmbr0 = 0; done = 0 }
            /^[[:space:]]*iface[[:space:]]+vmbr0([[:space:]]|$)/ { in_vmbr0 = 1; print; next }
            in_vmbr0 && !done && /^[[:space:]]*bridge-fd[[:space:]]+0([[:space:]]|$)/ { print; print hook; done = 1; next }
            in_vmbr0 && !done && /^[[:space:]]*$/ { print hook; done = 1 }
            /^[[:space:]]*$/ { in_vmbr0 = 0 }
            { print }
        ' /etc/network/interfaces > /etc/network/interfaces.tmp

        if grep -q "security-access" /etc/network/interfaces.tmp; then
            mv /etc/network/interfaces.tmp /etc/network/interfaces
            info "post-up hook added to the vmbr0 stanza."
        else
            rm -f /etc/network/interfaces.tmp
            warn "Hook insertion was not safe, original file left untouched."
        fi
    fi
fi

## 10. Show result
ufw reload >/dev/null 2>&1 || true

echo ""
echo "=================================================="
info "Current active UFW rules:"
echo "=================================================="
ufw status verbose || true

echo ""
info "Security rules setup completed successfully!"
