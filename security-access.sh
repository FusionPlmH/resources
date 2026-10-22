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
# 2. Interface selection (why vmbr0 and not end0)
#    Traffic addressed to the host's bridge IP enters the input chain with
#    IN=vmbr0. The physical member (e.g. "bridge-ports end0") never matches,
#    so per-port rules must be attached to the L3 interface, not the member.
#
# 3. Source selection
#    LAN rules are scoped to "from <link subnet of that interface>". The subnet
#    is read from the routing table (ip route ... scope link), so /16, /22 or
#    /25 networks are handled correctly. An interface is only treated as LAN
#    when it owns a private (RFC1918) address.
#
# 4. Supported environments
#    a) public address on vmbr0 : no management rule is added for that
#       interface (tunnels only), the host stays reachable via tailscale0,
#       CloudflareWARP or loopback (cloudflared).
#    b) private address on vmbr0: the link subnet is allowed on 8006 and SSH.
#    c) DHCP uplink bridged/NATed to vmbr0: the uplink holds a private address
#       and is therefore trusted like any other LAN; stale source rules from a
#       previous DHCP network are pruned, and NAT forwarding is preserved.
#
# 5. Order of operations
#    allow rules -> legacy cleanup -> default policies -> ufw enable.
#    Enabling UFW before the allow rules exist can lock the operator out.
#
# 6. Fail2ban safety
#    A fail2ban ban is inserted at the top of the ufw chains and therefore
#    overrides allow rules. RFC1918, CGNAT (100.64.0.0/10) and the Tailscale
#    IPv6 prefix are listed in ignoreip so internal clients are never banned.
#
# 7. Self-update and boot hook
#    /etc/network/if-up.d/security-access runs this file with --self-update on
#    every interface up (boot, ifup, ifreload). The new version is downloaded,
#    syntax checked with "bash -n" and moved into place; when the download
#    fails the existing file is kept and used. No backups are kept.
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

#------------------------------------------------------------------------------
# Self-update configuration and command line
#------------------------------------------------------------------------------
SELF_URL="${SELF_URL:-https://raw.githubusercontent.com/FusionPlmH/resources/refs/heads/main/security-access.sh}"
SELF_DEST="/usr/local/bin/security-access.sh"
SELF_UPDATE_REQUESTED=0
NO_SELF_INSTALL=0

for arg in "$@"; do
    case "$arg" in
        --self-update)     SELF_UPDATE_REQUESTED=1 ;;
        --no-self-install) NO_SELF_INSTALL=1 ;;
        -h|--help)
            echo "Usage: $0 [--self-update] [--no-self-install]"
            echo "  --self-update      download, verify and replace $SELF_DEST, then re-exec"
            echo "  --no-self-install  do not copy the running file to $SELF_DEST"
            echo "Download URL can be overridden with SELF_URL=<url>."
            echo "Set FORCE=1 to enable UFW even without any management path."
            exit 0 ;;
        *) warn "Unknown option: $arg" ;;
    esac
done

# Download, validate and replace the local copy in place.
# A short lived "<dest>.new" staging file is used so the running bash does not
# read a truncated file; it is removed right after the successful mv.
self_update() {
    local tmp newf rc=1
    tmp="$(mktemp /tmp/security-access.XXXXXX.sh)" || return 1
    newf="${SELF_DEST}.new"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --connect-timeout 5 --max-time 20 "$SELF_URL" -o "$tmp" && rc=0
    elif command -v wget >/dev/null 2>&1; then
        wget -q -T 20 -t 1 -O "$tmp" "$SELF_URL" && rc=0
    fi

    if [ "$rc" -ne 0 ] || [ ! -s "$tmp" ]; then
        rm -f "$tmp"
        warn "Self-update: download failed, keeping the current file."
        return 1
    fi

    # Never replace a working copy with something bash cannot parse.
    if ! bash -n "$tmp" 2>/dev/null; then
        rm -f "$tmp"
        warn "Self-update: syntax check failed, keeping the current file."
        return 1
    fi

    if [ -f "$SELF_DEST" ] && cmp -s "$tmp" "$SELF_DEST"; then
        rm -f "$tmp"
        info "Self-update: already up to date."
        return 0
    fi

    if install -m 0755 "$tmp" "$newf" && mv -f "$newf" "$SELF_DEST"; then
        rm -f "$tmp"
        info "Self-update: $SELF_DEST replaced."
        return 0
    fi

    rm -f "$tmp" "$newf"
    warn "Self-update: write failed, keeping the current file."
    return 1
}

PVE_PORT="${PVE_PORT:-8006}"
TS_SUBNET_ROUTING="${TS_SUBNET_ROUTING:-0}"
TS_DIRECT_UDP="${TS_DIRECT_UDP:-0}"
FORCE="${FORCE:-0}"

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

# 0.1 Self-update (requested by the if-up.d hook)
if [ "$SELF_UPDATE_REQUESTED" = "1" ] && [ "${SECURITY_ACCESS_SELF_UPDATED:-0}" != "1" ]; then
    self_update || true
    if [ -x "$SELF_DEST" ]; then
        # Run the freshly installed copy once; the env flag prevents a loop.
        SECURITY_ACCESS_SELF_UPDATED=1 exec "$SELF_DEST" "$@"
    fi
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

iface_first_v4() {
    iface_v4_addrs "$1" | head -n1 | cut -d/ -f1
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

# True when this host performs IPv4 NAT for its guests. The live ruleset is
# authoritative; the ifupdown files are only a fallback.
has_nat() {
    if command -v iptables-save >/dev/null 2>&1; then
        if iptables-save -t nat 2>/dev/null \
           | grep -qE '^-A POSTROUTING .* -j (MASQUERADE|SNAT)( |$)'; then
            return 0
        fi
    fi
    if command -v nft >/dev/null 2>&1; then
        if nft list ruleset 2>/dev/null \
           | grep -qE '(^|[[:space:]])(masquerade|snat to)([[:space:]]|$)'; then
            return 0
        fi
    fi
    if grep -rhE '^[[:space:]]*(pre-up|post-up|pre-down|post-down)[[:space:]].*(MASQUERADE|SNAT)' \
            /etc/network/interfaces /etc/network/interfaces.d/ /etc/iptables/ 2>/dev/null \
       | grep -q .; then
        return 0
    fi
    return 1
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
        # Documentation value while the default outbound policy is ACCEPT.
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
LAN_IFACES=()
OVERLAY_FOUND=0

add_managed() {
    local entry="$1|${2:-}" existing
    for existing in ${MANAGED_IFACES[@]+"${MANAGED_IFACES[@]}"}; do
        if [ "$existing" = "$entry" ]; then
            return 0
        fi
    done
    MANAGED_IFACES+=("$entry")
}

# Remove interface scoped source rules whose subnet no longer matches the
# interface (DHCP moved to another network). Only management ports are
# considered, only interfaces that still exist and hold an address, so a link
# that is temporarily down keeps its rules.
prune_stale_source_rules() {
    local num port rule_ifc src allowed nets
    local -a stale=()

    while IFS='|' read -r num port rule_ifc src; do
        if [ -z "$num" ]; then continue; fi

        allowed=0
        for pinned in "${ALLOW_PORTS[@]}"; do
            if [ "$port" = "$pinned" ]; then allowed=1; fi
        done
        if [ "$allowed" -ne 1 ]; then continue; fi

        if ! iface_exists "$rule_ifc"; then continue; fi
        if [ -z "$(iface_v4_addrs "$rule_ifc")" ]; then continue; fi

        nets=" $(iface_v4_nets "$rule_ifc" | tr '\n' ' ') "
        case "$nets" in
            *" $src "*) ;;
            *) stale+=("$num|$port|$rule_ifc|$src") ;;
        esac
    done < <(ufw status numbered 2>/dev/null | sed -nE \
        's/^\[ *([0-9]+)\] +([0-9]+)\/tcp +on ([^ ]+) +ALLOW IN +([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+).*$/\1|\2|\3|\4/p')

    if [ "${#stale[@]}" -eq 0 ]; then
        return 0
    fi

    while IFS='|' read -r num port rule_ifc src; do
        ufw --force delete "$num" >/dev/null 2>&1 || true
        info "  pruned stale rule: ${port}/tcp on $rule_ifc from $src"
    done < <(printf '%s\n' "${stale[@]}" | sort -t'|' -k1,1 -rn)
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
    # limited to the management ports.
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
        LAN_IFACES+=("$ifc")
        info "  LAN interface: $ifc"
    fi
done < <(ip -4 -o addr show scope global 2>/dev/null | awk '{print $2}' | sort -u)

# 3.2 Tailscale and Cloudflare tunnel / WARP interfaces.
for ifc in tailscale0 CloudflareWARP warp0 cloudflared; do
    if iface_exists "$ifc"; then
        add_managed "$ifc" ""
        OVERLAY_FOUND=1
        info "  Overlay interface: $ifc"
    fi
done
while read -r ifc; do
    if [ -z "$ifc" ]; then continue; fi
    case "$ifc" in
        warp*|cloudflared*|CloudflareWARP*)
            add_managed "$ifc" ""
            OVERLAY_FOUND=1
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

# 3.4 Classify the uplink so the log shows which environment was detected.
WAN_IF="$(ip -4 route show default 2>/dev/null | awk '/default/ {print $5; exit}' || true)"
if [ -n "$WAN_IF" ]; then
    WAN_ADDR="$(iface_first_v4 "$WAN_IF")"
    if [ -z "$WAN_ADDR" ]; then
        info "  Uplink $WAN_IF has no IPv4 address."
    elif is_private_v4 "$WAN_ADDR"; then
        info "  Uplink $WAN_IF is private ($WAN_ADDR): treated as LAN."
    else
        info "  Uplink $WAN_IF is public ($WAN_ADDR): management ports stay closed."
    fi
fi

if [ "${#MANAGED_IFACES[@]}" -eq 0 ]; then
    error "No manageable interface found, aborting to avoid a lockout."
    exit 1
fi

# Refuse to enable a firewall that would leave no management path at all.
if [ "${#LAN_IFACES[@]}" -eq 0 ] && [ "$OVERLAY_FOUND" -eq 0 ] && [ "$FORCE" != "1" ]; then
    error "No LAN interface and no tailscale/cloudflared interface detected."
    error "Enabling UFW would leave the host reachable through loopback only."
    error "Re-run with FORCE=1 to override."
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
echo "Checking existing UFW rules for legacy entries..."

# 5.1 Remove bare (interface less) rules for the management port.
delete_rules_matching '^\[ *[0-9]+\] +(8006|8006/tcp) +ALLOW (IN|OUT) +Anywhere( \(v6\))? *$'

# 5.2 Rules attached to a bridge member (end0, ...) can never match host traffic.
for member in $(awk '/^[[:space:]]*bridge-ports[[:space:]]/ {for (i=2; i<=NF; i++) if ($i != "none") print $i}' \
                    /etc/network/interfaces /etc/network/interfaces.d/* 2>/dev/null | sort -u || true); do
    delete_rules_matching "^\\[ *[0-9]+\\] +(8006|8006/tcp) +on ${member} +ALLOW IN"
done

# 5.3 Drop source rules from a previous DHCP network.
prune_stale_source_rules

## 6. Default policies and enable UFW
echo "Initializing UFW policies..."
systemctl enable ufw >/dev/null 2>&1 || true
systemctl start ufw >/dev/null 2>&1 || true
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw logging low >/dev/null
ufw --force enable >/dev/null
info "UFW enabled; inbound limited to ${ALLOW_PORTS[*]}."

## 7. Preserve forwarding for NAT setups
if has_nat; then
    if [ -z "$WAN_IF" ]; then
        warn "NAT detected but no default route found; forwarding rule not added."
    else
        if [ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)" != "1" ]; then
            warn "net.ipv4.ip_forward is 0: guests cannot be routed."
        fi
        info "NAT detected; preserving forwarding towards $WAN_IF."
        for ifc in ${LAN_IFACES[@]+"${LAN_IFACES[@]}"}; do
            if [ "$ifc" = "$WAN_IF" ]; then
                continue
            fi
            if ufw route allow in on "$ifc" out on "$WAN_IF" >/dev/null 2>&1; then
                info "  route allow: $ifc -> $WAN_IF"
            else
                warn "  route allow failed: $ifc -> $WAN_IF"
            fi
        done
        # Same-bridge NAT is not covered here; add it manually if needed:
        #   ufw route allow in on "$WAN_IF" out on "$WAN_IF"
    fi
else
    info "No NAT detected; forwarding stays at 'deny (routed)'."
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
# $SELF_DEST is only a cache: /etc/network/if-up.d/security-access calls it
# with --self-update on every ifup, so each boot or network restart overwrites
# it with the newest upstream version first.
SELF_PATH="$(readlink -f "$0" 2>/dev/null || true)"
if [ "$NO_SELF_INSTALL" != "1" ] \
   && [ -n "$SELF_PATH" ] && [ -f "$SELF_PATH" ] && [ "$SELF_PATH" != "$SELF_DEST" ]; then
    install -m 0755 "$SELF_PATH" "$SELF_DEST"
    info "Installed this script to $SELF_DEST"
fi

# Delete the legacy post-up hook: PVE rewrites /etc/network/interfaces from its
# own model, so a hook stored there disappears on the next GUI change.
if grep -q '^[[:space:]]*post-up.*security-access' /etc/network/interfaces 2>/dev/null; then
    sed -i '/^[[:space:]]*post-up.*security-access/d' /etc/network/interfaces
    info "Removed the legacy post-up hook from /etc/network/interfaces."
fi

# if-up.d runs on every interface up and is not managed by the PVE network
# stack. It always exits 0 so a failure can never block network setup.
install -d -m 0755 /etc/network/if-up.d
cat > /etc/network/if-up.d/security-access <<'EOF'
#!/bin/sh
[ "$IFACE" = "vmbr0" ] || exit 0
[ "$MODE" = "start" ] || exit 0
/usr/local/bin/security-access.sh --self-update >/var/log/security-access.log 2>&1 || true
exit 0
EOF
chmod 0755 /etc/network/if-up.d/security-access
info "Boot hook installed: /etc/network/if-up.d/security-access"

## 10. Show result
ufw reload >/dev/null 2>&1 || true

echo ""
echo "=================================================="
info "Current active UFW rules:"
echo "=================================================="
ufw status verbose || true

echo ""
info "Security rules setup completed successfully!"
