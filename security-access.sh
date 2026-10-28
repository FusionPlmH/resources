#!/bin/bash
#===============================================================================
# security-access.sh
#
# DESIGN
# ------
# Goal: expose this host on exactly two TCP ports (8006 and SSH) and only to
#       three trusted paths: the local LAN, cloudflared and tailscale0.
#
# 1. Policy model
#    - inbound : default DROP, explicit "interface + port" allow rules only.
#      Explicit OUT rules are not created on purpose: the default outbound
#      policy is ACCEPT, and cloudflared (7844/tcp+udp), tailscale (41641/udp,
#      443/tcp for DERP) and DNS all depend on unrestricted egress. Adding
#      per-port OUT rules would only duplicate what the policy already allows.
#    - forward : UFW defaults it to DROP. It is re-opened only for
#      (a) detected NAT towards the uplink and (b) tailscale0 when tailscale
#      is present. Forward rules never widen the inbound policy of the host.
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
#       interface (tunnels only); the host stays reachable via tailscale0,
#       CloudflareWARP or loopback (cloudflared).
#    b) private address on vmbr0: the link subnet is allowed on 8006 and SSH.
#    c) DHCP uplink bridged/NATed to vmbr0: the uplink holds a private address
#       and is therefore trusted like any other LAN; stale source rules from a
#       previous DHCP network are pruned and NAT forwarding is preserved.
#
# 5. Tailscale
#    As soon as tailscale0 exists the host is treated as exit node and subnet
#    router: IP forwarding is persisted in /etc/sysctl.d and FORWARD is opened
#    in/out of tailscale0. Direct peer links additionally need inbound
#    UDP/41641 on the uplink. Disable with TS_SUBNET_ROUTING=0 or
#    TS_DIRECT_UDP=0.
#
# 6. Order of operations
#    allow rules -> legacy cleanup -> default policies -> ufw enable.
#    Enabling UFW before the allow rules exist can lock the operator out.
#
# 7. Fail2ban safety
#    A fail2ban ban is inserted at the top of the ufw chains and therefore
#    overrides allow rules. RFC1918, CGNAT (100.64.0.0/10) and the Tailscale
#    IPv6 prefix are in ignoreip so internal clients are never banned. Every
#    run also rewrites the jail definitions, deletes legacy artifacts and
#    clears all active bans, so a reboot never inherits state.
#
# 8. Self-update and boot hook
#    The boot hook NEVER runs this file inside the ifup transaction.
#    networking.service is ordered Before=network.target and fail2ban.service
#    is ordered After=network.target, so a synchronous "systemctl restart
#    fail2ban" issued from an ifup hook deadlocks the entire boot: networking
#    never finishes, network.target is never reached, ssh/pveproxy never start
#    and the host is unreachable after every reboot - with correct firewall
#    rules, which is what makes this failure so hard to read.
#    /etc/network/if-up.d/security-access therefore only enqueues
#    "systemctl start --no-block security-access.service"; that oneshot unit
#    runs this file with --self-update after network-online.target and
#    fail2ban.service. Every systemctl call made here also uses --no-block, so
#    the script stays safe even when it is started from another hook.
#    The new version is downloaded, syntax checked with "bash -n" and moved
#    into place; when the download fails the existing file is kept and used.
#    Exactly one copy of the script is kept: $SELF_DEST. Any leftover
#    ".bak" / ".old" / ".new" copies are deleted on every run.
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
# Configuration and command line
#------------------------------------------------------------------------------
SELF_URL="${SELF_URL:-https://raw.githubusercontent.com/FusionPlmH/resources/refs/heads/main/security-access.sh}"
SELF_DEST="/usr/local/bin/security-access.sh"
SELF_UPDATE_REQUESTED=0
NO_SELF_INSTALL=0

PVE_PORT="${PVE_PORT:-8006}"
TS_SUBNET_ROUTING="${TS_SUBNET_ROUTING:-1}"
TS_DIRECT_UDP="${TS_DIRECT_UDP:-1}"
TS_IPV6_FORWARDING="${TS_IPV6_FORWARDING:-0}"
FORCE="${FORCE:-0}"

for arg in "$@"; do
    case "$arg" in
        --self-update)     SELF_UPDATE_REQUESTED=1 ;;
        --no-self-install) NO_SELF_INSTALL=1 ;;
        -h|--help)
            echo "Usage: $0 [--self-update] [--no-self-install]"
            echo "  --self-update      download, verify and replace $SELF_DEST, then re-exec"
            echo "  --no-self-install  do not copy the running file to $SELF_DEST"
            echo "Environment:"
            echo "  SELF_URL=<url>            override the download source"
            echo "  SSH_PORTS_OVERRIDE=22,222 pin the allowed SSH ports (the boot probe cannot see sshd)"
            echo "  FORCE=1                   enable UFW even without a management path"
            echo "  TS_SUBNET_ROUTING=0       skip exit-node / subnet-router forwarding"
            echo "  TS_DIRECT_UDP=0           skip inbound UDP/41641 for direct peers"
            echo "  TS_IPV6_FORWARDING=1      also enable IPv6 forwarding"
            echo "  FAIL2BAN_PURGE_DB=1       delete the fail2ban ban database"
            echo "  LEGACY_CLEANUP=1          force the one-time legacy rule cleanup again"
            echo "  UFW_IPV6=no|yes           set IPV6 in /etc/default/ufw (default: keep)"
            echo "  SELFCHECK=0               skip the post-apply management path check"
            echo "  SELFCHECK_FATAL=0         warn instead of disabling UFW when it fails"
            exit 0 ;;
        *) warn "Unknown option: $arg" ;;
    esac
done

# Download, validate and replace the local copy in place.
# A short lived "<dest>.new" staging file avoids truncating a file that bash is
# still reading; it is removed right after the successful mv.
self_update() {
    local tmp newf rc=1
    tmp="$(mktemp /tmp/security-access.XXXXXX.sh)" || return 1
    newf="${SELF_DEST}.new"

    if command -v curl >/dev/null 2>&1; then
        # -z (If-Modified-Since) skips the transfer when the cached copy is
        # already current, so a NIC flap does not depend on GitHub.
        if [ -f "$SELF_DEST" ]; then
            curl -fsSL -z "$SELF_DEST" --connect-timeout 5 --max-time 20 \
                "$SELF_URL" -o "$tmp" && rc=0
            if [ "$rc" -eq 0 ] && [ ! -s "$tmp" ]; then
                rm -f "$tmp"
                info "Self-update: already up to date."
                return 0
            fi
        else
            curl -fsSL --connect-timeout 5 --max-time 20 "$SELF_URL" -o "$tmp" && rc=0
        fi
    elif command -v wget >/dev/null 2>&1; then
        wget -q -T 20 -t 1 -O "$tmp" "$SELF_URL" && rc=0
    fi

    if [ "$rc" -ne 0 ] || [ ! -s "$tmp" ]; then
        rm -f "$tmp"
        warn "Self-update: download failed, keeping the current file."
        return 1
    fi

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
        # Bounded on purpose: this may run from the boot path, an apt that waits
        # for a dead network would stall networking.service as well.
        if ! { apt-get -o Acquire::http::Timeout=10 -o Acquire::https::Timeout=10 -o Acquire::Retries=1 update -qq \
               && apt-get -o Acquire::http::Timeout=10 -o Acquire::https::Timeout=10 -o Acquire::Retries=1 install -y -qq "$package" >/dev/null 2>&1; }; then
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

# Interface names as reported by ip, without the "@parent" suffix.
list_ifaces() {
    ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | sed 's/@.*//' | sort -u
}

# Interfaces that currently own a global IPv4 address, "@parent" removed.
list_v4_ifaces() {
    ip -4 -o addr show scope global 2>/dev/null | awk '{print $2}' | sed 's/@.*//' | sort -u
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
    echo "${ports:-22}"
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
    # Only the POSTROUTING chain counts. Grepping the whole ruleset also hits
    # overlay masquerade rules (tailscale's ts-postrouting) and would wrongly
    # widen FORWARD for every private bridge.
    if command -v nft >/dev/null 2>&1; then
        if nft list chain ip nat POSTROUTING 2>/dev/null \
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
# During early boot sshd is not listening yet, so the probe above always falls
# back to 22; set SSH_PORTS_OVERRIDE when sshd runs on another port, otherwise
# the boot run would open the wrong port and lock the operator out.
SSH_PORTS="${SSH_PORTS_OVERRIDE:-$(detect_ssh_ports)}"
# Accept both "22 222" and "22,222"; a comma separated value would otherwise
# be passed to ufw as a single invalid port token.
SSH_PORTS="${SSH_PORTS//,/ }"
ALLOW_PORTS=("$PVE_PORT")
for port in $SSH_PORTS; do
    if [ "$port" != "$PVE_PORT" ]; then
        ALLOW_PORTS+=("$port")
    fi
done

is_allowed_port() {
    local candidate="$1" port
    for port in "${ALLOW_PORTS[@]}"; do
        if [ "$port" = "$candidate" ]; then
            return 0
        fi
    done
    return 1
}

MANAGED_IFACES=()
LAN_IFACES=()
OVERLAY_FOUND=0

# Register "interface|source" once. Returns 0 only when it was actually added.
add_managed() {
    local entry="$1|${2:-}" existing
    for existing in ${MANAGED_IFACES[@]+"${MANAGED_IFACES[@]}"}; do
        if [ "$existing" = "$entry" ]; then
            return 1
        fi
    done
    MANAGED_IFACES+=("$entry")
    return 0
}

# Allow the management ports inbound on one interface.
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
    done
}

# "ufw status numbered" walks and prints the whole rule set, which gets slow
# once hundreds of rules exist. Cache it and invalidate after every change.
UFW_STATUS_CACHE=""
ufw_rules() {
    if [ -z "$UFW_STATUS_CACHE" ]; then
        UFW_STATUS_CACHE="$(ufw status numbered 2>/dev/null || true)"
    fi
    printf '%s\n' "$UFW_STATUS_CACHE"
}
ufw_rules_invalidate() { UFW_STATUS_CACHE=""; }

# Bridge member interfaces (end0, eno1, ...) from the ifupdown files.
bridge_members() {
    awk '/^[[:space:]]*bridge-ports[[:space:]]/ {for (i=2; i<=NF; i++) if ($i != "none") print $i}' \
        /etc/network/interfaces /etc/network/interfaces.d/* 2>/dev/null | sort -u || true
}

# Delete rules by pattern, highest index first so numbering does not shift.
delete_rules_matching() {
    local pattern="$1" numbers number
    numbers=$(ufw_rules \
        | grep -E "$pattern" \
        | sed -nE 's/^\[ *([0-9]+)\].*/\1/p' | sort -rn || true)
    if [ -z "$numbers" ]; then
        return 0
    fi
    for number in $numbers; do
        ufw --force delete "$number" >/dev/null 2>&1 || true
    done
    ufw_rules_invalidate
}

# fail2ban's "ufw" action writes a persistent REJECT rule per ban. When its
# database is reset (this script restarts fail2ban on every run) those rules
# stay behind untracked, so "unban --all" can never remove them again. They
# then override every allow rule at boot and make each ufw call rewrite a
# huge file. Drop every ban tuple that carries fail2ban's comment marker.
purge_ban_tuples() {
    local f=/etc/ufw/user.rules before after tmp
    [ -f "$f" ] || return 0
    before=$(grep -c 'in comment=' "$f" 2>/dev/null || true)
    [ "${before:-0}" -gt 0 ] || return 0

    tmp="$(mktemp)" || return 0
    awk '
        /^### tuple ### reject any any 0\.0\.0\.0\/0 any .* in comment=/ { pending=1; next }
        { if (pending==1 && $0 ~ /^-A ufw-user-input -s .* -j REJECT$/) { pending=0; next }
          pending=0; print }
    ' "$f" > "$tmp" || { rm -f "$tmp"; return 0; }

    after=$(grep -c 'in comment=' "$tmp" 2>/dev/null || true)
    if [ "${after:-0}" -gt 0 ]; then
        warn "  could not purge all ban tuples ($before -> $after); keeping the file."
        rm -f "$tmp"
        return 0
    fi
    if cmp -s "$tmp" "$f"; then
        rm -f "$tmp"
        return 0
    fi
    cp -a "$f" "${f}.bak" 2>/dev/null || true
    if mv -f "$tmp" "$f"; then
        info "  purged ${before} stale fail2ban ban tuple(s) from user.rules."
        NEED_UFW_RELOAD=1
    else
        rm -f "$tmp"
        warn "  failed to rewrite $f; stale bans left in place."
    fi
    ufw_rules_invalidate
}

# Rules that point at an overlay interface which is gone for good (WARP
# uninstalled or disabled) can never match again. Only prune when the owning
# service is really gone, never while it is merely down: a boot race must not
# delete the tailscale rules that the host depends on.
prune_dead_iface_rules() {
    local ifc svc
    for ifc in CloudflareWARP warp0 cloudflared; do
        case "$ifc" in
            cloudflared) svc=cloudflared ;;
            *)           svc=warp-svc ;;
        esac
        iface_exists "$ifc" && continue
        if systemctl is-enabled --quiet "$svc" 2>/dev/null \
           || systemctl is-active --quiet "$svc" 2>/dev/null; then
            continue
        fi
        delete_rules_matching "^\\[ *[0-9]+\\] +.* +on ${ifc} +ALLOW (IN|OUT)"
    done
    if ! iface_exists tailscale0 && ! systemctl is-enabled --quiet tailscaled 2>/dev/null; then
        delete_rules_matching "^\\[ *[0-9]+\\] +.* +on tailscale[0-9]* +ALLOW (IN|OUT)"
    fi
}

# Write stdin to $1 only when the content differs. Leaves IFC_CHANGED=1 when the
# file was replaced, so daemon-reload / service restarts can be skipped.
IFC_CHANGED=0
install_if_changed() {
    local dest="$1" mode="${2:-0644}" tmp
    IFC_CHANGED=0
    tmp="$(mktemp)" || return 1
    cat > "$tmp" || { rm -f "$tmp"; return 1; }
    if [ -f "$dest" ] && cmp -s "$tmp" "$dest"; then
        rm -f "$tmp"
        return 0
    fi
    if install -m "$mode" "$tmp" "$dest"; then
        IFC_CHANGED=1
    fi
    rm -f "$tmp"
    return 0
}

# Refuse to stay enabled without any management path. A wrong regex or a
# missing interface must not end as a locked-out host.
post_apply_selfcheck() {
    local port live missing=0
    if [ "${SELFCHECK:-1}" = "0" ]; then
        return 0
    fi
    live="$(iptables -S ufw-user-input 2>/dev/null || true)"
    if [ -z "$live" ]; then
        warn "self-check: cannot read ufw-user-input; skipped."
        return 0
    fi
    for port in "${ALLOW_PORTS[@]}"; do
        if ! printf '%s\n' "$live" | grep -qE -- "--dport ${port}( |\$).*-j ACCEPT"; then
            error "self-check: no ACCEPT rule for port ${port}."
            missing=1
        fi
    done
    if [ "$missing" -eq 0 ]; then
        info "Self-check passed: ${ALLOW_PORTS[*]}/tcp still reachable."
        return 0
    fi
    if [ "${SELFCHECK_FATAL:-1}" = "1" ]; then
        error "No management path left; disabling UFW instead of locking out."
        ufw --force disable >/dev/null 2>&1 || true
        exit 1
    fi
    warn "self-check failed (SELFCHECK_FATAL=0): UFW left enabled."
}

# Remove interface-scoped source rules whose subnet no longer matches the
# interface (DHCP moved to another network). Only management ports are
# considered and only interfaces that still exist and hold an address, so a
# link that is temporarily down keeps its rules.
prune_stale_source_rules() {
    local num port rule_ifc src nets
    local -a stale=()

    while IFS='|' read -r num port rule_ifc src; do
        if [ -z "$num" ]; then continue; fi
        if ! is_allowed_port "$port"; then continue; fi
        if ! iface_exists "$rule_ifc"; then continue; fi
        if [ -z "$(iface_v4_addrs "$rule_ifc")" ]; then continue; fi

        nets=" $(iface_v4_nets "$rule_ifc" | tr '\n' ' ') "
        case "$nets" in
            *" $src "*) ;;
            *) stale+=("$num|$port|$rule_ifc|$src") ;;
        esac
    done < <(ufw_rules | sed -nE \
        's/^\[ *([0-9]+)\] +([0-9]+)\/tcp +on ([^ ]+) +ALLOW IN +([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+).*$/\1|\2|\3|\4/p')

    if [ "${#stale[@]}" -eq 0 ]; then
        return 0
    fi

    while IFS='|' read -r num port rule_ifc src; do
        ufw --force delete "$num" >/dev/null 2>&1 || true
        info "  pruned stale rule: ${port}/tcp on $rule_ifc from $src"
    done < <(printf '%s\n' "${stale[@]}" | sort -t'|' -k1,1 -rn)
    ufw_rules_invalidate
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
            add_managed "$ifc" "$net" || true
            matched=1
        fi
    done <<< "$(iface_v4_nets "$ifc")"

    # Fallback when no scope-link route is present: allow any source, still
    # limited to the management ports.
    if [ "$matched" -eq 0 ]; then
        while read -r addr; do
            if [ -z "$addr" ]; then continue; fi
            if is_private_v4 "${addr%%/*}"; then
                # No scope-link route: the source cannot be narrowed, so this
                # opens the management ports to any source on that interface.
                warn "  no link route on $ifc; allowing any source on this interface."
                add_managed "$ifc" "" || true
                matched=1
            fi
        done <<< "$(iface_v4_addrs "$ifc")"
    fi

    if [ "$matched" -eq 1 ]; then
        LAN_IFACES+=("$ifc")
        info "  LAN interface: $ifc"
    fi
done < <(list_v4_ifaces)

# 3.2 Tailscale and Cloudflare tunnel / WARP interfaces (matches any name).
while read -r ifc; do
    if [ -z "$ifc" ]; then continue; fi
    case "$ifc" in
        tailscale*|warp*|CloudflareWARP*|cloudflared*)
            if add_managed "$ifc" ""; then
                OVERLAY_FOUND=1
                info "  Overlay interface: $ifc"
            fi
            ;;
    esac
done < <(list_ifaces)

# 3.3 cloudflared origin path: loopback, plus Docker bridges when the
#     connector runs as a container.
if add_managed lo ""; then
    info "  Loopback origin: lo"
fi
while read -r ifc; do
    if [ -z "$ifc" ]; then continue; fi
    case "$ifc" in
        docker0|br-*)
            if add_managed "$ifc" ""; then
                info "  Container origin interface: $ifc"
            fi
            ;;
    esac
done < <(list_ifaces)

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

# Refuse to enable a firewall that would leave no management path at all.
if [ "${#LAN_IFACES[@]}" -eq 0 ] && [ "$OVERLAY_FOUND" -eq 0 ] && [ "$FORCE" != "1" ]; then
    error "No LAN interface and no tailscale/cloudflared interface detected."
    error "Enabling UFW would leave the host reachable through loopback only."
    error "Re-run with FORCE=1 to override."
    exit 1
fi

## 3.5 Purge untracked fail2ban ban tuples first: every ufw command rewrites
##     the whole rules file, so a large ban list makes all of them slow.
NEED_UFW_RELOAD=0
purge_ban_tuples
if [ "$NEED_UFW_RELOAD" = "1" ]; then
    ufw reload >/dev/null 2>&1 || true
    NEED_UFW_RELOAD=0
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
# A bare rule such as "8006/tcp ALLOW IN Anywhere" is what the first versions
# produced, but it is also what an operator gets from "ufw allow 8006". Delete
# it on every run and any deliberate rule would be wiped at each boot, so the
# migration runs once and leaves a marker behind. Force it with
# LEGACY_CLEANUP=1.
LEGACY_MARKER_DIR="/var/lib/security-access"
LEGACY_MARKER="${LEGACY_MARKER_DIR}/legacy-cleanup-v2"

cleanup_legacy_rules() {
    local member p ovl
    echo "Checking existing UFW rules for legacy entries..."

    # 5.1 Bare (interface less) rules created by the first version: 443/HTTPS
    #     and the unqualified 8006. Rules for other ports are never touched.
    #     "(out)" is part of the numbering output of OUT rules.
    delete_rules_matching '^\[ *[0-9]+\] +(443|443/tcp|https)( \(v6\))? +ALLOW (IN|OUT) +Anywhere( \(v6\))?( \(out\))? *$'
    delete_rules_matching '^\[ *[0-9]+\] +(8006|8006/tcp)( \(v6\))? +ALLOW (IN|OUT) +Anywhere( \(v6\))?( \(out\))? *$'

    # 5.2 Older versions attached the management rules to the bridge MEMBER
    #     (end0, eno1, ...) instead of the bridge itself, and opened the overlay
    #     interfaces without any port filter. Both are dead weight now.
    for member in $(bridge_members); do
        for p in "${ALLOW_PORTS[@]}"; do
            delete_rules_matching "^\\[ *[0-9]+\\] +(${p}|${p}/tcp)( \\(v6\\))? +on ${member} +ALLOW (IN|OUT)"
        done
    done

    for ovl in tailscale0 CloudflareWARP warp0 cloudflared; do
        delete_rules_matching "^\\[ *[0-9]+\\] +Anywhere( \\(v6\\))? +on ${ovl} +ALLOW (IN|OUT) +Anywhere( \\(v6\\))?( \\(out\\))? *\$"
    done
}

if [ "${LEGACY_CLEANUP:-auto}" = "1" ] || [ ! -f "$LEGACY_MARKER" ]; then
    cleanup_legacy_rules
    if install -d -m 0755 "$LEGACY_MARKER_DIR" 2>/dev/null && : > "$LEGACY_MARKER" 2>/dev/null; then
        info "Legacy cleanup done once; marker: $LEGACY_MARKER"
    else
        warn "Could not write $LEGACY_MARKER; legacy cleanup will run again next time."
    fi
else
    info "Legacy rule cleanup already done ($LEGACY_MARKER); skipping."
fi

# 5.3 Always: drop rules that can no longer be valid.
prune_stale_source_rules
prune_dead_iface_rules

## 6. Default policies and enable UFW
echo "Initializing UFW policies..."
if [ "${UFW_IPV6:-keep}" != "keep" ] && [ -f /etc/default/ufw ]; then
    if grep -qE '^IPV6=' /etc/default/ufw; then
        cur_v6=$(grep -m1 -E '^IPV6=' /etc/default/ufw | cut -d'"' -f2)
        if [ "$cur_v6" != "$UFW_IPV6" ]; then
            sed -i "s/^IPV6=.*/IPV6=\"${UFW_IPV6}\"/" /etc/default/ufw
            info "UFW IPv6 set to $UFW_IPV6."
        fi
    fi
fi
systemctl enable ufw >/dev/null 2>&1 || true
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw default deny routed >/dev/null
ufw logging low >/dev/null
ufw --force enable >/dev/null
info "UFW enabled; inbound limited to ${ALLOW_PORTS[*]}."
post_apply_selfcheck

## 7. Forwarding: NAT and Tailscale
# 7.1 Guest NAT: keep vmbr0-style internal bridges able to reach the uplink.
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

# 7.2 Tailscale: exit node + subnet router + direct peer links, as soon as
#     tailscale0 exists. These are FORWARD rules; the inbound policy of the
#     host itself stays limited to the management ports.
if iface_exists tailscale0; then
    if [ "$TS_SUBNET_ROUTING" = "1" ]; then
        info "Configuring tailscale forwarding (exit node / subnet router)..."
        {
            echo "net.ipv4.ip_forward = 1"
            if [ "$TS_IPV6_FORWARDING" = "1" ]; then
                echo "net.ipv6.conf.all.forwarding = 1"
            fi
        } | install_if_changed /etc/sysctl.d/99-tailscale-forward.conf 0644 || true

        # Apply only the keys we own; "sysctl --system" would re-apply every
        # file in /etc/sysctl.d and could overwrite unrelated runtime values.
        sysctl -qw net.ipv4.ip_forward=1 2>/dev/null || true
        if [ "$TS_IPV6_FORWARDING" = "1" ]; then
            sysctl -qw net.ipv6.conf.all.forwarding=1 2>/dev/null || true
        fi

        # in  : exit-node traffic and tailnet -> LAN (subnet router)
        # out : return path and LAN -> tailnet
        ufw route allow in on tailscale0  >/dev/null 2>&1 || true
        ufw route allow out on tailscale0 >/dev/null 2>&1 || true
        info "  forwarding allowed in/out of tailscale0."
    fi

    if [ "$TS_DIRECT_UDP" = "1" ] && [ -n "$WAN_IF" ]; then
        if ufw allow in on "$WAN_IF" to any port 41641 proto udp >/dev/null 2>&1; then
            info "  allowed UDP/41641 on $WAN_IF for direct tailscale links."
        else
            warn "  failed to allow UDP/41641 on $WAN_IF."
        fi
    fi
fi

## 8. Setting up fail2ban
# The configuration is rewritten and the ban state is purged on every run, so a
# reboot never inherits bans or filters from an older version of this script.
if [ "$HAVE_FAIL2BAN" = "1" ]; then
    info "Configuring fail2ban..."

    # 8.1 Remove artifacts left by older versions.
    rm -f /etc/fail2ban/filter.d/ufw-aggressive.conf
    for snippet in /etc/fail2ban/jail.d/*.conf; do
        [ -f "$snippet" ] || continue
        if grep -q 'ufw-aggressive' "$snippet" 2>/dev/null; then
            rm -f "$snippet"
            info "  removed legacy jail snippet: $snippet"
        fi
    done

    # 8.2 Filters (written only when the content changes)
    F2B_CONF_CHANGED=0
    install_if_changed /etc/fail2ban/filter.d/proxmox.conf 0644 <<'EOF' || true
[Definition]
failregex = ^.*pveproxy\[\d+\]: authentication failure; rhost=<HOST> user=.*$
ignoreregex =
EOF
    [ "$IFC_CHANGED" = "1" ] && F2B_CONF_CHANGED=1

    install_if_changed /etc/fail2ban/filter.d/ufw-management.conf 0644 <<'EOF' || true
[Definition]
failregex = \[UFW (BLOCK|AUDIT)\].*SRC=<HOST> DST=
ignoreregex =
EOF
    [ "$IFC_CHANGED" = "1" ] && F2B_CONF_CHANGED=1

    # ufw writes to /var/log/ufw.log only when rsyslog is present.
    if systemctl is-active --quiet rsyslog 2>/dev/null; then
        UFW_JAIL_SOURCE="logpath = /var/log/ufw.log"
    else
        UFW_JAIL_SOURCE="backend = systemd"
    fi

    SSH_PORT_LIST="$(echo $SSH_PORTS | tr ' ' ',')"

    # The [ufw] jail needs the ufw binary; without it every ban attempt fails
    # and fail2ban logs an error on each match.
    if command -v ufw >/dev/null 2>&1; then
        UFW_JAIL_BLOCK="[ufw]
enabled  = true
filter   = ufw-management
action   = ufw
${UFW_JAIL_SOURCE}
maxretry = 5"
    else
        UFW_JAIL_BLOCK="# [ufw] jail skipped: the ufw binary is not installed"
    fi

    # 8.3 Jail definitions (jail.local is rewritten only when it changes)
    install_if_changed /etc/fail2ban/jail.local 0644 <<EOF || true
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

${UFW_JAIL_BLOCK}
EOF

    [ "$IFC_CHANGED" = "1" ] && F2B_CONF_CHANGED=1

    systemctl enable fail2ban >/dev/null 2>&1 || true

    # 8.4 Optional: delete the ban database as well (FAIL2BAN_PURGE_DB=1).
    if [ "${FAIL2BAN_PURGE_DB:-0}" = "1" ]; then
        systemctl stop fail2ban >/dev/null 2>&1 || true
        rm -f /var/lib/fail2ban/fail2ban.sqlite3
        warn "  fail2ban database purged; check for orphan 'DENY' rules afterwards."
    fi

    if [ "$F2B_CONF_CHANGED" = "1" ] || ! systemctl is-active --quiet fail2ban 2>/dev/null; then
        # --no-block is mandatory. The fail2ban start job can only be satisfied
        # after network.target, and this script may be running inside
        # networking.service (Before=network.target): waiting here deadlocks boot.
        if systemctl restart --no-block fail2ban >/dev/null 2>&1; then
            info "fail2ban restart requested (non-blocking)."
        else
            warn "fail2ban restart failed; see /var/log/fail2ban.log."
        fi
    else
        info "fail2ban configuration unchanged; restart skipped."
    fi

    # 8.5 Purge every active ban: a reboot must never inherit a stale ban.
    #     The socket may not be ready immediately after the restart, so retry.
    for attempt in 1 2 3 4 5; do
        if fail2ban-client ping >/dev/null 2>&1; then
            fail2ban-client unban --all >/dev/null 2>&1 || true
            info "  all fail2ban bans cleared."
            break
        fi
        sleep 1
    done
fi

## 9. Persist on boot
# Exactly one copy of this script is kept. Remove staging and any historical
# leftovers so no stale version can be executed later.
rm -f "${SELF_DEST}.new" "${SELF_DEST}.bak" "${SELF_DEST}.old" 2>/dev/null || true

# Install the running file as the cache, but never downgrade a newer cache.
SELF_PATH="$(readlink -f "$0" 2>/dev/null || true)"
if [ "$NO_SELF_INSTALL" != "1" ] \
   && [ -n "$SELF_PATH" ] && [ -f "$SELF_PATH" ] && [ "$SELF_PATH" != "$SELF_DEST" ]; then
    if [ -f "$SELF_DEST" ] && cmp -s "$SELF_PATH" "$SELF_DEST"; then
        info "Cache $SELF_DEST is already identical."
    elif [ -f "$SELF_DEST" ] && [ "$SELF_DEST" -nt "$SELF_PATH" ]; then
        warn "Cache $SELF_DEST is newer than $SELF_PATH; not overwriting."
    else
        install -m 0755 "$SELF_PATH" "$SELF_DEST"
        info "Installed this script to $SELF_DEST"
    fi
fi

# Delete the legacy post-up hook: PVE rewrites /etc/network/interfaces from its
# own model, so a hook stored there disappears on the next GUI change.
if grep -q '^[[:space:]]*post-up.*security-access' /etc/network/interfaces 2>/dev/null; then
    sed -i '/^[[:space:]]*post-up.*security-access/d' /etc/network/interfaces
    info "Removed the legacy post-up hook from /etc/network/interfaces."
fi

# if-up.d runs on every interface up and is not managed by the PVE network
# stack. It must only ENQUEUE the real work: running this script synchronously
# from here blocks networking.service, see section 8 of the header.
install -d -m 0755 /etc/network/if-up.d
install_if_changed /etc/network/if-up.d/security-access 0755 <<'EOF' || true
#!/bin/sh
[ "$MODE" = "start" ] || exit 0
[ -x /usr/local/bin/security-access.sh ] || exit 0

run=0
case "$IFACE" in
    vmbr0) run=1 ;;
    *)
        wan=$(ip -4 route show default 2>/dev/null | awk '/default/ {print $5; exit}')
        if [ -n "$wan" ] && [ "$IFACE" = "$wan" ]; then
            run=1
        fi
        ;;
esac
[ "$run" -eq 1 ] || exit 0

# --no-block: the job waits for network-online.target, ifup does not wait.
/usr/bin/systemctl start --no-block security-access.service >/dev/null 2>&1 || exit 0
exit 0
EOF
[ "$IFC_CHANGED" = "1" ] && info "Boot hook updated."

# The unit that actually applies the rules. It is ordered after the boot
# network and after fail2ban, so no ordering cycle can form.
install_if_changed /etc/systemd/system/security-access.service 0644 <<'EOF' || true
[Unit]
Description=Apply security-access firewall rules
Documentation=https://github.com/FusionPlmH/resources
After=network-online.target fail2ban.service
Wants=network-online.target
ConditionPathExists=/usr/local/bin/security-access.sh

[Service]
Type=oneshot
ExecStart=/usr/local/bin/security-access.sh --self-update
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
EOF
if [ "$IFC_CHANGED" = "1" ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    info "security-access.service updated (daemon-reload done)."
fi
systemctl enable security-access.service >/dev/null 2>&1 || true
info "Boot hook installed: if-up.d hook + security-access.service"

## 10. Show result
echo ""
echo "=================================================="
info "Current active UFW rules:"
echo "=================================================="
ufw status verbose || true

echo ""
info "Security rules setup completed successfully!"
