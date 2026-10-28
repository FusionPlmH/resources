#!/bin/bash
#===============================================================================
# security-access.sh - v4
#
# Expose exactly two TCP ports (Proxmox web UI + SSH) inbound, and only over
# the private LAN, tailscale0 and loopback (cloudflared origin).
#
# Prerequisite on every host: tailscale and cloudflared are installed and
# enabled. A host with a public management address has no other way in.
# ufw is installed automatically when missing; fail2ban is too, but a failure
# to install it is reported loudly instead of silently dropping protection.
#
# The script manages only the rules it created itself (recorded in
# /var/lib/security-access/managed-rules). Rules added by hand - for example a
# VM-to-bridge business rule - are never removed; they are listed as "not
# managed" so they stay visible. RECONCILE_ALL=1 makes it own the whole set.
#
# INVARIANTS - each one is a failure that already happened, do not remove:
#   1. The boot hook never runs this file inside the ifup transaction.
#      networking.service is Before=network.target while fail2ban.service is
#      After=network.target, so "systemctl restart fail2ban" issued from an
#      ifup hook deadlocks the boot and the host never comes back.
#   2. Every systemctl call here uses --no-block, for the same reason.
#   3. ufw does not wait for the xtables lock; retry instead of failing.
#   4. fail2ban's "ufw" action persists one REJECT rule per ban. Untracked
#      leftovers must be purged or they override every allow rule.
#   5. UFW is never left enabled without a verified management path.
#   6. Self-update never downgrades to an older SCRIPT_VERSION.
#===============================================================================
set -euo pipefail

SCRIPT_VERSION="4"
SELF_URL="${SELF_URL:-https://raw.githubusercontent.com/FusionPlmH/resources/refs/heads/main/security-access.sh}"
SELF_DEST="/usr/local/bin/security-access.sh"

PVE_PORT="${PVE_PORT:-8006}"
DRY_RUN="${DRY_RUN:-0}"
SELFCHECK_FATAL="${SELFCHECK_FATAL:-1}"

SELF_UPDATE_REQUESTED=0
NO_SELF_INSTALL=0

info()  { echo -e "\033[0;32m$*\033[0m"; }
warn()  { echo -e "\033[1;33m$*\033[0m"; }
error() { echo -e "\033[0;31m$*\033[0m"; }

for arg in "$@"; do
    case "$arg" in
        --self-update)     SELF_UPDATE_REQUESTED=1 ;;
        --no-self-install) NO_SELF_INSTALL=1 ;;
        --dry-run)         DRY_RUN=1 ;;
        -h|--help)
            cat <<EOF
Usage: $0 [--self-update] [--no-self-install] [--dry-run]
  version: $SCRIPT_VERSION
  --self-update      download, verify and replace $SELF_DEST, then re-exec
  --no-self-install  do not copy the running file to $SELF_DEST
  --dry-run          print the rule diff, change nothing
Environment:
  PVE_PORT=<port>           Proxmox web UI port (default 8006)
  SSH_PORTS_OVERRIDE=22,222 pin the allowed SSH ports
  SELF_URL=<url>            override the download source
  SELFCHECK_FATAL=0         warn instead of disabling UFW when the check fails
  RECONCILE_ALL=1           also remove hand-made rules this script did not create
EOF
            exit 0 ;;
        *) warn "Unknown option: $arg" ;;
    esac
done

if [ "$EUID" -ne 0 ]; then
    error "Please run this script as root."
    exit 1
fi

#------------------------------------------------------------------------------
# Self-update (never downgrades)
#------------------------------------------------------------------------------
self_update() {
    local tmp newf rc=1 cur_ver new_ver
    tmp="$(mktemp /tmp/security-access.XXXXXX.sh)" || return 1
    newf="${SELF_DEST}.new"

    if command -v curl >/dev/null 2>&1; then
        if [ -f "$SELF_DEST" ]; then
            curl -fsSL -z "$SELF_DEST" --connect-timeout 5 --max-time 20 "$SELF_URL" -o "$tmp" && rc=0
            if [ "$rc" -eq 0 ] && [ ! -s "$tmp" ]; then
                rm -f "$tmp"; info "Self-update: already up to date."; return 0
            fi
        else
            curl -fsSL --connect-timeout 5 --max-time 20 "$SELF_URL" -o "$tmp" && rc=0
        fi
    elif command -v wget >/dev/null 2>&1; then
        wget -q -T 20 -t 1 -O "$tmp" "$SELF_URL" && rc=0
    fi

    if [ "$rc" -ne 0 ] || [ ! -s "$tmp" ]; then
        rm -f "$tmp"; warn "Self-update: download failed, keeping the current file."; return 1
    fi
    if ! bash -n "$tmp" 2>/dev/null; then
        rm -f "$tmp"; warn "Self-update: syntax check failed, keeping the current file."; return 1
    fi

    cur_ver="$(sed -n 's/^SCRIPT_VERSION="\([0-9][0-9]*\)".*/\1/p' "$SELF_DEST" 2>/dev/null | head -1)"
    new_ver="$(sed -n 's/^SCRIPT_VERSION="\([0-9][0-9]*\)".*/\1/p' "$tmp" 2>/dev/null | head -1)"
    if [ "${new_ver:-0}" -lt "${cur_ver:-0}" ]; then
        rm -f "$tmp"
        warn "Self-update: remote version ${new_ver:-0} is older than local ${cur_ver:-0}; keeping local."
        return 0
    fi
    if [ -f "$SELF_DEST" ] && cmp -s "$tmp" "$SELF_DEST"; then
        rm -f "$tmp"; info "Self-update: already up to date."; return 0
    fi
    if install -m 0755 "$tmp" "$newf" && mv -f "$newf" "$SELF_DEST"; then
        rm -f "$tmp"; info "Self-update: $SELF_DEST replaced."; return 0
    fi
    rm -f "$tmp" "$newf"; warn "Self-update: write failed, keeping the current file."; return 1
}

if [ "$SELF_UPDATE_REQUESTED" = "1" ] && [ "${SECURITY_ACCESS_SELF_UPDATED:-0}" != "1" ]; then
    if [ "$DRY_RUN" = "1" ]; then
        info "[dry-run] skipping self-update (it would modify $SELF_DEST)."
    else
        self_update || true
        if [ -x "$SELF_DEST" ]; then
            SECURITY_ACCESS_SELF_UPDATED=1 exec "$SELF_DEST" "$@"
        fi
    fi
fi

#------------------------------------------------------------------------------
# ufw wrapper: retry while the xtables lock is held by tailscaled or fail2ban
#------------------------------------------------------------------------------
ufw() {
    local rc tries=0 errf
    errf="$(mktemp /run/.security-access.ufw.XXXXXX 2>/dev/null || echo /dev/null)"
    while : ; do
        command ufw "$@" 2>"$errf"
        rc=$?
        if [ "$rc" -eq 0 ]; then
            [ "$errf" != "/dev/null" ] && rm -f "$errf"
            return 0
        fi
        if grep -qE 'xtables\.lock|Another app is currently holding' "$errf" 2>/dev/null; then
            tries=$((tries + 1))
            if [ "$tries" -lt 10 ]; then
                sleep 1
                continue
            fi
            warn "ufw: xtables lock still busy after ${tries} retries."
        fi
        warn "ufw $* failed (rc=${rc})"
        [ "$errf" != "/dev/null" ] && cat "$errf" >&2 2>/dev/null
        [ "$errf" != "/dev/null" ] && rm -f "$errf"
        return "$rc"
    done
}

#------------------------------------------------------------------------------
# Package prerequisites. Every host must end up with ufw; fail2ban is strongly
# recommended. Both are installed here so a fresh machine needs no manual step.
# The apt calls are bounded: this may run from the boot path.
#------------------------------------------------------------------------------
APT_OPTS=(-o Acquire::http::Timeout=10 -o Acquire::https::Timeout=10 -o Acquire::Retries=1)

pkg_installed() {
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'
}

ensure_pkg() {
    local pkg="$1"
    if pkg_installed "$pkg"; then
        info "$pkg is already installed."
        return 0
    fi
    if [ "$DRY_RUN" = "1" ]; then
        info "  [dry-run] would install $pkg."
        return 0
    fi
    warn "Installing $pkg..."
    if ! { apt-get "${APT_OPTS[@]}" update -qq \
           && apt-get "${APT_OPTS[@]}" install -y -qq "$pkg" >/dev/null 2>&1; }; then
        error "Failed to install $pkg."
        return 1
    fi
    info "  installed $pkg."
    return 0
}

# Write stdin to $1 only when the content differs, so repeated runs (and every
# NIC flap) do not touch timestamps or trigger daemon-reload / service restarts.
FILE_CHANGED=0
install_if_changed() {
    local dest="$1" mode="${2:-0644}" tmp
    FILE_CHANGED=0
    tmp="$(mktemp)" || return 1
    cat > "$tmp" || { rm -f "$tmp"; return 1; }
    if [ -f "$dest" ] && cmp -s "$tmp" "$dest"; then
        rm -f "$tmp"; return 0
    fi
    install -m "$mode" "$tmp" "$dest" && FILE_CHANGED=1
    rm -f "$tmp"
    return 0
}

#------------------------------------------------------------------------------
# Detection helpers
#------------------------------------------------------------------------------
priv_v4() {
    case "${1:-}" in
        10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;
    esac
    return 1
}

iface_exists() { ip link show "$1" >/dev/null 2>&1; }

# Interfaces owning a global IPv4 address, "@parent" removed.
v4_ifaces() {
    ip -4 -o addr show scope global 2>/dev/null | awk '{print $2}' | sed 's/@.*//' | sort -u
}

iface_addrs() {
    ip -4 -o addr show dev "$1" scope global 2>/dev/null | awk '{print $4}'
}

# Real prefix lengths from the routing table, never assumed to be /24.
iface_nets() {
    ip -4 route show dev "$1" scope link 2>/dev/null \
        | awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/ {print $1}'
}

# SSH ports from the configuration files first: at boot sshd is not listening
# yet, so an ss probe would silently fall back to 22 and could lock the host out.
detect_ssh_ports() {
    local f ports="" out
    for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
        [ -f "$f" ] || continue
        ports="$ports $(sed -nE 's/^[[:space:]]*[Pp]ort[[:space:]]+([0-9]+).*/\1/p' "$f" | tr '\n' ' ')"
    done
    if [ -z "${ports// /}" ] && command -v ss >/dev/null 2>&1; then
        ports="$(ss -H -lntp 2>/dev/null | awk '/sshd/ {print $4}' \
                 | sed -E 's/.*:([0-9]+)$/\1/' | grep -E '^[0-9]+$' | tr '\n' ' ')"
    fi
    out="$(printf '%s\n' $ports 2>/dev/null | grep -E '^[0-9]+$' | sort -un | tr '\n' ' ' || true)"
    echo "${out:-22}"
}

# True when this host NATs for its guests; only POSTROUTING counts.
has_nat() {
    if command -v iptables-save >/dev/null 2>&1 \
       && iptables-save -t nat 2>/dev/null | grep -qE '^-A POSTROUTING .* -j (MASQUERADE|SNAT)( |$)'; then
        return 0
    fi
    grep -rhE '^[[:space:]]*(pre-up|post-up).*(MASQUERADE|SNAT)' \
        /etc/network/interfaces /etc/network/interfaces.d/ 2>/dev/null | grep -q .
}

#------------------------------------------------------------------------------
# Rule model
#
# Keys are canonical strings so that the desired and the current rule set can
# be compared as plain text:
#   in|<iface>|<src>|<port>|<proto>    allow in on iface [from src] to any port
#   out|<iface>                        allow out on iface
#   route|<in-iface>|<out-iface>       route allow in on X out on Y
#   rtin|<iface> / rtout|<iface>       route allow in/out on iface
#   from|<src> / to|<dst>              bare allow from/to
#------------------------------------------------------------------------------
# Only the shapes this script creates are parsed. Anything else (application
# profiles, "allow out", bare "allow from") is reported as unmanaged instead of
# being modelled, which keeps the rule vocabulary small.
key_of_line() {
    sed -nE \
        -e 's/^ufw allow in on ([^ ]+) from ([^ ]+) to any port ([0-9]+) proto (tcp|udp)$/in|\1|\2|\3|\4/p' \
        -e 's/^ufw allow in on ([^ ]+) to any port ([0-9]+) proto (tcp|udp)$/in|\1||\2|\3/p' \
        -e 's/^ufw route allow in on ([^ ]+) out on ([^ ]+)$/route|\1|\2/p' \
        -e 's/^ufw route allow in on ([^ ]+)$/rtin|\1/p' \
        -e 's/^ufw route allow out on ([^ ]+)$/rtout|\1/p'
}

# Turn a key back into the arguments "ufw delete" expects.
ufw_args_of_key() {
    IFS='|' read -r k1 k2 k3 k4 k5 <<< "$1"
    case "$k1" in
        in)    if [ -n "$k3" ]; then echo "allow in on $k2 from $k3 to any port $k4 proto $k5"
               else echo "allow in on $k2 to any port $k4 proto $k5"; fi ;;
        route) echo "route allow in on $k2 out on $k3" ;;
        rtin)  echo "route allow in on $k2" ;;
        rtout) echo "route allow out on $k2" ;;
    esac
}

CUR_KEYS=""
DESIRED_KEYS=""
declare -A WANT=()

want() {
    [ -n "${WANT[$1]:-}" ] && return 0
    WANT["$1"]=1
    DESIRED_KEYS="${DESIRED_KEYS}${1}"$'\n'
}

# Collect the rules ufw currently knows about (the persisted user rules).
# Lines this script cannot model are kept verbatim and reported to the operator.
RAW_UNPARSED=""
collect_current() {
    local line key
    CUR_KEYS=""
    RAW_UNPARSED=""
    while IFS= read -r line; do
        if [ -z "$line" ]; then continue; fi
        key="$(printf '%s\n' "$line" | key_of_line)"
        if [ -n "$key" ]; then
            CUR_KEYS="${CUR_KEYS}${key}"$'\n'
        else
            case "$line" in
                # fail2ban bans are handled by purge_ban_tuples + unban --all.
                "ufw reject "*) ;;
                ufw*) RAW_UNPARSED="${RAW_UNPARSED}${line#ufw }"$'\n' ;;
            esac
        fi
    done < <(command ufw show added 2>/dev/null || true)
}

#------------------------------------------------------------------------------
# Interface, port and address discovery
#------------------------------------------------------------------------------
SSH_PORTS="${SSH_PORTS_OVERRIDE:-$(detect_ssh_ports)}"
SSH_PORTS="${SSH_PORTS//,/ }"
ALLOW_PORTS=("$PVE_PORT")
for p in $SSH_PORTS; do
    if [ "$p" != "$PVE_PORT" ]; then ALLOW_PORTS+=("$p"); fi
done

info "Managing ports: $(printf '%s/tcp ' "${ALLOW_PORTS[@]}" | sed 's/ $//')"

# ufw is mandatory: without it there is no firewall to configure.
ensure_pkg ufw || { error "ufw is mandatory; aborting."; exit 1; }
# fail2ban is optional but a missing one is reported, never silently skipped.
HAVE_F2B=0
if ensure_pkg fail2ban; then
    HAVE_F2B=1
else
    warn "fail2ban unavailable: brute-force protection stays off."
fi

WAN_IF="$(ip -4 route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
WAN_ADDR=""
if [ -n "$WAN_IF" ]; then
    WAN_ADDR="$(iface_addrs "$WAN_IF" | head -n1 | cut -d/ -f1)"
fi

HAVE_TS=0
if iface_exists tailscale0; then HAVE_TS=1; fi
HAVE_CLOUDFLARED=0
if systemctl is-enabled --quiet cloudflared 2>/dev/null; then HAVE_CLOUDFLARED=1; fi

LAN_IFACES=()
info "Detecting management interfaces..."
while IFS= read -r ifc; do
    [ -n "$ifc" ] || continue
    case "$ifc" in
        lo|tailscale*|warp*|CloudflareWARP*|cloudflared*|wg*|tun*|tap*|docker*|br-*|veth*|virbr*|zt*) continue ;;
    esac
    matched=0
    while IFS= read -r net; do
        if [ -z "$net" ]; then continue; fi
        if priv_v4 "${net%%/*}"; then
            for p in "${ALLOW_PORTS[@]}"; do
                want "in|${ifc}|${net}|${p}|tcp"
            done
            matched=1
        fi
    done <<< "$(iface_nets "$ifc")"
    if [ "$matched" -eq 0 ]; then
        while IFS= read -r addr; do
            if [ -z "$addr" ]; then continue; fi
            if priv_v4 "${addr%%/*}"; then
                warn "  no link route on $ifc; allowing any source on this interface."
                for p in "${ALLOW_PORTS[@]}"; do
                    want "in|${ifc}||${p}|tcp"
                done
                matched=1
            fi
        done <<< "$(iface_addrs "$ifc")"
    fi
    if [ "$matched" -eq 1 ]; then
        LAN_IFACES+=("$ifc")
        info "  LAN interface: $ifc"
    fi
done < <(v4_ifaces)

# Loopback always: the cloudflared connector connects to 127.0.0.1:8006.
for p in "${ALLOW_PORTS[@]}"; do
    want "in|lo||${p}|tcp"
done
info "  Loopback origin: lo"

if [ "$HAVE_TS" = "1" ]; then
    for p in "${ALLOW_PORTS[@]}"; do
        want "in|tailscale0||${p}|tcp"
    done
    # Exit node / subnet router forwarding.
    want "rtin|tailscale0"
    want "rtout|tailscale0"
    info "  Overlay interface: tailscale0"
fi

# Direct peer links need inbound UDP/41641 on the uplink.
if [ "$HAVE_TS" = "1" ] && [ -n "$WAN_IF" ] && iface_exists "$WAN_IF"; then
    want "in|${WAN_IF}||41641|udp"
fi

# Guest NAT: keep the internal bridges routable to the uplink.
HAVE_NAT=0
if has_nat; then HAVE_NAT=1; fi
if [ "$HAVE_NAT" = "1" ] && [ -n "$WAN_IF" ]; then
    for ifc in ${LAN_IFACES[@]+"${LAN_IFACES[@]}"}; do
        if [ "$ifc" != "$WAN_IF" ]; then want "route|${ifc}|${WAN_IF}"; fi
    done
fi

if [ -n "$WAN_IF" ] && [ -n "$WAN_ADDR" ]; then
    if priv_v4 "$WAN_ADDR"; then
        info "  Uplink $WAN_IF is private ($WAN_ADDR): treated as LAN."
    else
        info "  Uplink $WAN_IF is public ($WAN_ADDR): management ports stay closed."
    fi
fi

if [ "${#LAN_IFACES[@]}" -eq 0 ] && [ "$HAVE_TS" = "0" ] && [ "$HAVE_CLOUDFLARED" = "0" ]; then
    error "No private LAN interface, no tailscale0 and cloudflared is not enabled."
    error "Enabling UFW would leave this host reachable through loopback only."
    error "Install and enable tailscale and cloudflared first (see README)."
    exit 1
fi

#------------------------------------------------------------------------------
# Untracked fail2ban bans make every ufw call rewrite a huge file: purge first.
#------------------------------------------------------------------------------
NEED_UFW_RELOAD=0
purge_ban_tuples() {
    local f before after tmp
    for f in /etc/ufw/user.rules /etc/ufw/user6.rules; do
        [ -f "$f" ] || continue
        before=$(grep -c 'in comment=' "$f" 2>/dev/null || true)
        [ "${before:-0}" -gt 0 ] || continue
        if [ "$DRY_RUN" = "1" ]; then
            info "[dry-run] would purge ${before} stale fail2ban ban tuple(s) from $(basename "$f")."
            continue
        fi
        tmp="$(mktemp)" || continue
        awk '
            /^### tuple ### reject .* in comment=/ { pending=1; next }
            { if (pending==1 && $0 ~ /^-A ufw6?-user-input -s .* -j REJECT$/) { pending=0; next }
              pending=0; print }
        ' "$f" > "$tmp" || { rm -f "$tmp"; continue; }
        after=$(grep -c 'in comment=' "$tmp" 2>/dev/null || true)
        if [ "${after:-0}" -gt 0 ]; then
            warn "  could not purge all ban tuples in $(basename "$f") ($before -> $after)."
            rm -f "$tmp"; continue
        fi
        if cmp -s "$tmp" "$f"; then
            rm -f "$tmp"; continue
        fi
        cp -a "$f" "${f}.bak" 2>/dev/null || true
        if mv -f "$tmp" "$f"; then
            info "  purged ${before} stale ban tuple(s) from $(basename "$f")."
            NEED_UFW_RELOAD=1
        else
            rm -f "$tmp"; warn "  failed to rewrite $f."
        fi
    done
    return 0
}
purge_ban_tuples
if [ "$NEED_UFW_RELOAD" = "1" ] && [ "$DRY_RUN" != "1" ]; then
    ufw reload >/dev/null 2>&1 || true
fi

#------------------------------------------------------------------------------
# Reconcile: add what is missing, remove only what THIS SCRIPT created earlier.
#
# Ownership model: every run records the rules it manages in $MARKER. A rule is
# deleted only when it is listed there and is no longer wanted. Rules added by
# an operator by hand (for example a VM-to-bridge business rule) are never in
# the marker, so they are never removed - they are listed as "not managed".
# Set RECONCILE_ALL=1 to override and treat the whole rule set as owned.
#
# This also makes the first run on an existing host a no-op for deletions,
# which is what makes a fleet-wide rollout safe.
#
# A rule is never deleted while one of its interfaces is missing, so a link
# that is temporarily down at boot keeps the rules needed to get back in.
#------------------------------------------------------------------------------
MARKER_DIR="/var/lib/security-access"
MARKER="${MARKER_DIR}/managed-rules"

declare -A PREV=()
load_marker() {
    PREV=()
    [ -f "$MARKER" ] || return 0
    local k
    while IFS= read -r k; do
        if [ -n "$k" ]; then PREV["$k"]=1; fi
    done < "$MARKER"
    return 0
}

save_marker() {
    [ "$DRY_RUN" = "1" ] && return 0
    install -d -m 0755 "$MARKER_DIR" 2>/dev/null || return 0
    printf '%s' "$DESIRED_KEYS" > "$MARKER" 2>/dev/null || true
    return 0
}

collect_current
load_marker

TO_ADD=(); TO_DEL=()
declare -a TO_ADD TO_DEL
UNMANAGED_RULES=""
while IFS= read -r key; do
    [ -n "$key" ] || continue
    [ -n "${WANT[$key]:-}" ] && continue
    if [ "${RECONCILE_ALL:-0}" = "1" ] || [ -n "${PREV[$key]:-}" ]; then
        TO_DEL+=("$key")
    else
        UNMANAGED_RULES="${UNMANAGED_RULES}$(ufw_args_of_key "$key")"$'\n'
    fi
done <<< "$CUR_KEYS"
for key in $DESIRED_KEYS; do
    case $'\n'"$CUR_KEYS" in
        *$'\n'"$key"$'\n'*) ;;
        *) TO_ADD+=("$key") ;;
    esac
done

key_iface() {
    IFS='|' read -r k1 k2 k3 _ <<< "$1"
    case "$k1" in
        in|rtin|rtout) echo "$k2" ;;
        route) echo "$k2 $k3" ;;
        *) echo "" ;;
    esac
}

info "Applying rules (${#TO_ADD[@]} to add, ${#TO_DEL[@]} to remove)..."
for key in ${TO_DEL[@]+"${TO_DEL[@]}"}; do
    absent=0
    for i in $(key_iface "$key"); do
        if ! iface_exists "$i"; then absent=1; fi
    done
    if [ "$absent" -eq 1 ]; then
        warn "  keeping rule for absent interface: $key"
        continue
    fi
    if [ "$DRY_RUN" = "1" ]; then
        info "  [dry-run] - $(ufw_args_of_key "$key")"
        continue
    fi
    read -r -a args <<< "$(ufw_args_of_key "$key")"
    if ufw delete "${args[@]}" >/dev/null 2>&1; then
        info "  - $(ufw_args_of_key "$key")"
    else
        warn "  failed to delete: $key"
    fi
done

for key in ${TO_ADD[@]+"${TO_ADD[@]}"}; do
    if [ "$DRY_RUN" = "1" ]; then
        info "  [dry-run] + $(ufw_args_of_key "$key")"
        continue
    fi
    read -r -a args <<< "$(ufw_args_of_key "$key")"
    ufw "${args[@]}" >/dev/null 2>&1 || warn "  failed to add: $key"
done

if [ -n "$UNMANAGED_RULES" ] || [ -n "$RAW_UNPARSED" ]; then
    info "Rules not managed by this script (left untouched):"
    printf '%s' "$UNMANAGED_RULES" | sed '/^$/d; s/^/  - /'
    printf '%s' "$RAW_UNPARSED" | sed '/^$/d; s/^/  - /'
fi

if [ "$DRY_RUN" = "1" ]; then
    info "Dry run: nothing changed."
    exit 0
fi

save_marker

#------------------------------------------------------------------------------
# Policy and enable
#------------------------------------------------------------------------------
info "Initializing UFW policies..."
systemctl enable ufw >/dev/null 2>&1 || true
# Another ufw caller (fail2ban's ufw action, or a concurrent run of this script)
# can make a single call fail; the rules themselves are already persisted, so
# retry the policy block instead of aborting.
apply_policy() {
    ufw default deny incoming >/dev/null
    ufw default allow outgoing >/dev/null
    ufw default deny routed >/dev/null
    ufw logging low >/dev/null
    ufw --force enable >/dev/null
}
if ! apply_policy; then
    warn "UFW policy attempt failed; retrying in 3s (concurrent ufw caller?)."
    sleep 3
    if ! apply_policy; then
        error "Could not apply the UFW policy. Check 'ufw status' manually."
        exit 1
    fi
fi
info "UFW enabled; inbound limited to ${ALLOW_PORTS[*]}."

#------------------------------------------------------------------------------
# Self-check: refuse to stay enabled without a management path.
#------------------------------------------------------------------------------
post_apply_selfcheck() {
    local port live missing=0
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
    # A rule on an interface that can never carry management traffic (docker0,
    # a bridge member, ...) must not satisfy this check.
    if ! printf '%s\n' "$live" | grep -qE -- '-i (tailscale[0-9]*|lo) .*--dport [0-9]+ .*-j ACCEPT'; then
        error "self-check: no ACCEPT rule on tailscale0 or lo."
        missing=1
    fi
    if [ "$missing" -eq 0 ]; then
        info "Self-check passed: ${ALLOW_PORTS[*]}/tcp still reachable."
        return 0
    fi
    if [ "$SELFCHECK_FATAL" = "1" ]; then
        error "No management path left; disabling UFW instead of locking out."
        ufw --force disable >/dev/null 2>&1 || true
        exit 1
    fi
    warn "self-check failed (SELFCHECK_FATAL=0): UFW left enabled."
}
post_apply_selfcheck

#------------------------------------------------------------------------------
# Forwarding: kernel knobs only, the rules were reconciled above.
#------------------------------------------------------------------------------
if [ "$HAVE_TS" = "1" ]; then
    info "Configuring tailscale forwarding..."
    # Persist the knob: relying on this run alone would silently lose exit-node
    # routing if the boot unit ever failed. Only IPv4: no host here has an IPv6
    # uplink, so v6 forwarding would be dead configuration.
    install_if_changed /etc/sysctl.d/99-tailscale-forward.conf 0644 <<'EOF' || true
net.ipv4.ip_forward = 1
EOF
    sysctl -qw net.ipv4.ip_forward=1 2>/dev/null || true
    if [ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)" != "1" ]; then
        warn "  net.ipv4.ip_forward is 0: exit node routing will not work."
    fi
    info "  forwarding allowed in/out of tailscale0."
fi

if [ "$HAVE_NAT" = "1" ]; then
    info "NAT detected; forwarding preserved towards $WAN_IF."
else
    info "No NAT detected; forwarding stays at 'deny (routed)'."
fi

#------------------------------------------------------------------------------
# fail2ban
#------------------------------------------------------------------------------
if [ "$HAVE_F2B" = "1" ]; then
    info "Configuring fail2ban..."
    F2B_CHANGED=0

    install_if_changed /etc/fail2ban/filter.d/proxmox.conf 0644 <<'EOF' || true
[Definition]
failregex = ^.*pveproxy\[\d+\]: authentication failure; rhost=<HOST> user=.*$
ignoreregex =
EOF
    [ "$FILE_CHANGED" = "1" ] && F2B_CHANGED=1

    install_if_changed /etc/fail2ban/filter.d/ufw-management.conf 0644 <<'EOF' || true
[Definition]
failregex = \[UFW (BLOCK|AUDIT)\].*SRC=<HOST> DST=
ignoreregex =
EOF
    [ "$FILE_CHANGED" = "1" ] && F2B_CHANGED=1

    if systemctl is-active --quiet rsyslog 2>/dev/null; then
        UFW_JAIL_SOURCE="logpath = /var/log/ufw.log"
    else
        UFW_JAIL_SOURCE="backend = systemd"
    fi
    UFW_JAIL_BLOCK="[ufw]
enabled  = true
filter   = ufw-management
action   = ufw
${UFW_JAIL_SOURCE}
maxretry = 5"

    install_if_changed /etc/fail2ban/jail.local 0644 <<EOF || true
[DEFAULT]
# A ban is inserted before the allow rules, so internal ranges must never be
# banned or the operator locks himself out.
ignoreip = 127.0.0.1/8 ::1 fe80::/10 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 fd7a:115c:a1e0::/48
findtime = 1d
maxretry = 5
bantime  = 1w

[sshd]
enabled  = true
port     = $(echo $SSH_PORTS | tr ' ' ',')
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
    [ "$FILE_CHANGED" = "1" ] && F2B_CHANGED=1

    systemctl enable fail2ban >/dev/null 2>&1 || true
    if [ "$F2B_CHANGED" = "1" ] || ! systemctl is-active --quiet fail2ban 2>/dev/null; then
        # --no-block: this may run inside networking.service, see INVARIANT 1.
        if systemctl restart --no-block fail2ban >/dev/null 2>&1; then
            info "  fail2ban restart requested (non-blocking)."
        else
            warn "  fail2ban restart failed; see /var/log/fail2ban.log."
        fi
    else
        info "  fail2ban configuration unchanged; restart skipped."
    fi
    for _ in 1 2 3 4 5; do
        if fail2ban-client ping >/dev/null 2>&1; then
            fail2ban-client unban --all >/dev/null 2>&1 || true
            info "  all fail2ban bans cleared."
            break
        fi
        sleep 1
    done
fi

#------------------------------------------------------------------------------
# Persist this script and the boot hook
#------------------------------------------------------------------------------
rm -f "${SELF_DEST}.new" "${SELF_DEST}.bak" "${SELF_DEST}.old" 2>/dev/null || true
SELF_PATH="$(readlink -f "$0" 2>/dev/null || true)"
if [ "$NO_SELF_INSTALL" != "1" ] && [ -n "$SELF_PATH" ] && [ -f "$SELF_PATH" ] && [ "$SELF_PATH" != "$SELF_DEST" ]; then
    if [ -f "$SELF_DEST" ] && cmp -s "$SELF_PATH" "$SELF_DEST"; then
        :
    elif [ -f "$SELF_DEST" ] && [ "$SELF_DEST" -nt "$SELF_PATH" ]; then
        warn "Cache $SELF_DEST is newer than $SELF_PATH; not overwriting."
    else
        install -m 0755 "$SELF_PATH" "$SELF_DEST"
        info "Installed this script to $SELF_DEST"
    fi
fi

if grep -q '^[[:space:]]*post-up.*security-access' /etc/network/interfaces 2>/dev/null; then
    sed -i '/^[[:space:]]*post-up.*security-access/d' /etc/network/interfaces
    info "Removed the legacy post-up hook from /etc/network/interfaces."
fi

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
        [ -n "$wan" ] && [ "$IFACE" = "$wan" ] && run=1
        ;;
esac
[ "$run" -eq 1 ] || exit 0
# Enqueue only: running this script inside ifup blocks networking.service.
/usr/bin/systemctl start --no-block security-access.service >/dev/null 2>&1 || exit 0
exit 0
EOF

install_if_changed /etc/systemd/system/security-access.service 0644 <<'EOF' || true
[Unit]
Description=Apply security-access firewall rules
Documentation=https://github.com/FusionPlmH/resources
# tailscaled programs iptables at boot and holds the xtables lock.
After=network-online.target fail2ban.service tailscaled.service
Wants=network-online.target
ConditionPathExists=/usr/local/bin/security-access.sh
StartLimitIntervalSec=300
StartLimitBurst=3

[Service]
Type=oneshot
ExecStart=/usr/local/bin/security-access.sh --self-update
TimeoutStartSec=300
Restart=on-failure
RestartSec=20

[Install]
WantedBy=multi-user.target
EOF
if [ "$FILE_CHANGED" = "1" ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    info "security-access.service updated."
fi
systemctl enable security-access.service >/dev/null 2>&1 || true
info "Boot hook installed: if-up.d hook + security-access.service"

#------------------------------------------------------------------------------
# Result
#------------------------------------------------------------------------------
echo
info "Current active UFW rules:"
ufw status verbose || true
echo
info "Security rules setup completed successfully!"
