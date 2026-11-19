#!/usr/bin/env bash
# install-nym-concurrency.sh — standalone installer for nym_concurrency.
# maestro itself does NOT run this file: it writes the same runtime script from
# its built-in template (agent.py NC_SCRIPT, word-identical — test_concurrency.py
# checks it). Use this only for a manual install on a node without the agent.
#
# Per-client cap on CONCURRENT new connections to high ports (anti-BitTorrent,
# incl. encrypted MSE) in its own mangle chain NYM-CONCURRENCY, hooked from
# PREROUTING for the tunnel interfaces (nymwg, nymtun0). Complementary to the
# extra-blocks rate/fan-out limits in NYM-EXIT (filter), which cap how FAST a
# client opens connections; this caps how MANY it holds at once.
#
#   sudo NYM_CONCURRENCY_LIMIT=50 ./install-nym-concurrency.sh
#   sudo /usr/local/sbin/nym-concurrency.sh stop     # remove rules (unit stays)
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

SCRIPT=/usr/local/sbin/nym-concurrency.sh
UNIT=/etc/systemd/system/nym-concurrency.service
STATE_DIR=/var/lib/nym-concurrency
LIMIT="${NYM_CONCURRENCY_LIMIT:-50}"
[[ "$LIMIT" =~ ^[0-9]+$ ]] && [ "$LIMIT" -ge 10 ] && [ "$LIMIT" -le 10000 ] \
    || { echo "NYM_CONCURRENCY_LIMIT must be an integer 10..10000"; exit 1; }

mkdir -p "$STATE_DIR"
echo "$LIMIT" > "$STATE_DIR/limit"

cat > "$SCRIPT" <<'EOF'
#!/usr/bin/env bash
# nym-maestro-managed — do not edit by hand; reinstall via maestro instead.
# nym_concurrency: per-client cap on CONCURRENT new connections to high ports
# (anti-BitTorrent, incl. encrypted MSE). Own chain in mangle, hooked from
# PREROUTING for the tunnel interfaces only. Usage: nym-concurrency.sh [apply|stop]
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH

STATE_DIR=/var/lib/nym-concurrency
DEFAULT_LIMIT=50
LIMIT_MIN=10
LIMIT_MAX=10000
PORT_LO=12000
PORT_HI=65535
WG_PORT=51822                 # WireGuard gateway, exempt
STEAM_LO=27000
STEAM_HI=27050                # Steam, exempt
IFACES="nymwg nymtun0"        # client traffic enters the exit only here
CHAIN=NYM-CONCURRENCY
TABLE=mangle
COMMENT=nym_concurrency

# Limit comes from a file (set by maestro), never from the script text.
LIMIT="$(cat "$STATE_DIR/limit" 2>/dev/null || true)"
LIMIT="${LIMIT//[[:space:]]/}"
if [[ "$LIMIT" =~ ^[0-9]{1,6}$ ]] && [ $((10#$LIMIT)) -ge $LIMIT_MIN ] && [ $((10#$LIMIT)) -le $LIMIT_MAX ]; then
    LIMIT=$((10#$LIMIT))
else
    [ -z "$LIMIT" ] || echo "invalid limit '$LIMIT' in $STATE_DIR/limit, using $DEFAULT_LIMIT" >&2
    LIMIT=$DEFAULT_LIMIT
fi

# Remove every PREROUTING jump to our chain (with or without -i), by exact spec —
# never by line number (fails silently on the nf_tables backend). Loops until
# none is left, so duplicates from earlier runs are drained.
unhook() {
    local ipt="$1" line n=0
    local -a spec
    while :; do
        line=$("$ipt" -t "$TABLE" -S PREROUTING 2>/dev/null \
            | grep -E -- "^-A PREROUTING( -i [A-Za-z0-9_.+-]+)? -j $CHAIN\$" | head -n1 || true)
        [ -n "$line" ] || return 0
        read -r -a spec <<< "${line#-A PREROUTING }"
        "$ipt" -t "$TABLE" -D PREROUTING "${spec[@]}" || return 1
        n=$((n+1)); [ "$n" -lt 100 ] || return 1
    done
}

teardown() {
    local ipt="$1"
    unhook "$ipt" || true
    "$ipt" -t "$TABLE" -F "$CHAIN" 2>/dev/null || true
    "$ipt" -t "$TABLE" -X "$CHAIN" 2>/dev/null || true
}

# Build the chain, THEN hook it, so a failed rule never leaves a live half-limiter.
nc_apply() {
    local ipt="$1" mask="$2" fam="$3" proto ifc
    "$ipt" -t "$TABLE" -N "$CHAIN" 2>/dev/null || "$ipt" -t "$TABLE" -F "$CHAIN" || return 1
    # exemptions first (first match wins)
    "$ipt" -t "$TABLE" -A "$CHAIN" -m addrtype --dst-type LOCAL -j RETURN || return 1
    "$ipt" -t "$TABLE" -A "$CHAIN" -p udp --dport "$WG_PORT" -j RETURN || return 1
    for proto in tcp udp; do
        "$ipt" -t "$TABLE" -A "$CHAIN" -p "$proto" --dport "$STEAM_LO:$STEAM_HI" -j RETURN || return 1
    done
    # only NEW connections are checked: established flows are never touched and
    # the per-packet path stays cheap
    for proto in tcp udp; do
        "$ipt" -t "$TABLE" -A "$CHAIN" -p "$proto" --dport "$PORT_LO:$PORT_HI" \
            -m conntrack --ctstate NEW \
            -m connlimit --connlimit-above "$LIMIT" --connlimit-mask "$mask" \
            -m comment --comment "$COMMENT" -j DROP || return 1
    done
    unhook "$ipt" || return 1
    for ifc in $IFACES; do
        "$ipt" -t "$TABLE" -I PREROUTING -i "$ifc" -j "$CHAIN" || return 1
    done
    echo "applied nym_concurrency (v$fam): limit $LIMIT concurrent per client, ports $PORT_LO-$PORT_HI, ifaces $IFACES"
}

# IPv6 is best-effort: only when ip6tables and its mangle table are usable.
IPT6=""
if command -v ip6tables >/dev/null 2>&1 && ip6tables -t "$TABLE" -nL PREROUTING >/dev/null 2>&1; then
    IPT6=ip6tables
fi

case "${1:-apply}" in
    stop)
        teardown iptables
        if [ -n "$IPT6" ]; then teardown "$IPT6"; fi
        echo "nym_concurrency removed"
        exit 0 ;;
    apply) ;;
    *) echo "usage: $0 [apply|stop]" >&2; exit 2 ;;
esac

modprobe nf_conntrack 2>/dev/null || true

if ! nc_apply iptables 32 4; then
    teardown iptables
    echo "nym_concurrency FAILED (v4) — rules removed, limiter NOT active" >&2
    exit 1
fi
if [ -n "$IPT6" ]; then
    if ! nc_apply "$IPT6" 128 6; then
        teardown "$IPT6"
        echo "nym_concurrency FAILED (v6) — v6 limiter not active, v4 unaffected" >&2
    fi
else
    echo "ip6tables mangle not available; v6 limiter skipped" >&2
fi
EOF
chmod +x "$SCRIPT"

cat > "$UNIT" <<'EOF'
[Unit]
Description=Per-client concurrent-connection limit on high ports (anti-BitTorrent, nym maestro managed)
After=nym-node.service
PartOf=nym-node.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStartPre=/bin/sleep 10
ExecStart=/usr/local/sbin/nym-concurrency.sh apply
ExecStop=/usr/local/sbin/nym-concurrency.sh stop
RemainAfterExit=yes

[Install]
WantedBy=nym-node.service
EOF

systemctl daemon-reload
systemctl enable nym-concurrency.service >/dev/null 2>&1 || true
# restart, not start: on an active oneshot (RemainAfterExit) start is a no-op
systemctl restart nym-concurrency.service
systemctl show nym-concurrency.service -p ActiveEnterTimestamp
echo "installed + restarted nym-concurrency.service (limit $LIMIT)"
