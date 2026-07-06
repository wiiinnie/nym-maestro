#!/usr/bin/env bash
# install-nym-extra-blocks.sh  (nym-maestro built-in template / GitHub installer)
# Writes the nym-extra-blocks runtime script + systemd unit that re-applies a
# single per-source rate-limit AND destination REJECTs to NYM-EXIT on every
# nym-node start, then RESTARTS the service so the change applies immediately
# (start alone is a no-op on an already-active RemainAfterExit oneshot).
#
# Teardown is nf_tables-safe: deletes by exact spec (never line number), and
# uses count-based draining (re-count after each delete) so duplicates cannot
# survive. Port 465 (SMTP) rules are never touched.
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

SCRIPT=/usr/local/sbin/nym-extra-blocks.sh
UNIT=/etc/systemd/system/nym-extra-blocks.service

cat > "$SCRIPT" <<'EOF'
#!/usr/bin/env bash
# nym-maestro-managed — do not edit by hand; reinstall via maestro instead.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH
IPT=$(command -v iptables || echo /usr/sbin/iptables)
IPT6=$(command -v ip6tables || echo /usr/sbin/ip6tables)

LIST_URL="https://raw.githubusercontent.com/wiiinnie/nym-maestro/refs/heads/main/blocklist.txt"
CACHE="/var/lib/nym-extra-blocks/blocklist.txt"
CHAIN="NYM-EXIT"; CHAIN6="NYM-EXIT"
IP_RE='^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'
IP6_RE='^[0-9a-fA-F:]*:[0-9a-fA-F:]+(/[0-9]{1,3})?$'
RL_RATE="200/sec"
RL_BURST="1000"

mkdir -p "$(dirname "$CACHE")"
if curl -fsS --max-time 15 "$LIST_URL" -o "${CACHE}.new"; then
    mv "${CACHE}.new" "$CACHE"
else
    echo "fetch failed, using cached list if present" >&2; rm -f "${CACHE}.new"
fi

have4=0
for _ in $(seq 1 30); do
    "$IPT" -nL "$CHAIN" >/dev/null 2>&1 && { have4=1; break; }
    sleep 2
done
[ "$have4" = 1 ] || echo "$CHAIN (v4) not present after waiting" >&2

have6=0
if [ -x "$IPT6" ] && "$IPT6" -nL "$CHAIN6" >/dev/null 2>&1; then have6=1; else
    echo "$CHAIN6 (v6) not present / ip6tables unavailable; skipping IPv6 blocks" >&2
fi

# Count how many rules in CHAIN match an exact -A spec.
count_exact() { "$IPT" -S "$CHAIN" 2>/dev/null | grep -Fxc -- "-A $CHAIN $*" || true; }

# Delete EVERY rule exactly matching the given spec; re-count each pass so no
# duplicate can survive (count-based, not guard-based).
purge_exact() {
    local n; n=$(count_exact "$@")
    while [ "${n:-0}" -gt 0 ]; do
        "$IPT" -D "$CHAIN" "$@" 2>/dev/null || break
        n=$(count_exact "$@")
    done
}

# Drain ALL nym_scan ACCEPT rules regardless of rate value; never touch dport 465.
drain_nym_scan() {
    local spec
    while :; do
        spec=$("$IPT" -S "$CHAIN" 2>/dev/null | grep 'nym_scan' | grep -v 'dport 465' | head -1 || true)
        [ -z "$spec" ] && break
        spec=$(printf '%s\n' "$spec" | sed "s/^-A $CHAIN //")
        "$IPT" -D "$CHAIN" $spec 2>/dev/null || break
    done
}

if [ "$have4" = 1 ]; then
    drain_nym_scan
    purge_exact -p tcp -m conntrack --ctstate NEW -j DROP
    purge_exact -p tcp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

    # insert exactly one clean triplet (final order: established, rate-accept, drop)
    "$IPT" -I "$CHAIN" -p tcp -m conntrack --ctstate NEW -j DROP
    "$IPT" -I "$CHAIN" -p tcp -m conntrack --ctstate NEW -m hashlimit \
        --hashlimit-mode srcip --hashlimit-upto "$RL_RATE" --hashlimit-burst "$RL_BURST" \
        --hashlimit-name nym_scan -j ACCEPT
    "$IPT" -I "$CHAIN" -p tcp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    echo "applied single rate-limit ($RL_RATE burst $RL_BURST) to $CHAIN"
else
    echo "skipped rate-limit: $CHAIN not present" >&2
fi

if [ -f "$CACHE" ]; then
    c4=0; c6=0
    while IFS= read -r line; do
        ip="${line%%#*}"; ip="$(echo "$ip" | xargs)"
        [ -z "$ip" ] && continue
        if [[ "$ip" =~ $IP_RE ]]; then
            [ "$have4" = 1 ] || continue
            "$IPT" -C "$CHAIN" -d "$ip" -j REJECT --reject-with icmp-port-unreachable 2>/dev/null \
                || "$IPT" -I "$CHAIN" -d "$ip" -j REJECT --reject-with icmp-port-unreachable || true
            c4=$((c4+1))
        elif [[ "$ip" == *:* && "$ip" =~ $IP6_RE ]]; then
            [ "$have6" = 1 ] || continue
            "$IPT6" -C "$CHAIN6" -d "$ip" -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null \
                || "$IPT6" -I "$CHAIN6" -d "$ip" -j REJECT --reject-with icmp6-port-unreachable || true
            c6=$((c6+1))
        fi
    done < "$CACHE"
    echo "applied $c4 IPv4 + $c6 IPv6 block entries"
else
    echo "no blocklist available; rate-limit applied, blocks skipped" >&2
fi
EOF
chmod +x "$SCRIPT"

cat > "$UNIT" <<'EOF'
[Unit]
Description=Nym extra blocks + rate-limit for NYM-EXIT
After=nym-node.service
PartOf=nym-node.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStartPre=/bin/sleep 10
ExecStart=/usr/local/sbin/nym-extra-blocks.sh
RemainAfterExit=yes

[Install]
WantedBy=nym-node.service
EOF

systemctl daemon-reload
systemctl enable nym-extra-blocks.service >/dev/null 2>&1 || true
# RESTART (not start): forces the oneshot to re-run so changes apply now.
systemctl restart nym-extra-blocks.service
echo "installed + restarted nym-extra-blocks.service"
