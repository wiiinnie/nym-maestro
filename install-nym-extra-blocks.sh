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

# Fan-out limiter (netscan protection, Hetzner 2610:3I8XTEPNAC40): caps how many
# NEW DISTINCT destinations one tunnel client may open. Stage 1 lets only the
# first SYN per (client, dst) pair within ~1h through to stage 2; stage 2 counts
# those per client and RSTs above FO_RATE/FO_BURST. Repeat connections to known
# destinations are never counted. No LOG target: nothing about clients is stored.
# FO_ENABLE=0 + "Run installer" removes the limiter again (kill switch).
FO_ENABLE=1
FO_RATE="20/minute"
FO_BURST="150"
FO_CHAIN="NYM-FANOUT"
FO_CHAIN_NEW="NYM-FANOUT-NEWDST"

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

# Drain ALL nym_scan* rules (legacy ACCEPT and v2 DROP) regardless of rate; never touch dport 465.
drain_nym_scan() {
    local spec
    while :; do
        spec=$("$IPT" -S "$CHAIN" 2>/dev/null | grep 'nym_scan' | grep -v 'dport 465' | head -1 || true)
        [ -z "$spec" ] && break
        spec=$(printf '%s\n' "$spec" | sed "s/^-A $CHAIN //")
        "$IPT" -D "$CHAIN" $spec 2>/dev/null || break
    done
}

# Apply (or with FO_ENABLE=0 remove) the fan-out limiter for one family.
# Rules live in our own sub-chains, so the per-source rate parser on NYM-EXIT and
# nym-node's exit policy are untouched; only one jump rule sits in NYM-EXIT.
# nym-node flushes NYM-EXIT on restart (jump gone) -> this oneshot re-adds it.
fanout_apply() {
    local ipt="$1" chain="$2" fam="$3" n
    # drop every existing jump (count-based, exact spec — never line numbers)
    n=$("$ipt" -S "$chain" 2>/dev/null | grep -Fxc -- "-A $chain -j $FO_CHAIN" || true)
    while [ "${n:-0}" -gt 0 ]; do
        "$ipt" -D "$chain" -j "$FO_CHAIN" 2>/dev/null || break
        n=$("$ipt" -S "$chain" 2>/dev/null | grep -Fxc -- "-A $chain -j $FO_CHAIN" || true)
    done
    if [ "$FO_ENABLE" != 1 ]; then
        "$ipt" -F "$FO_CHAIN" 2>/dev/null || true; "$ipt" -X "$FO_CHAIN" 2>/dev/null || true
        "$ipt" -F "$FO_CHAIN_NEW" 2>/dev/null || true; "$ipt" -X "$FO_CHAIN_NEW" 2>/dev/null || true
        echo "fan-out limiter removed (v$fam)"
        return 0
    fi
    "$ipt" -N "$FO_CHAIN" 2>/dev/null || "$ipt" -F "$FO_CHAIN"
    "$ipt" -N "$FO_CHAIN_NEW" 2>/dev/null || "$ipt" -F "$FO_CHAIN_NEW"
    # stage 1: first SYN to a (client, destination) pair not seen within ~1h
    "$ipt" -A "$FO_CHAIN" -p tcp --syn -m conntrack --ctstate NEW -m hashlimit \
        --hashlimit-mode srcip,dstip --hashlimit-upto 1/hour --hashlimit-burst 1 \
        --hashlimit-htable-size 131072 --hashlimit-htable-max 524288 \
        --hashlimit-htable-expire 3600000 --hashlimit-name "fo_pair$fam" -j "$FO_CHAIN_NEW"
    "$ipt" -A "$FO_CHAIN" -j RETURN
    # stage 2: cap new distinct destinations per client, fast-fail with RST
    "$ipt" -A "$FO_CHAIN_NEW" -p tcp -m hashlimit --hashlimit-mode srcip \
        --hashlimit-above "$FO_RATE" --hashlimit-burst "$FO_BURST" \
        --hashlimit-htable-expire 600000 --hashlimit-name "fo_src$fam" \
        -j REJECT --reject-with tcp-reset
    "$ipt" -A "$FO_CHAIN_NEW" -j RETURN
    # matches only NEW SYNs, falls through otherwise -> never bypasses the exit policy
    "$ipt" -I "$chain" -j "$FO_CHAIN"
    echo "applied fan-out limiter (v$fam): reject above $FO_RATE new destinations, burst $FO_BURST"
}

if [ "$have4" = 1 ]; then
    drain_nym_scan                     # removes legacy nym_scan ACCEPT and nym_scan_v2 DROP
    purge_exact -p tcp -m conntrack --ctstate NEW -j DROP   # legacy catch-all DROP
    purge_exact -p tcp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

    # DROP only the excess and let the rest FALL THROUGH to the exit policy.
    # Never ACCEPT NEW here: it would bypass the policy's port filter entirely.
    "$IPT" -I "$CHAIN" -p tcp -m conntrack --ctstate NEW -m hashlimit \
        --hashlimit-mode srcip --hashlimit-above "$RL_RATE" --hashlimit-burst "$RL_BURST" \
        --hashlimit-name nym_scan_v2 -j DROP
    fanout_apply "$IPT" "$CHAIN" 4
    "$IPT" -I "$CHAIN" -p tcp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    echo "applied per-source rate-limit (drop above $RL_RATE burst $RL_BURST) to $CHAIN"
else
    echo "skipped rate-limit: $CHAIN not present" >&2
fi

if [ "$have6" = 1 ]; then
    fanout_apply "$IPT6" "$CHAIN6" 6
fi

if [ -f "$CACHE" ]; then
    c4=0; c6=0
    while IFS= read -r line; do
        ip="${line%%#*}"; ip="$(echo "$ip" | xargs)"
        [ -z "$ip" ] && continue
        if [[ "$ip" =~ $IP_RE ]]; then
            [ "$have4" = 1 ] || continue
            # delete + re-insert so blocks always sit at the top of the chain
            while "$IPT" -D "$CHAIN" -d "$ip" -j REJECT --reject-with icmp-port-unreachable 2>/dev/null; do :; done
            "$IPT" -I "$CHAIN" -d "$ip" -j REJECT --reject-with icmp-port-unreachable || true
            c4=$((c4+1))
        elif [[ "$ip" == *:* && "$ip" =~ $IP6_RE ]]; then
            [ "$have6" = 1 ] || continue
            while "$IPT6" -D "$CHAIN6" -d "$ip" -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null; do :; done
            "$IPT6" -I "$CHAIN6" -d "$ip" -j REJECT --reject-with icmp6-port-unreachable || true
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
