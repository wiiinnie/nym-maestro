#!/usr/bin/env bash
# install-nym-extra-blocks.sh  (nym-maestro built-in template)
# Installs the nym-extra-blocks runtime script + systemd unit that re-applies
# destination REJECTs AND a single per-source rate-limit to NYM-EXIT on every
# nym-node start.
#
# FIX vs. earlier versions: the rate-limit delete-guard now removes EVERY existing
# nym_scan rule by name (loop over line numbers) before inserting exactly one, so
# retuning the rate can never leave old rules stacked in the chain.
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

SCRIPT=/usr/local/sbin/nym-extra-blocks.sh
UNIT=/etc/systemd/system/nym-extra-blocks.service

cat > "$SCRIPT" <<'EOF'
#!/usr/bin/env bash
# nym-maestro-managed — do not edit by hand; reinstall via maestro instead.
set -euo pipefail

LIST_URL="https://raw.githubusercontent.com/wiiinnie/nym-maestro/refs/heads/main/blocklist.txt"
CACHE="/var/lib/nym-extra-blocks/blocklist.txt"
CHAIN="NYM-EXIT"
CHAIN6="NYM-EXIT"
IP_RE='^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'
IP6_RE='^[0-9a-fA-F:]*:[0-9a-fA-F:]+(/[0-9]{1,3})?$'

# active rate-limit parameters (change here to retune fleet-wide via the template)
RL_RATE="200/sec"
RL_BURST="1000"

mkdir -p "$(dirname "$CACHE")"

# Fetch; only overwrite cache on a clean download, else keep last-known-good.
if curl -fsS --max-time 15 "$LIST_URL" -o "${CACHE}.new"; then
    mv "${CACHE}.new" "$CACHE"
else
    echo "fetch failed, using cached list" >&2
    rm -f "${CACHE}.new"
fi
[ -f "$CACHE" ] || { echo "no list available, nothing to do"; exit 0; }

# nym-node flushes/recreates the exit chains on start, so wait for the v4 chain to
# exist before applying ON TOP. Poll rather than rely on a fixed sleep.
have4=0
for _ in $(seq 1 30); do
    iptables -nL "$CHAIN" >/dev/null 2>&1 && { have4=1; break; }
    sleep 2
done
[ "$have4" = 1 ] || echo "$CHAIN (v4) not present after waiting" >&2

have6=0
if command -v ip6tables >/dev/null 2>&1 && ip6tables -nL "$CHAIN6" >/dev/null 2>&1; then
    have6=1
else
    echo "$CHAIN6 (v6) not present / ip6tables unavailable; skipping IPv6 blocks" >&2
fi

# Per-source rate-limit. FIRST remove EVERY existing nym_scan rule by name
# (loop over line numbers) so previous values can't stack; then remove the paired
# DROP and ESTABLISHED-accept; then insert exactly one fresh set.
if [ "$have4" = 1 ]; then
    while iptables -L "$CHAIN" --line-numbers -n 2>/dev/null | grep -q 'nym_scan'; do
        ln=$(iptables -L "$CHAIN" --line-numbers -n | awk '/nym_scan/{print $1; exit}')
        iptables -D "$CHAIN" "$ln" || break
    done
    iptables -D "$CHAIN" -p tcp -m conntrack --ctstate NEW -j DROP 2>/dev/null || true
    iptables -D "$CHAIN" -p tcp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

    # insert (reverse of final order; -I pushes to top):
    #   1) ESTABLISHED/RELATED accept  2) NEW up-to-rate accept  3) NEW over-rate drop
    iptables -I "$CHAIN" -p tcp -m conntrack --ctstate NEW -j DROP
    iptables -I "$CHAIN" -p tcp -m conntrack --ctstate NEW -m hashlimit \
        --hashlimit-mode srcip --hashlimit-upto "$RL_RATE" --hashlimit-burst "$RL_BURST" \
        --hashlimit-name nym_scan -j ACCEPT
    iptables -I "$CHAIN" -p tcp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    echo "applied single rate-limit ($RL_RATE burst $RL_BURST) to $CHAIN"
fi

c4=0; c6=0
while IFS= read -r line; do
    ip="${line%%#*}"; ip="$(echo "$ip" | xargs)"
    [ -z "$ip" ] && continue
    if [[ "$ip" =~ $IP_RE ]]; then
        [ "$have4" = 1 ] || continue
        if ! iptables -C "$CHAIN" -d "$ip" -j REJECT --reject-with icmp-port-unreachable 2>/dev/null; then
            iptables -I "$CHAIN" -d "$ip" -j REJECT --reject-with icmp-port-unreachable \
                || { echo "v4 add failed: $ip" >&2; continue; }
        fi
        c4=$((c4+1))
    elif [[ "$ip" == *:* && "$ip" =~ $IP6_RE ]]; then
        [ "$have6" = 1 ] || continue
        if ! ip6tables -C "$CHAIN6" -d "$ip" -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null; then
            ip6tables -I "$CHAIN6" -d "$ip" -j REJECT --reject-with icmp6-port-unreachable \
                || { echo "v6 add failed: $ip" >&2; continue; }
        fi
        c6=$((c6+1))
    else
        echo "skipping invalid entry: $ip" >&2
    fi
done < "$CACHE"

echo "applied $c4 IPv4 + $c6 IPv6 block entries"
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
systemctl disable nym-extra-blocks.service 2>/dev/null || true
systemctl enable nym-extra-blocks.service
systemctl start nym-extra-blocks.service
echo "installed nym-extra-blocks.service (enabled); ran once."
