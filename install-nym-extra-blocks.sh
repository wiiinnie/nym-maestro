#!/usr/bin/env bash
# install-nym-extra-blocks.sh — standalone installer for nym-extra-blocks.
# maestro itself does NOT run this file: the agent writes the same runtime script
# from its built-in template (agent.py EB_SCRIPT, word-identical with CHAIN6 set
# to NYM-EXIT — test_extra_blocks.py checks it) and ships the blocklist that is
# maintained in the maestro UI. Use this only for a manual install without agent:
#
#   sudo ./install-nym-extra-blocks.sh blocklist.txt
#
# The list file: one IPv4/IPv6 address or CIDR per line, '#' comments allowed.
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
[ -f "${1:-}" ] || { echo "usage: $0 <blocklist.txt>"; exit 1; }

SCRIPT=/usr/local/sbin/nym-extra-blocks.sh
UNIT=/etc/systemd/system/nym-extra-blocks.service
STATE_DIR=/var/lib/nym-extra-blocks

mkdir -p "$STATE_DIR"
# keep the list an older version applied, so its unmarked REJECTs get migrated
if [ -f "$STATE_DIR/blocklist.txt" ] && [ ! -f "$STATE_DIR/legacy.txt" ]; then
    cp "$STATE_DIR/blocklist.txt" "$STATE_DIR/legacy.txt"
fi
cp "$1" "$STATE_DIR/blocklist.txt"
rm -f "$STATE_DIR/list_url"

cat > "$SCRIPT" <<'EOF'
#!/usr/bin/env bash
# nym-maestro-managed — do not edit by hand; reinstall via maestro instead.
# Re-applies to NYM-EXIT on every nym-node start (nym-node / NTM flush the chain):
#   1. per-source scan rate-limit (nym_scan_v2) — maestro's own rule
#   2. fan-out limiter (own sub-chains, one jump in NYM-EXIT)
#   3. destination blocklist: REJECTs marked with the comment nym_block. The list
#      is written by maestro (blocklist.txt); nothing is fetched from the network.
# Every delete is by exact spec and count-/loop-based (never by line number: that
# fails silently on the nf_tables backend and lets rules stack).
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH
IPT=$(command -v iptables || echo /usr/sbin/iptables)
IPT6=$(command -v ip6tables || echo /usr/sbin/ip6tables)

STATE_DIR="/var/lib/nym-extra-blocks"
LIST="$STATE_DIR/blocklist.txt"     # current list, written by maestro
LEGACY="$STATE_DIR/legacy.txt"      # list of the pre-marker versions (migration)
CHAIN="NYM-EXIT"
CHAIN6="NYM-EXIT"
MARK="nym_block"
IP_RE='^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'
IP6_RE='^[0-9a-fA-F:]*:[0-9a-fA-F:]+(/[0-9]{1,3})?$'
RL_RATE="200/sec"
RL_BURST="1000"

# Fan-out limiter (netscan protection, Hetzner 2610:3I8XTEPNAC40): caps how many
# NEW DISTINCT destinations one tunnel client may open. Stage 1 lets only the
# first SYN per (client, dst) pair within ~1h through to stage 2; stage 2 counts
# those per client and RSTs above FO_RATE/FO_BURST. Repeat connections to known
# destinations are never counted. No LOG target: nothing about clients is stored.
# FO_ENABLE=0 + reinstall removes the limiter again (kill switch).
FO_ENABLE=1
FO_RATE="20/minute"
FO_BURST="150"
FO_CHAIN="NYM-FANOUT"
FO_CHAIN_NEW="NYM-FANOUT-NEWDST"

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
        --hashlimit-htable-expire 3600000 --hashlimit-name "fo_pair$fam" -j "$FO_CHAIN_NEW" || return 1
    "$ipt" -A "$FO_CHAIN" -j RETURN
    # stage 2: cap new distinct destinations per client, fast-fail with RST
    "$ipt" -A "$FO_CHAIN_NEW" -p tcp -m hashlimit --hashlimit-mode srcip \
        --hashlimit-above "$FO_RATE" --hashlimit-burst "$FO_BURST" \
        --hashlimit-htable-expire 600000 --hashlimit-name "fo_src$fam" \
        -j REJECT --reject-with tcp-reset || return 1
    "$ipt" -A "$FO_CHAIN_NEW" -j RETURN
    # matches only NEW SYNs, falls through otherwise -> never bypasses the exit policy.
    # Hooked last, so a failed rule above leaves no half-built limiter in NYM-EXIT.
    "$ipt" -I "$chain" -j "$FO_CHAIN" || return 1
    echo "applied fan-out limiter (v$fam): reject above $FO_RATE new destinations, burst $FO_BURST"
}

# nym-node flushes/recreates the exit chains on start, so wait for the v4 chain to
# exist before applying ON TOP. Poll rather than rely on a fixed sleep.
have4=0
for _ in $(seq 1 30); do
    "$IPT" -nL "$CHAIN" >/dev/null 2>&1 && { have4=1; break; }
    sleep 2
done
[ "$have4" = 1 ] || echo "$CHAIN (v4) not present after waiting" >&2

# IPv6 is best-effort: only if ip6tables and the v6 exit chain exist on this node.
have6=0
if [ -x "$IPT6" ] && "$IPT6" -nL "$CHAIN6" >/dev/null 2>&1; then
    have6=1
else
    echo "$CHAIN6 (v6) not present / ip6tables unavailable; skipping IPv6" >&2
fi

# Delete EVERY rule exactly matching the spec; re-count each pass (count-based).
purge_exact() {   # $1=ipt $2=chain $3..=spec
    local ipt="$1" ch="$2" n; shift 2
    n=$("$ipt" -S "$ch" 2>/dev/null | grep -Fxc -- "-A $ch $*" || true)
    while [ "${n:-0}" -gt 0 ]; do
        "$ipt" -D "$ch" "$@" 2>/dev/null || break
        n=$("$ipt" -S "$ch" 2>/dev/null | grep -Fxc -- "-A $ch $*" || true)
    done
}

# Delete every rule whose -S line matches the (grep -E) pattern, by its exact
# spec as printed by -S. Loops until none is left.
drain_matching() {   # $1=ipt $2=chain $3=pattern [$4=exclude pattern]
    local ipt="$1" ch="$2" pat="$3" excl="${4:-}" line n=0
    local -a spec
    while :; do
        if [ -n "$excl" ]; then
            line=$("$ipt" -S "$ch" 2>/dev/null | grep -E -- "$pat" | grep -Ev -- "$excl" | head -n1 || true)
        else
            line=$("$ipt" -S "$ch" 2>/dev/null | grep -E -- "$pat" | head -n1 || true)
        fi
        [ -n "$line" ] || return 0
        read -r -a spec <<< "${line#-A $ch }"
        "$ipt" -D "$ch" "${spec[@]}" || return 1
        n=$((n+1)); [ "$n" -lt 10000 ] || return 1
    done
}

# --- 1+2. scan rate-limit + fan-out limiter ----------------------------------
# DROP only the excess and let the rest FALL THROUGH to the exit policy. Never
# ACCEPT NEW here: an ACCEPT above the policy would bypass its port filter (every
# TCP port reachable, only throttled) — that was the pre-0.12.3 behaviour.
# All nym_scan* copies (legacy upto/ACCEPT and nym_scan_v2 at any rate) are
# drained first, so re-runs never stack; port 465 (NTM's SMTPS limit) is untouched.
if [ "$have4" = 1 ]; then
    drain_matching "$IPT" "$CHAIN" 'nym_scan' 'dport 465' || echo "nym_scan drain incomplete" >&2
    purge_exact "$IPT" "$CHAIN" -p tcp -m conntrack --ctstate NEW -j DROP   # legacy catch-all DROP
    purge_exact "$IPT" "$CHAIN" -p tcp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    "$IPT" -I "$CHAIN" -p tcp -m conntrack --ctstate NEW -m hashlimit \
        --hashlimit-mode srcip --hashlimit-above "$RL_RATE" --hashlimit-burst "$RL_BURST" \
        --hashlimit-name nym_scan_v2 -j DROP
    fanout_apply "$IPT" "$CHAIN" 4 || echo "fan-out limiter FAILED (v4), continuing" >&2
    "$IPT" -I "$CHAIN" -p tcp -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    echo "applied rate-limit (drop above $RL_RATE burst $RL_BURST) to $CHAIN"
fi
if [ "$have6" = 1 ]; then
    fanout_apply "$IPT6" "$CHAIN6" 6 || echo "fan-out limiter FAILED (v6), continuing" >&2
fi

# --- 3. blocklist: reconcile, not append --------------------------------------
# (a) drain ALL nym_block-marked REJECTs -> entries removed in maestro disappear
# (b) migration: drain the unmarked REJECTs older versions inserted, for every
#     entry of the current and the legacy list (exact old spec only, so nym-node's
#     own policy REJECTs with ports/other targets are never touched)
# (c) insert the current list, marked, at the top of the chain
entries() { [ -f "$1" ] || return 0; sed -e 's/#.*//' -e 's/[[:space:]]//g' "$1" | grep -v '^$' || true; }
c4=0; c6=0
if [ "$have4" = 1 ]; then
    drain_matching "$IPT" "$CHAIN" "--comment $MARK( |\$)" || echo "v4 $MARK drain incomplete" >&2
fi
if [ "$have6" = 1 ]; then
    drain_matching "$IPT6" "$CHAIN6" "--comment $MARK( |\$)" || echo "v6 $MARK drain incomplete" >&2
fi
for ip in $( { entries "$LIST"; entries "$LEGACY"; } | sort -u ); do
    if [[ "$ip" =~ $IP_RE ]]; then
        [ "$have4" = 1 ] || continue
        while "$IPT" -D "$CHAIN" -d "$ip" -j REJECT --reject-with icmp-port-unreachable 2>/dev/null; do :; done
    elif [[ "$ip" == *:* && "$ip" =~ $IP6_RE ]]; then
        [ "$have6" = 1 ] || continue
        while "$IPT6" -D "$CHAIN6" -d "$ip" -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null; do :; done
    fi
done
for ip in $(entries "$LIST"); do
    if [[ "$ip" =~ $IP_RE ]]; then
        [ "$have4" = 1 ] || continue
        "$IPT" -I "$CHAIN" -d "$ip" -m comment --comment "$MARK" \
            -j REJECT --reject-with icmp-port-unreachable || { echo "v4 add failed: $ip" >&2; continue; }
        c4=$((c4+1))
    elif [[ "$ip" == *:* && "$ip" =~ $IP6_RE ]]; then
        [ "$have6" = 1 ] || continue
        "$IPT6" -I "$CHAIN6" -d "$ip" -m comment --comment "$MARK" \
            -j REJECT --reject-with icmp6-port-unreachable || { echo "v6 add failed: $ip" >&2; continue; }
        c6=$((c6+1))
    else
        echo "skipping invalid entry: $ip" >&2
    fi
done
echo "applied $c4 IPv4 + $c6 IPv6 $MARK entries"
EOF
chmod +x "$SCRIPT"

cat > "$UNIT" <<'EOF'
[Unit]
Description=Extra destination blocks for NYM-EXIT (nym maestro managed)
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
# restart, not start: on an active oneshot (RemainAfterExit) start is a no-op
systemctl restart nym-extra-blocks.service
systemctl show nym-extra-blocks.service -p ActiveEnterTimestamp
echo "installed + restarted nym-extra-blocks.service"
