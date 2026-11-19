#!/usr/bin/env python3
"""nym maestro agent — runs on each node.

Stdlib only (http.server, ssl, subprocess, urllib, json) so the fleet needs no
pip installs. Exposes a mutually-authenticated HTTPS API:

    GET /v1/health   liveness + agent version
    GET /v1/status   telemetry for the dashboard grid

Config comes from the environment (set by the systemd unit / agent.env):

    MAESTRO_AGENT_HOST      bind address           (default 0.0.0.0)
    MAESTRO_AGENT_PORT      listen port            (default 8443)
    MAESTRO_AGENT_CERTDIR   cert directory         (default /etc/nym-maestro-agent)
                            expects server.crt, server.key, ca.crt
    MAESTRO_NYM_PORT        nym-node HTTP API port (default 8080)
    MAESTRO_NYM_SERVICE     systemd unit name      (default nym-node.service)

The agent is additive: it discovers the already-installed node setup and never
re-provisions it. Write actions arrive in later slices; for now it is read-only.
"""
import base64
import contextlib
import hashlib
import ipaddress
import json
import os
import re
import pwd
import shlex
import shutil
import sqlite3
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

AGENT_VERSION = "0.12.9"

try:
    with open(os.path.abspath(__file__), "rb") as _sf:
        AGENT_SHA = hashlib.sha256(_sf.read()).hexdigest()
except Exception:
    AGENT_SHA = None

HOST = os.environ.get("MAESTRO_AGENT_HOST", "0.0.0.0")
PORT = int(os.environ.get("MAESTRO_AGENT_PORT", "8443"))
CERTDIR = os.environ.get("MAESTRO_AGENT_CERTDIR", "/etc/nym-maestro-agent")
# The agent accepts only the orchestrator's client cert. All node certs are signed
# by the same CA, so a CA-signed check alone would let any node (or anyone holding a
# node's server key) drive root actions on every other node. We additionally pin the
# client cert's Common Name to the orchestrator's, so one compromised node cannot
# impersonate the orchestrator against the rest of the fleet.
ORCH_CN = os.environ.get("MAESTRO_ORCH_CN", "nym-maestro-orchestrator")
NYM_PORT = int(os.environ.get("MAESTRO_NYM_PORT", "8080"))
NYM_SERVICE = os.environ.get("MAESTRO_NYM_SERVICE", "nym-node.service")

# Live throughput is computed nload-style: sample /proc/net/dev on a short
# interval and diff the byte counters. No external tool, no sudo, no HTTP.
TRAFFIC_DEVICES = [d for d in os.environ.get(
    "MAESTRO_TRAFFIC_DEVICES", "nymtun0,nymwg").split(",") if d.strip()]
# the decrypted-exit tunnels (what leaves the node to the internet)
EXIT_DEVICES = list(TRAFFIC_DEVICES)


def _default_iface():
    """The primary uplink interface (the one holding the default route), so we
    can report total bandwidth across ALL ports, not just the exit tunnels.
    Override with MAESTRO_UPLINK_DEVICE. Returns a device name or None."""
    override = os.environ.get("MAESTRO_UPLINK_DEVICE")
    if override:
        return override.strip()
    try:
        with open("/proc/net/route") as f:
            next(f)  # header
            for line in f:
                p = line.split()
                if len(p) >= 4 and p[1] == "00000000":  # default route
                    return p[0]
    except Exception:
        pass
    return None


UPLINK_DEVICE = _default_iface()
if UPLINK_DEVICE and UPLINK_DEVICE not in TRAFFIC_DEVICES:
    TRAFFIC_DEVICES = TRAFFIC_DEVICES + [UPLINK_DEVICE]
SAMPLE_INTERVAL = float(os.environ.get("MAESTRO_SAMPLE_INTERVAL", "2.0"))

# Where nym-node stores per-node data (keys + sqlite). Agent runs as root, so
# ~ is /root. Backups are staged here before the orchestrator pulls them.
NYM_NODES_DIR = os.environ.get("MAESTRO_NYM_NODES_DIR", os.path.expanduser("~/.nym/nym-nodes"))
BACKUP_DIR = os.environ.get("MAESTRO_BACKUP_DIR", os.path.join(CERTDIR, "backups"))


def _run(cmd, timeout=6, merge=False):
    try:
        if merge:
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, timeout=timeout)
            return p.returncode, p.stdout, ""
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception:
        return 1, "", ""


def _get_json(url, timeout=2):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def wireguard_enabled(gw):
    """True if the gateway reports an active WireGuard interface.

    nym-node 1.34.0 nests it at client_interfaces.wireguard (an object when on,
    null when off). Older builds had it at the top level. Handle both.
    """
    if not isinstance(gw, dict):
        return False
    wg = (gw.get("client_interfaces") or {}).get("wireguard")
    if wg is None:
        wg = gw.get("wireguard")  # older API shape
    return isinstance(wg, dict) and bool(wg)


def read_nym():
    """Read roles/version/wireguard from the node's local nym-node HTTP API."""
    base = f"http://127.0.0.1:{NYM_PORT}/api/v1"
    out = {"version": None, "mode": None, "mixnode": None,
           "entry": None, "exit": None, "wireguard": None}
    try:
        out["version"] = _get_json(base + "/build-information").get("build_version")
    except Exception:
        pass
    try:
        roles = _get_json(base + "/roles")
        mix = bool(roles.get("mixnode_enabled"))
        gw = bool(roles.get("gateway_enabled"))
        is_exit = bool(roles.get("ip_packet_router_enabled") or roles.get("network_requester_enabled"))
        out["mixnode"] = mix
        out["exit"] = gw and is_exit
        out["entry"] = gw and not is_exit
        if mix:
            out["mode"] = "mixnode"
        elif out["exit"]:
            out["mode"] = "exit-gateway"
        elif out["entry"]:
            out["mode"] = "entry-gateway"
    except Exception:
        pass
    try:
        out["wireguard"] = wireguard_enabled(_get_json(base + "/gateway"))
    except Exception:
        pass
    return out


def unit_exists(unit):
    rc, _, _ = _run(["systemctl", "cat", unit])
    return rc == 0


def find_nym_unit():
    rc, out, _ = _run(["systemctl", "list-unit-files", "--no-legend", "nym-node*"])
    if rc == 0:
        for line in out.splitlines():
            parts = line.split()
            if parts:
                return parts[0]
    return None


def resolve_service():
    if unit_exists(NYM_SERVICE):
        return NYM_SERVICE
    return find_nym_unit() or NYM_SERVICE


def service_state():
    svc = resolve_service()
    rc, out, _ = _run(["systemctl", "is-active", svc])
    return (out.strip() == "active"), svc


def _show_props(svc, *props):
    """Query systemd unit properties; returns {prop: value} (empty on failure)."""
    cmd = ["systemctl", "show", svc]
    for p in props:
        cmd += ["-p", p]
    rc, out, _ = _run(cmd, timeout=10)
    if rc != 0:
        return {}
    d = {}
    for line in out.splitlines():
        k, sep, v = line.partition("=")
        if sep:
            d[k] = v.strip()
    return d


# systemd keeps a unit in ActiveState=deactivating for the whole teardown
# chain (stop-sigterm → stop-sigkill → stop-post → final-sigterm →
# final-sigkill, each bounded by TimeoutStopSec=90s by default). An exit
# gateway's nym-node can sit in that chain for minutes: with ~15k WireGuard
# peers on the kernel nymwg interface the process blocks uninterruptibly in
# the kernel while the interface is torn down, so even SIGKILL is only
# honoured once the kernel returns ("Processes still around after SIGKILL.
# Ignoring."). Seen on AT01: 4 min 08 s from "Stopping" to "Started", with the
# restart completing fine afterwards. As long as the unit is still
# deactivating, systemd has not given up, so neither do we — up to a hard
# cap that covers the full chain.
RESTART_SOFT_WAIT = 150   # normal budget: covers a slow-but-sane stop + start
RESTART_HARD_WAIT = 420   # only used while ActiveState stays "deactivating"


def _unit_state(svc):
    p = _show_props(svc, "ActiveState", "SubState", "MainPID")
    return p.get("ActiveState", ""), p.get("SubState", ""), p.get("MainPID", "0")


def _restart_service(svc, wait=RESTART_SOFT_WAIT, max_wait=RESTART_HARD_WAIT):
    """Queue a restart with --no-block, then poll until the new instance is up.

    nym-node can take well over a minute to stop: its sqlite pool guard waits
    on OS file handles, then the task manager force-shutdown kicks in, and
    systemd's TimeoutStopSec (default 90s) is the last resort before SIGKILL.
    A blocking `systemctl restart` under a short subprocess timeout kills only
    the systemctl *client* mid-job — systemd finishes the restart anyway and
    the action misreports failure. Queueing and polling ActiveState/MainPID
    gives the truthful outcome instead. Success requires an active state with
    a MainPID different from the pre-restart one, so the still-running old
    instance can't count as "restarted".

    `wait` is the soft budget. Past it we keep polling only while the unit is
    still *deactivating* (see RESTART_HARD_WAIT above), because the restart
    job is then demonstrably still in flight and will complete on its own.
    A unit that merely never leaves "active"/"activating" still times out at
    `wait`, so a genuinely stuck instance is reported promptly.

    Returns (restarted, active, error, elapsed_s).
    """
    old_pid = _show_props(svc, "MainPID").get("MainPID", "0")
    # a unit that exhausted its StartLimitBurst (e.g. nym-node crash-looping
    # while the nym-api was down) refuses plain restart until reset — clearing
    # first is a no-op for healthy units
    _run(["systemctl", "reset-failed", svc], timeout=10)
    rc, out, err = _run(["systemctl", "restart", "--no-block", svc], timeout=15)
    if rc != 0:
        return False, service_state()[0], (err or out or "systemctl restart failed").strip(), 0
    start = time.monotonic()
    seen_transition = old_pid in ("", "0")  # no old instance: any active pid is the new one
    failed_reads = 0
    state = sub = ""
    elapsed = 0
    while True:
        state, sub, pid = _unit_state(svc)
        elapsed = int(time.monotonic() - start)
        if state != "active" or pid != old_pid:
            seen_transition = True
        if seen_transition and state == "active" and pid not in ("", "0"):
            return True, True, None, elapsed
        # a Restart= unit can show "failed" for a moment before auto-restart
        # is scheduled — only give up if it stays failed across two reads
        failed_reads = failed_reads + 1 if state == "failed" else 0
        if failed_reads >= 2:
            return False, False, f"{svc} entered failed state after restart", elapsed
        if elapsed >= wait and (state != "deactivating" or elapsed >= max_wait):
            break
        time.sleep(2)
    active, _ = service_state()
    where = f"{state}/{sub}" if sub else (state or "unknown")
    if state == "deactivating":
        msg = (f"{svc} still shutting down after {elapsed}s (systemd phase {sub or 'deactivating'}); "
               f"the queued restart will complete once the old instance exits — re-check the node")
    else:
        msg = f"timed out after {elapsed}s waiting for {svc} to come back active (last state: {where})"
    return False, active, msg, elapsed


def _stop_service(svc, wait=RESTART_SOFT_WAIT, max_wait=RESTART_HARD_WAIT):
    """Queue a stop with --no-block, then poll until the unit is down.

    Same rationale as _restart_service: a slow nym-node stop outlives short
    subprocess timeouts, and past `wait` we keep polling only while systemd is
    still visibly tearing the unit down. Returns (stopped, error, elapsed_s).
    """
    rc, out, err = _run(["systemctl", "stop", "--no-block", svc], timeout=15)
    if rc != 0:
        return False, (err or out or "systemctl stop failed").strip(), 0
    start = time.monotonic()
    state = sub = ""
    elapsed = 0
    while True:
        state, sub, _pid = _unit_state(svc)
        elapsed = int(time.monotonic() - start)
        if state in ("inactive", "failed"):
            return True, None, elapsed
        if elapsed >= wait and (state != "deactivating" or elapsed >= max_wait):
            break
        time.sleep(2)
    where = f"{state}/{sub}" if sub else (state or "unknown")
    return False, f"timed out after {elapsed}s waiting for {svc} to stop (last state: {where})", elapsed


def fail2ban_banned():
    rc, out, _ = _run(["fail2ban-client", "status", "sshd"])
    if rc != 0:
        return None
    m = re.search(r"Currently banned:\s*(\d+)", out)
    return int(m.group(1)) if m else None


def parse_proc_net_dev(text, devices):
    """Return {device: cumulative rx+tx bytes} from /proc/net/dev for the given
    interfaces. Always returns a dict (possibly empty)."""
    want = set(devices)
    out = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        name, rest = line.split(":", 1)
        name = name.strip()
        if name not in want:
            continue
        f = rest.split()
        if len(f) < 9:
            continue
        try:
            out[name] = int(f[0]) + int(f[8])  # rx_bytes + tx_bytes
        except ValueError:
            continue
    return out


def parse_proc_net_dev_dir(text, devices):
    """Like parse_proc_net_dev but keeps direction: {device: {"rx": rx_bytes,
    "tx": tx_bytes}}. rx = received by the kernel on the interface, tx = sent.
    For the exit tunnels this is: rx = user upload / to-internet, tx = download /
    from-internet toward the user (see the WireGuard/Mixnet cards)."""
    want = set(devices)
    out = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        name, rest = line.split(":", 1)
        name = name.strip()
        if name not in want:
            continue
        f = rest.split()
        if len(f) < 9:
            continue
        try:
            out[name] = {"rx": int(f[0]), "tx": int(f[8])}
        except ValueError:
            continue
    return out


def compute_rates_dir(prev, cur, dt):
    """Per-device {rx,tx} bytes/sec from two directional snapshots; skips resets."""
    out = {}
    if dt > 0:
        for dev, c in cur.items():
            p = prev.get(dev)
            if not p:
                continue
            r = {}
            for k in ("rx", "tx"):
                if p.get(k) is not None and c.get(k) is not None and c[k] >= p[k]:
                    r[k] = (c[k] - p[k]) / dt
            if r:
                out[dev] = r
    return out


def parse_traffic(text, devices):
    """Summed rx+tx bytes across the given interfaces, or None."""
    by_dev = parse_proc_net_dev(text, devices)
    return sum(by_dev.values()) if by_dev else None


def compute_rates(prev, cur, dt):
    """Per-device bytes/sec from two counter snapshots; skips counter resets."""
    out = {}
    if dt > 0:
        for dev, c in cur.items():
            p = prev.get(dev)
            if p is not None and c >= p:
                out[dev] = (c - p) / dt
    return out


def _read_proc_net_dev():
    with open("/proc/net/dev", "r") as f:
        return f.read()


def read_traffic():
    """Cumulative rx+tx per interface (total since boot/restart)."""
    try:
        d = parse_proc_net_dev(_read_proc_net_dev(), TRAFFIC_DEVICES)
        return d or None
    except Exception:
        return None


def read_traffic_dir():
    """Cumulative {rx,tx} per EXIT tunnel (nymtun0/nymwg) — direction-split totals
    for the WireGuard and Mixnet-exit cards. Excludes the uplink (summing eth0's
    rx+tx would double-count the encapsulated payload)."""
    try:
        d = parse_proc_net_dev_dir(_read_proc_net_dev(), EXIT_DEVICES)
        return d or None
    except Exception:
        return None


_THROUGHPUT = {}
_THROUGHPUT_DIR = {}
_TPUT_LOCK = threading.Lock()

# ---- on-agent throughput history (rolling 30-day window, 1-minute buckets) ----
# The agent is the source of truth for its own time-series. The orchestrator pulls
# whatever it is missing via GET /v1/history, so history survives orchestrator
# downtime, restarts, or being moved to another host. Storage is stdlib sqlite3.
HISTORY_DIR = os.environ.get("MAESTRO_AGENT_HISTORY_DIR", "/var/lib/nym-maestro-agent")
HISTORY_DB = os.path.join(HISTORY_DIR, "history.db")
HISTORY_RETENTION_S = int(os.environ.get("MAESTRO_HISTORY_RETENTION_S", str(30 * 24 * 3600)))
HISTORY_BUCKET_S = int(os.environ.get("MAESTRO_HISTORY_BUCKET_S", "60"))  # 1-minute buckets
HISTORY_MAX_ROWS = int(os.environ.get("MAESTRO_HISTORY_MAX_ROWS", "10000"))  # response cap
_HISTORY_LOCK = threading.Lock()
_history_db = None  # module-level connection, opened once in start_sampler()

# in-progress bucket accumulation (bucket_ts -> {"tput": {dev: [sum, n]},
#                                                "traffic": {dev: last_bytes}})
_HIST_ACC = {}


def _history_connect():
    """Open (once) the agent's history DB in WAL mode so the sampler thread can
    write while the request handler reads. Returns the connection or None if the
    directory can't be created (history is best-effort, never fatal)."""
    global _history_db
    if _history_db is not None:
        return _history_db
    try:
        os.makedirs(HISTORY_DIR, exist_ok=True)
    except Exception:
        return None
    try:
        conn = sqlite3.connect(HISTORY_DB, check_same_thread=False, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS tput_history ("
            " ts INTEGER PRIMARY KEY, json TEXT NOT NULL)"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS traffic_history ("
            " ts INTEGER PRIMARY KEY, json TEXT NOT NULL)"
        )
        conn.commit()
        _history_db = conn
        return conn
    except Exception:
        return None


def _history_flush_bucket(bucket_ts):
    """Persist one completed bucket to the history DB. Throughput is stored as the
    per-device average bytes/sec over the bucket; traffic is stored as the last
    cumulative counter snapshot seen in the bucket (so deltas across buckets remain
    correct). Best-effort: any failure is swallowed so history never breaks polls."""
    acc = _HIST_ACC.pop(bucket_ts, None)
    if not acc:
        return
    conn = _history_connect()
    if conn is None:
        return
    try:
        tput = acc.get("tput") or {}
        avg = {dev: (s / n) for dev, (s, n) in tput.items() if n > 0}
        traffic = acc.get("traffic") or {}
        with _HISTORY_LOCK:
            if avg:
                conn.execute(
                    "INSERT OR REPLACE INTO tput_history (ts, json) VALUES (?, ?)",
                    (int(bucket_ts), json.dumps(avg)),
                )
            if traffic:
                conn.execute(
                    "INSERT OR REPLACE INTO traffic_history (ts, json) VALUES (?, ?)",
                    (int(bucket_ts), json.dumps(traffic)),
                )
            conn.commit()
    except Exception:
        pass


def _history_prune():
    """Drop rows older than the retention window. Called opportunistically from the
    sampler; cheap because ts is the primary key (indexed)."""
    conn = _history_connect()
    if conn is None:
        return
    cutoff = int(time.time() - HISTORY_RETENTION_S)
    try:
        with _HISTORY_LOCK:
            conn.execute("DELETE FROM tput_history WHERE ts < ?", (cutoff,))
            conn.execute("DELETE FROM traffic_history WHERE ts < ?", (cutoff,))
            conn.commit()
    except Exception:
        pass


def _history_accumulate(rates, traffic, now):
    """Fold one live sample into the current 1-minute bucket. When the wall clock
    crosses into a new bucket, the previous bucket(s) are flushed to disk."""
    bucket = int(now // HISTORY_BUCKET_S) * HISTORY_BUCKET_S
    # flush any older buckets that are now complete
    for old_ts in [b for b in _HIST_ACC if b < bucket]:
        _history_flush_bucket(old_ts)
    slot = _HIST_ACC.setdefault(bucket, {"tput": {}, "traffic": {}})
    if rates:
        for dev, v in rates.items():
            a = slot["tput"].setdefault(dev, [0.0, 0])
            a[0] += v
            a[1] += 1
    if traffic:
        # keep the latest cumulative snapshot in the bucket
        for dev, v in traffic.items():
            slot["traffic"][dev] = v


def history_query(since, until, kind):
    """Return up to HISTORY_MAX_ROWS rows in (since, until], oldest first, for the
    orchestrator to backfill. kind is 'tput' or 'traffic'. Each row is
    {"ts": epoch, "v": {device: value}}. The response is capped; if truncated the
    caller re-requests with since = last returned ts (cursor pagination)."""
    table = "tput_history" if kind == "tput" else "traffic_history"
    conn = _history_connect()
    if conn is None:
        return {"rows": [], "truncated": False}
    try:
        with _HISTORY_LOCK:
            cur = conn.execute(
                f"SELECT ts, json FROM {table} WHERE ts > ? AND ts <= ?"
                f" ORDER BY ts LIMIT ?",
                (int(since), int(until), HISTORY_MAX_ROWS + 1),
            )
            fetched = cur.fetchall()
    except Exception:
        return {"rows": [], "truncated": False}
    truncated = len(fetched) > HISTORY_MAX_ROWS
    fetched = fetched[:HISTORY_MAX_ROWS]
    rows = []
    for ts, js in fetched:
        try:
            rows.append({"ts": int(ts), "v": json.loads(js)})
        except Exception:
            continue
    return {"rows": rows, "truncated": truncated}


def read_throughput():
    with _TPUT_LOCK:
        return dict(_THROUGHPUT) or None


def read_throughput_dir():
    with _TPUT_LOCK:
        return {k: dict(v) for k, v in _THROUGHPUT_DIR.items()} or None


def _sampler_loop():
    """Background thread: diff /proc/net/dev every SAMPLE_INTERVAL for a live rate,
    both summed (_THROUGHPUT) and direction-split for the exit tunnels
    (_THROUGHPUT_DIR)."""
    global _THROUGHPUT, _THROUGHPUT_DIR
    try:
        text = _read_proc_net_dev()
        prev = parse_proc_net_dev(text, TRAFFIC_DEVICES)
        prev_d = parse_proc_net_dev_dir(text, EXIT_DEVICES)
    except Exception:
        prev, prev_d = {}, {}
    prev_t = time.monotonic()
    _history_connect()
    last_prune = 0.0
    while True:
        time.sleep(SAMPLE_INTERVAL)
        try:
            text = _read_proc_net_dev()
            cur = parse_proc_net_dev(text, TRAFFIC_DEVICES)
            cur_d = parse_proc_net_dev_dir(text, EXIT_DEVICES)
            t = time.monotonic()
            dt = t - prev_t
            rates = compute_rates(prev, cur, dt)
            rates_d = compute_rates_dir(prev_d, cur_d, dt)
            with _TPUT_LOCK:
                _THROUGHPUT = rates
                _THROUGHPUT_DIR = rates_d
            prev, prev_d, prev_t = cur, cur_d, t
            # fold this sample into the rolling on-agent history. `cur` is the raw
            # cumulative counter snapshot per device (summed rx+tx bytes).
            now_wall = time.time()
            _history_accumulate(rates, cur, now_wall)
            # prune the retention window at most once an hour
            if now_wall - last_prune > 3600:
                _history_prune()
                last_prune = now_wall
        except Exception:
            pass


def start_sampler():
    threading.Thread(target=_sampler_loop, name="throughput-sampler", daemon=True).start()


def _proc_btime():
    """Wall-clock epoch of the last boot, from /proc/stat (or None)."""
    try:
        with open("/proc/stat") as f:
            for line in f:
                if line.startswith("btime "):
                    return int(line.split()[1])
    except Exception:
        pass
    return None


def nym_node_since(svc):
    """Epoch seconds when the nym-node service last became active, or None.
    Uses systemd's monotonic active-enter timestamp + boot time, which is
    locale- and timezone-independent (no string-date parsing)."""
    try:
        rc, out, _ = _run(["systemctl", "show", svc,
                           "-p", "ActiveEnterTimestampMonotonic", "--value"])
        mono_us = int((out or "0").strip() or "0")
    except Exception:
        return None
    if mono_us <= 0:
        return None
    btime = _proc_btime()
    if not btime:
        return None
    return round(btime + mono_us / 1_000_000)


def read_disk():
    """Usage of the filesystem holding the root partition (the main disk). Uses
    os.statvfs on "/", so it works regardless of the underlying device name, which
    differs per VPS. Returns {total, used, free, percent_used} in bytes, or None if
    it can't be read. This is what surfaces the "disk nearly full" risk in the UI."""
    try:
        st = os.statvfs("/")
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize           # available to non-root
        # "used" as seen by df: total minus free-to-root, but for the bar we want
        # the space that is unavailable to us, so base percent on bavail vs blocks.
        used = total - (st.f_bfree * st.f_frsize)
        pct = (used / total * 100.0) if total > 0 else 0.0
        return {
            "total": total,
            "used": used,
            "free": free,
            "percent_used": round(pct, 1),
        }
    except Exception:
        return None


def build_status():
    active, svc = service_state()
    traffic = read_traffic()
    return {
        "agent_version": AGENT_VERSION,
        "agent_sha": AGENT_SHA,
        "service_name": svc,
        "service_active": active,
        "fail2ban_banned": fail2ban_banned(),
        "traffic": traffic,
        "traffic_bytes": (sum(traffic.get(d, 0) for d in EXIT_DEVICES) if traffic else None),
        "throughput": read_throughput(),
        "nym": read_nym(),
        "extra_blocks": _extra_blocks_state(),
        "concurrency": _nc_state(),
        "nym_node_since": nym_node_since(svc),
        "uplink_device": UPLINK_DEVICE,
        "boot_since": _proc_btime(),
        "traffic_dir": read_traffic_dir(),
        "throughput_dir": read_throughput_dir(),
        "disk": read_disk(),
        "os": read_os(),
    }


def read_os():
    """Current distro from /etc/os-release for the fleet table (cheap: one
    small file read per poll). None if unreadable."""
    try:
        osr = parse_os_release(_read_text("/etc/os-release") or "")
    except Exception:
        return None
    if not osr:
        return None
    return {"id": (osr.get("ID") or "").lower() or None,
            "version_id": osr.get("VERSION_ID"),
            "codename": (osr.get("VERSION_CODENAME") or "").lower() or None,
            "pretty": osr.get("PRETTY_NAME")}


# --- ExecStart flag editing (pure; unit-tested) ----------------------------

def parse_flags(cmd):
    """Parse an ExecStart command into [{flag, value}] for display."""
    try:
        toks = shlex.split(cmd)
    except ValueError:
        toks = cmd.split()
    flags, i = [], 0
    while i < len(toks):
        t = toks[i]
        if t.startswith("--"):
            if "=" in t:
                f, v = t.split("=", 1)
                flags.append({"flag": f, "value": v})
                i += 1
            elif i + 1 < len(toks) and not toks[i + 1].startswith("--"):
                flags.append({"flag": t, "value": toks[i + 1]})
                i += 2
            else:
                flags.append({"flag": t, "value": None})
                i += 1
        else:
            i += 1
    return flags


def set_flag(cmd, flag, value):
    pat = re.compile(re.escape(flag) + r"(?:=|\s+)(?!--)\S+")
    repl = f"{flag} {value}"
    if pat.search(cmd):
        return pat.sub(repl, cmd, count=1)
    return cmd.rstrip() + " " + repl


def set_present(cmd, flag):
    if re.search(r"(?<!\S)" + re.escape(flag) + r"(?!\S)", cmd):
        return cmd
    return cmd.rstrip() + " " + flag


def unset_flag(cmd, flag):
    pat_val = re.compile(r"\s*" + re.escape(flag) + r"(?:=|\s+)(?!--)\S+")
    if pat_val.search(cmd):
        return pat_val.sub("", cmd, count=1).strip()
    pat_bool = re.compile(r"\s*" + re.escape(flag) + r"(?=\s|$)")
    return pat_bool.sub("", cmd, count=1).strip()


def apply_flag_edits(cmd, sets, unsets, presents=None):
    out = cmd
    for flag, value in (sets or {}).items():
        out = set_flag(out, flag, str(value))
    for flag in (presents or []):
        out = set_present(out, flag)
    for flag in (unsets or []):
        out = unset_flag(out, flag)
    return re.sub(r"\s+", " ", out).strip()


# --- exec actions ----------------------------------------------------------

def _fragment_path(svc):
    rc, out, _ = _run(["systemctl", "show", "-p", "FragmentPath", "--value", svc])
    return out.strip() if rc == 0 else ""


def _read_execstart(svc):
    path = _fragment_path(svc)
    if not path or not os.path.isfile(path):
        return path, None, None
    text = open(path, "r").read()
    exec_value = None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("ExecStart=") and s[len("ExecStart="):].strip():
            exec_value = s[len("ExecStart="):]
    return path, text, exec_value


def act_service_file(params):
    svc = resolve_service()
    rc, out, _ = _run(["systemctl", "cat", svc])
    if rc != 0:
        return {"ok": False, "service": svc,
                "error": "could not read unit (systemctl unavailable or unit not found)"}
    return {"ok": True, "service": svc, "fragment_path": _fragment_path(svc), "content": out}


def act_get_execstart(params):
    svc = resolve_service()
    path, text, cmd = _read_execstart(svc)
    if cmd is None:
        return {"ok": False, "service": svc, "error": "no ExecStart found in unit"}
    return {"ok": True, "service": svc, "fragment_path": path,
            "execstart": cmd.strip(), "flags": parse_flags(cmd)}


def act_restart(params):
    svc = resolve_service()
    restarted, active, err, elapsed = _restart_service(svc)
    if not restarted:
        return {"ok": False, "service": svc, "active": active, "error": err}
    return {"ok": True, "service": svc, "active": active,
            "output": f"restarted {svc} ({elapsed}s)"}


def act_toggle(params):
    svc = resolve_service()
    path, text, cmd = _read_execstart(svc)
    if cmd is None:
        return {"ok": False, "service": svc, "error": "no ExecStart found in unit"}

    new_cmd = apply_flag_edits(cmd, params.get("set"), params.get("unset"), params.get("present"))
    if new_cmd == cmd.strip():
        return {"ok": True, "service": svc, "changed": False,
                "old_execstart": cmd.strip(), "new_execstart": new_cmd,
                "output": "no change"}

    backup = f"{path}.maestro.bak.{time.strftime('%Y%m%d_%H%M%S')}"
    try:
        with open(backup, "w") as f:
            f.write(text)
        new_lines, replaced = [], False
        for line in text.splitlines():
            s = line.strip()
            if (not replaced and s.startswith("ExecStart=")
                    and s[len("ExecStart="):].strip() == cmd.strip()):
                indent = line[:len(line) - len(line.lstrip())]
                new_lines.append(f"{indent}ExecStart={new_cmd}")
                replaced = True
            else:
                new_lines.append(line)
        with open(path, "w") as f:
            f.write("\n".join(new_lines) + ("\n" if text.endswith("\n") else ""))
    except Exception as e:
        return {"ok": False, "service": svc, "error": f"failed to write unit: {e}"}

    _run(["systemctl", "daemon-reload"])
    restarted, active = False, None
    if params.get("restart"):
        restarted, active, _rerr, _elapsed = _restart_service(svc)
    return {"ok": True, "service": svc, "changed": True, "fragment_path": path,
            "old_execstart": cmd.strip(), "new_execstart": new_cmd,
            "backup": backup, "restarted": restarted, "active": active}


def _schedule_self_restart():
    rc, _, _ = _run(["systemd-run", "--on-active=2", "systemctl", "restart", "nym-maestro-agent"])
    if rc == 0:
        return True
    try:
        subprocess.Popen(["/bin/sh", "-c", "sleep 2; systemctl restart nym-maestro-agent"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
        return True
    except Exception:
        return False


def act_update_agent(params):
    """Replace this agent's own code with content pushed over the mTLS channel.

    Syntax-checked before it can land; current version backed up; atomic replace.
    Only ever writes the agent's own file — not an arbitrary file-write primitive.
    """
    content = params.get("content")
    if not isinstance(content, str) or not content.strip():
        return {"ok": False, "error": "no content provided"}
    actual = hashlib.sha256(content.encode()).hexdigest()
    want = params.get("sha256")
    if want and want != actual:
        return {"ok": False, "error": "sha256 mismatch (transfer corrupted)"}
    try:
        compile(content, "agent.py", "exec")
    except SyntaxError as e:
        return {"ok": False, "error": f"refused: pushed agent has a syntax error: {e}"}

    target = os.path.abspath(__file__)
    backup = f"{target}.bak.{time.strftime('%Y%m%d_%H%M%S')}"
    try:
        with open(target, "r") as f:
            current = f.read()
        with open(backup, "w") as f:
            f.write(current)
        d = os.path.dirname(target)
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".agent-", suffix=".py")
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, target)
    except Exception as e:
        return {"ok": False, "error": f"failed to write agent: {e}"}

    new_version = AGENT_VERSION
    m = re.search(r'AGENT_VERSION\s*=\s*"([^"]+)"', content)
    if m:
        new_version = m.group(1)

    restart_scheduled = _schedule_self_restart() if params.get("restart") else False
    return {"ok": True, "old_version": AGENT_VERSION, "new_version": new_version,
            "sha256": actual, "backup": backup, "restart_scheduled": restart_scheduled}


def _download(url, dest, timeout=300):
    req = urllib.request.Request(url, headers={"User-Agent": "nym-maestro-agent"})
    with urllib.request.urlopen(req, timeout=timeout) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f)


def _binary_from_execstart(cmd):
    try:
        toks = shlex.split(cmd)
    except ValueError:
        toks = cmd.split()
    if not toks:
        return None
    return toks[0].lstrip("-@+!")


def act_upgrade(params):
    """Swap the nym-node binary the unit runs, optionally re-pull/run NTM and restart.

    With no release url the binary swap is skipped entirely: an NTM-only call
    (params.ntm.url set) just re-pulls and re-runs the script, plus the
    optional restart. The binary location is read from the unit's ExecStart,
    not assumed. The new binary is verified with --version before it replaces
    the old one, which is backed up first. NTM runs the pulled script with the
    given args (not a shell).
    """
    url = (params.get("url") or "").strip()
    ntm = params.get("ntm") if isinstance(params.get("ntm"), dict) else {}
    ntm_url = (ntm.get("url") or "").strip()
    if not url and not ntm_url:
        return {"ok": False,
                "error": "no download url provided (need a nym-node release url, an NTM script url, or both)"}

    svc = resolve_service()
    binary, new_version, backup = None, None, None
    log = []
    if url:
        if not url.lower().startswith("https://"):
            return {"ok": False, "error": "download url must be https:// (refusing an unverified transport)"}
        _, _, cmd = _read_execstart(svc)
        if cmd is None:
            return {"ok": False, "error": "could not read ExecStart to locate the binary"}
        binary = _binary_from_execstart(cmd)
        if not binary or not os.path.isabs(binary):
            return {"ok": False, "error": f"could not determine binary path from ExecStart (got {binary!r})"}

        bindir = os.path.dirname(binary)
        log.append(f"target binary (from ExecStart): {binary}")

        tmp = os.path.join(bindir, ".nym-node.new")
        try:
            log.append(f"downloading {url}")
            _download(url, tmp, timeout=300)
        except Exception as e:
            return {"ok": False, "error": f"download failed: {e}", "output": "\n".join(log)}

        # Mandatory integrity check: this binary runs as root, so we refuse to
        # install anything we cannot verify against an operator-supplied hash. A
        # hijacked download host or a wrong URL is otherwise arbitrary root code
        # execution.
        want_sha = (params.get("sha256") or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", want_sha):
            try:
                os.remove(tmp)
            except Exception:
                pass
            return {"ok": False, "error": "a sha256 (64 hex chars) of the release binary is required",
                    "output": "\n".join(log)}
        try:
            h = hashlib.sha256()
            with open(tmp, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
            got_sha = h.hexdigest()
        except Exception as e:
            try:
                os.remove(tmp)
            except Exception:
                pass
            return {"ok": False, "error": f"could not hash downloaded binary: {e}",
                    "output": "\n".join(log)}
        if got_sha != want_sha:
            try:
                os.remove(tmp)
            except Exception:
                pass
            return {"ok": False,
                    "error": f"sha256 mismatch: expected {want_sha}, got {got_sha}; "
                             f"discarded download, old binary untouched",
                    "output": "\n".join(log)}
        log.append(f"sha256 verified: {got_sha}")

        try:
            os.chmod(tmp, 0o755)
        except Exception:
            pass

        rc, out, err = _run([tmp, "--version"], timeout=30)
        if rc != 0:
            try:
                os.remove(tmp)
            except Exception:
                pass
            return {"ok": False, "error": "downloaded binary failed --version; left old binary in place",
                    "output": "\n".join(log + [out, err]).strip()}
        m = re.search(r"\d+\.\d+\.\d+", (out or "") + (err or ""))
        new_version = m.group(0) if m else "unknown"
        log.append(f"new binary reports version {new_version}")

        if os.path.isfile(binary):
            olddir = os.path.join(bindir, "old")
            try:
                os.makedirs(olddir, exist_ok=True)
                backup = os.path.join(olddir, f"nym-node.backup.{time.strftime('%Y%m%d_%H%M%S')}")
                shutil.copy2(binary, backup)
                log.append(f"backed up current binary -> {backup}")
            except Exception as e:
                return {"ok": False, "error": f"backup failed: {e}", "output": "\n".join(log)}
        try:
            os.replace(tmp, binary)
            os.chmod(binary, 0o755)
            log.append(f"installed new binary at {binary}")
        except Exception as e:
            return {"ok": False, "error": f"install failed: {e}", "output": "\n".join(log)}
    else:
        log.append("NTM-only run: no release url given, binary swap skipped")

    ntm_result = None
    if ntm_url:
        # The NTM script is always written inside CERTDIR (basename only), so a
        # caller can never turn this into an arbitrary root file write (e.g. into
        # /etc/cron.d/*); the url must be https for the same reason as the binary.
        base = os.path.basename(ntm.get("path") or "") or "network_tunnel_manager.sh"
        if base in (".", ".."):
            base = "network_tunnel_manager.sh"
        ntm_path = os.path.join(CERTDIR, base)
        if not ntm_url.lower().startswith("https://"):
            ntm_result = {"ok": False, "path": ntm_path, "error": "NTM url must be https://"}
        else:
            try:
                log.append(f"pulling NTM script {ntm_url} -> {ntm_path}")
                _download(ntm_url, ntm_path, timeout=60)
                os.chmod(ntm_path, 0o755)
            except Exception as e:
                ntm_result = {"ok": False, "path": ntm_path, "error": f"NTM pull failed: {e}"}
            else:
                args = ntm.get("args") or ""
                try:
                    argv = [ntm_path] + (shlex.split(args) if isinstance(args, str) else list(args))
                except ValueError:
                    argv = [ntm_path]
                rc2, out2, _ = _run(argv, timeout=180, merge=True)
                combined = (out2 or "").strip()
                ntm_result = {"ok": rc2 == 0, "exit_code": rc2, "path": ntm_path,
                              "command": " ".join(argv), "output": combined}
                log.append(f"ran NTM ({' '.join(argv)}) -> exit {rc2}")

    restarted, active = False, None
    if params.get("restart"):
        restarted, active, rerr, elapsed = _restart_service(svc)
        if restarted:
            log.append(f"restart ok ({elapsed}s); service active={active}")
        else:
            log.append(f"restart FAILED ({rerr}); service active={active}")

    # A bundled NTM failure after a successful binary swap stays ok=True (the
    # upgrade itself worked; the ntm sub-result carries the failure). On an
    # NTM-only run the script IS the job, so its failure fails the action.
    result = {"ok": True, "service": svc, "binary": binary, "new_version": new_version,
              "backup": backup, "ntm": ntm_result, "restarted": restarted,
              "active": active, "output": "\n".join(log)}
    if not url and not (ntm_result and ntm_result.get("ok")):
        result["ok"] = False
        result["error"] = ((ntm_result or {}).get("error")
                           or f"NTM exited with code {(ntm_result or {}).get('exit_code')}")
    return result


def _nym_id_from_execstart(cmd):
    for f in parse_flags(cmd or ""):
        if f["flag"] == "--id" and f["value"]:
            return f["value"]
    return None


_BACKUP_NAME_RE = re.compile(r"^nym-backup_[A-Za-z0-9._-]+_\d{8}_\d{6}\.tar\.gz$")


def _safe_backup_name(name):
    return bool(name) and os.path.basename(name) == name and bool(_BACKUP_NAME_RE.match(name))


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def make_archive(src_dir, archive_path):
    src_dir = src_dir.rstrip("/")
    parent, base = os.path.dirname(src_dir), os.path.basename(src_dir)
    rc, out, err = _run(["tar", "czf", archive_path, "-C", parent, base], timeout=900)
    if rc != 0:
        raise RuntimeError((err or out or "tar failed").strip())
    return os.path.getsize(archive_path), _sha256_file(archive_path)


def act_backup(params):
    """Stop the service, tar the node's data dir, restart, stage the archive.

    The id is read from the running ExecStart (--id), not assumed. Service is
    restarted immediately after the tar, so downtime is just stop + archive.
    """
    svc = resolve_service()
    _, _, cmd = _read_execstart(svc)
    nid = _nym_id_from_execstart(cmd) if cmd else None
    if not nid:
        try:
            dirs = [d for d in os.listdir(NYM_NODES_DIR)
                    if os.path.isdir(os.path.join(NYM_NODES_DIR, d))]
        except Exception:
            dirs = []
        if len(dirs) == 1:
            nid = dirs[0]
    if not nid:
        return {"ok": False, "error": "could not determine the nym-node id "
                "(no --id in ExecStart, and not a single dir under nym-nodes)"}

    data_dir = os.path.join(NYM_NODES_DIR, nid)
    if not os.path.isdir(data_dir):
        return {"ok": False, "error": f"node data dir not found: {data_dir}"}

    os.makedirs(BACKUP_DIR, exist_ok=True)
    fname = f"nym-backup_{nid}_{time.strftime('%Y%m%d_%H%M%S')}.tar.gz"
    archive_path = os.path.join(BACKUP_DIR, fname)
    log = [f"node id: {nid}", f"data dir: {data_dir}"]

    stopped, stop_err, stop_s = _stop_service(svc)
    if not stopped:
        return {"ok": False, "error": f"failed to stop {svc}; backup aborted",
                "output": "\n".join(log + [f"stop FAILED: {stop_err}"])}
    log.append(f"stopped {svc} ({stop_s}s)")

    archive_err, size, sha = None, None, None
    try:
        size, sha = make_archive(data_dir, archive_path)
        log.append(f"archived -> {fname} ({size} bytes)")
    except Exception as e:
        archive_err = str(e)

    restarted, active, start_err, start_s = _restart_service(svc)
    if restarted:
        log.append(f"restarted {svc}: ok ({start_s}s); active={active}")
    else:
        log.append(f"restarted {svc}: FAILED ({start_err}); active={active}")

    if archive_err:
        return {"ok": False, "error": f"archive failed: {archive_err}",
                "restarted": restarted, "active": active, "output": "\n".join(log)}
    return {"ok": True, "id": nid, "service": svc, "filename": fname, "size": size,
            "sha256": sha, "restarted": restarted, "active": active, "output": "\n".join(log)}


def act_backup_cleanup(params):
    name = params.get("name")
    if not _safe_backup_name(name):
        return {"ok": False, "error": "invalid backup name"}
    p = os.path.join(BACKUP_DIR, name)
    try:
        if os.path.isfile(p):
            os.remove(p)
        return {"ok": True, "deleted": name}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# --- fail2ban: status, setup (install + rules), unban ----------------------

F2B_JAIL = os.environ.get("MAESTRO_F2B_JAIL", "sshd")
F2B_DROPIN = "/etc/fail2ban/jail.d/nym-maestro.local"
F2B_LOG = os.environ.get("MAESTRO_F2B_LOG", "/var/log/fail2ban.log")

_TIME_RE = re.compile(r"^\d+[smhdw]?$")
_IP_RE = re.compile(r"^[0-9A-Fa-f:.]+(?:/\d{1,3})?$")


def _f2b_installed():
    return shutil.which("fail2ban-client") is not None


def _f2b_get(setting):
    rc, out, _ = _run(["fail2ban-client", "get", F2B_JAIL, setting])
    return out.strip().splitlines()[-1].strip() if rc == 0 and out.strip() else None


def _f2b_jail_status():
    rc, out, _ = _run(["fail2ban-client", "status", F2B_JAIL])
    if rc != 0:
        return None
    cur = re.search(r"Currently banned:\s*(\d+)", out)
    tot = re.search(r"Total banned:\s*(\d+)", out)
    ips = re.search(r"Banned IP list:\s*(.*)", out)
    return {
        "currently_banned": int(cur.group(1)) if cur else None,
        "total_banned": int(tot.group(1)) if tot else None,
        "banned_ips": (ips.group(1).split() if ips and ips.group(1).strip() else []),
    }


def _f2b_bans_24h():
    """Count 'Ban' events in the last 24h from the fail2ban log (best-effort)."""
    cutoff = time.time() - 24 * 3600
    n = 0
    for path in (F2B_LOG, F2B_LOG + ".1"):
        try:
            with open(path, "r", errors="replace") as f:
                for line in f:
                    if "] Ban " not in line:
                        continue
                    try:
                        t = time.mktime(time.strptime(line[:19], "%Y-%m-%d %H:%M:%S"))
                    except Exception:
                        continue
                    if t >= cutoff:
                        n += 1
        except FileNotFoundError:
            continue
        except Exception:
            continue
    return n


def act_fail2ban_status(params):
    if not _f2b_installed():
        return {"ok": True, "installed": False}
    rc, out, _ = _run(["systemctl", "is-active", "fail2ban"])
    running = out.strip() == "active"
    js = _f2b_jail_status() or {}
    return {
        "ok": True,
        "installed": True,
        "running": running,
        "jail": F2B_JAIL,
        "currently_banned": js.get("currently_banned"),
        "total_banned": js.get("total_banned"),
        "banned_24h": _f2b_bans_24h() if running else 0,
        "banned_ips": js.get("banned_ips", []),
        "bantime": _f2b_get("bantime"),
        "findtime": _f2b_get("findtime"),
        "maxretry": _f2b_get("maxretry"),
    }


def act_fail2ban_setup(params):
    maxretry = params.get("maxretry", 5)
    findtime = str(params.get("findtime", "10m"))
    bantime = str(params.get("bantime", "1h"))
    increment = bool(params.get("increment", True))
    ignoreip = params.get("ignoreip") or []
    if isinstance(ignoreip, str):
        ignoreip = ignoreip.split()

    # validate everything we are about to write into the config file
    try:
        maxretry = int(maxretry)
    except (TypeError, ValueError):
        return {"ok": False, "error": "maxretry must be an integer"}
    if not (1 <= maxretry <= 100):
        return {"ok": False, "error": "maxretry out of range (1-100)"}
    if not _TIME_RE.match(findtime) or not _TIME_RE.match(bantime):
        return {"ok": False, "error": "findtime/bantime must look like 600, 10m, 1h, 1d"}
    ign = ["127.0.0.1/8", "::1"]
    for ip in ignoreip:
        ip = ip.strip()
        if not ip:
            continue
        if not _IP_RE.match(ip):
            return {"ok": False, "error": f"invalid ignoreip entry: {ip}"}
        if ip not in ign:
            ign.append(ip)

    log = []
    # install if missing (Debian/Ubuntu)
    if not _f2b_installed():
        if not shutil.which("apt-get"):
            return {"ok": False, "error": "fail2ban not installed and apt-get not found; install manually"}
        env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
        rc, out, err = _run(["apt-get", "update"], timeout=120)
        log.append("apt-get update: " + ("ok" if rc == 0 else "FAILED"))
        try:
            p = subprocess.run(["apt-get", "install", "-y", "fail2ban"],
                               capture_output=True, text=True, timeout=300, env=env)
            irc = p.returncode
        except Exception as e:
            return {"ok": False, "error": f"apt-get install error: {e}", "output": "\n".join(log)}
        if irc != 0 or not _f2b_installed():
            tail = (p.stderr or p.stdout or "").strip().splitlines()[-3:]
            return {"ok": False, "error": "fail2ban install failed",
                    "output": "\n".join(log + ["apt-get install: FAILED"] + tail)}
        log.append("installed fail2ban")
    else:
        log.append("fail2ban already installed")

    # write our drop-in (scoped to the sshd jail only)
    conf = (
        "# Managed by nym maestro. Do not edit by hand.\n"
        "[DEFAULT]\n"
        f"bantime = {bantime}\n"
        f"findtime = {findtime}\n"
        f"maxretry = {maxretry}\n"
        f"bantime.increment = {'true' if increment else 'false'}\n"
        "bantime.factor = 2\n"
        "bantime.maxtime = 1w\n"
        f"ignoreip = {' '.join(ign)}\n\n"
        f"[{F2B_JAIL}]\n"
        "enabled = true\n"
    )
    try:
        os.makedirs(os.path.dirname(F2B_DROPIN), exist_ok=True)
        tmp = F2B_DROPIN + ".tmp"
        with open(tmp, "w") as f:
            f.write(conf)
        os.replace(tmp, F2B_DROPIN)
        log.append(f"wrote {F2B_DROPIN}")
    except Exception as e:
        return {"ok": False, "error": f"could not write config: {e}", "output": "\n".join(log)}

    _run(["systemctl", "enable", "fail2ban"], timeout=30)
    rc, out, err = _run(["systemctl", "restart", "fail2ban"], timeout=60)
    log.append("restart fail2ban: " + ("ok" if rc == 0 else "FAILED: " + (err or out).strip()))
    time.sleep(1)
    rc2, act, _ = _run(["systemctl", "is-active", "fail2ban"])
    running = act.strip() == "active"

    # confirm the effective values actually took
    eff = {"bantime": _f2b_get("bantime"), "findtime": _f2b_get("findtime"), "maxretry": _f2b_get("maxretry")}
    return {
        "ok": running, "installed": True, "running": running,
        "applied": {"bantime": bantime, "findtime": findtime, "maxretry": maxretry,
                    "increment": increment, "ignoreip": ign},
        "effective": eff, "output": "\n".join(log),
        "error": None if running else "fail2ban did not come back active after restart",
    }


def act_fail2ban_unban(params):
    ip = (params.get("ip") or "").strip()
    if not _IP_RE.match(ip):
        return {"ok": False, "error": "invalid IP"}
    if not _f2b_installed():
        return {"ok": False, "error": "fail2ban not installed"}
    rc, out, err = _run(["fail2ban-client", "set", F2B_JAIL, "unbanip", ip])
    if rc != 0:
        rc, out, err = _run(["fail2ban-client", "unban", ip])
    ok = rc == 0
    return {"ok": ok, "ip": ip, "error": None if ok else (err or out).strip()}


# --- SSH key auth + password-login hardening -------------------------------
#
# Login model: you log in as an unprivileged admin user (its name comes from
# MAESTRO_SSH_USER in the unit env — never hard-coded here) and sudo to root.
# Direct root SSH login is never enabled. Keys are installed into that
# user's ~/.ssh/authorized_keys (owned by the user), NOT root's. Hardening sets
# PasswordAuthentication no + PermitRootLogin no for the whole daemon.

SSH_USER_DEFAULT = os.environ.get("MAESTRO_SSH_USER", "")
SSH_MAIN = "/etc/ssh/sshd_config"
SSH_DROPIN_DIR = "/etc/ssh/sshd_config.d"
# 00- prefix so sshd (first-match-wins) reads our value BEFORE 50-cloud-init.conf etc.
SSH_DROPIN = SSH_DROPIN_DIR + "/00-nym-maestro.conf"
SSH_DROPIN_LEGACY = SSH_DROPIN_DIR + "/nym-maestro.conf"
SSH_BAK = ".nym-maestro.bak"
# directives whose stray "yes"/wrong values elsewhere would pre-empt our drop-in
SSH_NEUTRALIZE = ("PasswordAuthentication", "KbdInteractiveAuthentication",
                  "ChallengeResponseAuthentication", "PubkeyAuthentication", "PermitRootLogin")
SSH_DROPIN_CONF = ("# Managed by nym maestro. Do not edit by hand.\n"
                   "PasswordAuthentication no\n"
                   "KbdInteractiveAuthentication no\n"
                   "PubkeyAuthentication yes\n"
                   "PermitRootLogin no\n")

_PUBKEY_RE = re.compile(
    r"^(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-\S+|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-\S+@openssh\.com)"
    r"\s+[A-Za-z0-9+/]+={0,3}(?:\s+\S.*)?$"
)


def _ssh_service():
    for u in ("ssh", "sshd"):
        if unit_exists(u):
            return u
    return "ssh"


def _user_paths(user):
    """Resolve (pw_record, ssh_dir, authorized_keys) for a login user. Raises KeyError."""
    pw = pwd.getpwnam(user)
    ssh_dir = os.path.join(pw.pw_dir, ".ssh")
    return pw, ssh_dir, os.path.join(ssh_dir, "authorized_keys")


def _count_authkeys(user):
    try:
        _, _, authk = _user_paths(user)
        with open(authk) as f:
            return sum(1 for l in f if l.strip() and not l.lstrip().startswith("#"))
    except Exception:
        return 0


def act_ssh_add_key(params):
    user = params.get("user") or SSH_USER_DEFAULT
    try:
        pw, ssh_dir, authk = _user_paths(user)
    except KeyError:
        return {"ok": False, "error": f"login user '{user}' does not exist on this node"}

    keys = params.get("public_keys") or []
    if isinstance(keys, str):
        keys = [keys]
    valid = []
    for k in keys:
        k = (k or "").strip()
        if not k:
            continue
        if not _PUBKEY_RE.match(k):
            return {"ok": False, "error": "invalid public key format"}
        valid.append(k)
    if not valid:
        return {"ok": False, "error": "no public keys provided"}

    # ~/.ssh and authorized_keys must be owned by the login user or sshd StrictModes rejects them
    os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
    with contextlib.suppress(Exception):
        os.chown(ssh_dir, pw.pw_uid, pw.pw_gid)
        os.chmod(ssh_dir, 0o700)

    existing, content = set(), ""
    if os.path.exists(authk):
        with open(authk) as f:
            content = f.read()
        for line in content.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                existing.add(parts[1])

    add_lines, added, present = [], 0, 0
    for k in valid:
        body = k.split()[1]
        if body in existing:
            present += 1
        else:
            add_lines.append(k)
            existing.add(body)
            added += 1

    if add_lines:
        prefix = "" if (not content or content.endswith("\n")) else "\n"
        with open(authk, "a") as f:
            f.write(prefix + "\n".join(add_lines) + "\n")
    with contextlib.suppress(Exception):
        os.chown(authk, pw.pw_uid, pw.pw_gid)
        os.chmod(authk, 0o600)
    return {"ok": True, "user": user, "added": added, "already_present": present,
            "authorized_keys": authk, "total_keys": len(existing)}


def _sshd_effective():
    rc, out, _ = _run(["sshd", "-T"])
    if rc != 0:
        return {}

    def g(key):
        m = re.search(r"(?mi)^" + key + r"\s+(\S+)", out)
        return m.group(1) if m else None
    return {
        "password_auth": g("passwordauthentication"),
        "pubkey_auth": g("pubkeyauthentication"),
        "permit_root_login": g("permitrootlogin"),
        "ssh_port": int(g("port")) if g("port") and g("port").isdigit() else 22,
    }


def act_ssh_status(params):
    user = params.get("user") or SSH_USER_DEFAULT
    try:
        _user_paths(user)
        user_exists = True
    except KeyError:
        user_exists = False
    eff = _sshd_effective()
    return {
        "ok": True,
        "user": user,
        "user_exists": user_exists,
        "password_auth": eff.get("password_auth"),
        "pubkey_auth": eff.get("pubkey_auth"),
        "permit_root_login": eff.get("permit_root_login"),
        "ssh_port": eff.get("ssh_port", 22),
        "authorized_keys_count": _count_authkeys(user),
        "dropin_present": os.path.exists(SSH_DROPIN) or os.path.exists(SSH_DROPIN_LEGACY),
    }


def _sshd_main_includes_dropins():
    """True if the main sshd_config actively Includes the sshd_config.d drop-in dir."""
    txt = _read_file(SSH_MAIN) or ""
    for line in txt.splitlines():
        s = line.strip()
        if s and not s.startswith("#") and re.match(r"(?i)include\s+\S*sshd_config\.d/\*\.conf", s):
            return True
    return False


def _read_file(path):
    try:
        with open(path) as f:
            return f.read()
    except Exception:
        return None


def _write_file(path, text):
    with open(path, "w") as f:
        f.write(text)


def _backup_once(path, original):
    """Persist the TRUE original (used later by 'password on' to revert cleanly)."""
    if original is None:
        return
    bak = path + SSH_BAK
    if not os.path.exists(bak):
        with contextlib.suppress(Exception):
            _write_file(bak, original)


def _comment_conflicts(path, keys):
    """Comment out active directive lines for `keys` in `path`. Backs up first.
    Returns True if anything was changed."""
    orig = _read_file(path)
    if orig is None:
        return False
    pat = re.compile(r"(?i)^\s*(" + "|".join(keys) + r")\b")
    out, changed = [], False
    for line in orig.splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped and not stripped.startswith("#") and pat.match(line):
            nl = "" if line.endswith("\n") else "\n"
            out.append("# disabled by nym maestro: " + line + nl)
            changed = True
        else:
            out.append(line)
    if changed:
        _backup_once(path, orig)
        _write_file(path, "".join(out))
    return changed


def _dropins_before(name):
    """drop-in *.conf files that sort lexically before `name` — they would pre-empt ours."""
    res = []
    with contextlib.suppress(Exception):
        for fn in sorted(os.listdir(SSH_DROPIN_DIR)):
            if fn.endswith(".conf") and fn < name and \
               os.path.join(SSH_DROPIN_DIR, fn) not in (SSH_DROPIN, SSH_DROPIN_LEGACY):
                res.append(os.path.join(SSH_DROPIN_DIR, fn))
    return res


def _ensure_sshd_include():
    """Prepend the drop-in Include to the main sshd_config if missing (validated)."""
    if _sshd_main_includes_dropins():
        return False, True
    orig = _read_file(SSH_MAIN)
    if orig is None:
        return False, False
    _backup_once(SSH_MAIN, orig)
    with contextlib.suppress(Exception):
        _write_file(SSH_MAIN, "# Added by nym maestro so drop-ins apply.\n"
                              "Include /etc/ssh/sshd_config.d/*.conf\n\n" + orig)
    if _run(["sshd", "-t"])[0] != 0:                       # old sshd may not support Include
        with contextlib.suppress(Exception):
            _write_file(SSH_MAIN, orig)
        return False, False
    return True, True


def _ssh_rollback(touched):
    """Restore every file we modified in this call to its pre-call content."""
    for path, orig in touched.items():
        with contextlib.suppress(Exception):
            if orig is None:
                if os.path.exists(path):
                    os.remove(path)
            else:
                _write_file(path, orig)


def _eff_fields(eff, user):
    return {"password_auth": eff.get("password_auth"),
            "permit_root_login": eff.get("permit_root_login"),
            "authorized_keys_count": _count_authkeys(user)}


def act_ssh_harden(params):
    user = params.get("user") or SSH_USER_DEFAULT
    mode = params.get("password", "off")   # "off" disables password auth; "on" reverts
    svc = _ssh_service()

    if mode != "off":
        return _ssh_revert(user, svc)

    if _count_authkeys(user) == 0:
        return {"ok": False, "error": f"refusing to disable password auth: '{user}' has no "
                "authorized_keys on this node — that would lock you out. Install the key first."}

    touched = {}   # path -> pre-call content, for rollback inside this call

    def snap(path):
        if path not in touched:
            touched[path] = _read_file(path)

    try:
        # 1. Neutralize any directive that would pre-empt us (sshd uses the FIRST
        #    value it sees): explicit lines in the main config, and any drop-in that
        #    sorts before ours — most often 50-cloud-init.conf shipping
        #    "PasswordAuthentication yes". This is the case the old code missed.
        snap(SSH_MAIN)
        _comment_conflicts(SSH_MAIN, SSH_NEUTRALIZE)
        for p in _dropins_before(os.path.basename(SSH_DROPIN)):
            snap(p)
            _comment_conflicts(p, SSH_NEUTRALIZE)

        method = None

        # 2. Preferred: an authoritative 00- drop-in, with the Include guaranteed.
        with contextlib.suppress(Exception):
            os.makedirs(SSH_DROPIN_DIR, exist_ok=True)
        if os.path.isdir(SSH_DROPIN_DIR):
            snap(SSH_DROPIN)
            _write_file(SSH_DROPIN, SSH_DROPIN_CONF)
            if os.path.exists(SSH_DROPIN_LEGACY):
                snap(SSH_DROPIN_LEGACY)
                with contextlib.suppress(Exception):
                    os.remove(SSH_DROPIN_LEGACY)
            snap(SSH_MAIN)
            _ensure_sshd_include()
            if _sshd_main_includes_dropins() and _run(["sshd", "-t"])[0] == 0:
                method = "drop-in (00-nym-maestro.conf)"

        # 3. Fallback for sshd too old for Include / unusable drop-in dir: append our
        #    directives to the end of the main config. We already commented the earlier
        #    conflicting lines above, so this appended block is the only active copy.
        if method is None:
            with contextlib.suppress(Exception):
                if os.path.exists(SSH_DROPIN):
                    os.remove(SSH_DROPIN)
            main = _read_file(SSH_MAIN)
            if main is None:
                _ssh_rollback(touched)
                return {"ok": False, "error": "cannot read /etc/ssh/sshd_config on this node"}
            if not main.endswith("\n"):
                main += "\n"
            _backup_once(SSH_MAIN, touched.get(SSH_MAIN))
            _write_file(SSH_MAIN, main + "\n" + SSH_DROPIN_CONF)
            method = "main sshd_config (appended)"

        # 4. Validate before reloading the live daemon; never reload a broken config.
        rc, out, err = _run(["sshd", "-t"])
        if rc != 0:
            _ssh_rollback(touched)
            return {"ok": False, "error": "sshd config test failed; reverted: " + (err or out).strip()}

        # 5. Reload and confirm the EFFECTIVE config actually changed.
        _run(["systemctl", "reload", svc])
        eff = _sshd_effective()
        if eff.get("password_auth") != "no":
            _ssh_rollback(touched)
            _run(["systemctl", "reload", svc])
            eff2 = _sshd_effective()
            return {"ok": False, "mode": mode, "method": method, **_eff_fields(eff2, user),
                    "error": "effective config still allowed password auth after applying changes; "
                             "reverted. Inspect `sshd -T | grep -i passwordauthentication` and the "
                             "files under /etc/ssh/sshd_config.d/ for a conflicting directive."}

        return {"ok": True, "user": user, "mode": mode, "method": method,
                "include_added": _sshd_main_includes_dropins(), **_eff_fields(eff, user), "error": None}
    except Exception as e:
        _ssh_rollback(touched)
        return {"ok": False, "error": f"ssh harden failed and was reverted: {e}"}


def _ssh_revert(user, svc):
    """password=on: remove our drop-ins and restore every file we backed up."""
    for p in (SSH_DROPIN, SSH_DROPIN_LEGACY):
        with contextlib.suppress(Exception):
            if os.path.exists(p):
                os.remove(p)
    restored = []
    bak_files = []
    for d in (os.path.dirname(SSH_MAIN), SSH_DROPIN_DIR):
        with contextlib.suppress(Exception):
            for f in os.listdir(d):
                if f.endswith(SSH_BAK):
                    bak_files.append(os.path.join(d, f))
    for bak in bak_files:
        target = bak[:-len(SSH_BAK)]
        data = _read_file(bak)
        if data is not None:
            with contextlib.suppress(Exception):
                _write_file(target, data)
                os.remove(bak)
                restored.append(target)
    rc, out, err = _run(["sshd", "-t"])
    if rc != 0:
        return {"ok": False, "mode": "on", "restored": restored,
                "error": "sshd config test failed after revert; not reloading: " + (err or out).strip()}
    rc2, _, _ = _run(["systemctl", "reload", svc])
    eff = _sshd_effective()
    return {"ok": rc2 == 0, "mode": "on", "restored": restored, **_eff_fields(eff, user),
            "error": None if rc2 == 0 else "config restored but service reload failed"}


def _split_hostport(s):
    s = s.strip()
    if s.startswith("["):
        host, _, port = s[1:].partition("]")
        return host, port.lstrip(":")
    host, _, port = s.rpartition(":")
    return host, port


MAESTRO_PEER_PORTS = os.environ.get("MAESTRO_PEER_PORTS", "1789")
MAESTRO_CLIENT_PORTS = os.environ.get("MAESTRO_CLIENT_PORTS", "9000,9001")

# observed-since timestamps, keyed by "cat|ip" — persists across calls in the
# long-running agent. The kernel doesn't expose TCP connection age, so this is
# "how long the agent has continuously seen this endpoint".
_FIRST_SEEN = {}


def _ss_sample():
    """Parse `ss -tinHO` (oneline, with TCP info) -> {(lip,lport,rip,rport): bytes}."""
    rc, out, err = _run(["ss", "-tinHO", "state", "established"], timeout=8)
    if rc != 0:
        rc, out, err = _run(["ss", "-tnHO", "state", "established"], timeout=8)
        if rc != 0:
            return None
    conns = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        idx = 0 if parts[0].isdigit() else 1   # skip a State column if present
        if len(parts) < idx + 4:
            continue
        lip, lport = _split_hostport(parts[idx + 2])
        rip, rport = _split_hostport(parts[idx + 3])
        if not rip:
            continue
        sent = recv = 0
        m1 = re.search(r"bytes_sent:(\d+)", line)
        m2 = re.search(r"bytes_received:(\d+)", line)
        if m1:
            sent = int(m1.group(1))
        if m2:
            recv = int(m2.group(1))
        conns[(lip, lport, rip, rport)] = (sent, recv)
    return conns


def _wg_sample():
    """Parse `wg show all dump` -> {ip: {'bytes':rx+tx, 'hs':handshake_ts}}."""
    rc, out, err = _run(["wg", "show", "all", "dump"], timeout=6)
    if rc != 0:
        return None
    peers = {}
    for line in out.splitlines():
        f = line.split("\t")
        if len(f) < 9:            # interface lines have 5 fields; peers have 9
            continue
        endpoint, hs, rx, tx = f[3], f[5], f[6], f[7]
        if not endpoint or endpoint == "(none)":
            continue
        ip, port = _split_hostport(endpoint)
        if not ip:
            continue
        try:
            rxb, txb, hsi = int(rx), int(tx), int(hs)
        except ValueError:
            continue
        p = peers.setdefault(ip, {"bytes": 0, "hs": 0, "conns": 0})
        p["bytes"] += rxb + txb
        p["hs"] = max(p["hs"], hsi)
        p["conns"] += 1
    return peers


def act_peers(params):
    """Edges around this node with per-endpoint throughput, traffic and duration.

    Node<->node mixnet (1789): local port == mix -> 'up' (inbound), remote port
    == mix -> 'down' (outbound). Clients: websocket on 9000/9001, WireGuard dVPN
    on 51822 (from `wg show`). Rates are sampled over a ~1s window; traffic is
    cumulative bytes; duration is how long the agent has seen the endpoint.
    """
    raw = params.get("ports")
    if isinstance(raw, str):
        ports = [p.strip() for p in raw.split(",") if p.strip()]
    elif isinstance(raw, (list, tuple)):
        ports = [str(p) for p in raw]
    else:
        ports = [p.strip() for p in MAESTRO_PEER_PORTS.split(",") if p.strip()]
    mixset = set(ports)
    craw = params.get("client_ports")
    if isinstance(craw, str):
        cports = [p.strip() for p in craw.split(",") if p.strip()]
    elif isinstance(craw, (list, tuple)):
        cports = [str(p) for p in craw]
    else:
        cports = [p.strip() for p in MAESTRO_CLIENT_PORTS.split(",") if p.strip()]
    clientset = set(cports)

    t0 = time.time()
    s1 = _ss_sample()
    wg1 = _wg_sample()
    if s1 is None:
        return {"ok": False, "error": "ss failed"}
    time.sleep(1.0)
    s2 = _ss_sample()
    wg2 = _wg_sample()
    dt = max(0.2, time.time() - t0)
    if s2 is None:
        s2 = s1

    now = time.time()
    seen_keys = set()

    def dur(cat, ip):
        k = cat + "|" + ip
        seen_keys.add(k)
        if k not in _FIRST_SEEN:
            _FIRST_SEEN[k] = now
        return int(now - _FIRST_SEEN[k])

    peers = {}      # ip -> {conns, up, down, bytes, rate}
    clients = {}    # ip -> {conns, bytes, rate}
    onwire_peers = {"rx_bps": 0.0, "tx_bps": 0.0}    # 1789 node relay, by direction
    onwire_clients = {"rx_bps": 0.0, "tx_bps": 0.0}  # 9000 mixnet clients, by direction
    for key, pair2 in s2.items():
        lip, lport, rip, rport = key
        if not rip or rip.startswith("127.") or rip == "::1":
            continue
        sent2, recv2 = pair2
        sent1, recv1 = s1.get(key, pair2)
        b2 = sent2 + recv2
        rate = max(0, b2 - (sent1 + recv1)) * 8 / dt        # bit/s over the window
        tx_bps = max(0, sent2 - sent1) * 8 / dt             # node -> peer (sent)
        rx_bps = max(0, recv2 - recv1) * 8 / dt             # peer -> node (received)
        local_mix = lport in mixset
        remote_mix = rport in mixset
        if local_mix or remote_mix:
            p = peers.setdefault(rip, {"conns": 0, "up": 0, "down": 0, "bytes": 0, "rate": 0.0})
            p["conns"] += 1
            p["bytes"] += b2
            p["rate"] += rate
            onwire_peers["rx_bps"] += rx_bps
            onwire_peers["tx_bps"] += tx_bps
            if local_mix:
                p["up"] += 1
            if remote_mix:
                p["down"] += 1
        elif lport in clientset:
            c = clients.setdefault(rip, {"conns": 0, "bytes": 0, "rate": 0.0})
            c["conns"] += 1
            c["bytes"] += b2
            c["rate"] += rate
            onwire_clients["rx_bps"] += rx_bps
            onwire_clients["tx_bps"] += tx_bps

    out_peers, up, down = [], 0, 0
    for ip, d in sorted(peers.items(), key=lambda kv: -kv[1]["rate"]):
        direction = "both" if d["up"] and d["down"] else ("up" if d["up"] else "down")
        if d["up"]:
            up += 1
        if d["down"]:
            down += 1
        out_peers.append({"ip": ip, "conns": d["conns"], "dir": direction,
                          "bps": round(d["rate"]), "bytes": d["bytes"], "dur": dur("peer", ip)})

    out_clients = []
    for ip, d in sorted(clients.items(), key=lambda kv: -kv[1]["rate"]):
        out_clients.append({"ip": ip, "conns": d["conns"], "bps": round(d["rate"]),
                            "bytes": d["bytes"], "dur": dur("client", ip)})

    # WireGuard dVPN clients (51822/udp), from `wg show`
    wg_clients = []
    wg_ok = wg2 is not None
    if wg2:
        for ip, d in sorted(wg2.items(), key=lambda kv: -(kv[1]["bytes"])):
            prev = (wg1 or {}).get(ip, {}).get("bytes", d["bytes"])
            rate = max(0, d["bytes"] - prev) * 8 / dt
            hs_age = int(now - d["hs"]) if d["hs"] else None
            wg_clients.append({"ip": ip, "conns": d["conns"], "bps": round(rate),
                               "bytes": d["bytes"], "dur": dur("wg", ip), "handshake_age": hs_age})

    # prune first-seen entries no longer present
    for k in [k for k in _FIRST_SEEN if k not in seen_keys]:
        del _FIRST_SEEN[k]

    return {
        "ok": True,
        "ports": ports,
        "client_ports": cports,
        "total_peers": len(peers),
        "total_conns": sum(p["conns"] for p in peers.values()),
        "upstream": up,
        "downstream": down,
        "peers": out_peers,
        "clients": out_clients,
        "client_count": len(clients),
        "client_conns": sum(c["conns"] for c in clients.values()),
        "wg_clients": wg_clients,
        "wg_count": len(wg_clients),
        "wg_available": wg_ok,
        "onwire_mix": {"rx_bps": round(onwire_peers["rx_bps"] + onwire_clients["rx_bps"]),
                       "tx_bps": round(onwire_peers["tx_bps"] + onwire_clients["tx_bps"])},
        "onwire_clients": {"rx_bps": round(onwire_clients["rx_bps"]), "tx_bps": round(onwire_clients["tx_bps"])},
        "onwire_peers": {"rx_bps": round(onwire_peers["rx_bps"]), "tx_bps": round(onwire_peers["tx_bps"])},
        "sampled_s": round(dt, 2),
    }


# --- extra destination blocks (abuse mitigation) ---------------------------
# A oneshot systemd unit that runs AFTER nym-node (PartOf/WantedBy) and applies,
# on top of the NYM-EXIT chain nym-node rebuilds on every start: maestro's scan
# rate-limit (nym_scan_v2), the fan-out limiter and the destination blocklist.
# The blocklist is maintained in maestro (orchestrator DB) and shipped with the
# install action; the node never fetches it. Every block REJECT carries the
# comment "nym_block", so maestro reconciles exactly its own rules and never
# touches nym-node's exit-policy REJECTs.

EB_SH = "/usr/local/sbin/nym-extra-blocks.sh"
EB_UNIT_NAME = "nym-extra-blocks.service"
EB_UNIT = "/etc/systemd/system/" + EB_UNIT_NAME
EB_STATE_DIR = "/var/lib/nym-extra-blocks"
EB_CACHE = EB_STATE_DIR + "/blocklist.txt"     # current list (written by maestro)
EB_LEGACY = EB_STATE_DIR + "/legacy.txt"       # pre-marker list, for migration
EB_URL_FILE = EB_STATE_DIR + "/list_url"       # pre-0.12.9 leftover, removed on install
EB_CHAIN = "NYM-EXIT"
EB_CHAIN6 = os.environ.get("MAESTRO_NYM_EXIT6", "NYM-EXIT")  # ip6tables chain (same name by default)
EB_MARK = "nym_block"
EB_MAX_ENTRIES = 5000
# Guard against a typo taking the whole exit down (e.g. 0.0.0.0/0). Same bounds
# as the orchestrator's blocklist.py.
EB_MIN_PREFIX = {4: 16, 6: 32}

EB_SCRIPT = r"""#!/usr/bin/env bash
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
CHAIN6="__CHAIN6__"
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
"""

EB_UNIT_TPL = """[Unit]
Description=Extra destination blocks for NYM-EXIT (nym maestro managed)
After=__NYM__
PartOf=__NYM__
Wants=network-online.target

[Service]
Type=oneshot
ExecStartPre=/bin/sleep 10
ExecStart=/usr/local/sbin/nym-extra-blocks.sh
RemainAfterExit=yes

[Install]
WantedBy=__NYM__
"""


def _eb_installed():
    return os.path.exists(EB_SH) and os.path.exists(EB_UNIT)


def _eb_is(state_cmd):
    _, out, _ = _run(["systemctl", state_cmd, EB_UNIT_NAME])
    return out.strip()


def eb_canonical(entry):
    """Canonical network string ("1.2.3.4/32", "2001:db8::/48") or None.
    Host bits set ("10.0.0.5/24") and too-broad prefixes are rejected, not
    silently widened/accepted."""
    if not isinstance(entry, str):
        return None
    e = entry.strip()
    if not e or len(e) > 64:
        return None
    try:
        net = ipaddress.ip_network(e, strict=True)
    except ValueError:
        return None
    if net.prefixlen < EB_MIN_PREFIX[net.version]:
        return None
    return str(net)


def eb_list_sha(entries):
    """Order-independent fingerprint of a list; the orchestrator computes the same
    one so the UI can flag nodes that still run an older list."""
    canon = sorted({c for c in (eb_canonical(e) for e in entries) if c})
    return hashlib.sha256("\n".join(canon).encode()).hexdigest()


def _eb_parse_file(path):
    out = []
    for line in (_read_file(path) or "").splitlines():
        e = line.split("#", 1)[0].strip()
        if not e:
            continue
        try:
            out.append(str(ipaddress.ip_network(e, strict=False)))
        except ValueError:
            continue
    return out


def _eb_entries_cached():
    """Blocklist entries from the on-disk list (canonical form). Never the network."""
    return _eb_parse_file(EB_CACHE)


def _eb_fetch_entries(url=None):
    # kept for callers of the old name: the list is local now
    return _eb_entries_cached()


def _eb_family(entry):
    try:
        return ipaddress.ip_network(entry, strict=False).version
    except ValueError:
        return None


def _eb_norm(d):
    try:
        return str(ipaddress.ip_network(d, strict=False))
    except ValueError:
        return d


_EB_LEGACY_RE = re.compile(r"^-A (\S+) -d (\S+) -j REJECT --reject-with icmp6?-port-unreachable$")


def _eb_chain_rules(cmd, chain):
    """(chain_present, {marked dests}, {unmarked old-style dests}) from `-S`.
    Marked = REJECTs carrying the nym_block comment (ours). Unmarked old-style =
    the exact form pre-0.12.9 maestro inserted; nym-node's policy REJECTs may share
    it, so callers only ever look at dests that are (or were) on our list."""
    rc, out, _ = _run([cmd, "-S", chain])
    if rc != 0:
        return False, set(), set()
    marked, legacy = set(), set()
    for line in out.splitlines():
        line = line.strip()
        if "-j REJECT" not in line:
            continue
        m = re.match(r"-A\s+" + re.escape(chain) + r"\s+-d\s+(\S+)\s", line)
        if not m:
            continue
        if re.search(r"--comment\s+\"?" + EB_MARK + r"\"?(\s|$)", line):
            marked.add(_eb_norm(m.group(1)))
        elif _EB_LEGACY_RE.match(line):
            legacy.add(_eb_norm(m.group(1)))
    return True, marked, legacy


def _eb_v6_supported():
    return shutil.which("ip6tables") is not None


def _eb_hits(cmd, chain):
    """Packet counters of our marked REJECTs: (total, {dest: pkts}) or (None, {})."""
    rc, out, _ = _run([cmd, "-L", chain, "-n", "-v", "-x"], timeout=10)
    if rc != 0:
        return None, {}
    total, per = 0, {}
    for line in out.splitlines():
        if "REJECT" not in line or ("/* " + EB_MARK + " */") not in line:
            continue
        m = re.match(r"\s*(\d+)\s+\d+\s+REJECT\s", line)
        if not m:
            continue
        cols = line.split("/*", 1)[0].split()
        dest = _eb_norm(cols[-1]) if cols else "?"
        per[dest] = per.get(dest, 0) + int(m.group(1))
        total += int(m.group(1))
    return total, per


def _eb_scan(entries=None):
    """One read of both families: per-family presence of the list as marked
    rules, stale marked rules (not on the list), leftover unmarked old-style
    rules for list/legacy entries, and hit counters."""
    entries = _eb_entries_cached() if entries is None else entries
    legacy_src = set(_eb_parse_file(EB_LEGACY)) | set(entries)
    v6_supported = _eb_v6_supported()
    fams = {}
    for fam, cmd, chain in ((4, "iptables", EB_CHAIN), (6, "ip6tables", EB_CHAIN6)):
        want = [e for e in entries if _eb_family(e) == fam]
        if fam == 6 and not v6_supported:
            fams[fam] = {"size": len(want), "present": 0, "chain_present": False, "stale": 0,
                         "legacy": 0, "hits": None, "per_dest": {}, "supported": False,
                         "applicable": False}
            continue
        cp, marked, legacy = _eb_chain_rules(cmd, chain)
        hits, per = _eb_hits(cmd, chain) if cp else (None, {})
        fams[fam] = {
            "size": len(want),
            "present": sum(1 for e in want if e in marked),
            "chain_present": cp,
            "stale": len(marked - set(want)),
            "legacy": len({d for d in legacy if d in legacy_src and _eb_family(d) == fam}),
            "hits": hits, "per_dest": per,
            "supported": True, "applicable": bool(cp),
        }
    return entries, fams


def _eb_verify(entries=None):
    """Authoritative check of the blocklist rules. IPv6 is best-effort: a node
    without a v6 exit chain is not a failure."""
    entries, f = _eb_scan(entries)
    v4, v6 = f[4], f[6]
    v4_ok = v4["size"] == 0 or (v4["chain_present"] and v4["present"] >= v4["size"])
    v6_ok = v6["size"] == 0 or not v6["applicable"] or v6["present"] >= v6["size"]
    hits = [x["hits"] for x in (v4, v6) if x["hits"] is not None]
    per = dict(v4["per_dest"]); per.update(v6["per_dest"])
    sample = entries[0] if entries else None
    return {
        "chain_present": v4["chain_present"],
        "blocklist_size": len(entries),
        "rules_present": v4["present"] + (v6["present"] if v6["applicable"] else 0),
        "stale_rules": v4["stale"] + v6["stale"],
        "legacy_rules": v4["legacy"] + v6["legacy"],
        "hits": sum(hits) if hits else None,
        "hits_per_dest": per,
        "sample_ip": sample,
        "sample_blocked": (sample is not None and per.get(sample) is not None) if sample else None,
        # an empty list is a valid, fully applied state
        "all_present": v4_ok and v6_ok and v4["stale"] + v6["stale"] == 0,
        "list_sha": eb_list_sha(entries),
        "v4": {k: v4[k] for k in ("size", "present", "chain_present", "stale", "legacy")},
        "v6": {k: v6[k] for k in ("size", "present", "chain_present", "stale", "legacy",
                                   "supported", "applicable")},
    }


def _eb_rate_limit():
    """(rate, burst, count) of maestro's nym_scan_v2 rule, read by name from -S.
    count > 1 means stacked duplicates."""
    rc, out, _ = _run(["iptables", "-S", EB_CHAIN], timeout=10)
    if rc != 0:
        return None, None, 0
    rate = burst = None
    n = 0
    for line in out.splitlines():
        if "--hashlimit-name nym_scan_v2" not in line:
            continue
        n += 1
        m = re.search(r"--hashlimit-above (\S+)", line)
        b = re.search(r"--hashlimit-burst (\d+)", line)
        if m and rate is None:
            rate = m.group(1)
            burst = int(b.group(1)) if b else None
    return rate, burst, n


EB_FO_CHAIN = "NYM-FANOUT"            # fan-out limiter sub-chains, written by the installer
EB_FO_CHAIN_NEW = "NYM-FANOUT-NEWDST"


def _eb_fanout_summary():
    """Fan-out limiter (netscan protection) as seen live in iptables.

    hooked: a "-j NYM-FANOUT" jump sits in NYM-EXIT (v4 or v6). nym-node flushes
    NYM-EXIT on restart; the oneshot re-adds the jump, so hooked=False with the
    sub-chains still present means the limiter is NOT in effect.
    rejects: packet counter of the REJECT rule(s) in NYM-FANOUT-NEWDST, v4+v6
    summed. The installer flushes the chain on every run, so the counter covers
    the time since the oneshot last ran (since = its ActiveEnterTimestamp).
    Only counters are read — no per-client data. None = not readable."""
    hooked = False
    rejects = None
    rate = None
    burst = None
    fams = [("iptables", EB_CHAIN)]
    if _eb_v6_supported():
        fams.append(("ip6tables", EB_CHAIN6))
    for ipt, chain in fams:
        try:
            rc, out, _ = _run([ipt, "-S", chain], timeout=10)
            if rc == 0 and f"-A {chain} -j {EB_FO_CHAIN}" in (l.strip() for l in out.splitlines()):
                hooked = True
            # -x: exact counters (no K/M suffixes)
            rc, out, _ = _run([ipt, "-L", EB_FO_CHAIN_NEW, "-n", "-v", "-x"], timeout=10)
            if rc != 0:
                continue
            for line in out.splitlines():
                m = re.match(r"\s*(\d+)\s+\d+\s+REJECT\b", line)
                if not m:
                    continue
                rejects = (rejects or 0) + int(m.group(1))
                m = re.search(r"limit:\s*above\s+(\d+/\w+)\s+burst\s+(\d+)", line)
                if m and rate is None:
                    rate, burst = m.group(1), int(m.group(2))
        except Exception:
            pass
    return {"fanout_active": hooked,
            "fanout_rejects": rejects,
            "fanout_rate": rate,
            "fanout_burst": burst,
            "fanout_since": nym_node_since(EB_UNIT_NAME) if rejects is not None else None}


def _extra_blocks_state():
    """State for the fleet column: blocklist presence (marked rules only), hits,
    list fingerprint, migration leftovers, rate-limit and fan-out. Reads only the
    local list and iptables — never the network (runs on every status poll)."""
    if not _eb_installed():
        return {"installed": False, "enabled": False, "active": False, "state": "missing"}
    active = _eb_is("is-active") == "active"
    enabled = _eb_is("is-enabled") in ("enabled", "enabled-runtime", "static", "alias")
    st = {"installed": True, "enabled": enabled, "active": active,
          "state": "active" if active else "inactive"}
    try:
        v = _eb_verify()
        st.update({
            "chain_present": v["chain_present"],
            "blocked_count": v["rules_present"],
            "blocklist_size": v["blocklist_size"],
            "stale_rules": v["stale_rules"],
            "legacy_rules": v["legacy_rules"],
            "hits": v["hits"],
            "list_sha": v["list_sha"],
        })
    except Exception:
        st.update({"chain_present": None, "blocked_count": None, "blocklist_size": None})
    rate, burst, n = _eb_rate_limit()
    st.update({"rate_limit_active": rate is not None, "rate_limit_rate": rate,
               "rate_limit_burst": burst, "rate_limit_rules": n})
    st.update(_eb_fanout_summary())
    return st


def act_extra_blocks_status(params):
    st = _extra_blocks_state()
    st["ok"] = True
    st["chain"] = EB_CHAIN
    st["chain6"] = EB_CHAIN6
    st["mark"] = EB_MARK
    if st.get("installed"):
        st.update({k: v for k, v in _eb_verify().items() if k != "ok"})
    return st


def _eb_validate_entries(raw):
    """(canonical entries, error). The orchestrator validates first; this is the
    node's own check before anything reaches a root shell."""
    if not isinstance(raw, list):
        return None, "entries must be a list"
    if len(raw) > EB_MAX_ENTRIES:
        return None, f"too many entries (max {EB_MAX_ENTRIES})"
    out, seen = [], set()
    for e in raw:
        c = eb_canonical(e)
        if c is None:
            return None, f"invalid or too broad entry: {str(e)[:64]!r}"
        if c not in seen:
            seen.add(c); out.append(c)
    return out, None


def _eb_backup_existing():
    """If a pre-existing script/unit is NOT one of ours (e.g. the hand-made one on
    DE01), preserve it to <path>.maestro.bak before we overwrite. Reinstalling over
    maestro's own files is a no-op here. Returns (backed_up, replaced_handmade)."""
    backed, handmade = [], False
    for path in (EB_SH, EB_UNIT):
        if not os.path.exists(path):
            continue
        existing = _read_file(path) or ""
        if "nym-maestro" in existing or "nym maestro" in existing:
            continue                   # already ours — nothing to preserve
        handmade = True
        bak = path + ".maestro.bak"
        if not os.path.exists(bak):    # keep the very first (true) original
            with contextlib.suppress(Exception):
                _write_file(bak, existing)
                backed.append(bak)
    return backed, handmade


def _eb_write_files(entries):
    nym = resolve_service()
    backed, handmade = _eb_backup_existing()
    try:
        os.makedirs(EB_STATE_DIR, exist_ok=True)
        os.makedirs(os.path.dirname(EB_SH), exist_ok=True)
        # Migration: the list an older version applied (unmarked REJECTs) is kept
        # once as legacy.txt so the script can replace exactly those rules.
        if not os.path.exists(EB_LEGACY) and os.path.exists(EB_CACHE):
            _write_file(EB_LEGACY, _read_file(EB_CACHE) or "")
        # list before the script, so a concurrently-triggered oneshot finds it
        tmp = EB_CACHE + ".tmp"
        with open(tmp, "w") as f:
            f.write("# written by nym-maestro — edit the list in maestro, not here\n")
            f.write("".join(e + "\n" for e in entries))
        os.replace(tmp, EB_CACHE)
        with contextlib.suppress(FileNotFoundError):
            os.remove(EB_URL_FILE)
        tmp = EB_SH + ".tmp"
        with open(tmp, "w") as f:
            f.write(EB_SCRIPT.replace("__CHAIN6__", EB_CHAIN6))
        os.chmod(tmp, 0o755)
        os.replace(tmp, EB_SH)
        with open(EB_UNIT, "w") as f:
            f.write(EB_UNIT_TPL.replace("__NYM__", nym))
    except Exception as e:
        return False, f"could not write files: {e}", {}
    _run(["systemctl", "daemon-reload"], timeout=20)
    _run(["systemctl", "enable", EB_UNIT_NAME], timeout=20)
    return True, None, {"replaced_existing": handmade, "replaced_handmade": handmade,
                        "backups": backed}


def _eb_wait_rules(deadline_s=90):
    """Poll until the list is fully applied (after a nym-node restart), bounded."""
    end = time.time() + deadline_s
    last = _eb_verify()
    while time.time() < end:
        last = _eb_verify()
        if last["chain_present"] and last["all_present"]:
            return last
        time.sleep(3)
    return last


def act_extra_blocks_install(params):
    """Write the list maestro sent + script + unit, then apply. This is also the
    'roll out blocklist' action: the oneshot reconciles (drains every nym_block
    REJECT, then sets the current list), so removed entries disappear too."""
    if "entries" not in params:
        return {"ok": False, "error": "no blocklist entries sent — the list is managed in "
                                      "maestro now; update the orchestrator"}
    entries, err = _eb_validate_entries(params.get("entries"))
    if err:
        return {"ok": False, "error": err}
    restart_node = bool(params.get("restart_node", False))
    log = []
    before = _eb_verify()
    ok, err, meta = _eb_write_files(entries)
    if not ok:
        return {"ok": False, "error": err}
    log.append(f"wrote {len(entries)} entries + {EB_UNIT_NAME} (enabled), targeting {resolve_service()}")
    if meta.get("replaced_existing"):
        log.append("backed up the pre-existing " +
                   ("hand-made " if meta.get("replaced_handmade") else "") +
                   "script/unit to *.maestro.bak before overwriting")

    if restart_node:
        svc = resolve_service()
        restarted, _active, rerr, elapsed = _restart_service(svc)
        if not restarted:
            return {"ok": False, "error": f"failed to restart {svc}: {rerr}",
                    "before": before, "output": "\n".join(log)}
        log.append(f"restarted {svc} ({elapsed}s)")
        # the oneshot is WantedBy nym-node and fires on its own; poll for the rules,
        # then nudge it once if they haven't landed yet
        after = _eb_wait_rules(deadline_s=75)
        if not after["all_present"]:
            _run(["systemctl", "restart", EB_UNIT_NAME], timeout=90)
            after = _eb_wait_rules(deadline_s=45)
        applied = after["all_present"]
        return {
            "ok": applied, "mode": "install+restart", "restarted": svc,
            "replaced_existing": meta.get("replaced_existing", False),
            "replaced_handmade": meta.get("replaced_handmade", False),
            "before": before, "after": after, "state": _extra_blocks_state(),
            "output": "\n".join(log),
            "error": None if applied else
                     "nym-node restarted but the block rules did not all land — check "
                     "`journalctl -u nym-extra-blocks` and that the NYM-EXIT chain exists.",
        }

    # apply to the LIVE chain now (no nym-node restart). restart, not start: on an
    # active RemainAfterExit oneshot `start` is a no-op and nothing would change.
    rc, out, errx = _run(["systemctl", "restart", EB_UNIT_NAME], timeout=90)
    log.append("ran extra-blocks once: " + ("ok" if rc == 0 else "FAILED " + (errx or out).strip()))
    after = _eb_verify()
    applied_now = rc == 0 and after["chain_present"] and after["all_present"]
    if after.get("legacy_rules"):
        log.append(f"{after['legacy_rules']} unmarked pre-0.12.9 REJECT(s) still present")
    return {
        "ok": rc == 0 and (applied_now or not after["chain_present"]),
        "mode": "install-only", "applied_now": applied_now,
        "replaced_existing": meta.get("replaced_existing", False),
        "replaced_handmade": meta.get("replaced_handmade", False),
        "before": before, "after": after, "state": _extra_blocks_state(),
        "output": "\n".join(log),
        "note": ("list applied to the running NYM-EXIT chain (reconciled: removed entries are gone). "
                 "It re-applies automatically on every nym-node start.")
                if applied_now else
                ("unit installed and enabled, but NYM-EXIT was not present to apply to yet "
                 "(is nym-node running?). It applies automatically on the next nym-node start; "
                 "use 'verify' afterwards.") if not after["chain_present"] else None,
        "error": None if (rc == 0 and (applied_now or not after["chain_present"])) else
                 ("extra-blocks oneshot failed" if rc != 0 else
                  f"only {after['rules_present']}/{after['blocklist_size']} entries present"
                  + (f", {after['stale_rules']} stale" if after["stale_rules"] else "")),
    }


def act_extra_blocks_upgrade(params):
    """Rewrite script + unit from the built-in template, keeping the node's list,
    then restart the oneshot so the new script runs now."""
    entries = _eb_entries_cached()
    log = [f"rewriting {EB_SH} from built-in template ({len(entries)} entries kept)"]
    ok, err, meta = _eb_write_files(entries)
    if not ok:
        return {"ok": False, "error": err, "output": "\n".join(log)}
    rc, out, errx = _run(["systemctl", "restart", EB_UNIT_NAME], timeout=90)
    log.append("restarted extra-blocks: " + ("ok" if rc == 0 else "FAILED " + (errx or out).strip()))
    return {"ok": rc == 0, "after": _eb_verify(), "state": _extra_blocks_state(),
            "output": "\n".join(log),
            "error": None if rc == 0 else "service restart failed after script update"}


def act_extra_blocks_verify(params):
    """Confirm the list is in place — e.g. after a manual nym-node restart."""
    v = _eb_verify()
    v["ok"] = True
    v["state"] = _extra_blocks_state()["state"]
    if not v["chain_present"]:
        v["error"] = "NYM-EXIT chain not present (is nym-node running?)"
    elif not v["all_present"]:
        v["error"] = (f"only {v['rules_present']}/{v['blocklist_size']} entries present in {EB_CHAIN}"
                      + (f", {v['stale_rules']} stale {EB_MARK} rule(s)" if v["stale_rules"] else ""))
    else:
        v["error"] = None
    return v


def _eb_drain(cmd, chain, legacy_dests):
    """Python twin of the script's reconcile teardown: every marked REJECT by its
    exact -S spec, plus the unmarked old-style REJECT for each legacy dest."""
    removed = 0
    for _ in range(EB_MAX_ENTRIES + 10):
        rc, out, _ = _run([cmd, "-S", chain])
        if rc != 0:
            break
        hit = next((l.strip() for l in out.splitlines()
                    if "-j REJECT" in l and re.search(r"--comment\s+\"?" + EB_MARK + r"\"?(\s|$)", l)), None)
        if not hit:
            break
        if _run([cmd, "-D", chain] + hit.split()[2:])[0] != 0:
            break
        removed += 1
    rej = "icmp6-port-unreachable" if cmd == "ip6tables" else "icmp-port-unreachable"
    for d in legacy_dests:
        for _ in range(50):
            if _run([cmd, "-D", chain, "-d", d, "-j", "REJECT", "--reject-with", rej])[0] != 0:
                break
            removed += 1
    return removed


def act_extra_blocks_remove(params):
    """Disable + remove the unit/script/list and every nym_block REJECT (plus the
    unmarked pre-marker ones). Rate-limit and fan-out rules are left as they are;
    the next nym-node start rebuilds NYM-EXIT without them."""
    log = []
    _run(["systemctl", "disable", "--now", EB_UNIT_NAME], timeout=30)
    legacy = set(_eb_parse_file(EB_LEGACY)) | set(_eb_entries_cached())
    removed = _eb_drain("iptables", EB_CHAIN, [d for d in legacy if _eb_family(d) == 4])
    if _eb_v6_supported():
        removed += _eb_drain("ip6tables", EB_CHAIN6, [d for d in legacy if _eb_family(d) == 6])
    for p in (EB_SH, EB_UNIT, EB_URL_FILE, EB_CACHE, EB_LEGACY):
        with contextlib.suppress(Exception):
            if os.path.exists(p):
                os.remove(p)
    _run(["systemctl", "daemon-reload"], timeout=20)
    log.append(f"removed unit + script + list; deleted {removed} REJECT rules from the exit chains")
    return {"ok": True, "removed_rules": removed, "state": _extra_blocks_state(),
            "output": "\n".join(log), "error": None}


def act_extra_blocks_install_script(params):
    """Run the extra-blocks installer that the orchestrator pushed over mTLS.

    The script content and its sha256 come from the orchestrator, which vouches
    for its own local install-nym-extra-blocks.sh. The agent NEVER fetches code
    from the internet: the mTLS channel is the trusted transport, and the content
    is integrity-checked against the supplied hash before it is ever run as root.
    """
    content = params.get("content")
    if not isinstance(content, str) or not content.strip():
        return {"ok": False, "error": "no installer content provided"}
    actual = hashlib.sha256(content.encode()).hexdigest()
    want = (params.get("sha256") or "").strip().lower()
    if not want or want != actual:
        return {"ok": False, "error": "sha256 mismatch (transfer corrupted or hash missing)"}
    log = [f"received installer over mTLS ({len(content)} bytes, sha256 {actual[:12]})"]
    fd, tmp = tempfile.mkstemp(suffix=".sh", prefix="maestro-install-")
    rc = 1
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.chmod(tmp, 0o700)
        rc, out, errx = _run(["bash", tmp], timeout=180)
        log.append((out or "").strip())
        if errx and errx.strip():
            log.append(errx.strip())
        log.append("installer: " + ("ok" if rc == 0 else f"FAILED (exit {rc})"))
    except Exception as e:
        return {"ok": False, "error": f"run failed: {e}", "output": "\n".join(log)}
    finally:
        with contextlib.suppress(Exception):
            os.unlink(tmp)
    return {
        "ok": rc == 0,
        "state": _extra_blocks_state(),
        "output": "\n".join(log),
        "error": None if rc == 0 else f"installer exited with code {rc}",
    }


def act_extra_blocks_restart_service(params):
    """Restart nym-extra-blocks.service without touching nym-node."""
    log = [f"restarting {EB_UNIT_NAME}"]
    rc, out, errx = _run(["systemctl", "restart", EB_UNIT_NAME], timeout=90)
    log.append("restart: " + ("ok" if rc == 0 else "FAILED " + (errx or out).strip()))
    return {
        "ok": rc == 0,
        "state": _extra_blocks_state(),
        "output": "\n".join(log),
        "error": None if rc == 0 else "service restart failed",
    }


# --- nym_concurrency (anti-BitTorrent) ------------------------------------
# Per-client cap on CONCURRENT connections to high ports, enforced with connlimit
# in our own mangle chain NYM-CONCURRENCY, hooked from PREROUTING for the tunnel
# interfaces only. Separate from the extra-blocks unit (different table, no shared
# rules): nym_scan / the fan-out limiter cap how FAST a client opens connections,
# this caps how MANY it holds at once. BitTorrent (incl. encrypted MSE) holds
# hundreds; calibration on 3 exits: legit <= 26, torrent clients 279-670.
# A oneshot unit PartOf/WantedBy nym-node re-applies it on every nym-node start.

NC_SH = "/usr/local/sbin/nym-concurrency.sh"
NC_UNIT_NAME = "nym-concurrency.service"
NC_UNIT = "/etc/systemd/system/" + NC_UNIT_NAME
NC_STATE_DIR = "/var/lib/nym-concurrency"
NC_LIMIT_FILE = NC_STATE_DIR + "/limit"
NC_CHAIN = "NYM-CONCURRENCY"
NC_TABLE = "mangle"
NC_IFACES = ("nymwg", "nymtun0")      # must match IFACES in NC_SCRIPT
NC_DEFAULT_LIMIT = 50
NC_LIMIT_MIN = 10
NC_LIMIT_MAX = 10000

# Runtime script. Must stay word-identical to the heredoc in
# install-nym-concurrency.sh (test_concurrency.py checks it).
NC_SCRIPT = r"""#!/usr/bin/env bash
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
"""

NC_UNIT_TPL = """[Unit]
Description=Per-client concurrent-connection limit on high ports (anti-BitTorrent, nym maestro managed)
After=__NYM__
PartOf=__NYM__
Wants=network-online.target

[Service]
Type=oneshot
ExecStartPre=/bin/sleep 10
ExecStart=/usr/local/sbin/nym-concurrency.sh apply
ExecStop=/usr/local/sbin/nym-concurrency.sh stop
RemainAfterExit=yes

[Install]
WantedBy=__NYM__
"""

_NC_HOOK_RE = re.compile(r"^-A PREROUTING(?: -i (\S+))? -j " + re.escape(NC_CHAIN) + r"$")
# iptables -L -n -v -x line of a connlimit DROP rule, e.g.
#   "  812  48720 DROP  6  --  *  *  0.0.0.0/0  0.0.0.0/0  tcp dpts:12000:65535
#    ctstate NEW #conn src/32 > 50 /* nym_concurrency */"
# prot is numeric (6/17) on iptables-nft, a name on legacy builds.
_NC_DROP_RE = re.compile(r"^\s*(\d+)\s+\d+\s+DROP\s+(\S+)\s.*#conn\s+src/(\d+)\s*>\s*(\d+)")
_NC_PROTO = {"6": "tcp", "17": "udp", "tcp": "tcp", "udp": "udp"}


def nc_parse_limit(v):
    """Validated limit (int) or None. Accepts ints and digit strings; bools rejected."""
    if isinstance(v, bool):
        return None
    if isinstance(v, str):
        v = v.strip()
        if not v.isdigit() or len(v) > 6:
            return None
        v = int(v)
    if not isinstance(v, int) or not (NC_LIMIT_MIN <= v <= NC_LIMIT_MAX):
        return None
    return v


def _nc_installed():
    return os.path.exists(NC_SH) and os.path.exists(NC_UNIT)


def _nc_is(state_cmd):
    _, out, _ = _run(["systemctl", state_cmd, NC_UNIT_NAME])
    return out.strip()


def _nc_configured_limit():
    """The limit maestro wrote (what the script will apply), default if unset."""
    txt = _read_file(NC_LIMIT_FILE)
    if txt is None or not txt.strip():
        return NC_DEFAULT_LIMIT
    return nc_parse_limit(txt)        # None = file present but invalid


def _nc_family(ipt):
    """Live view of one family: hooks, chain presence, limit and drop counters
    straight from iptables (the UI shows the node's truth, not a config value)."""
    fam = {"hooked_ifaces": [], "chain_present": False, "limit": None, "mask": None,
           "drops": None, "drops_tcp": None, "drops_udp": None, "rules": 0}
    rc, out, _ = _run([ipt, "-t", NC_TABLE, "-S", "PREROUTING"], timeout=10)
    if rc == 0:
        for line in out.splitlines():
            m = _NC_HOOK_RE.match(line.strip())
            if m:
                fam["hooked_ifaces"].append(m.group(1) or "*")
    # -x: exact counters (no K/M suffixes)
    rc, out, _ = _run([ipt, "-t", NC_TABLE, "-L", NC_CHAIN, "-n", "-v", "-x"], timeout=10)
    if rc != 0:
        return fam
    fam["chain_present"] = True
    for line in out.splitlines():
        m = _NC_DROP_RE.match(line)
        if not m:
            continue
        pkts, proto = int(m.group(1)), _NC_PROTO.get(m.group(2).lower())
        fam["rules"] += 1
        fam["drops"] = (fam["drops"] or 0) + pkts
        if proto:
            k = "drops_" + proto
            fam[k] = (fam[k] or 0) + pkts
        if fam["limit"] is None:
            fam["limit"], fam["mask"] = int(m.group(4)), int(m.group(3))
    return fam


def _nc_live():
    v4 = _nc_family("iptables")
    v6 = _nc_family("ip6tables") if _eb_v6_supported() else None
    v6_active = bool(v6 and v6["chain_present"] and v6["rules"] and v6["hooked_ifaces"])

    def _sum(k):
        vals = [f[k] for f in (v4, v6) if f and f[k] is not None]
        return sum(vals) if vals else None
    return {
        "chain_present": v4["chain_present"],
        "hooked": bool(v4["hooked_ifaces"]) and v4["rules"] > 0,
        "hooked_ifaces": v4["hooked_ifaces"],
        "limit": v4["limit"] if v4["limit"] is not None else (v6 or {}).get("limit"),
        "rules": v4["rules"],
        "drops": _sum("drops"),
        "drops_tcp": _sum("drops_tcp"),
        "drops_udp": _sum("drops_udp"),
        "v6_supported": v6 is not None,
        "v6_active": v6_active,
        "v6_limit": (v6 or {}).get("limit"),
        "v6_drops": (v6 or {}).get("drops"),
    }


def _nc_state():
    """State for the fleet column + modal. The drop counters reset whenever the
    oneshot re-applies (install, limit change, nym-node restart); `since` is the
    unit's ActiveEnterTimestamp."""
    if not _nc_installed():
        live = _nc_live()
        st = {"installed": False, "enabled": False, "active": False, "state": "missing"}
        # rules without our unit (e.g. a hand-run test install) are worth knowing
        if live["chain_present"] or live["hooked_ifaces"]:
            st.update(live)
            st["state"] = "unmanaged"
        return st
    active = _nc_is("is-active") == "active"
    enabled = _nc_is("is-enabled") in ("enabled", "enabled-runtime", "static", "alias")
    st = {"installed": True, "enabled": enabled, "active": active,
          "state": "active" if active else "inactive",
          "configured_limit": _nc_configured_limit(),
          "ifaces": list(NC_IFACES)}
    st.update(_nc_live())
    st["since"] = nym_node_since(NC_UNIT_NAME) if st["chain_present"] else None
    return st


def _nc_verify():
    """Authoritative check after install/restart. Each check is (name, ok, detail)."""
    st = _nc_state()
    checks = []

    def add(name, ok, detail=""):
        checks.append({"name": name, "ok": bool(ok), "detail": detail})
    add("unit installed + enabled", st.get("installed") and st.get("enabled"))
    add("unit active", st.get("active"), _nc_is("is-active") if st.get("installed") else "")
    add(NC_CHAIN + " chain present (v4)", st.get("chain_present"))
    add("TCP + UDP limit rules (v4)", st.get("rules", 0) >= 2, f"{st.get('rules', 0)} rule(s)")
    hooked = set(st.get("hooked_ifaces") or [])
    add("hooked from PREROUTING on " + ", ".join(NC_IFACES), hooked >= set(NC_IFACES),
        ", ".join(sorted(hooked)) or "no hook")
    add("no unscoped PREROUTING hook", "*" not in hooked)
    cfg = st.get("configured_limit")
    add("live limit = configured limit", st.get("limit") is not None and st.get("limit") == cfg,
        f"live {st.get('limit')} · configured {cfg}")
    if st.get("v6_supported"):
        add("v6 limiter active (best-effort)", st.get("v6_active"),
            f"v6 limit {st.get('v6_limit')}")
    gate = [c for c in checks if not c["name"].startswith("v6")]
    return st, checks, all(c["ok"] for c in gate)


def _nc_journal(n=15):
    rc, out, _ = _run(["journalctl", "-u", NC_UNIT_NAME, "-n", str(n), "--no-pager", "-o", "cat"],
                      timeout=10)
    return (out or "").strip() if rc == 0 else ""


def _nc_write_files(limit=None):
    nym = resolve_service()
    try:
        os.makedirs(NC_STATE_DIR, exist_ok=True)
        os.makedirs(os.path.dirname(NC_SH), exist_ok=True)
        # limit file first, so a concurrently-triggered oneshot already reads it
        if limit is not None or not os.path.exists(NC_LIMIT_FILE):
            _write_file(NC_LIMIT_FILE, f"{limit if limit is not None else NC_DEFAULT_LIMIT}\n")
        tmp = NC_SH + ".tmp"
        with open(tmp, "w") as f:
            f.write(NC_SCRIPT)
        os.chmod(tmp, 0o755)
        os.replace(tmp, NC_SH)
        with open(NC_UNIT, "w") as f:
            f.write(NC_UNIT_TPL.replace("__NYM__", nym))
    except Exception as e:
        return False, f"could not write files: {e}"
    _run(["systemctl", "daemon-reload"], timeout=20)
    _run(["systemctl", "enable", NC_UNIT_NAME], timeout=20)
    return True, None


def _nc_apply_and_report(log, mode):
    # restart, not start: on an active oneshot (RemainAfterExit) start is a no-op
    rc, out, errx = _run(["systemctl", "restart", NC_UNIT_NAME], timeout=90)
    log.append(f"restarted {NC_UNIT_NAME}: " + ("ok" if rc == 0 else "FAILED " + (errx or out).strip()))
    j = _nc_journal()
    if j:
        log.append(j)
    st, checks, ok = _nc_verify()
    failed = [c["name"] for c in checks if not c["ok"] and not c["name"].startswith("v6")]
    return {"ok": rc == 0 and ok, "kind": "concurrency", "mode": mode, "state": st,
            "checks": checks, "output": "\n".join(log),
            "error": None if (rc == 0 and ok) else
                     ("checks failed: " + ", ".join(failed) if failed else "service restart failed")}


def act_concurrency_status(params):
    st = _nc_state()
    st["ok"] = True
    st["kind"] = "concurrency"
    st["chain"] = NC_CHAIN
    st["table"] = NC_TABLE
    return st


def act_concurrency_install(params):
    """Write script + unit from the built-in template (+ optional limit) and apply.
    Re-running it is the update path: the script is always rewritten."""
    limit = None
    if params.get("limit") is not None:
        limit = nc_parse_limit(params.get("limit"))
        if limit is None:
            return {"ok": False, "kind": "concurrency",
                    "error": f"limit must be an integer {NC_LIMIT_MIN}..{NC_LIMIT_MAX}"}
    ok, err = _nc_write_files(limit)
    if not ok:
        return {"ok": False, "kind": "concurrency", "error": err}
    log = [f"wrote {NC_SH} + {NC_UNIT_NAME} (enabled, PartOf {resolve_service()}), "
           f"limit {_nc_configured_limit()}"]
    return _nc_apply_and_report(log, "install")


def act_concurrency_set_limit(params):
    """Change the limit on a running install: rewrite the limit file, re-apply."""
    limit = nc_parse_limit(params.get("limit"))
    if limit is None:
        return {"ok": False, "kind": "concurrency",
                "error": f"limit must be an integer {NC_LIMIT_MIN}..{NC_LIMIT_MAX}"}
    if not _nc_installed():
        return {"ok": False, "kind": "concurrency", "error": "nym-concurrency is not installed"}
    old = _nc_configured_limit()
    try:
        os.makedirs(NC_STATE_DIR, exist_ok=True)
        _write_file(NC_LIMIT_FILE, f"{limit}\n")
    except Exception as e:
        return {"ok": False, "kind": "concurrency", "error": f"could not write limit: {e}"}
    return _nc_apply_and_report([f"limit {old} -> {limit}"], "set_limit")


def act_concurrency_restart(params):
    if not _nc_installed():
        return {"ok": False, "kind": "concurrency", "error": "nym-concurrency is not installed"}
    return _nc_apply_and_report([], "restart")


def act_concurrency_verify(params):
    st, checks, ok = _nc_verify()
    failed = [c["name"] for c in checks if not c["ok"] and not c["name"].startswith("v6")]
    return {"ok": ok, "kind": "concurrency", "mode": "verify", "state": st, "checks": checks,
            "error": None if ok else "checks failed: " + ", ".join(failed)}


def _nc_teardown(ipt):
    """Python-side removal for one family (same semantics as the script's
    `stop`): every PREROUTING jump by exact spec, then flush + delete our chain."""
    removed = 0
    for _ in range(100):
        rc, out, _ = _run([ipt, "-t", NC_TABLE, "-S", "PREROUTING"], timeout=10)
        if rc != 0:
            break
        hit = next((l.strip() for l in out.splitlines() if _NC_HOOK_RE.match(l.strip())), None)
        if not hit:
            break
        spec = hit.split()[2:]          # drop "-A PREROUTING"
        if _run([ipt, "-t", NC_TABLE, "-D", "PREROUTING"] + spec, timeout=10)[0] != 0:
            break
        removed += 1
    _run([ipt, "-t", NC_TABLE, "-F", NC_CHAIN], timeout=10)
    _run([ipt, "-t", NC_TABLE, "-X", NC_CHAIN], timeout=10)
    return removed


def act_concurrency_remove(params):
    """Kill switch: stop + disable the unit, remove hooks/chain (v4+v6), delete files."""
    log = []
    if os.path.exists(NC_SH):
        rc, out, errx = _run([NC_SH, "stop"], timeout=30)
        log.append("script stop: " + ("ok" if rc == 0 else "FAILED " + (errx or out).strip()))
    _run(["systemctl", "disable", "--now", NC_UNIT_NAME], timeout=60)
    hooks = _nc_teardown("iptables")
    if _eb_v6_supported():
        hooks += _nc_teardown("ip6tables")
    for p in (NC_SH, NC_UNIT, NC_LIMIT_FILE):
        with contextlib.suppress(Exception):
            if os.path.exists(p):
                os.remove(p)
    _run(["systemctl", "daemon-reload"], timeout=20)
    live = _nc_live()
    gone = not live["chain_present"] and not live["hooked_ifaces"]
    log.append(f"unit disabled + files removed; {hooks} leftover hook(s) deleted; "
               f"{NC_CHAIN} " + ("gone" if gone else "STILL PRESENT"))
    return {"ok": gone, "kind": "concurrency", "mode": "remove", "state": _nc_state(),
            "output": "\n".join(log),
            "error": None if gone else f"{NC_CHAIN} chain or hook still present after removal"}


# ---------------------------------------------------------------- landing page
# The node serves a public notice page at /var/www/<hostname>/index.html listing
# every exit gateway the operator runs. Maestro renders that page centrally and
# ships the finished file here; the agent only validates and installs it.
WEBROOT = os.environ.get("MAESTRO_WEBROOT", "/var/www")
LANDING_MAX_BYTES = 4 << 20   # the real page is ~35 KB; this is a generous cap

_LANDING_HOST_RE = re.compile(
    r'^(?=.{1,253}$)([a-zA-Z0-9](-?[a-zA-Z0-9])*\.)+[a-zA-Z]{2,}$')
_LANDING_VERSION_RE = re.compile(
    r'<!-- NODES:VERSION ([0-9a-f]{6,64}) GENERATED (\S+) COUNT (\d+) -->')
_LANDING_BAK_RE = re.compile(r'^index\.html\.bak-([0-9a-z]{6,64})$')


def _landing_path(params):
    """Resolve /var/www/<hostname>/index.html, returning (dir, file, error).

    The hostname comes from the orchestrator and is the node's own FQDN — the
    same value the page lists for it. It is matched against a strict FQDN
    pattern and rejected if it is anything other than one path component, so a
    bad or hostile value cannot walk out of the webroot.
    """
    host = (params.get("hostname") or "").strip().lower()
    if not host or not _LANDING_HOST_RE.match(host) or os.path.basename(host) != host:
        return None, None, "invalid or missing hostname"
    d = os.path.join(WEBROOT, host)
    return d, os.path.join(d, "index.html"), None


def _landing_file_info(path):
    """Describe a page on disk, or None if it can't be read."""
    try:
        st = os.stat(path)
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read(LANDING_MAX_BYTES + 1)
    except Exception:
        return None
    m = _LANDING_VERSION_RE.search(text)
    info = {"size": st.st_size, "mtime": int(st.st_mtime), "version": None,
            "generated": None, "count": None}
    with contextlib.suppress(Exception):
        info["sha256"] = _sha256_file(path)
    if m:
        info["version"], info["generated"] = m.group(1), m.group(2)
        info["count"] = int(m.group(3))
    return info


def _landing_backups(d):
    """Previously installed pages, newest first."""
    out = []
    try:
        names = os.listdir(d)
    except Exception:
        return out
    for n in names:
        m = _LANDING_BAK_RE.match(n)
        if not m:
            continue
        try:
            st = os.stat(os.path.join(d, n))
        except Exception:
            continue
        out.append({"name": n, "version": m.group(1),
                    "size": st.st_size, "mtime": int(st.st_mtime)})
    out.sort(key=lambda b: b["mtime"], reverse=True)
    return out


def _landing_restore_context(path):
    """Re-label after the rename. A temp file created in the webroot does not
    inherit the target's SELinux context, and the web server would then get
    EACCES on a file that looks fine to ls. No-op where restorecon is absent,
    which is the normal case on Debian/Ubuntu."""
    if shutil.which("restorecon"):
        _run(["restorecon", "-F", path], timeout=20)


def _landing_copy_nofollow(src, dst):
    """Copy src to dst without ever writing through a symlink at dst.

    shutil.copy2 opens the destination with 'wb', which follows a link — so a
    symlink planted at the backup path by anything with write access to the
    webroot would redirect a root-owned write anywhere on the box. O_NOFOLLOW
    makes that fail instead.
    """
    with open(src, "rb") as fsrc:
        data = fsrc.read()
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(dst, flags, 0o644)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    with contextlib.suppress(Exception):
        shutil.copystat(src, dst)


def _landing_write(path, text):
    """Install text at path with no window where the page is missing or partly
    written: temp file in the same directory, fsync, then rename over the top.
    Mode and owner are carried over from the file being replaced so the page
    stays web-readable."""
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".index.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        if os.path.exists(path):
            st = os.stat(path)
            os.chmod(tmp, st.st_mode)
            with contextlib.suppress(Exception):
                os.chown(tmp, st.st_uid, st.st_gid)
        else:
            os.chmod(tmp, 0o644)
        os.replace(tmp, path)
        tmp = None
    finally:
        if tmp:
            with contextlib.suppress(Exception):
                os.unlink(tmp)
    _landing_restore_context(path)


def act_landing_status(params):
    """Report what this node currently serves, without changing anything."""
    d, path, err = _landing_path(params)
    if err:
        return {"ok": False, "error": err}
    if not os.path.isdir(d):
        return {"ok": True, "path": path, "dir_exists": False, "file_exists": False,
                "backups": [], "note": f"{d} does not exist"}
    info = _landing_file_info(path) if os.path.exists(path) else None
    res = {"ok": True, "path": path, "dir_exists": True, "file_exists": info is not None,
           "backups": _landing_backups(d)}
    if info:
        res.update(info)
    else:
        res["note"] = "webroot exists but index.html is missing"
    return res


def act_landing_deploy(params):
    """Install the public notice page that maestro rendered.

    The content and its sha256 arrive over the mTLS channel; the hash is checked
    before anything on disk is touched, and the page must carry a NODES:VERSION
    marker so an unrelated file can't be installed through this action. The page
    being replaced is kept as index.html.bak-<version> so one node can be rolled
    back without touching the rest of the fleet.
    """
    d, path, err = _landing_path(params)
    if err:
        return {"ok": False, "error": err}

    content = params.get("content")
    if not isinstance(content, str) or not content.strip():
        return {"ok": False, "error": "no page content provided"}
    raw = content.encode()
    if len(raw) > LANDING_MAX_BYTES:
        return {"ok": False,
                "error": f"page too large ({len(raw)} bytes, max {LANDING_MAX_BYTES})"}
    actual = hashlib.sha256(raw).hexdigest()
    want = (params.get("sha256") or "").strip().lower()
    if not want or want != actual:
        return {"ok": False, "error": "sha256 mismatch (transfer corrupted or hash missing)"}
    m = _LANDING_VERSION_RE.search(content)
    if not m:
        return {"ok": False,
                "error": "page carries no NODES:VERSION marker — not a maestro-generated page"}
    version = m.group(1)

    log = [f"received page over mTLS ({len(raw)} bytes, sha256 {actual[:12]}, "
           f"version {version})"]

    # Pre-flight: never create a webroot. A missing one means this is not a web
    # node, or the vhost lives somewhere else — both need a human, not a mkdir.
    if not os.path.isdir(d):
        return {"ok": False, "skipped": True, "reason": "no-webroot", "path": path,
                "error": f"{d} does not exist — not a web node, or a different webroot",
                "output": "\n".join(log)}

    # A symlink here is never something we should work through: the backup step
    # would copy whatever it resolves to into the web-served directory, which is
    # how an odd vhost layout turns into an information leak. Report it instead.
    if os.path.islink(path):
        return {"ok": False, "skipped": True, "reason": "symlink", "path": path,
                "error": f"{path} is a symlink to "
                         f"{os.path.realpath(path)} — refusing to touch it; "
                         f"fix the vhost layout first",
                "output": "\n".join(log)}

    before = _landing_file_info(path) if os.path.exists(path) else None
    if before is None and not params.get("create_missing"):
        return {"ok": False, "skipped": True, "reason": "no-index", "path": path,
                "error": f"{path} does not exist — unprovisioned node; re-run with "
                         f"'create missing pages' to place it",
                "output": "\n".join(log)}

    # Compare the whole file, not just the version marker. The marker is derived
    # from the node list alone, so an edit to the surrounding page (the legal
    # T&C, say) leaves it unchanged — keying the skip on it would silently drop
    # exactly the kind of change that most needs to reach the fleet.
    if before and before.get("sha256") == actual and not params.get("force"):
        log.append("already serving this exact file; nothing to do")
        return {"ok": True, "skipped": True, "reason": "already-current", "path": path,
                "version": version, "sha256": actual, "verified": True,
                "output": "\n".join(log)}

    backup = None
    if before:
        backup = path + ".bak-" + (before.get("version") or "unversioned")
        if os.path.islink(backup):
            return {"ok": False, "skipped": True, "reason": "symlink", "path": path,
                    "error": f"{backup} is a symlink — refusing to write through it",
                    "output": "\n".join(log)}
        try:
            _landing_copy_nofollow(path, backup)
            log.append("backed up current page -> " + os.path.basename(backup))
        except Exception as e:
            return {"ok": False, "error": f"backup failed, refusing to overwrite: {e}",
                    "path": path, "output": "\n".join(log)}

    try:
        _landing_write(path, content)
    except Exception as e:
        return {"ok": False, "error": f"write failed: {e}", "path": path,
                "backup": backup, "output": "\n".join(log)}

    after = _landing_file_info(path) or {}
    verified = after.get("sha256") == actual and after.get("version") == version
    log.append(("wrote " if before else "created ") + path +
               (" · verified on disk" if verified else " · VERIFICATION FAILED"))
    return {
        "ok": verified,
        "path": path,
        "version": version,
        "sha256": actual,
        "backup": backup,
        "verified": verified,
        "created": before is None,
        "previous_version": (before or {}).get("version"),
        "output": "\n".join(log),
        "error": None if verified else "page written but post-write verification failed",
    }


def act_landing_revert(params):
    """Put a previously installed page back. Newest backup unless a version is
    named. The page being replaced is itself backed up first, so a revert can be
    undone."""
    d, path, err = _landing_path(params)
    if err:
        return {"ok": False, "error": err}
    if not os.path.isdir(d):
        return {"ok": False, "skipped": True, "reason": "no-webroot", "path": path,
                "error": f"{d} does not exist"}

    if os.path.islink(path):
        return {"ok": False, "skipped": True, "reason": "symlink", "path": path,
                "error": f"{path} is a symlink — refusing to touch it"}

    backups = _landing_backups(d)
    if not backups:
        return {"ok": False, "skipped": True, "reason": "no-backup", "path": path,
                "error": "no index.html.bak-<version> to revert to"}
    want = (params.get("version") or "").strip().lower()
    pick = next((b for b in backups if b["version"] == want), None) if want else backups[0]
    if pick is None:
        return {"ok": False, "error": f"no backup for version {want}", "path": path,
                "backups": backups}

    src = os.path.join(d, pick["name"])
    # A backup that is a symlink is not a backup we wrote. Following it would
    # publish whatever it points at to the public page, so refuse outright.
    if os.path.islink(src):
        return {"ok": False, "skipped": True, "reason": "symlink", "path": path,
                "error": f"{pick['name']} is a symlink, not a page we wrote — "
                         f"refusing to publish what it points at"}
    try:
        with open(src, "r", encoding="utf-8") as f:
            text = f.read(LANDING_MAX_BYTES + 1)
    except Exception as e:
        return {"ok": False, "error": f"cannot read {pick['name']}: {e}", "path": path}
    if len(text.encode()) > LANDING_MAX_BYTES:
        return {"ok": False, "error": f"{pick['name']} is too large to restore", "path": path}
    # "unversioned" is the page that predates maestro and legitimately has no
    # marker; anything claiming a version must actually carry it.
    found = _LANDING_VERSION_RE.search(text)
    if pick["version"] == "unversioned":
        if found:
            return {"ok": False, "path": path,
                    "error": f"{pick['name']} claims to predate maestro but carries a "
                             f"version marker — refusing to restore it"}
    elif not found or found.group(1) != pick["version"]:
        return {"ok": False, "path": path,
                "error": f"{pick['name']} does not carry version {pick['version']} — "
                         f"refusing to restore it"}

    log = [f"reverting to {pick['name']}"]
    current = _landing_file_info(path) if os.path.exists(path) else None
    if current:
        keep = path + ".bak-" + (current.get("version") or "unversioned")
        with contextlib.suppress(Exception):
            if os.path.abspath(keep) != os.path.abspath(src) and not os.path.islink(keep):
                _landing_copy_nofollow(path, keep)
                log.append("kept the replaced page -> " + os.path.basename(keep))

    try:
        _landing_write(path, text)
    except Exception as e:
        return {"ok": False, "error": f"write failed: {e}", "path": path,
                "output": "\n".join(log)}

    after = _landing_file_info(path) or {}
    # The pre-maestro page has no marker, so "restored correctly" means None
    # there — comparing against the literal "unversioned" would report every
    # rollback to the original page as a failure.
    want_marker = None if pick["version"] == "unversioned" else pick["version"]
    ok = after.get("version") == want_marker
    log.append("restored " + path + (" · verified on disk" if ok else " · VERIFICATION FAILED"))
    return {"ok": ok, "path": path, "version": after.get("version"),
            "restored": pick["version"], "sha256": after.get("sha256"),
            "reverted_from": (current or {}).get("version"),
            "verified": ok, "output": "\n".join(log),
            "error": None if ok else "restored page does not carry the expected version"}


# --- distro / OS upgrade ----------------------------------------------------
# The upgrade itself never runs inside the agent process: apt can restart
# services (including this agent) mid-flight, and a release upgrade ends in a
# reboot. The agent only writes a generated stdlib runner script and launches
# it as a detached transient systemd unit; both sides meet at a JSON state
# file + log that `distro_upgrade_status` reports back to the orchestrator.

DISTRO_STATE = os.path.join(CERTDIR, "distro-upgrade.state.json")
DISTRO_LOG = os.path.join(CERTDIR, "distro-upgrade.log")
DISTRO_RUNNER = os.path.join(CERTDIR, "distro-upgrade-runner.py")
DISTRO_UNIT = "maestro-distro-upgrade"


def parse_os_release(text):
    """Parse /etc/os-release into a dict (values unquoted)."""
    out = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        out[k.strip()] = v
    return out


def parse_meminfo_total(text):
    """MemTotal from /proc/meminfo, in bytes (or None)."""
    m = re.search(r"^MemTotal:\s+(\d+)\s*kB", text or "", re.M)
    return int(m.group(1)) * 1024 if m else None


def parse_cpu_info(text):
    """{model, cores} from /proc/cpuinfo (x86 + arm shapes)."""
    cores = len(re.findall(r"^processor\s*:", text or "", re.M))
    m = re.search(r"^model name\s*:\s*(.+)$", text or "", re.M)
    if not m:  # arm: no "model name" per core, but a "Model" line at the end
        m = re.search(r"^Model\s*:\s*(.+)$", text or "", re.M)
    return {"model": m.group(1).strip() if m else None, "cores": cores or None}


def parse_apt_counts(text):
    """(upgraded, newly_installed, security) from `apt-get -s full-upgrade`.

    `security` counts the Inst lines pulling from a -security pocket — the
    packages whose pending update is a security fix, not just a version bump.
    """
    m = re.search(r"(\d+) upgraded, (\d+) newly installed", text or "")
    if not m:
        return None, None, None
    security = len(re.findall(r"^Inst\s.*-security", text or "", re.M))
    return int(m.group(1)), int(m.group(2)), security


def _read_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return None


def _tail_text(path, nbytes=1600):
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - nbytes))
            return f.read().decode("utf-8", "replace")
    except Exception:
        return None


def act_os_info(params):
    """Inventory for the upgrade planner: distro, kernel, hardware, pending
    updates. Read-only apart from an optional `apt-get update` to refresh the
    package lists so the pending counts are current."""
    osr = parse_os_release(_read_text("/etc/os-release") or "")
    un = os.uname()
    rc, virt, _ = _run(["systemd-detect-virt"], timeout=5)
    pending = {"upgraded": None, "new": None, "security": None, "error": None}
    if params.get("check_updates", True):
        if params.get("refresh_lists"):
            _run(["apt-get", "-q", "update"], timeout=180, merge=True)
        rc1, out1, err1 = _run(["apt-get", "-s", "-o", "Debug::NoLocking=true",
                                "full-upgrade"], timeout=120)
        up, new, sec = parse_apt_counts(out1)
        if rc1 == 0 and up is not None:
            pending = {"upgraded": up, "new": new, "security": sec, "error": None}
        else:
            pending["error"] = (err1 or out1 or "apt-get simulate failed").strip()[-400:]
    return {
        "ok": True, "kind": "osinfo",
        "os": {"id": (osr.get("ID") or "").lower() or None,
               "version_id": osr.get("VERSION_ID"),
               "codename": (osr.get("VERSION_CODENAME") or "").lower() or None,
               "pretty": osr.get("PRETTY_NAME")},
        "kernel": un.release, "arch": un.machine,
        "cpu": parse_cpu_info(_read_text("/proc/cpuinfo") or ""),
        "mem_total": parse_meminfo_total(_read_text("/proc/meminfo") or ""),
        "disk": read_disk(),
        "virt": (virt or "").strip() if rc == 0 else None,
        "python": ".".join(str(v) for v in sys.version_info[:3]),
        "pending": pending,
        "reboot_required": os.path.exists("/var/run/reboot-required"),
        "do_release_upgrade": bool(shutil.which("do-release-upgrade")),
        "upgrade_state": _distro_state_summary(),
    }


# The runner is deliberately self-contained (stdlib, no imports from the
# agent): once systemd-run detaches it, the agent may be restarted by apt or
# the whole box rebooted under it. @PARAMS@ is base64-JSON so no quoting or
# escape sequence in a param can break the generated source.
DISTRO_RUNNER_TEMPLATE = r'''#!/usr/bin/env python3
"""Generated by nym-maestro-agent: headless distro upgrade, one shot.
Progress protocol: JSON state file (atomic replace) + append-only log."""
import base64, json, os, re, shutil, subprocess, sys, time, traceback

PARAMS = json.loads(base64.b64decode("@PARAMS@").decode("utf-8"))
STATE, LOG = PARAMS["state_file"], PARAMS["log_file"]

_state = {"version": 1, "mode": PARAMS["mode"], "reboot": PARAMS["reboot"],
          "started_at": int(time.time()), "phase": "starting", "pct": 0,
          "pkg_total": None, "pkg_done": 0, "eta_epoch": None, "error": None,
          "needs_reboot": False, "finished_at": None, "note": None,
          "from_version": PARAMS.get("from_version"),
          "target": PARAMS.get("target"), "phases": []}


def save(**kw):
    _state.update(kw)
    pct = _state.get("pct") or 0
    # Overall ETA: linear projection over the whole job from the fraction
    # done so far; refines as phases complete. Reboot adds a fixed buffer.
    if 3 <= pct < 100 and _state["phase"] not in ("done", "failed"):
        elapsed = int(time.time()) - _state["started_at"]
        eta = _state["started_at"] + int(elapsed * 100.0 / pct)
        if _state["reboot"] != "never":
            eta += 120
        _state["eta_epoch"] = eta
    tmp = STATE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(_state, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, STATE)


def log(msg):
    with open(LOG, "a") as f:
        f.write(time.strftime("[%H:%M:%S] ") + msg.rstrip() + "\n")


def phase(name, pct):
    _state["phases"].append({"phase": name, "ts": int(time.time())})
    save(phase=name, pct=pct)
    log("== phase: " + name)


def fail(msg):
    log("FAILED: " + msg)
    save(phase="failed", error=msg[:500], finished_at=int(time.time()))
    sys.exit(1)


APT_ENV = dict(os.environ, DEBIAN_FRONTEND="noninteractive",
               NEEDRESTART_MODE="a", UCF_FORCE_CONFFOLD="1")
APT_OPTS = ["-y", "-o", "Dpkg::Options::=--force-confdef",
            "-o", "Dpkg::Options::=--force-confold"]
# every package produces roughly one Get:, one Unpacking and one Setting up
MARK = re.compile(r"^(Unpacking |Setting up |Preparing to unpack |Get:)")


def run_stream(cmd, base_pct, span_pct, markers_total):
    """Run cmd with stdout going STRAIGHT to the log file (no pipe: if this
    runner is killed, the child must never block on a full pipe with no
    reader). Progress comes from tailing the log for marker lines."""
    log("$ " + " ".join(cmd))
    with open(LOG, "ab") as lf:
        p = subprocess.Popen(cmd, stdout=lf, stderr=subprocess.STDOUT, env=APT_ENV)
    seen, last, pos = 0, 0.0, os.path.getsize(LOG)
    while True:
        rc = p.poll()
        try:
            with open(LOG, "rb") as rf:
                rf.seek(pos)
                chunk = rf.read()
            pos += len(chunk)
            for line in chunk.decode("utf-8", "replace").splitlines():
                if MARK.match(line):
                    seen += 1
        except Exception:
            pass
        if time.time() - last > 2:
            frac = min(seen / float(max(markers_total, 1)), 1.0)
            save(pct=round(base_pct + span_pct * frac, 1), pkg_done=seen)
            last = time.time()
        if rc is not None:
            break
        time.sleep(2)
    save(pkg_done=seen)
    return rc, seen


def run_quiet(cmd):
    log("$ " + " ".join(cmd))
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True, errors="replace", env=APT_ENV)
    with open(LOG, "a") as f:
        f.write(p.stdout)
    return p.returncode, p.stdout


def os_release_field(key):
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith(key + "="):
                    return line.split("=", 1)[1].strip().strip('"')
    except Exception:
        pass
    return None


def ensure_essentials():
    """Reinstall lockout-critical packages a release upgrade may have dropped
    (Ubuntu's sudo -> sudo-rs transition has eaten sudo in the wild)."""
    missing = []
    if not shutil.which("sudo"):
        missing.append("sudo")
    if not (os.path.exists("/usr/sbin/sshd") or shutil.which("sshd")):
        missing.append("openssh-server")
    for pkg in missing:
        log("essential package %s missing after upgrade — reinstalling" % pkg)
        rc, _ = run_quiet(["apt-get"] + APT_OPTS + ["install", pkg])
        if rc != 0:
            _state["note"] = ((_state.get("note") or "") +
                              " could not reinstall %s — do it manually." % pkg).strip()
            save()


def finish(force_reboot=False):
    needs = force_reboot or os.path.exists("/var/run/reboot-required")
    save(needs_reboot=needs)
    pol = PARAMS["reboot"]
    if pol == "always" or (pol == "auto" and needs):
        phase("rebooting", 96)
        log("rebooting now")
        time.sleep(3)  # let a status poll in flight read the state first
        subprocess.run(["systemctl", "reboot"])
        time.sleep(120)  # shutdown kills this unit
        fail("reboot was requested but the node did not go down")
    save(phase="done", pct=100, finished_at=int(time.time()), eta_epoch=None)
    log("done" + (" (reboot still required — policy is 'never')" if needs else ""))


def main_packages():
    phase("update", 2)
    # no-op when dpkg is clean; finishes half-configured packages left by an
    # interrupted earlier run, which apt would otherwise refuse to touch
    run_quiet(["dpkg", "--configure", "-a"])
    rc, _ = run_quiet(["apt-get", "-q", "update"])
    if rc != 0:
        fail("apt-get update failed (exit %d) — see log" % rc)
    phase("simulate", 5)
    rc, out = run_quiet(["apt-get", "-s"] + APT_OPTS + ["full-upgrade"])
    if rc != 0:
        fail("apt-get simulate failed (exit %d)" % rc)
    m = re.search(r"(\d+) upgraded, (\d+) newly installed", out)
    total = (int(m.group(1)) + int(m.group(2))) if m else 0
    save(pkg_total=total)
    if total:
        phase("install", 8)
        rc, _ = run_stream(["apt-get"] + APT_OPTS + ["full-upgrade"],
                           8, 82, markers_total=total * 3)
        if rc != 0:
            fail("apt-get full-upgrade failed (exit %d) — see log" % rc)
    else:
        log("nothing to upgrade")
    phase("autoremove", 92)
    run_quiet(["apt-get"] + APT_OPTS + ["autoremove", "--purge"])
    finish()


def main_release_ubuntu():
    phase("prepare", 2)
    rc, _ = run_quiet(["apt-get", "-q", "update"])
    if rc != 0:
        fail("apt-get update failed (exit %d)" % rc)
    rc, _ = run_stream(["apt-get"] + APT_OPTS + ["full-upgrade"], 3, 7, 300)
    if rc != 0:
        fail("pre-upgrade full-upgrade failed (exit %d) — see log" % rc)
    phase("release_upgrade", 10)
    # marker total is a heuristic (~full package set); pct is coarse here but
    # monotonic, and the overall ETA projection still tracks reality.
    rc, _ = run_stream(["do-release-upgrade", "-f", "DistUpgradeViewNonInteractive"],
                       10, 80, markers_total=PARAMS.get("assume_markers") or 4500)
    if rc != 0:
        fail("do-release-upgrade failed (exit %d) — see log" % rc)
    now_ver = os_release_field("VERSION_ID")
    if now_ver == PARAMS.get("from_version"):
        fail("release unchanged after do-release-upgrade (still %s) — "
             "likely 'no new release found'; see log" % now_ver)
    ensure_essentials()
    finish(force_reboot=True)


def main_release_debian():
    cur, tgt = PARAMS["from_codename"], PARAMS["target_codename"]
    if not cur or not tgt or cur == tgt:
        fail("bad codenames for debian release upgrade: %r -> %r" % (cur, tgt))
    phase("prepare", 2)
    rc, _ = run_quiet(["apt-get", "-q", "update"])
    if rc != 0:
        fail("apt-get update failed (exit %d)" % rc)
    rc, _ = run_stream(["apt-get"] + APT_OPTS + ["full-upgrade"], 3, 5, 300)
    if rc != 0:
        fail("pre-upgrade full-upgrade failed (exit %d)" % rc)
    phase("sources", 8)
    pat = re.compile(r"\b" + re.escape(cur) + r"\b")
    roots = ["/etc/apt/sources.list"]
    for d in ("/etc/apt/sources.list.d",):
        if os.path.isdir(d):
            roots += [os.path.join(d, x) for x in sorted(os.listdir(d))
                      if x.endswith((".list", ".sources"))]
    changed = 0
    for path in roots:
        try:
            with open(path) as f:
                text = f.read()
        except Exception:
            continue
        if not pat.search(text):
            continue
        with open(path + ".maestro-dist-bak", "w") as f:
            f.write(text)
        with open(path, "w") as f:
            f.write(pat.sub(tgt, text))
        changed += 1
        log("rewrote %s (%s -> %s)" % (path, cur, tgt))
    if changed == 0:
        fail("no apt source mentions %r — refusing to guess" % cur)
    phase("update", 10)
    rc, _ = run_quiet(["apt-get", "-q", "update"])
    if rc != 0:
        fail("apt-get update failed after sources rewrite (exit %d) — "
             "originals kept as *.maestro-dist-bak" % rc)
    phase("upgrade_minimal", 12)
    rc, _ = run_stream(["apt-get"] + APT_OPTS + ["upgrade", "--without-new-pkgs"],
                       12, 33, markers_total=PARAMS.get("assume_markers") or 2500)
    if rc != 0:
        fail("minimal upgrade failed (exit %d) — see log" % rc)
    phase("full_upgrade", 45)
    rc, _ = run_stream(["apt-get"] + APT_OPTS + ["full-upgrade"],
                       45, 45, markers_total=PARAMS.get("assume_markers") or 2500)
    if rc != 0:
        fail("full-upgrade failed (exit %d) — see log" % rc)
    if os_release_field("VERSION_CODENAME") == cur:
        fail("codename unchanged after full-upgrade — see log")
    ensure_essentials()
    finish(force_reboot=True)


def main():
    open(LOG, "a").close()
    save()
    mode, distro = PARAMS["mode"], PARAMS.get("distro")
    if mode == "packages":
        main_packages()
    elif distro == "ubuntu":
        main_release_ubuntu()
    elif distro == "debian":
        main_release_debian()
    else:
        fail("unsupported: mode=%r distro=%r" % (mode, distro))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        err = traceback.format_exc()
        try:
            log(err)
        except Exception:
            pass
        fail(err.strip().splitlines()[-1])
'''


def render_distro_runner(run_params):
    """Runner source with the params baked in as base64 JSON."""
    blob = base64.b64encode(json.dumps(run_params).encode("utf-8")).decode("ascii")
    return DISTRO_RUNNER_TEMPLATE.replace("@PARAMS@", blob)


def _distro_read_state():
    try:
        with open(DISTRO_STATE) as f:
            return json.load(f)
    except Exception:
        return None


def _distro_write_state(st):
    tmp = DISTRO_STATE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, DISTRO_STATE)


def _distro_unit_active():
    rc, out, _ = _run(["systemctl", "is-active", DISTRO_UNIT], timeout=5)
    return (out or "").strip() in ("active", "activating")


def _distro_state_fresh(max_age=120):
    """Is the runner still writing the state file? run_stream saves at least
    every ~2s, so a recent mtime is proof of life that does not depend on
    systemd — `systemctl is-active` can transiently FAIL mid-release-upgrade
    while dbus/systemd themselves are being upgraded (false 'unit dead',
    seen in the field on BE01)."""
    try:
        return time.time() - os.path.getmtime(DISTRO_STATE) < max_age
    except Exception:
        return False


def _apt_locked():
    """True if dpkg/apt is locked — some package operation is running right
    now. Non-destructive probe: flock in non-blocking mode, never truncating
    (hence "ab"), released immediately."""
    import fcntl
    for path in ("/var/lib/dpkg/lock-frontend", "/var/lib/apt/lists/lock"):
        try:
            f = open(path, "ab")
        except Exception:
            continue
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(f, fcntl.LOCK_UN)
        except OSError:
            f.close()
            return True
        f.close()
    return False


def _verify_green(checks):
    """Gate on the critical checks only; informational ones (gate: False,
    e.g. "sudo installed") are reported but never hold "done" hostage."""
    return all(c["ok"] for c in checks if c.get("gate", True))


def _distro_state_summary():
    st, phase, _ = _distro_reconcile()
    if not st:
        return None
    out = {k: st.get(k) for k in ("mode", "pct", "started_at",
                                  "finished_at", "error", "needs_reboot", "note")}
    out["phase"] = phase
    return out


def act_distro_upgrade(params):
    """Kick off a headless OS upgrade as a detached transient systemd unit.

    mode "packages": apt full-upgrade within the current release.
    mode "release":  do-release-upgrade (Ubuntu) / sources rewrite (Debian).
    reboot policy: "auto" (only if the upgrade asks for it — a release
    upgrade always does), "always", "never".
    Returns immediately; progress is polled via distro_upgrade_status.
    """
    mode = params.get("mode") or "packages"
    if mode not in ("packages", "release"):
        return {"ok": False, "error": f"unknown mode {mode!r} (packages|release)"}
    reboot = params.get("reboot") or "auto"
    if reboot not in ("auto", "always", "never"):
        return {"ok": False, "error": f"unknown reboot policy {reboot!r} (auto|always|never)"}
    if _distro_unit_active():
        return {"ok": False, "error": "a distro upgrade is already running on this node"}
    st = _distro_read_state()
    if st and st.get("phase") not in (None, "done", "failed") and not st.get("finished_at"):
        # unit not active but state says mid-flight: stale unless we just rebooted
        btime = _proc_btime()
        if not (btime and st.get("started_at") and btime > st["started_at"]):
            if time.time() - st.get("started_at", 0) < 300:
                return {"ok": False, "error": "an upgrade appears to be in flight "
                                              "(state file is fresh); check status first"}

    osr = parse_os_release(_read_text("/etc/os-release") or "")
    distro = (osr.get("ID") or "").lower()
    if distro not in ("ubuntu", "debian"):
        return {"ok": False, "error": f"unsupported distro {distro!r} (ubuntu|debian)"}
    if mode == "release":
        if distro == "ubuntu" and not shutil.which("do-release-upgrade"):
            return {"ok": False, "error": "do-release-upgrade not found — "
                                          "install update-manager-core first"}
        if distro == "debian" and not params.get("target_codename"):
            return {"ok": False, "error": "target_codename is required for a debian release upgrade"}

    run_params = {
        "mode": mode, "reboot": reboot, "distro": distro,
        "state_file": DISTRO_STATE, "log_file": DISTRO_LOG,
        "from_version": osr.get("VERSION_ID"),
        "from_codename": (osr.get("VERSION_CODENAME") or "").lower() or None,
        "target": params.get("target"),
        "target_codename": params.get("target_codename"),
    }
    try:
        os.makedirs(CERTDIR, exist_ok=True)
        with open(DISTRO_RUNNER, "w") as f:
            f.write(render_distro_runner(run_params))
        os.chmod(DISTRO_RUNNER, 0o700)
        # seed state + fresh log so a status poll right after start is coherent
        _distro_write_state({"version": 1, "mode": mode, "reboot": reboot,
                             "started_at": int(time.time()), "phase": "starting",
                             "pct": 0, "pkg_total": None, "pkg_done": 0,
                             "eta_epoch": None, "error": None, "needs_reboot": False,
                             "finished_at": None, "target": params.get("target"),
                             "note": None, "from_version": osr.get("VERSION_ID"),
                             "phases": []})
        with open(DISTRO_LOG, "w") as f:
            f.write(time.strftime("[%H:%M:%S] ") + f"upgrade queued (mode={mode}, "
                    f"reboot={reboot}, distro={distro})\n")
    except Exception as e:
        return {"ok": False, "error": f"could not stage the upgrade runner: {e}"}

    # needrestart runs in auto mode during the apt phases (NEEDRESTART_MODE=a)
    # and will happily "restart" the transient upgrade unit itself when python
    # libs get upgraded — which kills the runner and orphans the running
    # apt/do-release-upgrade child. Pin both maestro units out of its reach.
    with contextlib.suppress(Exception):
        if os.path.isdir("/etc/needrestart/conf.d"):
            with open("/etc/needrestart/conf.d/zz-nym-maestro.conf", "w") as f:
                f.write("# written by nym-maestro-agent: never auto-restart the\n"
                        "# distro-upgrade runner (or the agent) mid-upgrade\n"
                        "$nrconf{override_rc}{qr(^maestro-distro-upgrade)} = 0;\n"
                        "$nrconf{override_rc}{qr(^nym-maestro-agent)} = 0;\n")

    _run(["systemctl", "reset-failed", DISTRO_UNIT], timeout=5)  # clear a dead prior run
    py = sys.executable or "/usr/bin/python3"
    rc, out, err = _run(["systemd-run", "--unit", DISTRO_UNIT, "--collect",
                         "--description", "nym-maestro distro upgrade",
                         "--property", "KillMode=process",
                         py, DISTRO_RUNNER], timeout=15)
    if rc != 0:
        return {"ok": False, "error": "systemd-run failed: "
                                      + ((err or out or "").strip() or f"exit {rc}")}
    return {"ok": True, "kind": "distro", "started": True, "mode": mode,
            "reboot": reboot, "distro": distro, "unit": DISTRO_UNIT}


def _post_upgrade_checks():
    """Did everything come back after the upgrade/reboot? Cheap, honest checks;
    the orchestrator keeps polling while the gating ones are still red.
    gate: False entries are reported but never block "done" (a healthy gateway
    without sudo is a nuisance, not an outage — seen with the Ubuntu sudo-rs
    transition eating sudo mid-upgrade)."""
    checks = []
    active, svc = service_state()
    checks.append({"check": f"{svc} active", "ok": bool(active)})
    devtxt = _read_text("/proc/net/dev") or ""
    for d in EXIT_DEVICES:
        checks.append({"check": f"iface {d} up", "ok": (d + ":") in devtxt})
    if unit_exists("fail2ban.service"):
        rc, out, _ = _run(["systemctl", "is-active", "fail2ban"], timeout=5)
        checks.append({"check": "fail2ban active", "ok": (out or "").strip() == "active"})
    checks.append({"check": "sudo installed", "ok": bool(shutil.which("sudo")),
                   "gate": False})
    return checks


def _distro_reconcile():
    """Read the upgrade state and resolve it against reality — boot time,
    unit, state-file freshness, apt lock, os-release. Returns (st, phase,
    verify); st is None when no upgrade ever ran. May persist a terminal
    phase as a side effect. Shared by distro_upgrade_status AND the os_info
    summary, so a stale mid-flight state self-heals on the next scan instead
    of blocking future upgrades forever."""
    st = _distro_read_state()
    if not st:
        return None, "idle", None
    phase = st.get("phase")
    btime = _proc_btime()
    rebooted = bool(btime and st.get("started_at") and btime > st["started_at"])
    verify = st.get("verify")
    osr = parse_os_release(_read_text("/etc/os-release") or "")
    if phase == "rebooting" and rebooted:
        checks = _post_upgrade_checks()
        verify = checks
        if _verify_green(checks):
            st.update(phase="done", pct=100, finished_at=int(time.time()),
                      eta_epoch=None, verify=checks)
            with contextlib.suppress(Exception):
                _distro_write_state(st)
            phase = "done"
        else:
            phase = "verifying"  # transient: caller polls until green
    elif phase not in (None, "idle", "done", "failed", "rebooting") and not _distro_unit_active():
        # Mid-flight state but no unit. The runner can die without a terminal
        # write (OOM kill, or needrestart "restarting" the transient unit)
        # while its apt/do-release-upgrade CHILD keeps running (KillMode=
        # process spares it — seen in the field). Decide by evidence, not by
        # the unit alone. Grace period covers the systemd-run start lag.
        if time.time() - st.get("started_at", 0) > 60:
            cur_ver, from_ver = osr.get("VERSION_ID"), st.get("from_version")
            if _distro_state_fresh():
                # the runner is still writing — the unit query lied (systemd/
                # dbus mid-upgrade). Report the state as-is, change nothing.
                pass
            elif _apt_locked():
                # the package system is still locked: the upgrade child is
                # alive and working — report progress, do NOT fail
                phase = "detached"
                st["note"] = ("runner unit died but the upgrade is still running "
                              "(package system locked) — waiting for it to finish")
            elif st.get("mode") == "release" and from_ver and cur_ver and cur_ver != from_ver:
                # the release landed without us: verify like after a reboot
                checks = _post_upgrade_checks()
                verify = checks
                st["note"] = (f"runner was killed mid-run but the release upgrade "
                              f"completed ({from_ver} -> {cur_ver})"
                              + ("" if rebooted else " — node has NOT rebooted yet"))
                if _verify_green(checks):
                    st.update(phase="done", pct=100, finished_at=int(time.time()),
                              eta_epoch=None, verify=checks,
                              needs_reboot=bool(st.get("needs_reboot")) or not rebooted)
                    with contextlib.suppress(Exception):
                        _distro_write_state(st)
                    phase = "done"
                else:
                    phase = "verifying"
            else:
                st.update(phase="failed",
                          error=st.get("error") or
                          "upgrade unit is not running and the upgrade did not "
                          "complete — check the log; `dpkg --configure -a` may be needed")
                with contextlib.suppress(Exception):
                    _distro_write_state(st)
                phase = "failed"

    return st, phase, verify


def act_distro_status(params):
    """Progress of the current/last upgrade. After the post-upgrade reboot this
    is also where verification happens: the state file still says "rebooting",
    so once /proc/stat shows a newer boot we run the service checks and flip
    the state to done (or keep reporting "verifying" until they pass)."""
    st, phase, verify = _distro_reconcile()
    if st is None:
        return {"ok": True, "kind": "distro", "phase": "idle"}
    osr = parse_os_release(_read_text("/etc/os-release") or "")
    out = {k: st.get(k) for k in ("mode", "reboot", "started_at", "pct",
                                  "pkg_total", "pkg_done", "eta_epoch", "error",
                                  "needs_reboot", "finished_at", "target",
                                  "note", "from_version")}
    out.update({"ok": True, "kind": "distro", "phase": phase, "verify": verify,
                "os_version": osr.get("VERSION_ID"),
                "log_tail": _tail_text(DISTRO_LOG)})
    return out


EXEC_ACTIONS = {
    "os_info": act_os_info,
    "distro_upgrade": act_distro_upgrade,
    "distro_upgrade_status": act_distro_status,
    "restart": act_restart,
    "toggle": act_toggle,
    "service_file": act_service_file,
    "get_execstart": act_get_execstart,
    "update_agent": act_update_agent,
    "upgrade": act_upgrade,
    "backup": act_backup,
    "backup_cleanup": act_backup_cleanup,
    "fail2ban_status": act_fail2ban_status,
    "fail2ban_setup": act_fail2ban_setup,
    "fail2ban_unban": act_fail2ban_unban,
    "ssh_add_key": act_ssh_add_key,
    "ssh_status": act_ssh_status,
    "ssh_harden": act_ssh_harden,
    "extra_blocks_status": act_extra_blocks_status,
    "extra_blocks_install": act_extra_blocks_install,
    "extra_blocks_install_script": act_extra_blocks_install_script,
    "extra_blocks_restart_service": act_extra_blocks_restart_service,
    "extra_blocks_upgrade": act_extra_blocks_upgrade,
    "extra_blocks_verify": act_extra_blocks_verify,
    "extra_blocks_remove": act_extra_blocks_remove,
    "concurrency_status": act_concurrency_status,
    "concurrency_install": act_concurrency_install,
    "concurrency_set_limit": act_concurrency_set_limit,
    "concurrency_restart": act_concurrency_restart,
    "concurrency_verify": act_concurrency_verify,
    "concurrency_remove": act_concurrency_remove,
    "landing_status": act_landing_status,
    "landing_deploy": act_landing_deploy,
    "landing_revert": act_landing_revert,
    "peers": act_peers,
}


class Handler(BaseHTTPRequestHandler):
    server_version = "nym-maestro-agent/" + AGENT_VERSION
    timeout = 30   # bound a stalled client mid-request (applied after handshake)

    def setup(self):
        # The listening socket is plain TCP; do the TLS handshake HERE, in the
        # per-request worker thread (bounded by the socket timeout) so a stalled
        # or garbage client can never block the main accept loop for everyone.
        raw = self.request
        raw.settimeout(HANDSHAKE_TIMEOUT)
        # wrap_socket performs the handshake here in the worker thread, bounded by
        # the socket timeout above — a stalled client only ties up its own thread
        self.request = self.server.ssl_context.wrap_socket(raw, server_side=True)
        # CERT_REQUIRED already guarantees the peer cert is signed by our CA. Since
        # every node's server cert is signed by that same CA, we must also confirm
        # the peer is specifically the orchestrator (by CN), not another node.
        peer = self.request.getpeercert()
        cn = None
        if peer:
            for rdn in peer.get("subject", ()):
                for k, v in rdn:
                    if k == "commonName":
                        cn = v
        if cn != ORCH_CN:
            # Refuse to serve anything to a non-orchestrator client, even though it
            # presented a CA-signed cert. Close before any request is dispatched.
            try:
                self.request.close()
            except Exception:
                pass
            raise ssl.SSLError(f"client CN {cn!r} is not the orchestrator ({ORCH_CN!r})")
        super().setup()

    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/v1/health":
            self._send(200, {"status": "ok", "agent_version": AGENT_VERSION})
        elif self.path == "/v1/status":
            self._send(200, build_status())
        elif self.path.startswith("/v1/history"):
            self._serve_history()
        elif self.path.startswith("/v1/backup"):
            self._serve_backup()
        else:
            self._send(404, {"error": "not found"})

    def _serve_history(self):
        """GET /v1/history?since=<epoch>&until=<epoch>&kind=tput|traffic

        Returns rolling on-agent history for orchestrator backfill. Bounded to
        HISTORY_MAX_ROWS rows; when truncated the caller re-requests with
        since=<last ts> (cursor pagination). Timestamps are the agent's clock, so
        a late pull still lands data at the correct historical position."""
        try:
            q = urllib.parse.urlparse(self.path).query
            p = urllib.parse.parse_qs(q)
            since = float(p.get("since", ["0"])[0])
            until = float(p.get("until", [str(time.time())])[0])
            kind = (p.get("kind", ["tput"])[0]).strip()
            if kind not in ("tput", "traffic"):
                kind = "tput"
        except Exception:
            self._send(400, {"error": "bad query params"})
            return
        result = history_query(since, until, kind)
        result["kind"] = kind
        result["retention_s"] = HISTORY_RETENTION_S
        result["bucket_s"] = HISTORY_BUCKET_S
        result["server_time"] = time.time()
        self._send(200, result)

    def _serve_backup(self):
        q = urllib.parse.urlparse(self.path).query
        name = urllib.parse.parse_qs(q).get("name", [""])[0]
        if not _safe_backup_name(name):
            self._send(400, {"error": "invalid backup name"})
            return
        fpath = os.path.join(BACKUP_DIR, name)
        if not os.path.isfile(fpath):
            self._send(404, {"error": "not found"})
            return
        try:
            size = os.path.getsize(fpath)
            self.send_response(200)
            self.send_header("Content-Type", "application/gzip")
            self.send_header("Content-Length", str(size))
            self.end_headers()
            with open(fpath, "rb") as f:
                shutil.copyfileobj(f, self.wfile)
        except Exception:
            pass

    def do_POST(self):
        if self.path != "/v1/exec":
            self._send(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            req = json.loads(raw or b"{}")
        except Exception:
            self._send(400, {"error": "invalid JSON"})
            return
        action = req.get("action")
        params = req.get("params") or {}
        fn = EXEC_ACTIONS.get(action)
        if fn is None:
            self._send(400, {"error": f"unknown action: {action}"})
            return
        try:
            self._send(200, fn(params))
        except Exception as e:
            self._send(500, {"error": str(e)})

    def log_message(self, fmt, *args):
        # Quiet: one concise line to stderr, captured by journald.
        print("agent %s - %s" % (self.address_string(), fmt % args))


def make_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(os.path.join(CERTDIR, "server.crt"),
                        os.path.join(CERTDIR, "server.key"))
    ctx.load_verify_locations(os.path.join(CERTDIR, "ca.crt"))
    ctx.verify_mode = ssl.CERT_REQUIRED  # require the orchestrator's client cert
    return ctx


HANDSHAKE_TIMEOUT = 15   # seconds a TLS handshake may take before the worker gives up


class Server(ThreadingHTTPServer):
    daemon_threads = True        # workers never block shutdown / can't pile up forever
    allow_reuse_address = True

    def __init__(self, addr, handler, ctx):
        self.ssl_context = ctx
        super().__init__(addr, handler)

    def get_request(self):
        # accept PLAIN tcp here; the TLS handshake is deferred to the worker thread
        # (Handler.setup) so a stalled handshake can't freeze the accept loop
        sock, addr = self.socket.accept()
        return sock, addr

    def handle_error(self, request, client_address):
        # public VPS TLS ports get scanned constantly; failed handshakes / timeouts
        # are routine and must not spam logs or take anything down
        exc = sys.exc_info()[1]
        if isinstance(exc, (ssl.SSLError, socket.timeout, TimeoutError, ConnectionError, OSError)):
            return
        super().handle_error(request, client_address)


def main():
    start_sampler()
    ctx = make_ssl_context()
    httpd = Server((HOST, PORT), Handler, ctx)
    print(f"nym maestro agent {AGENT_VERSION} listening on {HOST}:{PORT} (mTLS)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
