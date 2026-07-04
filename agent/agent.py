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
import contextlib
import hashlib
import ipaddress
import json
import os
import re
import pwd
import shlex
import shutil
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

AGENT_VERSION = "0.9.8"

try:
    with open(os.path.abspath(__file__), "rb") as _sf:
        AGENT_SHA = hashlib.sha256(_sf.read()).hexdigest()
except Exception:
    AGENT_SHA = None

HOST = os.environ.get("MAESTRO_AGENT_HOST", "0.0.0.0")
PORT = int(os.environ.get("MAESTRO_AGENT_PORT", "8443"))
CERTDIR = os.environ.get("MAESTRO_AGENT_CERTDIR", "/etc/nym-maestro-agent")
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
        "nym_node_since": nym_node_since(svc),
        "uplink_device": UPLINK_DEVICE,
        "boot_since": _proc_btime(),
        "traffic_dir": read_traffic_dir(),
        "throughput_dir": read_throughput_dir(),
    }


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
    rc, out, err = _run(["systemctl", "restart", svc], timeout=40)
    if rc != 0:
        return {"ok": False, "service": svc, "error": (err or out or "restart failed").strip()}
    time.sleep(1)
    active, _ = service_state()
    return {"ok": True, "service": svc, "active": active, "output": f"restarted {svc}"}


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
        rc, _, _ = _run(["systemctl", "restart", svc], timeout=40)
        restarted = rc == 0
        active, _ = service_state()
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

    The binary location is read from the unit's ExecStart, not assumed. The new
    binary is verified with --version before it replaces the old one, which is
    backed up first. NTM runs the pulled script with the given args (not a shell).
    """
    url = (params.get("url") or "").strip()
    if not url:
        return {"ok": False, "error": "no download url provided"}

    svc = resolve_service()
    _, _, cmd = _read_execstart(svc)
    if cmd is None:
        return {"ok": False, "error": "could not read ExecStart to locate the binary"}
    binary = _binary_from_execstart(cmd)
    if not binary or not os.path.isabs(binary):
        return {"ok": False, "error": f"could not determine binary path from ExecStart (got {binary!r})"}

    bindir = os.path.dirname(binary)
    log = [f"target binary (from ExecStart): {binary}"]

    tmp = os.path.join(bindir, ".nym-node.new")
    try:
        log.append(f"downloading {url}")
        _download(url, tmp, timeout=300)
    except Exception as e:
        return {"ok": False, "error": f"download failed: {e}", "output": "\n".join(log)}
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

    backup = None
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

    ntm_result = None
    ntm = params.get("ntm")
    if ntm and ntm.get("url"):
        dest = ntm.get("path")
        ntm_path = dest if (dest and os.path.isabs(dest)) else os.path.join(CERTDIR, "network_tunnel_manager.sh")
        try:
            log.append(f"pulling NTM script {ntm['url']} -> {ntm_path}")
            _download(ntm["url"], ntm_path, timeout=60)
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
        rc3, _, _ = _run(["systemctl", "restart", svc], timeout=40)
        restarted = rc3 == 0
        time.sleep(1)
        active, _ = service_state()
        log.append(f"restart {'ok' if restarted else 'FAILED'}; service active={active}")

    return {"ok": True, "service": svc, "binary": binary, "new_version": new_version,
            "backup": backup, "ntm": ntm_result, "restarted": restarted,
            "active": active, "output": "\n".join(log)}


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

    rc, out, err = _run(["systemctl", "stop", svc], timeout=60)
    if rc != 0:
        return {"ok": False, "error": f"failed to stop {svc}; backup aborted",
                "output": "\n".join(log + [f"stop FAILED: {(err or out).strip()}"])}
    log.append(f"stopped {svc}")

    archive_err, size, sha = None, None, None
    try:
        size, sha = make_archive(data_dir, archive_path)
        log.append(f"archived -> {fname} ({size} bytes)")
    except Exception as e:
        archive_err = str(e)

    rc2, _, _ = _run(["systemctl", "start", svc], timeout=60)
    restarted = rc2 == 0
    time.sleep(1)
    active, _ = service_state()
    log.append(f"restarted {svc}: {'ok' if restarted else 'FAILED'}; active={active}")

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
# Login model: you log in as an unprivileged user (default "hermes") and sudo
# to root. Direct root SSH login is never enabled. Keys are installed into that
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
# A oneshot systemd unit that runs AFTER nym-node (PartOf/WantedBy) and inserts
# REJECT rules for a fetched blocklist into the NYM-EXIT chain. nym-node flushes
# that chain on start, so the blocks must be (re)applied on top each time.

EB_SH = "/usr/local/sbin/nym-extra-blocks.sh"
EB_UNIT_NAME = "nym-extra-blocks.service"
EB_UNIT = "/etc/systemd/system/" + EB_UNIT_NAME
EB_STATE_DIR = "/var/lib/nym-extra-blocks"
EB_CACHE = EB_STATE_DIR + "/blocklist.txt"
EB_URL_FILE = EB_STATE_DIR + "/list_url"
EB_CHAIN = "NYM-EXIT"
EB_CHAIN6 = os.environ.get("MAESTRO_NYM_EXIT6", "NYM-EXIT")  # ip6tables chain (same name by default)
EB_DEFAULT_LIST_URL = ("https://raw.githubusercontent.com/wiiinnie/nym-maestro/"
                       "refs/heads/main/blocklist.txt")

EB_SCRIPT = r"""#!/usr/bin/env bash
# nym-maestro-managed — do not edit by hand; reinstall via maestro instead.
set -euo pipefail

LIST_URL="__LIST_URL__"
CACHE="/var/lib/nym-extra-blocks/blocklist.txt"
CHAIN="NYM-EXIT"
CHAIN6="__CHAIN6__"
IP_RE='^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'
IP6_RE='^[0-9a-fA-F:]*:[0-9a-fA-F:]+(/[0-9]{1,3})?$'

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

# IPv6 is best-effort: only if ip6tables and the v6 exit chain exist on this node.
have6=0
if command -v ip6tables >/dev/null 2>&1 && ip6tables -nL "$CHAIN6" >/dev/null 2>&1; then
    have6=1
else
    echo "$CHAIN6 (v6) not present / ip6tables unavailable; skipping IPv6 blocks" >&2
fi

c4=0; c6=0
while IFS= read -r line; do
    ip="${line%%#*}"; ip="$(echo "$ip" | xargs)"   # strip comments/whitespace
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
"""

EB_UNIT_TPL = """[Unit]
Description=Extra destination blocks for NYM-EXIT (nym maestro managed)
After=__NYM__
PartOf=__NYM__
Wants=network-online.target

[Service]
Type=oneshot
ExecStartPre=/bin/sleep 5
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


def _extra_blocks_state():
    """Lightweight state for the fleet column (no iptables/network calls)."""
    if not _eb_installed():
        return {"installed": False, "enabled": False, "active": False, "state": "missing"}
    active = _eb_is("is-active") == "active"
    enabled = _eb_is("is-enabled") in ("enabled", "enabled-runtime", "static", "alias")
    return {"installed": True, "enabled": enabled, "active": active,
            "state": "active" if active else "inactive"}


def _eb_url():
    txt = _read_file(EB_URL_FILE)
    return txt.strip() if txt and txt.strip() else EB_DEFAULT_LIST_URL


def _eb_fetch_entries(url=None):
    """Valid IPv4/IPv6 (optionally CIDR) entries from the URL or the on-disk cache."""
    url = url or _eb_url()
    text = None
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            text = r.read().decode("utf-8", "replace")
    except Exception:
        text = _read_file(EB_CACHE)
    out = []
    for line in (text or "").splitlines():
        e = line.split("#", 1)[0].strip()
        if not e:
            continue
        try:
            ipaddress.ip_network(e, strict=False)
        except ValueError:
            continue
        out.append(e)
    return out


# kept for callers/tests that expect the old name (now dual-stack)
_eb_fetch_list = _eb_fetch_entries


def _eb_family(entry):
    try:
        return ipaddress.ip_network(entry, strict=False).version
    except ValueError:
        return None


def _eb_chain_rules(cmd, chain):
    """(chain_present, {blocked dests}) for REJECT rules in `chain` (cmd = iptables|ip6tables)."""
    rc, out, _ = _run([cmd, "-S", chain])
    if rc != 0:
        return False, set()
    dests = set()
    for line in out.splitlines():
        m = re.match(r"-A\s+" + re.escape(chain) + r"\s+-d\s+(\S+)\s+.*-j\s+REJECT", line)
        if m:
            d = m.group(1)
            dests.add(d)
            if "/" in d:
                dests.add(d.split("/")[0])
    return True, dests


def _eb_present(entries, dests):
    n = 0
    for e in entries:
        base = e.split("/")[0]
        if e in dests or base in dests or (base + "/32") in dests or (base + "/128") in dests:
            n += 1
    return n


def _eb_v6_supported():
    return shutil.which("ip6tables") is not None


def _eb_verify(url=None):
    """Authoritative check: are the blocklist's REJECT rules present in the exit
    chains? We verify the installed rules (v4 in iptables/NYM-EXIT, v6 in
    ip6tables/NYM-EXIT), not node-originated reachability — those chains govern
    FORWARDed exit traffic, so a probe from the node's own stack wouldn't traverse
    them. IPv6 is best-effort: a v4-only node (no v6 exit chain) is not a failure."""
    entries = _eb_fetch_entries(url)
    v4 = [e for e in entries if _eb_family(e) == 4]
    v6 = [e for e in entries if _eb_family(e) == 6]
    cp4, d4 = _eb_chain_rules("iptables", EB_CHAIN)
    v6_supported = _eb_v6_supported()
    cp6, d6 = _eb_chain_rules("ip6tables", EB_CHAIN6) if v6_supported else (False, set())
    p4, p6 = _eb_present(v4, d4), _eb_present(v6, d6)
    v6_applicable = bool(v6) and v6_supported and cp6

    v4_ok = (not v4) or (cp4 and p4 >= len(v4))
    # v6 counts only when the node actually has a v6 exit chain to apply to
    v6_ok = (not v6) or (not (v6_supported and cp6)) or (p6 >= len(v6))

    sample = (v4 + v6)[0] if (v4 or v6) else None
    sample_blocked = None
    if sample is not None:
        dests = d4 if _eb_family(sample) == 4 else d6
        base = sample.split("/")[0]
        sample_blocked = (sample in dests or base in dests
                          or (base + "/32") in dests or (base + "/128") in dests)
    return {
        "chain_present": cp4,
        "blocklist_size": len(entries),
        "rules_present": p4 + p6,
        "sample_ip": sample,
        "sample_blocked": sample_blocked,
        "all_present": bool(entries) and v4_ok and v6_ok,
        "v4": {"size": len(v4), "present": p4, "chain_present": cp4},
        "v6": {"size": len(v6), "present": p6, "chain_present": cp6,
               "supported": v6_supported, "applicable": v6_applicable},
    }


def act_extra_blocks_status(params):
    st = _extra_blocks_state()
    st["ok"] = True
    st["chain"] = EB_CHAIN
    st["chain6"] = EB_CHAIN6
    st["list_url"] = _eb_url()
    st.update({k: v for k, v in _eb_verify().items() if k != "ok"})
    return st


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


def _eb_write_files(list_url):
    if not _EB_URL_OK(list_url):
        return False, "blocklist URL must be http(s)", {}
    nym = resolve_service()
    backed, handmade = _eb_backup_existing()
    try:
        os.makedirs(EB_STATE_DIR, exist_ok=True)
        os.makedirs(os.path.dirname(EB_SH), exist_ok=True)
        tmp = EB_SH + ".tmp"
        with open(tmp, "w") as f:
            f.write(EB_SCRIPT.replace("__LIST_URL__", list_url).replace("__CHAIN6__", EB_CHAIN6))
        os.chmod(tmp, 0o755)
        os.replace(tmp, EB_SH)
        with open(EB_UNIT, "w") as f:
            f.write(EB_UNIT_TPL.replace("__NYM__", nym))
        _write_file(EB_URL_FILE, list_url + "\n")
    except Exception as e:
        return False, f"could not write files: {e}", {}
    _run(["systemctl", "daemon-reload"], timeout=20)
    _run(["systemctl", "enable", EB_UNIT_NAME], timeout=20)
    return True, None, {"replaced_existing": handmade, "replaced_handmade": handmade,
                        "backups": backed}


def _EB_URL_OK(url):
    return isinstance(url, str) and url.startswith(("http://", "https://")) and len(url) < 2000


def _eb_wait_rules(want, deadline_s=90):
    """Poll until the blocklist rules appear (after a nym-node restart), bounded."""
    end = time.time() + deadline_s
    last = _eb_verify()
    while time.time() < end:
        last = _eb_verify()
        if last["chain_present"] and last["all_present"]:
            return last
        time.sleep(3)
    return last


def act_extra_blocks_install(params):
    list_url = params.get("list_url") or EB_DEFAULT_LIST_URL
    restart_node = bool(params.get("restart_node", False))
    log = []

    before = _eb_verify(list_url)
    ok, err, meta = _eb_write_files(list_url)
    if not ok:
        return {"ok": False, "error": err}
    log.append(f"installed {EB_UNIT_NAME} (enabled), targeting {resolve_service()}")
    if meta.get("replaced_existing"):
        log.append("backed up the pre-existing " +
                   ("hand-made " if meta.get("replaced_handmade") else "") +
                   "script/unit to *.maestro.bak before overwriting")

    if restart_node:
        svc = resolve_service()
        rc, out, errx = _run(["systemctl", "restart", svc], timeout=90)
        if rc != 0:
            return {"ok": False, "error": f"failed to restart {svc}: {(errx or out).strip()}",
                    "before": before, "output": "\n".join(log)}
        log.append(f"restarted {svc}")
        # the oneshot is WantedBy nym-node and fires on its own; poll for the rules,
        # then nudge it once if they haven't landed yet
        after = _eb_wait_rules(want=before["blocklist_size"], deadline_s=75)
        if not after["all_present"]:
            _run(["systemctl", "restart", EB_UNIT_NAME], timeout=90)
            after = _eb_wait_rules(want=before["blocklist_size"], deadline_s=45)
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

    # install only: apply to the LIVE chain now (non-disruptive; no nym-node restart),
    # so the node is protected immediately. Use restart (not start) so the freshly
    # written script actually re-runs even if the oneshot was already active.
    rc, out, errx = _run(["systemctl", "restart", EB_UNIT_NAME], timeout=90)
    log.append("ran extra-blocks once: " + ("ok" if rc == 0 else "FAILED " + (errx or out).strip()))
    after = _eb_verify(list_url)
    applied_now = after["chain_present"] and after["all_present"]
    return {
        "ok": True, "mode": "install-only", "applied_now": applied_now,
        "replaced_existing": meta.get("replaced_existing", False),
        "replaced_handmade": meta.get("replaced_handmade", False),
        "before": before, "after": after, "state": _extra_blocks_state(),
        "output": "\n".join(log),
        "note": ("blocks applied to the running NYM-EXIT chain now; no nym-node restart was done. "
                 "Restart nym-node when convenient, then use 'verify' to confirm they re-apply.")
                if applied_now else
                ("service installed and enabled, but NYM-EXIT was not present to apply to yet "
                 "(is nym-node running?). It will apply automatically on the next nym-node start; "
                 "use 'verify' afterwards."),
        "error": None,
    }


def act_extra_blocks_verify(params):
    """Confirm the blocks are in place — e.g. after a manual nym-node restart."""
    url = params.get("list_url") or _eb_url()
    v = _eb_verify(url)
    v["ok"] = True
    v["state"] = _extra_blocks_state()["state"]
    v["error"] = None if (v["chain_present"] and v["all_present"]) else (
        "NYM-EXIT chain not present (is nym-node running?)" if not v["chain_present"]
        else f"only {v['rules_present']}/{v['blocklist_size']} block rules present in {EB_CHAIN}")
    return v


def act_extra_blocks_remove(params):
    """Disable + remove the unit/script and flush our REJECT rules from the exit chains."""
    log = []
    _run(["systemctl", "disable", "--now", EB_UNIT_NAME], timeout=30)
    removed = 0
    entries = _eb_fetch_entries()
    cp4, d4 = _eb_chain_rules("iptables", EB_CHAIN)
    v6_supported = _eb_v6_supported()
    cp6, d6 = _eb_chain_rules("ip6tables", EB_CHAIN6) if v6_supported else (False, set())
    for e in entries:
        fam, base = _eb_family(e), e.split("/")[0]
        if fam == 4 and cp4 and (e in d4 or base in d4 or (base + "/32") in d4):
            if _run(["iptables", "-D", EB_CHAIN, "-d", e, "-j", "REJECT",
                     "--reject-with", "icmp-port-unreachable"])[0] == 0:
                removed += 1
        elif fam == 6 and cp6 and (e in d6 or base in d6 or (base + "/128") in d6):
            if _run(["ip6tables", "-D", EB_CHAIN6, "-d", e, "-j", "REJECT",
                     "--reject-with", "icmp6-port-unreachable"])[0] == 0:
                removed += 1
    for p in (EB_SH, EB_UNIT, EB_URL_FILE):
        with contextlib.suppress(Exception):
            if os.path.exists(p):
                os.remove(p)
    _run(["systemctl", "daemon-reload"], timeout=20)
    log.append(f"removed unit + script; deleted {removed} REJECT rules from the exit chains")
    return {"ok": True, "removed_rules": removed, "state": _extra_blocks_state(),
            "output": "\n".join(log), "error": None}


EXEC_ACTIONS = {
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
    "extra_blocks_verify": act_extra_blocks_verify,
    "extra_blocks_remove": act_extra_blocks_remove,
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
        elif self.path.startswith("/v1/backup"):
            self._serve_backup()
        else:
            self._send(404, {"error": "not found"})

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
