"""nym maestro — local orchestrator.

Runs on your Mac. Serves the dashboard and owns the node registry. Connects out
to node agents over mTLS (added in slice 2). Bind to localhost only.

    pip install -r requirements.txt
    python app.py                 # http://127.0.0.1:7766
    python app.py --addr 127.0.0.1:7766 --db ~/.nym-maestro/maestro.db
"""
import argparse
import asyncio
import contextlib
import hashlib
import json
import os
import re
import ssl
import ipaddress
import subprocess
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from pydantic import BaseModel

from store import Conflict, Store
import wallet

# Python 3.14+ deprecated asyncio.iscoroutinefunction, but some stdlib asyncio
# paths (wait_for / ensure_future) still call it internally, so a noisy
# DeprecationWarning gets attributed to our await sites. It's not from our code
# and is harmless; silence just that one message so the console stays clean.
import warnings
warnings.filterwarnings(
    "ignore",
    category=DeprecationWarning,
    message=r".*iscoroutinefunction.*is deprecated.*",
)

VERSION = "0.1.0"
BASE = Path(__file__).resolve().parent
INDEX_PATH = (BASE / "web" / "index.html")
INDEX_HTML = INDEX_PATH.read_bytes()   # fallback if the file can't be read at request time
BACKUPS = Path(os.environ.get("MAESTRO_BACKUPS") or (BASE / "backups"))
SSH_DIR = Path(os.environ.get("MAESTRO_SSH_DIR") or (Path.home() / ".nym-maestro" / "ssh"))
SSH_USER = os.environ.get("MAESTRO_SSH_USER", "")

_COUNTRY_NAME_TO_ISO2 = {
    "austria": "AT", "belgium": "BE", "bulgaria": "BG", "switzerland": "CH",
    "czechia": "CZ", "czech republic": "CZ", "germany": "DE", "denmark": "DK",
    "spain": "ES", "finland": "FI", "france": "FR", "united kingdom": "GB",
    "great britain": "GB", "greece": "GR", "hungary": "HU", "ireland": "IE",
    "italy": "IT", "luxembourg": "LU", "lithuania": "LT", "latvia": "LV",
    "moldova": "MD", "netherlands": "NL", "norway": "NO", "poland": "PL",
    "portugal": "PT", "romania": "RO", "serbia": "RS", "sweden": "SE",
    "slovakia": "SK", "slovenia": "SI", "ukraine": "UA", "russia": "RU",
    "united states": "US", "united states of america": "US", "usa": "US",
    "canada": "CA", "mexico": "MX", "brazil": "BR", "argentina": "AR",
    "australia": "AU", "new zealand": "NZ", "japan": "JP", "south korea": "KR",
    "korea": "KR", "china": "CN", "hong kong": "HK", "taiwan": "TW",
    "singapore": "SG", "india": "IN", "indonesia": "ID", "vietnam": "VN",
    "thailand": "TH", "malaysia": "MY", "philippines": "PH", "turkey": "TR",
    "israel": "IL", "united arab emirates": "AE", "south africa": "ZA",
    "estonia": "EE", "iceland": "IS", "cyprus": "CY", "croatia": "HR",
    "chile": "CL", "colombia": "CO", "kazakhstan": "KZ", "georgia": "GE",
}

# --- Nym network topology (IP -> country), for placing 1789 peers on the map -
# Topology source: the unified /described endpoint returns every node type
# (gateways + mixnodes) with host_information.ip_address + auxiliary_details.location.
# The legacy /gateways and /mixnodes/active endpoints were removed post-smoosh (404).
NYM_TOPOLOGY_URLS = [
    u.strip() for u in os.environ.get(
        "MAESTRO_NYM_TOPOLOGY_URLS",
        "https://validator.nymtech.net/api/v1/nym-nodes/described",
    ).split(",") if u.strip()
]
_NYM_TOPO_CACHE = {"at": 0.0, "map": {}}
_NYM_TOPO_TTL = float(os.environ.get("MAESTRO_NYM_TOPOLOGY_TTL", "3600"))
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HEX6 = set("0123456789abcdefABCDEF:.")


def _norm_ip(s):
    try:
        return ipaddress.ip_address(s.strip()).compressed
    except Exception:
        return None


def _maybe_ip(s):
    """Normalize s to an IP (v4 or v6) if it plausibly is one, else None.

    Gated so we don't run ipaddress.parse on every base58 key / timestamp.
    """
    if _IPV4_RE.match(s):
        return _norm_ip(s)
    if ":" in s and s and all(c in _HEX6 for c in s):
        return _norm_ip(s)
    return None


def _node_info(node):
    """Collect normalized IPs, country, and hostname within one node object."""
    ips, country, host = [], None, None

    def walk(x):
        nonlocal country, host
        if isinstance(x, dict):
            for k, v in x.items():
                kl = k.lower()
                if (kl in ("country_code", "country",
                           "two_letter_iso_country_code", "location")
                        and isinstance(v, str) and v.strip() and not country):
                    country = v.strip()
                if kl == "hostname" and isinstance(v, str) and v.strip() and not host:
                    host = v.strip()
                walk(v)
        elif isinstance(x, list):
            for e in x:
                walk(e)
        elif isinstance(x, str):
            n = _maybe_ip(x)
            if n:
                ips.append(n)
    walk(node)
    return ips, country, host


def _harvest_nodes(obj, into):
    """Find lists of node objects and map each node's IPs to {cc, host}.

    Tolerant to API shape: a node is any dict element of a list; IP, country,
    and hostname may live in different sub-objects of that node. Handles both
    IPv4 and (normalized) IPv6.
    """
    if isinstance(obj, list):
        for e in obj:
            if isinstance(e, dict):
                ips, cc, host = _node_info(e)
                if (cc or host) and ips:
                    for ip in ips:
                        rec = into.setdefault(ip, {})
                        if cc and "cc" not in rec:
                            rec["cc"] = cc
                        if host and "host" not in rec:
                            rec["host"] = host
                else:
                    _harvest_nodes(e, into)
            else:
                _harvest_nodes(e, into)
    elif isinstance(obj, dict):
        for v in obj.values():
            _harvest_nodes(v, into)


async def fetch_nym_topology(force=False):
    now = time.time()
    if not force and _NYM_TOPO_CACHE["map"] and (now - _NYM_TOPO_CACHE["at"]) < _NYM_TOPO_TTL:
        return _NYM_TOPO_CACHE["map"]
    merged = {}
    async with httpx.AsyncClient(timeout=25, follow_redirects=True) as client:
        for url in NYM_TOPOLOGY_URLS:
            try:
                r = await client.get(url)
                r.raise_for_status()
                data = r.json()
                _harvest_nodes(data, merged)
                # follow pagination if the endpoint reports more pages than it returned
                pg = data.get("pagination") if isinstance(data, dict) else None
                if pg:
                    total = int(pg.get("total") or 0)
                    size = int(pg.get("size") or 0)
                    page = int(pg.get("page") or 0)
                    got = size
                    guard = 0
                    while size and got < total and guard < 30:
                        page += 1
                        guard += 1
                        sep = "&" if "?" in url else "?"
                        rp = await client.get(f"{url}{sep}page={page}&size={size}")
                        rp.raise_for_status()
                        _harvest_nodes(rp.json(), merged)
                        got += size
            except Exception:
                continue
    if merged:
        _NYM_TOPO_CACHE["map"] = merged
        _NYM_TOPO_CACHE["at"] = now
    return _NYM_TOPO_CACHE["map"]


def _iso2(country: str):
    """Normalise a country string (code or full name) to an upper ISO-2 code."""
    if not country:
        return None
    c = country.strip()
    if len(c) == 2 and c.isalpha():
        return c.upper()
    return _COUNTRY_NAME_TO_ISO2.get(c.lower())


# --- client/peer IP geolocation + reverse DNS -------------------------------
# Location comes from GeoIP on the raw IP (uniform for every endpoint, and the
# only thing that works for clients, which are never in the topology). The Nym
# topology is still used for fleet detection + advertised node hostnames.
# Mode is runtime-toggleable from the UI and persisted to a small settings file.
MAESTRO_GEOIP_DB = os.environ.get("MAESTRO_GEOIP_DB", "").strip()
MAESTRO_SETTINGS = Path(os.environ.get("MAESTRO_SETTINGS")
                        or (Path.home() / ".nym-maestro" / "settings.json"))
_GEOIP_TTL = float(os.environ.get("MAESTRO_GEOIP_TTL", "86400"))
_GEOIP_CACHE = {}
_PTR_CACHE = {}
_geoip_reader = None
_GEOIP_MAX = 300

_SETTINGS = {"geoip": os.environ.get("MAESTRO_GEOIP", "off").strip().lower()}


def _load_settings():
    try:
        if MAESTRO_SETTINGS.exists():
            data = json.loads(MAESTRO_SETTINGS.read_text())
            if isinstance(data, dict) and data.get("geoip") in ("off", "ipapi", "mmdb"):
                _SETTINGS["geoip"] = data["geoip"]
    except Exception:
        pass


_load_settings()


def _geoip_mode():
    return _SETTINGS.get("geoip", "off")


def set_geoip_mode(mode):
    if mode not in ("off", "ipapi", "mmdb"):
        raise ValueError("bad mode")
    _SETTINGS["geoip"] = mode
    try:
        MAESTRO_SETTINGS.parent.mkdir(parents=True, exist_ok=True)
        MAESTRO_SETTINGS.write_text(json.dumps(_SETTINGS))
    except Exception:
        pass


def _unmap(ip):
    """::ffff:1.2.3.4  ->  1.2.3.4  (IPv4-mapped IPv6, e.g. v4 clients on a v6 socket)."""
    s = (ip or "").strip()
    try:
        a = ipaddress.ip_address(s)
        m = getattr(a, "ipv4_mapped", None)
        if m is not None:
            return str(m)
    except Exception:
        pass
    return s


def _is_public_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local
                    or a.is_multicast or a.is_reserved or a.is_unspecified)
    except Exception:
        return False


def _geoip_mmdb(todo, out, now):
    global _geoip_reader
    if not todo or not MAESTRO_GEOIP_DB:
        return
    try:
        import geoip2.database
        if _geoip_reader is None:
            _geoip_reader = geoip2.database.Reader(MAESTRO_GEOIP_DB)
    except Exception:
        return
    for ip in todo:
        try:
            r = _geoip_reader.city(ip)
            rec = {"cc": r.country.iso_code, "country": r.country.name,
                   "city": r.city.name, "lat": r.location.latitude, "lon": r.location.longitude}
            out[ip] = rec
            _GEOIP_CACHE[ip] = {"rec": rec, "at": now}
        except Exception:
            continue


async def _geoip_ipapi(todo, out, now):
    if not todo:
        return
    url = "http://ip-api.com/batch?fields=query,status,countryCode,country,city,lat,lon"
    async with httpx.AsyncClient(timeout=15) as client:
        for i in range(0, len(todo), 100):
            chunk = todo[i:i + 100]
            try:
                r = await client.post(url, json=chunk)
                r.raise_for_status()
                for item in r.json():
                    if item.get("status") == "success":
                        ip = item.get("query")
                        rec = {"cc": item.get("countryCode"), "country": item.get("country"),
                               "city": item.get("city"), "lat": item.get("lat"), "lon": item.get("lon")}
                        out[ip] = rec
                        _GEOIP_CACHE[ip] = {"rec": rec, "at": now}
            except Exception:
                continue


async def geolocate_ips(ips):
    """Resolve public IPs to {cc, country, city, lat, lon} per the current mode."""
    mode = _geoip_mode()
    if mode == "off":
        return {}
    now = time.time()
    out, todo = {}, []
    seen = set()
    for raw in ips:
        ip = _unmap(raw)
        if ip in seen or not _is_public_ip(ip):
            continue
        seen.add(ip)
        c = _GEOIP_CACHE.get(ip)
        if c and (now - c["at"]) < _GEOIP_TTL:
            out[ip] = c["rec"]
        elif len(todo) < _GEOIP_MAX:
            todo.append(ip)
    if mode == "mmdb":
        _geoip_mmdb(todo, out, now)
    elif mode == "ipapi":
        await _geoip_ipapi(todo, out, now)
    return out


def _ptr_lookup(ip):
    import socket
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


async def resolve_ptr(ips, budget=1.5):
    """Resolve reverse-DNS names, awaiting up to `budget` seconds so the first
    render already has most hostnames; cached results are instant and anything
    that doesn't finish in time fills the cache for the next call. Off when
    location is off."""
    if _geoip_mode() == "off":
        return {}
    now = time.time()
    out, todo = {}, []
    seen = set()
    for raw in ips:
        ip = _unmap(raw)
        if ip in seen or not _is_public_ip(ip):
            continue
        seen.add(ip)
        c = _PTR_CACHE.get(ip)
        if c is not None and (now - c["at"]) < _GEOIP_TTL:
            if c["host"]:
                out[ip] = c["host"]
        else:
            todo.append(ip)
    if not todo:
        return out
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(24)

    async def one(ip):
        async with sem:
            try:
                host = await asyncio.wait_for(loop.run_in_executor(None, _ptr_lookup, ip), 1.2)
            except Exception:
                host = None
            _PTR_CACHE[ip] = {"host": host, "at": time.time()}
            if host:
                out[ip] = host
    try:
        await asyncio.wait_for(
            asyncio.gather(*[one(ip) for ip in todo[:120]], return_exceptions=True), budget)
    except asyncio.TimeoutError:
        pass
    return out


_SSH_SEM = None


def _ssh_sem():
    # Limit concurrent ssh probes so a whole-fleet batch doesn't open 20+ handshakes at once.
    global _SSH_SEM
    if _SSH_SEM is None:
        _SSH_SEM = asyncio.Semaphore(int(os.environ.get("MAESTRO_SSH_CONCURRENCY", "6")))
    return _SSH_SEM


def ensure_ssh_key():
    """Generate (once) and return maestro's managed ed25519 keypair on this Mac.

    The private key never leaves this machine; only the public key is pushed.
    """
    SSH_DIR.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(Exception):
        os.chmod(SSH_DIR, 0o700)
    key = SSH_DIR / "id_maestro"
    if not key.exists():
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key),
                        "-C", "nym-maestro"], check=True, capture_output=True, timeout=30)
    pub = (SSH_DIR / "id_maestro.pub").read_text().strip()
    return str(key), pub


async def ssh_verify_login(node: dict, port: int = 22, timeout: float = 20.0, attempts: int = 2):
    """Confirm a real key-based SSH login as SSH_USER works. Returns (ok, detail).

    Each node uses its own known_hosts file so parallel probes never race on a
    shared file, and probes are throttled by a semaphore + retried once.
    """
    key = SSH_DIR / "id_maestro"
    if not key.exists():
        return False, "no managed key yet"
    khdir = SSH_DIR / "known_hosts.d"
    khdir.mkdir(parents=True, exist_ok=True)
    kh = khdir / node["ip"].replace(":", "_")
    cmd = ["ssh", "-i", str(key), "-o", "BatchMode=yes",
           "-o", "StrictHostKeyChecking=accept-new",
           "-o", f"UserKnownHostsFile={kh}",
           "-o", "ConnectTimeout=10", "-p", str(port),
           f"{SSH_USER}@{node['ip']}", "echo nym-maestro-ok"]
    last = "login failed"
    for i in range(attempts):
        async with _ssh_sem():
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                with contextlib.suppress(Exception):
                    proc.kill()
                last = "ssh timed out"
                out = err = b""
            except Exception as e:
                last = str(e)
                out = err = b""
            else:
                if proc.returncode == 0 and b"nym-maestro-ok" in out:
                    detail = (out + err).decode("utf-8", "replace").strip()
                    return True, (detail[-300:] if detail else "ok")
                last = (out + err).decode("utf-8", "replace").strip() or "login failed"
        if i + 1 < attempts:
            await asyncio.sleep(0.6)
    return False, last[-300:]
SCHEMA = (BASE / "schema.sql").read_text()


def default_db() -> str:
    return os.environ.get("MAESTRO_DB") or str(
        Path.home() / ".nym-maestro" / "maestro.db"
    )


def pki_dir() -> Path:
    return Path(os.environ.get("MAESTRO_PKI") or (Path.home() / ".nym-maestro" / "pki"))


class Pki:
    def __init__(self, d: Path):
        self.ca_cert = str(d / "ca.crt")
        self.client_cert = str(d / "orchestrator.crt")
        self.client_key = str(d / "orchestrator.key")

    def ready(self) -> bool:
        return all(Path(p).exists() for p in (self.ca_cert, self.client_cert, self.client_key))

    def mtls_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context(cafile=self.ca_cert)
        ctx.load_cert_chain(certfile=self.client_cert, keyfile=self.client_key)
        return ctx


async def _poll_one(client: httpx.AsyncClient, node: dict):
    url = f"https://{node['ip']}:{node['agent_port']}/v1/status"
    try:
        r = await client.get(url)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


async def poll_all(app: FastAPI) -> dict:
    store, pki = app.state.store, app.state.pki
    nodes = [n for n in store.list_nodes() if n["enabled"]]
    if not nodes:
        return {"polled": 0, "reachable": 0}

    async with httpx.AsyncClient(verify=pki.mtls_context(), timeout=8.0) as client:
        results = await asyncio.gather(*[_poll_one(client, n) for n in nodes])

    reachable = 0
    for node, res in zip(nodes, results):
        if not res:
            store.upsert_status(node["uid"], reachable=False)
            continue
        reachable += 1
        nym = res.get("nym") or {}
        store.upsert_status(
            node["uid"], reachable=True,
            version=nym.get("version"), mode=nym.get("mode"),
            mixnode=nym.get("mixnode"), entry=nym.get("entry"),
            exit=nym.get("exit"), wireguard=nym.get("wireguard"),
            service_active=res.get("service_active"),
            fail2ban_banned=res.get("fail2ban_banned"),
            traffic=res.get("traffic"), traffic_bytes=res.get("traffic_bytes"),
            throughput=res.get("throughput"),
            agent_version=res.get("agent_version"), agent_sha=res.get("agent_sha"),
            extra_blocks=res.get("extra_blocks"),
            nym_node_since=res.get("nym_node_since"),
            uplink_device=res.get("uplink_device"),
            boot_since=res.get("boot_since"),
            traffic_dir=res.get("traffic_dir"),
            throughput_dir=res.get("throughput_dir"),
            disk=res.get("disk"),
        )
    return {"polled": len(nodes), "reachable": reachable}


ALLOWED_EXEC = {"restart", "toggle", "upgrade"}


async def agent_exec(app: FastAPI, node: dict, action: str, params=None, timeout=40):
    url = f"https://{node['ip']}:{node['agent_port']}/v1/exec"
    async with httpx.AsyncClient(verify=app.state.pki.mtls_context(), timeout=timeout) as client:
        r = await client.post(url, json={"action": action, "params": params or {}})
        r.raise_for_status()
        return r.json()


async def download_backup(app: FastAPI, node: dict, name: str, dest: Path, timeout=900):
    """Stream a staged backup from the agent to local disk; return its sha256."""
    url = f"https://{node['ip']}:{node['agent_port']}/v1/backup"
    h = hashlib.sha256()
    async with httpx.AsyncClient(verify=app.state.pki.mtls_context(), timeout=timeout) as client:
        async with client.stream("GET", url, params={"name": name}) as r:
            r.raise_for_status()
            with open(dest, "wb") as f:
                async for chunk in r.aiter_bytes(1 << 16):
                    f.write(chunk)
                    h.update(chunk)
    return h.hexdigest()


async def repoll_nodes(app: FastAPI, nodes: list):
    store, pki = app.state.store, app.state.pki
    try:
        async with httpx.AsyncClient(verify=pki.mtls_context(), timeout=8.0) as client:
            results = await asyncio.gather(*[_poll_one(client, n) for n in nodes])
    except Exception:
        return
    for node, res in zip(nodes, results):
        if not res:
            store.upsert_status(node["uid"], reachable=False)
            continue
        nym = res.get("nym") or {}
        store.upsert_status(
            node["uid"], reachable=True,
            version=nym.get("version"), mode=nym.get("mode"),
            mixnode=nym.get("mixnode"), entry=nym.get("entry"),
            exit=nym.get("exit"), wireguard=nym.get("wireguard"),
            service_active=res.get("service_active"),
            fail2ban_banned=res.get("fail2ban_banned"),
            traffic=res.get("traffic"), traffic_bytes=res.get("traffic_bytes"),
            throughput=res.get("throughput"),
            agent_version=res.get("agent_version"), agent_sha=res.get("agent_sha"),
            extra_blocks=res.get("extra_blocks"),
            nym_node_since=res.get("nym_node_since"),
            uplink_device=res.get("uplink_device"),
            boot_since=res.get("boot_since"),
            traffic_dir=res.get("traffic_dir"),
            throughput_dir=res.get("throughput_dir"),
            disk=res.get("disk"),
        )


async def _poll_loop(app: FastAPI, interval: int):
    if interval <= 0:
        return
    while True:
        try:
            if app.state.pki.ready():
                await poll_all(app)
        except Exception:
            pass
        await asyncio.sleep(interval)


# How many cursor-paginated /v1/history pages to pull per node per sync round. The
# agent caps each page at HISTORY_MAX_ROWS (10000 minute-buckets ~= 7 days), so a
# few pages cover any realistic backlog; the rest is caught up on later rounds.
_HISTORY_MAX_PAGES = int(os.environ.get("MAESTRO_HISTORY_MAX_PAGES", "8"))


async def _sync_history_one(client, store, node, kind):
    """Pull minute-bucketed history for one node+kind from its agent, starting at
    the stored cursor, following cursor pagination until caught up (bounded by
    _HISTORY_MAX_PAGES), backfilling idempotently. Advances the cursor as it goes.

    kind is 'tput' (throughput_history) or 'traffic' (traffic_history). The agent's
    history survives orchestrator downtime, so this backfills any gap since the last
    successful sync — that is what makes the throughput chart gap-free even when the
    orchestrator was stopped or moved to another host."""
    uid = node["uid"]
    since = store.get_history_cursor(uid, kind)
    base = f"https://{node['ip']}:{node['agent_port']}/v1/history"
    total = 0
    for _ in range(_HISTORY_MAX_PAGES):
        url = f"{base}?kind={kind}&since={since}"
        try:
            r = await client.get(url)
            r.raise_for_status()
            data = r.json()
        except Exception:
            break
        rows = data.get("rows") or []
        if not rows:
            break
        if kind == "tput":
            _, max_ts = store.backfill_throughput(uid, rows)
        else:
            _, max_ts = store.backfill_traffic(uid, rows)
        total += len(rows)
        if max_ts is None:
            break
        since = max_ts
        store.set_history_cursor(uid, kind, since)
        if not data.get("truncated"):
            break
    return total


async def sync_history_all(app: FastAPI) -> dict:
    """Backfill throughput + traffic history for every enabled node from its agent."""
    store, pki = app.state.store, app.state.pki
    nodes = [n for n in store.list_nodes() if n["enabled"]]
    if not nodes:
        return {"synced": 0}
    synced = 0
    async with httpx.AsyncClient(verify=pki.mtls_context(), timeout=30.0) as client:
        for node in nodes:
            for kind in ("tput", "traffic"):
                try:
                    synced += await _sync_history_one(client, store, node, kind)
                except Exception:
                    pass
    # trim our own copy to the retention window (agent already trims its side)
    store.prune_throughput()
    store.prune_traffic()
    return {"synced": synced}


async def _history_loop(app: FastAPI, interval: int):
    """Periodically backfill on-agent history. Runs less often than the status poll
    since the agent buckets at 1 minute; the default 300s (5 min) keeps the chart
    fresh while staying light. Agents older than 0.10.0 lack /v1/history and simply
    return errors, which are swallowed — those nodes keep whatever history exists."""
    if interval <= 0:
        return
    # small initial delay so the first status poll populates the node registry first
    await asyncio.sleep(5)
    while True:
        try:
            if app.state.pki.ready():
                await sync_history_all(app)
        except Exception:
            pass
        await asyncio.sleep(interval)


def _sum_bps(items):
    """Sum bits/s across connection items, skipping loopback endpoints."""
    total = 0.0
    for it in items or []:
        ip = (it.get("ip") or "")
        if ip.startswith("127.") or ip in ("::1", "0.0.0.0"):
            continue
        total += it.get("bps") or 0
    return total


async def record_onwire_once(app: FastAPI):
    """Sample each node's on-wire throughput (via the peers action) and record it,
    split into wg (51822 dVPN) and mix (1789 node-relay + 9000 mixnet clients).
    This is the on-wire plane — includes mixnet relay + cover — distinct from the
    exit-tunnel counters. Kept on a gentle cadence since the peers scan parses ss."""
    store = app.state.store
    nodes = [n for n in store.list_nodes() if n["enabled"]]
    if not nodes:
        return

    async def one(node):
        try:
            res = await agent_exec(app, node, "peers", {}, timeout=15)
        except Exception:
            return
        wg = _sum_bps(res.get("wg_clients"))
        mix = _sum_bps(res.get("peers")) + _sum_bps(res.get("clients"))
        store.record_onwire(node["uid"], time.time(), wg, mix)

    await asyncio.gather(*[one(n) for n in nodes])
    store.prune_onwire()


async def _onwire_loop(app: FastAPI, interval: int):
    if interval <= 0:
        return
    while True:
        try:
            if app.state.pki.ready():
                await record_onwire_once(app)
        except Exception:
            pass
        await asyncio.sleep(interval)


@asynccontextmanager
async def lifespan(app: FastAPI):
    db = default_db()
    Path(db).parent.mkdir(parents=True, exist_ok=True)
    app.state.store = Store(db, SCHEMA)
    app.state.pki = Pki(pki_dir())
    interval = int(os.environ.get("MAESTRO_POLL", "30"))
    onwire_interval = int(os.environ.get("MAESTRO_ONWIRE_POLL", "60"))
    history_interval = int(os.environ.get("MAESTRO_HISTORY_POLL", "300"))
    task = asyncio.create_task(_poll_loop(app, interval))
    onwire_task = asyncio.create_task(_onwire_loop(app, onwire_interval))
    history_task = asyncio.create_task(_history_loop(app, history_interval))
    try:
        yield
    finally:
        for t in (task, onwire_task, history_task):
            t.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await t
        app.state.store.close()


app = FastAPI(title="nym maestro", version=VERSION, lifespan=lifespan)


# Keep the API's error shape as {"error": "..."} so the UI stays unchanged.
@app.exception_handler(HTTPException)
async def _http_exc(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})


@app.exception_handler(RequestValidationError)
async def _validation_exc(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=400, content={"error": "invalid request body"})


class NodeCreate(BaseModel):
    node_id: str
    name: str
    ip: str
    hostname: str = ""
    agent_port: int = 8443
    agent_fp: str = ""
    service_name: str = ""
    binary_path: str = ""
    notes: str = ""
    enabled: bool = True


class NodePatch(BaseModel):
    node_id: str | None = None
    name: str | None = None
    ip: str | None = None
    hostname: str | None = None
    agent_port: int | None = None
    agent_fp: str | None = None
    service_name: str | None = None
    binary_path: str | None = None
    notes: str | None = None
    enabled: bool | None = None


class ExecRequest(BaseModel):
    action: str
    node_ids: list[str]   # maestro uids
    params: dict = {}


class AgentUpdateRequest(BaseModel):
    node_ids: list[str]   # maestro uids
    restart: bool = False


class BackupRequest(BaseModel):
    node_ids: list[str]   # maestro uids


class Fail2banRequest(BaseModel):
    node_ids: list[str]


class Fail2banSetupRequest(BaseModel):
    node_ids: list[str]
    maxretry: int = 5
    findtime: str = "10m"
    bantime: str = "1h"
    increment: bool = True
    ignoreip: list[str] = []


class Fail2banUnbanRequest(BaseModel):
    node_id: str
    ip: str


class SshNodesRequest(BaseModel):
    node_ids: list[str]


class SshInstallRequest(BaseModel):
    node_ids: list[str]
    extra_pubkeys: list[str] = []


class SshHardenRequest(BaseModel):
    node_ids: list[str]
    password: str = "off"   # "off" disables password login, "on" re-enables


class PeersRequest(BaseModel):
    node_id: str


class ExtraBlocksRequest(BaseModel):
    node_ids: list[str]


class ExtraBlocksInstallRequest(BaseModel):
    node_ids: list[str]
    restart_node: bool = False
    list_url: str | None = None


class WalletQueryRequest(BaseModel):
    wallets: list[str]
    password: str
    with_usd: bool = True


class WalletRedeemRequest(BaseModel):
    wallets: list[str]
    password: str
    confirm: bool = False


class WalletSendRequest(BaseModel):
    wallets: list[str]           # send the same amount / max from each listed wallet
    password: str
    receiver: str
    amount_nym: float | None = None
    send_max: bool = False
    confirm: bool = False


class WalletAddRequest(BaseModel):
    name: str
    mnemonic: str
    password: str
    overwrite: bool = False


class WalletExportRequest(BaseModel):
    name: str
    password: str


class WalletDeleteRequest(BaseModel):
    name: str
    confirm: bool = False


def local_agent_source():
    data = (BASE / "agent" / "agent.py").read_bytes()
    text = data.decode("utf-8")
    version = "?"
    import re as _re
    m = _re.search(r'AGENT_VERSION\s*=\s*"([^"]+)"', text)
    if m:
        version = m.group(1)
    return text, version, hashlib.sha256(data).hexdigest()


def _require_node(request: Request, uid: str) -> dict:
    n = request.app.state.store.get_node(uid)
    if not n:
        raise HTTPException(404, "no node with that id")
    return n


@app.get("/", response_class=HTMLResponse)
def index():
    try:
        return HTMLResponse(INDEX_PATH.read_bytes())   # fresh each load; no app restart for UI changes
    except Exception:
        return HTMLResponse(INDEX_HTML)


# Favicons live next to index.html in web/. Serving both .ico and .svg kills the
# "GET /favicon.ico 404" noise and gives the browser tab the nym maestro mark.
_WEB_DIR = BASE / "web"


@app.get("/favicon.ico", include_in_schema=False)
def favicon_ico():
    p = _WEB_DIR / "favicon.ico"
    if p.exists():
        return FileResponse(p, media_type="image/x-icon")
    # fall back to the SVG if the .ico isn't present for some reason
    svg = _WEB_DIR / "favicon.svg"
    if svg.exists():
        return FileResponse(svg, media_type="image/svg+xml")
    return Response(status_code=404)


@app.get("/favicon.svg", include_in_schema=False)
def favicon_svg():
    p = _WEB_DIR / "favicon.svg"
    return FileResponse(p, media_type="image/svg+xml") if p.exists() else Response(status_code=404)


@app.get("/apple-touch-icon.png", include_in_schema=False)
@app.get("/apple-touch-icon-precomposed.png", include_in_schema=False)
def apple_touch_icon():
    p = _WEB_DIR / "apple-touch-icon.png"
    return FileResponse(p, media_type="image/png") if p.exists() else Response(status_code=404)


@app.get("/api/health")
def health():
    return {"status": "ok", "version": VERSION}


@app.get("/api/nodes")
async def list_nodes(request: Request):
    nodes = request.app.state.store.list_nodes()
    try:
        _, local_ver, local_sha = local_agent_source()
    except Exception:
        local_ver = local_sha = None
    topo = await fetch_nym_topology()
    for n in nodes:
        st = n.get("status")
        if st:
            st["agent_stale"] = bool(local_sha and st.get("agent_sha") and st["agent_sha"] != local_sha)
            st["local_agent_version"] = local_ver
        # real hosting country from the Nym topology (by IP), for accurate map placement
        nip = _norm_ip(n.get("ip", "")) or n.get("ip", "")
        rec = topo.get(nip) or {}
        cc = _iso2(rec.get("cc"))
        if cc:
            n["cc"] = cc
    return nodes


@app.get("/api/throughput")
def throughput_series(request: Request, hours: float = 24.0, buckets: int = 96):
    buckets = max(12, min(buckets, 480))
    hours = max(0.5, min(hours, 168.0))
    return request.app.state.store.throughput_series(hours=hours, buckets=buckets)


@app.get("/api/throughput/avg")
def throughput_average(request: Request, hours: float = 24.0):
    # fleet average throughput over the window, split by device (nymwg/nymtun0)
    hours = max(0.5, min(hours, 168.0))
    return request.app.state.store.throughput_avg(hours=hours)


@app.get("/api/traffic/window")
def traffic_window(request: Request, hours: float = 24.0):
    # REAL windowed traffic from cumulative-counter snapshots (no projection)
    hours = max(0.5, min(hours, 168.0))
    return request.app.state.store.traffic_window(hours=hours)


@app.get("/api/onwire/avg")
def onwire_average(request: Request, hours: float = 24.0):
    # fleet average ON-WIRE throughput (bits/s), split wg / mix
    hours = max(0.5, min(hours, 168.0))
    return request.app.state.store.onwire_avg(hours=hours)


@app.get("/api/nodes/{uid}")
def get_node(uid: str, request: Request):
    v = request.app.state.store.get_node(uid)
    if v is None:
        raise HTTPException(404, "no node with that id")
    return v


@app.post("/api/nodes", status_code=201)
def create_node(n: NodeCreate, request: Request):
    node_id, name, ip = n.node_id.strip(), n.name.strip(), n.ip.strip()
    if not (node_id and name and ip):
        raise HTTPException(400, "node_id, name and ip are required")
    data = n.model_dump()
    data.update(
        node_id=node_id, name=name, ip=ip,
        hostname=n.hostname.strip(), notes=n.notes.strip(),
        service_name=n.service_name.strip(), binary_path=n.binary_path.strip(),
        agent_fp=n.agent_fp.strip(),
    )
    try:
        uid = request.app.state.store.create_node(data)
    except Conflict as e:
        raise HTTPException(409, str(e))
    return request.app.state.store.get_node(uid)


@app.patch("/api/nodes/{uid}")
def update_node(uid: str, patch: NodePatch, request: Request):
    fields = patch.model_dump(exclude_unset=True)
    for k in ("hostname", "agent_fp", "service_name", "binary_path", "notes"):
        if k in fields and isinstance(fields[k], str):
            fields[k] = fields[k].strip() or None
    for k in ("name", "ip", "node_id"):
        if k in fields and isinstance(fields[k], str):
            fields[k] = fields[k].strip()
    try:
        ok = request.app.state.store.update_node(uid, fields)
    except Conflict as e:
        raise HTTPException(409, str(e))
    if not ok:
        raise HTTPException(404, "no node with that id")
    return request.app.state.store.get_node(uid)


@app.delete("/api/nodes/{uid}", status_code=204)
def delete_node(uid: str, request: Request):
    if not request.app.state.store.delete_node(uid):
        raise HTTPException(404, "no node with that id")
    return Response(status_code=204)


@app.post("/api/refresh")
async def refresh(request: Request):
    if not request.app.state.pki.ready():
        raise HTTPException(400, "PKI not initialised — run: python pki.py init")
    return await poll_all(request.app)


@app.post("/api/history/sync")
async def history_sync(request: Request):
    """Force an immediate on-agent history backfill for all nodes. Normally runs on
    a timer (MAESTRO_HISTORY_POLL, default 5 min); this triggers it on demand, e.g.
    right after starting the orchestrator so the chart catches up without waiting."""
    if not request.app.state.pki.ready():
        raise HTTPException(400, "PKI not initialised — run: python pki.py init")
    return await sync_history_all(request.app)


def _require_pki(request: Request):
    if not request.app.state.pki.ready():
        raise HTTPException(400, "PKI not initialised — run: python pki.py init")


@app.get("/api/nodes/{uid}/service-file")
async def service_file(uid: str, request: Request):
    node = _require_node(request, uid)
    _require_pki(request)
    try:
        return await agent_exec(request.app, node, "service_file", timeout=15)
    except Exception as e:
        raise HTTPException(502, f"agent unreachable: {e}")


@app.get("/api/nodes/{uid}/execstart")
async def node_execstart(uid: str, request: Request):
    node = _require_node(request, uid)
    _require_pki(request)
    try:
        return await agent_exec(request.app, node, "get_execstart", timeout=15)
    except Exception as e:
        raise HTTPException(502, f"agent unreachable: {e}")


@app.post("/api/exec")
async def exec_action(payload: ExecRequest, request: Request):
    app_ = request.app
    if payload.action not in ALLOWED_EXEC:
        raise HTTPException(400, f"action not allowed: {payload.action}")
    _require_pki(request)

    store = app_.state.store
    nodes = [n for n in (store.get_node(i) for i in payload.node_ids) if n]
    if not nodes:
        raise HTTPException(400, "no valid target nodes")

    job_id = uuid.uuid4().hex
    store.record_job(job_id, payload.action, json.dumps(payload.params), len(nodes))

    async def run_one(node):
        try:
            timeout = 300 if payload.action == "upgrade" else 40
            res = await agent_exec(app_, node, payload.action, payload.params, timeout=timeout)
            ok = bool(res.get("ok", True))
        except Exception as e:
            res, ok = {"ok": False, "error": str(e)}, False
        store.record_target(job_id, node["uid"],
                            "done" if ok else "failed", None, json.dumps(res))
        store.audit("ui", payload.action, job_id, node["uid"], json.dumps(res))
        return {"uid": node["uid"], "node_id": node["node_id"], "name": node["name"], "ok": ok, "result": res}

    results = await asyncio.gather(*[run_one(n) for n in nodes])
    ok_count = sum(1 for r in results if r["ok"])
    status = "done" if ok_count == len(results) else ("failed" if ok_count == 0 else "partial")
    store.finish_job(job_id, status)

    await repoll_nodes(app_, nodes)
    return {"job_id": job_id, "status": status, "results": results}


@app.post("/api/backup")
async def backup(payload: BackupRequest, request: Request):
    app_ = request.app
    _require_pki(request)
    store = app_.state.store
    nodes = [n for n in (store.get_node(i) for i in payload.node_ids) if n]
    if not nodes:
        raise HTTPException(400, "no valid target nodes")

    BACKUPS.mkdir(parents=True, exist_ok=True)
    job_id = uuid.uuid4().hex
    store.record_job(job_id, "backup", json.dumps({"nodes": len(nodes)}), len(nodes))

    results = []
    for node in nodes:  # sequential: only one node is stopped at a time
        try:
            res = await agent_exec(app_, node, "backup", timeout=900)
            ok = bool(res.get("ok"))
            if ok:
                dest = BACKUPS / res["filename"]
                got = await download_backup(app_, node, res["filename"], dest)
                if got != res.get("sha256"):
                    ok = False
                    res["error"] = "sha256 mismatch after download"
                    with contextlib.suppress(Exception):
                        dest.unlink()
                else:
                    res["saved_path"] = str(dest)
                    res["local_size"] = dest.stat().st_size
                    with contextlib.suppress(Exception):
                        await agent_exec(app_, node, "backup_cleanup",
                                         {"name": res["filename"]}, timeout=30)
        except Exception as e:
            res, ok = {"ok": False, "error": str(e)}, False
        store.record_target(job_id, node["uid"], "done" if ok else "failed", None, json.dumps(res))
        store.audit("ui", "backup", job_id, node["uid"], json.dumps(res))
        results.append({"uid": node["uid"], "node_id": node["node_id"],
                        "name": node["name"], "ok": ok, "result": res})

    ok_count = sum(1 for r in results if r["ok"])
    status = "done" if ok_count == len(results) else ("failed" if ok_count == 0 else "partial")
    store.finish_job(job_id, status)
    return {"job_id": job_id, "status": status, "results": results}


async def _f2b_fanout(app_, store, nodes, action, params, timeout, label):
    async def one(node):
        try:
            res = await agent_exec(app_, node, action, params, timeout=timeout)
            ok = bool(res.get("ok", True))
        except Exception as e:
            res, ok = {"ok": False, "error": str(e)}, False
        store.audit("ui", label, None, node["uid"], json.dumps(res))
        return {"uid": node["uid"], "node_id": node["node_id"], "name": node["name"],
                "ok": ok, "result": res}
    return await asyncio.gather(*[one(n) for n in nodes])


@app.post("/api/fail2ban/status")
async def fail2ban_status(payload: Fail2banRequest, request: Request):
    app_ = request.app
    _require_pki(request)
    store = app_.state.store
    nodes = [n for n in (store.get_node(i) for i in payload.node_ids) if n]
    if not nodes:
        raise HTTPException(400, "no valid target nodes")
    results = await _f2b_fanout(app_, store, nodes, "fail2ban_status", {}, 20, "fail2ban_status")
    return {"results": results}


@app.post("/api/fail2ban/setup")
async def fail2ban_setup(payload: Fail2banSetupRequest, request: Request):
    app_ = request.app
    _require_pki(request)
    store = app_.state.store
    nodes = [n for n in (store.get_node(i) for i in payload.node_ids) if n]
    if not nodes:
        raise HTTPException(400, "no valid target nodes")
    params = {"maxretry": payload.maxretry, "findtime": payload.findtime,
              "bantime": payload.bantime, "increment": payload.increment,
              "ignoreip": payload.ignoreip}
    job_id = uuid.uuid4().hex
    store.record_job(job_id, "fail2ban_setup", json.dumps({"nodes": len(nodes)}), len(nodes))
    results = await _f2b_fanout(app_, store, nodes, "fail2ban_setup", params, 360, "fail2ban_setup")
    for r in results:
        store.record_target(job_id, r["uid"], "done" if r["ok"] else "failed", None, json.dumps(r["result"]))
    ok_count = sum(1 for r in results if r["ok"])
    status = "done" if ok_count == len(results) else ("failed" if ok_count == 0 else "partial")
    store.finish_job(job_id, status)
    return {"job_id": job_id, "status": status, "results": results}


@app.post("/api/fail2ban/unban")
async def fail2ban_unban(payload: Fail2banUnbanRequest, request: Request):
    app_ = request.app
    _require_pki(request)
    node = app_.state.store.get_node(payload.node_id)
    if not node:
        raise HTTPException(404, "no node with that id")
    try:
        res = await agent_exec(app_, node, "fail2ban_unban", {"ip": payload.ip}, timeout=20)
    except Exception as e:
        res = {"ok": False, "error": str(e)}
    app_.state.store.audit("ui", "fail2ban_unban", None, node["uid"], json.dumps(res))
    return res


def _eb_targets(request: Request, node_ids):
    _require_pki(request)
    store = request.app.state.store
    nodes = [n for n in (store.get_node(i) for i in node_ids) if n]
    if not nodes:
        raise HTTPException(400, "no valid target nodes")
    return store, nodes


@app.post("/api/extra-blocks/status")
async def extra_blocks_status(payload: ExtraBlocksRequest, request: Request):
    store, nodes = _eb_targets(request, payload.node_ids)
    results = await _f2b_fanout(request.app, store, nodes, "extra_blocks_status", {}, 25,
                                "extra_blocks_status")
    return {"results": results}


@app.post("/api/extra-blocks/install")
async def extra_blocks_install(payload: ExtraBlocksInstallRequest, request: Request):
    store, nodes = _eb_targets(request, payload.node_ids)
    params = {"restart_node": payload.restart_node, "list_url": payload.list_url}
    # a restart waits for nym-node + the oneshot to re-apply, so give it room
    timeout = 230 if payload.restart_node else 120
    job_id = uuid.uuid4().hex
    store.record_job(job_id, "extra_blocks_install",
                     json.dumps({"nodes": len(nodes), "restart": payload.restart_node}), len(nodes))
    results = await _f2b_fanout(request.app, store, nodes, "extra_blocks_install", params,
                                timeout, "extra_blocks_install")
    for r in results:
        store.record_target(job_id, r["uid"], "done" if r["ok"] else "failed", None,
                            json.dumps(r["result"]))
    ok_count = sum(1 for r in results if r["ok"])
    status = "done" if ok_count == len(results) else ("failed" if ok_count == 0 else "partial")
    store.finish_job(job_id, status)
    # refresh the fleet column promptly after a change
    await repoll_nodes(request.app, nodes)
    return {"job_id": job_id, "status": status, "results": results}


@app.post("/api/extra-blocks/upgrade")
async def extra_blocks_upgrade(payload: ExtraBlocksRequest, request: Request):
    _require_pki(request)
    store = request.app.state.store
    nodes = store.get_nodes_by_ids(payload.node_ids)
    results = await _f2b_fanout(request.app, store, nodes, "extra_blocks_upgrade", {}, 60,
                                "extra_blocks_upgrade")
    return {"results": results}


@app.post("/api/extra-blocks/verify")
async def extra_blocks_verify(payload: ExtraBlocksRequest, request: Request):
    store, nodes = _eb_targets(request, payload.node_ids)
    results = await _f2b_fanout(request.app, store, nodes, "extra_blocks_verify", {}, 40,
                                "extra_blocks_verify")
    await repoll_nodes(request.app, nodes)
    return {"results": results}


@app.post("/api/extra-blocks/remove")
async def extra_blocks_remove(payload: ExtraBlocksRequest, request: Request):
    store, nodes = _eb_targets(request, payload.node_ids)
    results = await _f2b_fanout(request.app, store, nodes, "extra_blocks_remove", {}, 60,
                                "extra_blocks_remove")
    await repoll_nodes(request.app, nodes)
    return {"results": results}


@app.get("/api/wallet/list")
def wallet_list():
    # names + whether nym-cli is available locally; price is best-effort
    return {
        "wallets": wallet.list_wallets(),
        "nym_cli": wallet.have_nym_cli(),
        "wallet_dir": str(wallet.WALLET_DIR),
    }


@app.post("/api/wallet/query")
def wallet_query(payload: WalletQueryRequest):
    if not payload.wallets:
        raise HTTPException(400, "no wallets selected")
    if not wallet.have_nym_cli():
        raise HTTPException(400, "nym-cli not found on the orchestrator host")
    rows = wallet.query_wallets(payload.wallets, payload.password, with_usd=payload.with_usd)
    return {"results": rows}


@app.post("/api/wallet/redeem")
def wallet_redeem(payload: WalletRedeemRequest):
    # IRREVERSIBLE: require explicit confirmation from the operator
    if not payload.confirm:
        raise HTTPException(400, "redeem requires confirm=true")
    if not payload.wallets:
        raise HTTPException(400, "no wallets selected")
    if not wallet.have_nym_cli():
        raise HTTPException(400, "nym-cli not found on the orchestrator host")
    results = wallet.redeem_rewards(payload.wallets, payload.password)
    csv_info = wallet.write_withdrawal_csv(results)   # one dated file for this run
    return {"results": results, "csv": csv_info}


@app.post("/api/wallet/send")
def wallet_send(payload: WalletSendRequest):
    # IRREVERSIBLE: require explicit confirmation and a valid receiver
    if not payload.confirm:
        raise HTTPException(400, "send requires confirm=true")
    if not payload.wallets:
        raise HTTPException(400, "no wallets selected")
    if not wallet.validate_address(payload.receiver):
        raise HTTPException(400, "invalid receiver address")
    if not payload.send_max and (payload.amount_nym is None or payload.amount_nym <= 0):
        raise HTTPException(400, "provide amount_nym > 0 or send_max=true")
    if not wallet.have_nym_cli():
        raise HTTPException(400, "nym-cli not found on the orchestrator host")
    results = [wallet.send_from(name, payload.password, payload.receiver,
                                amount_nym=payload.amount_nym, send_max=payload.send_max)
               for name in payload.wallets]
    return {"results": results}


@app.post("/api/wallet/add")
def wallet_add(payload: WalletAddRequest):
    try:
        wallet.add_wallet(payload.name, payload.mnemonic, payload.password,
                          overwrite=payload.overwrite)
    except wallet.WalletError as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "name": payload.name.strip()}


@app.post("/api/wallet/export")
def wallet_export(payload: WalletExportRequest):
    # reveals a mnemonic to the local operator UI only (localhost-bound app)
    try:
        mnemonic = wallet.decrypt_mnemonic(payload.name, payload.password)
    except wallet.WalletError as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "name": payload.name, "mnemonic": mnemonic}


@app.post("/api/wallet/delete")
def wallet_delete(payload: WalletDeleteRequest):
    if not payload.confirm:
        raise HTTPException(400, "delete requires confirm=true")
    wallet.delete_wallet(payload.name)
    return {"ok": True, "name": payload.name}


@app.get("/api/wallet/rewards-files")
def wallet_rewards_files():
    # list of per-withdrawal CSVs (newest first) + overall totals
    return {"files": wallet.list_rewards_files(), **wallet.rewards_summary()}


@app.get("/api/wallet/rewards-file/{filename}")
def wallet_rewards_file(filename: str):
    # download one session CSV; filename is validated in the wallet module
    try:
        text = wallet.read_rewards_file(filename)
    except wallet.WalletError as e:
        raise HTTPException(404, str(e))
    return Response(content=text, media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@app.post("/api/peers")
async def api_peers(payload: PeersRequest, request: Request):
    app_ = request.app
    _require_pki(request)
    store = app_.state.store
    node = store.get_node(payload.node_id)
    if not node:
        raise HTTPException(404, "node not found")
    try:
        res = await agent_exec(app_, node, "peers", {}, timeout=15)
    except Exception as e:
        return {"ok": False, "error": str(e), "node": {"uid": node["uid"], "name": node["name"]}}

    fleet_by_ip = {}
    for n in store.list_nodes():
        fleet_by_ip[n["ip"]] = {"uid": n["uid"], "name": n["name"]}

    topo = await fetch_nym_topology()
    peers = res.get("peers", []) or []
    clients = res.get("clients", []) or []
    wg_clients = res.get("wg_clients", []) or []

    # normalize IPv4-mapped IPv6 (::ffff:a.b.c.d) so every IP is clean
    for p in peers:
        p["ip"] = _unmap(p.get("ip"))
    for c in clients:
        c["ip"] = _unmap(c.get("ip"))
    for w in wg_clients:
        w["ip"] = _unmap(w.get("ip"))

    # fleet membership + advertised node hostname from topology (still useful)
    fleet_count = 0
    for p in peers:
        ip = p["ip"]
        nip = _norm_ip(ip) or ip
        rec = topo.get(nip) or {}
        m = fleet_by_ip.get(ip) or fleet_by_ip.get(nip)
        if m and m["uid"] != node["uid"]:
            p["fleet"] = m
            fleet_count += 1
        host = rec.get("host") or (m["name"] if m else None)
        if host:
            p["host"] = host            # advertised node hostname, or our fleet name

    # LOCATION comes from GeoIP on the raw IP — uniform for every endpoint, and
    # the only thing that works for inbound peers (source IP) and clients. The
    # topology country is only a fallback when GeoIP is off.
    all_ips = [p["ip"] for p in peers] + [c["ip"] for c in clients] + [w["ip"] for w in wg_clients]
    geo, ptr = await asyncio.gather(geolocate_ips(all_ips), resolve_ptr(all_ips))

    for p in peers:
        g = geo.get(p["ip"])
        if g:
            if g.get("cc"):
                p["cc"] = g["cc"]
            if g.get("city"):
                p["city"] = g["city"]
            if g.get("lat") is not None:
                p["lat"] = g["lat"]
                p["lon"] = g["lon"]
            p["geo"] = True
        if not p.get("cc"):                    # GeoIP off / miss -> topology country
            nip = _norm_ip(p["ip"]) or p["ip"]
            tcc = _iso2((topo.get(nip) or {}).get("cc"))
            m = p.get("fleet")
            if not tcc and m:
                tcc = (m["name"][:2].upper() if len(m["name"]) >= 2 else None)
            if tcc:
                p["cc"] = tcc
        if not p.get("host") and ptr.get(p["ip"]):
            p["host"] = ptr[p["ip"]]           # reverse-DNS hostname

    located = sum(1 for p in peers if p.get("cc") or p.get("lat") is not None)
    located_up = sum(1 for p in peers if (p.get("cc") or p.get("lat") is not None) and (p.get("dir") in ("up", "both")))
    located_down = sum(1 for p in peers if (p.get("cc") or p.get("lat") is not None) and (p.get("dir") in ("down", "both")))

    client_located = 0
    for c in clients:
        g = geo.get(c["ip"])
        if g:
            for k in ("cc", "country", "city", "lat", "lon"):
                if g.get(k) is not None:
                    c[k] = g[k]
            if g.get("cc") or g.get("lat") is not None:
                client_located += 1
        if ptr.get(c["ip"]):
            c["host"] = ptr[c["ip"]]

    wg_located = 0
    for w in wg_clients:
        g = geo.get(w["ip"])
        if g:
            for k in ("cc", "country", "city", "lat", "lon"):
                if g.get(k) is not None:
                    w[k] = g[k]
            if g.get("cc") or g.get("lat") is not None:
                wg_located += 1
        if ptr.get(w["ip"]):
            w["host"] = ptr[w["ip"]]

    store.audit("ui", "peers", None, node["uid"],
                json.dumps({"total": res.get("total_peers"), "located": located, "fleet": fleet_count}))

    return {
        "ok": bool(res.get("ok")),
        "node": {"uid": node["uid"], "name": node["name"]},
        "ports": res.get("ports"),
        "total_peers": res.get("total_peers", 0),
        "total_conns": res.get("total_conns", 0),
        "upstream": res.get("upstream", 0),
        "downstream": res.get("downstream", 0),
        "located": located,
        "located_up": located_up,
        "located_down": located_down,
        "fleet_peers": fleet_count,
        "topology_known": bool(topo),
        "geoip": _geoip_mode(),
        "clients": clients,
        "client_count": res.get("client_count", 0),
        "client_conns": res.get("client_conns", 0),
        "client_located": client_located,
        "client_geo": _geoip_mode(),
        "client_ports": res.get("client_ports"),
        "wg_clients": wg_clients,
        "wg_count": res.get("wg_count", 0),
        "wg_located": wg_located,
        "wg_available": res.get("wg_available", False),
        "onwire_mix": res.get("onwire_mix"),
        "onwire_clients": res.get("onwire_clients"),
        "onwire_peers": res.get("onwire_peers"),
        "peers": peers,
    }


@app.get("/api/settings")
def get_settings(request: Request):
    return {"geoip": _geoip_mode(), "geoip_db_available": bool(MAESTRO_GEOIP_DB)}


class GeoipSetting(BaseModel):
    mode: str


@app.post("/api/settings/geoip")
def set_geoip(payload: GeoipSetting, request: Request):
    try:
        set_geoip_mode(payload.mode.strip().lower())
    except ValueError:
        raise HTTPException(400, "mode must be off, ipapi, or mmdb")
    return {"geoip": _geoip_mode(), "geoip_db_available": bool(MAESTRO_GEOIP_DB)}


@app.get("/api/agent/local")
def agent_local():
    _, version, sha = local_agent_source()
    return {"version": version, "sha256": sha}


@app.get("/api/ssh/key")
def ssh_key(request: Request):
    _require_pki(request)
    key_path, pub = ensure_ssh_key()
    home = Path.home()
    try:
        display_path = "~/" + str(Path(key_path).relative_to(home))
    except ValueError:
        display_path = key_path
    try:
        known_hosts_disp = "~/" + str((SSH_DIR / "known_hosts").relative_to(home))
    except ValueError:
        known_hosts_disp = str(SSH_DIR / "known_hosts")
    return {"private_key_path": display_path, "public_key": pub, "ssh_user": SSH_USER,
            "known_hosts": known_hosts_disp}


@app.post("/api/ssh/install")
async def ssh_install(payload: SshInstallRequest, request: Request):
    app_ = request.app
    _require_pki(request)
    store = app_.state.store
    nodes = [n for n in (store.get_node(i) for i in payload.node_ids) if n]
    if not nodes:
        raise HTTPException(400, "no valid target nodes")
    _, pub = ensure_ssh_key()
    pubkeys = [pub] + [k.strip() for k in payload.extra_pubkeys if k.strip()]
    results = await _f2b_fanout(app_, store, nodes, "ssh_add_key",
                                {"public_keys": pubkeys, "user": SSH_USER}, 20, "ssh_add_key")
    return {"results": results}


@app.post("/api/ssh/verify")
async def ssh_verify(payload: SshNodesRequest, request: Request):
    app_ = request.app
    _require_pki(request)
    store = app_.state.store
    nodes = [n for n in (store.get_node(i) for i in payload.node_ids) if n]
    if not nodes:
        raise HTTPException(400, "no valid target nodes")

    async def one(node):
        ok, detail = await ssh_verify_login(node)
        store.audit("ui", "ssh_verify", None, node["uid"], json.dumps({"ok": ok, "detail": detail}))
        return {"uid": node["uid"], "name": node["name"], "ok": ok,
                "result": {"ok": ok, "verified": ok, "detail": detail}}
    results = await asyncio.gather(*[one(n) for n in nodes])
    return {"results": results}


@app.post("/api/ssh/status")
async def ssh_status(payload: SshNodesRequest, request: Request):
    app_ = request.app
    _require_pki(request)
    store = app_.state.store
    nodes = [n for n in (store.get_node(i) for i in payload.node_ids) if n]
    if not nodes:
        raise HTTPException(400, "no valid target nodes")
    results = await _f2b_fanout(app_, store, nodes, "ssh_status", {"user": SSH_USER}, 15, "ssh_status")
    return {"results": results}


@app.post("/api/ssh/harden")
async def ssh_harden(payload: SshHardenRequest, request: Request):
    app_ = request.app
    _require_pki(request)
    store = app_.state.store
    nodes = [n for n in (store.get_node(i) for i in payload.node_ids) if n]
    if not nodes:
        raise HTTPException(400, "no valid target nodes")
    mode = "on" if payload.password == "on" else "off"
    job_id = uuid.uuid4().hex
    store.record_job(job_id, "ssh_harden", json.dumps({"mode": mode, "nodes": len(nodes)}), len(nodes))

    async def one(node):
        # SAFETY GATE: never disable password auth unless a real key login is confirmed first
        if mode == "off":
            vok, detail = await ssh_verify_login(node)
            if not vok:
                res = {"ok": False, "verified": False,
                       "error": "key login not verified — skipped to avoid lockout (" + detail + ")"}
                return {"uid": node["uid"], "name": node["name"], "ok": False, "result": res}
        try:
            res = await agent_exec(app_, node, "ssh_harden", {"password": mode, "user": SSH_USER}, timeout=30)
            res["verified"] = True
            ok = bool(res.get("ok"))
        except Exception as e:
            res, ok = {"ok": False, "error": str(e)}, False
        return {"uid": node["uid"], "name": node["name"], "ok": ok, "result": res}

    results = await asyncio.gather(*[one(n) for n in nodes])
    for r in results:
        store.record_target(job_id, r["uid"], "done" if r["ok"] else "failed", None, json.dumps(r["result"]))
        store.audit("ui", "ssh_harden", job_id, r["uid"], json.dumps(r["result"]))
    ok_count = sum(1 for r in results if r["ok"])
    status = "done" if ok_count == len(results) else ("failed" if ok_count == 0 else "partial")
    store.finish_job(job_id, status)
    return {"job_id": job_id, "status": status, "results": results}


@app.post("/api/agent/update")
async def agent_update(payload: AgentUpdateRequest, request: Request):
    app_ = request.app
    _require_pki(request)
    store = app_.state.store
    nodes = [n for n in (store.get_node(i) for i in payload.node_ids) if n]
    if not nodes:
        raise HTTPException(400, "no valid target nodes")

    content, version, sha = local_agent_source()
    params = {"content": content, "sha256": sha, "restart": payload.restart}

    job_id = uuid.uuid4().hex
    store.record_job(job_id, "update_agent",
                     json.dumps({"version": version, "sha256": sha, "restart": payload.restart}),
                     len(nodes))

    async def run_one(node):
        try:
            res = await agent_exec(app_, node, "update_agent", params, timeout=30)
            ok = bool(res.get("ok", False))
        except Exception as e:
            res, ok = {"ok": False, "error": str(e)}, False
        store.record_target(job_id, node["uid"],
                            "done" if ok else "failed", None, json.dumps(res))
        store.audit("ui", "update_agent", job_id, node["uid"], json.dumps(res))
        return {"uid": node["uid"], "node_id": node["node_id"], "name": node["name"], "ok": ok, "result": res}

    results = await asyncio.gather(*[run_one(n) for n in nodes])
    ok_count = sum(1 for r in results if r["ok"])
    status = "done" if ok_count == len(results) else ("failed" if ok_count == 0 else "partial")
    store.finish_job(job_id, status)
    return {"job_id": job_id, "status": status, "version": version, "sha256": sha, "results": results}


def main():
    ap = argparse.ArgumentParser(prog="nym-maestro")
    ap.add_argument("--addr", default="127.0.0.1:7766", help="listen address (keep on localhost)")
    ap.add_argument("--db", default=default_db(), help="path to the SQLite database")
    args = ap.parse_args()
    os.environ["MAESTRO_DB"] = args.db
    host, _, port = args.addr.rpartition(":")

    import uvicorn
    uvicorn.run(app, host=host or "127.0.0.1", port=int(port))


if __name__ == "__main__":
    main()
