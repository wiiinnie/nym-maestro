"""Tests for the 1789 peer-scan, Nym topology harvest, and /api/peers geolocation."""
import asyncio
import copy
import os
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "agent"))

os.environ.setdefault("MAESTRO_DB", os.path.join(tempfile.mkdtemp(), "t.db"))
os.environ.setdefault("MAESTRO_PKI", os.path.join(tempfile.mkdtemp(), "pki"))
os.environ.setdefault("MAESTRO_SETTINGS", os.path.join(tempfile.mkdtemp(), "settings.json"))

import agent  # noqa: E402
agent.time.sleep = lambda *a, **k: None   # skip the 1s sampling window in tests
import app as A  # noqa: E402

_REAL_FETCH_TOPO = A.fetch_nym_topology  # capture before any monkeypatching

ok = fail = 0


def check(label, cond):
    global ok, fail
    if cond:
        ok += 1; print(f"  pass  {label}")
    else:
        fail += 1; print(f"  FAIL  {label}")


# --------------------------------------------------------------------------
# Agent: act_peers direction classification on the mix port
# --------------------------------------------------------------------------
SS = """Recv-Q Send-Q Local Address:Port Peer Address:Port
0      0      10.0.0.1:1789        5.5.5.5:40112
0      0      10.0.0.1:1789        5.5.5.5:40113
0      0      10.0.0.1:55001       6.6.6.6:1789
0      0      10.0.0.1:1789        7.7.7.7:33001
0      0      10.0.0.1:44002       7.7.7.7:1789
0      0      10.0.0.1:9000        8.8.8.8:50000
0      0      127.0.0.1:1789       127.0.0.1:40000
0      0      [2a01:4f8::1]:1789   [2a01:4f8::2]:51000
"""
agent._run = lambda cmd, **kw: (0, SS, "")
r = agent.act_peers({})
byip = {p["ip"]: p for p in r["peers"]}
check("peers total counts established mix conns", r["total_peers"] == 4 and r["total_conns"] == 6)
check("peer that dialed us is upstream (x2)", byip["5.5.5.5"]["dir"] == "up" and byip["5.5.5.5"]["conns"] == 2)
check("peer we dialed is downstream", byip["6.6.6.6"]["dir"] == "down")
check("peer connected both ways is 'both'", byip["7.7.7.7"]["dir"] == "both")
check("non-1789 connection excluded", "8.8.8.8" not in byip)
check("loopback excluded", "127.0.0.1" not in byip)
check("ipv6 peer parsed", byip.get("2a01:4f8::2", {}).get("dir") == "up")
check("ports param normalised to strings", agent.act_peers({"ports": [1789]})["ports"] == ["1789"])

# clients (9000/9001) captured separately from 1789 node peers
SS2 = """Recv-Q Send-Q Local Address:Port Peer Address:Port
0 0 10.0.0.1:1789 5.5.5.5:40112
0 0 10.0.0.1:55001 6.6.6.6:1789
0 0 10.0.0.1:9000 11.11.11.11:51000
0 0 10.0.0.1:9000 11.11.11.11:51001
0 0 10.0.0.1:9001 12.12.12.12:40000
0 0 10.0.0.1:8080 9.9.9.9:5000
"""
agent._run = lambda cmd, **kw: (0, SS2, "")
rc = agent.act_peers({})
check("upstream/downstream counted", rc["upstream"] == 1 and rc["downstream"] == 1)
check("clients captured on 9000/9001", rc["client_count"] == 2 and rc["client_conns"] == 3)
check("client on 8080 (non-client port) excluded", "9.9.9.9" not in [c["ip"] for c in rc["clients"]])
check("clients separate from node peers", rc["total_peers"] == 2)

# per-connection throughput/traffic (ss -i) + WireGuard sampling
SS_A = """0 0 10.0.0.1:1789 5.5.5.5:40112 cubic bytes_sent:1000 bytes_received:2000
0 0 10.0.0.1:9000 11.11.11.11:51000 cubic bytes_sent:100 bytes_received:900"""
SS_B = """0 0 10.0.0.1:1789 5.5.5.5:40112 cubic bytes_sent:1000 bytes_received:10000
0 0 10.0.0.1:9000 11.11.11.11:51000 cubic bytes_sent:100 bytes_received:1900"""
WG_A = "wg0\tPRIV\tPUB\t51822\toff\nwg0\tPK\t(none)\t77.77.77.77:51820\t10.0.0.2/32\t1700000000\t1000\t2000\t25"
WG_B = "wg0\tPRIV\tPUB\t51822\toff\nwg0\tPK\t(none)\t77.77.77.77:51820\t10.0.0.2/32\t1700000000\t6000\t4000\t25"
_seq = {"ss": [SS_A, SS_B], "wg": [WG_A, WG_B]}
agent._run = lambda cmd, **kw: (0, _seq[cmd[0]].pop(0), "") if cmd[0] in _seq and _seq[cmd[0]] else (0, "", "")
rm = agent.act_peers({})
pm = {p["ip"]: p for p in rm["peers"]}
check("peer traffic (cumulative bytes) reported", pm["5.5.5.5"]["bytes"] == 11000)
check("peer throughput sampled (>0)", pm["5.5.5.5"]["bps"] > 0)
check("peer duration tracked", "dur" in pm["5.5.5.5"])
check("wireguard endpoint captured", rm["wg_count"] == 1 and rm["wg_clients"][0]["ip"] == "77.77.77.77")
check("wireguard traffic = rx+tx", rm["wg_clients"][0]["bytes"] == 10000)
check("wireguard throughput sampled", rm["wg_clients"][0]["bps"] > 0)

agent._run = lambda cmd, **kw: (1, "", "ss: not found")
check("ss failure surfaces ok=False", agent.act_peers({})["ok"] is False)


# --------------------------------------------------------------------------
# Orchestrator: defensive topology harvest + ISO2 normalisation
# --------------------------------------------------------------------------
shape_described = {"data": [
    {"description": {"host_information": {"ip_address": ["1.2.3.4", "2.3.4.5"], "hostname": "de1.example"},
                     "auxiliary_details": {"location": "Germany"}}},
]}
shape_flat = [
    {"ip_addresses": ["9.9.9.9"], "country_code": "fr", "hostname": "fr1.example"},
    {"host": "8.8.8.8", "location": "United States"},
]
shape_nested = {"data": {"nodes": [
    {"bond_information": {"node": {"host": "5.5.5.5"}}, "location": "Czechia"},
]}}
shape_v6 = [
    {"host_information": {"ip_address": ["2a01:04f8:0:0:0:0:0:2"]}, "location": "Romania"},
]
m = {}
for s in (shape_described, shape_flat, shape_nested, shape_v6):
    A._harvest_nodes(s, m)
check("harvest cross-subtree (ip + country in different objects)",
      m.get("1.2.3.4", {}).get("cc") == "Germany" and m.get("2.3.4.5", {}).get("cc") == "Germany")
check("harvest captures hostname", m.get("1.2.3.4", {}).get("host") == "de1.example")
check("harvest flat list with country_code + hostname",
      m.get("9.9.9.9", {}).get("cc") == "fr" and m.get("9.9.9.9", {}).get("host") == "fr1.example")
check("harvest deeply nested host + location", m.get("5.5.5.5", {}).get("cc") == "Czechia")
check("harvest normalizes IPv6 (expanded -> compressed)",
      m.get("2a01:4f8::2", {}).get("cc") == "Romania")
check("iso2 from full name", A._iso2("Germany") == "DE" and A._iso2("United States") == "US")
check("iso2 from 2-letter code (any case)", A._iso2("fr") == "FR" and A._iso2("CZ") == "CZ")
check("iso2 unknown -> None", A._iso2("Atlantis") is None and A._iso2("") is None)


# --------------------------------------------------------------------------
# Orchestrator: /api/peers attaches country, direction, fleet + counts
# --------------------------------------------------------------------------
class FakeStore:
    def __init__(self, nodes):
        self._nodes = nodes

    def get_node(self, nid):
        for n in self._nodes:
            if nid in (n["uid"], n.get("node_id"), n["name"]):
                return n
        return None

    def list_nodes(self):
        return self._nodes

    def audit(self, *a, **k):
        pass


FLEET = [
    {"uid": "u-at01", "name": "AT01", "ip": "152.53.92.255", "node_id": "at01"},
    {"uid": "u-pl01", "name": "PL01", "ip": "54.37.138.191", "node_id": "pl01"},
    {"uid": "u-cz09", "name": "CZ09", "ip": "203.0.113.9", "node_id": "cz09"},
]

AGENT_RESULT = {
    "ok": True, "ports": ["1789"], "total_peers": 5, "total_conns": 11,
    "upstream": 3, "downstream": 2,
    "clients": [{"ip": "11.11.11.11", "conns": 2}, {"ip": "12.12.12.12", "conns": 1}],
    "client_count": 2, "client_conns": 3, "client_ports": ["9000", "9001"],
    "wg_clients": [{"ip": "13.13.13.13", "conns": 1, "bps": 500, "bytes": 9000, "dur": 60}],
    "wg_count": 1, "wg_available": True,
    "peers": [
        {"ip": "54.37.138.191", "conns": 3, "dir": "up"},    # fleet (PL01), in topology (no host -> name)
        {"ip": "203.0.113.9", "conns": 2, "dir": "down"},    # fleet (CZ09), NOT in topology -> name fallback
        {"ip": "77.77.77.77", "conns": 3, "dir": "both"},    # external, in topology (RO + host)
        {"ip": "88.88.88.88", "conns": 1, "dir": "down"},    # external, unknown -> unplaced
        {"ip": "2a01:04f8:0:0:0:0:0:2", "conns": 2, "dir": "up"},  # external IPv6 (expanded form)
    ],
}
TOPO = {
    "54.37.138.191": {"cc": "Poland"},
    "77.77.77.77": {"cc": "Romania", "host": "ro1.example"},
    "2a01:4f8::2": {"cc": "Romania", "host": "ro6.example"},  # keyed by compressed v6
}


def run_peers(agent_result, topo):
    async def fake_exec(app_, node, action, params=None, timeout=40):
        return copy.deepcopy(agent_result)

    async def fake_topo(force=False):
        return topo

    A.agent_exec = fake_exec
    A.fetch_nym_topology = fake_topo

    async def fake_ptr(ips):
        return {}
    A.resolve_ptr = fake_ptr
    store = FakeStore(FLEET)
    pki = types.SimpleNamespace(ready=lambda: True)
    state = types.SimpleNamespace(store=store, pki=pki)
    request = types.SimpleNamespace(app=types.SimpleNamespace(state=state))
    payload = A.PeersRequest(node_id="u-at01")
    return asyncio.run(A.api_peers(payload, request))


res = run_peers(AGENT_RESULT, TOPO)
byip = {p["ip"]: p for p in res["peers"]}
check("endpoint ok", res["ok"] is True)
check("external peer geolocated from topology", byip["77.77.77.77"].get("cc") == "RO")
check("external peer hostname attached", byip["77.77.77.77"].get("host") == "ro1.example")
check("fleet peer geolocated from topology", byip["54.37.138.191"].get("cc") == "PL")
check("fleet peer hostname falls back to node name",
      byip["54.37.138.191"].get("host") == "PL01" and byip["203.0.113.9"].get("host") == "CZ09")
check("fleet peer missing in topology falls back to name prefix",
      byip["203.0.113.9"].get("cc") == "CZ")
check("IPv6 peer normalized + geolocated",
      byip["2a01:04f8:0:0:0:0:0:2"].get("cc") == "RO"
      and byip["2a01:04f8:0:0:0:0:0:2"].get("host") == "ro6.example")
check("unknown external peer left unplaced", "cc" not in byip["88.88.88.88"])
check("located count = placeable peers", res["located"] == 4)
check("fleet_peers counts only other fleet nodes", res["fleet_peers"] == 2)
check("fleet match annotates node identity",
      byip["54.37.138.191"]["fleet"]["name"] == "PL01")
check("direction preserved through endpoint", byip["77.77.77.77"]["dir"] == "both")
check("topology_known True when map populated", res["topology_known"] is True)
check("totals passed through", res["total_peers"] == 5 and res["total_conns"] == 11)
check("upstream/downstream counts pass through", res["upstream"] == 3 and res["downstream"] == 2)
check("clients pass through endpoint",
      res["client_count"] == 2 and res["client_conns"] == 3 and len(res["clients"]) == 2)
check("client_ports pass through", res["client_ports"] == ["9000", "9001"])

# client geolocation enrichment (GeoIP) flows through the endpoint
_orig_geo = A.geolocate_ips


async def _fake_geo(ips):
    return {"11.11.11.11": {"cc": "US", "country": "United States", "city": "NYC", "lat": 40.7, "lon": -74.0},
            "13.13.13.13": {"cc": "JP", "city": "Tokyo", "lat": 35.6, "lon": 139.7}}


A.geolocate_ips = _fake_geo
res_geo = run_peers(AGENT_RESULT, TOPO)
A.geolocate_ips = _orig_geo
cby = {c["ip"]: c for c in res_geo["clients"]}
check("client geolocated through endpoint",
      cby["11.11.11.11"].get("cc") == "US" and cby["11.11.11.11"].get("lat") == 40.7)
check("ungeolocated client left without location", "cc" not in cby["12.12.12.12"])
check("client_located counts placed clients", res_geo["client_located"] == 1)
wgby = {w["ip"]: w for w in res_geo["wg_clients"]}
check("wireguard client passed through + geolocated",
      res_geo["wg_count"] == 1 and wgby["13.13.13.13"].get("cc") == "JP" and wgby["13.13.13.13"].get("lat") == 35.6)
check("wireguard metrics preserved",
      wgby["13.13.13.13"].get("bps") == 500 and wgby["13.13.13.13"].get("dur") == 60)
check("wg_available flag passes through", res_geo["wg_available"] is True)

# inbound peers missed by topology get placed via GeoIP fallback (with exact coords)
AGENT_INB = {
    "ok": True, "ports": ["1789"], "total_peers": 3, "total_conns": 3,
    "upstream": 2, "downstream": 1, "clients": [], "client_count": 0,
    "peers": [
        {"ip": "77.77.77.77", "conns": 1, "dir": "down"},      # topology -> RO (centroid)
        {"ip": "203.0.113.50", "conns": 1, "dir": "up"},       # not in topology -> GeoIP
        {"ip": "203.0.113.51", "conns": 1, "dir": "up"},       # not in topology -> GeoIP
    ],
}


async def _geo_inb(ips):
    g = {"203.0.113.50": {"cc": "US", "lat": 40.7, "lon": -74.0},
         "203.0.113.51": {"cc": "JP", "lat": 35.6, "lon": 139.7}}
    return {ip: g[ip] for ip in ips if ip in g}


A.geolocate_ips = _geo_inb
res_inb = run_peers(AGENT_INB, {"77.77.77.77": {"cc": "Romania"}})
A.geolocate_ips = _orig_geo
ibp = {p["ip"]: p for p in res_inb["peers"]}
check("inbound peer placed via GeoIP fallback",
      ibp["203.0.113.50"].get("cc") == "US" and ibp["203.0.113.50"].get("lat") == 40.7)
check("GeoIP-placed peer flagged geo=True", ibp["203.0.113.50"].get("geo") is True)
check("topology peer keeps centroid placement (no latlon)",
      ibp["77.77.77.77"].get("cc") == "RO" and ibp["77.77.77.77"].get("lat") is None)
check("all three placed after fallback", res_inb["located"] == 3)
check("placed split by direction", res_inb["located_up"] == 2 and res_inb["located_down"] == 1)

# IPv4-mapped IPv6 unwrap (v4 clients on a v6 socket)
check("unmap ::ffff: -> v4", A._unmap("::ffff:196.115.25.189") == "196.115.25.189")
check("unmap leaves plain v4/v6 alone",
      A._unmap("1.2.3.4") == "1.2.3.4" and A._unmap("2a01:4f8::2") == "2a01:4f8::2")

# runtime geoip mode persists and is reloadable
A.set_geoip_mode("ipapi")
check("geoip mode set + read", A._geoip_mode() == "ipapi")
import json as _json
check("geoip mode persisted to disk",
      _json.load(open(os.environ["MAESTRO_SETTINGS"]))["geoip"] == "ipapi")
check("reverse DNS gated off when location off",
      (A.set_geoip_mode("off") or True) and asyncio.run(A.resolve_ptr(["8.8.8.8"])) == {})
A.set_geoip_mode("off")

# topology offline: fleet peers still resolve via name fallback, externals unplaced
res2 = run_peers(AGENT_RESULT, {})
byip2 = {p["ip"]: p for p in res2["peers"]}
check("topology offline flagged", res2["topology_known"] is False)
check("fleet peers still placed when topology offline",
      byip2["54.37.138.191"].get("cc") == "PL" and byip2["203.0.113.9"].get("cc") == "CZ")
check("external peers unplaced when topology offline",
      "cc" not in byip2["77.77.77.77"] and res2["located"] == 2)


# --------------------------------------------------------------------------
# Orchestrator: topology fetch follows pagination to get the whole network
# --------------------------------------------------------------------------
def _tnode(ip, cc):
    return {"description": {"host_information": {"ip_address": [ip]},
                            "auxiliary_details": {"location": cc}}}


PAGES = {
    0: {"pagination": {"total": 5, "page": 0, "size": 2}, "data": [_tnode("1.1.1.1", "DE"), _tnode("2.2.2.2", "FR")]},
    1: {"pagination": {"total": 5, "page": 1, "size": 2}, "data": [_tnode("3.3.3.3", "PL"), _tnode("4.4.4.4", "IT")]},
    2: {"pagination": {"total": 5, "page": 2, "size": 2}, "data": [_tnode("5.5.5.5", "ES")]},
}


class _FakeResp:
    def __init__(self, p):
        self._p = p

    def raise_for_status(self):
        pass

    def json(self):
        return self._p


class _FakeClient:
    def __init__(self, *a, **k):
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url):
        self.calls.append(url)
        import re as _re
        mm = _re.search(r"page=(\d+)", url)
        return _FakeResp(PAGES[int(mm.group(1)) if mm else 0])


_calls = []
_orig_client = A.httpx.AsyncClient
A.httpx.AsyncClient = lambda *a, **k: _calls.append(_FakeClient()) or _calls[-1]
A.NYM_TOPOLOGY_URLS = ["http://x/api/v1/nym-nodes/described"]
A._NYM_TOPO_CACHE = {"at": 0.0, "map": {}}
_topo = asyncio.run(_REAL_FETCH_TOPO(force=True))
A.httpx.AsyncClient = _orig_client
check("pagination harvests every page", len(_topo) == 5 and _topo["5.5.5.5"]["cc"] == "ES")
check("pagination requests subsequent pages",
      any("page=1" in u for u in _calls[0].calls) and any("page=2" in u for u in _calls[0].calls))


print(f"\n{ok} passed, {fail} failed")
sys.exit(1 if fail else 0)
