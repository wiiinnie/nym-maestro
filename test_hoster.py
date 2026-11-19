"""Tests for the per-node VPS hoster (hoster.py + store + refresh_hosters).
No network: RIPEstat answers are faked. Run: .venv/bin/python test_hoster.py
"""
import asyncio
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("MAESTRO_HOSTER_POLL", "0")
import hoster  # noqa: E402

ok = fail = 0


def check(label, cond):
    global ok, fail
    if cond:
        ok += 1; print(f"  pass  {label}")
    else:
        fail += 1; print(f"  FAIL  {label}")


print("\nparsing + naming:")
check("network-info: asn + prefix",
      hoster.parse_network_info({"data": {"asns": ["16276"], "prefix": "141.227.186.0/24"}})
      == (16276, "141.227.186.0/24"))
check("network-info: no asn -> (None, prefix)",
      hoster.parse_network_info({"data": {"asns": [], "prefix": "10.0.0.0/8"}}) == (None, "10.0.0.0/8"))
check("network-info: garbage -> (None, None)",
      hoster.parse_network_info({"nope": 1}) == (None, None)
      and hoster.parse_network_info(None) == (None, None))
check("as-overview: holder", hoster.parse_as_overview({"data": {"holder": " OVH OVH SAS "}}) == "OVH OVH SAS")
check("as-overview: missing -> None", hoster.parse_as_overview({"data": {}}) is None)

# the fleet as RIPEstat reported it on 2026-11-19
FLEET = {
    (16276, "OVH OVH SAS"): "OVH",
    (24940, "HETZNER-AS Hetzner Online GmbH"): "Hetzner",
    (197540, "netcup-AS netcup GmbH"): "netcup",
    (41075, "ATW-AS ATW Internet Kft."): "ATW",
    (200019, "AlexHost ALEXHOST S.R.L."): "AlexHost",
    (56655, "GIGAHOST Gigahost AS"): "Gigahost",
    (48881, "DATANODE DataNode DC SRL"): "DataNode",
}
for (asn, holder), want in FLEET.items():
    check(f"AS{asn} -> {want}", hoster.short_name(asn, holder) == want)
check("unknown ASN of a known hoster -> holder hint",
      hoster.short_name(99999, "OVH-CA OVH Hosting Inc.") == "OVH")
check("unknown hoster -> cleaned holder (handle + legal form dropped)",
      hoster.short_name(64500, "EXAMPLE-AS Example Cloud GmbH") == "Example Cloud")
check("holder without handle kept", hoster.short_name(64501, "Acme Networks Ltd") == "Acme Networks")
check("no holder -> AS number", hoster.short_name(64502, None) == "AS64502")
check("abuse provider names match (OVH, Hetzner, ATW)",
      {"OVH", "Hetzner", "ATW"} <= set(hoster.KNOWN_ASNS.values()))
check("URLs carry the IP / ASN and sourceapp",
      "resource=141.227.186.52" in hoster.network_info_url("141.227.186.52")
      and "resource=AS16276" in hoster.as_overview_url(16276)
      and "sourceapp=nym-maestro" in hoster.network_info_url("1.1.1.1"))

print("\nlookup policy:")
check("public IP looked up", hoster.is_public_ip("141.227.186.52"))
check("private / doc / garbage IPs never looked up",
      not any(hoster.is_public_ip(x) for x in ("10.0.0.1", "127.0.0.1", "203.0.113.5",
                                               "192.168.1.1", "", None, "nym-exit")))
now = time.time()
fresh = {"ip": "1.2.3.4", "hoster": {"name": "OVH", "ip": "1.2.3.4", "checked_at": now - 3600}}
check("fresh entry -> no lookup", hoster.needs_lookup(fresh, now) is False)
check("no entry -> lookup", hoster.needs_lookup({"ip": "1.2.3.4", "hoster": None}, now))
check("IP changed -> lookup",
      hoster.needs_lookup(dict(fresh, ip="5.6.7.8"), now))
check("older than a week -> lookup",
      hoster.needs_lookup(fresh, now + hoster.MAX_AGE_S + 1))
check("last attempt failed -> lookup",
      hoster.needs_lookup({"ip": "1.2.3.4", "hoster": dict(fresh["hoster"], error="x")}, now))

print("\nstore + refresh:")
import app as appmod  # noqa: E402
import store as storemod  # noqa: E402

d = tempfile.mkdtemp()
st = storemod.Store(os.path.join(d, "t.db"), (ROOT / "schema.sql").read_text())
u1 = st.create_node({"node_id": "nym-exit-be01", "name": "BE01", "ip": "141.227.186.52"})
u2 = st.create_node({"node_id": "nym-exit-hu01", "name": "HU01", "ip": "37.221.208.97"})
u3 = st.create_node({"node_id": "lab", "name": "LAB", "ip": "10.0.0.9"})

ANSWERS = {
    "141.227.186.52": ({"data": {"asns": ["16276"], "prefix": "141.227.186.0/24"}},
                       {"data": {"holder": "OVH OVH SAS"}}),
    "37.221.208.97": ({"data": {"asns": ["41075"], "prefix": "37.221.208.0/22"}},
                      {"data": {"holder": "ATW-AS ATW Internet Kft."}}),
    "46.62.247.165": ({"data": {"asns": ["24940"], "prefix": "46.62.128.0/17"}},
                      {"data": {"holder": "HETZNER-AS Hetzner Online GmbH"}}),
}
CALLS = []
DOWN = {"on": False}


class _R:
    def __init__(self, payload): self._p = payload
    def raise_for_status(self):
        if DOWN["on"]:
            raise RuntimeError("down")
    def json(self): return self._p


class _Client:
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False

    async def get(self, url, headers=None):
        CALLS.append(url)
        for ip, (ni, ao) in ANSWERS.items():
            if f"resource={ip}&" in url:
                return _R(ni)
        if "as-overview" in url:
            asn = url.split("resource=AS")[1].split("&")[0]
            for ni, ao in ANSWERS.values():
                if ni["data"]["asns"][0] == asn:
                    return _R(ao)
        return _R({"data": {"asns": []}})


appmod.httpx.AsyncClient = lambda **kw: _Client()


class _App:
    class state:
        pass
_App.state.store = st

r = asyncio.run(appmod.refresh_hosters(_App))
check("refresh: two public nodes looked up, private one skipped",
      r["checked"] == 2 and r["ok"] == 2
      and not any("10.0.0.9" in c for c in CALLS))
n1, n2, n3 = st.get_node(u1), st.get_node(u2), st.get_node(u3)
check("BE01 -> OVH with ASN/holder/prefix/ip",
      n1["hoster"]["name"] == "OVH" and n1["hoster"]["asn"] == 16276
      and n1["hoster"]["holder"] == "OVH OVH SAS" and n1["hoster"]["prefix"] == "141.227.186.0/24"
      and n1["hoster"]["ip"] == "141.227.186.52" and n1["hoster"]["error"] is None)
check("HU01 -> ATW", n2["hoster"]["name"] == "ATW")
check("private node has no hoster entry", n3["hoster"] is None)
check("list_nodes carries hoster too",
      {n["name"]: (n["hoster"] or {}).get("name") for n in st.list_nodes()}
      == {"BE01": "OVH", "HU01": "ATW", "LAB": None})

CALLS.clear()
r = asyncio.run(appmod.refresh_hosters(_App))
check("second pass: everything fresh, no requests", r["checked"] == 0 and not CALLS)

DOWN["on"] = True
r = asyncio.run(appmod.refresh_hosters(_App, force=True))
n1 = st.get_node(u1)
check("failed refresh keeps the last hoster, records the error",
      n1["hoster"]["name"] == "OVH" and n1["hoster"]["error"])
DOWN["on"] = False

st.update_node(u1, {"ip": "46.62.247.165"})
check("IP change -> needs lookup", hoster.needs_lookup(st.get_node(u1), time.time()))
DOWN["on"] = True
asyncio.run(appmod.refresh_hosters(_App))
check("failed lookup for a NEW IP clears the old hoster (no stale OVH)",
      st.get_node(u1)["hoster"]["name"] is None and st.get_node(u1)["hoster"]["ip"] == "46.62.247.165")
DOWN["on"] = False
asyncio.run(appmod.refresh_hosters(_App))
check("next pass resolves the moved node", st.get_node(u1)["hoster"]["name"] == "Hetzner")

st.delete_node(u2) if hasattr(st, "delete_node") else None
check("hoster row goes with the node (FK cascade)",
      st.db.execute("SELECT count(*) FROM node_hoster WHERE uid = ?", (u2,)).fetchone()[0]
      == (0 if hasattr(st, "delete_node") else 1))

print(f"\n{ok} passed, {fail} failed")
raise SystemExit(1 if fail else 0)
