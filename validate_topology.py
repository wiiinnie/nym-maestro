#!/usr/bin/env python3
"""
Validate the Nym topology endpoints and the maestro geolocation parser BEFORE
deploying. Stdlib only — no venv needed.

What it does:
  1. Probes each candidate topology endpoint (status, size, top-level shape).
  2. Runs the SAME parser maestro uses (imported from app.py if present, else an
     identical embedded copy) and reports how many IP->country mappings it found.
  3. Cross-checks against YOUR fleet IPs (read from recovery_nodes.csv if present,
     plus any IPs you pass as arguments) — the ground-truth test: does AT01's IP
     resolve to AT, PL01's to PL, etc.?
  4. Dumps one raw node record so we can fix the parser to the exact shape if the
     mapping count comes back low.

Usage:
    python3 validate_topology.py
    python3 validate_topology.py 152.53.92.255 54.37.138.191   # extra fleet IPs
"""
import csv
import json
import os
import re
import ssl
import sys
import urllib.request

ENDPOINTS = [
    "https://validator.nymtech.net/api/v1/nym-nodes/described",
    "https://validator.nymtech.net/api/v1/gateways",
    "https://validator.nymtech.net/api/v1/mixnodes/active",
]

# ---- parser: use production code if importable, else an identical copy --------
PARSER_SRC = "embedded copy (identical to app.py)"
try:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from app import _harvest_nodes, _iso2, _norm_ip  # noqa: F401
    PARSER_SRC = "app.py (live production parser)"
except Exception:
    import ipaddress
    _IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
    _HEX6 = set("0123456789abcdefABCDEF:.")
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

    def _norm_ip(s):
        try:
            return ipaddress.ip_address(s.strip()).compressed
        except Exception:
            return None

    def _maybe_ip(s):
        if _IPV4_RE.match(s):
            return _norm_ip(s)
        if ":" in s and s and all(c in _HEX6 for c in s):
            return _norm_ip(s)
        return None

    def _node_info(node):
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

    def _iso2(country):
        if not country:
            return None
        c = country.strip()
        if len(c) == 2 and c.isalpha():
            return c.upper()
        return _COUNTRY_NAME_TO_ISO2.get(c.lower())


def fetch(url, timeout=25):
    req = urllib.request.Request(url, headers={
        "User-Agent": "curl/8.0", "Accept": "application/json"})
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            raw = r.read()
            return r.status, raw, None
    except urllib.error.HTTPError as e:
        return e.code, e.read() if hasattr(e, "read") else b"", str(e)
    except Exception as e:
        return None, b"", str(e)


def shape(obj):
    if isinstance(obj, dict):
        return "dict keys: " + ", ".join(list(obj.keys())[:12])
    if isinstance(obj, list):
        inner = obj[0] if obj and isinstance(obj[0], dict) else None
        return f"list[{len(obj)}]" + (
            " of dict keys: " + ", ".join(list(inner.keys())[:12]) if inner else "")
    return type(obj).__name__


def first_record(obj):
    if isinstance(obj, list) and obj:
        return obj[0]
    if isinstance(obj, dict):
        for k in ("nodes", "data", "gateways", "mixnodes", "result", "items"):
            v = obj.get(k)
            if isinstance(v, list) and v:
                return v[0]
            if isinstance(v, dict):
                for vv in v.values():
                    if isinstance(vv, list) and vv:
                        return vv[0]
        for v in obj.values():
            r = first_record(v)
            if r is not None:
                return r
    return None


def load_fleet_ips():
    """name -> ip from recovery_nodes.csv (best effort)."""
    fleet = {}
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "recovery_nodes.csv")
    if os.path.exists(path):
        try:
            with open(path, newline="") as f:
                rdr = csv.DictReader(f)
                for row in rdr:
                    low = {(k or "").strip().lower(): (v or "").strip()
                           for k, v in row.items()}
                    name = low.get("name") or low.get("node") or ""
                    ip = low.get("ip") or low.get("address") or low.get("public_ip") or ""
                    if ip:
                        fleet[ip] = name
        except Exception as e:
            print(f"  (could not read recovery_nodes.csv: {e})")
    return fleet


def main():
    print(f"Parser source: {PARSER_SRC}\n")
    best = (None, {}, 0)  # url, map, count

    for url in ENDPOINTS:
        print("=" * 78)
        print("GET", url)
        status, raw, err = fetch(url)
        print(f"  status: {status}   bytes: {len(raw):,}" + (f"   error: {err}" if err else ""))
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except Exception as e:
            print(f"  not JSON: {e}")
            print("  first 200 bytes:", raw[:200])
            continue
        print("  shape:", shape(obj))
        mp = {}
        _harvest_nodes(obj, mp)
        print(f"  parser extracted {len(mp)} IP->country mappings")
        if mp:
            for ip, rec in list(mp.items())[:5]:
                cc = rec.get("cc"); host = rec.get("host") or ""
                print(f"    {ip:<18} {cc!r:<8} -> ISO2 {_iso2(cc)!s:<4} {host}")
        rec = first_record(obj)
        if rec is not None and len(mp) == 0:
            dump = json.dumps(rec, indent=2)[:1600]
            print("  ** 0 mappings — raw first record (send this back to fix the parser): **")
            print("  " + dump.replace("\n", "\n  "))
        elif rec is not None:
            has_ll = "latitude" in json.dumps(rec)
            print(f"  (record carries lat/lng: {has_ll} — exact placement possible later)")
        if len(mp) > best[2]:
            best = (url, mp, len(mp))

    print("=" * 78)
    if not best[0]:
        print("VERDICT: no endpoint returned usable data. Check connectivity / endpoint paths.")
        return
    url, mp, n = best
    print(f"BEST endpoint: {url}  ({n} mappings)\n")

    fleet = load_fleet_ips()
    for ip in sys.argv[1:]:
        fleet.setdefault(ip, "(arg)")
    if not fleet:
        print("Fleet cross-check skipped (no recovery_nodes.csv found, no IPs passed).")
        print("Re-run with your IPs, e.g.:  python3 validate_topology.py 152.53.92.255 54.37.138.191")
        return

    print("Fleet ground-truth cross-check (resolved vs. expected from node name):")
    hits = miss = 0
    for ip, name in sorted(fleet.items(), key=lambda kv: kv[1]):
        rec = mp.get(_norm_ip(ip) or ip) or mp.get(ip)
        cc = _iso2(rec.get("cc")) if rec else None
        expect = name[:2].upper() if name and name[:2].isalpha() else None
        if cc is None:
            mark = "NOT IN TOPOLOGY"
            miss += 1
        elif expect and cc != expect:
            mark = f"MISMATCH (expected {expect})"
            miss += 1
        else:
            mark = "ok"
            hits += 1
        print(f"  {name:<8} {ip:<18} -> {str(cc):<5} {mark}")
    print(f"\n  {hits} resolved correctly, {miss} missing/mismatch out of {len(fleet)}")
    print("\nIf your own nodes resolve to the right countries, the endpoint + parser are good to deploy.")


if __name__ == "__main__":
    main()
