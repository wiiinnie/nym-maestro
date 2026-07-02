#!/usr/bin/env python3
"""Bulk-add nodes to a running nym maestro from a CSV.

Use this to rebuild the registry quickly (e.g. after restoring without a DB
backup). Your CA/certs are unchanged, so re-added nodes reconnect on the next
poll — no re-enrollment needed.

CSV: a header row, then one node per line. Recognised columns (any order):
    name        (required)  e.g. AT01
    ip          (required)  e.g. 152.53.92.255
    hostname    (optional)  e.g. nym-exit-at01.hermes-stakepool.de
    node_id     (optional)  defaults to "default-nym-node"
    agent_port  (optional)  defaults to 8443
    notes       (optional)

Example:
    name,ip,hostname
    AT01,152.53.92.255,nym-exit-at01.hermes-stakepool.de
    AT02,188.172.228.15,nym-exit-at02.hermes-stakepool.de

Usage:
    python seed_nodes.py nodes.csv
    python seed_nodes.py nodes.csv --base http://127.0.0.1:7766
"""
import argparse
import csv
import json
import sys
import urllib.error
import urllib.request


def post(base, node):
    data = json.dumps(node).encode()
    req = urllib.request.Request(base + "/api/nodes", data=data,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        try:
            body = json.loads(body).get("error", body)
        except Exception:
            pass
        return e.code, body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", help="CSV file of nodes")
    ap.add_argument("--base", default="http://127.0.0.1:7766",
                    help="orchestrator base URL (default: %(default)s)")
    args = ap.parse_args()

    added = skipped = failed = 0
    with open(args.csv, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
            name, ip = row.get("name"), row.get("ip")
            if not name or not ip:
                print(f"  skip   (missing name/ip): {row}")
                skipped += 1
                continue
            node = {
                "node_id": row.get("node_id") or "default-nym-node",
                "name": name,
                "ip": ip,
                "hostname": row.get("hostname", ""),
                "agent_port": int(row["agent_port"]) if row.get("agent_port") else 8443,
                "notes": row.get("notes", ""),
                "enabled": True,
            }
            status, body = post(args.base, node)
            if status == 201:
                print(f"  added  {name} ({ip})")
                added += 1
            elif status == 409:
                print(f"  exists {name}: {body}")
                skipped += 1
            else:
                print(f"  FAIL   {name}: HTTP {status} — {body}")
                failed += 1

    print(f"\nadded {added}, skipped {skipped}, failed {failed}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
