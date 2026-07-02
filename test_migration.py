"""Migration test: an existing pre-uid DB (node_id was the PRIMARY KEY) is
migrated in place on open — registry + agent_fp pins preserved, fresh uids
assigned, and the new uid-keyed constraints become active."""
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import store  # noqa: E402

ok = fail = 0


def check(label, cond):
    global ok, fail
    if cond:
        ok += 1; print(f"  pass  {label}")
    else:
        fail += 1; print(f"  FAIL  {label}")


d = tempfile.mkdtemp()
dbp = os.path.join(d, "old.db")

con = sqlite3.connect(dbp)
con.executescript("""
CREATE TABLE nodes (node_id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, ip TEXT NOT NULL,
  hostname TEXT, agent_port INTEGER NOT NULL DEFAULT 8443, agent_fp TEXT, service_name TEXT,
  binary_path TEXT, notes TEXT, enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE node_status (node_id TEXT PRIMARY KEY REFERENCES nodes(node_id));
""")
con.execute("INSERT INTO nodes (node_id,name,ip,hostname,agent_port,agent_fp,enabled) VALUES (?,?,?,?,?,?,1)",
            ("hermes-gateway-at", "AT01", "152.53.92.255", "at01.h", 8443, "DEADBEEF"))
con.execute("INSERT INTO nodes (node_id,name,ip,hostname,agent_port,agent_fp,enabled) VALUES (?,?,?,?,?,?,1)",
            ("default-nym-node", "AT02", "188.172.228.15", "at02.h", 8443, "CAFE1234"))
con.commit(); con.close()

schema = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")).read()
st = store.Store(dbp, schema)   # migrates on open
nodes = st.list_nodes()

check("both nodes preserved", len(nodes) == 2)
check("each got a uid", all(n.get("uid") for n in nodes))
check("uids are distinct", len({n["uid"] for n in nodes}) == 2)
check("agent_fp pins preserved",
      {n["name"]: n["agent_fp"] for n in nodes} == {"AT01": "DEADBEEF", "AT02": "CAFE1234"})
check("node_ids preserved verbatim",
      {n["name"]: n["node_id"] for n in nodes} == {"AT01": "hermes-gateway-at", "AT02": "default-nym-node"})

st.upsert_status(nodes[0]["uid"], reachable=True, version="1.34.0", wireguard=True)
g = st.get_node(nodes[0]["uid"])
check("status writes by uid after migration", g["status"]["version"] == "1.34.0")

st.close()
st2 = store.Store(dbp, schema)
check("second open is a no-op", len(st2.list_nodes()) == 2)
st2.close()

print(f"\n{ok} passed, {fail} failed")
raise SystemExit(1 if fail else 0)
