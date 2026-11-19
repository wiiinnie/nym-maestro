"""Orchestrator side of the maestro-managed blocklist: seed, validation endpoints,
save semantics and what rollout sends to agents (incl. the old-agent gate).
No network, no agents: agent_exec is faked. Run: .venv/bin/python test_blocklist.py
"""
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
os.environ["MAESTRO_DB"] = os.path.join(tempfile.mkdtemp(), "t.db")
for k in ("MAESTRO_POLL", "MAESTRO_NYX_POLL", "MAESTRO_HOSTER_POLL", "MAESTRO_ONWIRE_POLL",
          "MAESTRO_HISTORY_POLL"):
    os.environ[k] = "0"

from fastapi.testclient import TestClient  # noqa: E402
import app as appmod  # noqa: E402
import blocklist  # noqa: E402

ok = fail = 0


def check(label, cond):
    global ok, fail
    if cond:
        ok += 1; print(f"  pass  {label}")
    else:
        fail += 1; print(f"  FAIL  {label}")


SENT = []


async def fake_exec(app_, node, action, params=None, timeout=40):
    SENT.append((node["name"], action, params))
    return {"ok": True, "mode": "install-only", "applied_now": True}

appmod.agent_exec = fake_exec


class _PKI:
    def ready(self): return True


print("\nblocklist API:")
with TestClient(appmod.app, base_url="http://127.0.0.1") as c:
    appmod.app.state.pki = _PKI()
    st = appmod.app.state.store

    g = c.get("/api/blocklist").json()
    seed = (ROOT / "blocklist.txt").read_text()
    check("first GET seeds from the repo blocklist.txt (6 entries, comments kept)",
          g["text"] == seed and g["count"] == 6 and g["valid"] and g["v6"] == 1)
    check("seed persisted in app_config", st.get_config(blocklist.BLOCKLIST_KEY) == seed)

    r = c.post("/api/blocklist/check", json={"text": "1.2.3.4\nbogus\n0.0.0.0/0\n"})
    j = r.json()
    check("check: marks invalid + too-broad lines by number, saves nothing",
          r.status_code == 200 and [e["line"] for e in j["errors"]] == [2, 3]
          and st.get_config(blocklist.BLOCKLIST_KEY) == seed)

    r = c.put("/api/blocklist", json={"text": "1.2.3.4\n10.0.0.5/24\n"})
    check("PUT with an invalid line -> 400, nothing saved",
          r.status_code == 400 and r.json()["errors"][0]["line"] == 2
          and st.get_config(blocklist.BLOCKLIST_KEY) == seed)

    new_text = "# test list\n185.195.236.172\n198.51.100.0/24  # range\n2001:db8::/48\n"
    r = c.put("/api/blocklist", json={"text": new_text})
    j = r.json()
    check("PUT valid list -> saved verbatim, summary returned",
          r.status_code == 200 and j["count"] == 3 and st.get_config(blocklist.BLOCKLIST_KEY) == new_text
          and j["sha"] == blocklist.list_sha(["185.195.236.172/32", "198.51.100.0/24", "2001:db8::/48"]))

    # rollout
    new_uid = st.create_node({"node_id": "nym-exit-de02", "name": "DE02", "ip": "198.51.100.10"})
    old_uid = st.create_node({"node_id": "nym-exit-xx01", "name": "XX01", "ip": "203.0.113.20"})
    st.upsert_status(new_uid, reachable=True, agent_version="0.12.9", exit=True)
    st.upsert_status(old_uid, reachable=True, agent_version="0.12.8", exit=True)
    SENT.clear()
    r = c.post("/api/extra-blocks/install", json={"node_ids": [new_uid, old_uid], "restart_node": False})
    j = r.json()
    check("rollout sends the SAVED list (canonical entries) to the new agent",
          SENT == [("DE02", "extra_blocks_install",
                    {"restart_node": False,
                     "entries": ["185.195.236.172/32", "198.51.100.0/24", "2001:db8::/48"]})])
    old = [x for x in j["results"] if x["name"] == "XX01"][0]
    check("old agent (0.12.8) is skipped with an update hint, never sent the request",
          old["ok"] is False and "0.12.9" in old["result"]["error"] and j["status"] == "partial")
    check("rollout reports the list fingerprint", j["list_sha"] == blocklist.list_sha(
          ["185.195.236.172/32", "198.51.100.0/24", "2001:db8::/48"]))

    SENT.clear()
    r = c.post("/api/extra-blocks/install", json={"node_ids": [new_uid], "list_url": "https://evil/x"})
    check("a list_url in the request is ignored (no URL ever reaches an agent)",
          r.status_code == 200 and SENT and "list_url" not in SENT[0][2])
    r = c.post("/api/extra-blocks/install-script", json={"node_ids": [new_uid]})
    check("'Run installer' endpoint is gone", r.status_code in (404, 405))

    # empty list is allowed (removes all blocks)
    c.put("/api/blocklist", json={"text": "# nothing blocked\n"})
    SENT.clear()
    c.post("/api/extra-blocks/install", json={"node_ids": [new_uid]})
    check("empty saved list rolls out as entries=[]", SENT and SENT[0][2]["entries"] == [])

    check("version compare is numeric (0.12.10 > 0.12.9)",
          appmod._vtuple("0.12.10") > appmod._vtuple("0.12.9") and appmod._vtuple(None) < (0, 12, 9))

print(f"\n{ok} passed, {fail} failed")
raise SystemExit(1 if fail else 0)
