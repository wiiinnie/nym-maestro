import os
import tempfile

os.environ["MAESTRO_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")

from fastapi.testclient import TestClient
import app as appmod

ok = 0
fail = 0


def check(label, cond):
    global ok, fail
    if cond:
        ok += 1
        print(f"  pass  {label}")
    else:
        fail += 1
        print(f"  FAIL  {label}")


with TestClient(appmod.app) as c:
    # health
    r = c.get("/api/health")
    check("health 200 + version", r.status_code == 200 and r.json()["version"] == appmod.VERSION)

    # index served
    r = c.get("/")
    check("index html served", r.status_code == 200 and b"nym maestro" in r.content)

    # empty list
    r = c.get("/api/nodes")
    check("nodes empty initially", r.status_code == 200 and r.json() == [])

    # create
    r = c.post("/api/nodes", json={
        "node_id": "default-nym-node", "name": "CH01", "ip": "51.83.0.1",
        "hostname": "ch01.hermes", "agent_port": 8443, "notes": "swiss exit",
        "enabled": True,
    })
    check("create 201", r.status_code == 201)
    body = r.json()
    check("create returns view", body["name"] == "CH01" and body["status"] is None)
    check("create returns a uid", bool(body.get("uid")))
    check("create hostname stored", body["hostname"] == "ch01.hermes")
    uid1 = body["uid"]

    # missing required field
    r = c.post("/api/nodes", json={"node_id": "x", "name": "", "ip": "1.2.3.4"})
    check("create rejects blank name (400 + error shape)",
          r.status_code == 400 and "error" in r.json())

    # duplicate name -> 409
    r = c.post("/api/nodes", json={"node_id": "other-id", "name": "CH01", "ip": "9.9.9.9"})
    check("duplicate name 409", r.status_code == 409 and "error" in r.json())

    # SAME node_id, different name+ip -> ALLOWED (the whole point: default-nym-node repeats)
    r = c.post("/api/nodes", json={
        "node_id": "default-nym-node", "name": "CH02", "ip": "141.227.149.187"})
    check("duplicate node_id is allowed", r.status_code == 201)
    uid2 = r.json()["uid"]
    check("the two share node_id but differ in uid",
          r.json()["node_id"] == "default-nym-node" and uid2 != uid1)

    # same ip+port -> 409 (the real 'same node twice' guard)
    r = c.post("/api/nodes", json={
        "node_id": "default-nym-node", "name": "DUP", "ip": "51.83.0.1", "agent_port": 8443})
    check("duplicate ip:port 409", r.status_code == 409)

    # list now has two
    r = c.get("/api/nodes")
    check("list has two nodes", len(r.json()) == 2)

    # get one by uid
    r = c.get("/api/nodes/" + uid1)
    check("get by uid 200", r.status_code == 200 and r.json()["ip"] == "51.83.0.1")
    r = c.get("/api/nodes/nope")
    check("get missing 404", r.status_code == 404)

    # patch partial (ip + disable)
    r = c.patch("/api/nodes/" + uid1, json={"ip": "51.83.9.9", "enabled": False})
    check("patch 200", r.status_code == 200)
    check("patch updated ip", r.json()["ip"] == "51.83.9.9")
    check("patch updated enabled", r.json()["enabled"] is False)

    # node_id is now an editable label
    r = c.patch("/api/nodes/" + uid1, json={"node_id": "hermes-gateway-ch"})
    check("patch can change node_id", r.status_code == 200 and r.json()["node_id"] == "hermes-gateway-ch")

    # clear nullable field via empty string
    r = c.patch("/api/nodes/" + uid1, json={"hostname": ""})
    check("patch clears hostname to empty", r.json()["hostname"] == "")

    # patch missing -> 404
    r = c.patch("/api/nodes/nope", json={"ip": "1.1.1.1"})
    check("patch missing 404", r.status_code == 404)

    # sort order by name
    r = c.get("/api/nodes")
    names = [n["name"] for n in r.json()]
    check("sorted by name", names == ["CH01", "CH02"])

    # delete by uid
    r = c.delete("/api/nodes/" + uid1)
    check("delete 204", r.status_code == 204)
    r = c.delete("/api/nodes/" + uid1)
    check("delete again 404", r.status_code == 404)
    r = c.get("/api/nodes")
    check("one node remains", len(r.json()) == 1)

print(f"\n{ok} passed, {fail} failed")
raise SystemExit(1 if fail else 0)
