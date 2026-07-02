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
        "node_id": "ch01-id", "name": "CH01", "ip": "51.83.0.1",
        "hostname": "ch01.hermes", "agent_port": 8443, "notes": "swiss exit",
        "enabled": True,
    })
    check("create 201", r.status_code == 201)
    body = r.json()
    check("create returns view", body["name"] == "CH01" and body["status"] is None)
    check("create hostname stored", body["hostname"] == "ch01.hermes")

    # missing required field
    r = c.post("/api/nodes", json={"node_id": "x", "name": "", "ip": "1.2.3.4"})
    check("create rejects blank name (400 + error shape)",
          r.status_code == 400 and "error" in r.json())

    # duplicate name -> 409
    r = c.post("/api/nodes", json={"node_id": "other-id", "name": "CH01", "ip": "9.9.9.9"})
    check("duplicate name 409", r.status_code == 409 and "error" in r.json())

    # duplicate node_id -> 409
    r = c.post("/api/nodes", json={"node_id": "ch01-id", "name": "OTHER", "ip": "9.9.9.9"})
    check("duplicate node_id 409", r.status_code == 409)

    # list now has one
    r = c.get("/api/nodes")
    check("list has one node", len(r.json()) == 1)

    # get one
    r = c.get("/api/nodes/ch01-id")
    check("get by id 200", r.status_code == 200 and r.json()["ip"] == "51.83.0.1")
    r = c.get("/api/nodes/nope")
    check("get missing 404", r.status_code == 404)

    # patch partial (ip + disable), node_id untouched
    r = c.patch("/api/nodes/ch01-id", json={"ip": "51.83.9.9", "enabled": False})
    check("patch 200", r.status_code == 200)
    check("patch updated ip", r.json()["ip"] == "51.83.9.9")
    check("patch updated enabled", r.json()["enabled"] is False)

    # clear nullable field via empty string
    r = c.patch("/api/nodes/ch01-id", json={"hostname": ""})
    check("patch clears hostname to empty", r.json()["hostname"] == "")

    # patch missing -> 404
    r = c.patch("/api/nodes/nope", json={"ip": "1.1.1.1"})
    check("patch missing 404", r.status_code == 404)

    # add a second node, check sort order
    c.post("/api/nodes", json={"node_id": "at03-id", "name": "AT03", "ip": "2.2.2.2"})
    r = c.get("/api/nodes")
    names = [n["name"] for n in r.json()]
    check("sorted by name", names == ["AT03", "CH01"])

    # delete
    r = c.delete("/api/nodes/ch01-id")
    check("delete 204", r.status_code == 204)
    r = c.delete("/api/nodes/ch01-id")
    check("delete again 404", r.status_code == 404)
    r = c.get("/api/nodes")
    check("one node remains", len(r.json()) == 1)

print(f"\n{ok} passed, {fail} failed")
raise SystemExit(1 if fail else 0)
