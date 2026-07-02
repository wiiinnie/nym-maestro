import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent
TMP = Path(tempfile.mkdtemp())
os.environ["MAESTRO_PKI"] = str(TMP / "pki")
os.environ["MAESTRO_DB"] = str(TMP / "maestro.db")
os.environ["MAESTRO_POLL"] = "0"  # disable background loop during the test

PORT = 8453
sys.path.insert(0, str(ROOT))
import pki  # noqa: E402
sys.path.insert(0, str(ROOT / "agent"))
import agent as _agentmod  # noqa: E402
AGENT_VERSION = _agentmod.AGENT_VERSION

ok = fail = 0


def check(label, cond):
    global ok, fail
    if cond:
        ok += 1; print(f"  pass  {label}")
    else:
        fail += 1; print(f"  FAIL  {label}")


def wait_port(host, port, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.15)
    return False


# 1. CA + orchestrator client cert
pki.init_ca(Path(os.environ["MAESTRO_PKI"]))
check("pki init creates CA + client cert",
      (Path(os.environ["MAESTRO_PKI"]) / "ca.crt").exists()
      and (Path(os.environ["MAESTRO_PKI"]) / "orchestrator.crt").exists())

# 2. enroll a node bound to localhost
bundle, fp = pki.enroll(Path(os.environ["MAESTRO_PKI"]), "T1", "127.0.0.1", PORT,
                        dist_root=TMP / "dist")
check("enroll builds a bundle with certs + agent",
      all((bundle / f).exists() for f in
          ("server.crt", "server.key", "ca.crt", "agent.py", "install.sh", "agent.env")))
check("enroll returns a fingerprint", len(fp) == 64)

# 3. start the real agent against that bundle
agent_env = dict(os.environ,
                 MAESTRO_AGENT_HOST="127.0.0.1",
                 MAESTRO_AGENT_PORT=str(PORT),
                 MAESTRO_AGENT_CERTDIR=str(bundle),
                 MAESTRO_NYM_PORT="59999",
                 MAESTRO_NYM_SERVICE="nonexistent.service")
proc = subprocess.Popen([sys.executable, str(bundle / "agent.py")],
                        env=agent_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
try:
    check("agent port opens", wait_port("127.0.0.1", PORT))

    ca = str(Path(os.environ["MAESTRO_PKI"]) / "ca.crt")
    import ssl
    cctx = ssl.create_default_context(cafile=ca)
    cctx.load_cert_chain(
        certfile=str(Path(os.environ["MAESTRO_PKI"]) / "orchestrator.crt"),
        keyfile=str(Path(os.environ["MAESTRO_PKI"]) / "orchestrator.key"))

    # 4. direct mTLS call with the orchestrator cert
    with httpx.Client(verify=cctx, timeout=5) as c:
        r = c.get(f"https://127.0.0.1:{PORT}/v1/health")
        check("health over mTLS 200", r.status_code == 200)
        r = c.get(f"https://127.0.0.1:{PORT}/v1/status")
        body = r.json()
        check("status over mTLS 200", r.status_code == 200)
        check("status: agent reports version", body.get("agent_version") == AGENT_VERSION)
        check("status: agent reports a source sha", len(body.get("agent_sha", "")) == 64)
        check("status: service inactive (no nym here)", body.get("service_active") is False)
        check("status: nym block present", isinstance(body.get("nym"), dict))

    # 5. a client WITHOUT the cert must be rejected at the TLS layer
    rejected = False
    try:
        with httpx.Client(verify=ca, timeout=5) as c:
            c.get(f"https://127.0.0.1:{PORT}/v1/status")
    except Exception:
        rejected = True
    check("uncertified client is rejected", rejected)

    # 5b. self-update: a syntactically broken push is refused, file left intact
    agent_file = bundle / "agent.py"
    before = agent_file.read_text()
    with httpx.Client(verify=cctx, timeout=5) as c:
        r = c.post(f"https://127.0.0.1:{PORT}/v1/exec",
                   json={"action": "update_agent", "params": {"content": "def broken(", "restart": False}})
        body = r.json()
        check("update_agent rejects syntax error", body.get("ok") is False and "syntax" in body.get("error", ""))
    check("agent file unchanged after rejected push", agent_file.read_text() == before)

    # 5c. self-update: a valid push lands, with a backup, no restart
    import hashlib
    new_src = before + "\n# pushed-by-maestro-test\n"
    with httpx.Client(verify=cctx, timeout=5) as c:
        r = c.post(f"https://127.0.0.1:{PORT}/v1/exec", json={"action": "update_agent", "params": {
            "content": new_src, "sha256": hashlib.sha256(new_src.encode()).hexdigest(), "restart": False}})
        body = r.json()
    check("update_agent accepts valid push", body.get("ok") is True)
    check("agent file actually replaced", "# pushed-by-maestro-test" in agent_file.read_text())
    check("update_agent created a backup", body.get("backup") and Path(body["backup"]).exists())
    check("update_agent echoes sha256",
          body.get("sha256") == hashlib.sha256(new_src.encode()).hexdigest())

    # 5d. backup download endpoint: serves a staged file, rejects bad names
    bdir = bundle / "backups"
    bdir.mkdir(exist_ok=True)
    good = "nym-backup_hermes-gateway-test_20260629_120000.tar.gz"
    payload = b"FAKE-TARBALL-BYTES" * 1000
    (bdir / good).write_bytes(payload)
    with httpx.Client(verify=cctx, timeout=10) as c:
        r = c.get(f"https://127.0.0.1:{PORT}/v1/backup", params={"name": good})
        check("backup download returns the staged bytes",
              r.status_code == 200 and r.content == payload)
        r = c.get(f"https://127.0.0.1:{PORT}/v1/backup", params={"name": "../../etc/passwd"})
        check("backup download rejects path traversal", r.status_code == 400)
        r = c.get(f"https://127.0.0.1:{PORT}/v1/backup", params={"name": "ca.crt"})
        check("backup download rejects non-backup filenames", r.status_code == 400)
        r = c.get(f"https://127.0.0.1:{PORT}/v1/backup",
                  params={"name": "nym-backup_x_20260629_120000.tar.gz"})
        check("backup download 404 for a missing staged file", r.status_code == 404)

    # 6. full orchestrator path: register node, refresh, see cached status
    from fastapi.testclient import TestClient
    import app as appmod
    with TestClient(appmod.app) as tc:
        cr = tc.post("/api/nodes", json={"node_id": "default-nym-node", "name": "T1",
                                         "ip": "127.0.0.1", "agent_port": PORT})
        uid = cr.json()["uid"]
        check("create returns a uid", bool(uid))
        r = tc.post("/api/refresh")
        summary = r.json()
        check("refresh reports one reachable", summary == {"polled": 1, "reachable": 1})
        r = tc.get("/api/nodes")
        node = r.json()[0]
        check("grid shows node reachable", node["status"] and node["status"]["reachable"] is True)
        check("grid shows service_active False", node["status"]["service_active"] is False)
        check("grid shows last_seen set", bool(node["status"]["last_seen"]))

        # exec routing: unknown action rejected at the orchestrator
        r = tc.post("/api/exec", json={"action": "danger", "node_ids": [uid], "params": {}})
        check("orchestrator rejects non-allowlisted action", r.status_code == 400)

        # restart fans out and returns structured per-node results (ok False: no systemd here)
        r = tc.post("/api/exec", json={"action": "restart", "node_ids": [uid], "params": {}})
        check("restart returns 200 + results", r.status_code == 200 and len(r.json()["results"]) == 1)

        # service-file read flows through to the agent
        r = tc.get(f"/api/nodes/{uid}/service-file")
        check("service-file endpoint returns agent payload", r.status_code == 200 and "ok" in r.json())

        # local agent info
        r = tc.get("/api/agent/local")
        check("agent/local reports version + sha", r.status_code == 200
              and r.json().get("version") == AGENT_VERSION and len(r.json().get("sha256", "")) == 64)

        # push the local agent to the node over mTLS (no restart in-test)
        r = tc.post("/api/agent/update", json={"node_ids": [uid], "restart": False})
        body = r.json()
        check("agent/update pushes successfully", r.status_code == 200
              and body["results"][0]["ok"] is True)

        # upgrade is accepted by the exec allowlist; missing url is reported per-node
        r = tc.post("/api/exec", json={"action": "upgrade", "node_ids": [uid], "params": {}})
        check("upgrade routes; no-url reported as failure",
              r.status_code == 200 and r.json()["results"][0]["ok"] is False
              and "url" in r.json()["results"][0]["result"].get("error", ""))

        # with a url but no systemd here, it fails locating the binary (no download attempted)
        r = tc.post("/api/exec", json={"action": "upgrade", "node_ids": [uid],
                                       "params": {"url": "https://example.invalid/nym-node"}})
        err = r.json()["results"][0]["result"].get("error", "")
        check("upgrade stops when ExecStart can't be read", "ExecStart" in err)

    # agent rejects an unknown exec action at the agent itself (400)
    with httpx.Client(verify=cctx, timeout=5) as c:
        r = c.post(f"https://127.0.0.1:{PORT}/v1/exec", json={"action": "nope"})
        check("agent rejects unknown action", r.status_code == 400)

    # fail2ban_status routes over mTLS and reports not-installed cleanly here
    with httpx.Client(verify=cctx, timeout=5) as c:
        r = c.post(f"https://127.0.0.1:{PORT}/v1/exec", json={"action": "fail2ban_status"})
        body = r.json()
        check("fail2ban_status routes + reports installed flag",
              r.status_code == 200 and body.get("ok") is True and body.get("installed") is False)
finally:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()

print(f"\n{ok} passed, {fail} failed")
raise SystemExit(1 if fail else 0)
