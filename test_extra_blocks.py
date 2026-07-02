"""Unit tests for the NYM-EXIT extra-blocks agent actions.

Simulates the systemd + iptables world so we can exercise install-only,
install+restart (with a nym-node flush/reapply), verify and remove without
touching the host. Run: python3 test_extra_blocks.py
"""
import io
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "agent"))
import agent  # noqa: E402

ok = fail = 0


def check(label, cond):
    global ok, fail
    if cond:
        ok += 1; print(f"  pass  {label}")
    else:
        fail += 1; print(f"  FAIL  {label}")


# --- temp paths ------------------------------------------------------------
_sd = tempfile.mkdtemp()
agent.EB_STATE_DIR = os.path.join(_sd, "var")
agent.EB_CACHE = os.path.join(agent.EB_STATE_DIR, "blocklist.txt")
agent.EB_URL_FILE = os.path.join(agent.EB_STATE_DIR, "list_url")
agent.EB_SH = os.path.join(_sd, "sbin", "nym-extra-blocks.sh")
agent.EB_UNIT = os.path.join(_sd, "systemd", "nym-extra-blocks.service")
os.makedirs(os.path.join(_sd, "systemd"), exist_ok=True)
agent.NYM_SERVICE = "nym-node.service"
agent.unit_exists = lambda u: True   # so resolve_service() -> nym-node.service

BLOCKLIST = "1.1.1.1\n2.2.2.2 # skhron\n3.3.3.3/32\nnot-an-ip\n# comment line\n"


class _Resp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False


agent.urllib.request.urlopen = lambda url, timeout=15: _Resp(BLOCKLIST.encode())


# --- simulated host state --------------------------------------------------
SIM = {"chain_present": True, "blocked": set(), "active": False,
       "enabled": False, "nym_restarts": 0, "eb_runs": 0}


def _norm(ip):
    return ip if "/" in ip else ip + "/32"


def _apply_list():
    """What the oneshot does: insert REJECT rules for each list entry."""
    if not SIM["chain_present"]:
        return
    for ip in agent._eb_fetch_list():
        SIM["blocked"].add(_norm(ip))
    SIM["active"] = True
    SIM["eb_runs"] += 1


def sim_run(cmd, timeout=6, merge=False):
    EB = agent.EB_UNIT_NAME
    if cmd[:1] == ["systemctl"]:
        sub = cmd[1] if len(cmd) > 1 else ""
        tgt = cmd[2] if len(cmd) > 2 else ""
        if sub == "daemon-reload":
            return (0, "", "")
        if sub == "enable":
            SIM["enabled"] = True; return (0, "", "")
        if sub == "disable":
            SIM["enabled"] = False; SIM["active"] = False; return (0, "", "")
        if sub == "is-enabled" and tgt == EB:
            return (0, "enabled\n" if SIM["enabled"] else "disabled\n", "")
        if sub == "is-active" and tgt == EB:
            return (0, "active\n" if SIM["active"] else "inactive\n", "")
        if sub in ("start", "restart") and tgt == EB:
            _apply_list(); return (0, "", "")
        if sub == "restart" and tgt == "nym-node.service":
            # nym-node restart: chain is flushed + recreated, then the oneshot
            # (WantedBy nym-node) fires and re-applies on top.
            SIM["nym_restarts"] += 1
            SIM["chain_present"] = True
            SIM["blocked"] = set()
            _apply_list()
            return (0, "", "")
        if sub == "is-active":   # nym-node liveness etc.
            return (0, "active\n", "")
        return (0, "", "")
    if cmd[:1] == ["iptables"]:
        if cmd[1:3] == ["-S", "NYM-EXIT"]:
            if not SIM["chain_present"]:
                return (1, "", "no chain")
            lines = ["-N NYM-EXIT"] + [
                f"-A NYM-EXIT -d {d} -j REJECT --reject-with icmp-port-unreachable"
                for d in sorted(SIM["blocked"])]
            return (0, "\n".join(lines) + "\n", "")
        if cmd[1:2] == ["-nL"]:
            return (0, "", "") if SIM["chain_present"] else (1, "", "")
        if cmd[1:2] == ["-D"] and "-d" in cmd:
            ip = cmd[cmd.index("-d") + 1]
            SIM["blocked"].discard(_norm(ip)); SIM["blocked"].discard(ip)
            return (0, "", "")
    return (0, "", "")


agent._run = sim_run


# --- tests -----------------------------------------------------------------
print("\nextra-blocks:")

# 1. fresh node: nothing installed
check("state is 'missing' before install",
      agent._extra_blocks_state()["state"] == "missing"
      and agent._extra_blocks_state()["installed"] is False)

# 2. blocklist parsing skips junk and comments
ips = agent._eb_fetch_list("https://example/list.txt")
check("blocklist parses 3 valid IPs, drops junk/comments",
      ips == ["1.1.1.1", "2.2.2.2", "3.3.3.3/32"])

# 3. install-only applies to the live chain, no nym-node restart
r = agent.act_extra_blocks_install({"restart_node": False})
check("install-only succeeds and applies immediately",
      r["ok"] is True and r["mode"] == "install-only" and r["applied_now"] is True)
check("install-only did NOT restart nym-node", SIM["nym_restarts"] == 0)
check("files written + unit enabled", os.path.exists(agent.EB_SH)
      and os.path.exists(agent.EB_UNIT) and SIM["enabled"] is True)
check("script is templated with the list URL and chain-wait loop",
      "LIST_URL=" in open(agent.EB_SH).read()
      and "seq 1 30" in open(agent.EB_SH).read())
check("unit targets the resolved nym service",
      "nym-node.service" in open(agent.EB_UNIT).read()
      and "PartOf=nym-node.service" in open(agent.EB_UNIT).read())

# 4. state now reports active, column badge data is right
st = agent.act_extra_blocks_status({})
check("status reports installed + active with all rules present",
      st["installed"] is True and st["state"] == "active"
      and st["rules_present"] == 3 and st["blocklist_size"] == 3 and st["all_present"] is True)
check("status reports the sample IP as blocked",
      st["sample_ip"] == "1.1.1.1" and st["sample_blocked"] is True)

# 5. verify is authoritative (rule presence)
v = agent.act_extra_blocks_verify({})
check("verify confirms all rules present", v["ok"] is True and v["all_present"] is True
      and v["error"] is None)

# 6. simulate nym-node flushing the chain WITHOUT our service -> verify should fail
SIM["blocked"] = set()
v2 = agent.act_extra_blocks_verify({})
check("verify fails when the chain was flushed and not reapplied",
      v2["all_present"] is False and v2["error"] is not None)

# 7. install WITH restart: nym-node restart flushes then the oneshot reapplies
SIM["nym_restarts"] = 0
r2 = agent.act_extra_blocks_install({"restart_node": True})
check("install+restart restarts nym-node exactly once", SIM["nym_restarts"] == 1)
check("install+restart lands all rules after the flush/reapply cycle",
      r2["ok"] is True and r2["mode"] == "install+restart"
      and r2["after"]["all_present"] is True and r2["before"] is not None)

# 8. bad URL is rejected before anything is written
rb = agent.act_extra_blocks_install({"restart_node": False, "list_url": "ftp://nope/list"})
check("install rejects a non-http(s) blocklist URL", rb["ok"] is False and "URL" in rb["error"])

# 9. remove: disables, deletes files, drops our REJECT rules
rr = agent.act_extra_blocks_remove({})
check("remove deletes the 3 REJECT rules and clears install",
      rr["ok"] is True and rr["removed_rules"] == 3
      and not os.path.exists(agent.EB_SH) and not os.path.exists(agent.EB_UNIT)
      and rr["state"]["state"] == "missing")

# 10. DE01 case: a hand-made script/unit already exists -> install backs it up
HANDMADE_SH = "#!/usr/bin/env bash\n# my own DE01 script\nsleep 10\n"
HANDMADE_UNIT = "[Unit]\nDescription=Extra destination blocks (hand made)\n[Service]\nType=oneshot\n"
os.makedirs(os.path.dirname(agent.EB_SH), exist_ok=True)
open(agent.EB_SH, "w").write(HANDMADE_SH)
open(agent.EB_UNIT, "w").write(HANDMADE_UNIT)
for p in (agent.EB_SH + ".maestro.bak", agent.EB_UNIT + ".maestro.bak"):
    if os.path.exists(p):
        os.remove(p)
SIM["blocked"] = set(); SIM["chain_present"] = True
rd = agent.act_extra_blocks_install({"restart_node": False})
check("install over a hand-made setup flags the replacement",
      rd["ok"] is True and rd["replaced_existing"] is True and rd["replaced_handmade"] is True)
check("the original hand-made files are preserved as *.maestro.bak",
      open(agent.EB_SH + ".maestro.bak").read() == HANDMADE_SH
      and open(agent.EB_UNIT + ".maestro.bak").read() == HANDMADE_UNIT)
check("the live files are now maestro's (marker + wait-loop present)",
      "nym-maestro-managed" in open(agent.EB_SH).read()
      and "seq 1 30" in open(agent.EB_SH).read())

# 11. reinstalling over maestro's OWN files does not re-flag or re-backup
os.remove(agent.EB_SH + ".maestro.bak")
rd2 = agent.act_extra_blocks_install({"restart_node": False})
check("reinstall over maestro's own files is not flagged as a replacement",
      rd2["replaced_existing"] is False
      and not os.path.exists(agent.EB_SH + ".maestro.bak"))

print(f"\n{ok} passed, {fail} failed")
raise SystemExit(1 if fail else 0)
