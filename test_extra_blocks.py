"""Tests for the NYM-EXIT extra-blocks feature (agent side + standalone installer).

The blocklist is maintained in maestro and shipped as `entries`; every block is a
REJECT marked "nym_block", and a rollout reconciles (drain all marked, set list).
Covers: the real runtime script against a stateful fake iptables (reconcile,
migration of unmarked pre-0.12.9 rules, idempotency, foreign rules untouched),
the agent actions with a simulated host, validation parity with the orchestrator,
the scan rate-limit (maestro's own nym_scan_v2) and the fan-out limiter.
Run: .venv/bin/python test_extra_blocks.py
"""
import hashlib
import inspect
import json
import os
import re as _re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "agent"))
sys.path.insert(0, str(ROOT))
import agent  # noqa: E402
import blocklist  # noqa: E402

ok = fail = 0


def check(label, cond):
    global ok, fail
    if cond:
        ok += 1; print(f"  pass  {label}")
    else:
        fail += 1; print(f"  FAIL  {label}")


_inst = (ROOT / "install-nym-extra-blocks.sh").read_text()
SCRIPT = agent.EB_SCRIPT.replace("__CHAIN6__", "NYM-EXIT")

# ---------------------------------------------------------------------------
print("\ntemplate vs installer, static invariants:")


def _heredoc(src, target):
    a = src.index(f'cat > "{target}" <<\'EOF\'\n') + len(f'cat > "{target}" <<\'EOF\'\n')
    return src[a:src.index("\nEOF\n", a) + 1]


check("installer runtime script is word-identical to EB_SCRIPT (CHAIN6=NYM-EXIT)",
      _heredoc(_inst, "$SCRIPT") == SCRIPT)
check("installer unit == EB_UNIT_TPL for nym-node.service",
      _heredoc(_inst, "$UNIT") == agent.EB_UNIT_TPL.replace("__NYM__", "nym-node.service"))
check("nothing is fetched from the network (no curl/wget/URL)",
      not any(x in SCRIPT for x in ("curl", "wget", "http://", "https://", "LIST_URL"))
      and "curl" not in _inst)
check("installer ends with restart, not start",
      "systemctl restart nym-extra-blocks.service" in _inst and "systemctl start" not in _inst)
check("unit: oneshot, PartOf/WantedBy nym-node, sleep 10",
      all(x in agent.EB_UNIT_TPL for x in ("PartOf=__NYM__", "WantedBy=__NYM__", "After=__NYM__",
                                           "RemainAfterExit=yes", "ExecStartPre=/bin/sleep 10")))
check("every inserted block REJECT carries the nym_block marker",
      all('--comment "$MARK"' in l for l in SCRIPT.replace("\\\n", " ").splitlines()
          if " -I " in l and "REJECT" in l))
check("marker constant matches the agent reader", 'MARK="nym_block"' in SCRIPT
      and agent.EB_MARK == "nym_block")
check("no line-number deletes", _re.search(r"-D \"?\$?\w+\"? \d+\b", SCRIPT) is None)
check("rate-limit stays maestro's: nym_scan_v2 200/sec burst 1000 (NTM ships none)",
      'RL_RATE="200/sec"' in SCRIPT and 'RL_BURST="1000"' in SCRIPT
      and "--hashlimit-name nym_scan_v2 -j DROP" in SCRIPT)
check("rate-limit drain never touches NTM's port-465 SMTPS limit",
      "drain_matching \"$IPT\" \"$CHAIN\" 'nym_scan' 'dport 465'" in SCRIPT)

# ---------------------------------------------------------------------------
print("\nruntime script against a stateful fake iptables:")

FAKE = r"""#!/usr/bin/env python3
import json, os, re, sys
fam = os.path.basename(sys.argv[0]); st_path = os.path.join(os.environ["D"], fam + ".json")
st = json.load(open(st_path)) if os.path.exists(st_path) else {"chains": {}}
a = sys.argv[1:]
open(os.path.join(os.environ["D"], "log"), "a").write(fam + " " + " ".join(a) + "\n")
host = "/128" if fam == "ip6tables" else "/32"
def norm(spec):
    out = list(spec)
    for i, x in enumerate(out[:-1]):
        if x == "-d" and "/" not in out[i + 1]:
            out[i + 1] += host
    return " ".join(out)
def save(): json.dump(st, open(st_path, "w"))
ch = st["chains"]
if os.environ.get("NOV6") == "1" and fam == "ip6tables":
    sys.exit(1)
if a[0] in ("-nL", "-L"):
    c = a[1]
    if c not in ch: sys.exit(1)
    if a[0] == "-L":
        for r in ch[c]:
            m = re.search(r"-d (\S+)", r)
            hits = st.get("hits", {}).get(r, 0)
            cm = " /* nym_block */" if "--comment nym_block" in r else ""
            print(f"  {hits}  0 REJECT 0 -- * * 0.0.0.0/0 {m.group(1) if m else '0.0.0.0/0'}{cm}")
    sys.exit(0)
if a[0] == "-S":
    c = a[1]
    if c not in ch: sys.exit(1)
    print("-N " + c)
    for r in ch[c]: print("-A " + c + " " + r)
    sys.exit(0)
if a[0] == "-N":
    if a[1] in ch: sys.exit(1)
    ch[a[1]] = []; save(); sys.exit(0)
if a[0] == "-F":
    if a[1] not in ch: sys.exit(1)
    ch[a[1]] = []; save(); sys.exit(0)
if a[0] == "-X":
    ch.pop(a[1], None); save(); sys.exit(0)
c, spec = a[1], norm(a[2:])
if c not in ch: sys.exit(1)
fail = os.environ.get("FAIL")
if a[0] in ("-I", "-A"):
    if fail and fail in spec: sys.exit(1)
    if a[0] == "-I": ch[c].insert(0, spec)
    else: ch[c].append(spec)
    save(); sys.exit(0)
if a[0] == "-D":
    if spec in ch[c]:
        ch[c].remove(spec); save(); sys.exit(0)
    sys.exit(1)
sys.exit(0)
"""

POLICY = [  # what nym-node / NTM put into NYM-EXIT (never ours to touch)
    "-p tcp --dport 465 -m conntrack --ctstate NEW -m hashlimit --hashlimit-upto 30/min "
    "--hashlimit-burst 60 --hashlimit-mode srcip --hashlimit-name smtps465v4 -j ACCEPT",
    "-d 10.0.0.0/8 -j REJECT --reject-with icmp-port-unreachable",
    "-p tcp --dport 25 -j REJECT --reject-with icmp-port-unreachable",
]


def run_eb(list_entries, legacy=None, v4_rules=None, v6_rules=None, env=None, keep=None):
    d = keep or tempfile.mkdtemp()
    b = os.path.join(d, "bin"); os.makedirs(b, exist_ok=True)
    for n in ("iptables", "ip6tables"):
        p = os.path.join(b, n); open(p, "w").write(FAKE); os.chmod(p, 0o755)
    if keep is None:
        json.dump({"chains": {"NYM-EXIT": list(POLICY if v4_rules is None else v4_rules)}},
                  open(os.path.join(d, "iptables.json"), "w"))
        json.dump({"chains": {"NYM-EXIT": list(v6_rules or [])}},
                  open(os.path.join(d, "ip6tables.json"), "w"))
    state = os.path.join(d, "state"); os.makedirs(state, exist_ok=True)
    if list_entries is not None:
        open(os.path.join(state, "blocklist.txt"), "w").write("".join(e + "\n" for e in list_entries))
    if legacy is not None:
        open(os.path.join(state, "legacy.txt"), "w").write("".join(e + "\n" for e in legacy))
    body = (SCRIPT.replace("export PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH\n", "")
                  .replace('STATE_DIR="/var/lib/nym-extra-blocks"', f'STATE_DIR="{state}"')
                  .replace("for _ in $(seq 1 30); do", "for _ in 1; do"))
    sp = os.path.join(d, "eb.sh"); open(sp, "w").write(body)
    e = dict(os.environ, D=d, PATH=b + ":/usr/bin:/bin"); e.update(env or {})
    r = subprocess.run(["bash", sp], capture_output=True, text=True, env=e, timeout=60)
    rules = lambda f: json.load(open(os.path.join(d, f + ".json")))["chains"]
    return r, d, rules("iptables"), rules("ip6tables")


MK4 = lambda ip: f"-d {ip} -m comment --comment nym_block -j REJECT --reject-with icmp-port-unreachable"
MK6 = lambda ip: f"-d {ip} -m comment --comment nym_block -j REJECT --reject-with icmp6-port-unreachable"
OLD4 = lambda ip: f"-d {ip} -j REJECT --reject-with icmp-port-unreachable"
OLD6 = lambda ip: f"-d {ip} -j REJECT --reject-with icmp6-port-unreachable"
RL = ("-p tcp -m conntrack --ctstate NEW -m hashlimit --hashlimit-mode srcip --hashlimit-above 200/sec "
      "--hashlimit-burst 1000 --hashlimit-name nym_scan_v2 -j DROP")
SKHRON = ["185.195.236.172/32", "88.218.206.43/32", "144.79.58.196/32", "144.79.59.63/32"]
V6E = "2001:470:1:332::fe/128"

# migration: a node as left by the old version (unmarked blocks, rate-limit, policy)
old_v4 = [OLD4(x) for x in SKHRON + ["178.162.202.97/32"]] + [RL, RL] + POLICY
r, d, c4, c6 = run_eb(SKHRON + ["178.162.202.97/32", V6E], legacy=SKHRON + ["178.162.202.97/32", V6E],
                      v4_rules=old_v4, v6_rules=[OLD6(V6E)])
x4 = c4["NYM-EXIT"]
check("migration run exits 0", r.returncode == 0)
check("migration: every old unmarked block replaced by a marked one",
      not any(OLD4(x) in x4 for x in SKHRON) and all(MK4(x) in x4 for x in SKHRON)
      and MK4("178.162.202.97/32") in x4)
check("migration: v6 entry marked in ip6tables", MK6(V6E) in c6["NYM-EXIT"]
      and OLD6(V6E) not in c6["NYM-EXIT"])
check("rate-limit: stacked nym_scan_v2 drained to exactly one",
      sum(1 for l in x4 if "nym_scan_v2" in l) == 1)
check("NTM/policy rules untouched (465 SMTPS, policy REJECTs incl. a -d one)",
      all(p in x4 for p in POLICY))
check("blocks sit at the top of NYM-EXIT", all("nym_block" in l for l in x4[:5]))
check("fan-out limiter hooked once (v4 + v6)",
      x4.count("-j NYM-FANOUT") == 1 and c6["NYM-EXIT"].count("-j NYM-FANOUT") == 1)

# idempotent: run again on the same state
r, d, c4, c6 = run_eb(None, keep=d)
x4b = c4["NYM-EXIT"]
check("re-run is idempotent: same rule set, nothing stacked",
      sorted(x4b) == sorted(x4) and sum(1 for l in x4b if "nym_block" in l) == 5)

# reconcile: entry removed in maestro disappears from the node, new one appears
r, d, c4, c6 = run_eb(SKHRON[:2] + ["198.51.100.0/24"], keep=d)
x4 = c4["NYM-EXIT"]
check("reconcile: removed entries gone, new entry added, only list remains marked",
      sorted(l for l in x4 if "nym_block" in l) == sorted(MK4(x) for x in SKHRON[:2] + ["198.51.100.0/24"]))
check("reconcile: v6 entry dropped from the list is removed from ip6tables",
      not any("nym_block" in l for l in c6["NYM-EXIT"]))
check("reconcile: a removed legacy entry does not come back unmarked",
      not any(OLD4(x) in x4 for x in SKHRON))

# empty list = remove all blocks, keep everything else
r, d, c4, c6 = run_eb([], keep=d)
x4 = c4["NYM-EXIT"]
check("empty list: no nym_block rules left, rate-limit + policy intact",
      not any("nym_block" in l for l in x4) and sum(1 for l in x4 if "nym_scan_v2" in l) == 1
      and all(p in x4 for p in POLICY))

# policy REJECT for a dest that is NOT on our lists is never touched
r, d, c4, c6 = run_eb(["203.0.113.7/32"], v4_rules=POLICY + [OLD4("192.0.2.9/32")])
check("unmarked REJECT for a dest never on our list is left alone",
      OLD4("192.0.2.9/32") in c4["NYM-EXIT"] and MK4("203.0.113.7/32") in c4["NYM-EXIT"])

# no v6 chain: v4 applied, v6 skipped
r, d, c4, c6 = run_eb(SKHRON + [V6E], env={"NOV6": "1"})
check("no ip6tables: v4 applied, v6 skipped with a note",
      r.returncode == 0 and all(MK4(x) in c4["NYM-EXIT"] for x in SKHRON) and "skipping IPv6" in r.stderr)

r, d, c4, c6 = run_eb(SKHRON, env={"NOV6": "1"})
check("apply prints the applied count", "applied 4 IPv4 + 0 IPv6 nym_block entries" in r.stdout)

# NYM-EXIT missing (nym-node down): nothing applied, but the unit does not fail
d = tempfile.mkdtemp()
json.dump({"chains": {}}, open(os.path.join(d, "iptables.json"), "w"))
json.dump({"chains": {}}, open(os.path.join(d, "ip6tables.json"), "w"))
r, d, c4, c6 = run_eb(SKHRON, keep=d)
check("missing NYM-EXIT: exit 0, nothing inserted, reason on stderr",
      r.returncode == 0 and "NYM-EXIT" not in c4 and "not present after waiting" in r.stderr)

# ---------------------------------------------------------------------------
print("\nvalidation parity (agent vs orchestrator):")
CASES = ["1.2.3.4", "1.2.3.4/32", "10.0.0.0/16", "10.0.0.5/24", "0.0.0.0/0", "10.0.0.0/15",
         "2001:db8::/32", "2001:db8::/31", "2001:db8::1", "::/0", "not-an-ip", "1.2.3.4; rm -rf /",
         "", " 8.8.8.8 ", "1.2.3.4/33", "fe80::1%eth0"]
check("agent.eb_canonical == blocklist.canonical for every case",
      all(agent.eb_canonical(c) == blocklist.canonical(c)[0] for c in CASES))
check("too-broad prefixes rejected (0.0.0.0/0, /15, ::/0, /31 v6)",
      all(blocklist.canonical(c)[0] is None for c in ("0.0.0.0/0", "10.0.0.0/15", "::/0", "2001:db8::/31")))
check("host bits set rejected with a hint", "did you mean 10.0.0.0/24" in blocklist.canonical("10.0.0.5/24")[1])
check("list fingerprints agree and ignore order/comments",
      agent.eb_list_sha(["1.2.3.4/32", "2001:db8::/32"]) == blocklist.list_sha(["2001:db8::/32", "1.2.3.4"]))
p = blocklist.parse("# head\n1.2.3.4 # note\n\n1.2.3.4/32\nbogus\n2001:db8::/32\n")
check("parse: entries canonical, duplicate reported, bad line with number",
      p["entries"] == ["1.2.3.4/32", "2001:db8::/32"] and p["duplicates"][0]["line"] == 4
      and p["errors"] == [{"line": 5, "text": "bogus", "error": "not an IPv4/IPv6 address or CIDR"}])
seed = blocklist.summary((ROOT / "blocklist.txt").read_text())
check("seed list (repo blocklist.txt) is valid: 4 Skhron + 2 CERT-Bund entries",
      seed["valid"] and seed["count"] == 6 and all(s in seed["entries"] for s in SKHRON))

# ---------------------------------------------------------------------------
print("\nagent actions (simulated host):")

_sd = tempfile.mkdtemp()
agent.EB_STATE_DIR = os.path.join(_sd, "var")
agent.EB_CACHE = os.path.join(agent.EB_STATE_DIR, "blocklist.txt")
agent.EB_LEGACY = os.path.join(agent.EB_STATE_DIR, "legacy.txt")
agent.EB_URL_FILE = os.path.join(agent.EB_STATE_DIR, "list_url")
agent.EB_SH = os.path.join(_sd, "sbin", "nym-extra-blocks.sh")
agent.EB_UNIT = os.path.join(_sd, "systemd", "nym-extra-blocks.service")
os.makedirs(os.path.join(_sd, "systemd"), exist_ok=True)
agent.NYM_SERVICE = "nym-node.service"
agent.unit_exists = lambda u: True
agent._eb_v6_supported = lambda: False

SIM = {"chain": True, "rules": [], "active": False, "enabled": False, "nym_restarts": 0,
       "nym_pid": 100, "eb_runs": 0}


def _apply_sim():
    """What the oneshot does: reconcile marked rules to the on-disk list."""
    if not SIM["chain"]:
        return
    lst = agent._eb_entries_cached()
    leg = set(agent._eb_parse_file(agent.EB_LEGACY)) | set(lst)
    SIM["rules"] = [r for r in SIM["rules"] if "nym_block" not in r
                    and not any(r == "-A NYM-EXIT " + OLD4(x) for x in leg)]
    SIM["rules"] = ["-A NYM-EXIT " + MK4(x) for x in lst if ":" not in x] + SIM["rules"]
    if not any("nym_scan_v2" in r for r in SIM["rules"]):
        SIM["rules"].insert(0, "-A NYM-EXIT " + RL)
    SIM["active"] = True
    SIM["eb_runs"] += 1


def sim_run(cmd, timeout=6, merge=False):
    EB = agent.EB_UNIT_NAME
    if cmd[0] == "systemctl":
        sub = cmd[1]
        units = [a for a in cmd[2:] if not a.startswith("-")]
        tgt = units[0] if units else ""
        if sub == "show":
            return (0, f"ActiveState=active\nMainPID={SIM['nym_pid']}\n", "")
        if sub == "enable":
            SIM["enabled"] = True; return (0, "", "")
        if sub == "disable":
            SIM["enabled"] = False; SIM["active"] = False; return (0, "", "")
        if sub == "is-enabled" and tgt == EB:
            return (0, "enabled\n" if SIM["enabled"] else "disabled\n", "")
        if sub == "is-active" and tgt == EB:
            return (0, "active\n" if SIM["active"] else "inactive\n", "")
        if sub in ("start", "restart") and tgt == EB:
            _apply_sim(); return (0, "", "")
        if sub == "restart" and tgt == "nym-node.service":
            SIM["nym_restarts"] += 1; SIM["nym_pid"] += 1
            SIM["chain"] = True; SIM["rules"] = []      # NTM/nym-node rebuild flushes NYM-EXIT
            _apply_sim(); return (0, "", "")
        if sub == "is-active":
            return (0, "active\n", "")
        return (0, "", "")
    if cmd[0] == "iptables":
        if cmd[1:3] == ["-S", "NYM-EXIT"]:
            if not SIM["chain"]:
                return (1, "", "no chain")
            return (0, "-N NYM-EXIT\n" + "".join(r + "\n" for r in SIM["rules"]), "")
        if cmd[1:3] == ["-L", "NYM-EXIT"]:
            if not SIM["chain"]:
                return (1, "", "")
            out = []
            for r in SIM["rules"]:
                m = _re.search(r"-d (\S+)", r)
                if m and "nym_block" in r:
                    out.append(f"   7   420 REJECT  0  --  *  *  0.0.0.0/0  {m.group(1).replace('/32', '')}"
                               f"  /* nym_block */ reject-with icmp-port-unreachable")
            return (0, "Chain NYM-EXIT\n pkts bytes target\n" + "\n".join(out) + "\n", "")
        if cmd[1:3] == ["-D", "NYM-EXIT"]:
            line = "-A NYM-EXIT " + " ".join(cmd[3:])
            if line in SIM["rules"]:
                SIM["rules"].remove(line); return (0, "", "")
            return (1, "", "")
    if cmd[0] == "ip6tables":
        return (1, "", "")
    return (0, "", "")


agent._run = sim_run
LIST = SKHRON + ["178.162.202.97/32"]

check("state is 'missing' before install", agent._extra_blocks_state()["state"] == "missing")
r = agent.act_extra_blocks_install({"restart_node": False})
check("install without entries (old orchestrator) is refused",
      r["ok"] is False and "managed in maestro" in r["error"])
r = agent.act_extra_blocks_install({"entries": ["0.0.0.0/0"]})
check("install refuses a too-broad entry before writing anything",
      r["ok"] is False and not os.path.exists(agent.EB_SH))
r = agent.act_extra_blocks_install({"entries": ["1.2.3.4; reboot"]})
check("install refuses shell junk", r["ok"] is False and not os.path.exists(agent.EB_CACHE))

# a node coming from the old version: cache + list_url + unmarked rules
os.makedirs(agent.EB_STATE_DIR, exist_ok=True)
open(agent.EB_CACHE, "w").write("# old github list\n" + "\n".join(x.replace("/32", "") for x in LIST) + "\n")
open(agent.EB_URL_FILE, "w").write("https://raw.githubusercontent.com/x/y/main/blocklist.txt\n")
SIM["rules"] = ["-A NYM-EXIT " + OLD4(x) for x in LIST] + ["-A NYM-EXIT " + RL]
SIM["rules"] += ["-A NYM-EXIT " + p for p in POLICY]
r = agent.act_extra_blocks_install({"entries": LIST, "restart_node": False})
check("install-only applies immediately, no nym-node restart",
      r["ok"] is True and r["mode"] == "install-only" and r["applied_now"] and SIM["nym_restarts"] == 0)
check("old list preserved as legacy.txt, list_url removed",
      os.path.exists(agent.EB_LEGACY) and "178.162.202.97" in open(agent.EB_LEGACY).read()
      and not os.path.exists(agent.EB_URL_FILE))
check("list written canonical, script = template, unit for nym-node",
      [l for l in open(agent.EB_CACHE).read().splitlines() if not l.startswith("#")] == LIST
      and open(agent.EB_SH).read() == agent.EB_SCRIPT.replace("__CHAIN6__", agent.EB_CHAIN6)
      and "PartOf=nym-node.service" in open(agent.EB_UNIT).read())
check("before: migration pending (5 unmarked), after: 5/5 marked, 0 unmarked",
      r["before"]["legacy_rules"] == 5 and r["before"]["rules_present"] == 0
      and r["after"]["rules_present"] == 5 and r["after"]["legacy_rules"] == 0)

st = agent.act_extra_blocks_status({})
check("status: counts, hits, list sha, rate-limit by name",
      st["installed"] and st["blocked_count"] == 5 and st["blocklist_size"] == 5
      and st["hits"] == 35 and st["list_sha"] == blocklist.list_sha(LIST)
      and st["rate_limit_rate"] == "200/sec" and st["rate_limit_burst"] == 1000
      and st["rate_limit_rules"] == 1 and st["stale_rules"] == 0)
check("status: per-destination hits keyed canonically",
      st["hits_per_dest"].get("185.195.236.172/32") == 7)
check("policy REJECTs are not counted as ours",
      st["blocked_count"] == 5 and "10.0.0.0/8" not in st["hits_per_dest"])

v = agent.act_extra_blocks_verify({})
check("verify confirms the list", v["all_present"] and v["error"] is None)
SIM["rules"].append("-A NYM-EXIT " + MK4("192.0.2.1/32"))
v = agent.act_extra_blocks_verify({})
check("verify flags a stale marked rule not on the list",
      not v["all_present"] and v["stale_rules"] == 1 and "stale" in v["error"])
SIM["rules"] = [r for r in SIM["rules"] if "192.0.2.1" not in r]
SIM["rules"] = []          # nym-node flushed, oneshot did not run
v = agent.act_extra_blocks_verify({})
check("verify fails after a flush without re-apply", not v["all_present"] and v["error"])

SIM["nym_restarts"] = 0
r = agent.act_extra_blocks_install({"entries": SKHRON, "restart_node": True})
check("install+restart: nym-node restarted once, list reconciled (CERT-Bund entry removed)",
      SIM["nym_restarts"] == 1 and r["ok"] and r["after"]["rules_present"] == 4
      and not any("178.162.202.97" in x for x in SIM["rules"]))

r = agent.act_extra_blocks_install({"entries": [], "restart_node": False})
check("empty list is a valid, fully applied state", r["ok"] and r["after"]["rules_present"] == 0
      and not any("nym_block" in x for x in SIM["rules"]))

agent.act_extra_blocks_install({"entries": LIST})
up = agent.act_extra_blocks_upgrade({})
check("upgrade rewrites the script and keeps the node's list",
      up["ok"] and up["after"]["rules_present"] == 5)

SIM["rules"].append("-A NYM-EXIT " + OLD4("185.195.236.172/32"))
rr = agent.act_extra_blocks_remove({})
check("remove: all marked + leftover unmarked list rules gone, policy kept, files gone",
      rr["ok"] and rr["removed_rules"] == 6
      and not any("nym_block" in x or OLD4("185.195.236.172/32") in x for x in SIM["rules"])
      and not any(os.path.exists(p) for p in (agent.EB_SH, agent.EB_UNIT, agent.EB_CACHE, agent.EB_LEGACY))
      and rr["state"]["state"] == "missing")

# hand-made setup is backed up (DE01 case)
HANDMADE_SH = "#!/usr/bin/env bash\n# my own DE01 script\nsleep 10\n"
os.makedirs(os.path.dirname(agent.EB_SH), exist_ok=True)
open(agent.EB_SH, "w").write(HANDMADE_SH)
open(agent.EB_UNIT, "w").write("[Unit]\nDescription=hand made\n")
rd = agent.act_extra_blocks_install({"entries": LIST})
check("install over a hand-made setup backs it up as *.maestro.bak",
      rd["replaced_handmade"] and open(agent.EB_SH + ".maestro.bak").read() == HANDMADE_SH)
os.remove(agent.EB_SH + ".maestro.bak")
rd2 = agent.act_extra_blocks_install({"entries": LIST})
check("reinstall over maestro's own files is not flagged",
      rd2["replaced_existing"] is False and not os.path.exists(agent.EB_SH + ".maestro.bak"))

SIM["rules"].insert(0, "-A NYM-EXIT " + RL)
check("stacked nym_scan_v2 is reported", agent._extra_blocks_state()["rate_limit_rules"] == 2)

# install-script action (kept for compatibility, still sha256-gated)
_iss = agent.EXEC_ACTIONS["extra_blocks_install_script"]
check("install-script rejects missing content / wrong / missing sha256",
      _iss({}).get("ok") is False and _iss({"content": "echo hi", "sha256": "deadbeef"}).get("ok") is False
      and _iss({"content": "echo hi"}).get("ok") is False)
_body = "#!/bin/bash\necho maestro-ok\n"
check("install-script runs content whose sha256 matches",
      _iss({"content": _body, "sha256": hashlib.sha256(_body.encode()).hexdigest()}).get("ok") is True)

check("status poll path never touches the network",
      "urlopen" not in inspect.getsource(agent._extra_blocks_state)
      and "urlopen" not in inspect.getsource(agent._eb_verify)
      and "urlopen" not in inspect.getsource(agent._eb_scan))
check("AGENT_VERSION 0.12.9", agent.AGENT_VERSION == "0.12.9")

# 15. act_upgrade hardening (A3): https required, sha256 mandatory, NTM path confined
_up = agent.EXEC_ACTIONS["upgrade"]
_r = _up({"url": "http://x/nym-node"})
check("upgrade rejects a non-https download url",
      _r.get("ok") is False and "https" in (_r.get("error") or ""))
check("upgrade no longer skips the integrity check when no sha is given",
      "skipping integrity check" not in inspect.getsource(_up)
      and 'fullmatch(r"[0-9a-f]{64}"' in inspect.getsource(_up))
check("upgrade confines the NTM script to a basename (no absolute path honoured)",
      "os.path.basename(ntm.get" in inspect.getsource(_up))

# 16. the rate-limit must never ACCEPT NEW above the exit policy (CERT-Bund
#     2026-09-28: port 9166 left the exit through an upto/ACCEPT rule).
_ins = [l for l in SCRIPT.replace("\\\n", " ").splitlines() if " -I " in l]
check("no inserted NEW/ACCEPT rule bypasses the exit policy",
      not any("NEW" in l and "-j ACCEPT" in l for l in _ins))
check("rate-limit drops only above the limit",
      any("--hashlimit-above" in l and "-j DROP" in l for l in _ins))
check("no catch-all NEW DROP is inserted",
      not any(_re.search(r"--ctstate NEW -j DROP", l) for l in _ins))

# 17. fan-out limiter (netscan protection, Hetzner 2026-10-24): lives in its own
#     sub-chains, only counts NEW SYNs to unseen (client, dst) pairs, never ACCEPTs,
#     is re-hooked idempotently and has a kill switch.
_fo = _inst.replace("\\\n", " ")
check("installer: fan-out stage 1 keys on (client, destination) pairs",
      "--hashlimit-mode srcip,dstip --hashlimit-upto 1/hour --hashlimit-burst 1" in _fo)
check("installer: fan-out stage 2 rejects per client above FO_RATE/FO_BURST",
      _re.search(r'-p tcp -m hashlimit --hashlimit-mode srcip\s+--hashlimit-above "\$FO_RATE" '
                 r'--hashlimit-burst "\$FO_BURST".*-j REJECT --reject-with tcp-reset', _fo) is not None)
check("installer: fan-out never ACCEPTs (falls through to the exit policy)",
      not any("FO_CHAIN" in l and "-j ACCEPT" in l for l in _fo.splitlines()))
check("installer: fan-out jump is purged by exact spec before re-insert",
      'grep -Fxc -- "-A $chain -j $FO_CHAIN"' in _fo and '-D "$chain" -j "$FO_CHAIN"' in _fo)
check("installer: fan-out applied to v4 and v6",
      'fanout_apply "$IPT" "$CHAIN" 4' in _fo and 'fanout_apply "$IPT6" "$CHAIN6" 6' in _fo)
check("installer: fan-out has a kill switch", 'if [ "$FO_ENABLE" != 1 ]' in _fo)
check("installer: fan-out writes no LOG rules (no client data stored)", "-j LOG" not in _fo)

# 17b. Upgrade/Install rewrite the runtime script from the agent's EB_SCRIPT, so the
#      built-in template must carry the identical limiter — else it silently vanishes
#      on the next nym-node restart after a maestro Upgrade/Install.
def _fo_block(src):
    """FO_* config + the fanout_apply function (not adjacent in the installer)."""
    a = src.index("# Fan-out limiter (netscan protection")
    cfg = src[a:src.index("\n", src.index('FO_CHAIN_NEW="', a)) + 1]
    f = src.index("# Apply (or with FO_ENABLE=0 remove) the fan-out limiter")
    return cfg + src[f:src.index("\n}\n", f) + 3]
_bi = agent.EB_SCRIPT.replace("\\\n", " ")
check("built-in: fan-out config + fanout_apply identical to the installer",
      _fo_block(agent.EB_SCRIPT) == _fo_block(_inst))
check("built-in: fan-out applied to v4 and v6",
      'fanout_apply "$IPT" "$CHAIN" 4' in _bi and 'fanout_apply "$IPT6" "$CHAIN6" 6' in _bi)
for _name, _src in (("built-in", _bi), ("installer", _fo)):
    check(f"{_name}: a fan-out failure cannot abort the blocklist/ESTABLISHED steps",
          all("|| echo" in l for l in _src.splitlines() if l.strip().startswith("fanout_apply ")))
    _ia = _src.index('fanout_apply "$IPT"')
    check(f"{_name}: v4 fan-out hooked before the ESTABLISHED accept is re-inserted",
          _ia < _src.index("--ctstate RELATED,ESTABLISHED -j ACCEPT", _ia))

# 17c. run fanout_apply for real against a fake iptables
import subprocess as _sp, tempfile as _tf
def _fo_exec(fail_on=None, enable=1, existing_jumps=0):
    fn = _fo_block(_inst)
    with _tf.TemporaryDirectory() as d:
        log = os.path.join(d, "log")
        sh = f"""set -euo pipefail
LOG={log!r}; FAIL={fail_on or ""!r}; JUMPS={existing_jumps}
fakeipt() {{
    echo "$*" >> "$LOG"
    if [ "$1" = -S ]; then i=0; while [ $i -lt $JUMPS ]; do echo "-A $2 -j NYM-FANOUT"; i=$((i+1)); done; return 0; fi
    if [ "$1" = -D ]; then JUMPS=$((JUMPS-1)); return 0; fi
    if [ -n "$FAIL" ] && [[ "$*" == *"$FAIL"* ]]; then return 1; fi
    return 0
}}
{fn}
FO_ENABLE={enable}
fanout_apply fakeipt NYM-EXIT 4 || echo "fan-out limiter FAILED (v4), continuing" >&2
echo REST-RAN
"""
        r = _sp.run(["bash", "-c", sh], capture_output=True, text=True, timeout=20)
        calls = open(log).read().splitlines() if os.path.exists(log) else []
        return r, calls
_r, _c = _fo_exec()
check("fanout_apply: hooks the jump after building both stages",
      _r.returncode == 0 and _c and _c[-1] == "-I NYM-EXIT -j NYM-FANOUT"
      and any("fo_pair4" in c for c in _c) and any("tcp-reset" in c for c in _c))
_r, _c = _fo_exec(fail_on="tcp-reset")
check("fanout_apply: failed stage 2 => no jump, warning, script continues",
      "REST-RAN" in _r.stdout and "FAILED (v4)" in _r.stderr
      and "-I NYM-EXIT -j NYM-FANOUT" not in _c)
_r, _c = _fo_exec(existing_jumps=2)
check("fanout_apply: re-run removes old jumps, inserts exactly one",
      sum(c == "-D NYM-EXIT -j NYM-FANOUT" for c in _c) == 2
      and sum(c == "-I NYM-EXIT -j NYM-FANOUT" for c in _c) == 1)
_r, _c = _fo_exec(enable=0, existing_jumps=1)
check("fanout_apply: kill switch unhooks + deletes chains, adds nothing",
      "-X NYM-FANOUT" in _c and "-X NYM-FANOUT-NEWDST" in _c
      and not any(c.startswith(("-I", "-A")) for c in _c))

check("installer chain names match the agent's fan-out reader",
      f'FO_CHAIN="{agent.EB_FO_CHAIN}"' in _fo and f'FO_CHAIN_NEW="{agent.EB_FO_CHAIN_NEW}"' in _fo)

# 18. agent reads the fan-out REJECT counter (v4+v6 summed) and the NYM-EXIT hook
_FO_L = {
    "iptables": ("Chain NYM-FANOUT-NEWDST (1 references)\n"
                 "    pkts      bytes target     prot opt in     out     source               destination\n"
                 "    1234    74040 REJECT     6    --  *      *       0.0.0.0/0            0.0.0.0/0"
                 "            limit: above 20/min burst 150 mode srcip htable-expire 600000 reject-with tcp-reset\n"
                 "    5000   300000 RETURN     0    --  *      *       0.0.0.0/0            0.0.0.0/0\n"),
    "ip6tables": ("Chain NYM-FANOUT-NEWDST (1 references)\n"
                  "    pkts      bytes target     prot opt in     out     source               destination\n"
                  "      66     5280 REJECT     6    --  *      *       ::/0                 ::/0"
                  "                 limit: above 20/min burst 150 mode srcip reject-with tcp-reset\n"),
}


def _fo_run(hooked, chains=True):
    def run(cmd, timeout=6, merge=False):
        if cmd[0] in _FO_L and cmd[1] == "-S":
            jump = f"-A {cmd[2]} -j NYM-FANOUT\n" if hooked else ""
            return (0, f"-N {cmd[2]}\n" + jump, "")
        if cmd[0] in _FO_L and cmd[1] == "-L" and cmd[2] == "NYM-FANOUT-NEWDST":
            return (0, _FO_L[cmd[0]], "") if chains else (1, "", "No chain/target/match by that name.")
        if cmd[:2] == ["systemctl", "show"]:
            return (0, "0\n", "")
        return (0, "", "")
    return run


_orig_run, _orig_v6 = agent._run, agent._eb_v6_supported
agent._eb_v6_supported = lambda: True
try:
    agent._run = _fo_run(hooked=True)
    _f = agent._eb_fanout_summary()
    check("fan-out: rejects summed over v4+v6", _f["fanout_rejects"] == 1300)
    check("fan-out: rate/burst parsed from the REJECT rule",
          _f["fanout_rate"] == "20/min" and _f["fanout_burst"] == 150)
    check("fan-out: jump in NYM-EXIT => active", _f["fanout_active"] is True)
    agent._run = _fo_run(hooked=False)
    _f = agent._eb_fanout_summary()
    check("fan-out: chains without jump => not active, counter still reported",
          _f["fanout_active"] is False and _f["fanout_rejects"] == 1300)
    agent._run = _fo_run(hooked=False, chains=False)
    _f = agent._eb_fanout_summary()
    check("fan-out: not installed => inactive, rejects None",
          _f["fanout_active"] is False and _f["fanout_rejects"] is None and _f["fanout_since"] is None)
finally:
    agent._run, agent._eb_v6_supported = _orig_run, _orig_v6
check("fan-out fields are part of the polled extra-blocks state",
      "fanout_rejects" in agent._extra_blocks_state() or not agent._eb_installed())


print(f"\n{ok} passed, {fail} failed")
raise SystemExit(1 if fail else 0)
