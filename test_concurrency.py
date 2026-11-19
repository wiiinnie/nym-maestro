"""Tests for nym_concurrency (per-client connlimit on high ports, anti-BitTorrent).

Covers: template == standalone installer, the real runtime script against a fake
iptables (idempotency, self-heal, limit file, fail-open, stop), the agent's live
parser/state/verify/actions with a simulated host, and the orchestrator side
(request validation, exit-only targeting, status column round-trip).
Run: .venv/bin/python test_concurrency.py
"""
import asyncio
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "agent"))
sys.path.insert(0, str(ROOT))
import agent  # noqa: E402

ok = fail = 0


def check(label, cond):
    global ok, fail
    if cond:
        ok += 1; print(f"  pass  {label}")
    else:
        fail += 1; print(f"  FAIL  {label}")


INST = (ROOT / "install-nym-concurrency.sh").read_text()

# ---------------------------------------------------------------------------
print("\ntemplate vs installer:")


def _heredoc(src, target):
    a = src.index(f'cat > "{target}" <<\'EOF\'\n') + len(f'cat > "{target}" <<\'EOF\'\n')
    return src[a:src.index("\nEOF\n", a) + 1]


check("runtime script in installer is word-identical to agent NC_SCRIPT",
      _heredoc(INST, "$SCRIPT") == agent.NC_SCRIPT)
check("unit in installer == agent NC_UNIT_TPL (for nym-node.service)",
      _heredoc(INST, "$UNIT") == agent.NC_UNIT_TPL.replace("__NYM__", "nym-node.service"))
S = agent.NC_SCRIPT
check("script IFACES match NC_IFACES",
      f'IFACES="{" ".join(agent.NC_IFACES)}"' in S)
check("script default/min/max limit match the agent constants",
      f"DEFAULT_LIMIT={agent.NC_DEFAULT_LIMIT}\n" in S and f"LIMIT_MIN={agent.NC_LIMIT_MIN}\n" in S
      and f"LIMIT_MAX={agent.NC_LIMIT_MAX}\n" in S)
check("script chain/table names match the agent reader",
      f"CHAIN={agent.NC_CHAIN}\n" in S and f"TABLE={agent.NC_TABLE}\n" in S)
check("limit rules only match NEW connections",
      S.count("--ctstate NEW") == 1 and "-m conntrack --ctstate NEW \\\n            -m connlimit" in S)
check("v4 counted per /32, v6 per /128",
      "nc_apply iptables 32 4" in S and 'nc_apply "$IPT6" 128 6' in S)
check("hooks are interface-scoped only (no unscoped -j insert)",
      re.search(r'-I PREROUTING -j', S) is None and '-I PREROUTING -i "$ifc" -j "$CHAIN"' in S)
check("no line-number deletes (nf_tables-safe)", re.search(r"-D \S+ \d+", S) is None)
check("unit: restart re-applies, stop tears down, PartOf nym-node",
      "ExecStop=/usr/local/sbin/nym-concurrency.sh stop" in agent.NC_UNIT_TPL
      and "PartOf=__NYM__" in agent.NC_UNIT_TPL and "RemainAfterExit=yes" in agent.NC_UNIT_TPL)
check("installer ends with restart (not start)",
      "systemctl restart nym-concurrency.service" in INST and "systemctl start" not in INST)
check("limit read from a file, never interpolated into the script text",
      'LIMIT="$(cat "$STATE_DIR/limit"' in S)

# ---------------------------------------------------------------------------
print("\nruntime script against a fake iptables:")

FAKE_IPT = r'''#!/usr/bin/env bash
# fake iptables/ip6tables: PREROUTING in $D/<fam>.pre, our chain in $D/<fam>.chain
fam=$(basename "$0"); pre="$D/$fam.pre"; ch="$D/$fam.chain"
echo "$fam $*" >> "$D/log"
[ "$1" = -t ] && shift 2
touch "$pre"
case "$1" in
  -S) [ "$2" = PREROUTING ] && cat "$pre"; exit 0 ;;
  -nL)
    if [ "$2" = PREROUTING ]; then
      [ "$fam" = ip6tables ] && [ "${NOV6:-0}" = 1 ] && exit 1; exit 0
    fi
    [ -f "$ch" ]; exit $? ;;
  -L) [ -f "$ch" ] && cat "$ch"; [ -f "$ch" ]; exit $? ;;
  -N) [ -f "$ch" ] && exit 1; : > "$ch"; exit 0 ;;
  -F) [ -f "$ch" ] || exit 1; : > "$ch"; exit 0 ;;
  -X) rm -f "$ch"; exit 0 ;;
  -A) shift 2
      if [ -n "${FAIL:-}" ] && [ "$fam" = "${FAILFAM:-iptables}" ] && [[ "$*" == *"$FAIL"* ]]; then exit 1; fi
      echo "$*" >> "$ch"; exit 0 ;;
  -I) shift 2; { echo "-A PREROUTING $*"; cat "$pre"; } > "$pre.n"; mv "$pre.n" "$pre"; exit 0 ;;
  -D) shift 2; want="-A PREROUTING $*"
      n=$(grep -nFx -- "$want" "$pre" | head -n1 | cut -d: -f1)
      [ -n "$n" ] || exit 1
      sed "${n}d" "$pre" > "$pre.n"; mv "$pre.n" "$pre"; exit 0 ;;
esac
exit 0
'''


def run_script(arg="apply", limit=None, pre4="", pre6="", env=None, keep=None):
    d = keep or tempfile.mkdtemp()
    bindir = os.path.join(d, "bin"); os.makedirs(bindir, exist_ok=True)
    for name in ("iptables", "ip6tables"):
        p = os.path.join(bindir, name)
        with open(p, "w") as f:
            f.write(FAKE_IPT)
        os.chmod(p, 0o755)
    with open(os.path.join(bindir, "modprobe"), "w") as f:
        f.write("#!/bin/sh\nexit 0\n")
    os.chmod(os.path.join(bindir, "modprobe"), 0o755)
    if keep is None:
        open(os.path.join(d, "iptables.pre"), "w").write(pre4)
        open(os.path.join(d, "ip6tables.pre"), "w").write(pre6)
    state = os.path.join(d, "state"); os.makedirs(state, exist_ok=True)
    lim = os.path.join(state, "limit")
    if limit is not None:
        open(lim, "w").write(limit)
    elif os.path.exists(lim) and keep is None:
        os.remove(lim)
    # the script prepends system dirs to PATH; drop that line so the fakes win,
    # and point STATE_DIR at the temp dir
    body = (agent.NC_SCRIPT
            .replace("export PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH\n", "")
            .replace("STATE_DIR=/var/lib/nym-concurrency", f"STATE_DIR={state}"))
    sp = os.path.join(d, "nc.sh")
    open(sp, "w").write(body)
    e = dict(os.environ, D=d, PATH=bindir + ":/usr/bin:/bin")
    e.update(env or {})
    r = subprocess.run(["bash", sp, arg], capture_output=True, text=True, env=e, timeout=30)

    def rd(n):
        p = os.path.join(d, n)
        return open(p).read().splitlines() if os.path.exists(p) else None
    return r, d, {"pre4": rd("iptables.pre"), "pre6": rd("ip6tables.pre"),
                  "ch4": rd("iptables.chain"), "ch6": rd("ip6tables.chain")}


HOOKS = ["-A PREROUTING -i nymtun0 -j NYM-CONCURRENCY", "-A PREROUTING -i nymwg -j NYM-CONCURRENCY"]

r, d, st = run_script()
check("clean apply exits 0", r.returncode == 0)
check("v4: exactly the two scoped hooks", sorted(st["pre4"]) == sorted(HOOKS))
check("v6: exactly the two scoped hooks", sorted(st["pre6"]) == sorted(HOOKS))
_drops4 = [l for l in st["ch4"] if "-j DROP" in l]
check("v4 chain: 4 exemptions then TCP+UDP limit rules",
      len(st["ch4"]) == 6 and all("RETURN" in l for l in st["ch4"][:4]) and len(_drops4) == 2)
check("exemptions: LOCAL dst, WG udp 51822, Steam tcp+udp",
      "-m addrtype --dst-type LOCAL -j RETURN" in st["ch4"]
      and "-p udp --dport 51822 -j RETURN" in st["ch4"]
      and "-p tcp --dport 27000:27050 -j RETURN" in st["ch4"]
      and "-p udp --dport 27000:27050 -j RETURN" in st["ch4"])
check("default limit 50, mask 32, NEW only, comment",
      all("--connlimit-above 50 --connlimit-mask 32" in l and "--ctstate NEW" in l
          and "--comment nym_concurrency" in l and "--dport 12000:65535" in l for l in _drops4))
check("v6 rules use mask 128",
      all("--connlimit-mask 128" in l for l in st["ch6"] if "-j DROP" in l))

# re-run on the same state: idempotent
r, d, st = run_script(keep=d)
check("re-apply is idempotent (still exactly two hooks, 6 rules)",
      r.returncode == 0 and sorted(st["pre4"]) == sorted(HOOKS) and len(st["ch4"]) == 6)

# self-heal: unscoped hook from the earlier hand test, duplicates, a foreign rule
_polluted = "\n".join([
    "-A PREROUTING -j NYM-CONCURRENCY",
    "-A PREROUTING -j NYM-CONCURRENCY",
    "-A PREROUTING -i nymwg -j NYM-CONCURRENCY",
    "-A PREROUTING -i nymwg -j NYM-CONCURRENCY",
    "-A PREROUTING -i eth0 -j CONNMARK --restore-mark",
]) + "\n"
r, d, st = run_script(pre4=_polluted)
check("self-heal: unscoped + duplicate hooks drained, two scoped hooks left",
      sorted(l for l in st["pre4"] if "NYM-CONCURRENCY" in l) == sorted(HOOKS))
check("self-heal: foreign PREROUTING rule untouched",
      "-A PREROUTING -i eth0 -j CONNMARK --restore-mark" in st["pre4"])

for val, want, label in (("75\n", 75, "limit file 75 is applied"),
                         ("080", 80, "leading zero parsed as decimal"),
                         ("5", 50, "below minimum falls back to 50"),
                         ("99999", 50, "above maximum falls back to 50"),
                         ("50; rm -rf /", 50, "garbage falls back to 50")):
    r, d, st = run_script(limit=val)
    check(label, r.returncode == 0 and all(f"--connlimit-above {want} " in l
                                           for l in st["ch4"] if "-j DROP" in l))
r, d, st = run_script(limit="abc")
check("invalid limit file is reported on stderr", "invalid limit 'abc'" in r.stderr)

# fail-open: v4 connlimit missing -> no half limiter, unit fails visibly
r, d, st = run_script(env={"FAIL": "connlimit", "FAILFAM": "iptables"})
check("v4 rule failure: exit 1, no hooks, chain removed",
      r.returncode == 1 and not [l for l in st["pre4"] if "NYM-CONCURRENCY" in l]
      and st["ch4"] is None and "FAILED (v4)" in r.stderr)
r, d, st = run_script(env={"FAIL": "connlimit", "FAILFAM": "ip6tables"})
check("v6 rule failure: v4 stays active, v6 torn down, exit 0",
      r.returncode == 0 and sorted(st["pre4"]) == sorted(HOOKS)
      and not [l for l in st["pre6"] if "NYM-CONCURRENCY" in l] and st["ch6"] is None)
r, d, st = run_script(env={"NOV6": "1"})
check("no ip6tables mangle: v6 skipped, v4 active",
      r.returncode == 0 and sorted(st["pre4"]) == sorted(HOOKS) and not st["pre6"]
      and "v6 limiter skipped" in r.stderr)

# stop
r, d, st = run_script(pre4="-A PREROUTING -i eth0 -j CONNMARK --restore-mark\n")
r, d, st = run_script("stop", keep=d)
check("stop: hooks + chains gone (v4+v6), foreign rule kept",
      r.returncode == 0 and st["pre4"] == ["-A PREROUTING -i eth0 -j CONNMARK --restore-mark"]
      and not st["pre6"] and st["ch4"] is None and st["ch6"] is None)
r, _, _ = run_script("bogus")
check("unknown argument -> exit 2", r.returncode == 2)

# ---------------------------------------------------------------------------
print("\nagent:")

check("nc_parse_limit", agent.nc_parse_limit(50) == 50 and agent.nc_parse_limit("75") == 75
      and agent.nc_parse_limit(" 60\n") == 60 and agent.nc_parse_limit(9) is None
      and agent.nc_parse_limit(10001) is None and agent.nc_parse_limit(True) is None
      and agent.nc_parse_limit("5e1") is None and agent.nc_parse_limit(50.0) is None
      and agent.nc_parse_limit(None) is None)
check("AGENT_VERSION >= 0.12.8 (first with nym_concurrency)",
      tuple(int(x) for x in agent.AGENT_VERSION.split(".")) >= (0, 12, 8))
for a in ("status", "install", "set_limit", "restart", "verify", "remove"):
    check(f"action concurrency_{a} registered", f"concurrency_{a}" in agent.EXEC_ACTIONS)

_sd = tempfile.mkdtemp()
agent.NC_STATE_DIR = os.path.join(_sd, "var")
agent.NC_LIMIT_FILE = os.path.join(agent.NC_STATE_DIR, "limit")
agent.NC_SH = os.path.join(_sd, "sbin", "nym-concurrency.sh")
agent.NC_UNIT = os.path.join(_sd, "systemd", "nym-concurrency.service")
os.makedirs(os.path.join(_sd, "systemd"), exist_ok=True)
agent.NYM_SERVICE = "nym-node.service"
agent.unit_exists = lambda u: True
agent.nym_node_since = lambda svc: 1700000000
agent._eb_v6_supported = lambda: True


def _l_out(fam, limit, tcp, udp, prot_numeric=True):
    src = "0.0.0.0/0" if fam == 4 else "::/0"
    t, u = ("6", "17") if prot_numeric else ("tcp", "udp")
    mask = 32 if fam == 4 else 128
    return (f"Chain NYM-CONCURRENCY (2 references)\n"
            f"    pkts      bytes target     prot opt in     out     source               destination\n"
            f"    9000   540000 RETURN     0    --  *      *       {src}            {src}            ADDRTYPE match dst-type LOCAL\n"
            f"     {tcp}    48720 DROP       {t}    --  *      *       {src}            {src}            "
            f"tcp dpts:12000:65535 ctstate NEW #conn src/{mask} > {limit} /* nym_concurrency */\n"
            f"     {udp}    99120 DROP       {u}    --  *      *       {src}            {src}            "
            f"udp dpts:12000:65535 ctstate NEW #conn src/{mask} > {limit} /* nym_concurrency */\n")


SIM = {}


def reset_sim(**kw):
    SIM.clear()
    SIM.update({"active": False, "enabled": False, "limit": 50,
                "pre": {"iptables": [], "ip6tables": []},
                "chain": {"iptables": False, "ip6tables": False},
                "drops": {"iptables": (812, 1652), "ip6tables": (10, 20)},
                "numeric": True, "restarts": 0, "fail_restart": False, "calls": []})
    SIM.update(kw)


def _apply_sim():
    # what the oneshot does, using the limit file the agent wrote
    try:
        SIM["limit"] = int(open(agent.NC_LIMIT_FILE).read().strip())
    except Exception:
        SIM["limit"] = 50
    for fam in ("iptables", "ip6tables"):
        SIM["chain"][fam] = True
        SIM["pre"][fam] = [f"-A PREROUTING -i {i} -j NYM-CONCURRENCY" for i in agent.NC_IFACES]
    SIM["active"] = True


def sim_run(cmd, timeout=6, merge=False):
    SIM["calls"].append(cmd)
    NC = agent.NC_UNIT_NAME
    if cmd[0] == "systemctl":
        sub = cmd[1]
        units = [a for a in cmd[2:] if not a.startswith("-")]
        tgt = units[0] if units else ""
        if sub == "is-active" and tgt == NC:
            return (0, "active\n" if SIM["active"] else "inactive\n", "")
        if sub == "is-enabled" and tgt == NC:
            return (0, "enabled\n" if SIM["enabled"] else "disabled\n", "")
        if sub == "enable":
            SIM["enabled"] = True; return (0, "", "")
        if sub == "disable":
            SIM["enabled"] = False; SIM["active"] = False; return (0, "", "")
        if sub == "restart" and tgt == NC:
            SIM["restarts"] += 1
            if SIM["fail_restart"]:
                SIM["active"] = False
                return (1, "", "Job failed")
            _apply_sim(); return (0, "", "")
        return (0, "", "")
    if cmd[0] == "journalctl":
        return (0, "applied nym_concurrency (v4): limit 50\n", "")
    if cmd[0] in ("iptables", "ip6tables"):
        fam = cmd[0]
        args = cmd[3:] if cmd[1] == "-t" else cmd[1:]
        if args[:2] == ["-S", "PREROUTING"]:
            return (0, "-P PREROUTING ACCEPT\n" + "".join(l + "\n" for l in SIM["pre"][fam]), "")
        if args[:2] == ["-L", "NYM-CONCURRENCY"]:
            if not SIM["chain"][fam]:
                return (1, "", "iptables: No chain/target/match by that name.")
            tcp, udp = SIM["drops"][fam]
            return (0, _l_out(4 if fam == "iptables" else 6, SIM["limit"], tcp, udp, SIM["numeric"]), "")
        if args[:2] == ["-D", "PREROUTING"]:
            line = "-A PREROUTING " + " ".join(args[2:])
            if line in SIM["pre"][fam]:
                SIM["pre"][fam].remove(line); return (0, "", "")
            return (1, "", "Bad rule")
        if args[:1] == ["-X"]:
            SIM["chain"][fam] = False
            return (0, "", "")
        return (0, "", "")
    if cmd[0] == agent.NC_SH and cmd[1:] == ["stop"]:
        for fam in ("iptables", "ip6tables"):
            SIM["pre"][fam] = []; SIM["chain"][fam] = False
        return (0, "nym_concurrency removed\n", "")
    return (0, "", "")


agent._run = sim_run
reset_sim()

st = agent._nc_state()
check("not installed, no rules -> missing", st["state"] == "missing" and st["installed"] is False)
SIM["chain"]["iptables"] = True
SIM["pre"]["iptables"] = ["-A PREROUTING -j NYM-CONCURRENCY"]
st = agent._nc_state()
check("rules without our unit -> 'unmanaged' with live limit",
      st["state"] == "unmanaged" and st["limit"] == 50 and st["hooked_ifaces"] == ["*"])

# parser
reset_sim(chain={"iptables": True, "ip6tables": True},
          pre={"iptables": ["-A PREROUTING -i nymwg -j NYM-CONCURRENCY",
                            "-A PREROUTING -i eth0 -j CONNMARK --restore-mark",
                            "-A PREROUTING -i nymtun0 -j NYM-CONCURRENCY"],
               "ip6tables": ["-A PREROUTING -i nymwg -j NYM-CONCURRENCY"]})
f4 = agent._nc_family("iptables")
check("parser: hooks only our jumps, keeps iface names",
      f4["hooked_ifaces"] == ["nymwg", "nymtun0"])
check("parser: limit/mask from '#conn src/32 > 50'", f4["limit"] == 50 and f4["mask"] == 32)
check("parser: TCP/UDP drops split, exact counters, RETURN ignored",
      f4["drops_tcp"] == 812 and f4["drops_udp"] == 1652 and f4["drops"] == 2464 and f4["rules"] == 2)
SIM["numeric"] = False
f4 = agent._nc_family("iptables")
check("parser: named protocols (legacy iptables) work too",
      f4["drops_tcp"] == 812 and f4["drops_udp"] == 1652)
live = agent._nc_live()
check("live: drops summed v4+v6, v6 reported separately",
      live["drops"] == 2494 and live["v6_drops"] == 30 and live["v6_active"] is True
      and live["drops_udp"] == 1672)
check("live: limit from v4 rule", live["limit"] == 50)

# install
reset_sim()
r = agent.act_concurrency_install({"limit": 5})
check("install rejects limit out of range before writing anything",
      r["ok"] is False and not os.path.exists(agent.NC_SH) and SIM["restarts"] == 0)
r = agent.act_concurrency_install({"limit": "50; reboot"})
check("install rejects non-integer limit", r["ok"] is False and not os.path.exists(agent.NC_LIMIT_FILE))
r = agent.act_concurrency_install({})
check("install without limit: default 50 written, applied, verified",
      r["ok"] is True and open(agent.NC_LIMIT_FILE).read().strip() == "50"
      and SIM["restarts"] == 1 and r["state"]["limit"] == 50, )
check("install writes the built-in template + unit for the resolved service",
      open(agent.NC_SH).read() == agent.NC_SCRIPT
      and "PartOf=nym-node.service" in open(agent.NC_UNIT).read()
      and os.access(agent.NC_SH, os.X_OK))
check("install enables the unit and restarts it (not start)",
      ["systemctl", "enable", agent.NC_UNIT_NAME] in SIM["calls"]
      and ["systemctl", "restart", agent.NC_UNIT_NAME] in SIM["calls"]
      and not any(c[:2] == ["systemctl", "start"] for c in SIM["calls"]))
check("install result tagged kind=concurrency with checks", r["kind"] == "concurrency"
      and all(c["ok"] for c in r["checks"]))
open(agent.NC_LIMIT_FILE, "w").write("70\n")
r = agent.act_concurrency_install({})
check("reinstall without limit keeps the node's current value",
      open(agent.NC_LIMIT_FILE).read().strip() == "70" and r["state"]["limit"] == 70)
r = agent.act_concurrency_install({"limit": 60})
check("install with limit writes it", open(agent.NC_LIMIT_FILE).read().strip() == "60"
      and r["state"]["configured_limit"] == 60 and r["ok"])

# set_limit
r = agent.act_concurrency_set_limit({"limit": 80})
check("set_limit: file rewritten, re-applied, live = configured",
      r["ok"] and r["state"]["limit"] == 80 and r["state"]["configured_limit"] == 80
      and "60 -> 80" in r["output"])
r = agent.act_concurrency_set_limit({"limit": 0})
check("set_limit rejects bad value, keeps file", r["ok"] is False
      and open(agent.NC_LIMIT_FILE).read().strip() == "80")

# verify catches drift
SIM["limit"] = 50          # rule says 50, file says 80 (e.g. hand edit without restart)
_, checks, vok = agent._nc_verify()
check("verify: live limit != configured -> fails", vok is False
      and any(c["name"] == "live limit = configured limit" and not c["ok"] for c in checks))
SIM["limit"] = 80
SIM["pre"]["iptables"] = ["-A PREROUTING -i nymwg -j NYM-CONCURRENCY"]
_, checks, vok = agent._nc_verify()
check("verify: missing nymtun0 hook -> fails", vok is False)
SIM["pre"]["iptables"] = [f"-A PREROUTING -i {i} -j NYM-CONCURRENCY" for i in agent.NC_IFACES]
SIM["pre"]["ip6tables"] = []
_, checks, vok = agent._nc_verify()
check("verify: v6 not active is reported but does not fail the node",
      vok is True and any(c["name"].startswith("v6") and not c["ok"] for c in checks))
SIM["fail_restart"] = True
r = agent.act_concurrency_restart({})
check("restart failure -> ok False with error", r["ok"] is False and r["error"])
SIM["fail_restart"] = False

# status poll
check("build_status carries the concurrency state",
      "concurrency" in agent.build_status())

# remove (also drains a leftover unscoped hook the script's stop might miss)
_apply_sim()
_orig_stop = sim_run


def _run_stop_misses(cmd, timeout=6, merge=False):
    if cmd[0] == agent.NC_SH:
        SIM["calls"].append(cmd)
        SIM["pre"]["iptables"] = ["-A PREROUTING -j NYM-CONCURRENCY",
                                  "-A PREROUTING -j NYM-CONCURRENCY"]
        SIM["pre"]["ip6tables"] = []
        return (0, "", "")
    return _orig_stop(cmd, timeout, merge)


agent._run = _run_stop_misses
r = agent.act_concurrency_remove({})
check("remove: hooks + chains gone, files deleted, unit disabled",
      r["ok"] is True and not SIM["pre"]["iptables"] and not SIM["chain"]["iptables"]
      and not SIM["chain"]["ip6tables"] and not os.path.exists(agent.NC_SH)
      and not os.path.exists(agent.NC_UNIT) and not os.path.exists(agent.NC_LIMIT_FILE)
      and SIM["enabled"] is False)
check("remove: leftover hooks deleted by exact spec", "2 leftover hook(s)" in r["output"])
agent._run = sim_run
r = agent.act_concurrency_set_limit({"limit": 50})
check("set_limit on a node without install -> error", r["ok"] is False and "not installed" in r["error"])

# ---------------------------------------------------------------------------
print("\norchestrator:")
import app as appmod  # noqa: E402
import store as storemod  # noqa: E402
from pydantic import ValidationError  # noqa: E402

try:
    appmod.ConcurrencyLimitRequest(node_ids=["x"], limit=9); _bad = False
except ValidationError:
    _bad = True
check("limit request: below 10 rejected", _bad)
try:
    appmod.ConcurrencyLimitRequest(node_ids=["x"], limit=True); _bad = False
except ValidationError:
    _bad = True
check("limit request: bool rejected", _bad)
check("install request: limit optional, valid value kept",
      appmod.ConcurrencyInstallRequest(node_ids=["x"]).limit is None
      and appmod.ConcurrencyInstallRequest(node_ids=["x"], limit=50).limit == 50)
check("orchestrator bounds match the agent",
      (appmod.NC_LIMIT_MIN, appmod.NC_LIMIT_MAX) == (agent.NC_LIMIT_MIN, agent.NC_LIMIT_MAX))

_d = tempfile.mkdtemp()
st = storemod.Store(os.path.join(_d, "t.db"), (ROOT / "schema.sql").read_text())
u_exit = st.create_node({"node_id": "nym-exit-AT01", "name": "AT01", "ip": "10.0.0.1"})
u_mix = st.create_node({"node_id": "mix-01", "name": "MIX01", "ip": "10.0.0.2"})
_conc = {"installed": True, "active": True, "limit": 50, "drops": 2464}
st.upsert_status(u_exit, reachable=True, mode="exit-gateway", exit=True, concurrency=_conc)
st.upsert_status(u_mix, reachable=True, mode="mixnode", exit=False)
check("status round-trip: concurrency persisted and returned",
      st.get_node(u_exit)["status"]["concurrency"] == _conc
      and st.get_node(u_mix)["status"]["concurrency"] is None)


class _PKI:
    def ready(self): return True


class _Req:
    class app:
        class state:
            pass
_Req.app.state.store = st
_Req.app.state.pki = _PKI()

_, nodes, skipped = appmod._nc_targets(_Req, [u_exit, u_mix])
check("install targets: exits only, mixnode skipped with a reason",
      [n["uid"] for n in nodes] == [u_exit] and len(skipped) == 1
      and skipped[0]["result"]["skipped"] and "not an exit" in skipped[0]["result"]["error"])
_, nodes, skipped = appmod._nc_targets(_Req, [u_exit, u_mix], exits_only=False)
check("remove/status/verify targets: all nodes", len(nodes) == 2 and not skipped)


class _Resp:
    def json(self): return {"error": "unknown action: concurrency_install"}


class _HTTPErr(Exception):
    response = _Resp()


async def _boom(*a, **k):
    raise _HTTPErr("Client error '400 Bad Request'")
_orig_exec = appmod.agent_exec
appmod.agent_exec = _boom
try:
    res = asyncio.run(appmod._nc_fanout(None, st, [st.get_node(u_exit)], "concurrency_install",
                                        {}, 5, "concurrency_install"))
finally:
    appmod.agent_exec = _orig_exec
check("old agent: 'unknown action' mapped to an update-agent hint",
      res[0]["ok"] is False and "0.12.8" in res[0]["result"]["error"]
      and res[0]["result"]["kind"] == "concurrency")

print(f"\n{ok} passed, {fail} failed")
raise SystemExit(1 if fail else 0)
