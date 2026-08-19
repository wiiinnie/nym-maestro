"""Distro-upgrade feature: agent parsers/guards + orchestrator planning.

Script-style suite like the others: run directly, prints N passed, M failed,
exits 1 on failure. No node, no network — everything is canned/monkeypatched.
"""
import base64
import json
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "agent"))
import agent   # noqa: E402
import distro  # noqa: E402

ok = fail = 0


def check(label, cond):
    global ok, fail
    if cond:
        ok += 1; print(f"  pass  {label}")
    else:
        fail += 1; print(f"  FAIL  {label}")


# --- agent: parsers ---------------------------------------------------------
print("agent parsers")

osr = agent.parse_os_release(
    'NAME="Ubuntu"\nID=ubuntu\n# comment\nVERSION_ID="22.04"\n'
    "VERSION_CODENAME=jammy\nPRETTY_NAME='Ubuntu 22.04.4 LTS'\nBROKEN\n")
check("os-release: unquotes values", osr["VERSION_ID"] == "22.04")
check("os-release: bare values", osr["VERSION_CODENAME"] == "jammy")
check("os-release: single quotes", osr["PRETTY_NAME"] == "Ubuntu 22.04.4 LTS")
check("os-release: skips junk lines", "BROKEN" not in osr and "# comment" not in osr)

check("meminfo total in bytes",
      agent.parse_meminfo_total("MemTotal:        4030584 kB\nMemFree: 1 kB")
      == 4030584 * 1024)
check("meminfo: None on garbage", agent.parse_meminfo_total("nope") is None)

cpu = agent.parse_cpu_info(
    "processor\t: 0\nmodel name\t: AMD EPYC 7282\nprocessor\t: 1\n"
    "model name\t: AMD EPYC 7282\n")
check("cpuinfo x86: model + cores", cpu == {"model": "AMD EPYC 7282", "cores": 2})
cpu = agent.parse_cpu_info("processor\t: 0\nBogoMIPS: 50\nModel\t: Raspberry Pi 4\n")
check("cpuinfo arm: Model fallback", cpu["model"] == "Raspberry Pi 4" and cpu["cores"] == 1)

up, new, sec = agent.parse_apt_counts(
    "Inst libssl3 [3.0.2-0ubuntu1.15] (3.0.2-0ubuntu1.16 Ubuntu:22.04/jammy-security [amd64])\n"
    "Inst vim [2:8.2] (2:8.2.1 Ubuntu:22.04/jammy-updates [amd64])\n"
    "Conf libssl3 (3.0.2-0ubuntu1.16 ...)\n"
    "7 upgraded, 2 newly installed, 0 to remove and 0 not upgraded.\n")
check("apt counts: upgraded/new", (up, new) == (7, 2))
check("apt counts: security pocket lines", sec == 1)
check("apt counts: None without summary", agent.parse_apt_counts("") == (None, None, None))

# --- agent: runner generation ------------------------------------------------
print("agent runner")

params = {"mode": "packages", "reboot": "auto", "distro": "ubuntu",
          "state_file": "/tmp/s.json", "log_file": "/tmp/l.log",
          "from_version": "22.04", "from_codename": "jammy",
          "target": '24.04 "noble"', "target_codename": None}
src = agent.render_distro_runner(params)
try:
    compile(src, "runner.py", "exec")
    check("runner compiles", True)
except SyntaxError:
    check("runner compiles", False)
blob = src.split('b64decode("')[1].split('")')[0]
check("runner params survive base64 round-trip (quotes included)",
      json.loads(base64.b64decode(blob)) == params)
check("runner is stdlib-only imports",
      all(m in ("base64", "json", "os", "re", "shutil", "subprocess", "sys",
                "time", "traceback")
          for line in src.splitlines() if line.startswith("import ")
          for m in line[7:].split(", ")))
check("runner reinstalls lockout-critical packages", "ensure_essentials" in src)

# --- agent: action guards (no systemd here — everything monkeypatched) -------
print("agent action guards")

tmp = tempfile.mkdtemp(prefix="maestro-distro-test-")
agent.CERTDIR = tmp
agent.DISTRO_STATE = os.path.join(tmp, "state.json")
agent.DISTRO_LOG = os.path.join(tmp, "log")
agent.DISTRO_RUNNER = os.path.join(tmp, "runner.py")

_orig_run, _orig_read = agent._run, agent._read_text
FAKE_FILES = {}


def fake_read(path):
    return FAKE_FILES.get(path)


def fake_run_inactive(cmd, timeout=6, merge=False):
    if cmd[:2] == ["systemctl", "is-active"]:
        return 3, "inactive\n", ""
    return 0, "", ""


agent._read_text = fake_read
agent._run = fake_run_inactive

FAKE_FILES["/etc/os-release"] = "ID=ubuntu\nVERSION_ID=\"22.04\"\nVERSION_CODENAME=jammy\n"
r = agent.act_distro_upgrade({"mode": "sideways"})
check("rejects unknown mode", not r["ok"] and "mode" in r["error"])
r = agent.act_distro_upgrade({"mode": "packages", "reboot": "yolo"})
check("rejects unknown reboot policy", not r["ok"] and "reboot" in r["error"])

FAKE_FILES["/etc/os-release"] = "ID=fedora\nVERSION_ID=40\n"
r = agent.act_distro_upgrade({"mode": "packages"})
check("rejects unsupported distro", not r["ok"] and "fedora" in r["error"])

FAKE_FILES["/etc/os-release"] = "ID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n"
r = agent.act_distro_upgrade({"mode": "release"})
check("debian release needs target_codename", not r["ok"] and "target_codename" in r["error"])

_which = agent.shutil.which
agent.shutil.which = lambda *_: None
FAKE_FILES["/etc/os-release"] = "ID=ubuntu\nVERSION_ID=\"22.04\"\nVERSION_CODENAME=jammy\n"
r = agent.act_distro_upgrade({"mode": "release"})
check("ubuntu release needs do-release-upgrade", not r["ok"] and "do-release-upgrade" in r["error"])
agent.shutil.which = _which

FAKE_FILES["/etc/os-release"] = "ID=ubuntu\nVERSION_ID=\"22.04\"\nVERSION_CODENAME=jammy\n"
r = agent.act_distro_upgrade({"mode": "packages"})
check("start: launches via systemd-run", r["ok"] and r.get("started"))
seed = json.load(open(agent.DISTRO_STATE))
check("start: seeds state with from_version + starting phase",
      seed["from_version"] == "22.04" and seed["phase"] == "starting")
os.remove(agent.DISTRO_STATE)

r = agent.act_distro_status({})
check("status: idle without state file", r["ok"] and r["phase"] == "idle")

# rebooting -> done once the box is up again and services are green
now = int(time.time())
with open(agent.DISTRO_STATE, "w") as f:
    json.dump({"version": 1, "mode": "packages", "reboot": "auto",
               "started_at": now - 600, "phase": "rebooting", "pct": 96,
               "eta_epoch": None, "error": None, "needs_reboot": True,
               "finished_at": None, "target": None, "phases": []}, f)
_orig_btime, _orig_svcstate, _orig_unit = agent._proc_btime, agent.service_state, agent.unit_exists
agent._proc_btime = lambda: now - 60          # booted after the upgrade started
agent.service_state = lambda: (True, "nym-node.service")
agent.unit_exists = lambda u: False           # no fail2ban here
FAKE_FILES["/proc/net/dev"] = "nymtun0: 1 2\n nymwg: 3 4\n"
r = agent.act_distro_status({})
check("status: reboot detected -> verified done", r["phase"] == "done" and r["pct"] == 100)
check("status: verify checks all ok", all(c["ok"] for c in r["verify"]))
st = json.load(open(agent.DISTRO_STATE))
check("status: done state persisted", st["phase"] == "done" and st["finished_at"])

# rebooting but a service missing -> stays "verifying" (orchestrator retries)
with open(agent.DISTRO_STATE, "w") as f:
    json.dump({"version": 1, "mode": "packages", "reboot": "auto",
               "started_at": now - 600, "phase": "rebooting", "pct": 96,
               "phases": []}, f)
agent.service_state = lambda: (False, "nym-node.service")
r = agent.act_distro_status({})
check("status: services red -> verifying, not done", r["phase"] == "verifying")
check("status: red check named", any(not c["ok"] for c in r["verify"]))

def _age_state(sec=600):
    """Push the state file's mtime into the past — a fresh mtime means 'the
    runner is alive and writing', which most dead-unit tests must not trip."""
    os.utime(agent.DISTRO_STATE, (now - sec, now - sec))


# runner died mid-flight (no unit, stale state) -> failed
with open(agent.DISTRO_STATE, "w") as f:
    json.dump({"version": 1, "mode": "packages", "reboot": "auto",
               "started_at": now - 600, "phase": "install", "pct": 40,
               "phases": []}, f)
agent._proc_btime = lambda: now - 3000        # no reboot since start
r = agent.act_distro_status({})
check("status: fresh state file -> runner alive, phase untouched",
      r["phase"] == "install" and not r["error"])
_age_state()
r = agent.act_distro_status({})
check("status: dead runner -> failed", r["phase"] == "failed" and "not running" in r["error"])

# runner killed but its apt/do-release-upgrade child still holds the lock
def _mid_release_state():
    with open(agent.DISTRO_STATE, "w") as f:
        json.dump({"version": 1, "mode": "release", "reboot": "auto",
                   "started_at": now - 600, "phase": "release_upgrade", "pct": 40,
                   "from_version": "25.04", "phases": []}, f)
    _age_state()


_mid_release_state()
FAKE_FILES["/etc/os-release"] = "ID=ubuntu\nVERSION_ID=\"25.04\"\nVERSION_CODENAME=plucky\n"
_orig_lock = agent._apt_locked
agent._apt_locked = lambda: True
r = agent.act_distro_status({})
check("status: apt locked -> detached, not failed", r["phase"] == "detached")
check("status: detached carries a note", "still running" in (r["note"] or ""))

# runner killed, lock free, but the release LANDED without us -> verify -> done
agent._apt_locked = lambda: False
agent.service_state = lambda: (True, "nym-node.service")
FAKE_FILES["/etc/os-release"] = "ID=ubuntu\nVERSION_ID=\"26.04\"\nVERSION_CODENAME=resolute\n"
r = agent.act_distro_status({})
check("status: orphaned-but-completed release -> done", r["phase"] == "done")
check("status: note names the version jump", "25.04 -> 26.04" in (r["note"] or ""))
check("status: unrebooted orphan flags needs_reboot", r["needs_reboot"] is True)

# missing sudo is reported but never gates "done"
_mid_release_state()
_which2 = agent.shutil.which
agent.shutil.which = lambda *_: None
r = agent.act_distro_status({})
agent.shutil.which = _which2
check("status: missing sudo reported, done anyway", r["phase"] == "done"
      and any(c["check"] == "sudo installed" and not c["ok"] for c in (r["verify"] or [])))

# a scan (os_info) resolves a stuck mid-flight state the same way, so it
# cannot block future upgrades forever
_mid_release_state()
r = agent.act_os_info({"check_updates": False})
check("os_info: stuck state self-heals to done via reconcile",
      (r["upgrade_state"] or {}).get("phase") == "done")
agent._apt_locked = _orig_lock

agent._proc_btime, agent.service_state, agent.unit_exists = _orig_btime, _orig_svcstate, _orig_unit

# os_info with canned files
FAKE_FILES["/etc/os-release"] = ("ID=ubuntu\nVERSION_ID=\"22.04\"\n"
                                 "VERSION_CODENAME=jammy\nPRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\n")
FAKE_FILES["/proc/meminfo"] = "MemTotal: 2000000 kB\n"
FAKE_FILES["/proc/cpuinfo"] = "processor: 0\nmodel name: test cpu\n"


def fake_run_osinfo(cmd, timeout=6, merge=False):
    if cmd[0] == "systemd-detect-virt":
        return 0, "kvm\n", ""
    if cmd[0] == "apt-get" and "-s" in cmd:
        return 0, "Inst a [1] (2 Ubuntu:22.04/jammy-security [amd64])\n" \
                  "3 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n", ""
    return 0, "", ""


agent._run = fake_run_osinfo
r = agent.act_os_info({"check_updates": True, "refresh_lists": False})
check("os_info: distro fields", r["os"]["id"] == "ubuntu" and r["os"]["codename"] == "jammy")
check("os_info: hardware fields", r["mem_total"] == 2000000 * 1024
      and r["cpu"]["model"] == "test cpu" and r["kernel"])
check("os_info: pending counts parsed", r["pending"] == {"upgraded": 3, "new": 0,
                                                         "security": 1, "error": None})
check("os_info: reports last upgrade state", (r["upgrade_state"] or {}).get("phase") == "done")
r = agent.act_os_info({"check_updates": False})
check("os_info: check_updates=False skips apt", r["pending"]["upgraded"] is None)

agent._run, agent._read_text = _orig_run, _orig_read

# --- distro: catalog + planning ----------------------------------------------
print("distro planning")

rows = distro.parse_endoflife("ubuntu", [
    {"cycle": "24.04", "codename": "Noble Numbat", "lts": True,
     "releaseDate": "2024-04-25", "eol": "2029-05-31"},
    {"cycle": "22.04", "codename": "Jammy Jellyfish", "lts": True,
     "releaseDate": "2022-04-21", "eol": "2027-06-01"},
    {"cycle": "25.04", "codename": "Plucky Puffin", "lts": False,
     "releaseDate": "2025-04-17", "eol": "2026-01-15"},
    {"bogus": True},
])
check("endoflife: codename lower-cased first word", rows[0]["codename"] in ("plucky", "noble"))
check("endoflife: newest first", rows[0]["cycle"] == "25.04")
check("endoflife: junk rows dropped", len(rows) == 3)

CAT = {"ubuntu": rows, "debian": distro.STATIC_CATALOG["debian"]}


def osinfo(id_, ver, code, **kw):
    base = {"os": {"id": id_, "version_id": ver, "codename": code},
            "arch": "x86_64", "disk": {"free": 40 * 2**30}, "mem_total": 4 * 2**30,
            "do_release_upgrade": True, "reboot_required": False, "virt": "kvm",
            "pending": {"upgraded": 0, "new": 0, "security": 0},
            "upgrade_state": None}
    base.update(kw)
    return base


p = distro.plan_upgrade(osinfo("ubuntu", "22.04", "jammy"), CAT)
check("ubuntu LTS rides the LTS train (skips 25.04)",
      p["release"]["target_cycle"] == "24.04" and p["release"]["lts"])
check("single step, nothing further", p["release"]["further"] == 0)

p = distro.plan_upgrade(osinfo("ubuntu", "24.04", "noble"), CAT)
check("latest LTS: no release suggested, up to date", p["release"] is None and p["up_to_date"])

p = distro.plan_upgrade(osinfo("ubuntu", "24.04", "noble",
                               pending={"upgraded": 5, "new": 0, "security": 2}), CAT)
check("pending packages block up_to_date", not p["up_to_date"] and p["release"] is None)

p = distro.plan_upgrade(osinfo("ubuntu", "20.04", "focal", do_release_upgrade=True),
                        {"ubuntu": distro.STATIC_CATALOG["ubuntu"]})
check("multi-hop: next step only, rest flagged",
      p["release"]["target_cycle"] == "22.04" and p["release"]["further"] == 1
      and p["release"]["path"] == ["20.04", "22.04", "24.04"])

p = distro.plan_upgrade(osinfo("debian", "12", "bookworm"), CAT)
check("debian 12 -> 13 with codename",
      p["release"]["target_cycle"] == "13" and p["release"]["target_codename"] == "trixie")

p = distro.plan_upgrade(osinfo("alpine", "3.19", None), CAT)
check("unknown distro -> error, no plan", p["error"] and p["release"] is None)

# --- distro: compat checks -----------------------------------------------------
print("distro compat")

oi = osinfo("ubuntu", "22.04", "jammy")
plan = distro.plan_upgrade(oi, CAT)
checks = distro.compat_checks(oi, plan)
check("healthy node passes all blockers", distro.compat_ok(checks))

bad = distro.compat_checks(osinfo("ubuntu", "22.04", "jammy",
                                  disk={"free": 3 * 2**30}), plan)
check("low disk blocks a release upgrade", not distro.compat_ok(bad))
check("release upgrade uses the 8 GiB disk floor",
      any("8 GiB" in c["check"] and not c["ok"] for c in bad))

pkg_plan = distro.plan_upgrade(osinfo("ubuntu", "24.04", "noble"), CAT)
ok_pkg = distro.compat_checks(osinfo("ubuntu", "24.04", "noble",
                                     disk={"free": 3 * 2**30}), pkg_plan)
check("3 GiB is fine for a package-only update", distro.compat_ok(ok_pkg))

bad = distro.compat_checks(osinfo("ubuntu", "22.04", "jammy", virt="lxc"), plan)
check("container virt blocks", not distro.compat_ok(bad))
bad = distro.compat_checks(osinfo("ubuntu", "22.04", "jammy", do_release_upgrade=False), plan)
check("missing do-release-upgrade blocks a release jump", not distro.compat_ok(bad))
warn = distro.compat_checks(osinfo("ubuntu", "22.04", "jammy", reboot_required=True), plan)
check("pending reboot is a warning, not a blocker", distro.compat_ok(warn)
      and any(c["level"] == "warn" and not c["ok"] for c in warn))
bad = distro.compat_checks(osinfo("ubuntu", "22.04", "jammy",
                                  upgrade_state={"phase": "install"}), plan)
check("in-flight upgrade blocks a new one", not distro.compat_ok(bad))

# --- distro: USN ranking --------------------------------------------------------
print("distro CVE ranking")


def notice(nid, pkgs, cvss=None, priority=None, cves=(), title="t", published="2026-08-01"):
    return {"id": nid, "title": title, "published": published,
            "packages": list(pkgs),
            "cves": [{"id": c, "cvss3": cvss, "priority": priority} for c in cves]}


notices = [
    notice("USN-1", ["linux-image-generic"], cvss=7.8, cves=["CVE-2026-0001"]),
    notice("USN-2", ["linux-hwe"], cvss=9.8, cves=["CVE-2026-0002"]),
    notice("USN-3", ["openssl"], cvss=8.1, cves=["CVE-2026-0003"]),
    notice("USN-4", ["openssh-server"], priority="high", cves=["CVE-2026-0004"]),
    notice("USN-5", ["imagemagick"], cvss=9.9, cves=["CVE-2026-0005"]),   # not ops-relevant
    notice("USN-6", ["wireguard-tools"], cvss=6.0, cves=["CVE-2026-0006"]),
    notice("USN-7", ["systemd"], cvss=5.5, cves=["CVE-2026-0007"]),
    notice("USN-8", ["fail2ban"], cvss=4.0, cves=["CVE-2026-0008"]),
]
top = distro.rank_usns(notices, limit=5)
ids = [t["usn"] for t in top]
check("non-ops package excluded even at CVSS 9.9", "USN-5" not in ids)
check("top item is the 9.8 kernel USN", ids[0] == "USN-2")
check("diversity: one kernel entry, openssl+ssh make the cut",
      "USN-1" not in ids and "USN-3" in ids and "USN-4" in ids)
check("exactly 5 returned", len(top) == 5)
check("priority word scored when no cvss",
      next(t for t in top if t["usn"] == "USN-4")["score"] == 8.0)
check("why-line attached", all(t["why"] for t in top))

# release_packages dict shape (per-release nesting) + string cve ids
top = distro.rank_usns([{"id": "USN-9", "title": "x", "published": "2026-01-01",
                         "release_packages": {"jammy": [{"name": "openssl"}]},
                         "cves": ["CVE-2026-0009"], "cvss3": 7.0}], limit=5)
check("release_packages dict shape parsed", top and top[0]["usn"] == "USN-9")
check("string cve ids parsed", top[0]["cves"] == ["CVE-2026-0009"])
check("empty/garbage feed -> empty list", distro.rank_usns(None) == []
      and distro.rank_usns(["x", 5]) == [])

# the LIVE feed shape: empty cves, ids in cves_ids, no severity anywhere —
# scores come from the per-CVE endpoint via rescore_with_cves
live = [{"id": "USN-A", "title": "x", "published": "2026-08-01", "cves": [],
         "cves_ids": ["CVE-2026-1"],
         "release_packages": {"noble": [{"name": "openssl", "is_source": True}]}},
        {"id": "USN-B", "title": "y", "published": "2026-08-02", "cves": [],
         "cves_ids": ["CVE-2026-3"],
         "release_packages": {"noble": [{"name": "linux-hwe", "is_source": True}]}}]
pre = distro.rank_usns(live, limit=5)
check("live shape: cves_ids fallback fills cve list",
      sorted(c for t in pre for c in t["cves"]) == ["CVE-2026-1", "CVE-2026-3"])
check("live shape: zero scores rank newest first", pre[0]["usn"] == "USN-B")
top = distro.rescore_with_cves(pre, {"CVE-2026-1": {"cvss3": 9.1, "priority": None},
                                     "CVE-2026-3": {"cvss3": None, "priority": "medium"}})
check("rescore: per-CVE cvss3 applied",
      next(t for t in top if t["usn"] == "USN-A")["score"] == 9.1)
check("rescore: priority word fallback",
      next(t for t in top if t["usn"] == "USN-B")["score"] == 5.0)
check("rescore: order follows real severity", top[0]["usn"] == "USN-A")

# --- distro: recommendations ----------------------------------------------------
print("distro recommendations")

import datetime  # noqa: E402

TODAY = datetime.date(2026, 8, 19)


def check_row(name, oi, cat, compat_ok=True, cve_key="jammy"):
    plan = distro.plan_upgrade(oi, cat)
    return {"uid": name, "node_id": name, "name": name, "plan": plan,
            "checks": distro.compat_checks(oi, plan), "compat_ok": compat_ok,
            "cve_key": cve_key}


CVES = {"jammy": {"top": distro.rank_usns(notices, 5)}}      # worst = 9.8 kernel

rows = [check_row("AT01", osinfo("ubuntu", "22.04", "jammy"), CAT),
        check_row("AT02", osinfo("ubuntu", "22.04", "jammy"), CAT)]
recs = distro.recommend_actions(rows, CVES, today=TODAY)
rel = [r for r in recs if r["action"] == "release"]
check("release rec exists for the 22.04 cohort", len(rel) == 1)
check("headline says what to move to",
      "Upgrade 2 node(s) from Ubuntu 22.04 to Ubuntu 24.04 LTS" in rel[0]["headline"])
check("high urgency from the CVSS 9.8 kernel USN", rel[0]["urgency"] == "high")
check("reason ties in the top vulnerability",
      any("USN-2" in t and "9.8" in t for t in rel[0]["reasons"]))
check("reason recommends the pre-upgrade backup",
      any("backup" in t for t in rel[0]["reasons"]))
check("settings preselect release + backup",
      rel[0]["settings"] == {"mode": "release", "backup": True})

# past-EOL release is high urgency even with no CVE feed
rows = [check_row("AT03", osinfo("ubuntu", "20.04", "focal"),
                  {"ubuntu": distro.STATIC_CATALOG["ubuntu"]}, cve_key="focal")]
recs = distro.recommend_actions(rows, {}, today=TODAY)
check("past-EOL cohort is high urgency", recs[0]["urgency"] == "high")
check("past-EOL named in the reasons",
      any("past end of standard support" in t for t in recs[0]["reasons"]))

# packages-only cohort
rows = [check_row("AT04", osinfo("ubuntu", "24.04", "noble",
                                 pending={"upgraded": 9, "new": 1, "security": 3}),
                  CAT, cve_key="noble")]
recs = distro.recommend_actions(rows, {"noble": {"top": distro.rank_usns(notices, 5)}},
                                today=TODAY)
check("packages rec for the up-to-date release",
      recs[0]["action"] == "packages" and "Install pending updates" in recs[0]["headline"])
check("security count in the reasons",
      any("3 of them security" in t for t in recs[0]["reasons"]))
check("packages settings keep backup off",
      recs[0]["settings"] == {"mode": "packages", "backup": False})

# fully up to date
rows = [check_row("AT05", osinfo("ubuntu", "24.04", "noble"), CAT, cve_key="noble")]
recs = distro.recommend_actions(rows, {}, today=TODAY)
check("up-to-date cohort -> action none / info",
      recs[0]["action"] == "none" and recs[0]["urgency"] == "info")

# a blocked node gets its own fix-first recommendation, sorted to the top
blocked_oi = osinfo("ubuntu", "22.04", "jammy", disk={"free": 3 * 2**30})
brow = check_row("AT06", blocked_oi, CAT)
brow["compat_ok"] = distro.compat_ok(brow["checks"])
recs = distro.recommend_actions([brow], CVES, today=TODAY)
fix = [r for r in recs if r["action"] == "fix"]
check("blocked node -> fix recommendation", len(fix) == 1 and fix[0]["urgency"] == "high")
check("blocker named with detail", any("8 GiB" in t for t in fix[0]["reasons"]))
check("release rec then counts 0 ready nodes",
      any(r["action"] == "release" and "Upgrade 0 node(s)" in r["headline"] for r in recs))
check("scan-failed rows are skipped, not crashed",
      distro.recommend_actions([{"uid": "x", "plan": None}], {}, today=TODAY) == [])

# --- app: _backup_node helper -----------------------------------------------------
print("app _backup_node")

import asyncio  # noqa: E402
import app as maestro_app  # noqa: E402

bdir = Path(tmp) / "backups"
bdir.mkdir()
maestro_app.BACKUPS = bdir
NODE = {"uid": "u1", "node_id": "n1", "name": "AT01", "ip": "192.0.2.1", "agent_port": 8443}
FNAME = "nym-backup_at01_20260819_120000.tar.gz"
calls = []


def fake_backup_env(agent_result, download_sha):
    async def fake_exec(app_, node, action, params=None, timeout=40):
        calls.append(action)
        if action == "backup":
            return dict(agent_result)
        return {"ok": True}

    async def fake_download(app_, node, name, dest, timeout=900):
        Path(dest).write_bytes(b"data")
        return download_sha

    maestro_app.agent_exec = fake_exec
    maestro_app.download_backup = fake_download


fake_backup_env({"ok": True, "filename": FNAME, "sha256": "abc"}, "abc")
r = asyncio.run(maestro_app._backup_node(None, NODE))
check("backup ok: sha verified, saved locally",
      r["ok"] and r["saved_path"] == str(bdir / FNAME) and r["local_size"] == 4)
check("backup ok: staged copy cleaned up on the node", calls[-1] == "backup_cleanup")

fake_backup_env({"ok": True, "filename": FNAME, "sha256": "abc"}, "WRONG")
r = asyncio.run(maestro_app._backup_node(None, NODE))
check("sha mismatch -> not ok, archive discarded",
      not r["ok"] and "mismatch" in r["error"] and not (bdir / FNAME).exists())

calls.clear()
fake_backup_env({"ok": True, "filename": "../../etc/shadow", "sha256": "abc"}, "abc")
r = asyncio.run(maestro_app._backup_node(None, NODE))
check("unsafe filename -> refused before any download",
      not r["ok"] and "unsafe" in r["error"] and calls == ["backup"])

print()
print(f"{ok} passed, {fail} failed")
sys.exit(1 if fail else 0)
