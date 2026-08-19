"""Distro-upgrade planning for the fleet.

Pure logic only — release catalog normalization, upgrade-path planning,
compatibility checks, and ops-relevant CVE ranking — so test_distro.py can
drive everything with canned data. app.py owns the network fetches (live
catalog from endoflife.date, USNs from ubuntu.com) and the agent fanout.
"""
from __future__ import annotations

import datetime
import re

# Where app.py fetches the live release catalog. endoflife.date is a plain
# static-JSON mirror of the distros' own release/EOL data.
ENDOFLIFE_URLS = {
    "ubuntu": "https://endoflife.date/api/ubuntu.json",
    "debian": "https://endoflife.date/api/debian.json",
}

# Ubuntu Security Notices, filtered server-side by release codename. The API
# hard-caps limit at 20, so coverage comes from offset pagination (app.py
# fetches a few pages). Severity is NOT in the list feed — cvss3/priority live
# on the per-CVE endpoint, fetched for the preselected notices only. Debian
# has no comparably small feed (the security-tracker dump is tens of MB), so
# Debian nodes get a link instead of an inline top-5 — stated, not silent.
USN_URL = "https://ubuntu.com/security/notices.json?release={codename}&limit=20&order=newest&offset={offset}"
CVE_URL = "https://ubuntu.com/security/cves/{cve}.json"
DEBIAN_SECURITY_URL = "https://www.debian.org/security/"

# Fallback when endoflife.date is unreachable. Deliberately conservative: it
# may LAG the real latest release (then the check simply suggests less than it
# could), but it must never claim a release that might not exist yet.
STATIC_CATALOG = {
    "ubuntu": [
        {"cycle": "24.04", "codename": "noble", "lts": True,
         "release_date": "2024-04-25", "eol": "2029-05-31"},
        {"cycle": "22.04", "codename": "jammy", "lts": True,
         "release_date": "2022-04-21", "eol": "2027-06-01"},
        {"cycle": "20.04", "codename": "focal", "lts": True,
         "release_date": "2020-04-23", "eol": "2025-05-29"},
    ],
    "debian": [
        {"cycle": "13", "codename": "trixie", "lts": False,
         "release_date": "2025-08-09", "eol": "2028-06-10"},
        {"cycle": "12", "codename": "bookworm", "lts": False,
         "release_date": "2023-06-10", "eol": "2026-06-10"},
        {"cycle": "11", "codename": "bullseye", "lts": False,
         "release_date": "2021-08-14", "eol": "2024-08-15"},
    ],
}

# Packages that matter for THIS operation (exit gateways: packet forwarding,
# WireGuard, mTLS control plane, SSH management, abuse filtering). Matched by
# prefix against a notice's package names; the value is the "why this matters
# to you" line shown next to the CVE.
OPS_PACKAGES = [
    ("linux", "kernel — forwards every exit packet; netfilter and WireGuard run here"),
    ("openssh", "OpenSSH — the fleet's management plane on every node"),
    ("openssl", "OpenSSL — TLS for the mTLS agent channel and nym-node crypto"),
    ("wireguard", "WireGuard tools — the nymwg exit tunnels"),
    ("systemd", "systemd — supervises nym-node and the maestro agent"),
    ("nftables", "nftables — the NYM-EXIT abuse-filter chains"),
    ("iptables", "iptables — the NYM-EXIT abuse-filter chains"),
    ("fail2ban", "fail2ban — SSH brute-force protection on the fleet"),
    ("glibc", "glibc — linked by every binary on the node"),
    ("python3", "Python — runs the maestro agent itself"),
    ("sudo", "sudo — local privilege boundary"),
]

_PRIORITY_SCORE = {"critical": 9.8, "high": 8.0, "medium": 5.0,
                   "low": 2.0, "negligible": 0.5}


def _ver_tuple(v):
    try:
        return tuple(int(x) for x in re.findall(r"\d+", str(v))[:3])
    except Exception:
        return ()


def parse_endoflife(distro_id, entries):
    """Normalize an endoflife.date payload to the STATIC_CATALOG row shape.
    Rows it cannot make sense of are dropped; returns newest-first."""
    out = []
    for e in entries or []:
        if not isinstance(e, dict) or not e.get("cycle"):
            continue
        codename = (e.get("codename") or "")
        # ubuntu codenames come as "Noble Numbat" — the apt/os-release name is
        # the lower-cased first word
        codename = codename.split()[0].lower() if codename else None
        out.append({
            "cycle": str(e["cycle"]),
            "codename": codename,
            "lts": bool(e.get("lts")),
            "release_date": e.get("releaseDate"),
            "eol": e.get("eol") if isinstance(e.get("eol"), str) else None,
        })
    out.sort(key=lambda r: _ver_tuple(r["cycle"]), reverse=True)
    return out


def plan_upgrade(osinfo, catalog):
    """What this node should move to, if anything.

    osinfo is the agent's os_info result; catalog is {distro_id: [rows]} in
    STATIC_CATALOG shape. Returns a dict with:
      current / current_codename / distro
      release: None, or the suggested release upgrade {target_cycle,
               target_codename, lts, path, further} — always the NEXT step on
               a supported path (LTS→LTS for Ubuntu LTS, N→N+1 for Debian),
               never a multi-hop jump.
      packages: pending package-update counts from the scan.
      up_to_date: no release upgrade suggested AND no pending packages.
      error: set when the node can't be planned at all.
    """
    os_ = (osinfo or {}).get("os") or {}
    distro = (os_.get("id") or "").lower()
    current = os_.get("version_id")
    plan = {"distro": distro, "current": current,
            "current_codename": os_.get("codename"),
            "release": None, "packages": (osinfo or {}).get("pending") or {},
            "up_to_date": False, "error": None}
    rows = (catalog or {}).get(distro)
    if not rows:
        plan["error"] = f"unsupported or unknown distro {distro!r}"
        return plan
    cur_t = _ver_tuple(current)
    if not cur_t:
        plan["error"] = f"could not parse current version {current!r}"
        return plan

    cur_row = next((r for r in rows if _ver_tuple(r["cycle"]) == cur_t), None)
    newer = sorted((r for r in rows if _ver_tuple(r["cycle"]) > cur_t),
                   key=lambda r: _ver_tuple(r["cycle"]))
    if distro == "ubuntu" and (cur_row is None or cur_row.get("lts")):
        # LTS boxes ride the LTS train (that is also do-release-upgrade's
        # default Prompt=lts behaviour). Unknown current: assume LTS train.
        newer = [r for r in newer if r.get("lts")]
    if newer:
        target = newer[0]  # next step only — upgrades don't skip releases
        plan["release"] = {
            "target_cycle": target["cycle"],
            "target_codename": target["codename"],
            "lts": target.get("lts", False),
            "eol": target.get("eol"),
            "path": [current] + [r["cycle"] for r in newer],
            "further": len(newer) - 1,   # steps still ahead after this one
        }
    pend = plan["packages"]
    plan["up_to_date"] = (plan["release"] is None
                          and not (pend.get("upgraded") or pend.get("new")))
    plan["current_eol"] = cur_row.get("eol") if cur_row else None
    return plan


_GIB = 1024 ** 3

# free-disk floor: a release upgrade downloads + unpacks the full package set
_DISK_MIN_RELEASE = 8 * _GIB
_DISK_MIN_PACKAGES = 2 * _GIB
_MEM_MIN = 900 * 1024 * 1024


def compat_checks(osinfo, plan):
    """Is the suggested upgrade safe to run on this node? Returns a list of
    {check, ok, level, detail}; level "block" must all pass before the
    orchestrator will start an upgrade, "warn" is informational."""
    checks = []

    def add(check, ok, level, detail=""):
        checks.append({"check": check, "ok": bool(ok), "level": level,
                       "detail": detail})

    osinfo = osinfo or {}
    release = (plan or {}).get("release")
    distro = (plan or {}).get("distro")

    add("supported distro", distro in ("ubuntu", "debian"), "block",
        f"got {distro!r} — only ubuntu/debian upgrades are automated")
    arch = osinfo.get("arch")
    add("supported architecture", arch in ("x86_64", "aarch64", "amd64", "arm64"),
        "block", f"arch {arch!r}")

    disk = osinfo.get("disk") or {}
    free = disk.get("free")
    need = _DISK_MIN_RELEASE if release else _DISK_MIN_PACKAGES
    add(f"free disk ≥ {need // _GIB} GiB",
        free is not None and free >= need, "block",
        f"{(free or 0) / _GIB:.1f} GiB free" if free is not None else "disk usage unknown")

    mem = osinfo.get("mem_total")
    add("RAM ≥ 1 GiB", mem is not None and mem >= _MEM_MIN, "block",
        f"{(mem or 0) / _GIB:.1f} GiB" if mem is not None else "unknown")

    if release and distro == "ubuntu":
        add("do-release-upgrade installed", bool(osinfo.get("do_release_upgrade")),
            "block", "apt install update-manager-core on the node first")
    if release and distro == "debian":
        add("target codename known", bool(release.get("target_codename")), "block",
            "catalog did not name the target codename")
    if release:
        add("single-step upgrade path", True, "warn" if release.get("further") else "warn",
            ("this is step 1; " + " → ".join(release["path"]) + " remains")
            if release.get("further") else " → ".join(release["path"]))

    if osinfo.get("reboot_required"):
        # named after the finding, not the pass-condition: this entry only
        # exists when it fails, and the UI shows failed checks by name
        add("reboot already pending", False, "warn",
            "node wants a reboot from earlier updates — the upgrade reboot clears it")
    virt = osinfo.get("virt")
    if virt in ("lxc", "openvz", "systemd-nspawn"):
        add("full VM / bare metal", False, "block",
            f"container virtualization ({virt}) — kernel upgrades won't apply")

    ust = osinfo.get("upgrade_state") or {}
    add("no upgrade already running",
        ust.get("phase") in (None, "done", "failed"), "block",
        f"agent reports phase {ust.get('phase')!r}")
    return checks


def compat_ok(checks):
    return all(c["ok"] for c in checks if c["level"] == "block")


_DISTRO_NAMES = {"ubuntu": "Ubuntu", "debian": "Debian"}
_EOL_SOON_DAYS = 180


def _eol_state(eol_str, today):
    """('past'|'soon'|'ok'|None, iso-date) for an EOL string."""
    try:
        eol = datetime.date.fromisoformat((eol_str or "")[:10])
    except ValueError:
        return None, None
    if eol <= today:
        return "past", eol.isoformat()
    if (eol - today).days <= _EOL_SOON_DAYS:
        return "soon", eol.isoformat()
    return "ok", eol.isoformat()


def _vuln_reason(top):
    """One sentence tying the recommendation to the ranked CVEs."""
    if not top:
        return None
    worst = top[0]
    area = (worst.get("why") or worst.get("ops_area") or "").split(" — ")[0]
    sev = f"CVSS {worst['score']}" if worst.get("score") else "unrated"
    s = (f"closes {worst['usn']} ({sev}"
         + (f", {area}" if area else "") + ")")
    if len(top) > 1:
        s += f" and {len(top) - 1} more ops-relevant security fixes — hover the CVEs pill"
    return s


def recommend_actions(results, cves, today=None):
    """Turn a finished dry run into explicit fleet advice: "upgrade these N
    nodes to X because …". Pure synthesis over /api/distro/check's per-node
    results + the ranked CVE groups; grouped by (distro, current version) so
    a mixed fleet gets one recommendation per cohort.

    Returns a list of {action, urgency, headline, reasons, nodes, settings},
    highest urgency first. `settings` is what the UI should preselect
    (mode, and backup=True for release jumps — the riskiest operation here).
    """
    today = today or datetime.date.today()
    groups = {}
    for r in results or []:
        if not r.get("plan"):
            continue  # scan failed; surfaced on the node row itself
        plan = r["plan"]
        groups.setdefault((plan.get("distro"), plan.get("current")), []).append(r)

    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    recs = []
    for (distro_id, current), rows in sorted(groups.items(), key=lambda kv: str(kv[0])):
        names = sorted(r.get("name") or r.get("node_id") or r["uid"] for r in rows)
        plan = rows[0]["plan"]
        rel = plan.get("release")
        top = ((cves or {}).get(rows[0].get("cve_key")) or {}).get("top") or []
        dname = _DISTRO_NAMES.get(distro_id, distro_id or "?")
        sec = sum((r["plan"].get("packages") or {}).get("security") or 0 for r in rows)
        pkgs = sum(((r["plan"].get("packages") or {}).get("upgraded") or 0)
                   + ((r["plan"].get("packages") or {}).get("new") or 0) for r in rows)
        blocked = [r for r in rows if not r.get("compat_ok")]
        ready = [r for r in rows if r.get("compat_ok")]
        vuln = _vuln_reason(top)
        worst_score = top[0]["score"] if top else 0

        if rel:
            eol_state, eol_date = _eol_state(plan.get("current_eol"), today)
            urgency = ("high" if eol_state == "past" or worst_score >= 7
                       else "medium" if eol_state == "soon" or sec else "low")
            reasons = []
            if eol_state == "past":
                reasons.append(f"{dname} {current} is past end of standard support "
                               f"(since {eol_date}) — no more security updates")
            elif eol_state == "soon":
                reasons.append(f"{dname} {current} support ends {eol_date}")
            elif eol_date:
                reasons.append(f"{dname} {current} is supported until {eol_date}, "
                               "but the newer release is available now")
            if vuln:
                reasons.append(vuln)
            if sec:
                reasons.append(f"{sec} pending security updates across these nodes "
                               "come along with the jump")
            tgt = (f"{dname} {rel['target_cycle']}"
                   + (" LTS" if rel.get("lts") else "")
                   + (f" ({rel['target_codename']})" if rel.get("target_codename") else ""))
            if rel.get("eol"):
                reasons.append(f"{tgt} is the current stable release, supported until {rel['eol']}")
            if rel.get("further"):
                reasons.append("this is step 1 of " + " → ".join(rel["path"])
                               + " — rerun the dry run after it lands")
            reasons.append("enable the pre-upgrade backup: a release jump is the "
                           "riskiest operation maestro runs")
            recs.append({"action": "release", "urgency": urgency,
                         "headline": f"Upgrade {len(ready)} node(s) from {dname} {current} to {tgt}",
                         "reasons": reasons,
                         "nodes": sorted(r.get("name") or r.get("node_id") or r["uid"]
                                         for r in ready),
                         "settings": {"mode": "release", "backup": True}})
        elif pkgs:
            urgency = ("high" if sec and worst_score >= 7
                       else "medium" if sec else "low")
            reasons = [f"{pkgs} pending package updates"
                       + (f", {sec} of them security fixes" if sec else " (no security fixes pending)")]
            if vuln and sec:
                reasons.append(vuln)
            reasons.append(f"{dname} {current} is already the latest release — "
                           "this is a package update, no reboot unless the kernel asks for it")
            recs.append({"action": "packages", "urgency": urgency,
                         "headline": f"Install pending updates on {len(ready)} {dname} {current} node(s)",
                         "reasons": reasons,
                         "nodes": sorted(r.get("name") or r.get("node_id") or r["uid"]
                                         for r in ready),
                         "settings": {"mode": "packages", "backup": False}})
        else:
            recs.append({"action": "none", "urgency": "info",
                         "headline": f"{len(rows)} {dname} {current} node(s) are up to date",
                         "reasons": ["no release upgrade available, no pending packages"],
                         "nodes": names, "settings": None})

        if blocked:
            why = sorted({f'{c["check"]} ({c["detail"]})'
                          for r in blocked for c in (r.get("checks") or [])
                          if not c["ok"] and c["level"] == "block"})
            recs.append({"action": "fix", "urgency": "high",
                         "headline": f"Fix {len(blocked)} node(s) before upgrading",
                         "reasons": why or ["compatibility check failed"],
                         "nodes": sorted(r.get("name") or r.get("node_id") or r["uid"]
                                         for r in blocked),
                         "settings": None})
    recs.sort(key=lambda r: order.get(r["urgency"], 9))
    return recs


def _ops_match(packages):
    """(prefix, why) for the first ops-relevant package in the list, else None."""
    for name in packages or []:
        n = str(name).lower()
        for prefix, why in OPS_PACKAGES:
            if n.startswith(prefix):
                return prefix, why
    return None


def _notice_score(notice):
    """Best severity signal available: max CVSS3 over the notice's CVEs, falling
    back to the priority word. notices.json has carried both shapes (cves as
    ids, or as objects), so parse defensively."""
    best = 0.0
    for cve in notice.get("cves") or []:
        if isinstance(cve, dict):
            v = cve.get("cvss3")
            try:
                best = max(best, float(v))
            except (TypeError, ValueError):
                pass
            p = (cve.get("priority") or "").lower()
            best = max(best, _PRIORITY_SCORE.get(p, 0.0))
    for key in ("cvss3", "priority"):
        v = notice.get(key)
        if isinstance(v, (int, float)):
            best = max(best, float(v))
        elif isinstance(v, str):
            best = max(best, _PRIORITY_SCORE.get(v.lower(), 0.0))
    return best


def _cve_ids(notice, limit=6):
    ids = []
    for cve in notice.get("cves") or []:
        cid = cve.get("id") if isinstance(cve, dict) else cve
        if isinstance(cid, str) and cid.startswith("CVE-"):
            ids.append(cid)
    if not ids:  # the live feed often ships empty `cves` but filled `cves_ids`
        ids = [c for c in (notice.get("cves_ids") or [])
               if isinstance(c, str) and c.startswith("CVE-")]
    return ids[:limit]


def rank_usns(notices, limit=5):
    """Top ops-relevant security notices, one angle per package where possible.

    Greedy: first the highest-scoring notice per ops package (so the top 5
    covers kernel AND ssh AND ssl instead of five kernel USNs), then fill any
    remaining slots by raw score.
    """
    scored = []
    for n in notices or []:
        if not isinstance(n, dict):
            continue
        pkgs = n.get("release_packages")
        if isinstance(pkgs, dict):  # the live feed nests per-release package lists
            plists = [p for plist in pkgs.values() for p in (plist or [])]
        else:
            plists = list(n.get("packages") or [])
        # match on SOURCE packages only where the shape tells us — otherwise a
        # binding like python3-samba drags a samba notice into the python bucket
        names = [p.get("name") if isinstance(p, dict) else p
                 for p in plists
                 if not isinstance(p, dict) or p.get("is_source", True)]
        names = [x for x in names if x]
        m = _ops_match(names)
        if not m:
            continue
        prefix, why = m
        scored.append({
            "usn": n.get("id"),
            "title": (n.get("title") or n.get("summary") or "").strip(),
            "packages": sorted({p for p in names
                                if str(p).lower().startswith(prefix)})[:4],
            "ops_area": prefix,
            "why": why,
            "score": round(_notice_score(n), 1),
            "cves": _cve_ids(n),
            "published": (n.get("published") or "")[:10],
        })
    return _pick_diverse(scored, limit)


def _pick_diverse(scored, limit):
    """Best per ops area first (so the top-N covers kernel AND ssh AND ssl),
    then fill by raw severity; newest first among equals."""
    scored = sorted(scored, key=lambda x: (x["score"], x["published"]), reverse=True)
    picked, seen_area = [], set()
    for item in scored:               # pass 1: best per ops area
        if item["ops_area"] not in seen_area:
            picked.append(item)
            seen_area.add(item["ops_area"])
        if len(picked) >= limit:
            break
    if len(picked) < limit:           # pass 2: fill by raw severity
        for item in scored:
            if item not in picked:
                picked.append(item)
                if len(picked) >= limit:
                    break
    picked.sort(key=lambda x: (x["score"], x["published"]), reverse=True)
    return picked[:limit]


def rescore_with_cves(items, cve_scores, limit=5):
    """Fold per-CVE severity (from the CVE detail endpoint) into ranked items.

    cve_scores: {cve_id: {"cvss3": float|None, "priority": str|None}}. Each
    item's score becomes the max of what it had and its CVEs' scores, then the
    diversity pick runs again. Items are not mutated."""
    out = []
    for item in items or []:
        best = item.get("score") or 0.0
        for cid in item.get("cves") or []:
            s = cve_scores.get(cid) or {}
            try:
                best = max(best, float(s.get("cvss3") or 0))
            except (TypeError, ValueError):
                pass
            best = max(best, _PRIORITY_SCORE.get((s.get("priority") or "").lower(), 0.0))
        out.append({**item, "score": round(best, 1)})
    return _pick_diverse(out, limit)
