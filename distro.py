"""Distro-upgrade planning for the fleet.

Pure logic only — release catalog normalization, upgrade-path planning,
compatibility checks, and ops-relevant CVE ranking — so test_distro.py can
drive everything with canned data. app.py owns the network fetches (live
catalog from endoflife.date, USNs from ubuntu.com) and the agent fanout.
"""
from __future__ import annotations

import re

# Where app.py fetches the live release catalog. endoflife.date is a plain
# static-JSON mirror of the distros' own release/EOL data.
ENDOFLIFE_URLS = {
    "ubuntu": "https://endoflife.date/api/ubuntu.json",
    "debian": "https://endoflife.date/api/debian.json",
}

# Ubuntu Security Notices, filtered server-side by release codename. Debian
# has no comparably small feed (the security-tracker dump is tens of MB), so
# Debian nodes get a link instead of an inline top-5 — stated, not silent.
USN_URL = "https://ubuntu.com/security/notices.json?release={codename}&limit=100&order=newest"
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
        add("no reboot already pending", False, "warn",
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
        if isinstance(pkgs, dict):  # some payloads nest per-release package lists
            names = [p.get("name") if isinstance(p, dict) else p
                     for plist in pkgs.values() for p in (plist or [])]
        else:
            names = [p.get("name") if isinstance(p, dict) else p
                     for p in (n.get("packages") or [])]
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
    scored.sort(key=lambda x: (-x["score"], x["published"]), reverse=False)

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
    picked.sort(key=lambda x: -x["score"])
    return picked[:limit]
