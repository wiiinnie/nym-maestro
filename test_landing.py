"""Tests for the public landing-page feature.

Covers the orchestrator-side generator (landing.py) — the field whitelist,
validation hard-stops, deterministic ordering, marker/legacy splicing and the
membership diff — and the agent-side install actions against a fake webroot in
a tmpdir, so nothing touches the host or the fleet.

Run: python3 test_landing.py
"""
import hashlib
import inspect
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "agent"))
import landing  # noqa: E402
import agent  # noqa: E402

ok = fail = 0


def check(label, cond):
    global ok, fail
    if cond:
        ok += 1; print(f"  pass  {label}")
    else:
        fail += 1; print(f"  FAIL  {label}")


GEN = "2026-08-09T12:00:00+00:00"

# A fleet shaped like the real /api/nodes payload, sensitive fields included so
# we can prove they never reach the page.
FLEET = [
    {"uid": "a1", "node_id": "hermes-gateway-at", "name": "AT01",
     "ip": "152.53.92.255", "hostname": "nym-exit-at01.hermes-stakepool.de",
     "cc": "AT", "enabled": True, "stake": {"amount": 123},
     "agent_fp": "SECRET-FINGERPRINT", "notes": "internal note",
     "service_name": "nym-node.service", "binary_path": "/root/nym-node",
     "status": {"mode": "exit-gateway", "exit": True, "reachable": True,
                "agent_sha": "SECRET-SHA", "fail2ban_banned": 7,
                "extra_blocks": {"v4": 900}, "disk": {"pct": 41}}},
    {"uid": "b2", "node_id": "hermes-gateway-de", "name": "DE01",
     "ip": "10.0.0.9", "hostname": "nym-exit-de01.hermes-stakepool.de",
     "cc": "DE", "enabled": True,
     "status": {"mode": "exit-gateway", "exit": True, "reachable": True}},
    {"uid": "c3", "node_id": "hermes-gateway-ch", "name": "CH01",
     "ip": "10.0.0.10", "hostname": "nym-exit-ch01.hermes-stakepool.de",
     "cc": "", "enabled": True, "status": None},          # agent down, no cc
    {"uid": "d4", "node_id": "hermes-gateway-off", "name": "XX99",
     "ip": "10.0.0.11", "hostname": "nym-exit-xx99.hermes-stakepool.de",
     "cc": "IT", "enabled": False,
     "status": {"mode": "exit-gateway", "exit": True}},   # disabled
    {"uid": "e5", "node_id": "hermes-mixnode-1", "name": "MX01",
     "ip": "10.0.0.12", "hostname": "mix01.hermes-stakepool.de",
     "cc": "FR", "enabled": True,
     "status": {"mode": "mixnode", "exit": False}},       # not an exit gateway
]

MASTER_LEGACY = """<!DOCTYPE html>
<html lang="en-US"><head><title>This is a NYM Exit Gateway</title>
<style>:root{--title-color:#07ff94;}</style></head>
<body>
<main><h2>Nym Node Terms &amp; Conditions</h2><p>Mere conduit.</p></main>

<h2 style="text-align:center; color: #07ff94; margin-top: 40px;">All nodes operated by Hermes Blockchain Ventures</h2>

<div style="text-align:center; margin: 30px 0;">
  <iframe src="https://nymesis.vercel.app/?q=hermes" style="width:100%"></iframe>
</div>

</body></html>"""

print("\n=== generator: selection + whitelist ===")

recs, warns, fatal = landing.select(FLEET)
check("only enabled exit gateways are published",
      sorted(r["name"] for r in recs) == ["AT01", "CH01", "DE01"])
check("disabled node excluded by default", all(r["name"] != "XX99" for r in recs))
check("mixnode excluded", all(r["name"] != "MX01" for r in recs))
check("no fatal errors on a healthy fleet", fatal == [])
check("missing country code warns but does not fail",
      any("country code" in w for w in warns))
check("record carries exactly the four public fields",
      all(set(r) == {"name", "ip", "hostname", "cc"} for r in recs))
check("rows sorted by country then name, unknown country last",
      [(r["cc"], r["name"]) for r in recs] == [("AT", "AT01"), ("DE", "DE01"), ("", "CH01")])

recs_d, _, _ = landing.select(FLEET, include_disabled=True)
check("include_disabled admits the disabled node",
      any(r["name"] == "XX99" for r in recs_d))

res = landing.build(FLEET, MASTER_LEGACY, generated=GEN)
block = res["block"]
SENSITIVE = ["SECRET-FINGERPRINT", "SECRET-SHA", "internal note", "agent_fp", "agent_sha",
             "fail2ban", "extra_blocks", "binary_path", "service_name", "notes",
             "nym-node.service", "/root/nym-node", "disk", "uid", "reachable", "123"]
leaked = [s for s in SENSITIVE if s in block]
check("no sensitive field reaches the generated block: " + (", ".join(leaked) or "clean"),
      leaked == [])
check("the four public values do reach the block",
      "152.53.92.255" in block and "nym-exit-at01.hermes-stakepool.de" in block
      and "AT01" in block and "Austria" in block)
check("page renders without JS: node rows are static <tr>", block.count("<tr>") >= 3)
check("plain-IP view is present", "nov-plain" in block)
check("stat cards show gateway and country counts",
      ">3</div><div class=\"nov-lbl\">Exit gateways" in block)

print("\n=== generator: validation hard-stops ===")

bad_ip = [dict(FLEET[0], ip="not-an-ip")]
try:
    landing.build(bad_ip, MASTER_LEGACY, generated=GEN)
    check("a broken IPv4 stops the build", False)
except landing.LandingError as e:
    check("a broken IPv4 stops the build", "unusable IP" in e.message)
    check("the offending node is named in the error", any("AT01" in d for d in e.details))

bad_host = [dict(FLEET[0], hostname="no-dots")]
try:
    landing.build(bad_host, MASTER_LEGACY, generated=GEN)
    check("a broken hostname stops the build", False)
except landing.LandingError:
    check("a broken hostname stops the build", True)

part = landing.build(bad_ip + FLEET[1:3], MASTER_LEGACY, allow_partial=True, generated=GEN)
check("allow_partial excludes the broken node and continues",
      part["counts"]["nodes"] == 2 and part["counts"]["excluded"] == 1
      and "not-an-ip" not in part["html"])

for label, arg in (("empty fleet", []), ("None", None), ("non-list", {"a": 1})):
    try:
        landing.build(arg, MASTER_LEGACY, generated=GEN)
        check(f"refuses to publish from {label}", False)
    except landing.LandingError:
        check(f"refuses to publish from {label}", True)

try:
    landing.build([FLEET[4]], MASTER_LEGACY, generated=GEN)   # only a mixnode
    check("refuses when nothing survives filtering", False)
except landing.LandingError as e:
    check("refuses when nothing survives filtering", "no publishable" in e.message)

check("IPv4 regex rejects a CIDR", not landing.IPV4_RE.match("10.0.0.0/8"))
check("IPv4 regex rejects an octet over 255", not landing.IPV4_RE.match("999.1.1.1"))
check("FQDN regex rejects a trailing-dot label", not landing.FQDN_RE.match("a..b.de"))

print("\n=== generator: splice, idempotency, diff ===")

check("first run replaces the legacy iframe section", res["splice_mode"] == "legacy-section")
check("the dead nymesis iframe is gone", "nymesis" not in res["html"])
check("the legal T&C survives untouched",
      "Nym Node Terms &amp; Conditions" in res["html"] and "Mere conduit." in res["html"])
check("markers are now present",
      landing.START in res["html"] and landing.END in res["html"])
check("first run reports itself as such", res["diff"]["first_run"] is True)

again = landing.build(FLEET, res["html"], generated=GEN)
check("re-run splices on the markers", again["splice_mode"] == "markers")
check("re-run is byte-identical (idempotent)", again["html"] == res["html"])
check("re-run reports no membership change",
      again["diff"]["added"] == [] and again["diff"]["removed"] == []
      and again["diff"]["changed"] == [])
check("re-run keeps exactly one marker pair", again["html"].count(landing.START) == 1)

NEW_FLEET = [n for n in FLEET if n["name"] != "DE01"] + [
    {"uid": "f6", "node_id": "hermes-gateway-dk", "name": "DK01", "ip": "10.0.0.20",
     "hostname": "nym-exit-dk01.hermes-stakepool.de", "cc": "DK", "enabled": True,
     "status": {"mode": "exit-gateway", "exit": True}}]
d = landing.build(NEW_FLEET, res["html"], generated=GEN)["diff"]
check("added node is reported", d["added"] == ["nym-exit-dk01.hermes-stakepool.de"])
check("removed node is reported", d["removed"] == ["nym-exit-de01.hermes-stakepool.de"])
check("previous version is carried in the diff", d["previous_version"] == res["version"])

moved = [dict(n, ip="10.9.9.9") if n["name"] == "DE01" else n for n in FLEET]
d2 = landing.build(moved, res["html"], generated=GEN)["diff"]
check("an IP change shows up as ~changed",
      d2["changed"] == ["nym-exit-de01.hermes-stakepool.de"] and d2["added"] == [])

check("version is content-addressed, not time-based",
      landing.build(FLEET, MASTER_LEGACY, generated="2030-01-01T00:00:00+00:00")["version"]
      == res["version"])
check("version changes when the list changes",
      landing.build(NEW_FLEET, MASTER_LEGACY, generated=GEN)["version"] != res["version"])

man = landing.extract_manifest(res["html"])
check("embedded manifest round-trips", man["version"] == res["version"] and man["count"] == 3)
check("manifest holds only public fields",
      all(set(n) == {"name", "ip", "hostname", "cc"} for n in man["nodes"]))
check("no illegal '--' inside the HTML comment",
      "--" not in res["html"].split("<!-- NODES:DATA ")[1].split(" -->")[0])
# a name or hostname containing "--" would otherwise close the comment early
_dd = [{"name": "AT--01", "ip": "1.2.3.4", "hostname": "a--b.hermes-stakepool.de", "cc": "AT"}]
_ddblock = landing.render_block(_dd, GEN, "v1")
_ddman = _ddblock.split("<!-- NODES:DATA ")[1].split(" -->")[0]
check("a '--' in node data is escaped out of the comment", "--" not in _ddman)
check("and restored exactly when the manifest is read back",
      landing.extract_manifest(_ddblock)["nodes"] == _dd)
check("version marker is parseable", landing.extract_version(res["html"]) == res["version"])
check("extract_version on a page without a marker returns None",
      landing.extract_version(MASTER_LEGACY) is None)

no_body = landing.build(FLEET, "<html><p>bare</p></html>", generated=GEN)
check("a page with no legacy section and no </body> still gets the block",
      no_body["splice_mode"] == "appended-eof" and landing.START in no_body["html"])

check("is_exit_gateway keeps a node whose agent is down",
      landing.is_exit_gateway({"node_id": "hermes-gateway-x", "hostname": "h.de", "status": None}))
check("is_exit_gateway drops an explicit non-exit role",
      not landing.is_exit_gateway({"node_id": "x", "hostname": "h.de",
                                   "status": {"mode": "mixnode", "exit": False}}))
check("html escaping is applied to node values",
      "&lt;b&gt;" in landing.render_block(
          [{"name": "<b>x</b>", "ip": "1.2.3.4", "hostname": "h.de", "cc": "DE"}], GEN, "v1"))

# Node names/hostnames come from a DB an operator edits by hand, and the page is
# public. Parse the output rather than grepping it: a hostile value must not add
# a single element, and must not close the comment that holds the manifest.
from html.parser import HTMLParser  # noqa: E402
from collections import Counter  # noqa: E402


class _Tags(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags, self.comments = [], 0

    def handle_starttag(self, t, a):
        self.tags.append(t)

    def handle_comment(self, d):
        self.comments += 1


def _shape(name):
    p = _Tags()
    p.feed(landing.render_block(
        [{"name": name, "ip": "1.2.3.4", "hostname": "h.hermes-stakepool.de", "cc": "DE"}],
        GEN, "v1"))
    return Counter(p.tags), p.comments


_base_tags, _base_comments = _shape("X")
# The odd-length dash runs are the regression cases: the old guard replaced "--"
# non-overlapping, so "--->" came out as "-<zwsp>-->" and closed the comment.
for _hostile in ['</script><script>alert(1)</script>',
                 '--> <script>alert(2)</script> <!--',
                 ']]>--!><script>alert(3)</script>',
                 'AT01---><img src=x onerror=alert(document.domain)>',
                 'AT01-----><img src=x onerror=alert(1)>',
                 'a--------->b<svg onload=alert(1)>',
                 '</style><style>body{display:none}</style>',
                 'A"onmouseover="alert(1)',
                 "</td></tr><tr><td>spoofed"]:
    _t, _c = _shape(_hostile)
    check(f"no element injected by {_hostile[:26]!r}", _t == _base_tags)
    check(f"manifest comment stays sealed against {_hostile[:26]!r}", _c == _base_comments)

# belt and braces: whatever the data, the rendered comment must be dash-free, so
# neither "-->" nor "--!>" can form in the first place
for _run in ["-", "--", "---", "----", "----->", "a-b--c---d"]:
    _blk = landing.render_block(
        [{"name": _run, "ip": "1.2.3.4", "hostname": "h.hermes-stakepool.de", "cc": "DE"}],
        GEN, "v1")
    _inner = _blk.split("<!-- NODES:DATA ")[1].split(" -->")[0]
    check(f"manifest payload has no bare dash for name {_run!r}", "-" not in _inner)
    check(f"and the name still round-trips for {_run!r}",
          landing.extract_manifest(_blk)["nodes"][0]["name"] == _run)

_legacy = ('<!-- NODES:VERSION abc123 GENERATED 2026-01-01T00:00:00+00:00 COUNT 1 -->'
           '<!-- NODES:DATA {"version":"abc123","count":1,"nodes":'
           '[{"name":"AT-​-01","ip":"1.2.3.4","hostname":"h.de","cc":"AT"}]} -->')
check("a manifest written with the old zero-width guard is still readable",
      landing.extract_manifest(_legacy)["nodes"][0]["name"] == "AT--01")

print("\n=== generator: publish only what the node really is ===")

_internal = {"node_id": "hermes-gw-fi02-INTERNAL-DONOTPUBLISH", "name": "",
             "ip": "1.2.3.4", "hostname": "nym-exit-fi02.hermes-stakepool.de",
             "cc": "FI", "enabled": True,
             "status": {"mode": "exit-gateway", "exit": True}}
_r, _w, _ = landing.select([_internal])
check("an empty name falls back to the hostname, never to node_id",
      _r[0]["name"] == "nym-exit-fi02.hermes-stakepool.de")
check("node_id never reaches a published record",
      "INTERNAL" not in json.dumps(_r))
check("and the missing name is warned about",
      any("no short name" in w for w in _w))

check("a node reporting exit=False is not published even if named like a gateway",
      not landing.is_exit_gateway({"node_id": "hermes-gateway-mix1",
                                   "hostname": "h.hermes-stakepool.de",
                                   "status": {"exit": False, "mixnode": True}}))
check("a node reporting a non-exit mode is not published",
      not landing.is_exit_gateway({"node_id": "hermes-gateway-x",
                                   "hostname": "h.de",
                                   "status": {"mode": "mixnode"}}))
check("a mixnode whose agent is down is not published on naming alone",
      not landing.is_exit_gateway({"node_id": "hermes-mix-fr01",
                                   "hostname": "mix01.hermes-stakepool.de",
                                   "status": None}))
check("a gateway whose agent is down is still published",
      landing.is_exit_gateway({"node_id": "hermes-gateway-fr01",
                               "hostname": "nym-exit-fr01.hermes-stakepool.de",
                               "status": None}))

print("\n=== agent: path safety ===")

WEB = tempfile.mkdtemp()
agent.WEBROOT = WEB
HOST = "nym-exit-at01.hermes-stakepool.de"
VHOST = os.path.join(WEB, HOST)
PAGE = os.path.join(VHOST, "index.html")

d_, p_, err = agent._landing_path({"hostname": HOST})
check("a valid hostname resolves under the webroot",
      err is None and p_ == PAGE and d_ == VHOST)
for bad in ["../../etc", "a/../../etc", "foo/bar", "/etc/passwd", "", None,
            "no-dots", "..", "a.de/../../b", "he re.de"]:
    _, _, e = agent._landing_path({"hostname": bad})
    check(f"hostname {bad!r} is rejected", e is not None)
check("hostname is lower-cased before use",
      agent._landing_path({"hostname": HOST.upper()})[1] == PAGE)

print("\n=== agent: deploy pre-flight ===")

PAGE_HTML = res["html"]
PAGE_SHA = hashlib.sha256(PAGE_HTML.encode()).hexdigest()
VERSION = res["version"]


def deploy(**kw):
    p = {"hostname": HOST, "content": PAGE_HTML, "sha256": PAGE_SHA}
    p.update(kw)
    return agent.act_landing_deploy(p)


r = deploy()
check("missing webroot is reported, not created",
      r["ok"] is False and r.get("reason") == "no-webroot" and not os.path.isdir(VHOST))

os.makedirs(VHOST)
r = deploy()
check("missing index.html is reported, not created blindly",
      r["ok"] is False and r.get("reason") == "no-index" and not os.path.exists(PAGE))

r = deploy(sha256="0" * 64)
check("a bad sha256 is refused before any write",
      r["ok"] is False and "sha256 mismatch" in r["error"])
r = deploy(sha256="")
check("a missing sha256 is refused (hash is mandatory)",
      r["ok"] is False and "sha256 mismatch" in r["error"])
r = deploy(content="")
check("empty content is refused", r["ok"] is False and "no page content" in r["error"])
_plain = "<html><body>not from maestro</body></html>"
r = deploy(content=_plain, sha256=hashlib.sha256(_plain.encode()).hexdigest())
check("a page without a NODES:VERSION marker is refused",
      r["ok"] is False and "NODES:VERSION" in r["error"])
_big = "x" * (agent.LANDING_MAX_BYTES + 1)
r = deploy(content=_big, sha256=hashlib.sha256(_big.encode()).hexdigest())
check("an oversized page is refused", r["ok"] is False and "too large" in r["error"])
check("nothing was written by any refused deploy", not os.path.exists(PAGE))

print("\n=== agent: deploy, backup, idempotency, revert ===")

r = deploy(create_missing=True)
check("create_missing places the page", r["ok"] is True and os.path.exists(PAGE))
check("deploy reports it created the file", r.get("created") is True)
check("deploy verifies the file it wrote", r.get("verified") is True)
check("deploy reports the version it installed", r.get("version") == VERSION)
check("content on disk matches what was sent",
      open(PAGE).read() == PAGE_HTML)
check("a created page is world-readable for the web server",
      (os.stat(PAGE).st_mode & 0o044) == 0o044)
check("no temp files left behind",
      [f for f in os.listdir(VHOST) if f.startswith(".index.")] == [])

r = deploy()
check("re-deploying the same version is skipped (idempotent)",
      r["ok"] is True and r.get("skipped") is True and r.get("reason") == "already-current")
r = deploy(force=True)
check("force re-deploys anyway", r["ok"] is True and not r.get("skipped"))

# a second, different version -> backup of the first
NEXT = landing.build(NEW_FLEET, PAGE_HTML, generated=GEN)
NEXT_HTML, NEXT_VER = NEXT["html"], NEXT["version"]
r = deploy(content=NEXT_HTML, sha256=hashlib.sha256(NEXT_HTML.encode()).hexdigest())
check("a new version deploys over the old one", r["ok"] is True and r["version"] == NEXT_VER)
check("the replaced page was backed up",
      r.get("backup") and os.path.exists(r["backup"])
      and r["backup"].endswith(".bak-" + VERSION))
check("the backup holds the previous content", open(r["backup"]).read() == PAGE_HTML)
check("previous version is reported", r.get("previous_version") == VERSION)
check("the live page is now the new version",
      landing.extract_version(open(PAGE).read()) == NEXT_VER)

st = agent.act_landing_status({"hostname": HOST})
check("status reports the served version", st["version"] == NEXT_VER)
check("status reports the node count from the marker", st["count"] == NEXT["counts"]["nodes"])
check("status lists the available backups",
      [b["version"] for b in st["backups"]] == [VERSION])
check("status sha256 matches the file",
      st["sha256"] == hashlib.sha256(open(PAGE, "rb").read()).hexdigest())

rv = agent.act_landing_revert({"hostname": HOST})
check("revert restores the previous page",
      rv["ok"] is True and rv["version"] == VERSION and open(PAGE).read() == PAGE_HTML)
check("revert reports what it replaced", rv.get("reverted_from") == NEXT_VER)
check("revert kept the page it replaced, so it can be undone",
      os.path.exists(PAGE + ".bak-" + NEXT_VER))
rv2 = agent.act_landing_revert({"hostname": HOST, "version": NEXT_VER})
check("revert to a named version works", rv2["ok"] is True and rv2["version"] == NEXT_VER)
rv3 = agent.act_landing_revert({"hostname": HOST, "version": "deadbeef1234"})
check("revert to an unknown version fails cleanly",
      rv3["ok"] is False and "no backup for version" in rv3["error"])

OTHER = "nym-exit-de01.hermes-stakepool.de"
os.makedirs(os.path.join(WEB, OTHER))
rv4 = agent.act_landing_revert({"hostname": OTHER})
check("revert with no backup present is a clean skip",
      rv4["ok"] is False and rv4.get("reason") == "no-backup")
st2 = agent.act_landing_status({"hostname": OTHER})
check("status on a webroot without a page says so",
      st2["ok"] is True and st2["dir_exists"] is True and st2["file_exists"] is False)
st3 = agent.act_landing_status({"hostname": "nym-exit-zz99.hermes-stakepool.de"})
check("status on a node without a webroot says so", st3["dir_exists"] is False)
check("status on a bad hostname errors", agent.act_landing_status({"hostname": "x"})["ok"] is False)

print("\n=== agent: a page edit outside the node list still deploys ===")

# The version marker hashes the node list only, so an edit to the surrounding
# page (the legal T&C, above all) leaves it identical. Keying the idempotency
# skip on the marker silently dropped exactly that change.
EDITED = PAGE_HTML.replace("Mere conduit.", "Mere conduit. REVISED CLAUSE 2026.")
check("editing the page body does not change the version marker",
      landing.extract_version(EDITED) == VERSION and EDITED != PAGE_HTML)
r = deploy(content=EDITED, sha256=hashlib.sha256(EDITED.encode()).hexdigest())
check("a same-version page with different content is NOT skipped",
      r["ok"] is True and not r.get("skipped"))
check("the node actually serves the revised text",
      "REVISED CLAUSE 2026." in open(PAGE).read())
r = deploy(content=EDITED, sha256=hashlib.sha256(EDITED.encode()).hexdigest())
check("re-deploying that identical file IS skipped",
      r["ok"] is True and r.get("reason") == "already-current")
# put the original back for the tests that follow
deploy(content=PAGE_HTML, sha256=PAGE_SHA)

print("\n=== agent: reverting to the pre-maestro page ===")

PRE = os.path.join(WEB, "nym-exit-pre01.hermes-stakepool.de")
os.makedirs(PRE)
PRE_PAGE = os.path.join(PRE, "index.html")
ORIGINAL = "<html><body><h2>ORIGINAL HANDWRITTEN PAGE</h2></body></html>"
with open(PRE_PAGE, "w") as _f:
    _f.write(ORIGINAL)
r = agent.act_landing_deploy({"hostname": "nym-exit-pre01.hermes-stakepool.de",
                              "content": PAGE_HTML, "sha256": PAGE_SHA})
check("the pre-maestro page is backed up as .bak-unversioned",
      r["ok"] is True and r["backup"].endswith(".bak-unversioned"))
r = agent.act_landing_revert({"hostname": "nym-exit-pre01.hermes-stakepool.de"})
check("reverting to the un-versioned original reports success, not failure",
      r["ok"] is True and r.get("restored") == "unversioned")
check("and the original page really is back", open(PRE_PAGE).read() == ORIGINAL)

print("\n=== agent: planted backups cannot redirect a root write or leak a file ===")

BK = "nym-exit-bk01.hermes-stakepool.de"
BKDIR = os.path.join(WEB, BK)
os.makedirs(BKDIR)
BKPAGE = os.path.join(BKDIR, "index.html")
_conf = os.path.join(WEB, "root-owned-victim.conf")
with open(_conf, "w") as _f:
    _f.write("ORIGINAL CONFIG")
agent.act_landing_deploy({"hostname": BK, "content": PAGE_HTML, "sha256": PAGE_SHA,
                          "create_missing": True})
# a symlink planted at the backup path must not turn into a write through it
os.symlink(_conf, BKPAGE + ".bak-" + VERSION)
r = agent.act_landing_deploy({"hostname": BK, "content": NEXT_HTML,
                              "sha256": hashlib.sha256(NEXT_HTML.encode()).hexdigest()})
check("a symlinked backup path is refused",
      r["ok"] is False and r.get("reason") == "symlink")
check("the symlink target was NOT written through",
      open(_conf).read() == "ORIGINAL CONFIG")
check("the live page was left untouched by the refused deploy",
      open(BKPAGE).read() == PAGE_HTML)

# a symlinked backup must not be published by revert
LK = "nym-exit-lk01.hermes-stakepool.de"
LKDIR = os.path.join(WEB, LK)
os.makedirs(LKDIR)
LKPAGE = os.path.join(LKDIR, "index.html")
with open(LKPAGE, "w") as _f:
    _f.write(PAGE_HTML)
_secret = os.path.join(WEB, "fake-shadow")
with open(_secret, "w") as _f:
    _f.write("root:$6$SECRETHASH:19000:::")
os.symlink(_secret, os.path.join(LKDIR, "index.html.bak-aaaaaa"))
r = agent.act_landing_revert({"hostname": LK})
check("revert refuses a symlinked backup", r["ok"] is False and r.get("reason") == "symlink")
check("the secret was NOT published to the page",
      "SECRETHASH" not in open(LKPAGE).read())

# a regular file masquerading as a versioned backup is refused too
with open(os.path.join(LKDIR, "index.html.bak-bbbbbb"), "w") as _f:
    _f.write("<html>not a maestro page</html>")
r = agent.act_landing_revert({"hostname": LK, "version": "bbbbbb"})
check("a backup that doesn't carry its claimed version is refused",
      r["ok"] is False and "does not carry version" in r["error"])
check("and that refusal left the page alone", open(LKPAGE).read() == PAGE_HTML)

print("\n=== agent: symlinked page is refused, not worked through ===")

SYM = "nym-exit-sy01.hermes-stakepool.de"
SYMDIR = os.path.join(WEB, SYM)
os.makedirs(SYMDIR)
_victim = os.path.join(WEB, "victim-outside-webroot.txt")
with open(_victim, "w") as _f:
    _f.write("SECRET-OUTSIDE-CONTENT")
os.symlink(_victim, os.path.join(SYMDIR, "index.html"))

r = agent.act_landing_deploy({"hostname": SYM, "content": PAGE_HTML, "sha256": PAGE_SHA,
                              "create_missing": True})
check("deploy refuses a symlinked index.html",
      r["ok"] is False and r.get("reason") == "symlink")
check("the symlink target was left alone",
      open(_victim).read() == "SECRET-OUTSIDE-CONTENT")
check("the symlink target's content was NOT copied into the webroot",
      not any("SECRET-OUTSIDE-CONTENT" in open(os.path.join(SYMDIR, f)).read()
              for f in os.listdir(SYMDIR)
              if f != "index.html" and os.path.isfile(os.path.join(SYMDIR, f))))
check("no backup file was created next to the symlink",
      [f for f in os.listdir(SYMDIR) if f.startswith("index.html.bak-")] == [])
r = agent.act_landing_revert({"hostname": SYM})
check("revert also refuses a symlinked page",
      r["ok"] is False and r.get("reason") == "symlink")

print("\n=== agent: install semantics ===")

_dep = inspect.getsource(agent.act_landing_deploy)
check("deploy never creates the webroot itself",
      "os.makedirs" not in _dep and "os.mkdir" not in _dep)
check("deploy hashes the content it was given, not a hash it was told",
      "hashlib.sha256(raw).hexdigest()" in _dep)
_w = inspect.getsource(agent._landing_write)
check("the swap is atomic (temp file + os.replace)",
      "mkstemp" in _w and "os.replace" in _w)
check("the temp file is fsynced before the rename", "fsync" in _w)
check("mode and owner are carried over from the replaced file",
      "st.st_mode" in _w and "st.st_uid" in _w)
check("SELinux context is re-applied after the rename", "_landing_restore_context" in _w)
check("landing actions are registered on the agent",
      all(a in agent.EXEC_ACTIONS for a in ("landing_status", "landing_deploy", "landing_revert")))
check("agent version was bumped for the new actions",
      tuple(int(x) for x in agent.AGENT_VERSION.split(".")) >= (0, 11, 0))
check("agent stays stdlib-only (no new third-party import)",
      not any(m in inspect.getsource(agent)[:4000]
              for m in ("import httpx", "import requests", "import fastapi")))

print("\n=== orchestrator wiring ===")

_app_src = (ROOT / "app.py").read_text()
for route in ("/api/landing/status", "/api/landing/preview", "/api/landing/master",
              "/api/landing/master/fetch", "/api/landing/rebuild", "/api/landing/nodes",
              "/api/landing/deploy", "/api/landing/revert"):
    check(f"route {route} exists", f'"{route}"' in _app_src)
check("deploy ships the sha256 alongside the content",
      '"content": content, "sha256": sha' in _app_src)
check("deploy refuses when there is nothing rebuilt to ship",
      "no rebuilt page to deploy" in _app_src)
check("each node gets its own hostname in the params",
      'p["hostname"] = (node.get("hostname") or "").strip()' in _app_src)
check("an old agent's 'unknown action' is translated for the operator",
      "agent is too old for the landing-page actions" in _app_src)
check("the agent's own error body is read out of the httpx exception",
      'resp = getattr(e, "response", None)' in _app_src)
check("rebuild and deploy write job + audit rows",
      '"landing_deploy"' in _app_src and '"landing_rebuild"' in _app_src)
check("results are tagged so the shared renderer reads them correctly",
      'res.setdefault("kind", "landing")' in _app_src)
check("the preview is sandboxed so a pasted/fetched page can't drive the API",
      '"Content-Security-Policy": "sandbox allow-scripts"' in _app_src)
check("the master size cap counts bytes, matching the agent's cap",
      'len(v.encode("utf-8")) > LANDING_MAX_BYTES' in _app_src)

_ag_src = (ROOT / "agent" / "agent.py").read_text()
_ag_landing = _ag_src.split(
    "# ---------------------------------------------------------------- landing page")[1]
check("no landing path calls shutil.copy2 (it writes through a symlinked dest)",
      "shutil.copy2(" not in _ag_landing)
check("backups go through the O_NOFOLLOW helper instead",
      _ag_landing.count("_landing_copy_nofollow(") >= 3)
check("the backup copy opens the destination with O_NOFOLLOW",
      "O_NOFOLLOW" in _ag_src)

_ui = (ROOT / "web" / "index.html").read_text()
check("the menu has a Landing page button", 'id="btn-landing"' in _ui and "openLanding()" in _ui)
check("the modal exists", 'id="lp-overlay"' in _ui)
check("the modal closes on backdrop click", "if(e.target.id === 'lp-overlay') closeLanding()" in _ui)
check("the modal closes on Escape",
      "closeLanding();" in _ui.split("if(e.key === 'Escape')")[1][:400])
check("deploy asks for confirmation before publishing",
      "confirm(" in _ui.split("function lpDeploy()")[1][:600])
check("the master controls stay reachable after a master exists",
      'id="lp-master-toggle"' in _ui and "function lpToggleMaster()" in _ui)
check("both node pickers preserve the operator's choice across the 15s refresh",
      "const keepSeed = seed.value" in _ui)
check("the empty seed option cannot be submitted",
      "o.value = ''; o.disabled = true; seed.append(o)" in _ui)
check("a failed status load is not rendered as 'no master'",
      "status unavailable" in _ui and "lpStatusError" in _ui)
check("the symlink skip reason is explained in the UI",
      "index.html is a symlink" in _ui)

shutil.rmtree(WEB, ignore_errors=True)
print(f"\n{ok} passed, {fail} failed")
raise SystemExit(1 if fail else 0)
