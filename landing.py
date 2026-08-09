"""Public landing-page generator for the Hermes exit-gateway fleet.

Each exit gateway serves a public notice page at /var/www/<hostname>/index.html.
This module regenerates ONLY the "All nodes operated by ..." block inside a
master index.html, between two auto-markers; the rest of the page (legal T&C,
SVG diagram) is never touched.

The generated block is fully static — it renders with JavaScript disabled. JS
only adds progressive niceties (view toggle, column sort, copy button). That
matters because /api/nodes binds to localhost and sends no CORS header, so the
public page can never fetch fleet data itself: it has to be baked in here.

Only four fields ever leave maestro — name, ip, hostname, cc. The allow-list in
select() is hard-coded so that future admin fields cannot leak into a page whose
whole purpose is to be read by authorities.

stdlib only, so the same code can run under the orchestrator or standalone.
"""

import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone

START = "<!-- NODES:AUTO START -->"
END = "<!-- NODES:AUTO END -->"

# First run, before any markers exist: the hand-written section to replace is the
# h2 plus the <div> wrapping the (now dead) nymesis iframe.
LEGACY_RE = re.compile(
    r'<h2[^>]*>\s*All nodes operated by Hermes Blockchain Ventures\s*</h2>\s*'
    r'<div[^>]*>.*?</div>',
    re.IGNORECASE | re.DOTALL,
)

VERSION_RE = re.compile(r'<!-- NODES:VERSION ([0-9a-f]{6,64}) GENERATED (\S+) COUNT (\d+) -->')
MANIFEST_RE = re.compile(r'<!-- NODES:DATA (\{.*?\}) -->', re.DOTALL)

IPV4_RE = re.compile(r'^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$')
FQDN_RE = re.compile(r'^(?=.{1,253}$)([a-zA-Z0-9](-?[a-zA-Z0-9])*\.)+[a-zA-Z]{2,}$')
CC_RE = re.compile(r'^[A-Za-z]{2}$')

# An HTML comment ends at the first "-->" (or "--!>"), and the embedded manifest
# is JSON that can contain a run of dashes. Both terminators need "--", so the
# comment is safe as long as no literal "-" survives in the payload: escape every
# dash as the JSON escape -, which json.loads decodes back on the way out
# with no un-escaping step of our own.
#
# Do NOT go back to str.replace("--", <guard>) — that is non-overlapping, so an
# odd-length run like "--->" comes out as "-<guard>-->" and still closes the
# comment. That was exploitable: a node name of
#   AT01---><img src=x onerror=...>
# put live markup on the public page.
_DASH_JSON_ESCAPE = "\\u002d"
# Pages generated before that fix guarded with a zero-width space; still accepted
# when reading a manifest back so an older page's diff base survives.
_ZWSP = "​"
_LEGACY_COMMENT_SAFE_DASHES = "-" + _ZWSP + "-"

WHITE_FLAG = "\U0001F3F3️"

COUNTRY = {
    "AT": "Austria", "BE": "Belgium", "BG": "Bulgaria", "CH": "Switzerland", "CY": "Cyprus",
    "CZ": "Czechia", "DE": "Germany", "DK": "Denmark", "EE": "Estonia", "ES": "Spain",
    "FI": "Finland", "FR": "France", "GB": "United Kingdom", "GR": "Greece", "HR": "Croatia",
    "HU": "Hungary", "IE": "Ireland", "IS": "Iceland", "IT": "Italy", "LT": "Lithuania",
    "LU": "Luxembourg", "LV": "Latvia", "MD": "Moldova", "MT": "Malta", "NL": "Netherlands",
    "NO": "Norway", "PL": "Poland", "PT": "Portugal", "RO": "Romania", "RS": "Serbia",
    "SE": "Sweden", "SI": "Slovenia", "SK": "Slovakia", "UA": "Ukraine",
    "US": "United States", "CA": "Canada", "JP": "Japan", "SG": "Singapore", "AU": "Australia",
    "HK": "Hong Kong", "IN": "India", "BR": "Brazil", "ZA": "South Africa", "AE": "UAE",
    "TR": "Turkey",
}


class LandingError(Exception):
    """Generation refused. `details` lists the offending nodes, if any."""

    def __init__(self, message, details=None):
        super().__init__(message)
        self.message = message
        self.details = details or []


def flag(cc):
    cc = (cc or "").upper()
    if len(cc) != 2 or not cc.isalpha():
        return WHITE_FLAG
    return "".join(chr(0x1F1E6 + (ord(c) - ord('A'))) for c in cc)


def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                  .replace('"', "&quot;"))


# ----------------------------------------------------------------- select
def is_exit_gateway(node):
    st = node.get("status") or {}
    if isinstance(st, dict) and st:
        # The node's own report wins in both directions. In particular a node
        # saying exit=False is never published, whatever its name looks like —
        # listing a mixnode as an exit gateway misinforms the reader of an
        # authority page, which is worse than omitting a node.
        if st.get("exit") is False:
            return False
        if st.get("mode") not in (None, "", "exit-gateway"):
            return False
        if st.get("mode") == "exit-gateway" or st.get("exit") is True:
            return True
    # No status at all (agent down, never polled): fall back to naming hints
    # rather than assuming either way, so a real gateway whose agent is down
    # still gets listed but a mixnode doesn't.
    hint = (node.get("node_id", "") + " " + node.get("hostname", "")).lower()
    return ("gateway" in hint) or ("exit" in hint)


def select(nodes, include_disabled=False):
    """Filter the fleet down to publishable records.

    Returns (records, warnings, fatal). Each record holds exactly the four
    public fields; nothing else from the admin API is ever carried over.
    """
    pub, warn, fatal = [], [], []
    for n in nodes:
        if not isinstance(n, dict):
            continue
        if not include_disabled and n.get("enabled") is False:
            continue
        if not is_exit_gateway(n):
            continue
        # node_id is deliberately NOT a fallback here: it is an internal
        # identifier outside the published four, and letting it through would
        # put internal naming on a public page.
        name = (n.get("name") or "").strip()
        ip = (n.get("ip") or "").strip()
        host = (n.get("hostname") or "").strip()
        cc = (n.get("cc") or "").strip().upper()
        label = name or host or ip or "<unknown>"

        if not ip or not IPV4_RE.match(ip):
            fatal.append("%s: missing/invalid IPv4 (%r)" % (label, ip))
            continue
        if not host or not FQDN_RE.match(host):
            fatal.append("%s: missing/invalid hostname (%r)" % (label, host))
            continue
        if not name:
            warn.append("%s: no short name; using hostname" % label)
            name = host
        if not CC_RE.match(cc):
            warn.append("%s: missing/unknown country code" % label)
            cc = ""
        # WHITELIST — only these four fields ever leave maestro:
        pub.append({"name": name, "ip": ip, "hostname": host, "cc": cc})
    # deterministic ordering keeps regenerated pages diffable
    pub.sort(key=lambda r: (r["cc"] or "ZZ", r["name"]))
    return pub, warn, fatal


def version_for(records):
    """Content hash of the published set — changes only when the list changes."""
    return hashlib.sha256(
        json.dumps(records, sort_keys=True).encode("utf-8")).hexdigest()[:12]


# ----------------------------------------------------------------- render
def render_block(records, generated_iso, version):
    total = len(records)
    countries = len({r["cc"] for r in records if r["cc"]})
    gen_date = generated_iso[:10]

    rows = []
    for r in records:
        cc = r["cc"]
        cname = COUNTRY.get(cc, cc or "Unknown")
        rows.append(
            "        <tr>"
            "<td class=\"nov-name\">{name}</td>"
            "<td class=\"nov-ip\">{ip}</td>"
            "<td class=\"nov-host\">{host}</td>"
            "<td class=\"nov-cc\"><span class=\"nov-flag\">{flag}</span>{cname}</td>"
            "</tr>".format(
                name=esc(r["name"]), ip=esc(r["ip"]), host=esc(r["hostname"]),
                flag=flag(cc), cname=esc(cname),
            )
        )
    table_rows = "\n".join(rows) if rows else \
        '        <tr><td colspan="4" class="nov-empty">No nodes.</td></tr>'

    w = max([len(r["ip"]) for r in records], default=0) + 3
    plain = "\n".join(esc(r["ip"].ljust(w) + r["hostname"]) for r in records)
    ip_js = json.dumps([r["ip"] for r in records])

    manifest = json.dumps(
        {"version": version, "generated": generated_iso, "count": total,
         "nodes": records}, separators=(",", ":"))

    return TEMPLATE.format(
        start=START, end=END, version=version, generated=generated_iso,
        gen_date=esc(gen_date), total=total, countries=countries,
        table_rows=table_rows, plain=plain, ip_js=ip_js,
        manifest=manifest.replace("-", _DASH_JSON_ESCAPE),
    )


TEMPLATE = """{start}
<!-- AUTO-GENERATED by nym-maestro. Do not edit between the markers; regenerate instead. -->
<!-- NODES:VERSION {version} GENERATED {generated} COUNT {total} -->
<style id="nov-style">
  #node-overview{{max-width:1000px;margin:40px auto 0;padding:0 5vw;
    font-family:Consolas,"Ubuntu Mono",Menlo,"DejaVu Sans Mono",monospace;
    --nov-accent:var(--title-color,#07ff94);--nov-panel:#1a1f21;--nov-muted:#9fb3ad;--nov-line:#2f3a3c;}}
  #node-overview .nov-title{{font-size:28px;color:var(--nov-accent);text-align:center;margin:0 0 22px;}}
  #node-overview .nov-summary{{display:flex;flex-wrap:wrap;gap:14px;justify-content:center;margin:0 0 22px;}}
  #node-overview .nov-stat{{background:var(--nov-panel);border:1px solid var(--nov-line);border-radius:8px;
    padding:14px 26px;min-width:160px;text-align:center;}}
  #node-overview .nov-num{{font-size:32px;color:var(--nov-accent);font-weight:bold;line-height:1;}}
  #node-overview .nov-lbl{{font-size:12px;color:var(--nov-muted);text-transform:uppercase;letter-spacing:1px;margin-top:6px;}}
  #node-overview .nov-toolbar{{display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;margin:0 0 14px;}}
  #node-overview .nov-views{{display:flex;gap:6px;}}
  #node-overview .nov-btn{{background:transparent;color:var(--nov-accent);border:1px solid var(--nov-accent);
    border-radius:6px;padding:7px 14px;font:inherit;font-size:14px;cursor:pointer;}}
  #node-overview .nov-btn:hover{{background:rgba(7,255,148,.12);}}
  #node-overview .nov-btn.nov-active{{background:var(--nov-accent);color:#08110d;font-weight:bold;}}
  #node-overview .nov-updated{{font-size:12px;color:var(--nov-muted);}}
  #node-overview .nov-panel{{background:var(--nov-panel);border:2px solid var(--nov-accent);border-radius:8px;overflow:hidden;}}
  #node-overview table{{width:100%;border-collapse:collapse;font-size:14px;}}
  #node-overview thead th{{text-align:left;color:var(--nov-accent);font-weight:bold;padding:12px 14px;
    border-bottom:1px solid var(--nov-accent);text-transform:uppercase;letter-spacing:.5px;font-size:12px;white-space:nowrap;}}
  #node-overview tbody td{{padding:11px 14px;border-bottom:1px solid var(--nov-line);}}
  #node-overview tbody tr:last-child td{{border-bottom:none;}}
  #node-overview tbody tr:hover{{background:rgba(7,255,148,.05);}}
  #node-overview .nov-name{{font-weight:bold;}}
  #node-overview .nov-ip{{font-weight:bold;color:#fff;}}
  #node-overview .nov-host{{color:var(--nov-muted);font-size:13px;word-break:break-all;}}
  #node-overview .nov-flag{{margin-right:8px;}}
  #node-overview .nov-plain{{margin:0;padding:16px 18px;font-size:14px;white-space:pre;overflow-x:auto;color:#cfe;}}
  #node-overview .nov-foot{{text-align:center;font-size:13px;color:var(--nov-muted);margin:24px 0 0;}}
  #node-overview .nov-foot a{{font-size:13px;}}
  #node-overview .nov-hidden{{display:none;}}
  #node-overview .sortable{{cursor:pointer;user-select:none;}}
  @media(max-width:640px){{#node-overview thead th:nth-child(3),#node-overview tbody td:nth-child(3){{display:none;}}}}
</style>
<section id="node-overview" aria-label="All Nym exit gateways operated by Hermes Blockchain Ventures">
  <h2 class="nov-title">All nodes operated by Hermes Blockchain Ventures</h2>
  <div class="nov-summary">
    <div class="nov-stat"><div class="nov-num">{total}</div><div class="nov-lbl">Exit gateways</div></div>
    <div class="nov-stat"><div class="nov-num">{countries}</div><div class="nov-lbl">Countries</div></div>
  </div>
  <div class="nov-toolbar">
    <div class="nov-views">
      <button type="button" class="nov-btn nov-active" data-view="table">&#9636; Table</button>
      <button type="button" class="nov-btn" data-view="plain">&#8803; Plain IPs</button>
    </div>
    <div style="display:flex;gap:10px;align-items:center;">
      <button type="button" class="nov-btn" id="nov-copy">&#10696; Copy all IPs</button>
      <span class="nov-updated">list generated {gen_date}</span>
    </div>
  </div>
  <div id="nov-table" class="nov-panel">
    <table>
      <thead><tr>
        <th class="sortable" data-k="name">Node</th>
        <th class="sortable" data-k="ip">IPv4</th>
        <th class="sortable" data-k="hostname">Hostname</th>
        <th class="sortable" data-k="cc">Country</th>
      </tr></thead>
      <tbody>
{table_rows}
      </tbody>
    </table>
  </div>
  <div id="nov-plain" class="nov-panel nov-hidden"><pre class="nov-plain">{plain}</pre></div>
  <p class="nov-foot">Registered operator: Hermes Blockchain Ventures &middot; Germany &middot; abuse contact:
    <a href="mailto:hermes-stakepool@proton.me">hermes-stakepool@proton.me</a></p>
</section>
<script>
(function(){{
  var root=document.getElementById('node-overview'); if(!root) return;
  var ips={ip_js};
  root.querySelectorAll('.nov-btn[data-view]').forEach(function(b){{
    b.addEventListener('click',function(){{
      var v=b.getAttribute('data-view');
      root.querySelector('#nov-table').classList.toggle('nov-hidden',v!=='table');
      root.querySelector('#nov-plain').classList.toggle('nov-hidden',v!=='plain');
      root.querySelectorAll('.nov-btn[data-view]').forEach(function(x){{x.classList.remove('nov-active');}});
      b.classList.add('nov-active');
    }});
  }});
  var copy=root.querySelector('#nov-copy');
  copy.addEventListener('click',function(){{
    var text=ips.join('\\n');
    var done=function(){{var t=copy.textContent;copy.textContent='\\u2713 Copied '+ips.length+' IPs';setTimeout(function(){{copy.textContent=t;}},1500);}};
    if(navigator.clipboard&&navigator.clipboard.writeText){{navigator.clipboard.writeText(text).then(done,done);}}
    else{{var ta=document.createElement('textarea');ta.value=text;document.body.appendChild(ta);ta.select();try{{document.execCommand('copy');}}catch(e){{}}document.body.removeChild(ta);done();}}
  }});
  var tb=root.querySelector('tbody'), asc=true, curr=null;
  root.querySelectorAll('th.sortable').forEach(function(th,i){{
    th.addEventListener('click',function(){{
      asc = (curr===i)?!asc:true; curr=i;
      var rows=[].slice.call(tb.querySelectorAll('tr'));
      rows.sort(function(a,b){{
        var x=a.children[i].textContent.trim().toLowerCase(), y=b.children[i].textContent.trim().toLowerCase();
        return (x>y?1:x<y?-1:0)*(asc?1:-1);
      }});
      rows.forEach(function(r){{tb.appendChild(r);}});
    }});
  }});
}})();
</script>
<!-- NODES:DATA {manifest} -->
{end}"""


# ----------------------------------------------------------------- diff + splice
def extract_manifest(html):
    """The embedded machine-readable node list, or None if the page has none."""
    m = MANIFEST_RE.search(html or "")
    if not m:
        return None
    try:
        # - dashes are decoded by json itself; the zero-width guard is only
        # present in pages written before that changed.
        return json.loads(m.group(1).replace(_LEGACY_COMMENT_SAFE_DASHES, "--"))
    except Exception:
        return None


def extract_version(html):
    """The NODES:VERSION stamp of a page, or None. Used to tell whether a node
    already serves the current list without shipping the file again."""
    m = VERSION_RE.search(html or "")
    return m.group(1) if m else None


def membership_diff(prev, records):
    """Compare against the previous embedded manifest, keyed by hostname."""
    old = {r["hostname"]: r for r in ((prev or {}).get("nodes") or [])}
    new = {r["hostname"]: r for r in records}
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    changed = sorted(h for h in (set(new) & set(old)) if new[h] != old[h])
    return added, removed, changed


def splice(html, block):
    """Put the block into the master, returning (new_html, mode)."""
    if START in html and END in html:
        return re.sub(re.escape(START) + r'.*?' + re.escape(END), lambda _: block, html,
                      count=1, flags=re.DOTALL), "markers"
    if LEGACY_RE.search(html):
        return LEGACY_RE.sub(lambda _: block, html, count=1), "legacy-section"
    if "</body>" in html:
        return html.replace("</body>", block + "\n</body>", 1), "appended"
    return html + "\n" + block, "appended-eof"


# ----------------------------------------------------------------- build
def build(nodes, master_html, include_disabled=False, allow_partial=False, generated=None):
    """Regenerate the node block inside `master_html`.

    Raises LandingError rather than publishing anything questionable: an empty
    or half-validated authority list is worse than a stale one.
    """
    if not isinstance(nodes, list) or not nodes:
        raise LandingError("no nodes available; refusing to publish an empty list")

    records, warnings, fatal = select(nodes, include_disabled=include_disabled)
    if fatal and not allow_partial:
        raise LandingError(
            "%d node(s) have an unusable IP or hostname. Fix them in maestro, or "
            "enable \"allow partial\" to exclude them and continue." % len(fatal),
            fatal)
    if not records:
        raise LandingError("no publishable exit gateways after filtering")

    if generated is None:
        generated = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    version = version_for(records)

    prev = extract_manifest(master_html)
    added, removed, changed = membership_diff(prev, records)

    block = render_block(records, generated, version)
    new_html, mode = splice(master_html, block)

    return {
        "version": version,
        "generated": generated,
        "html": new_html,
        "block": block,
        "splice_mode": mode,
        "records": records,
        "counts": {
            "nodes": len(records),
            "countries": len({r["cc"] for r in records if r["cc"]}),
            "excluded": len(fatal),
        },
        "diff": {
            "first_run": prev is None,
            "added": added,
            "removed": removed,
            "changed": changed,
            "previous_version": (prev or {}).get("version"),
        },
        "warnings": warnings,
        "excluded": fatal if allow_partial else [],
    }


def atomic_write(path, data):
    """Write via a temp file in the same directory, preserving mode/owner."""
    path = str(path)
    d = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".landing.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        if os.path.exists(path):
            st = os.stat(path)
            os.chmod(tmp, st.st_mode)
            try:
                os.chown(tmp, st.st_uid, st.st_gid)
            except (PermissionError, AttributeError):
                pass
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
