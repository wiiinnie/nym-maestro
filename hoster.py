"""VPS hoster per node, derived from the node's IP (pure helpers, no network).

The hostname is our own domain (nym-exit-XX01.hermes-stakepool.de) and says
nothing about the hoster, so the IP's origin AS is the signal: RIPEstat
network-info gives the ASN announcing the IP, as-overview gives the AS holder
("OVH OVH SAS", "HETZNER-AS Hetzner Online GmbH"). RIPEstat answers for every
RIR, not just RIPE. Fetching lives in app.py (refresh_hosters).

Hosters change only when a node moves, so a lookup is cached per node and
redone only when the IP changes or the entry is older than MAX_AGE_S.
"""
import ipaddress
import re
import urllib.parse

RIPESTAT = "https://stat.ripe.net/data"
SOURCEAPP = "nym-maestro"          # RIPEstat asks clients to identify the app
MAX_AGE_S = 7 * 86400

# Short names for the hosters the fleet uses. They match the provider names in
# the abuse cases (OVH, Hetzner, ATW), so both views speak the same language.
KNOWN_ASNS = {
    16276: "OVH",
    35540: "OVH",
    24940: "Hetzner",
    213230: "Hetzner",
    212317: "Hetzner",
    197540: "netcup",
    41075: "ATW",
    200019: "AlexHost",
    56655: "Gigahost",
    48881: "DataNode",
}

# AS holder text -> short name, for ASNs not listed above (another AS of a
# known hoster, or a new hoster whose name is recognisable).
_HOLDER_HINTS = (
    (re.compile(r"\bovh", re.I), "OVH"),
    (re.compile(r"\bhetzner", re.I), "Hetzner"),
    (re.compile(r"\bnetcup", re.I), "netcup"),
    (re.compile(r"\batw\b", re.I), "ATW"),
    (re.compile(r"\balexhost", re.I), "AlexHost"),
    (re.compile(r"\bgigahost", re.I), "Gigahost"),
    (re.compile(r"\bdatanode", re.I), "DataNode"),
    (re.compile(r"\bcontabo", re.I), "Contabo"),
    (re.compile(r"\bdigitalocean", re.I), "DigitalOcean"),
    (re.compile(r"\bscaleway|\bonline s\.?a\.?s", re.I), "Scaleway"),
    (re.compile(r"\bleaseweb", re.I), "Leaseweb"),
    (re.compile(r"\bvultr|\bchoopa|\bconstant", re.I), "Vultr"),
    (re.compile(r"\blinode|\bakamai", re.I), "Akamai/Linode"),
    (re.compile(r"\bionos|\b1&1", re.I), "IONOS"),
    (re.compile(r"\bm247", re.I), "M247"),
    (re.compile(r"\bfranTech|\bbuyvm", re.I), "BuyVM"),
)

_LEGAL = re.compile(
    r"[,\s]+(gmbh|ag|sas|sa|s\.a\.|s\.r\.l\.|srl|kft\.?|ltd\.?|limited|llc|inc\.?|"
    r"b\.v\.|bv|as|ab|oy|sp\. z o\.o\.|s\.r\.o\.|co\.?)$", re.I)


def network_info_url(ip):
    q = urllib.parse.urlencode({"resource": ip, "sourceapp": SOURCEAPP})
    return f"{RIPESTAT}/network-info/data.json?{q}"


def as_overview_url(asn):
    q = urllib.parse.urlencode({"resource": f"AS{int(asn)}", "sourceapp": SOURCEAPP})
    return f"{RIPESTAT}/as-overview/data.json?{q}"


def parse_network_info(payload):
    """(asn, prefix) from network-info, or (None, None). With several origin
    ASNs (rare, MOAS) the first one is taken."""
    try:
        d = payload["data"]
        asns = d.get("asns") or []
        asn = int(asns[0]) if asns else None
    except (KeyError, TypeError, ValueError, IndexError, AttributeError):
        return None, None
    prefix = d.get("prefix") if isinstance(d.get("prefix"), str) else None
    return asn, prefix


def parse_as_overview(payload):
    """AS holder string ("OVH OVH SAS") or None."""
    try:
        h = payload["data"].get("holder")
    except (KeyError, TypeError, AttributeError):
        return None
    return h.strip() if isinstance(h, str) and h.strip() else None


def _clean_holder(holder):
    """'ALEXHOST ALEXHOST S.R.L.' -> 'ALEXHOST'. Drops the leading AS handle
    when an organisation name follows it, then trailing legal forms."""
    parts = holder.split(None, 1)
    name = holder
    if len(parts) == 2:
        head, rest = parts
        # RIPE-style "<HANDLE> <Org>": the handle has a dash/underscore, is all
        # caps, or repeats the org's first word ("AlexHost ALEXHOST S.R.L.").
        # "Acme Networks Ltd" has no handle and stays whole.
        if ("-" in head or "_" in head or (head.isupper() and len(head) > 1)
                or rest.split()[0].lower() == head.lower()):
            name = rest
    for _ in range(3):
        new = _LEGAL.sub("", name).strip(" ,")
        if new == name:
            break
        name = new
    return name or holder


def short_name(asn, holder):
    """Display name for the hoster: known ASN > holder hint > cleaned holder."""
    if asn in KNOWN_ASNS:
        return KNOWN_ASNS[asn]
    if holder:
        for rx, name in _HOLDER_HINTS:
            if rx.search(holder):
                return name
        return _clean_holder(holder)
    return f"AS{asn}" if asn else None


def is_public_ip(ip):
    """Only globally routable IPs are looked up — private, loopback and
    documentation ranges (test fixtures) never leave the machine."""
    try:
        return ipaddress.ip_address((ip or "").strip()).is_global
    except ValueError:
        return False


def needs_lookup(node, now_epoch):
    """True when the node has no cached hoster, its IP changed since the lookup,
    the last attempt failed, or the entry is older than MAX_AGE_S."""
    h = node.get("hoster") or {}
    if not h.get("name") or h.get("error"):
        return True
    if (h.get("ip") or "") != (node.get("ip") or ""):
        return True
    checked = h.get("checked_at")
    if not isinstance(checked, (int, float)):
        return True
    return now_epoch - checked > MAX_AGE_S
