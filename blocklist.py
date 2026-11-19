"""Destination blocklist maintained in maestro (pure helpers, no I/O).

The list lives in app_config (key BLOCKLIST_KEY) as the text the operator edits:
one IPv4/IPv6 address or CIDR per line, '#' comments allowed. On rollout the
canonical entries are sent to each agent (extra_blocks_install), which writes them
to the node and applies them as REJECTs marked "nym_block" in NYM-EXIT. maestro is
the source of truth; the GitHub blocklist.txt fetch is gone. The repo file
blocklist.txt only seeds the list on first use.

Validation rules are mirrored agent-side (agent.eb_canonical): keep them in sync,
test_extra_blocks.py checks that both agree.
"""
import hashlib
import ipaddress

BLOCKLIST_KEY = "blocklist"
MAX_ENTRIES = 5000
# Refuse prefixes broader than this: one typo (0.0.0.0/0, 2000::/3) would take
# the whole exit down for every client.
MIN_PREFIX = {4: 16, 6: 32}


def canonical(entry):
    """(canonical network string, None) or (None, reason)."""
    e = (entry or "").strip()
    if not e:
        return None, "empty"
    if len(e) > 64:
        return None, "too long"
    try:
        net = ipaddress.ip_network(e, strict=True)
    except ValueError as ex:
        try:
            loose = ipaddress.ip_network(e, strict=False)
        except ValueError:
            return None, "not an IPv4/IPv6 address or CIDR"
        return None, f"host bits set ({ex}) — did you mean {loose}?"
    if net.prefixlen < MIN_PREFIX[net.version]:
        return None, (f"too broad: /{net.prefixlen} (minimum /{MIN_PREFIX[net.version]} "
                      f"for IPv{net.version}) — this would block a huge part of the internet")
    return str(net), None


def parse(text):
    """Parse the editable list. Returns
    {"entries": [canonical, ...] (first-seen order, deduplicated),
     "errors": [{"line": n, "text": raw, "error": reason}],
     "duplicates": [{"line": n, "text": raw, "same_as": canonical}]}"""
    entries, errors, dups, seen = [], [], [], {}
    for i, raw in enumerate((text or "").splitlines(), 1):
        e = raw.split("#", 1)[0].strip()
        if not e:
            continue
        c, err = canonical(e)
        if err:
            errors.append({"line": i, "text": raw.strip()[:200], "error": err})
            continue
        if c in seen:
            dups.append({"line": i, "text": raw.strip()[:200], "same_as": c})
            continue
        seen[c] = i
        entries.append(c)
    if len(entries) > MAX_ENTRIES:
        errors.append({"line": 0, "text": "", "error": f"too many entries (max {MAX_ENTRIES})"})
    return {"entries": entries, "errors": errors, "duplicates": dups}


def list_sha(entries):
    """Order-independent fingerprint; identical to agent.eb_list_sha, so the UI
    can tell which nodes still run an older list."""
    canon = sorted({c for c in (canonical(e)[0] for e in entries) if c})
    return hashlib.sha256("\n".join(canon).encode()).hexdigest()


def summary(text):
    """parse() plus the fields the UI shows."""
    p = parse(text)
    v4 = sum(1 for e in p["entries"] if ":" not in e)
    return dict(p, count=len(p["entries"]), v4=v4, v6=len(p["entries"]) - v4,
                sha=list_sha(p["entries"]), valid=not p["errors"])
