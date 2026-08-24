"""Abuse-reply drafting for nym maestro (orchestrator-side, stdlib-only).

Pure functions, no I/O — testable without the app. The point of the feature is
CONSISTENCY: the same complainant (e.g. Paramount) gets the same reasoning every
time, only the case id changes. So drafting prefers reusing the stored reply of
the most recent case from that complainant (with the case id swapped) over
rendering the template fresh.

Reply canon (all present in DEFAULT_TEMPLATE, keep them when editing):
  mere conduit · content never selected or modified (deliberate part of the
  legal strategy — the mere-conduit safe harbour requires it) · operated by
  Hermes Blockchain Ventures, fully compliant with German and EU law ·
  no client data · no logs · tight exit policy (link) · rate limiting to
  mitigate abuse · we take this seriously.
"""
import ipaddress
import re

EXIT_POLICY_URL = "https://nymtech.net/.wellknown/network-requester/exit-policy.txt"

# Placeholders are literal {case_id} / {ip} tokens replaced by render_reply()
# (plain str.replace, NOT str.format — the template may contain braces).
DEFAULT_TEMPLATE = """\
Dear {addressee},

thank you for your notice regarding Case ID {case_id}.

The IP address {ip} is the exit address of a Nym exit gateway operated by us. \
It is part of the Nym mixnet (https://nym.com), a decentralised privacy network \
comparable to Tor. The traffic in question did not originate from us or from any \
customer of ours: as the operator of an exit gateway we act as a mere conduit \
and only relay traffic on behalf of anonymous users of the network. This node \
is operated by Hermes Blockchain Ventures and fully complies with German and \
EU law.

Regarding your report:

- We are a mere conduit. We do not host, store or control any of the content in
  question, and we do not select or modify the transmitted content in any way;
  the connection was routed through our system automatically.
- We hold no client data relating to this traffic. Depending on the client's
  mode, traffic reaches the exit through the Nym mixnet (five layered-encrypted
  hops) or through the two-hop dVPN tunnel. In either case at least two
  separate hops are involved, and the route is selected by the client — not by
  us — from a network of independent operators, so the hops are typically run
  by different, unrelated parties. Our gateway only ever sees the immediately
  preceding hop, never the originating user; it is therefore technically
  impossible for us to identify the source of a connection.
- We keep no logs that would allow attribution of past connections.
- We operate a tight exit policy ({exit_policy}) that blocks abuse-prone ports
  and services on this gateway.
- We operate rate limiting on this gateway to mitigate abuse and automated
  attacks.

We take abuse reports seriously — the measures above exist precisely to keep
abuse through this exit as low as technically possible, and we review every
report we receive.

Please keep Case ID {case_id} in the subject line of any further correspondence.

Kind regards,
""".replace("{exit_policy}", EXIT_POLICY_URL)

CASE_ID_PLACEHOLDER = "[CASE-ID]"

# Ordered by confidence: an explicitly labelled id beats a bare hex token.
_CASE_PATTERNS = [
    re.compile(r"\bcase\s*(?:id|number|no\.?|#)?\s*[:#]?\s*([A-Za-z0-9][A-Za-z0-9._/-]{3,63})", re.I),
    re.compile(r"\b(?:ticket|incident|report|complaint|reference|abuse)"
               r"\s*(?:id|number|no\.?|#)?\s*[:#]?\s*([A-Za-z0-9][A-Za-z0-9._/-]{3,63})", re.I),
    re.compile(r"\bref\.?\s*[:#]\s*([A-Za-z0-9][A-Za-z0-9._/-]{3,63})", re.I),
    re.compile(r"\[([A-Za-z0-9][A-Za-z0-9._/-]{5,63})\]"),   # bracketed subject ref
    re.compile(r"\b([0-9a-f]{12,64})\b", re.I),              # bare long hex token
]

# Words a labelled pattern may capture by accident ("in case you need ...").
_STOPWORDS = {"id", "number", "the", "that", "this", "your", "you"}


def _plausible_id(tok: str) -> bool:
    tok = tok.strip(".,;:")
    if len(tok) < 4 or tok.lower() in _STOPWORDS:
        return False
    return any(c.isdigit() for c in tok)


def extract_case_id(text: str) -> str:
    """Best-effort case/ticket id from a pasted abuse report ('' if none)."""
    for pat in _CASE_PATTERNS:
        for m in pat.finditer(text or ""):
            tok = m.group(1).strip(".,;:")
            if _plausible_id(tok):
                return tok
    return ""


_IP4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IP6_RE = re.compile(r"\b[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){2,7}\b")


def extract_ips(text: str) -> list:
    """Valid, deduped IPs found in the report, public before private."""
    seen, pub, priv = set(), [], []
    for m in list(_IP4_RE.finditer(text or "")) + list(_IP6_RE.finditer(text or "")):
        raw = m.group(0)
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        s = str(ip)
        if s in seen:
            continue
        seen.add(s)
        (pub if ip.is_global else priv).append(s)
    return pub + priv


def _match_known(text: str, known: list) -> str:
    """Match a previously-seen name in the report (longest first, case-
    insensitive). Only ever suggests names already in the DB — no NER."""
    low = (text or "").lower()
    for name in sorted((n for n in known if n), key=len, reverse=True):
        if name.lower() in low:
            return name
    return ""


def guess_complainant(text: str, known: list) -> str:
    return _match_known(text, known)


def guess_provider(text: str, known: list) -> str:
    """Abuse mails usually arrive via the hoster and often open with its name
    ('ATW Internet Kft.' ...). Match known providers so the reply can be
    addressed 'Dear ATW,'."""
    return _match_known(text, known)


DEFAULT_ADDRESSEE = "Sir or Madam"


def render_reply(template: str, case_id: str = "", ip: str = "",
                 addressee: str = "") -> str:
    """Fill the template. Missing values degrade to readable text, never to an
    empty hole: the operator sees [CASE-ID] and fixes it before sending."""
    return ((template or DEFAULT_TEMPLATE)
            .replace("{addressee}", addressee or DEFAULT_ADDRESSEE)
            .replace("{case_id}", case_id or CASE_ID_PLACEHOLDER)
            .replace("{ip}", ip or "listed in your report"))


# First line that looks like a salutation — replaced on reuse so a reply that
# went to OVH last time greets ATW this time (body stays verbatim).
_SALUTATION_RE = re.compile(
    r"^(?:dear\b[^\n]{0,80}|hello[^\n]{0,40}|hi[^\n]{0,40}|to whom it may concern[^\n]{0,10})$",
    re.I | re.M)


def swap_salutation(reply: str, addressee: str) -> str:
    """Point the greeting of a reused reply at the new addressee. Only the
    first salutation-looking line is touched; a reply without one is returned
    unchanged rather than guessing where to inject a greeting."""
    if not addressee:
        return reply
    return _SALUTATION_RE.sub(f"Dear {addressee},", reply or "", count=1)


def swap_case_id(reply: str, old_id: str, new_id: str) -> str:
    """Reuse a stored reply verbatim, only the case id changes. If the old reply
    carries no recognisable id to swap, prefix one so the new id is guaranteed
    to appear (identical body, traceable case)."""
    new_id = new_id or CASE_ID_PLACEHOLDER
    if old_id and old_id in (reply or ""):
        return reply.replace(old_id, new_id)
    if CASE_ID_PLACEHOLDER in (reply or ""):
        return reply.replace(CASE_ID_PLACEHOLDER, new_id)
    return f"Case ID: {new_id}\n\n{reply or ''}"
