"""Per-node Nyx account balance (ticket-redemption funds).

Every nym-node holds a Nyx account whose balance pays for ticket redemptions.
The node publishes that address on its own HTTP API
(`http://<ip>:8080/api/v2/auxiliary-details`); the balance comes from any Nyx
LCD (`/cosmos/bank/v1beta1/balances/<addr>`). When the balance drops below
MIN_NYM the fleet table shows a warning.

This module is the pure part (URL building, parsing, threshold logic) so it is
testable without network access; the fetching lives in app.py.
"""
import ipaddress
import os
import re

UNYM = 1_000_000
ADDR_RE = re.compile(r"^n1[a-z0-9]{38,50}$")

# nym-node's public HTTP API port (the one serving /api/v2/...).
NODE_API_PORT = int(os.environ.get("MAESTRO_NODE_API_PORT", "8080"))
# warn when the account holds less than this many NYM
MIN_NYM = float(os.environ.get("MAESTRO_NYX_MIN_NYM", "5"))
# nym-api's per-node annotation (network-side verdict: has_sufficient_tokens,
# feegrant, cached on-chain balance, scores). Keyed by the numeric node id.
ANNOTATION_URL = os.environ.get(
    "MAESTRO_NYM_ANNOTATION_URL",
    "https://validator.nymtech.net/api/v2/nym-nodes/annotation/")


def aux_details_url(ip: str, port: int = None) -> str:
    """http://<ip>:<port>/api/v2/auxiliary-details (IPv6 literal bracketed)."""
    port = NODE_API_PORT if port is None else port
    host = str(ip).strip()
    try:
        if isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address):
            host = f"[{host}]"
    except ValueError:
        pass  # a hostname is fine as-is
    return f"http://{host}:{port}/api/v2/auxiliary-details"


def balance_path(address: str) -> str:
    return f"/cosmos/bank/v1beta1/balances/{address}"


def parse_aux_details(data) -> str | None:
    """Extract the Nyx address from an auxiliary-details payload, or None."""
    if not isinstance(data, dict):
        return None
    addr = data.get("address")
    if isinstance(addr, str) and ADDR_RE.match(addr.strip()):
        return addr.strip()
    return None


def parse_balances(data) -> int | None:
    """Sum of the account's `unym` balances in uNYM. An account that exists
    but holds nothing yields 0; a malformed payload yields None."""
    if not isinstance(data, dict) or not isinstance(data.get("balances"), list):
        return None
    total = 0
    for b in data["balances"]:
        if not isinstance(b, dict) or b.get("denom") != "unym":
            continue
        try:
            total += int(b.get("amount"))
        except (TypeError, ValueError):
            return None
    return total


def annotation_url(node_id) -> str:
    return ANNOTATION_URL + str(int(node_id))


def parse_annotation(data) -> dict | None:
    """Reduce a nym-api annotation payload to what the fleet table needs.

    Returns {node_id, balance_unym, sufficient, feegrant, role, performance}
    (each None when absent) or None if the payload is not an annotation.
    """
    if not isinstance(data, dict) or not isinstance(data.get("annotation"), dict):
        return None
    ann = data["annotation"]
    cic = ann.get("chain_interaction_capabilities") or {}
    perf = ann.get("detailed_performance") or {}
    cfg = (perf.get("config_score") or {}).get("chain_interaction_capabilities") or {}
    bal = None
    ocb = cic.get("on_chain_balance")
    if isinstance(ocb, dict) and ocb.get("denom") in (None, "unym"):
        try:
            bal = int(ocb.get("amount"))
        except (TypeError, ValueError):
            bal = None
    suff = cfg.get("has_sufficient_tokens")
    fee = cfg.get("is_fee_grant_grantee")
    if fee is None:
        fee = cic.get("is_feegrant_grantee")
    score = perf.get("performance_score")
    return {
        "node_id": data.get("node_id"),
        "balance_unym": bal,
        "sufficient": (bool(suff) if suff is not None else None),
        "feegrant": (bool(fee) if fee is not None else None),
        "role": ann.get("current_role"),
        "performance": (float(score) if isinstance(score, (int, float)) else None),
    }


def unym_to_nym(unym) -> float | None:
    if unym is None:
        return None
    return round(int(unym) / UNYM, 6)


def annotate(rec: dict | None, threshold: float = None) -> dict | None:
    """Attach the warning verdict to a stored nyx record for the API/UI.

    `low` is True only when a balance is known and below the threshold; an
    unknown balance is not a warning by itself (it carries `error` instead).
    The live LCD balance wins; nym-api's cached on-chain balance (`net`) is the
    fallback when the LCD read failed (`balance_source` says which). A node
    with a fee grant never counts as low: someone else pays its fees.
    `insufficient` is the network's own verdict (has_sufficient_tokens false),
    which costs the node config score regardless of our threshold.
    """
    if not rec:
        return None
    threshold = MIN_NYM if threshold is None else float(threshold)
    out = dict(rec)
    net = out.get("net") or None
    bal = out.get("balance_nym")
    source = "lcd" if bal is not None else None
    if bal is None and net and net.get("balance_unym") is not None:
        bal = unym_to_nym(net["balance_unym"])
        source = "nym-api"
    feegrant = bool(net and net.get("feegrant"))
    out["threshold"] = threshold
    out["shown_balance_nym"] = bal
    out["balance_source"] = source
    out["feegrant"] = feegrant
    out["insufficient"] = bool(net and net.get("sufficient") is False)
    out["low"] = (bal is not None) and (bal < threshold) and not feegrant
    return out
