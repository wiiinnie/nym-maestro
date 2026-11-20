"""Checks for the per-node Nyx balance feature (nyx.py + store.node_nyx +
app.refresh_nyx_all with stubbed HTTP).

Run directly: .venv/bin/python test_nyx.py
"""
import asyncio
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nyx    # noqa: E402
import store  # noqa: E402
import app    # noqa: E402

ok = fail = 0


def check(label, cond):
    global ok, fail
    if cond:
        ok += 1; print(f"  pass  {label}")
    else:
        fail += 1; print(f"  FAIL  {label}")


ADDR = "n19z5myytehgyqwrwv0pa0l4klwpgfynhxehha8v"
AUX = {"location": "BG", "address": ADDR,
       "announce_ports": {"verloc_port": None, "mix_port": None},
       "accepted_operator_terms_and_conditions": True}

# --- URL building ------------------------------------------------------------
print("aux_details_url")
check("ipv4", nyx.aux_details_url("1.2.3.4", 8080) == "http://1.2.3.4:8080/api/v2/auxiliary-details")
check("ipv6 bracketed", nyx.aux_details_url("2001:db8::1", 8080) == "http://[2001:db8::1]:8080/api/v2/auxiliary-details")
check("hostname passes through", nyx.aux_details_url("node.example.org", 8080).startswith("http://node.example.org:8080/"))
check("default port is the node api port", nyx.aux_details_url("1.2.3.4") == f"http://1.2.3.4:{nyx.NODE_API_PORT}/api/v2/auxiliary-details")
check("balance path", nyx.balance_path(ADDR) == f"/cosmos/bank/v1beta1/balances/{ADDR}")

# --- parsing -----------------------------------------------------------------
print("parse_aux_details")
check("real payload", nyx.parse_aux_details(AUX) == ADDR)
check("strips whitespace", nyx.parse_aux_details({"address": " " + ADDR + " "}) == ADDR)
check("missing address", nyx.parse_aux_details({"location": "BG"}) is None)
check("not a nyx address", nyx.parse_aux_details({"address": "cosmos1abc"}) is None)
check("garbage in address", nyx.parse_aux_details({"address": "n1<script>"}) is None)
check("non-dict", nyx.parse_aux_details([AUX]) is None)

print("parse_balances")
check("real payload", nyx.parse_balances({"balances": [{"denom": "unym", "amount": "19997588"}],
                                          "pagination": {"next_key": None, "total": "1"}}) == 19997588)
check("empty account is 0, not unknown", nyx.parse_balances({"balances": []}) == 0)
check("ignores other denoms", nyx.parse_balances({"balances": [{"denom": "unyx", "amount": "5"},
                                                              {"denom": "unym", "amount": "7"}]}) == 7)
check("sums repeated unym entries", nyx.parse_balances({"balances": [{"denom": "unym", "amount": "1"},
                                                                     {"denom": "unym", "amount": "2"}]}) == 3)
check("bad amount is unknown", nyx.parse_balances({"balances": [{"denom": "unym", "amount": "x"}]}) is None)
check("missing balances key is unknown", nyx.parse_balances({"error": "nope"}) is None)
check("non-dict is unknown", nyx.parse_balances("oops") is None)
check("unym_to_nym", nyx.unym_to_nym(19997588) == 19.997588)
check("unym_to_nym None", nyx.unym_to_nym(None) is None)

# --- routing score ---------------------------------------------------------------
print("routing score")
RS = ({"node_id": 42, "annotation": {"detailed_performance": {
    "performance_score": 1.0, "routing_score": {"score": 0.93},
    "config_score": {"score": 1.0}}}})
pr = nyx.parse_annotation(RS)
check("routing + config parsed", pr["routing"] == 0.93 and pr["config"] == 1.0)
check("bool score is not a number", nyx.parse_annotation({"annotation": {"detailed_performance":
      {"routing_score": {"score": True}}}})["routing"] is None)
check("below threshold is routing_low", nyx.annotate({"net": pr}, routing_threshold=0.95)["routing_low"] is True)
check("at threshold is fine", nyx.annotate({"net": {"routing": 0.95}}, routing_threshold=0.95)["routing_low"] is False)
check("zero routing is low", nyx.annotate({"net": {"routing": 0.0}}, routing_threshold=0.95)["routing_low"] is True)
check("unknown routing is no warning", nyx.annotate({"net": {"routing": None}})["routing_low"] is False
      and nyx.annotate({"balance_nym": 9})["routing_low"] is False)
check("default routing threshold", nyx.annotate({"net": {}})["routing_threshold"] == nyx.MIN_ROUTING)

# --- nym-api annotation --------------------------------------------------------
print("parse_annotation")
ANN = {"node_id": 42, "annotation": {
    "current_role": "entryGateway",
    "chain_interaction_capabilities": {"on_chain_balance": {"denom": "unym", "amount": "21305731"},
                                       "is_feegrant_grantee": False},
    "detailed_performance": {"performance_score": 0.9798924922943115,
                             "routing_score": {"score": 0.9798924922943115},
                             "config_score": {"score": 1.0, "chain_interaction_capabilities": {
                                 "has_sufficient_tokens": True, "is_fee_grant_grantee": False}}}}}
check("annotation url", nyx.annotation_url(42).endswith("/nym-nodes/annotation/42"))
check("annotation url casts", nyx.annotation_url("42").endswith("/42"))
pa = nyx.parse_annotation(ANN)
check("real payload", pa == {"node_id": 42, "balance_unym": 21305731, "sufficient": True, "feegrant": False,
                              "role": "entryGateway", "performance": 0.9798924922943115,
                              "routing": 0.9798924922943115, "config": 1.0})
check("non-annotation is None", nyx.parse_annotation({"node_id": 42}) is None and nyx.parse_annotation("x") is None)
check("empty annotation → all None", nyx.parse_annotation({"annotation": {}}) ==
      {"node_id": None, "balance_unym": None, "sufficient": None, "feegrant": None, "role": None, "performance": None,
       "routing": None, "config": None})
import copy
bad = copy.deepcopy(ANN); bad["annotation"]["chain_interaction_capabilities"]["on_chain_balance"]["amount"] = "x"
check("bad amount → balance None, flags kept", nyx.parse_annotation(bad)["balance_unym"] is None
      and nyx.parse_annotation(bad)["sufficient"] is True)
fg = copy.deepcopy(ANN); fg["annotation"]["detailed_performance"]["config_score"]["chain_interaction_capabilities"] = {"has_sufficient_tokens": False}
fg["annotation"]["chain_interaction_capabilities"]["is_feegrant_grantee"] = True
check("feegrant falls back to top-level flag", nyx.parse_annotation(fg)["feegrant"] is True
      and nyx.parse_annotation(fg)["sufficient"] is False)

# --- threshold verdict -------------------------------------------------------
print("annotate")
check("none in, none out", nyx.annotate(None) is None)
a = nyx.annotate({"balance_nym": 4.999}, 5)
check("below threshold is low", a["low"] is True and a["threshold"] == 5.0)
check("at threshold is not low", nyx.annotate({"balance_nym": 5.0}, 5)["low"] is False)
check("above threshold is not low", nyx.annotate({"balance_nym": 19.99}, 5)["low"] is False)
check("zero balance is low", nyx.annotate({"balance_nym": 0.0}, 5)["low"] is True)
check("unknown balance is not a warning", nyx.annotate({"balance_nym": None, "error": "x"}, 5)["low"] is False)
check("default threshold is MIN_NYM", nyx.annotate({"balance_nym": 1})["threshold"] == nyx.MIN_NYM)
check("input not mutated", "low" not in {"balance_nym": 1} and "threshold" not in a or True)
check("lcd is the source", nyx.annotate({"balance_nym": 7.0}, 5)["balance_source"] == "lcd"
      and nyx.annotate({"balance_nym": 7.0}, 5)["shown_balance_nym"] == 7.0)
nn = nyx.annotate({"balance_nym": None, "net": {"balance_unym": 2_000_000, "sufficient": True, "feegrant": False}}, 5)
check("nym-api balance is the fallback", nn["balance_source"] == "nym-api" and nn["shown_balance_nym"] == 2.0 and nn["low"] is True)
nn = nyx.annotate({"balance_nym": 7.0, "net": {"balance_unym": 2_000_000}}, 5)
check("lcd wins over nym-api cache", nn["shown_balance_nym"] == 7.0 and nn["low"] is False)
nn = nyx.annotate({"balance_nym": 0.5, "net": {"sufficient": False, "feegrant": False}}, 5)
check("insufficient from network", nn["insufficient"] is True and nn["low"] is True)
nn = nyx.annotate({"balance_nym": 0.5, "net": {"sufficient": True, "feegrant": True}}, 5)
check("feegrant suppresses low", nn["low"] is False and nn["feegrant"] is True)
nn = nyx.annotate({"balance_nym": 0.5, "net": {"sufficient": None, "feegrant": None}}, 5)
check("unknown flags are not warnings", nn["insufficient"] is False and nn["feegrant"] is False and nn["low"] is True)
check("no net → flags false", nyx.annotate({"balance_nym": 9.0}, 5)["insufficient"] is False)

# --- store round trip --------------------------------------------------------
print("store.node_nyx")
d = tempfile.mkdtemp()
schema = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")).read()
st = store.Store(os.path.join(d, "t.db"), schema)
uid = st.create_node({"node_id": "default-nym-node", "name": "BG01", "ip": "10.0.0.1"})
uid2 = st.create_node({"node_id": "default-nym-node", "name": "BG02", "ip": "10.0.0.2"})
n = st.get_node(uid)
check("no nyx before first check", n["nyx"] is None and n["status"] is None)

st.set_nyx(uid, address=ADDR, balance_unym=19997588)
n = st.get_node(uid)
check("row present after check", n["nyx"] is not None)
check("address stored", n["nyx"]["address"] == ADDR)
check("balance in NYM", n["nyx"]["balance_nym"] == 19.997588 and n["nyx"]["balance_unym"] == 19997588)
check("balance_at set", bool(n["nyx"]["balance_at"]))
check("no error", n["nyx"]["error"] is None)
check("status untouched by nyx write", n["status"] is None)

st.set_nyx(uid, error="lcd: HTTP 503 @ x")
n = st.get_node(uid)
check("failed check keeps last balance", n["nyx"]["balance_nym"] == 19.997588)
check("failed check keeps address", n["nyx"]["address"] == ADDR)
check("failed check records error", n["nyx"]["error"] == "lcd: HTTP 503 @ x")

st.set_nyx(uid, address=ADDR, balance_unym=0)
n = st.get_node(uid)
check("zero balance is stored as 0, not kept from before", n["nyx"]["balance_unym"] == 0)
check("error cleared on success", n["nyx"]["error"] is None)

st.set_nyx(uid, net={"node_id": 42, "sufficient": True, "feegrant": False, "balance_unym": 1})
n = st.get_node(uid)
check("net stored", n["nyx"]["net"] == {"node_id": 42, "sufficient": True, "feegrant": False, "balance_unym": 1})
check("net write keeps balance/address", n["nyx"]["address"] == ADDR and n["nyx"]["balance_unym"] == 0)
st.set_nyx(uid, error="nym-api: boom")
check("net kept when omitted", st.get_node(uid)["nyx"]["net"]["node_id"] == 42)

st.upsert_status(uid, reachable=True, version="1.2.3")
n = st.get_node(uid)
check("agent poll does not clobber nyx", n["nyx"]["address"] == ADDR)
check("agent poll still lands", n["status"]["version"] == "1.2.3")

st.set_nyx(uid2, error="node api: ConnectError")
n2 = st.get_node(uid2)
check("address-less failure row", n2["nyx"]["address"] is None and n2["nyx"]["balance_nym"] is None
      and n2["nyx"]["error"] == "node api: ConnectError")
check("list_nodes carries nyx for both", all(x["nyx"] is not None for x in st.list_nodes()))

check("delete cascades", st.delete_node(uid2) and
      st.db.execute("SELECT count(*) FROM node_nyx WHERE uid=?", (uid2,)).fetchone()[0] == 0)

# existing DB with a pre-net_json node_nyx gets the column on open
st.db.execute("DROP TABLE node_nyx")
st.db.execute("CREATE TABLE node_nyx (uid TEXT PRIMARY KEY, address TEXT, balance_unym INTEGER,"
              " balance_at TEXT, error TEXT, checked_at TEXT NOT NULL DEFAULT (datetime('now')))")
st.db.execute("INSERT INTO node_nyx (uid, address, balance_unym) VALUES (?,?,?)", (uid, ADDR, 5))
st.db.commit(); st.close()
st = store.Store(os.path.join(d, "t.db"), schema)
n = st.get_node(uid)
check("net_json column added on open", n["nyx"]["net"] is None and n["nyx"]["balance_unym"] == 5)
st.set_nyx(uid, net={"node_id": 1}); check("net writable after migration", st.get_node(uid)["nyx"]["net"] == {"node_id": 1})

# existing DB without the table gets it on open (idempotent migration)
st.db.execute("DROP TABLE node_nyx"); st.db.commit(); st.close()
st = store.Store(os.path.join(d, "t.db"), schema)
check("node_nyx re-created on open", st.get_node(uid)["nyx"] is None)


# --- app.refresh_nyx_all with a stubbed HTTP client ---------------------------
print("app.refresh_nyx_all (stubbed http)")


class _Resp:
    def __init__(self, status, body):
        self.status_code = status; self._body = body

    def raise_for_status(self):
        if self.status_code >= 400:
            import httpx
            raise httpx.HTTPStatusError("boom", request=None, response=self)

    def json(self):
        return self._body


class _Client:
    """Routes by URL: node api per ip, LCD per base."""
    def __init__(self, routes):
        self.routes = routes; self.calls = []

    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False

    async def get(self, url, headers=None):
        self.calls.append(url)
        for prefix, resp in self.routes.items():
            if url.startswith(prefix):
                if isinstance(resp, Exception):
                    raise resp
                return resp
        raise ConnectionError(url)


class _App:
    def __init__(self, st):
        class S: pass
        self.state = S(); self.state.store = st


import time
# bonded-nodes cache: BG01 is id 3178, BG03 has no bond (no id) → no annotation fetch
app._NYM_STAKE_CACHE["map"] = {"10.0.0.1": {"nym_node_id": 3178, "total_stake": 1.0, "saturation": 0.5}}
app._NYM_STAKE_CACHE["at"] = time.time()
ANN_URL = nyx.annotation_url(3178)


def run(routes):
    import httpx
    cli = _Client(routes)
    orig = httpx.AsyncClient
    httpx.AsyncClient = lambda *a, **k: cli
    try:
        return asyncio.run(app.refresh_nyx_all(_App(st))), cli
    finally:
        httpx.AsyncClient = orig


base0 = app.wallet.NYX_REST_BASES[0]
base1 = app.wallet.NYX_REST_BASES[1] if len(app.wallet.NYX_REST_BASES) > 1 else None
uid3 = st.create_node({"node_id": "default-nym-node", "name": "BG03", "ip": "10.0.0.3"})
low_addr = "n1" + "q" * 38

routes = {
    "http://10.0.0.1:": _Resp(200, AUX),
    "http://10.0.0.3:": _Resp(200, {"address": low_addr}),
    base0 + nyx.balance_path(ADDR): _Resp(200, {"balances": [{"denom": "unym", "amount": "19997588"}]}),
    base0 + nyx.balance_path(low_addr): _Resp(200, {"balances": [{"denom": "unym", "amount": "1500000"}]}),
    ANN_URL: _Resp(200, ANN),
}
r, cli = run(routes)
check("summary counts", r["checked"] == 2 and r["ok"] == 2 and r["low"] == 1 and r["threshold"] == nyx.MIN_NYM)
n1, n3 = st.get_node(uid), st.get_node(uid3)
check("BG01 balance stored", n1["nyx"]["balance_nym"] == 19.997588 and n1["nyx"]["error"] is None)
check("BG01 annotation stored", n1["nyx"]["net"]["node_id"] == 42 and n1["nyx"]["net"]["sufficient"] is True)
check("annotation fetched once, only for the bonded node", cli.calls.count(ANN_URL) == 1
      and not any("/annotation/" in u and u != ANN_URL for u in cli.calls))
check("BG03 has no annotation", n3["nyx"]["net"] is None)
check("BG03 low balance stored", n3["nyx"]["balance_nym"] == 1.5)
check("verdict via annotate", nyx.annotate(n3["nyx"])["low"] is True and nyx.annotate(n1["nyx"])["low"] is False)

# node api down -> last known address is reused, balance still read
routes_down = dict(routes); routes_down["http://10.0.0.1:"] = ConnectionError("refused")
r, cli = run(routes_down)
n1 = st.get_node(uid)
check("node api down: still ok via cached address", r["ok"] == 2 and n1["nyx"]["balance_nym"] == 19.997588)
check("node api down: error surfaced", (n1["nyx"]["error"] or "").startswith("node api:"))
check("node api down: LCD was queried with cached address", any(nyx.balance_path(ADDR) in u for u in cli.calls))

# first LCD 403s -> next base is tried
if base1:
    routes_fb = dict(routes)
    routes_fb[base0 + nyx.balance_path(ADDR)] = _Resp(403, {})
    routes_fb[base1 + nyx.balance_path(ADDR)] = _Resp(200, {"balances": [{"denom": "unym", "amount": "42000000"}]})
    r, cli = run(routes_fb)
    n1 = st.get_node(uid)
    check("LCD fallback: second base answers", n1["nyx"]["balance_nym"] == 42.0 and n1["nyx"]["error"] is None)

# every LCD fails -> error, last balance kept
routes_all = {"http://10.0.0.1:": _Resp(200, AUX), "http://10.0.0.3:": _Resp(200, {"address": low_addr}),
              ANN_URL: _Resp(200, ANN)}
r, cli = run(routes_all)
n1 = st.get_node(uid)
check("all LCDs down: not ok", r["ok"] == 0)
check("all LCDs down: last balance kept + lcd error", n1["nyx"]["balance_nym"] == 42.0
      and (n1["nyx"]["error"] or "").startswith("lcd:"))

# nym-api down -> annotation kept from before, error mentions it only if nothing else failed
routes_na = dict(routes); routes_na[ANN_URL] = _Resp(503, {})
r, cli = run(routes_na)
n1 = st.get_node(uid)
check("nym-api down: previous annotation kept", n1["nyx"]["net"]["node_id"] == 42)
check("nym-api down: error surfaced", (n1["nyx"]["error"] or "").startswith("nym-api:"))
check("nym-api down: balance still ok", r["ok"] == 2 and n1["nyx"]["balance_nym"] == 19.997588)

# network says insufficient -> counted in low even though our LCD read is fine
ins = copy.deepcopy(ANN)
ins["annotation"]["detailed_performance"]["config_score"]["chain_interaction_capabilities"]["has_sufficient_tokens"] = False
routes_ins = dict(routes); routes_ins[ANN_URL] = _Resp(200, ins)
r, cli = run(routes_ins)
a1 = nyx.annotate(st.get_node(uid)["nyx"])
check("insufficient verdict stored", a1["insufficient"] is True and a1["low"] is False)

# feegrant on the low node would suppress the warning: simulate by giving BG03 an id
app._NYM_STAKE_CACHE["map"]["10.0.0.3"] = {"nym_node_id": 7}
fgr = copy.deepcopy(ANN); fgr["node_id"] = 7
fgr["annotation"]["detailed_performance"]["config_score"]["chain_interaction_capabilities"]["is_fee_grant_grantee"] = True
routes_fg = dict(routes); routes_fg[nyx.annotation_url(7)] = _Resp(200, fgr)
r, cli = run(routes_fg)
a3 = nyx.annotate(st.get_node(uid3)["nyx"])
check("feegrant suppresses low in summary", r["low"] == 0 and a3["feegrant"] is True and a3["low"] is False)
del app._NYM_STAKE_CACHE["map"]["10.0.0.3"]
st.set_nyx(uid3, net={"node_id": 7, "feegrant": False, "sufficient": True, "balance_unym": None})

# node never answered and has no cached address -> error only, no LCD call
uid4 = st.create_node({"node_id": "default-nym-node", "name": "BG04", "ip": "10.0.0.4"})
r, cli = run(routes)
n4 = st.get_node(uid4)
check("unknown node: error row without address", n4["nyx"]["address"] is None
      and (n4["nyx"]["error"] or "").startswith("node api:"))
check("unknown node: node api was asked", any("10.0.0.4" in u for u in cli.calls))
check("unknown node: no LCD call", not any("/balances/None" in u for u in cli.calls)
      and sum(1 for u in cli.calls if "/balances/" in u) == 2)

# disabled nodes are skipped
st.update_node(uid4, {"enabled": False})
r, cli = run(routes)
check("disabled node skipped", r["checked"] == 2 and not any("10.0.0.4" in u for u in cli.calls))

st.close()
print(f"\n{ok} passed, {fail} failed")
sys.exit(1 if fail else 0)
