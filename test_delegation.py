"""Checks for the Telegram delegation-post draft (app._delegation_*).

Run directly: .venv/bin/python test_delegation.py
"""
import sys

import app

ok = fail = 0


def check(label, cond):
    global ok, fail
    if cond:
        ok += 1; print(f"  pass  {label}")
    else:
        fail += 1; print(f"  FAIL  {label}")


def node(name, ip, hostname=None, enabled=True):
    return {"name": name, "ip": ip, "hostname": hostname or "", "enabled": enabled}


def srec(sat, key="IDKEY", nid=7):
    return {"saturation": sat, "identity_key": key, "nym_node_id": nid}


# --- _delegation_split -------------------------------------------------------

nodes = [
    node("FI01", "1.1.1.1"),
    node("DE01", "2.2.2.2"),
    node("AT03", "3.3.3.3"),
    node("NL01", "4.4.4.4"),
    node("SE01", "5.5.5.5"),
    node("CH01", "6.6.6.6", enabled=False),
]
stake = {
    "1.1.1.1": srec(0.67, key="FIKEY", nid=101),
    "2.2.2.2": srec(1.23, key="DEKEY"),
    "3.3.3.3": srec(0.95),                 # between 90-threshold and 100
    "4.4.4.4": srec(1.00, key="NLKEY"),    # exactly 100 -> over
    "6.6.6.6": srec(0.10),                 # disabled -> ignored entirely
    # SE01 has no record -> no_data
}

under, over, no_data = app._delegation_split(nodes, stake, threshold=90.0)
check("under holds only nodes below threshold", [e["name"] for e in under] == ["FI01"])
check("over holds nodes at/over 100%", {e["name"] for e in over} == {"DE01", "NL01"})
check("between threshold and 100 is in neither list",
      all(e["name"] != "AT03" for e in under + over))
check("missing stake record lands in no_data", no_data == ["SE01"])
check("disabled node is skipped", all("CH01" not in (e["name"],) for e in under + over)
      and "CH01" not in no_data)

fi = under[0]
check("saturation is a whole rounded percent", fi["saturation_pct"] == 67
      and isinstance(fi["saturation_pct"], int))
check("identity key is passed through", fi["identity_key"] == "FIKEY")
check("nym node id is passed through", fi["nym_node_id"] == 101)
check("country resolved from the name prefix", fi["country"] == "Finland")
check("flag emoji built from cc", fi["flag"] == "🇫🇮")
check("description follows the post wording",
      fi["description"] == "EXIT Gateway Finland - FI01")
check("over list is sorted most-saturated first",
      [e["name"] for e in over] == ["DE01", "NL01"])

# threshold 100: the 95% node now has room
under2, over2, _ = app._delegation_split(nodes, stake, threshold=100.0)
check("threshold is configurable", {e["name"] for e in under2} == {"FI01", "AT03"})
check("under list is sorted least-saturated first",
      [e["name"] for e in under2] == ["FI01", "AT03"])

# a node that would DISPLAY as "(100% saturated)" (99.5%+) must never be
# advertised as having room — the split uses the same rounded percent
u4, o4, _ = app._delegation_split(
    [node("BE01", "8.8.8.8")], {"8.8.8.8": srec(0.996)}, threshold=100.0)
check("display-rounded 100% is excluded from under", u4 == [])
check("display-rounded 100% counts as over saturated",
      [e["name"] for e in o4] == ["BE01"])

# hostname fallback for nodes bonded under a DNS name
u3, _, nd3 = app._delegation_split(
    [node("HU01", "9.9.9.9", hostname="Nym-Exit-HU01.example.de")],
    {"nym-exit-hu01.example.de": srec(0.5, key="HUKEY")}, 100.0)
check("stake lookup falls back to the hostname", u3 and u3[0]["identity_key"] == "HUKEY")
check("hostname fallback leaves no_data empty", nd3 == [])

# --- _delegation_message (plain text) ----------------------------------------

EXPLORER = app.NYM_EXPLORER_NODE_URL

msg = app._delegation_message(under2)
check("header present", msg.startswith("💫 Hermes Stakepool - EXIT Gateways 💫"))
check("count spelled out", "Two of my well established" in msg)
check("plural wording", "EXIT Gateways have room" in msg)
check("under node line with flag + saturation",
      "🇫🇮 EXIT Gateway Finland - FI01 (67% saturated)" in msg)
check("explorer url on its own line under the node",
      f"FI01 (67% saturated)\n{EXPLORER}FIKEY" in msg)
check("no plain id key anywhere", "ID:" not in msg and "\nFIKEY" not in msg)
check("blank line between entries",
      f"{EXPLORER}FIKEY\n\n🇦🇹 " in msg)
check("no over-saturated block", "Over saturated nodes" not in msg
      and "❗" not in msg)
check("support chat kept", "💬 Support-Chat: https://t.me/hermespool" in msg)
check("twitter/X line dropped", "x.com" not in msg and "Twitter" not in msg)
check("signoff kept", msg.endswith("Cheers Wunderbaer"))

msg1 = app._delegation_message(under)
check("singular wording for one node", "EXIT Gateway has room" in msg1
      and "One of my" in msg1)

msg_nosat = app._delegation_message(under2, sat=False)
check("sat toggle removes the percent", "saturated)" not in msg_nosat)

# node without an identity key gets no url line
no_key = [dict(under2[0], identity_key=None)]
check("missing identity key emits no url line",
      EXPLORER not in app._delegation_message(no_key))

# --- _delegation_message (html, for the rich-text clipboard) ------------------

h = app._delegation_message(under2, html=True)
check("html links the gateway name to the explorer",
      f'<a href="{EXPLORER}FIKEY">EXIT Gateway Finland - FI01</a>' in h)
check("html keeps flag + saturation outside the link",
      f'🇫🇮 <a href="{EXPLORER}FIKEY">EXIT Gateway Finland - FI01</a>'
      " (67% saturated)" in h)
check("html paragraphs separated by double br", "<br><br>" in h
      and "\n" not in h)
check("html links the support chat",
      '<a href="https://t.me/hermespool">https://t.me/hermespool</a>' in h)
check("html has no over-saturated block", "❗" not in h)

evil = [dict(under2[0], description='EXIT <img src=x onerror=alert(1)> - FI01',
             identity_key='K"><script>')]
he = app._delegation_message(evil, html=True)
check("html escapes the description", "<img" not in he and "&lt;img" in he)
check("html escapes the url attribute", '"><script>' not in he)

hk = app._delegation_message(no_key, html=True)
check("html without identity key emits plain text, no link", "<a " not in hk.split("<br><br>")[3])

print(f"\n{ok} passed, {fail} failed")
sys.exit(1 if fail else 0)
