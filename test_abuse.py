"""Tests for the abuse-reply feature.

Covers the pure drafting module (abuse.py) — case-id/IP extraction, complainant
matching, template rendering, case-id swap on reuse — and the store side
(abuse_cases CRUD, config key/value for the template) against a tmp DB, so
nothing touches the real maestro.db.

Run: python3 test_abuse.py
"""
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import abuse  # noqa: E402
from store import Store  # noqa: E402

ok = fail = 0


def check(label, cond):
    global ok, fail
    if cond:
        ok += 1; print(f"  pass  {label}")
    else:
        fail += 1; print(f"  FAIL  {label}")


# -- case-id extraction --------------------------------------------------------
print("case-id extraction")
check("labelled 'Case ID <hex>'",
      abuse.extract_case_id("... regarding Case ID 7c188c8c3e9732e89c23 we ...")
      == "7c188c8c3e9732e89c23")
check("'Case #' with number",
      abuse.extract_case_id("Case #4711-B closed") == "4711-B")
check("'Ticket#' glued",
      abuse.extract_case_id("Ticket#ABC-12345 opened") == "ABC-12345")
check("'AbuseID:'",
      abuse.extract_case_id("AbuseID: 123456-789") == "123456-789")
check("'Ref:'",
      abuse.extract_case_id("Ref: 2026-08-0001") == "2026-08-0001")
check("bracketed subject ref",
      abuse.extract_case_id("Subject: [P-2026-99887] infringement") == "P-2026-99887")
check("bare long hex as fallback",
      abuse.extract_case_id("token deadbeefcafe1234 in body") == "deadbeefcafe1234")
check("'in case you need' does not match (no digit)",
      abuse.extract_case_id("in case you need anything, write us") == "")
check("labelled id wins over earlier bare hex",
      abuse.extract_case_id("hash deadbeefcafe1234, Case ID 99-ZZ-1") == "99-ZZ-1")
check("trailing punctuation stripped",
      abuse.extract_case_id("Case ID 7c188c8c3e9732e89c23.") == "7c188c8c3e9732e89c23")
check("empty input", abuse.extract_case_id("") == "")

# -- IP extraction -------------------------------------------------------------
print("ip extraction")
ips = abuse.extract_ips("seen from 203.0.113.9 and 10.0.0.5, also 203.0.113.9 again")
check("dedupes and keeps valid IPs", ips == ["203.0.113.9", "10.0.0.5"])
check("public sorts before private", ips[0] == "203.0.113.9")
check("octet >255 rejected", abuse.extract_ips("bogus 999.1.1.300") == [])
check("ipv6 extracted",
      "2001:db8::1" in abuse.extract_ips("addr 2001:db8:0:0:0:0:0:1 port 443"))
check("version strings don't count as IPs", abuse.extract_ips("nym-node 1.2.3") == [])

# -- complainant matching ------------------------------------------------------
print("complainant matching")
known = ["Paramount", "BREIN", "Sony Music"]
check("case-insensitive substring match",
      abuse.guess_complainant("on behalf of PARAMOUNT Global", known) == "Paramount")
check("longest name wins",
      abuse.guess_complainant("Sony Music Entertainment notice", ["Sony", "Sony Music"])
      == "Sony Music")
check("no match -> empty", abuse.guess_complainant("someone else", known) == "")

# -- provider matching / salutation -------------------------------------------
print("provider matching / salutation")
provs = ["OVH", "ATW", "netcup"]
check("provider matched from report head",
      abuse.guess_provider("ATW Internet Kft.\n\nDear Sir or Madam:\n...", provs) == "ATW")
check("provider no match -> empty", abuse.guess_provider("Hetzner Online", provs) == "")
check("swap 'Dear Sir or Madam,' -> new addressee",
      abuse.swap_salutation("Dear Sir or Madam,\n\nbody", "ATW")
      == "Dear ATW,\n\nbody")
check("swap legacy 'Hello,' greeting",
      abuse.swap_salutation("Hello,\n\nbody", "OVH") == "Dear OVH,\n\nbody")
check("only first salutation line touched",
      abuse.swap_salutation("Dear OVH,\n\nsay hello to Dear Leader\nDear X,", "ATW")
      .startswith("Dear ATW,\n\nsay hello"))
check("mid-line 'dear' untouched",
      abuse.swap_salutation("my dear friend wrote\n\nbody", "ATW")
      == "my dear friend wrote\n\nbody")
check("no addressee -> unchanged",
      abuse.swap_salutation("Hello,\n\nbody", "") == "Hello,\n\nbody")

# -- template rendering --------------------------------------------------------
print("template rendering")
r = abuse.render_reply(abuse.DEFAULT_TEMPLATE, "7c188c", "203.0.113.9", addressee="ATW")
check("addressee filled in", r.startswith("Dear ATW,"))
check("case id filled in", "Case ID 7c188c" in r)
check("ip filled in", "203.0.113.9" in r)
r_flat = " ".join(r.split())   # canon check ignores template line wrapping
for phrase in ("mere conduit", "do not select or modify the transmitted content",
               "operated by Hermes Blockchain Ventures",
               "complies with German and EU law",
               "no client data", "no logs", "rate limiting",
               "two-hop dVPN", "at least two separate hops",
               "route is selected by the client",
               "typically run by different, unrelated parties",
               "seriously", abuse.EXIT_POLICY_URL):
    check(f"canon point present: {phrase[:40]}", phrase in r_flat)
r2 = abuse.render_reply(abuse.DEFAULT_TEMPLATE, "", "")
check("missing addressee -> Dear Sir or Madam", r2.startswith("Dear Sir or Madam,"))
check("missing case id -> visible placeholder", abuse.CASE_ID_PLACEHOLDER in r2)
check("missing ip degrades readably", "listed in your report" in r2)
check("no unresolved {placeholders} left",
      "{case_id}" not in r and "{ip}" not in r and "{addressee}" not in r)

# -- case-id swap (the reuse path) --------------------------------------------
print("case-id swap")
old = abuse.render_reply(abuse.DEFAULT_TEMPLATE, "OLD-111", "203.0.113.9")
swapped = abuse.swap_case_id(old, "OLD-111", "NEW-222")
check("old id fully replaced", "OLD-111" not in swapped and "Case ID NEW-222" in swapped)
check("body otherwise identical",
      swapped.replace("NEW-222", "OLD-111") == old)
check("placeholder reply gets the id",
      "NEW-1" in abuse.swap_case_id(f"re {abuse.CASE_ID_PLACEHOLDER} ok", "", "NEW-1"))
noid = abuse.swap_case_id("a reply without any id", "GONE", "NEW-3")
check("reply without id gets one prefixed", noid.startswith("Case ID: NEW-3"))

# -- store: abuse_cases CRUD + config -----------------------------------------
print("store")
schema = (ROOT / "schema.sql").read_text()
with tempfile.TemporaryDirectory() as td:
    db = os.path.join(td, "t.db")
    st = Store(db, schema)
    a = st.abuse_create({"case_id": "AAA-1", "complainant": "Paramount",
                         "provider": "OVH", "node_name": "AT01",
                         "ip": "203.0.113.9", "report_text": "rep A",
                         "reply_text": "reply A with AAA-1"})
    b = st.abuse_create({"case_id": "BBB-2", "complainant": "Paramount",
                         "provider": "ATW", "report_text": "rep B",
                         "reply_text": "reply B with BBB-2"})
    c = st.abuse_create({"case_id": "CCC-3", "complainant": "BREIN",
                         "provider": "OVH", "reply_text": "reply C"})
    rows = st.abuse_list()
    check("list newest first", [r["id"] for r in rows] == [c, b, a])
    check("q filter matches complainant",
          {r["id"] for r in st.abuse_list(q="Param")} == {a, b})
    check("q filter matches ip", [r["id"] for r in st.abuse_list(q="203.0.113")] == [a])
    latest = st.abuse_latest_for("paramount")
    check("latest_for is newest + case-insensitive",
          latest and latest["id"] == b and latest["case_id"] == "BBB-2")
    check("latest_for unknown -> None", st.abuse_latest_for("Nobody") is None)
    check("distinct complainants", st.abuse_distinct("complainant") == ["BREIN", "Paramount"])
    check("distinct providers", st.abuse_distinct("provider") == ["ATW", "OVH"])
    got = st.abuse_get(a)
    check("get returns full row", got["report_text"] == "rep A" and got["created_at"])
    check("delete works", st.abuse_delete(c) and st.abuse_get(c) is None)
    check("delete missing -> False", st.abuse_delete(9999) is False)
    # config (template storage)
    check("config default", st.get_config("abuse_reply_template", None) is None)
    st.set_config("abuse_reply_template", "custom {case_id}")
    check("config roundtrip", st.get_config("abuse_reply_template") == "custom {case_id}")
    st.set_config("abuse_reply_template", None)
    check("config None deletes", st.get_config("abuse_reply_template", "d") == "d")
    # migration path: an older DB without the table gets it via _ensure_columns
    st.db.execute("DROP TABLE abuse_cases")
    st.db.commit()
    st.close()
    st2 = Store(db, schema)
    check("existing DB grows abuse_cases table on open",
          st2.abuse_create({"complainant": "X", "reply_text": "r"}) >= 1)
    st2.close()

print(f"\n{ok} passed, {fail} failed")
sys.exit(1 if fail else 0)
