"""
test_wallet.py — wallet.py unit tests.

No real nym-cli, no real funds, no network: a fake nym-cli executable records its
argv and emits canned output, and the rewards REST is monkeypatched. Verifies
parsing, uNYM math, the encrypted store (real openssl round-trip, and backward
compat with a pass:-encrypted file), and the redeem/send command construction.
"""
import importlib
import json
import io
import os
import stat
import sys
import tempfile
import subprocess
from pathlib import Path

TMP = Path(tempfile.mkdtemp(prefix="wallet-test-"))
WDIR = TMP / "wallets"
WDIR.mkdir()
FAKE_LOG = TMP / "nymcli.log"

FAKE_NYM_CLI = TMP / "nym-cli"
FAKE_NYM_CLI.write_text(f"""#!/usr/bin/env python3
import sys, json
open({json.dumps(str(FAKE_LOG))}, "a").write(json.dumps(sys.argv[1:]) + "\\n")
a = sys.argv[1:]
addr = "n1" + "q"*40
if a[:2] == ["account", "pub-key"]:
    print("account pub-key")
    print("address: " + addr)
elif a[:2] == ["account", "balance"]:
    print("Account " + a[2])
    print("144.974769 nym")
elif a[:5] == ["mixnet", "operators", "nymnode", "rewards", "claim"]:
    print("tx broadcast: hash ABC123 claimed rewards")
elif a[:2] == ["account", "send"]:
    print("tx broadcast: hash DEF456 sent " + a[3] + " unym to " + a[2])
else:
    sys.stderr.write("unknown cmd\\n"); sys.exit(2)
""")
os.chmod(FAKE_NYM_CLI, FAKE_NYM_CLI.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

os.environ["MAESTRO_WALLET_DIR"] = str(WDIR)
os.environ["MAESTRO_NYM_CLI"] = str(FAKE_NYM_CLI)

sys.path.insert(0, str(Path(__file__).parent))
import wallet
importlib.reload(wallet)

PASS = "hunter2"
MNEMONIC = "abandon ability about above absent absorb abstract absurd abuse access accident account"

_passed = 0
_failed = 0


def check(name, cond, extra=""):
    global _passed, _failed
    if cond:
        _passed += 1
    else:
        _failed += 1
        print(f"  FAIL: {name} {extra}")


def read_log():
    if not FAKE_LOG.exists():
        return []
    return [json.loads(l) for l in FAKE_LOG.read_text().splitlines() if l.strip()]


# ---- store: add / list / decrypt round-trip --------------------------------
wallet.add_wallet("AT01", MNEMONIC, PASS)
wallet.add_wallet("CH01", MNEMONIC, PASS)
check("list_wallets", wallet.list_wallets() == ["AT01", "CH01"], wallet.list_wallets())
check("wallet_exists", wallet.wallet_exists("AT01") and not wallet.wallet_exists("ZZ99"))
check("decrypt round-trip", wallet.decrypt_mnemonic("AT01", PASS) == MNEMONIC)

try:
    wallet.decrypt_mnemonic("AT01", "wrongpass")
    check("wrong password raises", False)
except wallet.WalletError:
    check("wrong password raises", True)

try:
    wallet.add_wallet("AT01", MNEMONIC, PASS)  # duplicate
    check("duplicate add raises", False)
except wallet.WalletError:
    check("duplicate add raises", True)

# backward compat: a file encrypted the OLD way (openssl -pass pass:) must decrypt
old_enc = WDIR / "OLD01.enc"
subprocess.run(["openssl", "enc", "-aes-256-cbc", "-salt", "-pbkdf2", "-iter", "100000",
                "-out", str(old_enc), "-pass", f"pass:{PASS}"],
               input=MNEMONIC + "\n", text=True, check=True)
check("old-format .enc appears in list", "OLD01" in wallet.list_wallets())
check("old-format .enc decrypts", wallet.decrypt_mnemonic("OLD01", PASS) == MNEMONIC)

# ---- nym-cli backed ops ----------------------------------------------------
check("have_nym_cli", wallet.have_nym_cli())
addr = wallet.derive_address(MNEMONIC)
check("derive_address parses n1", wallet.validate_address(addr), addr)
check("balance parse", wallet.get_balance(addr) == 144.974769, wallet.get_balance(addr))

# rewards REST — first, exercise the REAL failover logic with a fake urlopen:
# base #1 returns 403, base #2 returns valid JSON -> must recover and parse, and
# the request must carry our non-default User-Agent (the fix for the 403).
import urllib.request as _urlreq
import urllib.error as _urlerr

_seen_ua = []
_orig_bases = list(wallet.NYX_REST_BASES)
wallet.NYX_REST_BASES = ["https://blocked.example", "https://good.example"]

class _FakeResp:
    def __init__(self, body): self._b = body.encode()
    def read(self): return self._b
    def __enter__(self): return self
    def __exit__(self, *a): return False

def _fake_urlopen(req, timeout=0):
    _seen_ua.append(req.get_header("User-agent"))
    if "blocked.example" in req.full_url:
        raise _urlerr.HTTPError(req.full_url, 403, "Forbidden", {}, None)
    return _FakeResp(json.dumps({"data": {"amount_earned": {"amount": "1500000", "denom": "unym"}}}))

_urlreq.urlopen = _fake_urlopen
pr = wallet.pending_rewards("n1" + "a"*40)
check("rewards failover recovers to base #2", pr == {"unym": 1500000, "nym": 1.5}, pr)
check("rewards sent non-default UA", _seen_ua and _seen_ua[-1] and "Python-urllib" not in _seen_ua[-1], _seen_ua)

# all bases fail -> WalletError naming the last host
def _all_fail(req, timeout=0):
    raise _urlerr.HTTPError(req.full_url, 403, "Forbidden", {}, None)
_urlreq.urlopen = _all_fail
try:
    wallet.pending_rewards("n1" + "a"*40)
    check("rewards all-fail raises", False)
except wallet.WalletError as e:
    check("rewards all-fail raises w/ host", "good.example" in str(e), str(e))

# empty / no-reward response parses to zero
def _zero(req, timeout=0):
    return _FakeResp(json.dumps({"data": {"amount_earned": None}}))
_urlreq.urlopen = _zero
check("rewards zero parses", wallet.pending_rewards("n1" + "a"*40) == {"unym": 0, "nym": 0.0})

wallet.NYX_REST_BASES = _orig_bases

# rewards REST — monkeypatch the network call for the higher-level query tests
def fake_rewards(address, timeout=15):
    return {"unym": 2500000, "nym": 2.5}
wallet.pending_rewards = fake_rewards  # type: ignore
check("rewards via patched fn", wallet.pending_rewards(addr)["nym"] == 2.5)

# ---- unym math + address validation ---------------------------------------
check("nym_to_unym", wallet.nym_to_unym(12.34) == 12340000, wallet.nym_to_unym(12.34))
check("nym_to_unym rounds", wallet.nym_to_unym(12.3456789) == 12345679, wallet.nym_to_unym(12.3456789))
check("unym_to_nym", wallet.unym_to_nym(2500000) == 2.5)
check("addr ok", wallet.validate_address("n1" + "a"*40))
check("addr bad prefix", not wallet.validate_address("cosmos1" + "a"*40))
check("addr too short", not wallet.validate_address("n1abc"))

# ---- redeem: command construction + confirmation-shaped result -------------
FAKE_LOG.unlink(missing_ok=True)
res = wallet.redeem_rewards(["AT01", "CH01"], PASS)
check("redeem two wallets ok", all(r["ok"] for r in res), res)
log = read_log()
claim_calls = [c for c in log if c[:5] == ["mixnet", "operators", "nymnode", "rewards", "claim"]]
check("redeem issued 2 claim calls", len(claim_calls) == 2, len(claim_calls))
check("redeem passes --mnemonic", all("--mnemonic" in c for c in claim_calls))
check("redeem records reward amount", res[0].get("rewards_nym") == 2.5)

# redeem with wrong password fails that wallet, doesn't crash batch
res2 = wallet.redeem_rewards(["AT01"], "nope")
check("redeem wrong pass -> not ok + error", (not res2[0]["ok"]) and "error" in res2[0])

# ---- send: exact amount + send_max floor ----------------------------------
FAKE_LOG.unlink(missing_ok=True)
r = wallet.send_from("AT01", PASS, "n1" + "b"*40, amount_nym=10.5)
check("send exact ok", r["ok"], r)
check("send exact amount_unym", r["amount_unym"] == 10500000, r.get("amount_unym"))
sends = [c for c in read_log() if c[:2] == ["account", "send"]]
check("send issued 1 send call", len(sends) == 1)
check("send argv has uNYM integer", sends[0][3] == "10500000", sends[0] if sends else None)
check("send argv receiver", sends[0][2] == "n1" + "b"*40)

FAKE_LOG.unlink(missing_ok=True)
r = wallet.send_from("AT01", PASS, "n1" + "b"*40, send_max=True)
# balance is 144.974769 -> floor 144 whole NYM -> 144000000 uNYM
check("send_max floors to whole NYM", r["amount_nym"] == 144 and r["amount_unym"] == 144000000, r)

# invalid receiver rejected before any nym-cli call
FAKE_LOG.unlink(missing_ok=True)
r = wallet.send_from("AT01", PASS, "bogus", amount_nym=1)
check("send bad receiver -> error", (not r["ok"]) and "error" in r)
check("send bad receiver made no nym-cli call", len(read_log()) == 0)

# ---- CoinTracking rewards CSV (one dated file per withdrawal run) ----------
import csv as _csv
import datetime as _dt
when = _dt.datetime(2026, 7, 1, 13, 34, 27)
results = [
    {"name": "AT01", "ok": True, "rewards_unym": 444503100, "tx": "a"*64},
    {"name": "CH01", "ok": True, "rewards_unym": 827118687},
    {"name": "ZZ00", "ok": True, "rewards_unym": 0},        # zero -> no line
    {"name": "YY88", "ok": False, "error": "decrypt failed"},  # failed -> no line
]
info = wallet.write_withdrawal_csv(results, when=when)
check("session filename dated", info["filename"] == "20260701_nym_rewards.csv", info)
check("session line count = successful non-zero", info["count"] == 2, info)
check("session total exact", info["total_nym"] == "1271.621787", info)  # 444.5031 + 827.118687

text = wallet.read_rewards_file(info["filename"])
rows = list(_csv.reader(io.StringIO(text)))
check("file has header + 2 rows", len(rows) == 3, len(rows))
check("file header 14 cols", rows[0] == wallet.CT_HEADER, rows[0])
check("row currency NYM2", rows[1][2] == "NYM2", rows[1])
check("row type Masternode", rows[1][0] == "Masternode")
check("row amount exact", rows[1][1] == "444.5031", rows[1][1])
check("row date DD.MM.YYYY", rows[1][13] == "01.07.2026 13:34:27", rows[1][13])
check("row tx in comment", "a"*64 in rows[1][9], rows[1][9])
check("row trade id", rows[1][10] == "nym-withdraw-AT01-" + str(int(when.timestamp())))

# same-day repeats -> _v2, _v3
info2 = wallet.write_withdrawal_csv(results, when=when)
check("second same-day is _v2", info2["filename"] == "20260701_nym_rewards_v2.csv", info2)
info3 = wallet.write_withdrawal_csv(results, when=when)
check("third same-day is _v3", info3["filename"] == "20260701_nym_rewards_v3.csv", info3)

# a different day starts fresh (no version)
info_d2 = wallet.write_withdrawal_csv(results, when=_dt.datetime(2026, 7, 2, 9, 0, 0))
check("next day no version", info_d2["filename"] == "20260702_nym_rewards.csv", info_d2)

# listing (newest filename first) + summary across files
files = wallet.list_rewards_files()
check("lists 4 files", len(files) == 4, [f["filename"] for f in files])
check("newest first", files[0]["filename"] == "20260702_nym_rewards.csv", files[0]["filename"])
summ = wallet.rewards_summary()
check("summary file count", summ["file_count"] == 4, summ)
check("summary entries", summ["entries"] == 8, summ)          # 2 lines * 4 files
check("summary total", summ["total_nym"] == "5086.487148", summ)  # 1271.621787 * 4

# nothing to record -> no file
none_info = wallet.write_withdrawal_csv([{"name": "X", "ok": True, "rewards_unym": 0}])
check("no non-zero -> no file written", none_info is None, none_info)

# path-traversal guard on the download reader
for bad in ["../../etc/passwd", "foo.csv", "20260701_nym_rewards.csv/../x", "20260701_nym_rewards.txt"]:
    try:
        wallet.read_rewards_file(bad)
        check("reject bad filename: " + bad, False)
    except wallet.WalletError:
        check("reject bad filename: " + bad, True)

# ---- delete ----------------------------------------------------------------
wallet.delete_wallet("OLD01")
check("delete removes from list", "OLD01" not in wallet.list_wallets())
check("delete removes file", not (WDIR / "OLD01.enc").exists())


# --- O3: wallet-name path traversal is rejected on the read/delete paths --------
def _rejects(fn):
    try:
        fn()
    except wallet.WalletError:
        return True
    except Exception:
        return False
    return False

check("decrypt_mnemonic rejects a traversal wallet name",
      _rejects(lambda: wallet.decrypt_mnemonic("../../etc/passwd", "pw")))
check("delete_wallet rejects a traversal wallet name",
      _rejects(lambda: wallet.delete_wallet("../../x")))
check("valid names accepted, separators/dotfiles rejected",
      wallet._valid_wallet_name("ok_wallet")
      and not wallet._valid_wallet_name("a/b")
      and not wallet._valid_wallet_name(".hidden"))

print(f"\n{_passed} passed, {_failed} failed")
sys.exit(1 if _failed else 0)
