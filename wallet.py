"""
wallet.py — orchestrator-side Nym wallet operations for nym maestro.

DESIGN / SECURITY
-----------------
Wallet operations run HERE, on the operator's machine (the same host as app.py),
never on the exit-node agents. Mnemonics live only in the local encrypted store
(~/.nym_wallets, reused verbatim from the old nym_node_manager CLI) and are
decrypted in-memory for the duration of a single request. Claiming rewards and
sending funds don't require the key to sit on a node: nym-cli signs locally and
broadcasts to the Nyx chain. Keeping keys off the internet-facing nodes is the
whole point — a compromised exit node must never be able to spend operator funds.

Secrets never touch a command line: the wallet password is handed to openssl via
an environment variable (env:VAR), not argv, so it isn't visible in `ps`. The
mnemonic likewise reaches nym-cli via the MNEMONIC env var, never argv, so the
spending key isn't exposed in `ps` / /proc either; those invocations are brief
and local to the operator's machine.

Nothing in this module logs a mnemonic or a password.

The exact command surface mirrors the proven old CLI:
  address : MNEMONIC=<m> nym-cli account pub-key            -> parse n1...
  balance : nym-cli account balance <addr>                  -> parse "N.NNNNNN nym"
  rewards : Nyx cosmwasm smart-query get_pending_operator_reward (read-only REST)
  redeem  : MNEMONIC=<m> nym-cli mixnet operators nymnode rewards claim
  send    : MNEMONIC=<m> nym-cli account send <receiver> <amount_uNYM>
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import urllib.request
import urllib.error
import csv
import io
import datetime
from decimal import Decimal
from pathlib import Path

# ---- configuration (env-overridable) --------------------------------------
WALLET_DIR = Path(os.environ.get("MAESTRO_WALLET_DIR",
                                 str(Path.home() / ".nym_wallets"))).expanduser()
WALLET_LIST = WALLET_DIR / "wallet_list.txt"
NYM_CLI = os.environ.get("MAESTRO_NYM_CLI", "nym-cli")

# CoinTracking rewards export: one CSV per withdrawal run, named
# <YYYYMMDD>_nym_rewards.csv (a same-day repeat becomes _v2, _v3, …), each with
# one line per wallet withdrawn. Format matches the old nym_node_manager export
# so it lands on the same asset: Type "Masternode", currency "NYM2", DD.MM.YYYY.
REWARDS_DIR = Path(os.environ.get(
    "MAESTRO_REWARDS_DIR", str(WALLET_DIR / "rewards"))).expanduser()
CT_TYPE = os.environ.get("MAESTRO_CT_TYPE", "Masternode")
CT_CURRENCY = os.environ.get("MAESTRO_CT_CURRENCY", "NYM2")
CT_HEADER = ["Type", "Buy", "Cur.", "Sell", "Cur.", "Fee", "Cur.", "Exchange",
             "Group", "Comment", "Trade ID", "Imported From", "Add Date", "Date"]
# session filenames we're willing to serve back (guards the download endpoint)
REWARDS_FILE_RE = re.compile(r"^\d{8}_nym_rewards(_v\d+)?\.csv$")
# Nyx cosmwasm REST bases for the pending-operator-reward smart query, tried in
# order until one answers. cosmos.directory is a round-robin proxy whose backend
# pool intermittently 403s, so we prefer dedicated LCDs and keep it only as a last
# resort. Override with MAESTRO_NYX_REST (comma/space separated, first wins).
_DEFAULT_NYX_REST = (
    "https://nym-api.polkachu.com,"
    "https://api.nyx.nodes.guru,"
    "https://api.nymtech.net,"
    "https://rest.cosmos.directory/nyx"
)
NYX_REST_BASES = [b.strip().rstrip("/") for b in
                  re.split(r"[,\s]+", os.environ.get("MAESTRO_NYX_REST", _DEFAULT_NYX_REST))
                  if b.strip()]
# a non-default User-Agent: the stdlib "Python-urllib/x" UA is WAF-blocked (403)
# by several of these gateways; a curl-like UA sails through, as the old CLI did.
REST_UA = os.environ.get("MAESTRO_REST_UA", "nym-maestro/1.0 (+curl-compatible)")
MIXNET_CONTRACT = os.environ.get(
    "MAESTRO_MIXNET_CONTRACT",
    "n17srjznxl9dvzdkpwpw24gg668wc73val88a6m5ajg6ankwvz9wtst0cznr")

UNYM = 1_000_000                      # 1 NYM = 1e6 uNYM
ADDR_RE = re.compile(r"^n1[a-z0-9]{38,50}$")
_ADDR_EXTRACT = re.compile(r"n1[0-9a-z]{38,}")

# subprocess timeouts (seconds) — broadcasts can be slow, reads are quick
T_QUICK = 20
T_TX = 150


class WalletError(Exception):
    """User-facing wallet error (safe to show; never contains secrets)."""


# ---- helpers ---------------------------------------------------------------
def nym_cli_path() -> str | None:
    return shutil.which(NYM_CLI) or (NYM_CLI if os.path.isabs(NYM_CLI) and os.path.exists(NYM_CLI) else None)


def have_nym_cli() -> bool:
    return nym_cli_path() is not None


def _run(cmd: list[str], timeout: int, env_extra: dict | None = None,
         stdin: str | None = None) -> tuple[int, str, str]:
    env = None
    if env_extra:
        env = os.environ.copy()
        env.update(env_extra)
    try:
        # capture bytes and decode leniently: openssl emits binary garbage on a
        # wrong password, which would crash a text-mode decode.
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, env=env,
                           input=(stdin.encode() if stdin is not None else None))
        out = (p.stdout or b"").decode("utf-8", "replace")
        err = (p.stderr or b"").decode("utf-8", "replace")
        return p.returncode, out, err
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s"
    except FileNotFoundError as e:
        return 127, "", str(e)


def validate_address(addr: str) -> bool:
    return bool(addr and ADDR_RE.match(addr.strip()))


def nym_to_unym(amount_nym: float) -> int:
    # round to the nearest uNYM to avoid float drift (e.g. 12.34 -> 12340000)
    return int(round(float(amount_nym) * UNYM))


def unym_to_nym(amount_unym) -> float:
    return int(amount_unym) / UNYM


# ---- encrypted store (compatible with old nym_node_manager .enc files) ------
def _ensure_dir():
    WALLET_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(WALLET_DIR, 0o700)
    except OSError:
        pass
    if not WALLET_LIST.exists():
        WALLET_LIST.touch()
        try:
            os.chmod(WALLET_LIST, 0o600)
        except OSError:
            pass


def list_wallets() -> list[str]:
    """Wallet names, sorted. Union of wallet_list.txt and any *.enc on disk so a
    hand-dropped .enc still shows up."""
    names: set[str] = set()
    if WALLET_LIST.exists():
        for line in WALLET_LIST.read_text().splitlines():
            n = line.strip()
            if n:
                names.add(n)
    if WALLET_DIR.exists():
        for p in WALLET_DIR.glob("*.enc"):
            names.add(p.stem)
    return sorted(names)


def wallet_exists(name: str) -> bool:
    return (WALLET_DIR / f"{name}.enc").exists()


def _register_name(name: str):
    _ensure_dir()
    existing = set()
    if WALLET_LIST.exists():
        existing = {l.strip() for l in WALLET_LIST.read_text().splitlines() if l.strip()}
    if name not in existing:
        with WALLET_LIST.open("a") as f:
            f.write(name + "\n")


def decrypt_mnemonic(name: str, password: str) -> str:
    """Return the decrypted mnemonic, or raise WalletError. Password is passed to
    openssl via env (never argv)."""
    enc = WALLET_DIR / f"{name}.enc"
    if not enc.exists():
        raise WalletError(f"wallet '{name}' not found")
    rc, out, err = _run(
        ["openssl", "enc", "-aes-256-cbc", "-d", "-pbkdf2", "-iter", "100000",
         "-in", str(enc), "-pass", "env:MAESTRO_WPASS"],
        T_QUICK, env_extra={"MAESTRO_WPASS": password})
    mnemonic = out.strip()
    if rc != 0 or not mnemonic:
        raise WalletError("decryption failed (wrong password?)")
    return mnemonic


def add_wallet(name: str, mnemonic: str, password: str, overwrite: bool = False) -> None:
    name = name.strip()
    if not name or "/" in name or name.startswith("."):
        raise WalletError("invalid wallet name")
    if not mnemonic.strip():
        raise WalletError("empty mnemonic")
    _ensure_dir()
    enc = WALLET_DIR / f"{name}.enc"
    if enc.exists() and not overwrite:
        raise WalletError(f"wallet '{name}' already exists")
    rc, out, err = _run(
        ["openssl", "enc", "-aes-256-cbc", "-salt", "-pbkdf2", "-iter", "100000",
         "-out", str(enc), "-pass", "env:MAESTRO_WPASS"],
        T_QUICK, env_extra={"MAESTRO_WPASS": password}, stdin=mnemonic.strip() + "\n")
    if rc != 0:
        raise WalletError("encryption failed")
    try:
        os.chmod(enc, 0o600)
    except OSError:
        pass
    _register_name(name)


def delete_wallet(name: str) -> None:
    enc = WALLET_DIR / f"{name}.enc"
    if enc.exists():
        enc.unlink()
    if WALLET_LIST.exists():
        kept = [l for l in WALLET_LIST.read_text().splitlines() if l.strip() and l.strip() != name]
        WALLET_LIST.write_text(("\n".join(kept) + "\n") if kept else "")


# ---- nym-cli backed operations --------------------------------------------
def derive_address(mnemonic: str) -> str:
    if not have_nym_cli():
        raise WalletError("nym-cli not found in PATH")
    # Pass the mnemonic via the environment, not argv: argv is world-readable via
    # ps / /proc/<pid>/cmdline, which would briefly expose the spending key to any
    # local process. nym-cli reads MNEMONIC as a fallback for the --mnemonic flag.
    rc, out, err = _run([NYM_CLI, "account", "pub-key"], T_QUICK,
                        env_extra={"MNEMONIC": mnemonic})
    blob = (out + "\n" + err)
    m = _ADDR_EXTRACT.search(blob)
    if not m:
        raise WalletError("could not derive address from mnemonic")
    return m.group(0)


def get_balance(address: str) -> float:
    """Balance in NYM. Parses nym-cli's 'N.NNNNNN nym' output; 0.0 if none."""
    if not have_nym_cli():
        raise WalletError("nym-cli not found in PATH")
    rc, out, err = _run([NYM_CLI, "account", "balance", address], T_QUICK)
    blob = out + "\n" + err
    m = re.search(r"([0-9]+\.[0-9]+)\s*nym", blob)
    if not m:
        m = re.search(r"([0-9]+)\s*nym", blob)
    if not m:
        # surface a real failure rather than silently reporting 0
        if rc != 0:
            raise WalletError((err or out or "balance query failed").strip().splitlines()[-1][:200])
        return 0.0
    return float(m.group(1))


def pending_rewards(address: str, timeout: int = 12) -> dict:
    """Read-only pending operator reward via the Nyx cosmwasm smart-query.
    Tries each REST base in turn with a non-default User-Agent; returns
    {'unym': int, 'nym': float} (0 if none). Raises WalletError with the last
    endpoint error only if every base fails."""
    query = json.dumps({"get_pending_operator_reward": {"address": address}},
                       separators=(",", ":")).encode()
    b64 = base64.b64encode(query).decode()
    path = f"/cosmwasm/wasm/v1/contract/{MIXNET_CONTRACT}/smart/{b64}"
    headers = {"Accept": "application/json", "User-Agent": REST_UA}
    last_err = "no endpoints configured"
    for base in NYX_REST_BASES:
        url = base + path
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            last_err = f"HTTP {e.code} @ {_host(base)}"
            continue
        except Exception as e:
            last_err = f"{type(e).__name__} @ {_host(base)}"
            continue
        amt = (((data or {}).get("data") or {}).get("amount_earned") or {}).get("amount")
        if amt in (None, "", "null"):
            return {"unym": 0, "nym": 0.0}
        try:
            unym = int(amt)
        except (TypeError, ValueError):
            return {"unym": 0, "nym": 0.0}
        return {"unym": unym, "nym": unym_to_nym(unym)}
    raise WalletError(f"rewards query failed ({last_err})")


def _host(url: str) -> str:
    m = re.match(r"https?://([^/]+)", url)
    return m.group(1) if m else url


def claim_rewards(mnemonic: str) -> dict:
    """Redeem (claim) pending operator rewards. Irreversible on success."""
    if not have_nym_cli():
        raise WalletError("nym-cli not found in PATH")
    rc, out, err = _run(
        [NYM_CLI, "mixnet", "operators", "nymnode", "rewards", "claim"],
        T_TX, env_extra={"MNEMONIC": mnemonic})
    ok = rc == 0
    return {"ok": ok, "output": _tail(out if ok else (err or out))}


def send(receiver: str, amount_unym: int, mnemonic: str) -> dict:
    """Send amount_unym uNYM to receiver. Irreversible on success."""
    if not have_nym_cli():
        raise WalletError("nym-cli not found in PATH")
    if not validate_address(receiver):
        raise WalletError("invalid receiver address")
    if int(amount_unym) <= 0:
        raise WalletError("amount must be positive")
    rc, out, err = _run(
        [NYM_CLI, "account", "send", receiver, str(int(amount_unym))],
        T_TX, env_extra={"MNEMONIC": mnemonic})
    ok = rc == 0
    return {"ok": ok, "output": _tail(out if ok else (err or out))}


def nym_price_usd() -> float | None:
    """Best-effort spot price for USD display. None on failure — never fatal."""
    sources = [
        ("https://api.coingecko.com/api/v3/simple/price?ids=nym&vs_currencies=usd",
         lambda d: float(d["nym"]["usd"])),
        ("https://api.coinpaprika.com/v1/tickers/nym-nym",
         lambda d: float(d["quotes"]["USD"]["price"])),
        ("https://api.binance.com/api/v3/ticker/price?symbol=NYMUSDT",
         lambda d: float(d["price"])),
    ]
    for url, pick in sources:
        try:
            with urllib.request.urlopen(url, timeout=8) as r:
                val = pick(json.loads(r.read().decode()))
            if val and val > 0:
                return val
        except Exception:
            continue
    return None


def _tail(text: str, n: int = 1200) -> str:
    text = (text or "").strip()
    return text[-n:]


# ---- CoinTracking rewards ledger ------------------------------------------
_TXHASH_RE = re.compile(r"\b([0-9A-Fa-f]{64})\b")


def _ct_date(dt: datetime.datetime) -> str:
    return dt.strftime("%d.%m.%Y %H:%M:%S")


def _amount_str(unym) -> str:
    # exact decimal from integer uNYM, no float artifacts, no scientific notation
    return format(Decimal(int(unym)) / Decimal(1_000_000), "f")


def _ct_row(wallet_name: str, unym, when: datetime.datetime, tx: str | None = None) -> list:
    """One CoinTracking row for a reward withdrawal."""
    date_s = _ct_date(when)
    trade_id = f"nym-withdraw-{wallet_name}-{int(when.timestamp())}"
    comment = f"Nym operator rewards withdrawal ({wallet_name})"
    if tx:
        comment += f" tx {tx}"
    return [CT_TYPE, _amount_str(unym), CT_CURRENCY, "", "", "", "", "",
            "", comment, trade_id, "nym-maestro", date_s, date_s]


def _next_session_path(when: datetime.datetime) -> Path:
    """<YYYYMMDD>_nym_rewards.csv, then _v2, _v3 … for repeats on the same day."""
    date = when.strftime("%Y%m%d")
    base = REWARDS_DIR / f"{date}_nym_rewards.csv"
    if not base.exists():
        return base
    v = 2
    while True:
        p = REWARDS_DIR / f"{date}_nym_rewards_v{v}.csv"
        if not p.exists():
            return p
        v += 1
        if v > 9999:
            return p  # give up de-duplicating; overwrite the last


def write_withdrawal_csv(results: list[dict], when: datetime.datetime | None = None) -> dict | None:
    """Write ONE dated CoinTracking CSV for this withdrawal run: one line per
    wallet that was successfully withdrawn with a non-zero amount. Returns file
    info, or None if there was nothing to record."""
    when = when or datetime.datetime.now()
    rows = []
    total = Decimal(0)
    for r in results:
        if not r.get("ok"):
            continue
        unym = r.get("rewards_unym")
        if not unym or int(unym) <= 0:
            continue
        rows.append(_ct_row(r["name"], unym, when, r.get("tx")))
        total += Decimal(int(unym)) / Decimal(1_000_000)
    if not rows:
        return None
    REWARDS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(REWARDS_DIR, 0o700)
    except OSError:
        pass
    path = _next_session_path(when)
    with path.open("w", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(CT_HEADER)
        w.writerows(rows)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return {"filename": path.name, "path": str(path), "count": len(rows),
            "total_nym": format(total, "f")}


def list_rewards_files() -> list[dict]:
    """All session CSVs, newest first, with line counts and totals for the UI."""
    out = []
    if not REWARDS_DIR.exists():
        return out
    for p in REWARDS_DIR.glob("*_nym_rewards*.csv"):
        if not REWARDS_FILE_RE.match(p.name):
            continue
        count = 0
        total = Decimal(0)
        try:
            with p.open(newline="") as f:
                for i, row in enumerate(csv.reader(f)):
                    if i == 0 or len(row) < 2:
                        continue
                    count += 1
                    try:
                        total += Decimal(row[1])
                    except Exception:
                        pass
        except OSError:
            continue
        out.append({"filename": p.name, "count": count,
                    "total_nym": format(total, "f"),
                    "mtime": int(p.stat().st_mtime)})
    out.sort(key=lambda x: x["filename"], reverse=True)
    return out


def read_rewards_file(filename: str) -> str:
    """Return the text of one session CSV. Guards against path traversal."""
    if not REWARDS_FILE_RE.match(filename or ""):
        raise WalletError("invalid rewards filename")
    p = (REWARDS_DIR / filename)
    if p.parent.resolve() != REWARDS_DIR.resolve() or not p.exists():
        raise WalletError("rewards file not found")
    return p.read_text()


def rewards_summary() -> dict:
    """Totals across all session files: NYM withdrawn, entries, file count."""
    files = list_rewards_files()
    total = Decimal(0)
    entries = 0
    for fdesc in files:
        try:
            total += Decimal(fdesc["total_nym"])
        except Exception:
            pass
        entries += fdesc["count"]
    return {"total_nym": format(total, "f"), "entries": entries,
            "file_count": len(files), "dir": str(REWARDS_DIR)}


# ---- high-level, request-facing orchestration ------------------------------
def query_wallets(names: list[str], password: str, with_usd: bool = True) -> list[dict]:
    """For each wallet: address, balance, pending rewards. Read-only. Per-wallet
    errors are captured so one bad password doesn't abort the batch."""
    price = nym_price_usd() if with_usd else None
    rows = []
    for name in names:
        row = {"name": name}
        try:
            mnemonic = decrypt_mnemonic(name, password)
            addr = derive_address(mnemonic)
            row["address"] = addr
            try:
                row["balance_nym"] = get_balance(addr)
            except WalletError as e:
                row["balance_error"] = str(e)
            try:
                pr = pending_rewards(addr)
                row["rewards_unym"] = pr["unym"]
                row["rewards_nym"] = pr["nym"]
            except WalletError as e:
                row["rewards_error"] = str(e)
            if price is not None:
                b = row.get("balance_nym")
                r = row.get("rewards_nym")
                if isinstance(b, (int, float)):
                    row["balance_usd"] = round(b * price, 2)
                if isinstance(r, (int, float)):
                    row["rewards_usd"] = round(r * price, 2)
        except WalletError as e:
            row["error"] = str(e)
        rows.append(row)
    if price is not None:
        for row in rows:
            row["price_usd"] = price
    return rows


def redeem_rewards(names: list[str], password: str) -> list[dict]:
    """Claim operator rewards for each wallet. IRREVERSIBLE — callers must gate
    on an explicit user confirmation before invoking. Per-wallet results carry
    rewards_unym + tx so the caller can write one session CSV for the whole run."""
    out = []
    for name in names:
        r = {"name": name}
        unym = None
        try:
            mnemonic = decrypt_mnemonic(name, password)
            # capture the amount we're about to claim, for the receipt + CSV
            try:
                addr = derive_address(mnemonic)
                r["address"] = addr
                pr = pending_rewards(addr)
                r["rewards_nym"] = pr["nym"]
                r["rewards_unym"] = pr["unym"]
                unym = pr["unym"]
            except WalletError:
                pass
            res = claim_rewards(mnemonic)
            r["ok"] = res["ok"]
            r["output"] = res["output"]
            if res["ok"]:
                m = _TXHASH_RE.search(res["output"] or "")
                if m:
                    r["tx"] = m.group(1)
                if unym == 0:
                    r["record_note"] = "no pending rewards — no CSV line"
                elif not unym:
                    r["record_note"] = "claim ok but reward amount unknown — no CSV line"
        except WalletError as e:
            r["ok"] = False
            r["error"] = str(e)
        out.append(r)
    return out


def send_from(name: str, password: str, receiver: str,
              amount_nym: float | None = None, send_max: bool = False) -> dict:
    """Send from a single wallet. IRREVERSIBLE — gate on explicit confirmation.
    Either amount_nym or send_max must be given. send_max sends floor(balance)
    whole NYM, leaving the sub-1-NYM remainder for the transaction fee (mirrors
    the old CLI's max-send behaviour)."""
    r = {"name": name, "receiver": receiver}
    try:
        if not validate_address(receiver):
            raise WalletError("invalid receiver address")
        mnemonic = decrypt_mnemonic(name, password)
        addr = derive_address(mnemonic)
        r["address"] = addr
        if send_max:
            bal = get_balance(addr)
            whole = int(bal)  # floor to whole NYM, keep remainder for fees
            if whole <= 0:
                raise WalletError(f"balance too low to send ({bal} NYM)")
            amount_unym = whole * UNYM
            r["amount_nym"] = whole
        else:
            if amount_nym is None or float(amount_nym) <= 0:
                raise WalletError("amount must be positive")
            amount_unym = nym_to_unym(amount_nym)
            r["amount_nym"] = float(amount_nym)
        r["amount_unym"] = amount_unym
        res = send(receiver, amount_unym, mnemonic)
        r["ok"] = res["ok"]
        r["output"] = res["output"]
    except WalletError as e:
        r["ok"] = False
        r["error"] = str(e)
    return r
