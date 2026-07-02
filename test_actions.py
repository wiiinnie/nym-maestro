import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "agent"))
import agent  # noqa: E402

EXEC = ("/root/nym/nym-node run --mode exit-gateway --id at01 "
        "--accept-operator-terms-and-conditions --wireguard-enabled true")

ok = fail = 0


def check(label, cond):
    global ok, fail
    if cond:
        ok += 1; print(f"  pass  {label}")
    else:
        fail += 1; print(f"  FAIL  {label}")


# set: replace existing value flag
r = agent.apply_flag_edits(EXEC, {"--mode": "mixnode"}, [])
check("set replaces existing flag value", "--mode mixnode" in r and "exit-gateway" not in r)
check("set leaves other flags intact", "--id at01" in r and "--wireguard-enabled true" in r)

# set: flip a boolean-style value flag
r = agent.apply_flag_edits(EXEC, {"--wireguard-enabled": "false"}, [])
check("set flips wireguard true->false", "--wireguard-enabled false" in r and "true" not in r)

# set: append an absent flag
r = agent.apply_flag_edits(EXEC, {"--http-bind-address": "127.0.0.1:8080"}, [])
check("set appends absent flag", r.endswith("--http-bind-address 127.0.0.1:8080"))

# unset: remove a value flag and its value
r = agent.apply_flag_edits(EXEC, {}, ["--wireguard-enabled"])
check("unset removes flag + value", "--wireguard-enabled" not in r and "true" not in r)
check("unset keeps the rest", "--mode exit-gateway" in r and "--id at01" in r)

# = form is handled
r = agent.apply_flag_edits("/root/nym/nym-node run --mode=exit-gateway --id x",
                           {"--mode": "mixnode"}, [])
check("set handles --flag=value form", "--mode mixnode" in r and "exit-gateway" not in r)

# combined set + unset
r = agent.apply_flag_edits(EXEC, {"--mode": "entry-gateway"}, ["--wireguard-enabled"])
check("combined set+unset", "--mode entry-gateway" in r and "--wireguard-enabled" not in r)

# no-op when value unchanged
r = agent.apply_flag_edits(EXEC, {"--mode": "exit-gateway"}, [])
check("setting same value is a no-op", r == EXEC)

# prefix flags are not confused (--mode vs --modex)
r = agent.apply_flag_edits("/root/nym/nym-node run --modex keep --mode old",
                           {"--mode": "new"}, [])
check("prefix flag not clobbered", "--modex keep" in r and "--mode new" in r)

# parse_flags
flags = agent.parse_flags(EXEC)
fd = {f["flag"]: f["value"] for f in flags}
check("parse: mode value", fd.get("--mode") == "exit-gateway")
check("parse: wireguard value", fd.get("--wireguard-enabled") == "true")
check("parse: boolean flag value is None",
      fd.get("--accept-operator-terms-and-conditions") is None)

# --- presence-flag handling against the real node ExecStart ----------------
REAL = ("/root/nym/nym-node run --id hermes-gateway-at "
        "--accept-operator-terms-and-conditions --mode exit-gateway "
        "--wireguard-enabled true")
ACCEPT = "--accept-operator-terms-and-conditions"

# unset a bare flag that is followed by another --flag: only the bare flag goes
r = agent.apply_flag_edits(REAL, {}, [ACCEPT], [])
check("unset bare flag keeps the following flag",
      ACCEPT not in r and "--mode exit-gateway" in r and "--id hermes-gateway-at" in r)

# present is a no-op when already there (no duplicate)
r = agent.apply_flag_edits(REAL, {}, [], [ACCEPT])
check("present is idempotent", r.count(ACCEPT) == 1)

# present appends when absent
base = "/root/nym/nym-node run --id x --mode exit-gateway"
r = agent.apply_flag_edits(base, {}, [], [ACCEPT])
check("present appends a bare flag when absent", r.endswith(ACCEPT))

# set --mode after a preceding bare flag does not eat the bare flag
r = agent.apply_flag_edits(REAL, {"--mode": "mixnode"}, [], [])
check("set value flag preserves preceding bare flag",
      ACCEPT in r and "--mode mixnode" in r and "exit-gateway" not in r)

# combined: flip mode + wireguard, drop the accept flag
r = agent.apply_flag_edits(REAL, {"--mode": "entry-gateway", "--wireguard-enabled": "false"},
                           [ACCEPT], [])
check("combined dropdown-style edit",
      "--mode entry-gateway" in r and "--wireguard-enabled false" in r and ACCEPT not in r)

# --- binary locator (upgrade lands in the right spot) ----------------------
check("binary from real ExecStart", agent._binary_from_execstart(REAL) == "/root/nym/nym-node")
check("binary strips systemd prefix char",
      agent._binary_from_execstart("-/usr/bin/nym-node run --id x") == "/usr/bin/nym-node")
check("binary from quoted path",
      agent._binary_from_execstart('"/opt/nym/nym-node" run') == "/opt/nym/nym-node")

# --- WireGuard detection (nym-node 1.34.0 shape) ---------------------------
GW_ON = {"enforces_zk_nyms": False, "client_interfaces": {
    "wireguard": {"port": 51822, "tunnel_port": 51822, "metadata_port": 51830,
                  "public_key": "2hnfD8wuAg8RtWLHR4uKbxGDYmKYqcDb6GJUm4RdCFwn"},
    "mixnet_websockets": {"ws_port": 9000, "wss_port": 9001}}}
check("WG on: real 1.34.0 nested object", agent.wireguard_enabled(GW_ON) is True)
check("WG off: nested null", agent.wireguard_enabled(
    {"client_interfaces": {"wireguard": None, "mixnet_websockets": {}}}) is False)
check("WG off: no client_interfaces", agent.wireguard_enabled({"enforces_zk_nyms": False}) is False)
check("WG on: legacy top-level object", agent.wireguard_enabled({"wireguard": {"port": 51822}}) is True)
check("WG off: legacy top-level null", agent.wireguard_enabled({"wireguard": None}) is False)
check("WG off: junk input", agent.wireguard_enabled(None) is False)

# --- _run merge keeps stdout/stderr in true order (NTM output ordering) -----
rc, out, err = agent._run(
    ["python3", "-c", "import sys;sys.stdout.write('OUT\\n');sys.stdout.flush();sys.stderr.write('ERR\\n')"],
    merge=True)
check("_run(merge) combines stdout+stderr into one stream", "OUT" in out and "ERR" in out and err == "")
rc, out, err = agent._run(["python3", "-c", "import sys;sys.stderr.write('ERR\\n')"])
check("_run default keeps stderr separate", "ERR" in err and "ERR" not in out)

# --- /proc/net/dev traffic parsing + live-rate math ------------------------
PROC = """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1234 10 0 0 0 0 0 0 1234 10 0 0 0 0 0 0
  eth0: 9990000000 100 0 0 0 0 0 0 1000000000 100 0 0 0 0 0 0
 nymwg: 20490000000 5 0 0 0 0 0 0 203090000000 9 0 0 0 0 0 0
nymtun0: 500000000 1 0 0 0 0 0 0 500000000 1 0 0 0 0 0 0
"""
check("proc parses rx+tx per device",
      agent.parse_proc_net_dev(PROC, ["nymtun0", "nymwg"]) ==
      {"nymwg": 223580000000, "nymtun0": 1000000000})
check("proc ignores eth0/lo",
      agent.parse_proc_net_dev(PROC, ["nymwg"]) == {"nymwg": 223580000000})
check("traffic sums selected devices", agent.parse_traffic(PROC, ["nymtun0", "nymwg"]) == 224580000000)
check("traffic None when no device matches", agent.parse_traffic(PROC, ["wg99"]) is None)
check("traffic None on empty input", agent.parse_traffic("", ["nymwg"]) is None)

check("rate is delta over dt",
      agent.compute_rates({"nymwg": 1000}, {"nymwg": 3000}, 2.0) == {"nymwg": 1000.0})
check("rate skips counter resets (cur < prev)",
      agent.compute_rates({"nymwg": 5000}, {"nymwg": 10}, 2.0) == {})
check("rate skips unknown-prev devices",
      agent.compute_rates({}, {"nymwg": 3000}, 2.0) == {})
check("rate guards dt<=0", agent.compute_rates({"nymwg": 1000}, {"nymwg": 3000}, 0) == {})

# end-to-end: the live sampler updates the cached throughput
_orig = agent._read_proc_net_dev
_seq = iter([
    " nymwg: 1000 0 0 0 0 0 0 0 1000 0 0 0 0 0 0 0\n",   # total 2000
    " nymwg: 1000 0 0 0 0 0 0 0 5000 0 0 0 0 0 0 0\n",   # total 6000 (+4000)
])
agent._read_proc_net_dev = lambda: next(_seq)
agent.SAMPLE_INTERVAL = 0.05
agent.start_sampler()
time.sleep(0.2)
_tp = agent.read_throughput()
agent._read_proc_net_dev = _orig
check("sampler exposes a positive live rate for nymwg",
      _tp is not None and _tp.get("nymwg", 0) > 0)

# --- backup mechanics ------------------------------------------------------
check("id from ExecStart --id", agent._nym_id_from_execstart(REAL) == "hermes-gateway-at")
check("id None when no --id", agent._nym_id_from_execstart("/root/nym/nym-node run --mode exit-gateway") is None)

check("safe name accepts a real backup name",
      agent._safe_backup_name("nym-backup_hermes-gateway-cz01_20260629_143006.tar.gz") is True)
check("safe name rejects path traversal",
      agent._safe_backup_name("../../etc/shadow") is False)
check("safe name rejects a subdir", agent._safe_backup_name("sub/x.tar.gz") is False)
check("safe name rejects arbitrary file", agent._safe_backup_name("ca.crt") is False)

import os as _os, tempfile as _tf, tarfile as _tar
_d = _tf.mkdtemp()
_src = _os.path.join(_d, "hermes-gateway-cz01")
_os.makedirs(_os.path.join(_src, "data"))
with open(_os.path.join(_src, "data", "ed25519_identity"), "w") as _f:
    _f.write("SECRET-KEY-MATERIAL")
_arc = _os.path.join(_d, "out.tar.gz")
_size, _sha = agent.make_archive(_src, _arc)
check("archive produces a non-empty file", _size > 0 and len(_sha) == 64)
with _tar.open(_arc) as _t:
    _names = _t.getnames()
check("archive contains the node dir under its id",
      any(n.startswith("hermes-gateway-cz01") for n in _names)
      and any(n.endswith("ed25519_identity") for n in _names))

# --- store persists per-device traffic + agent-provided throughput ----------
import store as _store
_sp = _os.path.join(_tf.mkdtemp(), "tp.db")
_s = _store.Store(_sp, open("schema.sql").read())
_uid = _s.create_node({"node_id": "default-nym-node", "name": "TP01", "ip": "10.0.0.9"})
_s.upsert_status(_uid, reachable=True,
                 traffic={"nymtun0": 1000, "nymwg": 5000},
                 throughput={"nymtun0": 0.0, "nymwg": 1_000_000.0})
_v = _s.get_node(_uid)["status"]
check("store persists per-device traffic", _v["traffic"] == {"nymtun0": 1000, "nymwg": 5000})
check("traffic_bytes is the summed counter", _v["traffic_bytes"] == 6000)
check("store persists per-device throughput",
      _v["throughput"] == {"nymtun0": 0.0, "nymwg": 1_000_000.0})
_s.upsert_status(_uid, reachable=True)  # poll with no traffic payload
check("missing traffic payload leaves columns null",
      _s.get_node(_uid)["status"]["traffic"] is None)

# history: record -> downsampled series -> prune
import time as _time
_now = _time.time()
for _h in range(24):
    _s.record_throughput(_uid, _now - (24 - _h) * 3600 + 1,
                         {"nymwg": float(_h * 1_000_000), "nymtun0": 500000.0})
_ser = _s.throughput_series(hours=24, buckets=24)
check("series returns per-node, per-device buckets",
      _uid in _ser and set(_ser[_uid]["dev"]) == {"nymwg", "nymtun0"} and len(_ser[_uid]["ts"]) == 24)
_wg = [x for x in _ser[_uid]["dev"]["nymwg"] if x is not None]
check("series captures the ramp (max ~23 MB/s)", _wg and max(_wg) >= 22_000_000)
_s.record_throughput(_uid, _now, None)  # None payload is ignored
_s.prune_throughput(max_age_s=1)
check("prune empties the rolling window", _s.throughput_series(hours=24, buckets=24) == {})
_s.upsert_status(_uid, reachable=True, agent_version="0.6.0", agent_sha="deadbeef" * 8)
_av = _s.get_node(_uid)["status"]
check("store persists agent version + sha",
      _av["agent_version"] == "0.6.0" and _av["agent_sha"] == "deadbeef" * 8)
_s.close()

# --- fail2ban: log parse, config write (scoped to sshd), validation --------
import os as _os3, tempfile as _tf3, time as _tm3
_fd = _tf3.mkdtemp()
_logf = _os3.path.join(_fd, "f2b.log")
_recent = _tm3.strftime("%Y-%m-%d %H:%M:%S")
_old = _tm3.strftime("%Y-%m-%d %H:%M:%S", _tm3.localtime(_tm3.time() - 48 * 3600))
with open(_logf, "w") as _f:
    _f.write(f"{_recent},001 fail2ban.actions [1]: NOTICE [sshd] Ban 1.2.3.4\n"
             f"{_recent},002 fail2ban.actions [1]: NOTICE [sshd] Ban 5.6.7.8\n"
             f"{_old},003 fail2ban.actions [1]: NOTICE [sshd] Ban 9.9.9.9\n"
             f"{_recent},004 fail2ban.filter [1]: INFO matched something\n")
agent.F2B_LOG = _logf
check("bans_24h counts only recent Ban events", agent._f2b_bans_24h() == 2)

agent._f2b_installed = lambda: True
agent._run = lambda cmd, timeout=6, merge=False: (0, "active", "") if cmd[:2] == ["systemctl", "is-active"] else (0, "", "")
agent._f2b_get = lambda s: {"bantime": "3600", "findtime": "600", "maxretry": "5"}.get(s)
agent.F2B_DROPIN = _os3.path.join(_fd, "nym-maestro.local")
_r = agent.act_fail2ban_setup({"maxretry": 5, "findtime": "10m", "bantime": "1h", "ignoreip": ["203.0.113.7"]})
check("setup returns ok + effective config", _r["ok"] is True and _r["effective"]["maxretry"] == "5")
_conf = open(agent.F2B_DROPIN).read()
check("drop-in is scoped to the sshd jail", "[sshd]" in _conf and "enabled = true" in _conf)
check("drop-in carries our rules", all(s in _conf for s in
      ["maxretry = 5", "bantime = 1h", "findtime = 10m", "bantime.increment = true"]))
check("drop-in keeps loopback + admin ignoreip", "127.0.0.1/8" in _conf and "203.0.113.7" in _conf)
check("setup rejects shell-injection in ignoreip",
      agent.act_fail2ban_setup({"ignoreip": ["1.2.3.4; rm -rf /"]})["ok"] is False)
check("setup rejects bad time", agent.act_fail2ban_setup({"bantime": "1y"})["ok"] is False)
check("unban validates the IP", agent.act_fail2ban_unban({"ip": "nope"})["ok"] is False)

# --- SSH key auth + harden gating (login user = hermes, never root) --------
import types as _types3
_ED = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc123+/def maestro@mac"
check("pubkey accepts real keys, rejects junk",
      bool(agent._PUBKEY_RE.match(_ED)) and bool(agent._PUBKEY_RE.match("ssh-rsa AAAAB3+/== u@h"))
      and not agent._PUBKEY_RE.match("not a key") and not agent._PUBKEY_RE.match("ssh-ed25519"))

_sd = _tf3.mkdtemp()
_home = _os3.path.join(_sd, "home", "hermes")
_os3.makedirs(_home, exist_ok=True)
_fakepw = _types3.SimpleNamespace(pw_uid=_os3.getuid(), pw_gid=_os3.getgid(), pw_dir=_home)


def _fake_user_paths(user):
    if user != "hermes":
        raise KeyError(user)
    sshd = _os3.path.join(_home, ".ssh")
    return _fakepw, sshd, _os3.path.join(sshd, "authorized_keys")


agent._user_paths = _fake_user_paths
_authk = _os3.path.join(_home, ".ssh", "authorized_keys")

_a1 = agent.act_ssh_add_key({"public_keys": [_ED]})
_a2 = agent.act_ssh_add_key({"public_keys": [_ED]})
check("add_key installs once then dedupes into the login user's account",
      _a1["added"] == 1 and _a1["user"] == "hermes" and _a1["authorized_keys"] == _authk
      and _a2["already_present"] == 1)
check("authorized_keys perms are 600 file / 700 dir",
      oct(_os3.stat(_authk).st_mode)[-3:] == "600" and
      oct(_os3.stat(_os3.path.dirname(_authk)).st_mode)[-3:] == "700")
check("add_key rejects malformed keys", agent.act_ssh_add_key({"public_keys": ["bad key"]})["ok"] is False)
check("add_key rejects an unknown login user",
      agent.act_ssh_add_key({"public_keys": [_ED], "user": "nobody"})["ok"] is False)

agent.SSH_DROPIN = _os3.path.join(_sd, "sshd_dropin.conf")
agent.unit_exists = lambda u: u == "ssh"
_SAMPLE = "passwordauthentication no\npubkeyauthentication yes\npermitrootlogin no\nport 22\n"
agent._run = lambda cmd, timeout=6, merge=False: (0, _SAMPLE, "") if cmd[:1] == ["sshd"] and "-T" in cmd else (0, "", "")

# empty the user's authorized_keys -> harden must refuse
open(_authk, "w").close()
check("harden REFUSES to disable passwords when the login user has no keys",
      agent.act_ssh_harden({"password": "off"})["ok"] is False)
with open(_authk, "w") as _f:
    _f.write(_ED + "\n")
_h = agent.act_ssh_harden({"password": "off"})
_conf = open(agent.SSH_DROPIN).read()
check("harden writes key-only drop-in that also FORBIDS root login",
      _h["ok"] is True and "PasswordAuthentication no" in _conf and "PermitRootLogin no" in _conf
      and "prohibit-password" not in _conf)
check("re-enable (password=on) removes the maestro drop-in",
      agent.act_ssh_harden({"password": "on"})["ok"] is True and not _os3.path.exists(agent.SSH_DROPIN))

# When the drop-in has no effect (sshd_config lacks the Include), harden adds it.
_sshd_main = _os3.path.join(_sd, "sshd_config")
with open(_sshd_main, "w") as _f:
    _f.write("Port 22\nPermitRootLogin no\n")  # no Include line
_eff_state = {"pw": "yes"}  # flips to "no" only after the Include is added


def _run_inc(cmd, timeout=6, merge=False):
    if cmd[:1] == ["sshd"] and "-T" in cmd:
        return (0, f"passwordauthentication {_eff_state['pw']}\npermitrootlogin no\nport 22\n", "")
    return (0, "", "")


agent._run = _run_inc
_orig_open = open

# redirect the agent's hard-coded sshd_config path to our temp file, and make
# "adding the Include" flip the effective password_auth to "no"
agent._sshd_main_includes_dropins = (lambda: "Include /etc/ssh/sshd_config.d/*.conf"
                                     in _orig_open(_sshd_main).read())


def _ensure_inc_stub():
    changed = not agent._sshd_main_includes_dropins()
    if changed:
        with _orig_open(_sshd_main, "a") as f:
            f.write("Include /etc/ssh/sshd_config.d/*.conf\n")
        _eff_state["pw"] = "no"
    return changed, True


agent._ensure_sshd_include = _ensure_inc_stub
_hi = agent.act_ssh_harden({"password": "off"})
check("harden self-heals a missing sshd_config Include and then disables passwords",
      _hi["ok"] is True and _hi["include_added"] is True)

_st = agent.act_ssh_status({})
check("ssh_status reports user, key count, and effective config",
      _st["password_auth"] == "no" and _st["user"] == "hermes"
      and _st["user_exists"] is True and _st["authorized_keys_count"] == 1)

print(f"\n{ok} passed, {fail} failed")
raise SystemExit(1 if fail else 0)
