"""SQLite store for nym maestro.

Runs on the Mac. Holds the node registry + cached telemetry + (later) job
history and audit. Wallet material is deliberately NOT here and never touches
a node — it stays in your existing ~/.nym_wallets store.
"""
import json
import secrets
import sqlite3
import threading
import time


def _new_uid():
    return secrets.token_hex(6)  # 12-hex surrogate id


class NotFound(Exception):
    pass


class Conflict(Exception):
    pass


EDITABLE = {
    "node_id", "name", "ip", "hostname", "agent_port", "agent_fp",
    "service_name", "binary_path", "notes", "enabled",
}

# Aliased so sqlite3.Row lookups by name work (COALESCE expressions otherwise
# become the column "name"). Registry text cols coalesce to '' to match the API.
NODE_SELECT = """
SELECT n.uid AS uid, n.node_id AS node_id, n.name AS name, n.ip AS ip,
       COALESCE(n.hostname,'')     AS hostname,
       n.agent_port                AS agent_port,
       COALESCE(n.agent_fp,'')     AS agent_fp,
       COALESCE(n.service_name,'') AS service_name,
       COALESCE(n.binary_path,'')  AS binary_path,
       COALESCE(n.notes,'')        AS notes,
       n.enabled AS enabled, n.created_at AS created_at, n.updated_at AS updated_at,
       st.reachable AS reachable, st.version AS version, st.mode AS mode,
       st.mixnode AS mixnode, st.entry AS entry, st.exit AS exit,
       st.wireguard AS wireguard, st.service_active AS service_active,
       st.fail2ban_banned AS fail2ban_banned, st.traffic_bytes AS traffic_bytes,
       st.agent_version AS agent_version, st.agent_sha AS agent_sha,
       st.traffic_json AS traffic_json, st.bandwidth_json AS bandwidth_json,
       st.extra_blocks_json AS extra_blocks_json,
       st.nym_node_since AS nym_node_since,
       st.uplink_device AS uplink_device,
       st.boot_since AS boot_since,
       st.traffic_dir_json AS traffic_dir_json,
       st.throughput_dir_json AS throughput_dir_json,
       st.last_seen AS last_seen
FROM nodes n
LEFT JOIN node_status st ON st.uid = n.uid
"""


class Store:
    def __init__(self, path: str, schema: str):
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.execute("PRAGMA journal_mode = WAL")
        self.db.execute("PRAGMA busy_timeout = 5000")
        self._ensure_schema(schema)

    def close(self):
        self.db.close()

    def _ensure_schema(self, schema: str):
        have_nodes = self.db.execute(
            "SELECT count(*) FROM sqlite_master "
            "WHERE type='table' AND name='nodes'"
        ).fetchone()[0]
        if not have_nodes:
            self.db.executescript(schema)
            self.db.commit()
            return
        # existing DB: migrate the pre-uid layout (node_id was the PK) if needed
        cols = [r[1] for r in self.db.execute("PRAGMA table_info(nodes)").fetchall()]
        if "uid" not in cols:
            self._migrate_to_uid(schema)
        self._ensure_columns()

    def _ensure_columns(self):
        # additive, non-destructive: add columns introduced after a DB was created
        wanted = {
            ("node_status", "traffic_bytes", "INTEGER"),
            ("node_status", "traffic_json", "TEXT"),
            ("node_status", "traffic_at", "REAL"),
            ("node_status", "bandwidth_json", "TEXT"),
            ("node_status", "agent_version", "TEXT"),
            ("node_status", "agent_sha", "TEXT"),
            ("node_status", "extra_blocks_json", "TEXT"),
            ("node_status", "nym_node_since", "REAL"),
            ("node_status", "uplink_device", "TEXT"),
            ("node_status", "boot_since", "REAL"),
            ("node_status", "traffic_dir_json", "TEXT"),
            ("node_status", "throughput_dir_json", "TEXT"),
        }
        for table, col, decl in wanted:
            have = [r[1] for r in self.db.execute(f"PRAGMA table_info({table})").fetchall()]
            if have and col not in have:
                self.db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
        # idempotent: create tables added after a DB was first built
        self.db.executescript(
            "CREATE TABLE IF NOT EXISTS throughput_history ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT, uid TEXT NOT NULL,"
            " ts REAL NOT NULL, json TEXT NOT NULL);"
            "CREATE INDEX IF NOT EXISTS idx_tput_uid_ts ON throughput_history(uid, ts);"
            "CREATE TABLE IF NOT EXISTS traffic_history ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT, uid TEXT NOT NULL,"
            " ts REAL NOT NULL, json TEXT NOT NULL);"
            "CREATE INDEX IF NOT EXISTS idx_traf_uid_ts ON traffic_history(uid, ts);"
            "CREATE TABLE IF NOT EXISTS onwire_history ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT, uid TEXT NOT NULL,"
            " ts REAL NOT NULL, json TEXT NOT NULL);"
            "CREATE INDEX IF NOT EXISTS idx_onwire_uid_ts ON onwire_history(uid, ts);"
        )
        self.db.commit()

    def _migrate_to_uid(self, schema: str):
        # Preserve the registry (incl. agent_fp cert pins). Telemetry and job/
        # audit history are disposable — they regenerate on the next poll/action.
        db = self.db
        db.execute("PRAGMA foreign_keys=OFF")
        old = db.execute(
            "SELECT node_id, name, ip, hostname, agent_port, agent_fp, "
            "service_name, binary_path, notes, enabled, created_at FROM nodes"
        ).fetchall()
        db.executescript(
            "DROP TABLE IF EXISTS node_status;"
            "DROP TABLE IF EXISTS job_targets;"
            "DROP TABLE IF EXISTS audit_log;"
            "DROP TABLE IF EXISTS jobs;"
            "DROP TRIGGER IF EXISTS nodes_touch;"
        )
        # Rename — do NOT drop — the registry, so a failure here is recoverable.
        db.execute("DROP TABLE IF EXISTS _migrate_old_nodes")
        db.execute("ALTER TABLE nodes RENAME TO _migrate_old_nodes")
        db.executescript(schema)  # idempotent: app_config etc. survive untouched
        for r in old:
            try:
                db.execute(
                    "INSERT INTO nodes (uid, node_id, name, ip, hostname, agent_port, "
                    "agent_fp, service_name, binary_path, notes, enabled, created_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (_new_uid(), r["node_id"], r["name"], r["ip"], r["hostname"],
                     r["agent_port"], r["agent_fp"], r["service_name"],
                     r["binary_path"], r["notes"], r["enabled"], r["created_at"]),
                )
            except sqlite3.IntegrityError:
                pass  # skip a row that collides under the new constraints (rare)
        db.execute("DROP TABLE IF EXISTS _migrate_old_nodes")
        db.execute("PRAGMA foreign_keys=ON")
        db.commit()

    # -- reads ---------------------------------------------------------------

    def list_nodes(self):
        rows = self.db.execute(
            NODE_SELECT + " ORDER BY n.name COLLATE NOCASE"
        ).fetchall()
        return [_row_to_view(r) for r in rows]

    def get_node(self, uid: str):
        row = self.db.execute(
            NODE_SELECT + " WHERE n.uid = ?", (uid,)
        ).fetchone()
        return _row_to_view(row) if row else None

    # -- writes --------------------------------------------------------------

    def create_node(self, d: dict) -> str:
        uid = _new_uid()
        with self.lock:
            try:
                self.db.execute(
                    "INSERT INTO nodes (uid, node_id, name, ip, hostname, agent_port, "
                    "agent_fp, service_name, binary_path, notes, enabled) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        uid, d["node_id"], d["name"], d["ip"], _nz(d.get("hostname")),
                        d.get("agent_port") or 8443, _nz(d.get("agent_fp")),
                        _nz(d.get("service_name")), _nz(d.get("binary_path")),
                        _nz(d.get("notes")), 1 if d.get("enabled", True) else 0,
                    ),
                )
                self.db.commit()
            except sqlite3.IntegrityError as e:
                msg = str(e)
                if "nodes.name" in msg:
                    raise Conflict("a node with that name already exists")
                if "nodes.ip" in msg or "ip, agent_port" in msg:
                    raise Conflict("a node with that IP and agent port already exists")
                raise
        return uid

    def update_node(self, uid: str, fields: dict) -> bool:
        sets, args = [], []
        for k, v in fields.items():
            if k not in EDITABLE:
                continue
            if k == "enabled":
                v = 1 if v else 0
            sets.append(f"{k} = ?")
            args.append(v)
        if not sets:
            return self.get_node(uid) is not None
        args.append(uid)
        with self.lock:
            try:
                cur = self.db.execute(
                    f"UPDATE nodes SET {', '.join(sets)} WHERE uid = ?", args
                )
                self.db.commit()
            except sqlite3.IntegrityError as e:
                msg = str(e)
                if "nodes.name" in msg:
                    raise Conflict("a node with that name already exists")
                if "nodes.ip" in msg or "ip, agent_port" in msg:
                    raise Conflict("a node with that IP and agent port already exists")
                raise
        return cur.rowcount > 0

    def delete_node(self, uid: str) -> bool:
        with self.lock:
            cur = self.db.execute(
                "DELETE FROM nodes WHERE uid = ?", (uid,)
            )
            self.db.commit()
        return cur.rowcount > 0

    def upsert_status(self, uid, reachable, version=None, mode=None,
                      mixnode=None, entry=None, exit=None, wireguard=None,
                      service_active=None, fail2ban_banned=None,
                      traffic_bytes=None, traffic=None, throughput=None,
                      agent_version=None, agent_sha=None, extra_blocks=None,
                      nym_node_since=None, uplink_device=None, boot_since=None,
                      traffic_dir=None, throughput_dir=None):
        with self.lock:
            traffic_json = None
            if traffic is not None:
                if traffic_bytes is None:   # agent already sends exit-only bytes
                    traffic_bytes = sum(traffic.values())
                traffic_json = json.dumps(traffic)
            # bandwidth_json column holds live per-device throughput (bytes/sec)
            throughput_json = json.dumps(throughput) if throughput is not None else None
            extra_blocks_json = json.dumps(extra_blocks) if extra_blocks is not None else None
            traffic_dir_json = json.dumps(traffic_dir) if traffic_dir is not None else None
            throughput_dir_json = json.dumps(throughput_dir) if throughput_dir is not None else None
            self.db.execute(
                'INSERT INTO node_status (uid, reachable, version, mode, '
                'mixnode, entry, "exit", wireguard, service_active, '
                'fail2ban_banned, agent_version, agent_sha, traffic_bytes, '
                'traffic_json, bandwidth_json, extra_blocks_json, '
                'nym_node_since, uplink_device, boot_since, '
                'traffic_dir_json, throughput_dir_json, last_seen) '
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, datetime('now')) "
                'ON CONFLICT(uid) DO UPDATE SET '
                'reachable=excluded.reachable, version=excluded.version, '
                'mode=excluded.mode, mixnode=excluded.mixnode, '
                'entry=excluded.entry, "exit"=excluded."exit", '
                'wireguard=excluded.wireguard, '
                'service_active=excluded.service_active, '
                'fail2ban_banned=excluded.fail2ban_banned, '
                'agent_version=excluded.agent_version, '
                'agent_sha=excluded.agent_sha, '
                'traffic_bytes=excluded.traffic_bytes, '
                'traffic_json=excluded.traffic_json, '
                'bandwidth_json=excluded.bandwidth_json, '
                'extra_blocks_json=excluded.extra_blocks_json, '
                'nym_node_since=excluded.nym_node_since, '
                'uplink_device=excluded.uplink_device, '
                'boot_since=excluded.boot_since, '
                'traffic_dir_json=excluded.traffic_dir_json, '
                'throughput_dir_json=excluded.throughput_dir_json, '
                'last_seen=excluded.last_seen',
                (uid, 1 if reachable else 0, version, mode,
                 _ob(mixnode), _ob(entry), _ob(exit), _ob(wireguard),
                 _ob(service_active), fail2ban_banned, agent_version, agent_sha,
                 traffic_bytes, traffic_json, throughput_json, extra_blocks_json,
                 nym_node_since, uplink_device, boot_since,
                 traffic_dir_json, throughput_dir_json),
            )
            self.db.commit()

    def record_throughput(self, uid, ts, throughput):
        """Append one per-device throughput sample ({device: bytes/sec})."""
        if not throughput:
            return
        with self.lock:
            self.db.execute(
                "INSERT INTO throughput_history (uid, ts, json) VALUES (?,?,?)",
                (uid, float(ts), json.dumps(throughput)),
            )
            self.db.commit()

    def prune_throughput(self, max_age_s=26 * 3600):
        with self.lock:
            self.db.execute(
                "DELETE FROM throughput_history WHERE ts < ?",
                (time.time() - max_age_s,),
            )
            self.db.commit()

    def record_traffic(self, uid, ts, traffic):
        """Append one CUMULATIVE per-device counter snapshot ({device: bytes})."""
        if not traffic:
            return
        with self.lock:
            self.db.execute(
                "INSERT INTO traffic_history (uid, ts, json) VALUES (?,?,?)",
                (uid, float(ts), json.dumps(traffic)),
            )
            self.db.commit()

    def prune_traffic(self, max_age_s=26 * 3600):
        with self.lock:
            self.db.execute(
                "DELETE FROM traffic_history WHERE ts < ?",
                (time.time() - max_age_s,),
            )
            self.db.commit()

    def record_onwire(self, uid, ts, wg_bps, mix_bps):
        """Append one fleet-node on-wire throughput sample (bits/s), split into
        wg (51822 dVPN) and mix (1789 node-relay + 9000 mixnet clients)."""
        with self.lock:
            self.db.execute(
                "INSERT INTO onwire_history (uid, ts, json) VALUES (?,?,?)",
                (uid, float(ts), json.dumps({"wg": wg_bps, "mix": mix_bps})),
            )
            self.db.commit()

    def prune_onwire(self, max_age_s=26 * 3600):
        with self.lock:
            self.db.execute(
                "DELETE FROM onwire_history WHERE ts < ?",
                (time.time() - max_age_s,),
            )
            self.db.commit()

    def onwire_avg(self, hours=24.0, buckets=288):
        """Average fleet ON-WIRE throughput (bits/s) over the window, split into
        wg and mix. Bucketed like throughput_avg: each node's bucket value is its
        mean, summed across nodes per bucket, then averaged over observed buckets."""
        buckets = max(12, min(int(buckets), 1440))
        now = time.time()
        since = now - hours * 3600
        width = (hours * 3600) / buckets
        with self.lock:
            rows = self.db.execute(
                "SELECT uid, ts, json FROM onwire_history WHERE ts >= ? ORDER BY ts",
                (since,),
            ).fetchall()
        per = {}
        for r in rows:
            try:
                d = json.loads(r["json"]) or {}
            except Exception:
                continue
            bi = int((r["ts"] - since) / width)
            if bi < 0 or bi >= buckets:
                continue
            for k in ("wg", "mix"):
                v = d.get(k)
                if v is None:
                    continue
                a = per.setdefault((bi, k, r["uid"]), [0.0, 0])
                a[0] += v
                a[1] += 1
        fleet = {}
        observed = set()
        for (bi, k, _uid), (s, c) in per.items():
            if c <= 0:
                continue
            fleet[(bi, k)] = fleet.get((bi, k), 0.0) + (s / c)
            observed.add(bi)
        n = len(observed)
        if n == 0:
            return {"wg_bps": None, "mix_bps": None, "total_bps": None,
                    "observed_hours": 0.0, "window_hours": hours}
        wg = sum(b for (bi, k), b in fleet.items() if k == "wg") / n
        mix = sum(b for (bi, k), b in fleet.items() if k == "mix") / n
        span = (max(observed) - min(observed) + 1) * width / 3600.0
        return {"wg_bps": wg, "mix_bps": mix, "total_bps": wg + mix,
                "observed_hours": round(span, 2), "window_hours": hours}

    def traffic_window(self, hours=24.0):
        """REAL fleet traffic over the last `hours`, from cumulative-counter
        snapshots — no averaging assumptions, no projection.

        For each node, sum consecutive-snapshot deltas within the window:
          - counter rose  -> add (b2 - b1)               [normal]
          - counter fell   -> add b2                       [nym-node restart reset;
                                                            count the post-reset bytes]
        This is gap-immune (the kernel keeps counting through maestro downtime, so a
        large gap between two snapshots is still a real delta) and reset-safe. The
        rate is bytes / observed span, so volume and rate reconcile exactly.

        Returns per-device + total bytes, the observed span (which grows to `hours`
        as snapshots accrue), and total_bps = total_bytes / observed span."""
        now = time.time()
        since = now - hours * 3600
        with self.lock:
            rows = self.db.execute(
                "SELECT uid, ts, json FROM traffic_history WHERE ts >= ? ORDER BY uid, ts",
                (since,),
            ).fetchall()
        per_node = {}
        for r in rows:
            try:
                d = json.loads(r["json"]) or {}
            except Exception:
                continue
            per_node.setdefault(r["uid"], []).append((r["ts"], d))
        dev_bytes = {}
        first_ts = None
        last_ts = None
        for uid, snaps in per_node.items():
            if len(snaps) < 2:
                continue
            nfirst, nlast = snaps[0][0], snaps[-1][0]
            first_ts = nfirst if first_ts is None else min(first_ts, nfirst)
            last_ts = nlast if last_ts is None else max(last_ts, nlast)
            prev = snaps[0][1]
            for ts, cur in snaps[1:]:
                for dev, v in cur.items():
                    pv = prev.get(dev)
                    if pv is None:
                        continue
                    delta = (v - pv) if v >= pv else v   # reset -> post-reset bytes
                    if delta > 0:
                        dev_bytes[dev] = dev_bytes.get(dev, 0.0) + delta
                prev = cur
        have = first_ts is not None and last_ts is not None and last_ts > first_ts
        span = (last_ts - first_ts) if have else 0.0
        total_bytes = sum(dev_bytes.values()) if dev_bytes else (0.0 if have else None)
        total_bps = (total_bytes / span) if (have and span > 0 and total_bytes is not None) else None
        return {"total_bytes": total_bytes, "dev_bytes": dev_bytes,
                "total_bps": total_bps, "observed_hours": round(span / 3600.0, 2),
                "window_hours": hours, "nodes": len(per_node)}

    def throughput_series(self, hours=24, buckets=96):
        """Downsampled per-node, per-device throughput over the last `hours`.

        Returns {uid: {"ts": [epoch,...], "dev": {device: [bytes/sec | None,...]}}}
        with `buckets` time slots; empty slots are None so the UI can show gaps.
        """
        now = time.time()
        since = now - hours * 3600
        width = (hours * 3600) / buckets
        with self.lock:
            rows = self.db.execute(
                "SELECT uid, ts, json FROM throughput_history WHERE ts >= ? ORDER BY ts",
                (since,),
            ).fetchall()
        acc = {}  # uid -> list[buckets] of {dev: [sum, count]}
        for r in rows:
            try:
                d = json.loads(r["json"]) or {}
            except Exception:
                continue
            bi = int((r["ts"] - since) / width)
            if bi < 0 or bi >= buckets:
                continue
            slots = acc.setdefault(r["uid"], [None] * buckets)
            slot = slots[bi]
            if slot is None:
                slot = slots[bi] = {}
            for dev, val in d.items():
                a = slot.setdefault(dev, [0.0, 0])
                a[0] += val
                a[1] += 1
        centers = [round(since + width * (i + 0.5)) for i in range(buckets)]
        out = {}
        for uid, slots in acc.items():
            devset = set()
            for slot in slots:
                if slot:
                    devset.update(slot.keys())
            series = {dev: [] for dev in devset}
            for slot in slots:
                for dev in devset:
                    if slot and dev in slot and slot[dev][1] > 0:
                        series[dev].append(slot[dev][0] / slot[dev][1])
                    else:
                        series[dev].append(None)
            out[uid] = {"ts": centers, "dev": series}
        return out

    def throughput_avg(self, hours=24.0, buckets=288):
        """Fleet-wide average throughput (bytes/sec) over the last `hours`, split
        by device. Robust to uneven polling: samples are bucketed, each node's
        bucket value is its mean, buckets are summed across nodes, then averaged
        over the buckets that actually have data. Also reports the observed span
        so the UI can label it honestly when history is shorter than requested."""
        buckets = max(12, min(int(buckets), 1440))
        now = time.time()
        since = now - hours * 3600
        width = (hours * 3600) / buckets
        with self.lock:
            rows = self.db.execute(
                "SELECT uid, ts, json FROM throughput_history WHERE ts >= ? ORDER BY ts",
                (since,),
            ).fetchall()
        # per (bucket, device, uid) -> [sum, count] to average each node in a bucket
        per = {}
        for r in rows:
            try:
                d = json.loads(r["json"]) or {}
            except Exception:
                continue
            bi = int((r["ts"] - since) / width)
            if bi < 0 or bi >= buckets:
                continue
            for dev, val in d.items():
                a = per.setdefault((bi, dev, r["uid"]), [0.0, 0])
                a[0] += val
                a[1] += 1
        # fleet[(bucket, device)] = sum over nodes of that node's bucket mean
        fleet = {}
        observed = set()
        for (bi, dev, _uid), (s, c) in per.items():
            if c <= 0:
                continue
            fleet[(bi, dev)] = fleet.get((bi, dev), 0.0) + (s / c)
            observed.add(bi)
        n = len(observed)
        if n == 0:
            return {"total_bps": None, "dev": {}, "total_bytes": None,
                    "dev_bytes": {}, "window_hours": hours,
                    "observed_hours": 0.0, "buckets_observed": 0}
        dev_sum = {}
        for (bi, dev), bps in fleet.items():
            dev_sum[dev] = dev_sum.get(dev, 0.0) + bps
        dev_avg = {dev: s / n for dev, s in dev_sum.items()}
        total = sum(dev_avg.values())
        # aggregated volume over the observed window: bytes = Σ (bucket bps × width)
        dev_bytes = {}
        for (bi, dev), bps in fleet.items():
            dev_bytes[dev] = dev_bytes.get(dev, 0.0) + bps * width
        total_bytes = sum(dev_bytes.values())
        span = (max(observed) - min(observed) + 1) * width / 3600.0
        return {"total_bps": total, "dev": dev_avg,
                "total_bytes": total_bytes, "dev_bytes": dev_bytes,
                "window_hours": hours, "observed_hours": round(span, 2),
                "buckets_observed": n}

    def record_job(self, job_id, action, params_json, node_count, created_by="ui"):
        with self.lock:
            self.db.execute(
                "INSERT INTO jobs (job_id, action, params_json, status, "
                "node_count, created_by) VALUES (?,?,?,?,?,?)",
                (job_id, action, params_json, "running", node_count, created_by),
            )
            self.db.commit()

    def record_target(self, job_id, node_uid, status, exit_code, output):
        with self.lock:
            self.db.execute(
                "INSERT INTO job_targets (job_id, node_uid, status, exit_code, "
                "started_at, finished_at, output) "
                "VALUES (?,?,?,?, datetime('now'), datetime('now'), ?)",
                (job_id, node_uid, status, exit_code, output),
            )
            self.db.commit()

    def finish_job(self, job_id, status):
        with self.lock:
            self.db.execute(
                "UPDATE jobs SET status=?, finished_at=datetime('now') WHERE job_id=?",
                (status, job_id),
            )
            self.db.commit()

    def audit(self, actor, action, job_id, node_uid, detail_json):
        with self.lock:
            self.db.execute(
                "INSERT INTO audit_log (actor, action, job_id, node_uid, detail_json) "
                "VALUES (?,?,?,?,?)",
                (actor, action, job_id, node_uid, detail_json),
            )
            self.db.commit()


def _nz(s):
    return s if s else None


def _ob(v):
    return None if v is None else (1 if v else 0)


def _nb(v):
    return None if v is None else bool(v)


def _row_to_view(r: sqlite3.Row) -> dict:
    status = None
    if r["reachable"] is not None:
        status = {
            "reachable": bool(r["reachable"]),
            "version": r["version"],
            "mode": r["mode"],
            "mixnode": _nb(r["mixnode"]),
            "entry": _nb(r["entry"]),
            "exit": _nb(r["exit"]),
            "wireguard": _nb(r["wireguard"]),
            "service_active": _nb(r["service_active"]),
            "fail2ban_banned": r["fail2ban_banned"],
            "agent_version": r["agent_version"],
            "agent_sha": r["agent_sha"],
            "traffic_bytes": r["traffic_bytes"],
            "traffic": json.loads(r["traffic_json"]) if r["traffic_json"] else None,
            "throughput": json.loads(r["bandwidth_json"]) if r["bandwidth_json"] else None,
            "extra_blocks": json.loads(r["extra_blocks_json"]) if r["extra_blocks_json"] else None,
            "nym_node_since": (r["nym_node_since"] if "nym_node_since" in r.keys() else None),
            "uplink_device": (r["uplink_device"] if "uplink_device" in r.keys() else None),
            "boot_since": (r["boot_since"] if "boot_since" in r.keys() else None),
            "traffic_dir": (json.loads(r["traffic_dir_json"]) if ("traffic_dir_json" in r.keys() and r["traffic_dir_json"]) else None),
            "throughput_dir": (json.loads(r["throughput_dir_json"]) if ("throughput_dir_json" in r.keys() and r["throughput_dir_json"]) else None),
            "last_seen": r["last_seen"],
        }
    return {
        "uid": r["uid"],
        "node_id": r["node_id"],
        "name": r["name"],
        "ip": r["ip"],
        "hostname": r["hostname"],
        "agent_port": r["agent_port"],
        "agent_fp": r["agent_fp"],
        "service_name": r["service_name"],
        "binary_path": r["binary_path"],
        "notes": r["notes"],
        "enabled": bool(r["enabled"]),
        "created_at": r["created_at"],
        "updated_at": r["updated_at"],
        "status": status,
    }
