"""SQLite store for nym maestro.

Runs on the Mac. Holds the node registry + cached telemetry + (later) job
history and audit. Wallet material is deliberately NOT here and never touches
a node — it stays in your existing ~/.nym_wallets store.
"""
import sqlite3
import threading


class NotFound(Exception):
    pass


class Conflict(Exception):
    pass


EDITABLE = {
    "name", "ip", "hostname", "agent_port", "agent_fp",
    "service_name", "binary_path", "notes", "enabled",
}

# Aliased so sqlite3.Row lookups by name work (COALESCE expressions otherwise
# become the column "name"). Registry text cols coalesce to '' to match the API.
NODE_SELECT = """
SELECT n.node_id AS node_id, n.name AS name, n.ip AS ip,
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
       st.fail2ban_banned AS fail2ban_banned, st.last_seen AS last_seen
FROM nodes n
LEFT JOIN node_status st ON st.node_id = n.node_id
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
        cur = self.db.execute(
            "SELECT count(*) FROM sqlite_master "
            "WHERE type='table' AND name='nodes'"
        )
        if cur.fetchone()[0] == 0:
            self.db.executescript(schema)
            self.db.commit()

    # -- reads ---------------------------------------------------------------

    def list_nodes(self):
        rows = self.db.execute(
            NODE_SELECT + " ORDER BY n.name COLLATE NOCASE"
        ).fetchall()
        return [_row_to_view(r) for r in rows]

    def get_node(self, node_id: str):
        row = self.db.execute(
            NODE_SELECT + " WHERE n.node_id = ?", (node_id,)
        ).fetchone()
        return _row_to_view(row) if row else None

    # -- writes --------------------------------------------------------------

    def create_node(self, d: dict):
        with self.lock:
            try:
                self.db.execute(
                    "INSERT INTO nodes (node_id, name, ip, hostname, agent_port, "
                    "agent_fp, service_name, binary_path, notes, enabled) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (
                        d["node_id"], d["name"], d["ip"], _nz(d.get("hostname")),
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
                if "nodes.node_id" in msg:
                    raise Conflict("a node with that id already exists")
                raise

    def update_node(self, node_id: str, fields: dict) -> bool:
        sets, args = [], []
        for k, v in fields.items():
            if k not in EDITABLE:
                continue
            if k == "enabled":
                v = 1 if v else 0
            sets.append(f"{k} = ?")
            args.append(v)
        if not sets:
            return self.get_node(node_id) is not None
        args.append(node_id)
        with self.lock:
            try:
                cur = self.db.execute(
                    f"UPDATE nodes SET {', '.join(sets)} WHERE node_id = ?", args
                )
                self.db.commit()
            except sqlite3.IntegrityError as e:
                if "nodes.name" in str(e):
                    raise Conflict("a node with that name already exists")
                raise
        return cur.rowcount > 0

    def delete_node(self, node_id: str) -> bool:
        with self.lock:
            cur = self.db.execute(
                "DELETE FROM nodes WHERE node_id = ?", (node_id,)
            )
            self.db.commit()
        return cur.rowcount > 0


def _nz(s):
    return s if s else None


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
            "last_seen": r["last_seen"],
        }
    return {
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
