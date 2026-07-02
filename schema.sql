-- Nym node manager — orchestrator local store (SQLite)
-- Runs on the Mac. Holds registry + cached telemetry + job history + audit.
-- Wallet material is NOT here: it stays in ~/.nym_wallets and never touches a node.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------------
-- Registry: operator-owned facts. Replaces nodes.txt.
-- node_id = the id used at `nym-node init` (what the old tool called Node ID).
-- service_name / binary_path are OPTIONAL overrides; normally NULL because the
-- agent discovers them at runtime from the already-installed systemd unit.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS nodes (
    uid            TEXT PRIMARY KEY,     -- maestro surrogate id (stable, internal)
    node_id        TEXT NOT NULL,        -- the `nym-node init` id; NOT unique (e.g. "default-nym-node")
    name           TEXT NOT NULL UNIQUE,
    ip             TEXT NOT NULL,
    hostname       TEXT,
    agent_port     INTEGER NOT NULL DEFAULT 8443,
    agent_fp       TEXT,                 -- pinned agent server-cert fingerprint
    service_name   TEXT,                 -- override; NULL = auto-discover
    binary_path    TEXT,                 -- override; NULL = auto-discover
    notes          TEXT,
    enabled        INTEGER NOT NULL DEFAULT 1,
    created_at     TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at     TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (ip, agent_port)              -- the real "same node twice" guard
);

CREATE INDEX IF NOT EXISTS idx_nodes_node_id ON nodes(node_id);

CREATE TRIGGER IF NOT EXISTS nodes_touch AFTER UPDATE ON nodes
BEGIN
    UPDATE nodes SET updated_at = datetime('now') WHERE uid = NEW.uid;
END;

-- ---------------------------------------------------------------------------
-- Cached telemetry: last status pulled from each agent (1:1 with nodes).
-- Drives the grid; refreshed on poll. raw_json keeps the full agent payload.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS node_status (
    uid              TEXT PRIMARY KEY REFERENCES nodes(uid) ON DELETE CASCADE,
    reachable        INTEGER NOT NULL DEFAULT 0,
    version          TEXT,
    mode             TEXT,               -- mixnode | entry-gateway | exit-gateway
    mixnode          INTEGER,
    entry            INTEGER,
    exit             INTEGER,
    wireguard        INTEGER,
    service_active   INTEGER,
    fail2ban_banned  INTEGER,
    agent_version    TEXT,
    agent_sha        TEXT,
    traffic_bytes    INTEGER,
    traffic_json     TEXT,               -- {device: cumulative rx+tx bytes}
    traffic_at       REAL,               -- epoch seconds of the sample (for rate calc)
    bandwidth_json   TEXT,               -- {device: bytes/sec} over the last interval
    extra_blocks_json TEXT,              -- {installed,enabled,active,state} for NYM-EXIT blocks
    nym_node_since   REAL,               -- epoch: when nym-node last became active (traffic counter start)
    uplink_device    TEXT,               -- primary uplink iface (default route), for all-ports total
    boot_since       REAL,               -- epoch of last boot (uplink counter start)
    traffic_dir_json TEXT,               -- {dev: {rx,tx}} cumulative, for WG/Mixnet-exit in/out
    throughput_dir_json TEXT,            -- {dev: {rx,tx}} live rate
    last_seen        TEXT,
    raw_json         TEXT
);

-- ---------------------------------------------------------------------------
-- Jobs: one row per bulk action (e.g. "upgrade 3 nodes").
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS jobs (
    job_id      TEXT PRIMARY KEY,        -- uuid
    action      TEXT NOT NULL,           -- upgrade | restart | toggle | backup | ...
    params_json TEXT,                    -- action args (url, mode, wg flag, file, ...)
    status      TEXT NOT NULL DEFAULT 'queued', -- queued|running|done|failed|partial
    node_count  INTEGER NOT NULL DEFAULT 0,
    created_by  TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT
);

-- ---------------------------------------------------------------------------
-- Per-node result for a job. Output is the streamed log, persisted on finish.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS job_targets (
    job_id      TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
    node_uid    TEXT NOT NULL REFERENCES nodes(uid) ON DELETE CASCADE,
    status      TEXT NOT NULL DEFAULT 'queued', -- queued|running|done|failed
    exit_code   INTEGER,
    started_at  TEXT,
    finished_at TEXT,
    output      TEXT,
    PRIMARY KEY (job_id, node_uid)
);

CREATE INDEX IF NOT EXISTS idx_job_targets_node ON job_targets(node_uid);

-- ---------------------------------------------------------------------------
-- Append-only audit. Every issued action, who issued it, the outcome.
-- Replaces the old debug.log with something queryable.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL DEFAULT (datetime('now')),
    actor       TEXT,
    action      TEXT NOT NULL,
    job_id      TEXT,
    node_uid    TEXT,
    detail_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);

-- ---------------------------------------------------------------------------
-- App settings (orchestrator port, mTLS cert paths, default upgrade URL, ...).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS app_config (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- ---------------------------------------------------------------------------
-- Rolling per-node throughput history (one row per poll), for the sparkline
-- and the 24h graph. json = {device: bytes/sec}. Pruned to a ~26h window.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS throughput_history (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    uid  TEXT NOT NULL,
    ts   REAL NOT NULL,
    json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tput_uid_ts ON throughput_history(uid, ts);

-- ---------------------------------------------------------------------------
-- Rolling per-node CUMULATIVE traffic snapshots (one row per poll), for real
-- windowed volume/rate via counter deltas. json = {device: cumulative rx+tx
-- bytes} (same counters as node_status.traffic_json). Pruned to a ~26h window.
-- These are the authoritative kernel counters — gap-immune (they count through
-- maestro downtime) and reset-safe when diffed piecewise.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS traffic_history (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    uid  TEXT NOT NULL,
    ts   REAL NOT NULL,
    json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_traf_uid_ts ON traffic_history(uid, ts);

-- ---------------------------------------------------------------------------
-- Rolling per-node ON-WIRE throughput samples (bits/s), split wg (51822) vs
-- mix (1789 node-relay + 9000 mixnet clients), from the peers sampler. Lets us
-- show a real on-wire average distinct from the exit-tunnel counters. ~26h.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS onwire_history (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    uid  TEXT NOT NULL,
    ts   REAL NOT NULL,
    json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_onwire_uid_ts ON onwire_history(uid, ts);
