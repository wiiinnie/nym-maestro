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
CREATE TABLE nodes (
    node_id        TEXT PRIMARY KEY,
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
    updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TRIGGER nodes_touch AFTER UPDATE ON nodes
BEGIN
    UPDATE nodes SET updated_at = datetime('now') WHERE node_id = NEW.node_id;
END;

-- ---------------------------------------------------------------------------
-- Cached telemetry: last status pulled from each agent (1:1 with nodes).
-- Drives the grid; refreshed on poll. raw_json keeps the full agent payload.
-- ---------------------------------------------------------------------------
CREATE TABLE node_status (
    node_id          TEXT PRIMARY KEY REFERENCES nodes(node_id) ON DELETE CASCADE,
    reachable        INTEGER NOT NULL DEFAULT 0,
    version          TEXT,
    mode             TEXT,               -- mixnode | entry-gateway | exit-gateway
    mixnode          INTEGER,
    entry            INTEGER,
    exit             INTEGER,
    wireguard        INTEGER,
    service_active   INTEGER,
    fail2ban_banned  INTEGER,
    last_seen        TEXT,
    raw_json         TEXT
);

-- ---------------------------------------------------------------------------
-- Jobs: one row per bulk action (e.g. "upgrade 3 nodes").
-- ---------------------------------------------------------------------------
CREATE TABLE jobs (
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
CREATE TABLE job_targets (
    job_id      TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
    node_id     TEXT NOT NULL REFERENCES nodes(node_id) ON DELETE CASCADE,
    status      TEXT NOT NULL DEFAULT 'queued', -- queued|running|done|failed
    exit_code   INTEGER,
    started_at  TEXT,
    finished_at TEXT,
    output      TEXT,
    PRIMARY KEY (job_id, node_id)
);

CREATE INDEX idx_job_targets_node ON job_targets(node_id);

-- ---------------------------------------------------------------------------
-- Append-only audit. Every issued action, who issued it, the outcome.
-- Replaces the old debug.log with something queryable.
-- ---------------------------------------------------------------------------
CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL DEFAULT (datetime('now')),
    actor       TEXT,
    action      TEXT NOT NULL,
    job_id      TEXT,
    node_id     TEXT,
    detail_json TEXT
);

CREATE INDEX idx_audit_ts ON audit_log(ts);

-- ---------------------------------------------------------------------------
-- App settings (orchestrator port, mTLS cert paths, default upgrade URL, ...).
-- ---------------------------------------------------------------------------
CREATE TABLE app_config (
    key   TEXT PRIMARY KEY,
    value TEXT
);
