# nym maestro

Client/server control plane for a Nym node fleet. Replaces the SSH-and-expect
`nym_node_manager.sh` with a local orchestrator that talks to a small agent on
each node over mTLS — fixed command catalogue, no passwords on the wire, no
arbitrary remote root shell.

This repo currently contains **slice 1: the local orchestrator** (Python +
FastAPI). It runs on your Mac, serves the dashboard on localhost, and owns the
node registry. Node agents and remote actions come in later slices.

Stack split: rich deps on the Mac (FastAPI), and the node agent — added in
slice 2 — will be a single dependency-free stdlib `.py` so the fleet needs no
pip installs.

## What works now

- SQLite-backed node registry (replaces `nodes.txt`).
- Dashboard at `http://127.0.0.1:7766` with add / edit / delete node.
- Live grid columns (version, roles, WG, service, bans) wired up but empty —
  they fill in once agents report (slice 2).
- Append-only audit + jobs tables created and ready for the action slices.

Wallet material is deliberately **not** in this database and never touches a
node — it stays in your existing ~/.nym_wallets store.

## Run

Requires Python 3.11+.

    cd nym-maestro
    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    python app.py                 # http://127.0.0.1:7766

Flags:

    --addr   listen address           (default 127.0.0.1:7766 — keep on localhost)
    --db     path to SQLite database  (default ~/.nym-maestro/maestro.db)

The DB and its parent directory are created on first run; the schema is applied
automatically if the database is empty.

## Test

    pip install fastapi httpx     # httpx powers the test client
    python smoke_test.py          # 21 checks across the registry API

## API (slice 1)

    GET    /api/health
    GET    /api/nodes                 registry joined with cached status
    POST   /api/nodes                 {node_id,name,ip,hostname,agent_port,notes,enabled}
    GET    /api/nodes/{id}
    PATCH  /api/nodes/{id}            partial; node_id is immutable
    DELETE /api/nodes/{id}

Errors are returned as {"error": "..."}.

## Layout

    app.py          FastAPI app: routes, serves embedded UI, runs on localhost
    store.py        SQLite open/bootstrap + registry CRUD + telemetry join
    schema.sql      applied on first run
    web/index.html  dashboard (vanilla JS, no external deps)
    smoke_test.py   in-process API tests
    requirements.txt

## Roadmap

1. Local foundation — registry + UI.            <- you are here
2. Agent + live /v1/status (grid goes live). Stdlib-only, deploys to 22 nodes.
3. Safe write actions: restart -> upgrade -> toggle.
4. fail2ban + harden-ssh (native, no expect).
5. File ops: replace-html, then backup.
6. run_allowlisted -- gated + audited, last.
