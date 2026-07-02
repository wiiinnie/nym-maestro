# nym maestro

Client/server control plane for a Nym node fleet. Replaces the SSH-and-expect
`nym_node_manager.sh` with a local orchestrator (your Mac) that talks to a small
agent on each node over mutual TLS — fixed command catalogue, no passwords on the
wire, no arbitrary remote root shell.

Slices 1-2 are in: the orchestrator + registry, and the node agent with live
status over mTLS. Remote write actions come next.

## Components

    app.py          orchestrator: FastAPI, serves the UI, polls agents (Mac)
    store.py        SQLite registry + cached telemetry
    pki.py          local CA + per-node enrollment (Mac)
    agent/agent.py  node agent: stdlib-only mTLS server, read-only status
    web/index.html  dashboard (vanilla JS)
    schema.sql      applied on first run

Wallet material stays in your existing ~/.nym_wallets store — never in this DB,
never on a node.

## Run the orchestrator (Mac)

Requires Python 3.11+.

    cd nym-maestro
    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    python app.py                 # http://127.0.0.1:7766

Flags: --addr (default 127.0.0.1:7766), --db (default ~/.nym-maestro/maestro.db).
Env:   MAESTRO_PKI (cert dir, default ~/.nym-maestro/pki),
       MAESTRO_POLL (background poll seconds, default 30; 0 disables).

## Trust model

A local CA on your Mac signs one orchestrator client cert and one server cert per
node. The agent requires a client cert signed by your CA; the orchestrator
requires a server cert signed by your CA. Nothing unsigned completes the TLS
handshake. The CA private key never leaves your Mac.

### Wallets

Wallet operations run on the orchestrator (your Mac), never on the agents.
Mnemonics live only in a local encrypted store (`~/.nym_wallets`, the same AES-256
`.enc` format the old `nym_node_manager.sh` used, so existing wallets work
unchanged) and are decrypted in-memory for the duration of one request. Claiming
rewards and sending funds don't need the key on a node — nym-cli signs locally and
broadcasts to Nyx. Keeping spendable keys off the internet-facing exit nodes is
the point: a compromised node must never be able to move operator funds.

The wallet password is handed to openssl via an environment variable, not argv,
so it isn't visible in `ps`; nothing logs a mnemonic or password. Redeem and send
require an explicit confirmation. Environment overrides:

    MAESTRO_WALLET_DIR      wallet store           (default ~/.nym_wallets)
    MAESTRO_NYM_CLI         nym-cli binary/path    (default nym-cli, must be in PATH)
    MAESTRO_NYX_REST        Nyx REST base(s) for the pending-reward query, comma/space
                            separated, tried in order (default: polkachu, nodes.guru,
                            nymtech, then cosmos.directory as a fallback)
    MAESTRO_REST_UA         User-Agent for the reward query (default nym-maestro/1.0;
                            a non-default UA avoids WAF 403s from the gateways)
    MAESTRO_MIXNET_CONTRACT mixnet contract addr   (default n17srj…t0cznr)

nym-cli must be installed on the Mac; the wallet toolbar warns if it isn't found.

## Bring a node online (slice 2)

1. Add the node in the UI (name, IP, agent port — default 8443).
2. One-time, create the CA + orchestrator cert:

       python pki.py init

3. Enroll the node — issues its server cert and builds a deploy bundle
   (IP is looked up from the registry):

       python pki.py enroll CH01

   This prints the two commands to run, e.g.:

       scp -r dist/CH01 root@<ip>:/tmp/nym-maestro-agent
       ssh root@<ip> 'cd /tmp/nym-maestro-agent && bash install.sh'

4. Open the node's agent port (default 8443) in its firewall if one is active.
5. Click Refresh in the UI (or wait for the poll). The node goes live: version,
   roles, WireGuard, service state, fail2ban ban count.

The agent runs as its own systemd unit (`nym-maestro-agent.service`), additive to
the existing nym-node setup, discovering the installed service rather than
re-provisioning it. It is read-only this slice.

## Network map

The dashboard renders a world map with one dot per fleet node, placed by the
country in its name (AT01 -> Austria); same-country nodes fan out on a small
ring so they stay distinct. Hover a node to draw a live spider-web of its
node-to-node connections on the Nym mix port (1789):

- The agent reads established TCP conns via `ss -tn` and classifies each peer by
  which side holds 1789: peer dialed us -> upstream (accent), we dialed peer ->
  downstream (amber), both -> purple. Clients (websocket) and verloc (1790) are
  intentionally excluded — this is the node graph only.
- The orchestrator geolocates each peer IP against the Nym network topology
  (validator.nymtech.net) — cached, with a tolerant parser that survives API
  shape changes. Peers it can place are drawn at their country (jittered);
  unplaceable peers are reported as a count. If the topology API is unreachable,
  fleet peers still resolve from the registry and the map degrades gracefully.
- The world outline is fetched from a CDN; if that fails it falls back to a
  graticule so dots and webs always render.

Roles flip per epoch, so the web is a live snapshot, not a fixed wiring.


### Fleet stats cards

Four cards summarise the fleet (or the current selection). They live on two
distinct, real measurement planes — nothing is projected or estimated:

- **Total traffic** — cumulative **exit payload** since each node's nym-node last
  restarted, in decimal **TB**, split per exit tunnel: **WG** (`nymwg`) and **Mixnet**
  (`nymtun0`). Foot: `since <oldest restart>` and the **real exit volume over 24h**
  (cumulative-counter snapshots diffed piecewise — gap-immune, reset-safe).
- **Throughput** (`on-wire now`) — live **on-wire** throughput from the peers
  sampler: **WG** (51822 dVPN) vs **Mixnet** (node-relay 1789 + mixnet clients
  9000/9001), i.e. everything actually moving on the wire, including mixnet cover.
  Foot: the **real on-wire 24h average** (`Ø24h`, from `onwire_history`) + nodes
  sampled.
- **Exit throughput** (`now`) — live decrypted-payload rate routed **out to the
  internet**, per exit tunnel: **WG** (`nymwg`) vs **Mixnet** (`nymtun0`). Cover/relay
  (1789) is not an exit tunnel, so it's excluded by construction — which is why
  mixnet-exit is typically tiny next to on-wire mixnet. Foot: the **real 24h exit
  average** (`Ø24h`), which equals the Total-traffic 24h volume ÷ its covered time.
- **Top traffic · country** — **on-wire client activity** by country (WG/Mixnet
  toggle). WG ranks by dVPN clients (51822); Mixnet by mixnet clients (9000). Bytes
  here are on-wire session bytes — for mixnet that's sphinx incl. cover, bidirectional
  — so a country can exceed the mixnet *exit* total on the other cards. They measure
  different planes (on-wire vs exit payload); they are not meant to reconcile.
  Node-to-node relay (1789) is excluded (infrastructure/noise, not user geography).

Data sources: `/api/traffic/window` (exit volume/avg, cumulative-counter deltas),
`/api/onwire/avg` (on-wire avg, from the peers sampler), `/api/throughput` (the
sparkline/24h chart, per-poll live-rate samples). The on-wire samples are recorded
by a background loop that scans each node's peers every `MAESTRO_ONWIRE_POLL`
seconds (default 60; set 0 to disable — the scan parses `ss`, so raise it on very
busy nodes).
- **Top traffic - country** — top destination countries by volume (with flags),
  from the geolocated connection data.

The 24h average comes from `/api/throughput/avg`, computed from the rolling
throughput history; if history is shorter than 24h it labels the real span
(e.g. `Ø6h`).

## Tests

    pip install fastapi httpx cryptography
    python smoke_test.py          # registry API
    python test_agent_mtls.py     # CA, agent, mTLS, orchestrator poll
    python test_actions.py        # flag edits, ssh harden, fail2ban, backups
    python test_migration.py      # surrogate-uid schema migration
    python test_peers.py          # 1789 peer-scan, topology harvest, geolocation
    python test_extra_blocks.py   # NYM-EXIT abuse blocklist (v4 + v6)
    python test_wallet.py         # wallet store, nym-cli wrappers, redeem/send

## API

    GET    /api/health
    GET    /api/nodes                 registry joined with cached status
    POST   /api/nodes
    GET    /api/nodes/{id}
    PATCH  /api/nodes/{id}            partial; node_id is immutable
    DELETE /api/nodes/{id}
    POST   /api/refresh               poll all enabled agents over mTLS
    POST   /api/peers                 live 1789 peers for one node, geolocated

Wallets (orchestrator-local; keys never leave the Mac):

    GET    /api/wallet/list           names + whether nym-cli is present
    POST   /api/wallet/query          balances + pending operator rewards (read-only)
    POST   /api/wallet/redeem         withdraw (claim) rewards into balance (confirm=true)
    POST   /api/wallet/send           send NYM from wallet(s)       (confirm=true)
    POST   /api/wallet/add            import a mnemonic (encrypted at rest)
    POST   /api/wallet/export         reveal a mnemonic (localhost UI only)
    POST   /api/wallet/delete         remove a wallet .enc          (confirm=true)
    GET    /api/wallet/rewards-files  list per-withdrawal CSVs + totals
    GET    /api/wallet/rewards-file/{name}  download one dated withdrawal CSV

### Rewards CSV (tax)

Each **Withdraw rewards** run writes ONE dated CoinTracking CSV with one line per
wallet withdrawn: `<YYYYMMDD>_nym_rewards.csv`, and a second run on the same day
becomes `_v2`, `_v3`, … Files live in `<wallet_dir>/rewards/` (override with
`MAESTRO_REWARDS_DIR`). The format matches the old nym_node_manager export so it
lands on the same asset: Type `Masternode`, currency `NYM2`, date
`DD.MM.YYYY HH:MM:SS`, 14 quoted columns; each row also carries a stable Trade ID
(`nym-withdraw-<wallet>-<unix>`) and the wallet name (plus tx hash when nym-cli
reports one) in the Comment. Download the file straight from the withdrawal
receipt, or browse every run's file from the wallet panel ("Rewards CSV").
Overrides: `MAESTRO_CT_TYPE`, `MAESTRO_CT_CURRENCY`. Only successful non-zero
withdrawals get a line; sends are transfers, not income, so they aren't logged.

Agent (mTLS, on each node):

    GET    /v1/health
    GET    /v1/status                 version, roles, wireguard, service, bans
    (exec) peers                      established 1789 conns, dir-classified

## Roadmap

1. Local foundation — registry + UI.                 done
2. Agent + live status over mTLS.                    done
3. Safe write actions: restart -> upgrade -> toggle.
4. fail2ban + harden-ssh (native, no expect).
5. File ops: replace-html, then backup.
6. run_allowlisted -- gated + audited, last.
