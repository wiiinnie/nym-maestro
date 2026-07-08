# nym maestro

<p align="center">
  <img src="web/favicon.svg" width="72" alt="nym maestro logo">
</p>

A Python mTLS control plane for Nym exit-gateway fleets. Replaces SSH/bash tooling
with a local orchestrator (your Mac) that talks to a small agent on each node over
mutual TLS — fixed command catalogue, no passwords on the wire, no arbitrary remote
root shell.

The orchestrator runs on your machine (or any host — a VPS works too), polls each
node's agent over mTLS, and renders a single dashboard: live throughput, 30-day
history, disk usage, abuse blocklists, per-node WireGuard/Mixnet detail, and wallet
operations that never expose keys to a node.

## Screenshots

> Drop your own PNGs into `docs/screenshots/` (filenames below) and they render here.

| Fleet overview | Throughput history |
|---|---|
| ![Fleet overview](docs/screenshots/fleet-overview.png) | ![Throughput history](docs/screenshots/throughput-history.png) |

| Network map | Per-node detail |
|---|---|
| ![Network map](docs/screenshots/network-map.png) | ![Per-node detail](docs/screenshots/node-detail.png) |

---

## Quick start

> **Windows:** use WSL (Ubuntu). Run `wsl --install` in PowerShell, then follow
> these instructions inside the WSL terminal.

---

### On your Mac (once, ever)

**1. Clone and launch**

```bash
git clone git@github.com:wiiinnie/nym-maestro.git
cd nym-maestro
./run.sh
```

`run.sh` installs Homebrew and Python if missing, creates a virtualenv, installs
pip dependencies, then starts the orchestrator at `http://127.0.0.1:7766`.

**2. Initialise the CA**

```bash
source .venv/bin/activate
python pki.py init
```

Creates `~/.nym-maestro/pki/` with your CA key and orchestrator cert. Never shared,
never in the repo. Run this once — regenerating the CA invalidates all node certs.

---

### Per-node setup — do this for every new VPS

The flow for each new node is:

```
VPS provider → create node → you get root/password access
       ↓
Create a sudo user on the node (your deployment user)
       ↓
Enable passwordless sudo for that user
       ↓
Open port 8443 (the maestro agent port)
       ↓
Run enroll + deploy from your Mac (uses password SSH — this is the only time)
       ↓
Node appears green in the dashboard
       ↓
Use SSH keys panel in UI to install maestro key + disable password login
```

**3. On the node — create your sudo user (if not already done)**

Log in as root via your VPS provider's console or their provided SSH access:

```bash
adduser <your-user>
usermod -aG sudo <your-user>
```

**4. On the node — enable passwordless sudo**

Required so the deploy script can run `install.sh` as root without prompting:

```bash
echo "<your-user> ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/maestro-user
sudo chmod 440 /etc/sudoers.d/maestro-user
```

**5. On the node — open port 8443**

The maestro agent listens on port 8443 (mTLS). Open it before deploying:

```bash
# iptables (Debian/Ubuntu default):
sudo iptables -I INPUT -p tcp --dport 8443 -j ACCEPT
sudo apt install -y iptables-persistent
sudo netfilter-persistent save

# UFW (if active instead):
sudo ufw allow 8443/tcp
```

Verify: `sudo iptables -L INPUT -n | grep 8443`

**6. On your Mac — enroll and deploy**

This uses password-based SSH — it is the only time you need the password:

```bash
source .venv/bin/activate
python pki.py enroll AT01
ssh <your-user>@<node-ip> 'rm -rf /tmp/maestro-deploy && mkdir /tmp/maestro-deploy'
scp dist/AT01/* <your-user>@<node-ip>:/tmp/maestro-deploy/
ssh <your-user>@<node-ip> 'sudo bash -c "cd /tmp/maestro-deploy && bash install.sh"'
```

The agent installs as `nym-maestro-agent.service` (systemd, port 8443).

**7. Add the node in the dashboard**

Open `http://127.0.0.1:7766` → **Add node** → enter name (e.g. `AT01`), IP,
port (default `8443`). Click **Refresh** or wait 30 s — the node goes green.

**8. Switch to key-based SSH (disable password login)**

Once the node is green, open the **SSH keys** panel in the UI:

1. Copy the maestro public key shown (or use your own)
2. Click **Install key** — adds it to the node's `~/.ssh/authorized_keys`
3. Click **Verify login** — confirms key login works before touching password auth
4. Click **Disable password** — locks down SSH to key-only

From this point on, the maestro key (`~/.nym-maestro/ssh/id_maestro`) is the only
way in. Add it to `~/.ssh/config` so plain `ssh <your-user>@<host>` uses it:

```
Host *.your-domain.com
    User <your-user>
    IdentityFile ~/.nym-maestro/ssh/id_maestro
    IdentitiesOnly yes
```

Set `MAESTRO_SSH_USER` so the orchestrator knows which user to connect as:

```bash
export MAESTRO_SSH_USER=<your-user>
```

---

## Fleet rollout

For multiple nodes, use a deploy script with one `deploy()` call per node. Always
test on one node first, then roll to the fleet.

```bash
#!/bin/bash
SSH_KEY=~/.nym-maestro/ssh/id_maestro
USER=<your-user>

deploy() {
  name=$1; ip=$2
  echo "--- $name ($ip) ---"
  python pki.py enroll "$name"
  ssh -i "$SSH_KEY" "$USER"@"$ip" 'rm -rf /tmp/maestro-deploy && mkdir /tmp/maestro-deploy'
  scp -i "$SSH_KEY" dist/"$name"/* "$USER"@"$ip":/tmp/maestro-deploy/
  ssh -i "$SSH_KEY" "$USER"@"$ip" 'sudo bash -c "cd /tmp/maestro-deploy && bash install.sh"'
  echo "--- $name done ---"
}

deploy AT01 1.2.3.4
deploy AT02 1.2.3.5
# ...
```

---

## Components

```
app.py          orchestrator: FastAPI, serves the UI, polls agents (Mac)
store.py        SQLite registry + cached telemetry
pki.py          local CA + per-node enrollment (Mac)
agent/agent.py  node agent: stdlib-only mTLS server
web/index.html  dashboard (vanilla JS)
schema.sql      applied on first run, additive migrations on restart
requirements.txt
run.sh          launcher (handles venv + deps)
install-nym-extra-blocks.sh   NYM-EXIT rate-limit + abuse blocklist installer
```

Wallet material stays in `~/.nym_wallets` — never in the DB, never on a node.
Each agent keeps its own 30-day throughput/traffic history in a local SQLite DB
(`/var/lib/nym-maestro-agent/history.db`); the orchestrator backfills from it, so
charts stay gap-free even when the orchestrator is offline or moved to another host.

---

## Configuration

**Orchestrator flags:** `--addr` (default `127.0.0.1:7766`), `--db` (default
`~/.nym-maestro/maestro.db`).

**Environment variables:**

| Variable | Default | Description |
|---|---|---|
| `MAESTRO_PKI` | `~/.nym-maestro/pki` | CA + cert directory |
| `MAESTRO_POLL` | `30` | Agent poll interval in seconds (0 = disable) |
| `MAESTRO_ONWIRE_POLL` | `60` | On-wire sampler interval (0 = disable) |
| `MAESTRO_SSH_USER` | system user | SSH user on each node |
| `MAESTRO_SSH_DIR` | `~/.nym-maestro/ssh` | Maestro SSH key directory |
| `MAESTRO_UPLINK_DEVICE` | auto | Override uplink interface detection |
| `MAESTRO_WALLET_DIR` | `~/.nym_wallets` | Wallet store |
| `MAESTRO_NYM_CLI` | `nym-cli` | nym-cli binary path |
| `MAESTRO_NYX_REST` | polkachu, nodes.guru, nymtech, cosmos.directory | Nyx REST endpoints |
| `MAESTRO_REST_UA` | `nym-maestro/1.0` | User-Agent for reward queries |
| `MAESTRO_MIXNET_CONTRACT` | `n17srj…t0cznr` | Mixnet contract address |
| `MAESTRO_REWARDS_DIR` | `<wallet_dir>/rewards/` | Rewards CSV output directory |
| `MAESTRO_HISTORY_POLL` | `300` | History-sync interval in seconds (0 = disable) |
| `MAESTRO_HISTORY_MAX_PAGES` | `8` | Max `/v1/history` pages pulled per node per sync |

**Agent-side (set on each node's `nym-maestro-agent.service` if needed):**

| Variable | Default | Description |
|---|---|---|
| `MAESTRO_ORCH_CN` | `nym-maestro-orchestrator` | Required CN on the client cert (see Trust model) |
| `MAESTRO_AGENT_HISTORY_DIR` | `/var/lib/nym-maestro-agent` | Agent history DB directory |
| `MAESTRO_HISTORY_RETENTION_S` | `2592000` | History retention window (30 days) |
| `MAESTRO_HISTORY_BUCKET_S` | `60` | History bucket size (1-minute buckets) |
| `NYM_EB_RATE` | `500/sec` | Extra-blocks per-source rate-limit ceiling |
| `NYM_EB_BURST` | `5000` | Extra-blocks per-source burst allowance |

---

## Trust model

A local CA on your Mac signs one orchestrator client cert and one server cert per
node. The agent refuses any connection not signed by your CA; the orchestrator
refuses any server not signed by your CA. Nothing unsigned completes the TLS
handshake. The CA private key never leaves your Mac.

Because every node's server cert is signed by the same CA, a CA-signed check alone
would let one compromised node impersonate the orchestrator to another. The agent
therefore also pins the client cert's Common Name to `nym-maestro-orchestrator`
(override with `MAESTRO_ORCH_CN`) — so a node's own cert can never drive root
actions on another node.

nym-node binary upgrades are optionally sha256-verified before the downloaded
binary is made executable or run.

### Wallets

Wallet operations run on the orchestrator (your Mac), never on the agents.
Mnemonics live only in `~/.nym_wallets` (AES-256 `.enc`, same format as the old
`nym_node_manager.sh`) and are decrypted in-memory for the duration of one request.
`nym-cli` signs locally and broadcasts to Nyx — the spendable key never touches an
internet-facing node.

The wallet password is passed via environment variable, not argv, so it's invisible
in `ps`. Nothing logs a mnemonic or password. Redeem and send require explicit
`confirm=true`.

---

## Dashboard

### Network map

One dot per node, placed by country (AT01 → Austria; same-country nodes fan out on
a ring). Hover a node to draw its live 1789 peer web:

- **Green** = peer dialled us (upstream)
- **Orange** = we dialled peer (downstream)
- **Purple** = both directions

Clients (9000) and verloc (1790) are excluded — this is the node graph only. Peer
IPs are geolocated against the Nym topology API (cached). Roles flip per epoch so
the web is a live snapshot.

### Traffic cards (top row)

**Total exit traffic** — `nymtun0` + `nymwg` cumulative since last **nym-node
restart**, WG / Mixnet split, plus real 24h exit volume.

**Top traffic · country** — WG (51822) and Mixnet (9000) side by side. Ranks by
on-wire client bytes (sphinx-padded for mixnet, so it exceeds the exit total —
different measurement planes, not a bug).

### Per-node detail cards (bottom row)

Select a node in the map dropdown. Each section shows **IN · OUT · Σ**.
IN = uploads (user → internet), OUT = downloads (internet → user). OUT is always
the big number.

**WireGuard** (violet) — `nymwg` rx/tx. Real kernel counters, rate + running total.
No double-counting: a 1 GB download = ~1 GB OUT, not 2 GB.

**Mixnet** — three colour-matched sections:
- **clients · 9000** (cyan) — sphinx to/from connected clients. Rate only.
- **relay · 1789** (green IN / orange OUT) — sphinx to/from other nodes. Rate only.
  Padded + cover-inflated; treat as "how hard am I shuffling," not user data.
- **exit · nymtun0** (neutral) — real decrypted payload to/from the internet. Rate
  + running total. Usually tiny vs on-wire — expected and correct.

### Fleet table columns

Beyond version, roles, WG, and service state, each row shows:

- **Extra blocks** — NYM-EXIT abuse blocklist status: `Active`/`Inactive`, the count
  of your blocklist IPs actually present in the chain (not the node-wide exit policy,
  which adds hundreds), and the live per-source rate-limit (`rate/sec · burst`), all
  read straight from `iptables`. The 3-section modal installs/updates the blocklist
  script, refreshes the list, or restarts the oneshot.
- **24h** — throughput sparkline over the last 24 hours (click to expand).
- **Disk** — green/red pie of the **root partition** usage (`os.statvfs("/")`, so it
  works regardless of the device name, which differs per VPS). Colour escalates:
  muted < 70%, amber 70–90%, red > 90%.

The Version column also stacks the maestro **agent version** beneath the nym-node
version (amber if the agent is older than the orchestrator).

### Throughput history

Each agent buckets its own throughput and traffic into 1-minute samples in a local
SQLite DB and keeps a rolling 30-day window. The orchestrator's history-sync loop
pulls whatever it's missing (cursor-paginated, idempotent), so the 24h chart and
the expanded history view stay **gap-free across orchestrator downtime** — close
your laptop overnight and the line is continuous the next morning. It also means the
orchestrator can run from any host (e.g. a VPS) and catch up on restart.

### Two clocks, one explanation

- **Exit traffic** resets on **nym-node restart** (`nymtun0`/`nymwg` are created by
  nym-node; a restart makes fresh zeroed interfaces).

---

## Agent versions

| Version | What it adds |
|---|---|
| 0.9.6 | Uplink detection (`_default_iface()`), reports `uplink_device` + `boot_since` |
| 0.9.7 | Directional interface counters (`traffic_dir`, `throughput_dir`), WG + Mixnet-exit IN/OUT |
| 0.9.8 | Split on-wire into `onwire_clients` (9000) + `onwire_peers` (1789), each `{rx_bps,tx_bps}` |
| 0.9.9 | Extra-blocks live rate/burst + blocklist-aware blocked count in fleet status |
| 0.9.10 | Client-cert CN pinning (privesc fix); sha256-verify nym-node binary on upgrade |
| 0.10.0 | Agent-side 30-day history buffering, `GET /v1/history` with cursor pagination |
| 0.10.1 | Root-partition disk usage (`read_disk`) in status |
| 0.10.2 | Status path reads the blocklist from the local cache only — never the network |

Current agent: **0.10.2**

---

## Deploy checklist

1. `./run.sh` restart + browser hard-refresh (runs additive DB migration).
2. Push agent via **"Update agent"** in the UI — **one node first**, verify green,
   then roll to the fleet.
3. Sanity check: WireGuard OUT should be the big number; a known download should
   show ~its real size on OUT (not 2×); on-wire mixnet ≫ exit.

Graceful degradation before agent is updated:
- WireGuard + Mixnet-exit totals need **≥ 0.9.7**
- clients/relay on-wire split needs **≥ 0.9.8** (shows `—` until then)

---

## Tests

286 passing. Run individually:

```bash
source .venv/bin/activate
python smoke_test.py          # 25  — registry API
python test_agent_mtls.py     # 36  — CA, agent, mTLS, orchestrator poll
python test_actions.py        # 79  — flag edits, ssh harden, fail2ban, backups
python test_migration.py      # 7   — surrogate-uid schema migration
python test_peers.py          # 65  — 1789 peer-scan, topology harvest, geolocation
python test_extra_blocks.py   # 14  — NYM-EXIT abuse blocklist (v4 + v6)
python test_wallet.py         # 60  — wallet store, nym-cli wrappers, redeem/send
```

---

## API reference

### Orchestrator (`localhost:7766`)

```
GET    /api/health
GET    /api/nodes                 registry joined with cached status
POST   /api/nodes
GET    /api/nodes/{id}
PATCH  /api/nodes/{id}            partial; node_id is immutable
DELETE /api/nodes/{id}
POST   /api/refresh               poll all enabled agents over mTLS
POST   /api/peers                 live 1789 peers for one node, geolocated
GET    /api/traffic/window        exit volume/avg, cumulative-counter deltas
GET    /api/onwire/avg            on-wire avg from the peers sampler
GET    /api/throughput            sparkline/24h chart (backfilled from agent history)
GET    /api/throughput/avg        24h average (labels real span if < 24h, e.g. Ø6h)
POST   /api/history/sync          force an immediate history backfill from all agents
POST   /api/extra-blocks/install-script    run the NYM-EXIT blocklist installer
POST   /api/extra-blocks/restart-service   restart the nym-extra-blocks oneshot
GET    /favicon.ico | /favicon.svg | /apple-touch-icon.png
```

### Wallets (orchestrator-local; keys never leave the Mac)

```
GET    /api/wallet/list                    names + whether nym-cli is present
POST   /api/wallet/query                   balances + pending operator rewards (read-only)
POST   /api/wallet/redeem                  withdraw rewards into balance (confirm=true)
POST   /api/wallet/send                    send NYM (confirm=true)
POST   /api/wallet/add                     import a mnemonic (encrypted at rest)
POST   /api/wallet/export                  reveal a mnemonic (localhost UI only)
POST   /api/wallet/delete                  remove a wallet .enc (confirm=true)
GET    /api/wallet/rewards-files           list per-withdrawal CSVs + totals
GET    /api/wallet/rewards-file/{name}     download one dated withdrawal CSV
```

### Agent (mTLS, port 8443, on each node)

```
GET    /v1/health
GET    /v1/status     version, roles, wireguard, service, bans,
                      traffic_dir, throughput_dir, uplink_device,
                      boot_since, nym_node_since, disk, extra_blocks
GET    /v1/history    ?since=&until=&kind=tput|traffic — rolling 30-day
                      history, cursor-paginated (for orchestrator backfill)
(exec) peers          established 1789 conns + onwire_clients + onwire_peers
```

---

## Roadmap

1. Local foundation — registry + UI ✓
2. Agent + live status over mTLS ✓
3. Safe write actions: restart → upgrade → toggle
4. fail2ban + harden-ssh (native, no expect)
5. File ops: replace-html, then backup
6. `run_allowlisted` — gated + audited, last
