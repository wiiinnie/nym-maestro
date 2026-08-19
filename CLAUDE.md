# nym-maestro

## Overview
Python mTLS orchestrator für ein 22-Node Nym Exit-Gateway Fleet. Zwei Komponenten: ein zentraler Orchestrator (Control Plane) und ein Agent, der auf jedem Node läuft (Data Plane).

## Architecture
- **Orchestrator** (Control Plane): FastAPI-App, läuft lokal auf `localhost:7766`. Aggregiert Fleet-State, liefert die Dashboard-UI aus, spricht die Agents an.
- **Agent** (Data Plane): stdlib-only Python, deployed auf jedem der 22 Nodes, lauscht auf Port 8443 über mTLS. Keine Third-Party-Dependencies — Agent muss ohne Paketmanager/venv-Setup auf frisch provisionierten Nodes laufen.
- **Storage**: SQLite orchestrator-seitig für aggregierten State. Agent puffert lokal (30-Tage Rolling History) und meldet nach oben.
- **Traffic/Throughput-Modell**: Three-Plane-Visualisierung — On-Wire Sphinx (Mixnet-Paketebene), Exit Payload (entschlüsselter/austretender Traffic), Physical Uplink (rohe NIC-Counter). Pro-Node-Detailkarten im Dashboard trennen WireGuard- und Mixnet-Metriken separat aus.

## Non-negotiable constraints
- **Agent-Code bleibt stdlib-only.** Niemals Third-Party-Deps auf Agent-Seite einführen — der ganze Sinn ist Deployment auf 22 Nodes ohne Package-Management-Overhead.
- Orchestrator-Seite darf FastAPI/uvicorn/etc. nutzen, das ist unkritisch.
- mTLS ist die Vertrauensgrenze zwischen Orchestrator und Agents auf Port 8443. Änderungen an Cert-Handling, mTLS-Handshake oder Agent-Auth explizit ankündigen, nicht "nebenbei" mitrefactoren.

## Data model
- SQLite orchestrator-seitig für aggregierten Fleet-State.
- Agent-seitig: 30-Tage Rolling History Buffer (zuletzt hinzugefügt — bei allem, was History/Retention betrifft, hier zuerst nachsehen).
- Disk-Usage-Spalte kürzlich ergänzt, vermutlich neben den übrigen Per-Node-Metriken (WireGuard-, Mixnet-Counter).

## UI / Dashboard
- Pro-Node-Detailkarten: getrennte WireGuard- und Mixnet-Sektionen.
- Bekannter kürzlich behobener Bug: Modal-z-index-Problem — bei Änderungen an Modals/Overlays auf Stacking-Context-Regressionen prüfen.
- Favicon kürzlich ergänzt — trivial, aber der Vollständigkeit halber vermerkt.
- Modal-Konventionen (verifiziert): `div.overlay` als Sibling von `.wrap`, `classList.add/remove('open')`, `.overlay` z-index 20, `.overlay.overlay-top` z-index 40 für Modals, die über einem offenen Modal liegen (Results/Throughput). Neue Overlays IMMER in beiden Listen am Script-Ende registrieren (Backdrop-Click + Escape) — `eb-overlay` fehlt in beiden, das ist ein bestehender Bug, nicht das Muster.
- Fetch-Helper ist `api(path, opts)`; Fehler via `toast(e.message, true)`; Per-Node-Ergebnisse via `showResults(title, r.results)` → `buildResultCards()`. Neue Result-Felder werden dort ergänzt; `res.kind` unterscheidet Shapes (sonst kollidieren gleichnamige Felder wie `verified` zwischen Features).

## Landing page (public node overview)
- Jede Exit-Gateway serviert unter `/var/www/<hostname>/index.html` eine öffentliche Notice-Page mit Legal-T&C. Der Node-Overview-Block darin wird von maestro generiert (Ersatz für das tote nymesis-iframe) — Zweck: eine vollständige, eindeutige IP-Liste für Behörden.
- `landing.py` (orchestrator-seitig, stdlib-only) ist der Generator: Whitelist, Validierung, Rendering, Splice, Diff. Splice passiert zwischen `<!-- NODES:AUTO START/END -->`; beim ersten Lauf wird der alte handgeschriebene Abschnitt via `LEGACY_RE` ersetzt. Alles außerhalb der Marker (T&C, SVG) bleibt unberührt.
- **Whitelist nie erweitern:** nur `name`, `ip`, `hostname`, `cc` verlassen maestro. Hart kodiert in `select()`, damit neue Admin-Felder nicht leaken können. Insbesondere ist `node_id` **kein** Fallback für einen leeren `name` (interne IDs gehören nicht auf eine öffentliche Seite) — Fallback ist der Hostname, plus Warnung.
- **Sicherheits-Invarianten (jeweils durch einen Regressionstest in `test_landing.py` abgedeckt — nicht "aufräumen"):**
  - Der Manifest-JSON im HTML-Kommentar escaped **jeden** `-` als `-`. Nicht auf `replace("--", <guard>)` zurückbauen: `str.replace` ist non-overlapping, `"--->"` wurde zu `"-<guard>-->"` und schloss den Kommentar → ein Node-Name wie `AT01---><img onerror=...>` brachte lebendes Markup auf die öffentliche Seite. **Die mitgelieferte Referenz `generate_landing.py` hat diesen Bug ebenfalls.**
  - `is_exit_gateway()`: der Selbstbericht des Nodes gewinnt in beide Richtungen; `exit: False` wird nie publiziert, egal wie der Node heißt. Ohne `status` entscheiden Namens-Hints (ein Mixnode mit totem Agent wird also nicht gelistet).
  - Agent: Backups nie mit `shutil.copy2` — das öffnet das Ziel mit `'wb'` und schreibt durch einen dort platzierten Symlink (Root-Write überall hin). Stattdessen `_landing_copy_nofollow()` mit `O_NOFOLLOW`. Symlinks als `index.html` oder als Backup werden abgelehnt (`reason: "symlink"`), und ein Backup muss die Version tragen, die sein Name behauptet (sonst wäre `/etc/shadow` als `index.html.bak-aaaaaa` publizierbar).
  - Der Idempotenz-Skip vergleicht die **sha256 der ganzen Datei**, nicht den Versionsmarker. Der Marker hasht nur die Node-Liste, eine T&C-Änderung lässt ihn unverändert — ein Skip darauf hätte genau die wichtigste Änderung still verschluckt.
  - `/api/landing/preview` liefert `Content-Security-Policy: sandbox allow-scripts`. Der Master ist Fremd-HTML (gefetcht/eingefügt) und diese Origin hält das Dashboard-Cookie.
- Master liegt unter `~/.nym-maestro/landing/master.html` (Env: `MAESTRO_LANDING_DIR`), Deploy-Kopie unter `serve/index.html` + `.sha256`.
- Zwei getrennte Schritte im UI (Rebuild / Deploy) — bewusst, damit ein fehlgeschlagener Deploy ohne Neu-Generieren wiederholbar ist. Rebuild publiziert nichts.
- Die Seite ist statisch (funktioniert ohne JS) — `/api/nodes` ist localhost-only und ohne CORS, die Daten müssen also zur Build-Zeit eingebacken werden. Kein Live-Online-Status auf der Seite; das `list generated <date>` ist das Freshness-Signal.
- Agent-Actions: `landing_status`, `landing_deploy`, `landing_revert`. Deploy verifiziert sha256 vor jedem Disk-Zugriff, verlangt einen `NODES:VERSION`-Marker im Content, legt Backup `index.html.bak-<version>` an und swappt atomar. Webroot wird nie angelegt — fehlender Webroot/index.html wird gemeldet.
- Ein `index.html`, das ein Symlink ist, wird abgelehnt (`reason: "symlink"`): der Backup-Schritt würde sonst den Symlink-Zielinhalt ins web-servierte Verzeichnis kopieren.
- **Bekannte Einschränkung von `FQDN_RE`** (aus der Referenzimplementierung übernommen, in `landing.py` UND agent-seitig): Labels mit doppeltem Bindestrich werden abgelehnt — also auch Punycode/IDN (`xn--…`). Für die aktuellen `nym-exit-XX01.hermes-stakepool.de`-Hostnames irrelevant. Der Fehler ist fail-closed: Rebuild stoppt hart und nennt den betroffenen Node, statt ihn stillschweigend auszulassen. Wenn je ein IDN-Hostname dazukommt, muss das Pattern in beiden Dateien angepasst werden.

## Versioning
- Agent-Version steht auf **0.11.0** (`AGENT_VERSION` in `agent/agent.py`). Vor Annahmen über Feature-Verfügbarkeit fleet-weit den Agent-Versionsstring prüfen — nicht alle 23 Nodes laufen zwangsläufig auf derselben Agent-Version.
- Es gibt keine Capability-Negotiation: ein alter Agent antwortet auf eine unbekannte Action mit HTTP 400 `unknown action: ...`. Das ist das Feature-Detection-Signal. Achtung: `agent_exec` macht `raise_for_status()`, und httpx' Exception-Message enthält den Response-Body NICHT — für eine brauchbare Fehlermeldung `e.response.json()["error"]` auslesen (siehe `_landing_fanout`).

## Working conventions
- Bei allem, was mTLS/Cert-Logik betrifft oder Agents fleet-weit offline nehmen könnte, vorher nachfragen — ein Bug hier heißt nicht "Commit reverten", sondern "22 Nodes melden sich nicht mehr."
- Defensiver, expliziter Code auf Agent-Seite (keine externen Error-Handling-Libs — stdlib only, siehe oben).
- Beim Hinzufügen von Orchestrator-API-Feldern/Endpoints auf das Muster achten, das im Schwesterprojekt SOZU bereits aufgetreten ist: still fallengelassene Felder in Config-APIs. Verifizieren, dass neue Felder tatsächlich durchverdrahtet sind, nicht nur deklariert.
- Fleet hat heterogene Node-Historie — im breiteren Nym-Ops-Kontext gab es NAT/Routing-Eigenheiten (IPv6 NAT66, verwaiste WireGuard-Peer-States) auf einzelnen Nodes. Nicht direkt Aufgabe dieses Repos, aber bei verdächtigem Reporting für einen einzelnen Node ein plausibler erster Verdacht.

## Testing
- Vor "fertig" die Test-Suites für Agent und Orchestrator laufen lassen. Existiert für ein geändertes Modul noch keine Test-Suite, das explizit benennen statt die Verifikation stillschweigend zu überspringen.
- Für Agent-Änderungen: da stdlib-only, Tests nicht mit Third-Party-Test-Deps überladen, die nicht schon etabliert sind (pytest als Dev-only-Dependency ist unkritisch, wird ja nicht auf die Nodes ausgeliefert).
- **Die Suites sind Skripte, nicht pytest-Tests** — direkt laufen: `.venv/bin/python test_<name>.py`. Jede printet `N passed, M failed` und exitet mit 1 bei Fehlern. Vorhanden: `test_actions`, `test_agent_mtls`, `test_delegation`, `test_extra_blocks`, `test_landing`, `test_migration`, `test_peers`, `test_wallet`, plus `smoke_test.py`.
- `test_wallet.py` hat einen bekannten, vorbestehenden Failure (`redeem passes --mnemonic`) — nicht durch neue Änderungen verursacht, vor dem Debuggen gegen HEAD verifizieren.
- `test_agent_mtls.py` enthält das Harness, um einen echten Agent lokal mit frischer CA + Enrollment über echtes mTLS zu starten (`pki.init_ca` / `pki.enroll` + Subprocess). Für Wire-Level-Tests neuer Agent-Actions von dort kopieren, statt nur `act_*` in-process aufzurufen.

## Git / commits
- Commit-Messages: knapp, imperativ, technisch.
- Orchestrator- und Agent-Änderungen nicht in einem Commit bündeln, außer sie sind wirklich gekoppelt (z.B. eine Wire-Protocol-Änderung zwischen beiden).

## Notes for Claude Code sessions
- Dieses File ist ein Startentwurf aus dem bisherigen Projektkontext, kein verifizierter Snapshot des aktuellen Repo-Stands. In der ersten Session Struktur (exakte Pfade, Testbefehle, Dependency-Manifeste) gegen das tatsächliche Repo validieren und dieses File entsprechend nachziehen.
- Schwesterprojekt: SOZU Provisioner Dashboard (Repo `provisioner_server`) teilt architektonische DNA (Telegram-Notifications, Config-API-Muster) — bei ähnlichen Problemen dort nach Prior Art schauen, bevor man hier von null anfängt.
