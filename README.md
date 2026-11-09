# AD-Integrated Endpoint Detection & Response (EDR) — Working Prototype

Project: _Design and Development of an Active Directory-Integrated EDR System for Enterprise Windows Networks_ (Botho University, C8-PRO-11).

What it is: endpoint agent → ingestion API → rule-based behaviour detection (14 MITRE ATT&CK-mapped rules) → every event/alert is tied to an **Active Directory identity** (user, department, groups, privilege) → risk-ranked tickets → incident response with **QR-assisted biometric verification** for sensitive actions → tamper-evident audit log, encrypted backups and a web console.

```
 Win
```

## Quick start (5 minutes, any OS, no Docker, no database server)

Requires Python 3.11+ and Node 18+.

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate        macOS/Linux:  source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env                      # Windows: copy .env.example .env
cd frontend && npm install && npm run build && cd ..
python run_server.py                      # → http://127.0.0.1:8000
```

Populate it with the 28 simulated scenarios (15 attacks, 13 benign look-alikes) and see the evaluation numbers:

```bash
python simulation/run_eval.py            # in a second terminal, server running
```

.

## VS Code

Open this folder in VS Code → _Run and Debug_: **EDR Server**, **EDR Agent (replay scenario)**, **Run evaluation**, **Pytest (all)**. _Terminal → Run Task_ has install/build/test tasks. Dashboard hot-reload: task “Dashboard dev server” (http://localhost:5173, proxies the API).

## Tests

```bash
python -m pytest -q tests                                  # 260 tests, SQLite
TEST_DATABASE_URL=postgresql+psycopg2://user@host/db python -m pytest -q tests   # against PostgreSQL
python -m pytest -q tests --cov=server/app --cov=agent/edr_agent --cov-branch --cov-report=term-missing
```

## Layout

| Path                      | Purpose                                                                                                                                              |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `server/app/`             | FastAPI app: `ingest.py`, `detection.py` + `rules/rules.yaml`, `ad.py`, `tickets.py`, `biometric.py`, `audit.py`, `backup.py`, `tools.py`, `routes/` |
| `agent/edr_agent/`        | Endpoint agent: Sysmon/Security parser, Windows collector, HTTP client with spool/retry, host isolation                                              |
| `frontend/`               | React + Vite console (built into `frontend/dist`, served by the server)                                                                              |
| `device/authenticator.py` | Simulated phone authenticator (Ed25519)                                                                                                              |
| `lab/`                    | Lab AD directory (`lab.local`, 11 users) and generator                                                                                               |
| `simulation/`             | Attack scenarios with ground truth, evaluation harness, screenshot script                                                                            |
| `tests/`                  | Unit, integration, black-box, white-box and scenario tests                                                                                           |
| `docs/`                   | `INSTALL.md` (incl. Windows endpoint, real AD, PostgreSQL, Docker), `USER_MANUAL.md`                                                                 |
