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

## Accounts (backend/ + dashboard/): authenticator app, passwords, reset
**Authenticator app (the real second factor).** Sign in → **My account** → *Set up authenticator*. Enter your password, scan the QR code with
Microsoft Authenticator (**+ → Other account (Google, Facebook, etc.)**), Google Authenticator, Authy, 1Password or any TOTP app, then type the 6-digit code to confirm.
From then on the QR + biometric prompt asks for the current code instead of the dev reference. Turn on the app's own fingerprint/face lock on the phone.
Codes are standard RFC 6238 (SHA-1, 6 digits, 30 s), each works once, and the secret is stored encrypted (keyed from `SECRET_KEY`: if you change `SECRET_KEY`, users must re-enrol).
Replacing or removing an authenticator needs the password and a current code.

**Passwords**
- *Change*: **My account** → *Change password* (needs the current password). All other sessions for that account are signed out.
- *Forgot*: **Sign in → Forgot password?** resets with a current authenticator code. Accounts without an authenticator ask an administrator.
- *Admin*: **Users** page (administrators) to edit email/role, deactivate, *Reset password…* (shows a one-time temporary password; the user must change it at next sign-in and their old sessions end) and *Reset authenticator…* (lost phone). Role/active changes and resets need the QR + biometric step (`user_admin`).
- Repeated wrong passwords/codes on these endpoints lock them for 15 minutes (`RECOVERY_MAX_ATTEMPTS`, `RECOVERY_LOCKOUT_MINUTES`). Signing in itself is not affected.
- *Break-glass* (nobody can sign in, e.g. the only admin lost their phone and password): on the server run `cd backend && python -m app.cli reset-password admin` and/or `python -m app.cli reset-authenticator admin`. Use the same `DATABASE_URL`. Docker: `docker compose exec backend python -m app.cli reset-password admin`.

`BIOMETRIC_MODE` (in `backend/.env`): `both` (default: authenticator if enrolled, otherwise the dev reference), `totp` (authenticator only; **use this outside the lab**, it ignores the demo `demo-fingerprint` reference), `simulated` (dev reference only).
Existing databases are upgraded automatically on start (new columns are added in place).
