# Installation Guide

## 1. Server (development / lab)
See README “Quick start”. Environment variables are listed in `.env.example`.

### PostgreSQL (recommended)
```sql
CREATE USER edr WITH PASSWORD 'edr_password';
CREATE DATABASE edr OWNER edr;
```
Set `DATABASE_URL=postgresql+psycopg2://edr:edr_password@localhost:5432/edr` in `.env`. Tables, the 14 detection rules and the default users are created on first start.

### Docker
```bash
docker compose up --build        # server on http://localhost:8000 with PostgreSQL
```

### Production hardening checklist
Set a long random `SECRET_KEY`, `ENROLLMENT_TOKEN`, `BACKUP_KEY`; change default passwords; run behind a TLS reverse proxy (nginx/Caddy/IIS ARR) — agents and the console must use HTTPS; restrict the database to the server host; store `BACKUP_DIR` on a separate volume.

## 2. Active Directory
* **Lab (default):** `AD_MODE=mock` reads `lab/lab_directory.json` (domain `lab.local`). Regenerate with `python lab/make_lab_directory.py`.
* **Real domain:** `AD_MODE=ldap`, `AD_SERVER=dc01.yourdomain.local`, `AD_BASE_DN`, `AD_BIND_DN` (a read-only service account, e.g. `svc_edr`), `AD_BIND_PASSWORD`, `AD_USE_SSL=true` (LDAPS/636). The service account needs only read access to users and group membership. Use the *Administration → Tool terminal → ad_lookup* tool to check a user resolves.
* Local logons (`DOMAIN\user`) are attributed through the `sAMAccountName`; the SID and group membership decide the privilege level (standard / elevated / admin).

## 3. Endpoint agent on a Windows machine
1. Install **Sysmon** (Sysinternals) with a configuration that logs event IDs 1, 3, 10, 11, 13 (e.g. SwiftOnSecurity or Olaf Hartong's modular config): `sysmon64.exe -accepteula -i sysmonconfig.xml`.
2. Enable auditing of logon events (4624/4625): *Local Security Policy → Advanced Audit Policy → Logon/Logoff → Audit Logon: Success and Failure*.
3. Install Python 3.11+ and copy the `agent/` folder to the endpoint (`C:\edr-agent`).
4. Create `agent.json`:
```json
{ "server_url": "https://edr.yourdomain.local:8000", "enrollment_token": "<ENROLLMENT_TOKEN>", "criticality": 3, "state_dir": "C:\\edr-agent\\state" }
```
5. Run from an **elevated** prompt (reading the Security log needs admin rights): `cd C:\edr-agent && python -m edr_agent.main --config agent.json`. To run as a service use NSSM or Task Scheduler (“run at startup, highest privileges”).
6. The endpoint appears under *Endpoints*. If the server is unreachable events are spooled to disk and sent when it returns.

*Lab without Windows:* replay recorded events through the real agent pipeline: `python simulation/export_scenario.py A15 > ev.jsonl; cd agent; python -m edr_agent.main --replay ../ev.jsonl` (set `EDR_SERVER`, `EDR_HOSTNAME`).

## 4. Authenticator device (biometric verification)
Enrol a device key under *Administration → Authenticator device*. The browser simulator is for the lab. A mobile app must: scan the QR (`edr://verify?id=<id>&n=<nonce>`), call `POST /api/v1/verify/{id}/scan` {nonce, device_id}, perform the OS biometric prompt, sign `EDR-VERIFY|<id>|<challenge>|<purpose>|<user_id>` with the enrolled Ed25519 private key and `POST /api/v1/verify/{id}/complete` {device_id, signature}. See `device/authenticator.py` for a reference implementation.

## 5. Troubleshooting
| Symptom | Fix |
|---|---|
| Blank page at `/` | Run `npm install && npm run build` in `frontend/` |
| `connection refused` to PostgreSQL | Check `DATABASE_URL`/port; SQLite needs no server |
| Everyone logged out after restart | Set a fixed `SECRET_KEY` |
| Agent `401` | Wrong `enrollment_token`; delete `state/api_key.json` to re-enrol |
| “Ed25519 not supported” in browser | Use current Chrome/Edge/Firefox, or `device/authenticator.py` |
| Account locked | 5 failed logins lock for 5 min (`MAX_FAILED_LOGINS`, `LOCKOUT_MINUTES`) |
