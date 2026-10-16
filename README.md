# AD-Integrated EDR System

Working prototype of the Active Directory-integrated Endpoint Detection and Response system designed in Chapters 1-3.
Endpoint agent → AD identity enrichment → rule-based detection (MITRE ATT&CK) → prioritised tickets → incidents →
QR + biometric-gated response actions → reports, with audit trail, backup/restore and a security terminal.

## Run it

### Option A: Docker (full stack with PostgreSQL)
```bash
docker compose up --build
```
Open http://localhost:5173 and sign in as `admin` / `ChangeMe123!` (also `analyst` / `ChangeMe123!`).
Tables and starter detection rules are created automatically on first start. A simulated agent (`demo-ws-01`) starts sending benign telemetry.

Trigger the scripted (simulated) attack chain:
```bash
docker compose run --rm agent python agent.py --server http://backend:8000 --hostname fin-ws-04 --attack
```

### Option B: VS Code / no Docker (SQLite, zero setup)
```bash
# terminal 1: backend
cd backend && python -m venv .venv && .venv\Scripts\activate    # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# terminal 2: dashboard
cd dashboard && npm install && npm run dev

# terminal 3: agent
cd agent && pip install -r requirements.txt
python agent.py --hostname fin-ws-04 --attack          # or without --attack for benign traffic
```
(`.vscode/launch.json` has debug configs for the backend, agent and tests.)

### Tests
```bash
cd backend && PYTHONPATH=. python -m pytest tests -v     # 13 end-to-end tests (also verified against PostgreSQL 16)
cd agent && python -m pytest tests -q                    # Sysmon event parser
```

## Demo walkthrough (about 5 minutes)
1. Run the attack chain. **Overview** and the live ticker light up; **Tickets** is sorted by priority score.
2. **Alerts** → click a row: evidence shows the AD user (e.g. `tshepo`, Domain Admin) behind each event.
3. **Tickets** → *Take* → *Escalate*: an incident is created (ticket: Under Investigation → Escalated).
4. **Incident** → *Start investigating* → choose `isolate_endpoint` → *Execute…*
   A QR modal appears. Scan it, or use the dev simulator box and enter `demo-fingerprint`.
   The incident becomes **Contained**, the endpoint **Isolated**, and the action is audited. Reusing the verification fails.
5. *Mark resolved* → *Generate report* → *Close incident* (closing without a report is refused).
6. **Overview** now shows MTTD / MTTR. **Audit trail** shows every step, including denied attempts.
7. **Backup & restore**, **Detection rules**, **Security terminal** all demand the same QR + biometric step.

## Design → code traceability
| Chapter 3 element | Implementation |
|---|---|
| Class diagram (12 classes) | `backend/app/models.py` (SystemUser, Endpoint, TelemetryEvent, ADUser, DetectionRule, Alert, Ticket, Incident, IncidentReport, AuthTransaction, AuditEntry, Backup) |
| Multiplicities (Alert 1..* events, Alert→0..1 Ticket, Incident groups tickets) | `alert_events` table, `Ticket.alert_id` unique, `Ticket.incident_id` |
| Sequence/communication (event → AD → rule → alert → ticket) | `services/pipeline.py` |
| State chart: Ticket (Fig 8a) | `services/workflow.py` `TICKET_TRANSITIONS` |
| State chart: Incident (Fig 8b) | `services/workflow.py` `INCIDENT_TRANSITIONS` (Contained only via verified response) |
| Process design `executeResponseAction` pre/post | `services/response.py` |
| QR + biometric AuthTransaction (single use, expiry) | `services/auth_tx.py` |
| Scoring model (Ch. 2) | `services/scoring.py` |
| Backup + verification | `services/backup.py` |
| MTTD / MTTR evaluation metrics | `services/metrics.py`, `GET /api/metrics` |

Every test in `backend/tests/test_system.py` is written against these behaviours, so the test names and assertions can be cited as Chapter 4 evidence.

## Real Windows endpoint (Sysmon)
On a Windows VM with Sysmon installed, run from an elevated prompt:
```
python agent.py --mode sysmon --server http://<server-ip>:8000 --key <AGENT_API_KEY> --hostname WS-001
```
It reads Sysmon events 1/3/11/12-14 and maps them to telemetry. Add `--enforce` to let the agent actually carry out isolate / release / kill-process
commands (Windows Firewall rules and `taskkill`); without it they are logged as dry-runs. The agent sends the `DOMAIN\user` from Sysmon and the server resolves it in AD.

For live Active Directory set `AD_ENABLED=true` and the `AD_*` variables in `backend/.env` (LDAPS, read-only bind account).

## Honest limitations
- **Biometrics are simulated.** The QR/transaction flow, expiry, attempt limits, single-use and audit are real; the fingerprint/face check is a stand-in (an enrolled secret, stored only as a salted hash). `BIOMETRIC_MODE=simulated`; a WebAuthn verifier would replace `_verify_biometric` in `services/auth_tx.py`.
- **Agent ↔ server uses a shared API key over HTTP.** Put TLS in front (reverse proxy/VPN) and issue per-endpoint keys before real use.
- **`disable_ad_account` is recorded, not executed** (the EDR deliberately never writes to AD).
- The Sysmon reader and `--enforce` actions are written for Windows but could only be unit-tested for parsing here; run them in your lab VM.
- Detection runs synchronously in the request path; fine for a lab, use a queue for scale.
- Never run `--attack` or `--enforce` against machines you do not own. The attack chain only sends fake telemetry strings, but `--enforce` changes real firewall settings.
