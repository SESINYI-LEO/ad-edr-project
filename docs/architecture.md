# Architecture

```
Windows endpoint agent ──HTTP(S)+API key──▶ FastAPI server ──▶ PostgreSQL (SQLite for dev)
 (Sysmon / simulated)                         │  ├─ services/pipeline   ingest → dedupe → AD enrich → detect → alert → ticket
        ▲                                     │  ├─ services/ad         mock directory or live LDAPS (read-only)
        └── polls approved commands ◀─────────┤  ├─ services/response   executeResponseAction (pre/post conditions)
                                              │  ├─ services/auth_tx    QR + biometric transactions
 React dashboard ◀──REST/JWT──────────────────┘  └─ services/backup, reports, metrics, terminal
```

## Privileged operations
Response actions, rule changes, backup create/restore, endpoint release and the security terminal all require an Administrator
**and** a verified, unexpired, single-use `AuthTransaction` issued for that exact purpose (header `X-Auth-Transaction`).
Failures are audited and change no state.

## Local vs VPN
`DEPLOYMENT_MODE=local|vpn` is informational. Neither mode exposes the server publicly: bind it to the LAN/VPN interface,
restrict `CORS_ORIGINS`/`PUBLIC_BASE_URL` to the internal hostname, and terminate TLS in a reverse proxy. The VPN itself is infrastructure.
