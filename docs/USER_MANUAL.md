# User Manual

**Roles.** *Analyst*: view everything, acknowledge alerts, move tickets, open incidents, add notes, close incidents. *Administrator*: all of that plus response actions, rule enable/disable, backups, tool terminal, users — the sensitive ones require biometric verification.

1. **Sign in** with your username and password. Five wrong passwords lock the account for five minutes.
2. **Overview** – endpoints, 24 h alerts, open tickets/incidents, % of events attributed to an AD identity, alerts by tactic/user/host. Refreshes every 5 s.
3. **Alerts** – filter by severity/status; click a row for the rule, ATT&CK technique, the *responsible AD identity* (account, department, groups, SID, privilege) and the evidence events. *Acknowledge* marks it as seen.
4. **Tickets** – each alert becomes a ticket with a priority (Critical/High/Medium/Low) from severity, confidence, asset criticality and user privilege. Move it New → Assigned → Under Investigation → Resolved → Closed (Resolved can be reopened). *Open incident* starts an investigation.
5. **Incidents** – the report shows *who* (AD identity), *what* (techniques), *where* (hosts), *when* and a correlated timeline. Add notes. **Administrators** can *Isolate host*, *Release host* or *Flag account*; each shows a QR code that must be verified (scan + fingerprint) before it runs. Isolation takes effect when the agent next heartbeats (≤ 30 s). *Close incident* resolves escalated tickets.
6. **Endpoints** – state (online/isolated/offline), criticality, last seen; click a host for recent events with the AD identity next to each.
7. **Detection rules** – description, ATT&CK mapping, severity, number of alerts. Enable/disable needs verification.
8. **Audit log** – every login, change and action; **Verify integrity** recomputes the hash chain and reports the first tampered entry if any.
9. **Administration** – enrol your authenticator device; create/verify/restore encrypted backups (restore re-checks checksum and audit chain); run allow-listed diagnostics (tcp_check, dns_resolve, ad_lookup, endpoint_status, audit_verify, system_stats); manage users.

**The verification dialog.** Scan the QR with your enrolled device and confirm with your fingerprint. A code is valid for 120 s and for one action only; a failed fingerprint, a different action or an expired code is refused and audited.
